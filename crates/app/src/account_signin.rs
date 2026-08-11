//! Desktop → Hub account sign-in: the local control plane's half of the
//! **native device handoff** (LOGIN-2, ADR 0123).
//!
//! The desktop links the person's GaugeWright account with the same handoff
//! native mobile uses: the system browser opens the Hub's `/auth/login` with a
//! PKCE-style challenge, the Hub authenticates the person and 302s to
//! `gaugewright://auth/callback#code=<single-use>`, and this module redeems the
//! code — with the verifier that never left this process — at the Hub's
//! exchange endpoint. The verified id-token (the account bearer) is sealed at
//! rest (`SEC-4`) in the local account scope; the webview only ever sees the
//! one-time code and non-secret status projections. Signing out deletes the
//! sealed record and is idempotent; a session close to expiry is refreshed
//! proactively when its status is read (the account surfaces poll status, so a
//! live desktop keeps itself signed in without a background daemon).
//!
//! The Hub endpoint is deployment configuration, not edition:
//! `GAUGEDESK_ACCOUNT_HUB_URL` overrides the production default, and an
//! explicitly empty value disables the surface (status then reports
//! `available: false`, and the welcome/account UIs show their local-only
//! wording instead of a dead button).

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::account::ACCOUNT_SCOPE;
use crate::net_http::HttpClient;
use crate::{LockUnpoisoned, SharedWorkbench};

/// Latest-wins record family holding the sealed Hub session in the account scope.
const RECORD_KIND: &str = "hub-session";
const RECORD_ID: &str = "session";
/// Refresh when the id-token has less than this long to live (it lives ~1h).
const REFRESH_SKEW_MS: i64 = 10 * 60 * 1000;
/// A started sign-in that was never completed expires after this long.
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);
/// The one native return URI the Hub admits (`auth_oidc::native_return_uri`).
const NATIVE_RETURN: &str = "gaugewright://auth/callback";

/// The Hub account-API base, or `None` when the surface is disabled.
/// `GAUGEDESK_ACCOUNT_HUB_URL` overrides; explicitly empty disables.
fn hub_base() -> Option<String> {
    let configured = gaugedesk_env::var("ACCOUNT_HUB_URL")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|| "https://auth.gaugewright.com".to_string());
    if configured.is_empty() {
        return None;
    }
    Some(configured.trim_end_matches('/').to_string())
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

/// The Hub login URL that begins a native handoff bound to `challenge`.
fn login_url(hub: &str, challenge: &str) -> String {
    // The challenge alphabet is base64url (alphanumeric, `-`, `_`) — URL-safe by
    // construction; only the return URI needs encoding.
    format!(
        "{hub}/auth/login?return_to=gaugewright%3A%2F%2Fauth%2Fcallback&handoff_challenge={challenge}"
    )
}

/// Decode a claims field from an (already server-verified) JWT for projection —
/// never verification; the Hub verified the token before handing it over.
fn jwt_claim(token: &str, claim: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get(claim).cloned()
}

fn jwt_subject(token: &str) -> Option<String> {
    jwt_claim(token, "sub")?.as_str().map(str::to_string)
}

/// `exp` in epoch milliseconds, `None` when the token carries none.
fn jwt_expiry_ms(token: &str) -> Option<i64> {
    jwt_claim(token, "exp")?.as_i64().map(|secs| secs * 1000)
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
    expires: i64,
    /// The Hub-minted trusted-device id this session is bound to (LOGIN-3);
    /// presented on refresh so revocation from the account surface bites.
    #[serde(default)]
    device: String,
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

/// The current account bearer, unsealed — for core callers that present the
/// person to the Hub (projections, opaque routes). Never crosses HTTP.
pub fn hub_session_token(wb: &SharedWorkbench) -> Option<String> {
    let record = latest_session(wb)?;
    let workbench = wb.lock_unpoisoned();
    workbench.unseal_account_secret(&record.sealed)
}

fn seal_session(
    wb: &SharedWorkbench,
    id_token: &str,
    device: &str,
) -> Result<SessionRecord, String> {
    let person = jwt_subject(id_token).unwrap_or_default();
    let expires = jwt_expiry_ms(id_token).unwrap_or(0);
    let sealed = {
        let workbench = wb.lock_unpoisoned();
        workbench
            .seal_account_secret(id_token)
            .ok_or_else(|| "could not seal the Hub session".to_string())?
    };
    let record = SessionRecord {
        id: RECORD_ID.to_string(),
        sealed,
        person,
        expires,
        device: device.to_string(),
    };
    write_session(wb, &record)?;
    Ok(record)
}

/// Redeem the deep-linked single-use code at the Hub. Blocking (ureq) — run off
/// the async runtime.
fn redeem_at_hub(hub: &str, code: &str, verifier: &str) -> Result<(String, String), String> {
    let http = HttpClient::new();
    let body = json!({
        "code": code,
        "verifier": verifier,
        "device_label": device_label(),
    })
    .to_string();
    let (status, response) = http
        .post_json_headers(&format!("{hub}/auth/mobile/exchange"), &[], &body)
        .map_err(|error| format!("the Hub was unreachable: {error}"))?;
    if status != 200 {
        return Err(format!("the Hub refused the handoff ({status})"));
    }
    let parsed: Value =
        serde_json::from_str(&response).map_err(|_| "malformed Hub response".to_string())?;
    let id_token = parsed
        .get("id_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "malformed Hub response".to_string())?;
    let device = parsed
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok((id_token, device))
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
fn refresh_at_hub(hub: &str, bearer: &str, device: &str) -> Result<String, String> {
    let http = HttpClient::new();
    let mut headers = vec![("authorization".to_string(), format!("Bearer {bearer}"))];
    if !device.is_empty() {
        // LOGIN-3: bind the refresh to the registered device, so revoking it
        // from the account surface stops this session's renewal.
        headers.push(("x-gw-device".to_string(), device.to_string()));
    }
    let (status, response) = http
        .post_json_headers(&format!("{hub}/auth/mobile/refresh"), &headers, "{}")
        .map_err(|error| format!("the Hub was unreachable: {error}"))?;
    if status != 200 {
        return Err(format!("the Hub refused the refresh ({status})"));
    }
    let parsed: Value =
        serde_json::from_str(&response).map_err(|_| "malformed Hub response".to_string())?;
    parsed
        .get("id_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
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
            "expires": record.expires,
            "expired": record.expires <= now_ms(),
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
    let verifier = new_verifier();
    let challenge = challenge_for(&verifier);
    *pending() = Some(PendingSignin {
        verifier,
        started: Instant::now(),
    });
    Json(json!({
        "url": login_url(&hub, &challenge),
        "return": NATIVE_RETURN,
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
        return (
            StatusCode::BAD_REQUEST,
            "no sign-in was started on this device",
        )
            .into_response();
    };
    if taken.started.elapsed() > PENDING_TTL {
        return (
            StatusCode::BAD_REQUEST,
            "the sign-in attempt expired; start again",
        )
            .into_response();
    }
    let code = request.code.trim().to_string();
    let redeemed =
        tokio::task::spawn_blocking(move || redeem_at_hub(&hub, &code, &taken.verifier)).await;
    let (id_token, device) = match redeemed {
        Ok(Ok(token)) => token,
        Ok(Err(message)) => return (StatusCode::BAD_GATEWAY, message).into_response(),
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "sign-in task panicked").into_response()
        }
    };
    match seal_session(&wb, &id_token, &device) {
        Ok(record) => Json(status_json(Some(&record), true)).into_response(),
        Err(message) => (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
    }
}

/// `GET /account/hub-session` — non-secret status. A session inside the
/// refresh window is refreshed here, proactively: the account surfaces poll
/// this route, so an open desktop renews itself before the ~1h token lapses.
pub async fn get_signin_status(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let available = hub_base().is_some();
    let Some(record) = latest_session(&wb) else {
        return Json(status_json(None, available)).into_response();
    };
    let due = record.expires > now_ms() && record.expires - now_ms() < REFRESH_SKEW_MS;
    if available && due {
        if let (Some(hub), Some(bearer)) = (hub_base(), hub_session_token(&wb)) {
            let device = record.device.clone();
            let refreshed =
                tokio::task::spawn_blocking(move || refresh_at_hub(&hub, &bearer, &device)).await;
            if let Ok(Ok(token)) = refreshed {
                if let Ok(updated) = seal_session(&wb, &token, &record.device) {
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
    if latest_session(&wb).is_none() {
        return StatusCode::NO_CONTENT.into_response();
    }
    let cleared = SessionRecord {
        id: RECORD_ID.to_string(),
        sealed: String::new(),
        person: String::new(),
        expires: 0,
        device: String::new(),
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
        let url = login_url("https://auth.example.test", "abc-_123");
        assert_eq!(
            url,
            "https://auth.example.test/auth/login?return_to=gaugewright%3A%2F%2Fauth%2Fcallback&handoff_challenge=abc-_123"
        );
    }

    fn test_jwt(claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        format!("{header}.{payload}.sig")
    }

    #[test]
    fn jwt_projection_reads_subject_and_expiry() {
        let token = test_jwt(json!({ "sub": "alice@example.test", "exp": 1000 }));
        assert_eq!(jwt_subject(&token).as_deref(), Some("alice@example.test"));
        assert_eq!(jwt_expiry_ms(&token), Some(1_000_000));
        assert_eq!(jwt_subject("not-a-jwt"), None);
        assert_eq!(jwt_expiry_ms("not-a-jwt"), None);
    }

    #[test]
    fn session_seals_projects_and_clears_without_leaking_the_token() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let token = test_jwt(json!({ "sub": "alice@example.test", "exp": 4_102_444_800i64 }));

        let record = seal_session(&wb, &token, "native-abc123").unwrap();
        assert_eq!(record.person, "alice@example.test");
        assert_eq!(record.expires, 4_102_444_800_000);
        assert_eq!(record.device, "native-abc123");
        assert!(
            !record.sealed.contains(&token),
            "the stored form is sealed, not plaintext"
        );
        assert_eq!(hub_session_token(&wb).as_deref(), Some(token.as_str()));

        let projection = status_json(Some(&record), true);
        assert_eq!(projection["linked"], true);
        assert_eq!(projection["person"], "alice@example.test");
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
            device: String::new(),
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
            device: String::new(),
        };
        let projection = status_json(Some(&record), true);
        assert_eq!(projection["linked"], true);
        assert_eq!(projection["expired"], true);
    }
}
