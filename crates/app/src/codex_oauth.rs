//! GaugeDesk-owned OpenAI Codex OAuth lifecycle (LLM-1, ADR 0062).
//!
//! Desktop uses the loopback PKCE helper. A hosted Home or Hub speaks OpenAI's
//! ChatGPT device authorization directly — no Codex CLI, no subprocess — and seals
//! the resulting bundle into the authenticated person's account scope. The
//! browser and Durable Objects receive only a verification code/status;
//! WhippleScript does not own credentials.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::account::{
    credentials_in_scope, seal_token, unseal_token, CredentialAuthentication, ModelExecutionClass,
    ACCOUNT_SCOPE,
};
use crate::{net_http, LockUnpoisoned, SharedWorkbench};

const PROVIDER: &str = "openai-codex";
const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const REFRESH_SKEW_MS: i64 = 60_000;
pub const CODEX_ACCESS_BINDING: &str = "GAUGEDESK_CODEX_ACCESS_TOKEN";
pub const CODEX_ACCOUNT_BINDING: &str = "GAUGEDESK_CODEX_ACCOUNT_ID";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CodexOAuthCredential {
    pub access: String,
    pub refresh: String,
    pub expires: i64,
    pub account_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexRuntimeCredential {
    pub access: String,
    pub account_id: String,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn load_credential_in(
    wb: &SharedWorkbench,
    scope: &str,
    execution_class: ModelExecutionClass,
) -> Option<(CodexOAuthCredential, BTreeSet<ModelExecutionClass>)> {
    let workbench = wb.lock_unpoisoned();
    let record = credentials_in_scope(workbench.store_ref(), scope)
        .remove(PROVIDER)
        .filter(|record| {
            record.authentication == CredentialAuthentication::OAuth
                && record.admits(execution_class)
        })?;
    let encoded = unseal_token(workbench.account_key(), &record.sealed_token)?;
    serde_json::from_str(&encoded)
        .ok()
        .map(|credential| (credential, record.execution_classes))
}

fn load_versioned_credential_in(
    wb: &SharedWorkbench,
    scope: &str,
    execution_class: ModelExecutionClass,
) -> Option<(CodexOAuthCredential, BTreeSet<ModelExecutionClass>, u64)> {
    let workbench = wb.lock_unpoisoned();
    let record = credentials_in_scope(workbench.store_ref(), scope)
        .remove(PROVIDER)
        .filter(|record| {
            record.authentication == CredentialAuthentication::OAuth
                && record.admits(execution_class)
        })?;
    let encoded = unseal_token(workbench.account_key(), &record.sealed_token)?;
    serde_json::from_str(&encoded)
        .ok()
        .map(|credential| (credential, record.execution_classes, record.version))
}

fn store_credential_in(
    wb: &SharedWorkbench,
    scope: &str,
    credential: &CodexOAuthCredential,
    execution_classes: BTreeSet<ModelExecutionClass>,
) -> Result<(), String> {
    let plaintext = serde_json::to_string(credential).map_err(|error| error.to_string())?;
    let mut workbench = wb.lock_unpoisoned();
    let sealed = seal_token(workbench.account_key(), &plaintext)
        .ok_or_else(|| "could not seal Codex OAuth credential".to_owned())?;
    workbench
        .upsert_account_credential_in_with_policy(
            scope,
            PROVIDER.to_owned(),
            sealed,
            String::new(),
            execution_classes,
        )
        .map_err(|error| format!("could not store Codex OAuth credential: {error:?}"))?;
    Ok(())
}

pub(crate) fn store_credential(
    wb: &SharedWorkbench,
    credential: &CodexOAuthCredential,
) -> Result<(), String> {
    store_credential_in(
        wb,
        ACCOUNT_SCOPE,
        credential,
        BTreeSet::from([ModelExecutionClass::LocalInteractive]),
    )
}

/// Fold pre-execution-class desktop Codex records into the explicit local-only OAuth shape.
/// This is an in-place metadata rotation of already sealed GaugeDesk-owned material; it never
/// imports another client's auth file and never widens the credential to hosted execution.
pub(crate) fn ensure_local_credential_record(wb: &SharedWorkbench) -> Result<(), String> {
    let needs_migration = {
        let workbench = wb.lock_unpoisoned();
        credentials_in_scope(workbench.store_ref(), ACCOUNT_SCOPE)
            .get(PROVIDER)
            .is_some_and(|record| {
                record.authentication != CredentialAuthentication::OAuth
                    || record.execution_classes
                        != BTreeSet::from([ModelExecutionClass::LocalInteractive])
            })
    };
    if needs_migration {
        let credential = {
            let workbench = wb.lock_unpoisoned();
            let record = credentials_in_scope(workbench.store_ref(), ACCOUNT_SCOPE)
                .remove(PROVIDER)
                .ok_or_else(|| "could not migrate the sealed Codex OAuth credential".to_owned())?;
            let encoded = unseal_token(workbench.account_key(), &record.sealed_token)
                .ok_or_else(|| "could not migrate the sealed Codex OAuth credential".to_owned())?;
            serde_json::from_str(&encoded)
                .map_err(|_| "could not migrate the sealed Codex OAuth credential".to_owned())?
        };
        store_credential(wb, &credential)?;
    }
    Ok(())
}

/// Status projection; plaintext token fields never cross HTTP.
pub async fn get_codex_status(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    codex_status(&wb, &headers, false)
}

pub async fn get_home_codex_status(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    codex_status(&wb, &headers, true)
}

fn codex_status(wb: &SharedWorkbench, headers: &HeaderMap, hosted: bool) -> Json<Value> {
    let (scope, class) = {
        let workbench = wb.lock_unpoisoned();
        (
            workbench.credential_scope_for(net_http::bearer(headers)),
            if hosted {
                ModelExecutionClass::PrivateHome
            } else {
                ModelExecutionClass::LocalInteractive
            },
        )
    };
    let credential = load_credential_in(wb, &scope, class).map(|(credential, _)| credential);
    let expires = credential.as_ref().map(|value| value.expires);
    let login = if hosted {
        device_login_for_scope(&scope).map(|login| login.projection())
    } else {
        None
    };
    Json(json!({
        "provider": PROVIDER,
        "linked": credential.is_some(),
        "expires": expires,
        "expired": expires.is_some_and(|value| value <= now_ms()),
        "login": login,
    }))
}

/// Secret-free hosted status for an already authenticated exact account scope.
/// GaugeApp adapters use this instead of rebuilding provider OAuth state.
pub fn home_status_for_scope(wb: &crate::Workbench, scope: &str) -> Value {
    let credential = credentials_in_scope(wb.store_ref(), scope)
        .remove(PROVIDER)
        .filter(|record| {
            record.authentication == CredentialAuthentication::OAuth
                && record.admits(ModelExecutionClass::PrivateHome)
        })
        .and_then(|record| wb.unseal_account_secret(&record.sealed_token))
        .and_then(|encoded| serde_json::from_str::<CodexOAuthCredential>(&encoded).ok());
    let expires = credential.as_ref().map(|value| value.expires);
    json!({
        "provider": PROVIDER,
        "linked": credential.is_some(),
        "expires": expires,
        "expired": expires.is_some_and(|value| value <= now_ms()),
        "login": device_login_for_scope(scope).map(|login| login.projection()),
    })
}

fn node_bin() -> String {
    gaugedesk_env::var("NODE_BIN").unwrap_or_else(|| "node".to_owned())
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DeviceLoginState {
    Pending,
    Linked,
    Failed,
    Cancelled,
}

#[derive(Clone)]
struct DeviceLogin {
    login_id: String,
    scope: String,
    /// When this login was started. The map is keyed by a random `login_id`, so
    /// without this there is no notion of "the current attempt" — only
    /// lexicographic order, which is what made the status route answer with
    /// whichever login happened to sort first.
    started_at: i64,
    verification_url: String,
    user_code: String,
    state: DeviceLoginState,
    error: Option<String>,
    /// Read by the polling thread before each poll and again before it seals a
    /// credential, so a cancelled login never links.
    cancelled: Arc<AtomicBool>,
}

impl DeviceLogin {
    fn projection(&self) -> Value {
        json!({
            "login_id": self.login_id,
            "verification_url": self.verification_url,
            "user_code": self.user_code,
            "status": self.state,
            "error": self.error,
        })
    }

    fn active(&self) -> bool {
        self.state == DeviceLoginState::Pending
    }
}

fn device_logins() -> &'static Mutex<BTreeMap<String, DeviceLogin>> {
    static LOGINS: OnceLock<Mutex<BTreeMap<String, DeviceLogin>>> = OnceLock::new();
    LOGINS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// This scope's current device login: an active one if there is one, otherwise
/// the most recently started.
///
/// `find` over a `BTreeMap` keyed by a random `login_id` returned whichever
/// login sorted first, which is unrelated to which one is current. Two things
/// went wrong with that. The status route answered with a stale login — the
/// wrong `user_code` and `verification_url`, so a person would be told to enter
/// a code that authorizes nothing. And `start_device_login_blocking`, which
/// reuses an existing login through this same lookup, saw `None` whenever the
/// first-sorting login was inactive and started a second login for a scope
/// that already had one.
///
/// Active wins over recency deliberately: at most one login can be live for a
/// scope, and it is the one a person is part-way through. Recency only orders
/// the terminal ones, so the status keeps reporting the last outcome —
/// `linked`, `failed` — rather than an arbitrary older one.
fn device_login_for_scope(scope: &str) -> Option<DeviceLogin> {
    device_logins()
        .lock()
        .ok()?
        .values()
        .filter(|login| login.scope == scope)
        .max_by_key(|login| (login.active(), login.started_at))
        .cloned()
}

/// Settle a pending login. A login that has already settled keeps its outcome,
/// so a poll that finishes after a cancel cannot turn it back into `linked`.
fn settle_device_login(login_id: &str, state: DeviceLoginState, error: Option<String>) {
    if let Ok(mut logins) = device_logins().lock() {
        if let Some(login) = logins.get_mut(login_id).filter(|login| login.active()) {
            login.state = state;
            login.error = error;
        }
    }
}

fn jwt_expiry_ms(token: &str) -> Option<i64> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("exp")
        .and_then(Value::as_i64)?
        .checked_mul(1_000)
}

fn account_id_from_jwt(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    // The issuer nests this under a namespaced claim object rather than putting
    // it at the top level. Both call sites below reach this only when the
    // `auth.json` the CLI wrote carries no `tokens.account_id`, so a wrong path
    // here fails open into "stored no ChatGPT account id" rather than anything
    // louder — which is how it survived: the two tests that cover this function
    // supply `tokens.account_id` too, so neither ever took the fallback.
    claims
        .get("https://api.openai.com/auth")?
        .get("chatgpt_account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// The sealed bundle from a token response: the `oauth/token` reply's own
/// field names, with the account id read from the namespaced claim when the
/// reply does not carry it outright.
fn credential_from_tokens(tokens: &Value) -> Result<CodexOAuthCredential, String> {
    let access = tokens
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "OpenAI returned no access token".to_owned())?;
    let refresh = tokens
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "OpenAI returned no refresh token".to_owned())?;
    let account_id = tokens
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            tokens
                .get("id_token")
                .and_then(Value::as_str)
                .and_then(account_id_from_jwt)
        })
        .or_else(|| account_id_from_jwt(access))
        .ok_or_else(|| "OpenAI returned no ChatGPT account id".to_owned())?;
    let expires = jwt_expiry_ms(access)
        .ok_or_else(|| "OpenAI's access token has no usable expiry".to_owned())?;
    Ok(CodexOAuthCredential {
        access: access.to_owned(),
        refresh: refresh.to_owned(),
        expires,
        account_id,
    })
}

// A hosted Home or Hub speaks OpenAI's ChatGPT device authorization itself.
// It is the flow the official Codex CLI drives in
// `codex-rs/login/src/device_code_auth.rs`, read at rust-v0.144.4:
//
//   1. POST `{issuer}/api/accounts/deviceauth/usercode` `{client_id}` answers a
//      `device_auth_id`, the `user_code` a person types at
//      `{issuer}/codex/device`, and a poll `interval` in seconds, as a string.
//   2. POST `{issuer}/api/accounts/deviceauth/token` `{device_auth_id,
//      user_code}` answers 403 (or 404) while the person has not approved, and
//      then an `authorization_code` with the PKCE pair the issuer generated.
//   3. That code is exchanged at `{issuer}/oauth/token` against the issuer's own
//      `deviceauth/callback` redirect, as any PKCE authorization code is.
//
// It used to spawn `codex app-server` to do this, which made the Codex CLI and
// Node a runtime dependency of every process that could start a sign-in. The
// Hub image had neither, so its Account Settings answered every Codex sign-in
// with 502 (gaugewright-cloud WS-744).

/// Upper bound on one device login, the CLI's own: its prompt says the code
/// expires in fifteen minutes.
const DEVICE_LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);

fn issuer() -> String {
    gaugedesk_env::var("CODEX_OAUTH_ISSUER")
        .unwrap_or_else(|| "https://auth.openai.com".to_owned())
        .trim_end_matches('/')
        .to_owned()
}

struct DeviceCode {
    device_auth_id: String,
    user_code: String,
    interval: Duration,
}

#[derive(Deserialize)]
struct AuthorizationCode {
    authorization_code: String,
    code_verifier: String,
}

enum DevicePoll {
    Pending,
    Approved(AuthorizationCode),
}

fn request_device_code(issuer: &str) -> Result<DeviceCode, String> {
    let body: Value = ureq::post(&format!("{issuer}/api/accounts/deviceauth/usercode"))
        .set("accept", "application/json")
        .send_json(json!({ "client_id": CLIENT_ID }))
        .map_err(|error| format!("Codex device authorization failed: {error}"))?
        .into_json()
        .map_err(|error| format!("Codex device authorization was not valid JSON: {error}"))?;
    let field = |name: &str| {
        body.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let device_auth_id = field("device_auth_id")
        .ok_or_else(|| "Codex device authorization returned no device id".to_owned())?;
    let user_code = field("user_code")
        .or_else(|| field("usercode"))
        .ok_or_else(|| "Codex device authorization returned no user code".to_owned())?;
    let interval = body
        .get("interval")
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str()?.trim().parse().ok())
        })
        .unwrap_or(5)
        .clamp(1, 30);
    Ok(DeviceCode {
        device_auth_id,
        user_code,
        interval: Duration::from_secs(interval),
    })
}

fn poll_device_code(issuer: &str, device: &DeviceCode) -> Result<DevicePoll, String> {
    match ureq::post(&format!("{issuer}/api/accounts/deviceauth/token"))
        .set("accept", "application/json")
        .send_json(json!({
            "device_auth_id": device.device_auth_id,
            "user_code": device.user_code,
        })) {
        Ok(response) => response
            .into_json()
            .map(DevicePoll::Approved)
            .map_err(|error| format!("Codex device authorization was not valid JSON: {error}")),
        Err(ureq::Error::Status(403 | 404, _)) => Ok(DevicePoll::Pending),
        Err(error) => Err(format!("Codex device authorization failed: {error}")),
    }
}

fn exchange_authorization_code(
    issuer: &str,
    code: &AuthorizationCode,
) -> Result<CodexOAuthCredential, String> {
    let redirect_uri = format!("{issuer}/deviceauth/callback");
    let tokens: Value = ureq::post(&format!("{issuer}/oauth/token"))
        .set("accept", "application/json")
        .send_form(&[
            ("grant_type", "authorization_code"),
            ("code", code.authorization_code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", CLIENT_ID),
            ("code_verifier", code.code_verifier.as_str()),
        ])
        .map_err(|error| format!("Codex token exchange failed: {error}"))?
        .into_json()
        .map_err(|error| format!("Codex token exchange returned invalid JSON: {error}"))?;
    credential_from_tokens(&tokens)
}

fn random_login_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| format!("create Codex login id: {error}"))?;
    Ok(hex::encode(bytes))
}

fn start_device_login_blocking(
    wb: SharedWorkbench,
    scope: String,
    issuer: String,
) -> Result<Value, String> {
    if let Some(existing) = device_login_for_scope(&scope).filter(DeviceLogin::active) {
        return Ok(existing.projection());
    }
    let device = request_device_code(&issuer)?;
    let login_id = random_login_id()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let login = DeviceLogin {
        login_id: login_id.clone(),
        scope: scope.clone(),
        verification_url: format!("{issuer}/codex/device"),
        user_code: device.user_code.clone(),
        state: DeviceLoginState::Pending,
        error: None,
        cancelled: Arc::clone(&cancelled),
        started_at: now_ms(),
    };
    let projection = login.projection();
    {
        let mut logins = device_logins()
            .lock()
            .map_err(|_| "Codex device-login state is unavailable".to_owned())?;
        // Nothing ever removed a login, so this map grew for the life of the
        // process and every stale entry was another candidate for the lookup
        // above. Settled logins for this scope are dropped as a new one starts.
        logins.retain(|_, login| login.scope != scope || login.active());
        logins.insert(login_id.clone(), login);
    }

    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + DEVICE_LOGIN_WINDOW;
        loop {
            if cancelled.load(Ordering::SeqCst) {
                return;
            }
            match poll_device_code(&issuer, &device) {
                Ok(DevicePoll::Pending) => {}
                Ok(DevicePoll::Approved(code)) => {
                    let linked =
                        exchange_authorization_code(&issuer, &code).and_then(|credential| {
                            if cancelled.load(Ordering::SeqCst) {
                                return Err("Codex device login was cancelled".to_owned());
                            }
                            store_credential_in(
                                &wb,
                                &scope,
                                &credential,
                                BTreeSet::from([ModelExecutionClass::PrivateHome]),
                            )
                        });
                    match linked {
                        Ok(()) => settle_device_login(&login_id, DeviceLoginState::Linked, None),
                        Err(error) => {
                            settle_device_login(&login_id, DeviceLoginState::Failed, Some(error))
                        }
                    }
                    return;
                }
                Err(error) => {
                    settle_device_login(&login_id, DeviceLoginState::Failed, Some(error));
                    return;
                }
            }
            if std::time::Instant::now() + device.interval >= deadline {
                settle_device_login(
                    &login_id,
                    DeviceLoginState::Failed,
                    Some("Codex device code expired before it was approved".to_owned()),
                );
                return;
            }
            std::thread::sleep(device.interval);
        }
    });
    Ok(projection)
}

pub async fn start_home_login_for_scope(
    wb: SharedWorkbench,
    scope: String,
) -> Result<Value, String> {
    tokio::task::spawn_blocking(move || start_device_login_blocking(wb, scope, issuer()))
        .await
        .map_err(|_| "Codex device-login task panicked".to_owned())?
}

/// End this scope's pending device login. Cancelling when nothing is pending
/// is the state the caller asked for, not a failure.
pub fn cancel_home_login_for_scope(scope: &str) {
    if let Some(login) = device_login_for_scope(scope).filter(DeviceLogin::active) {
        login.cancelled.store(true, Ordering::SeqCst);
        settle_device_login(&login.login_id, DeviceLoginState::Cancelled, None);
    }
}

pub async fn post_home_codex_login_start(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let scope = wb
        .lock_unpoisoned()
        .credential_scope_for(net_http::bearer(&headers));
    match start_home_login_for_scope(wb, scope).await {
        Ok(login) => Json(json!({ "mode": "device", "login": login })).into_response(),
        Err(error) => (StatusCode::BAD_GATEWAY, Json(json!({ "error": error }))).into_response(),
    }
}

pub async fn post_home_codex_login_cancel(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let scope = wb
        .lock_unpoisoned()
        .credential_scope_for(net_http::bearer(&headers));
    cancel_home_login_for_scope(&scope);
    StatusCode::NO_CONTENT
}

/// The helper script rides inside the binary: spawning it must not depend on the
/// process cwd or a bundled payload (the packaged app ships no `sidecar/` tree).
/// `GAUGEDESK_CODEX_LOGIN` still points at an on-disk script when set — the
/// dev/test seam for substituting a fake helper.
const HELPER_SOURCE: &str = include_str!("../../../sidecar/codex-oauth-login.mjs");

/// The browser helper waiting for its callback, if one is.
///
/// Its loopback port is fixed and registered with OpenAI, so at most one helper
/// can be live and a second one fails outright with `EADDRINUSE`. Holding the
/// child here is what lets this process end an attempt: a new start supersedes
/// the one it replaces, and the cancel route ends one a person walked away from.
/// Without it the only way back to a working sign-in was to kill the helper by
/// hand — and if the app had exited, the orphan outlived every route that could
/// have known about it.
fn browser_login() -> &'static Mutex<Option<Arc<Mutex<Child>>>> {
    static LOGIN: OnceLock<Mutex<Option<Arc<Mutex<Child>>>>> = OnceLock::new();
    LOGIN.get_or_init(|| Mutex::new(None))
}

/// End whichever browser helper is current. Returns whether there was one.
fn end_browser_login() -> bool {
    // Take the child out from under the slot lock before touching the process:
    // the reader thread holds the child lock across its final `wait`, so holding
    // both here in the other order is a deadlock.
    let Some(child) = browser_login().lock().ok().and_then(|mut slot| slot.take()) else {
        return false;
    };
    if let Ok(mut process) = child.lock() {
        let _ = process.kill();
        let _ = process.wait();
    }
    true
}

/// Drop `child` from the slot if it is still the current helper. A later start
/// may already have superseded it, and that one is not this thread's to clear.
fn forget_browser_login(child: &Arc<Mutex<Child>>) {
    if let Ok(mut slot) = browser_login().lock() {
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, child))
        {
            *slot = None;
        }
    }
}

/// End this particular helper: the failure paths of a start that already
/// registered one, where killing whatever is current could kill a later attempt.
fn end_browser_login_child(child: &Arc<Mutex<Child>>) {
    if let Ok(mut process) = child.lock() {
        let _ = process.kill();
        let _ = process.wait();
    }
    forget_browser_login(child);
}

/// Start the helper, return the authorization URL, then retain its private pipe
/// in a background thread until the credential bundle can be sealed.
fn start_login_blocking(wb: SharedWorkbench, scope: String) -> Result<String, String> {
    // An earlier attempt still holds the callback port, and the person asking for
    // this one is not going back to it. Superseding here is what keeps a start
    // from failing on the wait the previous start is still doing.
    end_browser_login();
    let mut command = Command::new(node_bin());
    let override_path = gaugedesk_env::var("CODEX_LOGIN");
    match &override_path {
        Some(path) => {
            command.arg(path).stdin(Stdio::null());
        }
        None => {
            // `node --input-type=module -` runs the embedded ESM source from stdin.
            command
                .arg("--input-type=module")
                .arg("-")
                .stdin(Stdio::piped());
        }
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn Codex login helper: {error}"))?;
    if override_path.is_none() {
        use std::io::Write;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "Codex login helper exposed no input pipe".to_owned())?;
        stdin
            .write_all(HELPER_SOURCE.as_bytes())
            .map_err(|error| format!("Codex login helper feed: {error}"))?;
        // Dropping the handle closes the pipe so node sees EOF and runs the program.
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Codex login helper exposed no output pipe".to_owned())?;
    let mut stderr = child.stderr.take();
    // Current from here on, not from the URL: the helper binds the callback port
    // before it emits one, so a start that fails after this point has something
    // to reclaim too.
    let child = Arc::new(Mutex::new(child));
    if let Ok(mut slot) = browser_login().lock() {
        *slot = Some(Arc::clone(&child));
    }
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    for _ in 0..6 {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                end_browser_login_child(&child);
                return Err(format!("Codex login helper read: {error}"));
            }
        }
        let Ok(event) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        match event.get("event").and_then(Value::as_str) {
            Some("auth_url") => {
                let Some(url) = event.get("url").and_then(Value::as_str).map(str::to_owned) else {
                    end_browser_login_child(&child);
                    return Err("Codex login helper returned no URL".to_owned());
                };
                // Drain stderr so a chatty helper can never block on a full pipe.
                if let Some(mut pipe) = stderr.take() {
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut pipe, &mut std::io::sink());
                    });
                }
                std::thread::spawn(move || {
                    let mut result = String::new();
                    while reader
                        .read_line(&mut result)
                        .map(|count| count > 0)
                        .unwrap_or(false)
                    {
                        if let Ok(event) = serde_json::from_str::<Value>(result.trim()) {
                            if event.get("event").and_then(Value::as_str) == Some("linked") {
                                if let Ok(credential) =
                                    serde_json::from_value::<CodexOAuthCredential>(event)
                                {
                                    // Into the account that started the
                                    // sign-in, not whichever is selected
                                    // when the browser answers (DR-0313).
                                    let _ = store_credential_in(
                                        &wb,
                                        &scope,
                                        &credential,
                                        BTreeSet::from([ModelExecutionClass::LocalInteractive]),
                                    );
                                }
                            }
                        }
                        result.clear();
                    }
                    // Stdout closed, so the helper is on its way out either way:
                    // it linked, it timed out, or a cancel killed it.
                    if let Ok(mut process) = child.lock() {
                        let _ = process.wait();
                    }
                    forget_browser_login(&child);
                });
                return Ok(url);
            }
            Some("error") => {
                end_browser_login_child(&child);
                return Err(event
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("Codex login failed")
                    .to_owned());
            }
            _ => {}
        }
    }
    end_browser_login_child(&child);
    // The helper died before emitting a URL; its stderr is the actual reason
    // (e.g. a missing node module) — surface it instead of a blind 502.
    let mut detail = String::new();
    if let Some(mut pipe) = stderr.take() {
        use std::io::Read;
        let _ = pipe.read_to_string(&mut detail);
    }
    let detail = detail.trim();
    if detail.is_empty() {
        Err("Codex login helper produced no authorization URL".to_owned())
    } else {
        Err(format!(
            "Codex login helper produced no authorization URL: {detail}"
        ))
    }
}

/// End the desktop browser sign-in.
///
/// The helper holds the fixed loopback callback port for as long as it waits, so
/// an abandoned sign-in has to be endable from the UI: its own timeout is
/// measured in minutes, and until this route existed the browser half of the
/// cancel button dropped the waiting state locally and left the port held.
/// Answers 204 either way — "there is no sign-in in flight" is the state the
/// caller asked for.
pub async fn post_codex_login_cancel() -> impl IntoResponse {
    let _ = tokio::task::spawn_blocking(end_browser_login).await;
    StatusCode::NO_CONTENT
}

pub async fn post_codex_login_start(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let scope = wb
        .lock_unpoisoned()
        .credential_scope_for(net_http::bearer(&headers));
    match tokio::task::spawn_blocking(move || start_login_blocking(wb, scope)).await {
        Ok(Ok(url)) => Json(json!({ "mode": "browser", "url": url })).into_response(),
        Ok(Err(error)) => {
            (StatusCode::BAD_GATEWAY, Json(json!({ "error": error }))).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Codex login task panicked",
        )
            .into_response(),
    }
}

fn refresh_credential(credential: &CodexOAuthCredential) -> Result<CodexOAuthCredential, String> {
    let response = ureq::post(TOKEN_URL)
        .set("content-type", "application/x-www-form-urlencoded")
        .send_form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", credential.refresh.as_str()),
            ("client_id", CLIENT_ID),
        ])
        .map_err(|error| format!("Codex token refresh failed: {error}"))?;
    let body: Value = response
        .into_json()
        .map_err(|error| format!("Codex token refresh returned invalid JSON: {error}"))?;
    let access = body
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "Codex token refresh returned no access token".to_owned())?;
    let refresh = body
        .get("refresh_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "Codex token refresh returned no refresh token".to_owned())?;
    let expires_in = body
        .get("expires_in")
        .and_then(Value::as_i64)
        .ok_or_else(|| "Codex token refresh returned no expiry".to_owned())?;
    Ok(CodexOAuthCredential {
        access: access.to_owned(),
        refresh: refresh.to_owned(),
        expires: now_ms() + expires_in * 1_000,
        account_id: credential.account_id.clone(),
    })
}

/// Resolve the short-lived material used for one turn. Refresh runs outside the
/// workbench lock; a successful replacement is sealed before it is returned.
pub fn resolve_runtime_credential(
    wb: &SharedWorkbench,
) -> Result<Option<CodexRuntimeCredential>, String> {
    resolve_runtime_credential_in(wb, ACCOUNT_SCOPE, ModelExecutionClass::LocalInteractive)
}

/// Resolve the structured Codex credential for the turn's exact execution class.
/// Desktop owns the legacy singleton account scope; a hosted private Home owns
/// the authenticated person's account scope. Public deployments never receive
/// subscription credentials.
pub fn resolve_turn_credential(
    wb: &SharedWorkbench,
    actor: &str,
    execution_class: ModelExecutionClass,
) -> Result<Option<CodexRuntimeCredential>, String> {
    match execution_class {
        ModelExecutionClass::LocalInteractive => {
            let scope = wb.lock_unpoisoned().account_scope_for_actor(actor);
            resolve_runtime_credential_in(wb, &scope, ModelExecutionClass::LocalInteractive)
        }
        ModelExecutionClass::PrivateHome => resolve_runtime_credential_in(
            wb,
            &crate::account::account_scope(actor),
            ModelExecutionClass::PrivateHome,
        ),
        ModelExecutionClass::PublicDeployment => Ok(None),
    }
}

/// Resolve one scoped Codex credential for an admitted execution class. This is
/// the Home broker seam: refresh material remains sealed in the Home and only
/// the short-lived access/account pair reaches the exact provider egress call.
pub fn resolve_runtime_credential_in(
    wb: &SharedWorkbench,
    scope: &str,
    execution_class: ModelExecutionClass,
) -> Result<Option<CodexRuntimeCredential>, String> {
    let Some((mut credential, execution_classes)) = load_credential_in(wb, scope, execution_class)
    else {
        return Ok(None);
    };
    if credential.expires <= now_ms() + REFRESH_SKEW_MS {
        credential = refresh_credential(&credential)?;
        store_credential_in(wb, scope, &credential, execution_classes)?;
    }
    Ok(Some(CodexRuntimeCredential {
        access: credential.access,
        account_id: credential.account_id,
    }))
}

/// Version-bound variant used by the hosted broker after WhippleScript admits
/// an opaque credential ref. A refresh is committed only if that exact version
/// is still current, so a concurrent re-link cannot retarget an in-flight ref.
pub fn resolve_runtime_credential_versioned_in(
    wb: &SharedWorkbench,
    scope: &str,
    execution_class: ModelExecutionClass,
    expected_version: u64,
) -> Result<Option<CodexRuntimeCredential>, String> {
    let Some((mut credential, execution_classes, version)) =
        load_versioned_credential_in(wb, scope, execution_class)
    else {
        return Ok(None);
    };
    if version != expected_version {
        return Ok(None);
    }
    if credential.expires <= now_ms() + REFRESH_SKEW_MS {
        credential = refresh_credential(&credential)?;
        let plaintext = serde_json::to_string(&credential).map_err(|error| error.to_string())?;
        let mut workbench = wb.lock_unpoisoned();
        let still_current = credentials_in_scope(workbench.store_ref(), scope)
            .get(PROVIDER)
            .is_some_and(|record| {
                record.version == expected_version
                    && record.authentication == CredentialAuthentication::OAuth
                    && record.admits(execution_class)
            });
        if !still_current {
            return Ok(None);
        }
        let sealed = seal_token(workbench.account_key(), &plaintext)
            .ok_or_else(|| "could not seal Codex OAuth credential".to_owned())?;
        workbench
            .upsert_account_credential_in_with_policy(
                scope,
                PROVIDER.to_owned(),
                sealed,
                String::new(),
                execution_classes,
            )
            .map_err(|error| format!("could not store Codex OAuth credential: {error:?}"))?;
    }
    Ok(Some(CodexRuntimeCredential {
        access: credential.access,
        account_id: credential.account_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seed a login directly: these tests are about the lookup, not about
    /// the issuer.
    fn seed_login(scope: &str, login_id: &str, state: DeviceLoginState, started_at: i64) {
        device_logins().lock().unwrap().insert(
            login_id.to_owned(),
            DeviceLogin {
                login_id: login_id.to_owned(),
                scope: scope.to_owned(),
                verification_url: "https://example.invalid/device".into(),
                user_code: login_id.to_owned(),
                state,
                error: None,
                cancelled: Arc::new(AtomicBool::new(false)),
                started_at,
            },
        );
    }

    /// The status route must answer with the login a person is part-way
    /// through, not with whichever id sorts first.
    ///
    /// The map is keyed by a random `login_id`, so `find` returned an arbitrary
    /// login — in production it answered `2d94d963…` while the caller had just
    /// started `a8a8ebbb…`, purely because the first sorts lower.
    #[test]
    fn the_current_login_wins_over_one_that_merely_sorts_first() {
        let scope = "scope:codex-lookup-active";
        seed_login(scope, "0000-settled", DeviceLoginState::Failed, 100);
        seed_login(scope, "ffff-pending", DeviceLoginState::Pending, 50);

        let found = device_login_for_scope(scope).expect("a login for the scope");
        assert_eq!(
            found.login_id, "ffff-pending",
            "an active login is the current one even when another sorts first \
             and even when it started earlier",
        );
    }

    /// With nothing active, the most recent outcome is the useful one.
    #[test]
    fn the_newest_settled_login_is_reported_when_none_is_active() {
        let scope = "scope:codex-lookup-settled";
        seed_login(scope, "aaaa-older", DeviceLoginState::Failed, 10);
        seed_login(scope, "zzzz-newer", DeviceLoginState::Linked, 20);

        let found = device_login_for_scope(scope).expect("a login for the scope");
        assert_eq!(found.login_id, "zzzz-newer");
        assert_eq!(found.state, DeviceLoginState::Linked);
    }

    /// A scope with no login at all is still `None`, and scopes do not bleed.
    #[test]
    fn a_login_belongs_to_exactly_one_scope() {
        seed_login(
            "scope:codex-owner",
            "owner-login",
            DeviceLoginState::Pending,
            1,
        );
        assert!(device_login_for_scope("scope:codex-stranger").is_none());
        assert_eq!(
            device_login_for_scope("scope:codex-owner")
                .unwrap()
                .login_id,
            "owner-login",
        );
    }

    #[test]
    fn legacy_codex_record_migrates_once_to_explicit_local_oauth() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let credential = CodexOAuthCredential {
            access: "access".into(),
            refresh: "refresh".into(),
            expires: i64::MAX,
            account_id: "account".into(),
        };
        let plaintext = serde_json::to_string(&credential).unwrap();
        let sealed = {
            let workbench = wb.lock_unpoisoned();
            seal_token(workbench.account_key(), &plaintext).unwrap()
        };
        let legacy = crate::account::CredentialRecord {
            id: PROVIDER.into(),
            op: crate::library::RecordOp::Upsert,
            sealed_token: sealed,
            base_url: String::new(),
            version: 1,
            authentication: CredentialAuthentication::Bearer,
            status: crate::account::CredentialStatus::Active,
            execution_classes: BTreeSet::from([ModelExecutionClass::LocalInteractive]),
        };
        wb.lock_unpoisoned()
            .store_mut()
            .append_record(
                ACCOUNT_SCOPE,
                "credential",
                &serde_json::to_string(&legacy).unwrap(),
            )
            .unwrap();

        ensure_local_credential_record(&wb).unwrap();
        ensure_local_credential_record(&wb).unwrap();
        let current = credentials_in_scope(wb.lock_unpoisoned().store_ref(), ACCOUNT_SCOPE)
            .remove(PROVIDER)
            .unwrap();
        assert_eq!(current.version, 2, "migration is one-time");
        assert_eq!(current.authentication, CredentialAuthentication::OAuth);
        assert_eq!(
            current.execution_classes,
            BTreeSet::from([ModelExecutionClass::LocalInteractive])
        );
    }

    #[test]
    fn credential_bundle_round_trips_without_changing_wire_names() {
        let credential = CodexOAuthCredential {
            access: "access".to_owned(),
            refresh: "refresh".to_owned(),
            expires: 42,
            account_id: "account".to_owned(),
        };
        let value = serde_json::to_value(&credential).expect("serialize");
        assert_eq!(value["accountId"], "account");
        assert_eq!(
            serde_json::from_value::<CodexOAuthCredential>(value).expect("deserialize"),
            credential
        );
    }

    #[test]
    fn token_response_is_imported_without_returning_secret_fields() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"exp":4102444800,"chatgpt_account_id":"acct-home"}"#);
        let access = format!("{header}.{claims}.signature");
        let credential = credential_from_tokens(&json!({
            "id_token": access,
            "access_token": access,
            "refresh_token": "refresh-home",
            "account_id": "acct-home"
        }))
        .unwrap();
        assert_eq!(credential.account_id, "acct-home");
        assert_eq!(credential.expires, 4_102_444_800_000);
        assert_eq!(credential.refresh, "refresh-home");
    }

    // Exercises the JWT fallback. The payload is the shape the issuer really
    // mints: the account id sits inside the `https://api.openai.com/auth` claim
    // object, so a reader that looks for a top-level `chatgpt_account_id` finds
    // nothing. The `oauth/token` reply carries no `account_id` of its own, so
    // every real sign-in takes this path.
    #[test]
    fn account_id_falls_back_to_the_namespaced_access_token_claim() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"exp":4102444800,"https://api.openai.com/auth":{"chatgpt_account_id":"acct-nested","chatgpt_plan_type":"pro"}}"#,
        );
        let access = format!("{header}.{claims}.signature");
        let credential = credential_from_tokens(&json!({
            "id_token": access,
            "access_token": access,
            "refresh_token": "refresh-nested"
        }))
        .unwrap();
        assert_eq!(credential.account_id, "acct-nested");
    }

    #[test]
    fn account_id_is_not_read_from_a_flat_claim_the_issuer_never_mints() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"exp":4102444800,"chatgpt_account_id":"acct-flat"}"#);
        let access = format!("{header}.{claims}.signature");
        assert_eq!(account_id_from_jwt(&access), None);
    }

    #[test]
    fn hosted_resolution_is_bound_to_the_admitted_credential_version() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let scope = crate::account::account_scope("person:home");
        let credential = CodexOAuthCredential {
            access: "access".into(),
            refresh: "refresh".into(),
            expires: i64::MAX,
            account_id: "account".into(),
        };
        store_credential_in(
            &wb,
            &scope,
            &credential,
            BTreeSet::from([ModelExecutionClass::PrivateHome]),
        )
        .unwrap();

        assert!(resolve_runtime_credential_versioned_in(
            &wb,
            &scope,
            ModelExecutionClass::PrivateHome,
            1,
        )
        .unwrap()
        .is_some());
        assert!(resolve_runtime_credential_versioned_in(
            &wb,
            &scope,
            ModelExecutionClass::PrivateHome,
            2,
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn turn_resolution_preserves_private_home_account_id_and_denies_public_use() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let actor = "person:hosted";
        let credential = CodexOAuthCredential {
            access: "access-private".into(),
            refresh: "refresh-private".into(),
            expires: i64::MAX,
            account_id: "account-private".into(),
        };
        store_credential_in(
            &wb,
            &crate::account::account_scope(actor),
            &credential,
            BTreeSet::from([ModelExecutionClass::PrivateHome]),
        )
        .unwrap();

        assert_eq!(
            resolve_turn_credential(&wb, actor, ModelExecutionClass::PrivateHome).unwrap(),
            Some(CodexRuntimeCredential {
                access: "access-private".into(),
                account_id: "account-private".into(),
            })
        );
        assert!(
            resolve_turn_credential(&wb, actor, ModelExecutionClass::PublicDeployment)
                .unwrap()
                .is_none()
        );
    }

    /// A stand-in for OpenAI's issuer that answers the three device-login calls
    /// the way the real one does: a string interval, 403 until the person has
    /// approved, then an authorization code carrying the PKCE verifier the
    /// issuer generated. It records the token-exchange form it was sent.
    struct FakeIssuer {
        url: String,
        exchanged: Arc<Mutex<Option<String>>>,
    }

    fn fake_issuer(pending_polls: usize, access: String) -> FakeIssuer {
        use axum::routing::post;
        use std::sync::atomic::AtomicUsize;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let exchanged = Arc::new(Mutex::new(None));
        let polls = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::clone(&exchanged);
        let router = axum::Router::new()
            .route(
                "/api/accounts/deviceauth/usercode",
                post(|Json(body): Json<Value>| async move {
                    assert_eq!(body, json!({ "client_id": CLIENT_ID }));
                    Json(json!({
                        "device_auth_id": "deviceauth_test",
                        "user_code": "ABCD-1234",
                        "interval": "1",
                    }))
                }),
            )
            .route(
                "/api/accounts/deviceauth/token",
                post(move |Json(body): Json<Value>| async move {
                    assert_eq!(
                        body,
                        json!({ "device_auth_id": "deviceauth_test", "user_code": "ABCD-1234" })
                    );
                    if polls.fetch_add(1, Ordering::SeqCst) < pending_polls {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(
                                json!({ "error": { "code": "deviceauth_authorization_pending" } }),
                            ),
                        );
                    }
                    (
                        StatusCode::OK,
                        Json(json!({
                            "authorization_code": "code-test",
                            "code_challenge": "challenge-test",
                            "code_verifier": "verifier-test",
                        })),
                    )
                }),
            )
            .route(
                "/oauth/token",
                post(move |form: String| async move {
                    *recorded.lock().unwrap() = Some(form);
                    Json(json!({
                        "id_token": access,
                        "access_token": access,
                        "refresh_token": "refresh-device",
                    }))
                }),
            );
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    axum::serve(listener, router).await.unwrap();
                });
        });
        FakeIssuer { url, exchanged }
    }

    fn wait_for_settled(scope: &str) -> Option<DeviceLoginState> {
        // A test synchronization bound, not a product deadline: leave room for
        // a loaded gate host to schedule the polling thread.
        for _ in 0..1000 {
            match device_login_for_scope(scope) {
                Some(login) if !login.active() => return Some(login.state),
                _ => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        device_login_for_scope(scope).map(|login| login.state)
    }

    #[test]
    fn device_login_completion_seals_only_the_bound_home_person_scope() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        workbench.lock_unpoisoned().enable_hosted_home_mode();
        let scope = crate::account::account_scope("person:device-flow");

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"exp":4102444800,"https://api.openai.com/auth":{"chatgpt_account_id":"acct-device"}}"#,
        );
        let access = format!("{header}.{claims}.signature");
        // One unapproved poll first, so the 403-means-pending path is the one
        // that reaches the approval.
        let issuer = fake_issuer(1, access.clone());

        let projection =
            start_device_login_blocking(workbench.clone(), scope.clone(), issuer.url.clone())
                .unwrap();
        assert_eq!(projection["user_code"], "ABCD-1234");
        assert_eq!(
            projection["verification_url"],
            format!("{}/codex/device", issuer.url)
        );
        assert_eq!(projection["status"], "pending");
        assert_eq!(wait_for_settled(&scope), Some(DeviceLoginState::Linked));

        let form = issuer.exchanged.lock().unwrap().clone().unwrap();
        let fields: BTreeMap<String, String> = url::form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(fields["grant_type"], "authorization_code");
        assert_eq!(fields["code"], "code-test");
        assert_eq!(fields["code_verifier"], "verifier-test");
        assert_eq!(fields["client_id"], CLIENT_ID);
        assert_eq!(
            fields["redirect_uri"],
            format!("{}/deviceauth/callback", issuer.url)
        );

        let records = credentials_in_scope(workbench.lock_unpoisoned().store_ref(), &scope);
        let record = records.get(PROVIDER).unwrap();
        assert!(record.admits(ModelExecutionClass::PrivateHome));
        assert!(!record.admits(ModelExecutionClass::PublicDeployment));
        let (credential, _) =
            load_credential_in(&workbench, &scope, ModelExecutionClass::PrivateHome).unwrap();
        assert_eq!(credential.account_id, "acct-device");
        assert_eq!(credential.refresh, "refresh-device");
        assert_eq!(credential.expires, 4_102_444_800_000);
        assert!(!credentials_in_scope(
            workbench.lock_unpoisoned().store_ref(),
            &crate::account::account_scope("person:someone-else")
        )
        .contains_key(PROVIDER));
    }

    /// A cancelled login settles at once and never links, even though the
    /// polling thread only notices on its next wake.
    #[test]
    fn a_cancelled_device_login_never_links() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        workbench.lock_unpoisoned().enable_hosted_home_mode();
        let scope = crate::account::account_scope("person:device-cancel");
        let issuer = fake_issuer(usize::MAX, String::new());

        start_device_login_blocking(workbench.clone(), scope.clone(), issuer.url.clone()).unwrap();
        cancel_home_login_for_scope(&scope);
        assert_eq!(
            device_login_for_scope(&scope).map(|login| login.state),
            Some(DeviceLoginState::Cancelled)
        );
        // Past the poll interval: the thread has woken, seen the flag, and left.
        std::thread::sleep(std::time::Duration::from_millis(1_500));
        assert_eq!(
            device_login_for_scope(&scope).map(|login| login.state),
            Some(DeviceLoginState::Cancelled)
        );
        assert!(issuer.exchanged.lock().unwrap().is_none());
        assert!(
            !credentials_in_scope(workbench.lock_unpoisoned().store_ref(), &scope)
                .contains_key(PROVIDER)
        );
        // Cancelling nothing is the state the caller asked for.
        cancel_home_login_for_scope(&scope);
    }

    /// The browser helper holds one fixed loopback port for as long as it waits,
    /// so a helper this process forgets about is a sign-in nobody can start.
    ///
    /// Observed 2026-08-14: a helper spawned hours earlier still held
    /// `127.0.0.1:1455`, its app long gone, and every attempt after it failed
    /// with `EADDRINUSE`. Nothing here could end one — the browser flow had no
    /// cancel route and start did not supersede.
    ///
    /// One test for both ends because the slot is process-global; two would race
    /// each other rather than the thing they describe.
    #[cfg(unix)]
    #[test]
    fn a_browser_sign_in_is_superseded_by_the_next_and_endable_by_cancel() {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        // Stands in for a helper that has emitted its URL and is now waiting on a
        // browser that never comes back.
        let helper = root.path().join("fake-login.mjs");
        std::fs::write(
            &helper,
            r#"process.stdout.write(JSON.stringify({ event: "auth_url", url: "https://example.invalid/authorize" }) + "\n");
setInterval(() => {}, 60000);
"#,
        )
        .unwrap();
        std::env::set_var("GAUGEDESK_CODEX_LOGIN", &helper);

        let url = start_login_blocking(workbench.clone(), ACCOUNT_SCOPE.to_owned()).unwrap();
        assert_eq!(url, "https://example.invalid/authorize");
        let first = browser_login().lock().unwrap().clone().unwrap();

        start_login_blocking(workbench.clone(), ACCOUNT_SCOPE.to_owned()).unwrap();
        let second = browser_login().lock().unwrap().clone().unwrap();
        assert_ne!(first.lock().unwrap().id(), second.lock().unwrap().id());
        // Killed and reaped by the start that replaced it, not merely dropped:
        // dropping a `Child` leaves the process running, which is the whole bug.
        assert!(first.lock().unwrap().try_wait().unwrap().is_some());

        assert!(end_browser_login());
        assert!(second.lock().unwrap().try_wait().unwrap().is_some());
        assert!(browser_login().lock().unwrap().is_none());
        // Cancelling nothing is the state the caller asked for, not a failure.
        assert!(!end_browser_login());

        std::env::remove_var("GAUGEDESK_CODEX_LOGIN");
    }
}
