//! GaugeDesk-owned OpenAI Codex OAuth lifecycle (LLM-1, ADR 0062).
//!
//! Desktop uses the loopback PKCE helper. A hosted Home drives the official Codex
//! app-server device-code flow in a short-lived, isolated `CODEX_HOME`, immediately
//! imports the resulting bundle into the authenticated person's sealed Home scope,
//! and deletes the temporary Codex store. The browser and Durable Objects receive
//! only a verification code/status; neither Pi nor WhippleScript owns credentials.

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
use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

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
    workbench.advance_onboarding("credential", &json!({ "provider": PROVIDER }).to_string());
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
            workbench.account_scope_for(net_http::bearer(headers)),
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

fn node_bin() -> String {
    gaugedesk_env::var("NODE_BIN").unwrap_or_else(|| "node".to_owned())
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DeviceLoginState {
    Pending,
    Cancelling,
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
    stdin: Option<Arc<Mutex<ChildStdin>>>,
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
        matches!(
            self.state,
            DeviceLoginState::Pending | DeviceLoginState::Cancelling
        )
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
/// first-sorting login was inactive and spawned a second app-server for a scope
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

fn set_device_login_state(login_id: &str, state: DeviceLoginState, error: Option<String>) {
    if let Ok(mut logins) = device_logins().lock() {
        if let Some(login) = logins.get_mut(login_id) {
            login.state = state;
            login.error = error;
            if !login.active() {
                login.stdin = None;
            }
        }
    }
}

fn write_rpc(stdin: &mut ChildStdin, message: Value) -> Result<(), String> {
    serde_json::to_writer(&mut *stdin, &message)
        .map_err(|error| format!("encode Codex app-server request: {error}"))?;
    stdin
        .write_all(b"\n")
        .and_then(|_| stdin.flush())
        .map_err(|error| format!("write Codex app-server request: {error}"))
}

fn read_rpc_response(reader: &mut BufReader<impl std::io::Read>, id: i64) -> Result<Value, String> {
    let mut line = String::new();
    loop {
        line.clear();
        let count = reader
            .read_line(&mut line)
            .map_err(|error| format!("read Codex app-server response: {error}"))?;
        if count == 0 {
            return Err("Codex app-server stopped before replying".to_owned());
        }
        let Ok(message) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if message.get("id").and_then(Value::as_i64) != Some(id) {
            continue;
        }
        if let Some(error) = message.get("error") {
            return Err(format!("Codex app-server rejected the request: {error}"));
        }
        return message
            .get("result")
            .cloned()
            .ok_or_else(|| "Codex app-server returned no result".to_owned());
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

fn read_codex_auth(path: &std::path::Path) -> Result<CodexOAuthCredential, String> {
    let encoded = std::fs::read_to_string(path.join("auth.json"))
        .map_err(|error| format!("read isolated Codex credential: {error}"))?;
    let auth: Value = serde_json::from_str(&encoded)
        .map_err(|error| format!("parse isolated Codex credential: {error}"))?;
    let tokens = auth
        .get("tokens")
        .ok_or_else(|| "Codex app-server stored no ChatGPT tokens".to_owned())?;
    let access = tokens
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Codex app-server stored no access token".to_owned())?;
    let refresh = tokens
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Codex app-server stored no refresh token".to_owned())?;
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
        .ok_or_else(|| "Codex app-server stored no ChatGPT account id".to_owned())?;
    let expires = jwt_expiry_ms(access)
        .ok_or_else(|| "Codex app-server access token has no usable expiry".to_owned())?;
    Ok(CodexOAuthCredential {
        access: access.to_owned(),
        refresh: refresh.to_owned(),
        expires,
        account_id,
    })
}

fn codex_bin() -> String {
    gaugedesk_env::var("CODEX_BIN").unwrap_or_else(|| "codex".to_owned())
}

fn start_device_login_blocking(wb: SharedWorkbench, scope: String) -> Result<Value, String> {
    if let Some(existing) = device_login_for_scope(&scope).filter(DeviceLogin::active) {
        return Ok(existing.projection());
    }

    let codex_home = tempfile::Builder::new()
        .prefix("gaugewright-codex-login-")
        .tempdir()
        .map_err(|error| format!("create isolated Codex login store: {error}"))?;
    std::fs::write(
        codex_home.path().join("config.toml"),
        "cli_auth_credentials_store = \"file\"\n",
    )
    .map_err(|error| format!("configure isolated Codex login store: {error}"))?;

    let mut child = Command::new(codex_bin())
        .arg("app-server")
        .env("CODEX_HOME", codex_home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn Codex app-server: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Codex app-server exposed no input pipe".to_owned())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Codex app-server exposed no output pipe".to_owned())?;
    if let Some(mut stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        });
    }
    let mut reader = BufReader::new(stdout);
    write_rpc(
        &mut stdin,
        json!({
            "method": "initialize",
            "id": 1,
            "params": {
                "clientInfo": {
                    "name": "gaugewright",
                    "title": "GaugeWright",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            }
        }),
    )?;
    let _ = read_rpc_response(&mut reader, 1)?;
    write_rpc(&mut stdin, json!({ "method": "initialized", "params": {} }))?;
    write_rpc(
        &mut stdin,
        json!({
            "method": "account/login/start",
            "id": 2,
            "params": { "type": "chatgptDeviceCode" }
        }),
    )?;
    let result = read_rpc_response(&mut reader, 2)?;
    let login_id = result
        .get("loginId")
        .and_then(Value::as_str)
        .ok_or_else(|| "Codex app-server returned no login id".to_owned())?
        .to_owned();
    let verification_url = result
        .get("verificationUrl")
        .and_then(Value::as_str)
        .ok_or_else(|| "Codex app-server returned no verification URL".to_owned())?
        .to_owned();
    let user_code = result
        .get("userCode")
        .and_then(Value::as_str)
        .ok_or_else(|| "Codex app-server returned no user code".to_owned())?
        .to_owned();
    let shared_stdin = Arc::new(Mutex::new(stdin));
    let login = DeviceLogin {
        login_id: login_id.clone(),
        scope: scope.clone(),
        verification_url,
        user_code,
        state: DeviceLoginState::Pending,
        error: None,
        stdin: Some(shared_stdin),
        started_at: now_ms(),
    };
    let projection = login.projection();
    {
        let mut logins = device_logins()
            .lock()
            .map_err(|_| "Codex device-login state is unavailable".to_owned())?;
        // Nothing ever removed a login, so this map grew for the life of the
        // process and every stale entry was another candidate for the lookup
        // above. Settled logins for this scope are dropped as a new one starts:
        // `set_device_login_state` clears `stdin` the moment a login stops being
        // active, so a non-active entry holds no live process and removing it
        // cannot orphan one.
        logins.retain(|_, login| login.scope != scope || login.active());
        logins.insert(login_id.clone(), login);
    }

    std::thread::spawn(move || {
        let mut line = String::new();
        let mut completed = false;
        while reader
            .read_line(&mut line)
            .map(|count| count > 0)
            .unwrap_or(false)
        {
            let message = serde_json::from_str::<Value>(line.trim()).ok();
            line.clear();
            let Some(params) = message
                .as_ref()
                .filter(|message| {
                    message.get("method").and_then(Value::as_str) == Some("account/login/completed")
                })
                .and_then(|message| message.get("params"))
            else {
                continue;
            };
            if params.get("loginId").and_then(Value::as_str) != Some(login_id.as_str()) {
                continue;
            }
            if params.get("success").and_then(Value::as_bool) == Some(true) {
                let stored = read_codex_auth(codex_home.path()).and_then(|credential| {
                    store_credential_in(
                        &wb,
                        &scope,
                        &credential,
                        BTreeSet::from([ModelExecutionClass::PrivateHome]),
                    )
                });
                match stored {
                    Ok(()) => set_device_login_state(&login_id, DeviceLoginState::Linked, None),
                    Err(error) => {
                        set_device_login_state(&login_id, DeviceLoginState::Failed, Some(error))
                    }
                }
            } else {
                let cancelled = device_logins()
                    .lock()
                    .ok()
                    .and_then(|logins| logins.get(&login_id).map(|login| login.state))
                    == Some(DeviceLoginState::Cancelling);
                let error = params
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                set_device_login_state(
                    &login_id,
                    if cancelled {
                        DeviceLoginState::Cancelled
                    } else {
                        DeviceLoginState::Failed
                    },
                    error,
                );
            }
            completed = true;
            break;
        }
        if !completed {
            let cancelling = device_logins()
                .lock()
                .ok()
                .and_then(|logins| logins.get(&login_id).map(|login| login.state))
                == Some(DeviceLoginState::Cancelling);
            set_device_login_state(
                &login_id,
                if cancelling {
                    DeviceLoginState::Cancelled
                } else {
                    DeviceLoginState::Failed
                },
                if cancelling {
                    None
                } else {
                    Some("Codex app-server stopped before login completed".to_owned())
                },
            );
        }
        let _ = child.kill();
        let _ = child.wait();
    });
    Ok(projection)
}

pub async fn post_home_codex_login_start(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let scope = wb
        .lock_unpoisoned()
        .account_scope_for(net_http::bearer(&headers));
    match tokio::task::spawn_blocking(move || start_device_login_blocking(wb, scope)).await {
        Ok(Ok(login)) => Json(json!({ "mode": "device", "login": login })).into_response(),
        Ok(Err(error)) => {
            (StatusCode::BAD_GATEWAY, Json(json!({ "error": error }))).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Codex device-login task panicked",
        )
            .into_response(),
    }
}

pub async fn post_home_codex_login_cancel(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let scope = wb
        .lock_unpoisoned()
        .account_scope_for(net_http::bearer(&headers));
    let login = device_login_for_scope(&scope).filter(DeviceLogin::active);
    let Some(login) = login else {
        return StatusCode::NO_CONTENT.into_response();
    };
    // Mark cancellation before the RPC write: a fast app-server may emit the
    // completion notification before this handler regains the state lock.
    set_device_login_state(&login.login_id, DeviceLoginState::Cancelling, None);
    let sent = login
        .stdin
        .as_ref()
        .and_then(|stdin| stdin.lock().ok())
        .map(|mut stdin| {
            write_rpc(
                &mut stdin,
                json!({
                    "method": "account/login/cancel",
                    "id": 3,
                    "params": { "loginId": login.login_id }
                }),
            )
        });
    match sent {
        Some(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        _ => {
            set_device_login_state(
                &login.login_id,
                DeviceLoginState::Failed,
                Some("could not cancel Codex device login".to_owned()),
            );
            (
                StatusCode::BAD_GATEWAY,
                "could not cancel Codex device login",
            )
                .into_response()
        }
    }
}

/// The helper script rides inside the binary: spawning it must not depend on the
/// process cwd or a bundled payload (the packaged app ships no `sidecar/` tree).
/// `GAUGEDESK_CODEX_LOGIN` still points at an on-disk script when set — the
/// dev/test seam for substituting a fake helper.
const HELPER_SOURCE: &str = include_str!("../../../sidecar/codex-oauth-login.mjs");

/// Start the helper, return the authorization URL, then retain its private pipe
/// in a background thread until the credential bundle can be sealed.
fn start_login_blocking(wb: SharedWorkbench) -> Result<String, String> {
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
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    for _ in 0..6 {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => return Err(format!("Codex login helper read: {error}")),
        }
        let Ok(event) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        match event.get("event").and_then(Value::as_str) {
            Some("auth_url") => {
                let url = event
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "Codex login helper returned no URL".to_owned())?
                    .to_owned();
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
                                    let _ = store_credential(&wb, &credential);
                                }
                            }
                        }
                        result.clear();
                    }
                    let _ = child.wait();
                });
                return Ok(url);
            }
            Some("error") => {
                return Err(event
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("Codex login failed")
                    .to_owned())
            }
            _ => {}
        }
    }
    let _ = child.kill();
    let _ = child.wait();
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

pub async fn post_codex_login_start(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    match tokio::task::spawn_blocking(move || start_login_blocking(wb)).await {
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
        ModelExecutionClass::LocalInteractive => resolve_runtime_credential(wb),
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

    #[cfg(unix)]
    fn executable(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    /// Seed a login directly: these tests are about the lookup, not about
    /// spawning a real Codex app-server.
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
                stdin: None,
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
    fn codex_auth_file_is_imported_without_returning_secret_fields() {
        let root = tempfile::tempdir().unwrap();
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"exp":4102444800,"chatgpt_account_id":"acct-home"}"#);
        let access = format!("{header}.{claims}.signature");
        std::fs::write(
            root.path().join("auth.json"),
            json!({
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": access,
                    "access_token": access,
                    "refresh_token": "refresh-home",
                    "account_id": "acct-home"
                }
            })
            .to_string(),
        )
        .unwrap();
        let credential = read_codex_auth(root.path()).unwrap();
        assert_eq!(credential.account_id, "acct-home");
        assert_eq!(credential.expires, 4_102_444_800_000);
        assert_eq!(credential.refresh, "refresh-home");
    }

    // Exercises the JWT fallback, which every other test here skips by supplying
    // `tokens.account_id`. The payload is the shape the issuer really mints: the
    // account id sits inside the `https://api.openai.com/auth` claim object, so
    // a reader that looks for a top-level `chatgpt_account_id` finds nothing.
    #[test]
    fn account_id_falls_back_to_the_namespaced_access_token_claim() {
        let root = tempfile::tempdir().unwrap();
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"exp":4102444800,"https://api.openai.com/auth":{"chatgpt_account_id":"acct-nested","chatgpt_plan_type":"pro"}}"#,
        );
        let access = format!("{header}.{claims}.signature");
        std::fs::write(
            root.path().join("auth.json"),
            json!({
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": access,
                    "access_token": access,
                    "refresh_token": "refresh-nested"
                }
            })
            .to_string(),
        )
        .unwrap();
        let credential = read_codex_auth(root.path()).unwrap();
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

    #[cfg(unix)]
    #[test]
    fn device_app_server_completion_seals_only_the_bound_home_person_scope() {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        workbench.lock_unpoisoned().enable_hosted_home_mode();
        let scope = crate::account::account_scope("person:device-flow");

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"exp":4102444800,"chatgpt_account_id":"acct-device"}"#);
        let access = format!("{header}.{claims}.signature");
        let helper = root.path().join("fake-codex");
        std::fs::write(
            &helper,
            format!(
                r#"#!/bin/sh
IFS= read -r initialize
printf '%s\n' '{{"id":1,"result":{{}}}}'
IFS= read -r initialized
IFS= read -r start
printf '%s\n' '{{"id":2,"result":{{"type":"chatgptDeviceCode","loginId":"login-device-test","verificationUrl":"https://auth.openai.com/codex/device","userCode":"ABCD-1234"}}}}'
printf '%s' '{{"auth_mode":"chatgpt","tokens":{{"id_token":"{access}","access_token":"{access}","refresh_token":"refresh-device","account_id":"acct-device"}}}}' > "$CODEX_HOME/auth.json"
printf '%s\n' '{{"method":"account/login/completed","params":{{"loginId":"login-device-test","success":true,"error":null}}}}'
IFS= read -r done
"#
            ),
        )
        .unwrap();
        executable(&helper);
        std::env::set_var("GAUGEDESK_CODEX_BIN", &helper);
        let projection = start_device_login_blocking(workbench.clone(), scope.clone()).unwrap();
        std::env::remove_var("GAUGEDESK_CODEX_BIN");
        assert_eq!(projection["user_code"], "ABCD-1234");

        for _ in 0..100 {
            if device_login_for_scope(&scope)
                .is_some_and(|login| login.state == DeviceLoginState::Linked)
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            device_login_for_scope(&scope).map(|login| login.state),
            Some(DeviceLoginState::Linked)
        );
        let records = credentials_in_scope(workbench.lock_unpoisoned().store_ref(), &scope);
        let record = records.get(PROVIDER).unwrap();
        assert!(record.admits(ModelExecutionClass::PrivateHome));
        assert!(!record.admits(ModelExecutionClass::PublicDeployment));
        assert!(!credentials_in_scope(
            workbench.lock_unpoisoned().store_ref(),
            &crate::account::account_scope("person:someone-else")
        )
        .contains_key(PROVIDER));
    }
}
