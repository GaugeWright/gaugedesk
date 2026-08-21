//! GaugeDesk-owned xAI Grok subscription OAuth lifecycle (LLM-7, ADR 0144).
//!
//! xAI exposes an RFC 8628 device grant for its public Grok CLI OAuth client.
//! GaugeDesk seals the refreshable bundle in the account/Home scope and gives
//! WhippleScript only the short-lived access bearer for one admitted turn.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::account::{
    credentials_in_scope, seal_token, unseal_token, CredentialAuthentication, ModelExecutionClass,
    ACCOUNT_SCOPE,
};
use crate::{net_http, LockUnpoisoned, SharedWorkbench};

pub const PROVIDER: &str = "xai-grok";
const CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
const SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const REFRESH_SKEW_MS: i64 = 120_000;

fn device_url() -> String {
    gaugedesk_env::var("XAI_OAUTH_DEVICE_URL")
        .unwrap_or_else(|| "https://auth.x.ai/oauth2/device/code".to_owned())
}

fn token_url() -> String {
    gaugedesk_env::var("XAI_OAUTH_TOKEN_URL")
        .unwrap_or_else(|| "https://auth.x.ai/oauth2/token".to_owned())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct XaiOAuthCredential {
    pub access: String,
    pub refresh: String,
    pub expires: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XaiRuntimeCredential {
    pub access: String,
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: Option<u64>,
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum LoginState {
    Pending,
    Linked,
    Failed,
    Cancelled,
}

#[derive(Clone)]
struct DeviceLogin {
    login_id: String,
    scope: String,
    verification_url: String,
    user_code: String,
    state: LoginState,
    error: Option<String>,
    started_at: i64,
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
        self.state == LoginState::Pending
    }
}

fn logins() -> &'static Mutex<BTreeMap<String, DeviceLogin>> {
    static LOGINS: OnceLock<Mutex<BTreeMap<String, DeviceLogin>>> = OnceLock::new();
    LOGINS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn login_for_scope(scope: &str) -> Option<DeviceLogin> {
    logins()
        .lock()
        .ok()?
        .values()
        .filter(|login| login.scope == scope)
        .max_by_key(|login| (login.active(), login.started_at))
        .cloned()
}

fn settle_login(login_id: &str, state: LoginState, error: Option<String>) {
    if let Ok(mut all) = logins().lock() {
        if let Some(login) = all.get_mut(login_id) {
            login.state = state;
            login.error = error;
        }
    }
}

fn random_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| format!("create xAI login id: {error}"))?;
    Ok(hex::encode(bytes))
}

fn store_credential_in(
    wb: &SharedWorkbench,
    scope: &str,
    credential: &XaiOAuthCredential,
    execution_classes: BTreeSet<ModelExecutionClass>,
) -> Result<(), String> {
    let plaintext = serde_json::to_string(credential).map_err(|error| error.to_string())?;
    let mut workbench = wb.lock_unpoisoned();
    let sealed = seal_token(workbench.account_key(), &plaintext)
        .ok_or_else(|| "could not seal xAI OAuth credential".to_owned())?;
    workbench
        .upsert_account_credential_in_with_policy(
            scope,
            PROVIDER.to_owned(),
            sealed,
            String::new(),
            execution_classes,
        )
        .map_err(|error| format!("could not store xAI OAuth credential: {error:?}"))?;
    workbench.advance_onboarding("credential", &json!({ "provider": PROVIDER }).to_string());
    Ok(())
}

fn load_credential_in(
    wb: &SharedWorkbench,
    scope: &str,
    execution_class: ModelExecutionClass,
) -> Option<(XaiOAuthCredential, BTreeSet<ModelExecutionClass>)> {
    let workbench = wb.lock_unpoisoned();
    let record = credentials_in_scope(workbench.store_ref(), scope)
        .remove(PROVIDER)
        .filter(|record| {
            record.authentication == CredentialAuthentication::OAuth
                && record.admits(execution_class)
        })?;
    let plaintext = unseal_token(workbench.account_key(), &record.sealed_token)?;
    serde_json::from_str(&plaintext)
        .ok()
        .map(|credential| (credential, record.execution_classes))
}

fn request_device_code() -> Result<DeviceCodeResponse, String> {
    let response = ureq::post(&device_url())
        .set("accept", "application/json")
        .set(
            "user-agent",
            concat!("gaugedesk/", env!("CARGO_PKG_VERSION")),
        )
        .send_form(&[
            ("client_id", CLIENT_ID),
            ("scope", SCOPE),
            ("referrer", "gaugedesk"),
        ])
        .map_err(|error| format!("xAI device authorization failed: {error}"))?;
    response
        .into_json()
        .map_err(|error| format!("xAI device authorization was not valid JSON: {error}"))
}

fn exchange_device_code(device_code: &str) -> Result<TokenResponse, (bool, String)> {
    match ureq::post(&token_url())
        .set("accept", "application/json")
        .set(
            "user-agent",
            concat!("gaugedesk/", env!("CARGO_PKG_VERSION")),
        )
        .send_form(&[
            ("grant_type", DEVICE_GRANT),
            ("client_id", CLIENT_ID),
            ("device_code", device_code),
        ]) {
        Ok(response) => response.into_json().map_err(|error| {
            (
                false,
                format!("xAI token response was not valid JSON: {error}"),
            )
        }),
        Err(ureq::Error::Status(_, response)) => {
            let body = response.into_json::<Value>().unwrap_or(Value::Null);
            let code = body.get("error").and_then(Value::as_str).unwrap_or("");
            if matches!(code, "authorization_pending" | "slow_down") {
                Err((true, code.to_owned()))
            } else {
                Err((false, format!("xAI device authorization failed: {code}")))
            }
        }
        Err(error) => Err((false, format!("xAI device authorization failed: {error}"))),
    }
}

fn start_login(
    wb: SharedWorkbench,
    scope: String,
    execution_class: ModelExecutionClass,
) -> Result<Value, String> {
    if let Some(existing) = login_for_scope(&scope).filter(DeviceLogin::active) {
        return Ok(existing.projection());
    }
    let device = request_device_code()?;
    if device.device_code.is_empty()
        || device.user_code.is_empty()
        || device.verification_uri.is_empty()
    {
        return Err("xAI device authorization omitted its code or verification URL".to_owned());
    }
    let login_id = random_id()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let login = DeviceLogin {
        login_id: login_id.clone(),
        scope: scope.clone(),
        verification_url: device
            .verification_uri_complete
            .clone()
            .unwrap_or_else(|| device.verification_uri.clone()),
        user_code: device.user_code.clone(),
        state: LoginState::Pending,
        error: None,
        started_at: now_ms(),
        cancelled: Arc::clone(&cancelled),
    };
    let projection = login.projection();
    {
        let mut all = logins()
            .lock()
            .map_err(|_| "xAI device-login state is unavailable".to_owned())?;
        all.retain(|_, prior| prior.scope != scope || prior.active());
        all.insert(login_id.clone(), login);
    }
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now()
            + Duration::from_secs(device.expires_in.unwrap_or(300).clamp(30, 900));
        let mut interval = device.interval.unwrap_or(5).clamp(1, 30);
        while std::time::Instant::now() < deadline {
            if cancelled.load(Ordering::Relaxed) {
                settle_login(&login_id, LoginState::Cancelled, None);
                return;
            }
            match exchange_device_code(&device.device_code) {
                Ok(tokens) => {
                    if tokens.access_token.is_empty()
                        || tokens.refresh_token.as_deref().is_none_or(str::is_empty)
                    {
                        settle_login(
                            &login_id,
                            LoginState::Failed,
                            Some("xAI returned an incomplete OAuth bundle".to_owned()),
                        );
                        return;
                    }
                    let credential = XaiOAuthCredential {
                        access: tokens.access_token,
                        refresh: tokens.refresh_token.unwrap_or_default(),
                        expires: now_ms() + tokens.expires_in.unwrap_or(3600) * 1_000,
                    };
                    let stored = store_credential_in(
                        &wb,
                        &scope,
                        &credential,
                        BTreeSet::from([execution_class]),
                    );
                    match stored {
                        Ok(()) => settle_login(&login_id, LoginState::Linked, None),
                        Err(error) => settle_login(&login_id, LoginState::Failed, Some(error)),
                    }
                    return;
                }
                Err((true, code)) => {
                    if code == "slow_down" {
                        interval = (interval + 5).min(60);
                    }
                }
                Err((false, error)) => {
                    settle_login(&login_id, LoginState::Failed, Some(error));
                    return;
                }
            }
            std::thread::sleep(Duration::from_secs(interval));
        }
        settle_login(
            &login_id,
            LoginState::Failed,
            Some("xAI device authorization expired".to_owned()),
        );
    });
    Ok(projection)
}

fn status(wb: &SharedWorkbench, headers: &HeaderMap, class: ModelExecutionClass) -> Json<Value> {
    let scope = wb
        .lock_unpoisoned()
        .account_scope_for(net_http::bearer(headers));
    let credential = load_credential_in(wb, &scope, class).map(|(credential, _)| credential);
    Json(json!({
        "provider": PROVIDER,
        "linked": credential.is_some(),
        "expires": credential.as_ref().map(|credential| credential.expires),
        "expired": credential.as_ref().is_some_and(|credential| credential.expires <= now_ms()),
        "login": login_for_scope(&scope).map(|login| login.projection()),
    }))
}

pub async fn get_status(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    status(&wb, &headers, ModelExecutionClass::LocalInteractive)
}

pub async fn get_home_status(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    status(&wb, &headers, ModelExecutionClass::PrivateHome)
}

async fn start(
    wb: SharedWorkbench,
    headers: HeaderMap,
    class: ModelExecutionClass,
) -> axum::response::Response {
    let scope = wb
        .lock_unpoisoned()
        .account_scope_for(net_http::bearer(&headers));
    match tokio::task::spawn_blocking(move || start_login(wb, scope, class)).await {
        Ok(Ok(login)) => Json(json!({ "mode": "device", "login": login })).into_response(),
        Ok(Err(error)) => {
            (StatusCode::BAD_GATEWAY, Json(json!({ "error": error }))).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "xAI login task panicked").into_response(),
    }
}

pub async fn post_start(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    start(wb, headers, ModelExecutionClass::LocalInteractive).await
}

pub async fn post_home_start(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    start(wb, headers, ModelExecutionClass::PrivateHome).await
}

pub async fn post_cancel(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let scope = wb
        .lock_unpoisoned()
        .account_scope_for(net_http::bearer(&headers));
    if let Some(login) = login_for_scope(&scope).filter(DeviceLogin::active) {
        login.cancelled.store(true, Ordering::Relaxed);
    }
    StatusCode::NO_CONTENT
}

fn refresh_credential(credential: &XaiOAuthCredential) -> Result<XaiOAuthCredential, String> {
    let response = ureq::post(&token_url())
        .set("accept", "application/json")
        .set(
            "user-agent",
            concat!("gaugedesk/", env!("CARGO_PKG_VERSION")),
        )
        .send_form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", credential.refresh.as_str()),
            ("client_id", CLIENT_ID),
        ])
        .map_err(|error| format!("xAI token refresh failed: {error}"))?;
    let tokens: TokenResponse = response
        .into_json()
        .map_err(|error| format!("xAI refresh response was not valid JSON: {error}"))?;
    if tokens.access_token.is_empty() {
        return Err("xAI token refresh returned no access token".to_owned());
    }
    Ok(XaiOAuthCredential {
        access: tokens.access_token,
        refresh: tokens
            .refresh_token
            .unwrap_or_else(|| credential.refresh.clone()),
        expires: now_ms() + tokens.expires_in.unwrap_or(3600) * 1_000,
    })
}

fn resolve_in(
    wb: &SharedWorkbench,
    scope: &str,
    execution_class: ModelExecutionClass,
) -> Result<Option<XaiRuntimeCredential>, String> {
    let Some((mut credential, classes)) = load_credential_in(wb, scope, execution_class) else {
        return Ok(None);
    };
    if credential.expires <= now_ms() + REFRESH_SKEW_MS {
        credential = refresh_credential(&credential)?;
        store_credential_in(wb, scope, &credential, classes)?;
    }
    Ok(Some(XaiRuntimeCredential {
        access: credential.access,
    }))
}

pub fn resolve_turn_credential(
    wb: &SharedWorkbench,
    actor: &str,
    execution_class: ModelExecutionClass,
) -> Result<Option<XaiRuntimeCredential>, String> {
    match execution_class {
        ModelExecutionClass::LocalInteractive => {
            resolve_in(wb, ACCOUNT_SCOPE, ModelExecutionClass::LocalInteractive)
        }
        ModelExecutionClass::PrivateHome => resolve_in(
            wb,
            &crate::account::account_scope(actor),
            ModelExecutionClass::PrivateHome,
        ),
        ModelExecutionClass::PublicDeployment => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_login(scope: &str, login_id: &str, state: LoginState, started_at: i64) {
        logins().lock().unwrap().insert(
            login_id.to_owned(),
            DeviceLogin {
                login_id: login_id.to_owned(),
                scope: scope.to_owned(),
                verification_url: "https://example.invalid/device".to_owned(),
                user_code: login_id.to_owned(),
                state,
                error: None,
                started_at,
                cancelled: Arc::new(AtomicBool::new(false)),
            },
        );
    }

    #[test]
    fn active_login_wins_and_scopes_do_not_bleed() {
        let scope = "scope:xai-grok-active";
        seed_login(scope, "0000-failed", LoginState::Failed, 100);
        seed_login(scope, "ffff-pending", LoginState::Pending, 50);

        assert_eq!(
            login_for_scope(scope).map(|login| login.login_id),
            Some("ffff-pending".to_owned())
        );
        assert!(login_for_scope("scope:xai-grok-other").is_none());
    }

    #[test]
    fn subscription_credentials_are_home_scoped_and_never_public() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let actor = "person:grok-home";
        let credential = XaiOAuthCredential {
            access: "access-private".to_owned(),
            refresh: "refresh-private".to_owned(),
            expires: i64::MAX,
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
            Some(XaiRuntimeCredential {
                access: "access-private".to_owned()
            })
        );
        assert!(
            resolve_turn_credential(&wb, actor, ModelExecutionClass::PublicDeployment)
                .unwrap()
                .is_none()
        );
        assert!(resolve_turn_credential(
            &wb,
            "person:someone-else",
            ModelExecutionClass::PrivateHome
        )
        .unwrap()
        .is_none());
    }
}
