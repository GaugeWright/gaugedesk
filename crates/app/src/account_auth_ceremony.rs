//! Passkey-first GaugeDesk account creation and authentication (`AUTH-2`).
//!
//! Email proves a contact address; WebAuthn proves an authenticator. Neither is
//! persisted as an account until both bounded, single-use ceremonies finish.
//! Successful registration atomically admits the custodied governance root,
//! verified contact, and public passkey verifier, then mints an opaque account
//! session naming that root.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine as _;
use passkey_auth::{
    AuthenticationResponse, AuthenticationState, PasskeyCredential, RegistrationResponse,
    RegistrationState, Webauthn,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::account_auth::{
    append_facts, decide_add_webauthn, decide_verify_email, normalize_email_contact, AccountAuth,
    AccountAuthFact, AuthMethodStatus, CustodiedAccountRootRecord, VerifiedEmailRecord,
    WebAuthnMethodRecord,
};
use crate::account_session::unix_now;
use crate::{auth_oidc::AuthShellState, LockUnpoisoned, SharedWorkbench};

const EMAIL_TTL_SECS: u64 = 10 * 60;
const EMAIL_ATTEMPTS: u8 = 5;
const CEREMONY_TTL_SECS: u64 = 5 * 60;
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;
const PENDING_MAX: usize = 512;

pub trait EmailChallengeSender: Send + Sync {
    fn send_verification(&self, email: &str, code: &str, expires_in: u64) -> Result<(), String>;
}

/// Provider-neutral delivery relay. Deployments choose the mail provider
/// behind this HTTPS endpoint; GaugeDesk sends no account/root material.
struct WebhookEmailChallengeSender {
    endpoint: String,
    bearer: Option<String>,
}

impl EmailChallengeSender for WebhookEmailChallengeSender {
    fn send_verification(&self, email: &str, code: &str, expires_in: u64) -> Result<(), String> {
        let mut request = ureq::post(&self.endpoint).set("content-type", "application/json");
        if let Some(bearer) = &self.bearer {
            request = request.set("authorization", &format!("Bearer {bearer}"));
        }
        request
            .send_json(json!({
                "to": email,
                "template": "gaugedesk-account-verification",
                "code": code,
                "expires_in": expires_in,
            }))
            .map(|_| ())
            .map_err(|error| format!("email delivery failed: {error}"))
    }
}

#[derive(Clone, Debug)]
pub struct AccountAuthConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
    pub session_ttl_secs: u64,
}

impl AccountAuthConfig {
    pub fn new(rp_id: &str, rp_name: &str, origin: &str) -> Result<Self, String> {
        let rp_id = rp_id.trim();
        let rp_name = rp_name.trim();
        let origin = origin.trim().trim_end_matches('/');
        if rp_id.is_empty()
            || rp_name.is_empty()
            || rp_id.contains("://")
            || rp_id.contains('/')
            || rp_id.contains(':')
        {
            return Err("WebAuthn RP id must be a bare hostname".into());
        }
        let parsed = url::Url::parse(origin).map_err(|_| "WebAuthn origin must be a URL")?;
        if parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err("WebAuthn origin must contain only scheme, host, and optional port".into());
        }
        let secure_loopback = parsed.scheme() == "http"
            && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        if parsed.scheme() != "https" && !secure_loopback {
            return Err("WebAuthn origin must be HTTPS (except loopback development)".into());
        }
        if parsed.host_str() != Some(rp_id) {
            return Err("WebAuthn RP id must equal the origin host".into());
        }
        Ok(Self {
            rp_id: rp_id.to_owned(),
            rp_name: rp_name.to_owned(),
            origin: origin.to_owned(),
            session_ttl_secs: SESSION_TTL_SECS,
        })
    }
}

struct PendingEmail {
    email: String,
    salt: [u8; 16],
    code_hash: [u8; 32],
    attempts_left: u8,
    expires_at: u64,
}

struct VerifiedEmailTicket {
    email: String,
    expires_at: u64,
}

struct PendingRegistration {
    email: String,
    account_id: String,
    root_seed: [u8; 32],
    state: RegistrationState,
    expires_at: u64,
}

struct PendingAuthentication {
    account_id: String,
    state: AuthenticationState,
    credentials: BTreeMap<String, PasskeyCredential>,
    expires_at: u64,
}

#[derive(Default)]
struct PendingCeremonies {
    emails: BTreeMap<String, PendingEmail>,
    verified: BTreeMap<String, VerifiedEmailTicket>,
    registrations: BTreeMap<String, PendingRegistration>,
    authentications: BTreeMap<String, PendingAuthentication>,
}

pub struct AccountAuthRuntime {
    webauthn: Webauthn,
    sender: Arc<dyn EmailChallengeSender>,
    pending: Mutex<PendingCeremonies>,
    session_ttl_secs: u64,
}

impl AccountAuthRuntime {
    pub fn new(
        config: AccountAuthConfig,
        sender: Arc<dyn EmailChallengeSender>,
    ) -> Result<Self, String> {
        let webauthn = Webauthn::new(&config.rp_id, &config.rp_name, &config.origin)
            .require_user_verification(true)
            .strict_base64(true)
            .authenticator_attachment(passkey_auth::Attachment::Any);
        Ok(Self {
            webauthn,
            sender,
            pending: Mutex::new(PendingCeremonies::default()),
            session_ttl_secs: config.session_ttl_secs,
        })
    }

    pub fn from_env() -> Option<Arc<Self>> {
        let rp_id = gaugedesk_env::var("ACCOUNT_RP_ID")?;
        let origin = gaugedesk_env::var("ACCOUNT_ORIGIN")?;
        let endpoint = gaugedesk_env::var("AUTH_EMAIL_WEBHOOK_URL")?;
        if !endpoint.starts_with("https://") {
            return None;
        }
        let config = AccountAuthConfig::new(&rp_id, "GaugeDesk", &origin).ok()?;
        let sender = Arc::new(WebhookEmailChallengeSender {
            endpoint,
            bearer: gaugedesk_env::var("AUTH_EMAIL_WEBHOOK_TOKEN"),
        });
        Self::new(config, sender).ok().map(Arc::new)
    }

    fn lock(&self) -> MutexGuard<'_, PendingCeremonies> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn begin_email(&self, email: &str, now: u64) -> Result<String, CeremonyError> {
        let email = normalize_email_contact(email).ok_or(CeremonyError::InvalidEmail)?;
        let challenge_id = random_token(24)?;
        let code = random_numeric_code()?;
        let mut salt = [0_u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| CeremonyError::Unavailable)?;
        let pending = PendingEmail {
            email: email.clone(),
            salt,
            code_hash: email_code_hash(&salt, &code),
            attempts_left: EMAIL_ATTEMPTS,
            expires_at: now.saturating_add(EMAIL_TTL_SECS),
        };
        {
            let mut store = self.lock();
            sweep(&mut store, now);
            if store.emails.len() >= PENDING_MAX {
                return Err(CeremonyError::Unavailable);
            }
            store.emails.insert(challenge_id.clone(), pending);
        }
        if self
            .sender
            .send_verification(&email, &code, EMAIL_TTL_SECS)
            .is_err()
        {
            self.lock().emails.remove(&challenge_id);
            return Err(CeremonyError::DeliveryFailed);
        }
        Ok(challenge_id)
    }

    fn complete_email(
        &self,
        challenge_id: &str,
        code: &str,
        now: u64,
    ) -> Result<String, CeremonyError> {
        let mut store = self.lock();
        let Some(pending) = store.emails.get_mut(challenge_id) else {
            return Err(CeremonyError::UnknownOrExpired);
        };
        if pending.expires_at <= now || pending.attempts_left == 0 {
            store.emails.remove(challenge_id);
            return Err(CeremonyError::UnknownOrExpired);
        }
        let presented = email_code_hash(&pending.salt, code.trim());
        if !constant_time_eq(&pending.code_hash, &presented) {
            pending.attempts_left -= 1;
            if pending.attempts_left == 0 {
                store.emails.remove(challenge_id);
            }
            return Err(CeremonyError::InvalidProof);
        }
        let email = store
            .emails
            .remove(challenge_id)
            .expect("pending email exists")
            .email;
        let ticket = random_token(24)?;
        if store.verified.len() >= PENDING_MAX {
            return Err(CeremonyError::Unavailable);
        }
        store.verified.insert(
            ticket.clone(),
            VerifiedEmailTicket {
                email,
                expires_at: now.saturating_add(CEREMONY_TTL_SECS),
            },
        );
        Ok(ticket)
    }

    fn start_registration(
        &self,
        email_ticket: &str,
        display_name: &str,
        now: u64,
    ) -> Result<(String, serde_json::Value), CeremonyError> {
        let ticket = self
            .lock()
            .verified
            .remove(email_ticket)
            .filter(|ticket| ticket.expires_at > now)
            .ok_or(CeremonyError::UnknownOrExpired)?;
        let (root_seed, account_id) = generate_account_root()?;
        let user_handle = account_user_handle(&account_id);
        let display_name = if display_name.trim().is_empty() {
            ticket.email.as_str()
        } else {
            display_name.trim()
        };
        let (challenge, state) =
            self.webauthn
                .start_registration(&user_handle, &ticket.email, display_name, &[]);
        let ceremony_id = random_token(24)?;
        let challenge = serde_json::to_value(challenge).map_err(|_| CeremonyError::Unavailable)?;
        let mut store = self.lock();
        sweep(&mut store, now);
        if store.registrations.len() >= PENDING_MAX {
            return Err(CeremonyError::Unavailable);
        }
        store.registrations.insert(
            ceremony_id.clone(),
            PendingRegistration {
                email: ticket.email,
                account_id,
                root_seed,
                state,
                expires_at: now.saturating_add(CEREMONY_TTL_SECS),
            },
        );
        Ok((ceremony_id, challenge))
    }

    fn finish_registration(
        &self,
        wb: &mut crate::Workbench,
        ceremony_id: &str,
        response: &RegistrationResponse,
        label: &str,
        now: u64,
    ) -> Result<(String, String), CeremonyError> {
        let pending = self
            .lock()
            .registrations
            .remove(ceremony_id)
            .filter(|pending| pending.expires_at > now)
            .ok_or(CeremonyError::UnknownOrExpired)?;
        let credential = self
            .webauthn
            .finish_registration(&pending.state, response)
            .map_err(|_| CeremonyError::InvalidProof)?;
        let credential_id = credential.id.to_b64url();
        let verifier_json =
            serde_json::to_string(&credential).map_err(|_| CeremonyError::Unavailable)?;
        let sealed_seed = wb
            .seal_custodied_account_root(&pending.account_id, &hex::encode(pending.root_seed))
            .ok_or(CeremonyError::Unavailable)?;
        let state = AccountAuth::rebuild(wb.store_ref()).map_err(|_| CeremonyError::Unavailable)?;
        if state.roots.contains_key(&pending.account_id) {
            return Err(CeremonyError::AlreadyExists);
        }
        let mut facts = vec![AccountAuthFact::RootCustody(
            CustodiedAccountRootRecord::new(&pending.account_id, &sealed_seed, now)
                .map_err(|_| CeremonyError::Unavailable)?,
        )];
        facts.extend(
            decide_verify_email(
                &state,
                VerifiedEmailRecord::new(&pending.account_id, &pending.email, now)
                    .map_err(|_| CeremonyError::InvalidEmail)?,
            )
            .map_err(|_| CeremonyError::AlreadyExists)?,
        );
        facts.extend(
            decide_add_webauthn(
                &state,
                WebAuthnMethodRecord::new(
                    &pending.account_id,
                    &credential_id,
                    &verifier_json,
                    label,
                    now,
                )
                .map_err(|_| CeremonyError::Unavailable)?,
            )
            .map_err(|_| CeremonyError::AlreadyExists)?,
        );
        append_facts(wb.store_mut(), &facts).map_err(|_| CeremonyError::Unavailable)?;
        crate::auth_oidc::provision_web_account(wb, &pending.account_id, true);
        let session = wb
            .mint_account_session(&pending.account_id, "passkey", self.session_ttl_secs)
            .ok_or(CeremonyError::Unavailable)?;
        Ok((pending.account_id, session))
    }

    fn start_authentication(
        &self,
        state: &AccountAuth,
        email: &str,
        now: u64,
    ) -> Result<(String, serde_json::Value), CeremonyError> {
        let email = normalize_email_contact(email).ok_or(CeremonyError::InvalidEmail)?;
        let contact = state
            .emails
            .values()
            .find(|record| record.email == email && record.status == AuthMethodStatus::Active)
            .ok_or(CeremonyError::InvalidProof)?;
        let credentials: Vec<PasskeyCredential> = state
            .webauthn_methods
            .values()
            .filter(|record| {
                record.account_id == contact.account_id && record.status == AuthMethodStatus::Active
            })
            .map(|record| serde_json::from_str(&record.verifier_json))
            .collect::<Result<_, _>>()
            .map_err(|_| CeremonyError::Unavailable)?;
        if credentials.is_empty() {
            return Err(CeremonyError::InvalidProof);
        }
        let (challenge, auth_state) = self.webauthn.start_authentication_with_creds_for_user(
            &account_user_handle(&contact.account_id),
            &credentials,
        );
        let credential_map = credentials
            .into_iter()
            .map(|credential| (credential.id.to_b64url(), credential))
            .collect();
        let ceremony_id = random_token(24)?;
        let challenge = serde_json::to_value(challenge).map_err(|_| CeremonyError::Unavailable)?;
        let mut pending = self.lock();
        sweep(&mut pending, now);
        if pending.authentications.len() >= PENDING_MAX {
            return Err(CeremonyError::Unavailable);
        }
        pending.authentications.insert(
            ceremony_id.clone(),
            PendingAuthentication {
                account_id: contact.account_id.clone(),
                state: auth_state,
                credentials: credential_map,
                expires_at: now.saturating_add(CEREMONY_TTL_SECS),
            },
        );
        Ok((ceremony_id, challenge))
    }

    fn finish_authentication(
        &self,
        wb: &mut crate::Workbench,
        ceremony_id: &str,
        response: &AuthenticationResponse,
        now: u64,
    ) -> Result<(String, String), CeremonyError> {
        let pending = self
            .lock()
            .authentications
            .remove(ceremony_id)
            .filter(|pending| pending.expires_at > now)
            .ok_or(CeremonyError::UnknownOrExpired)?;
        let mut credential = pending
            .credentials
            .get(&response.id)
            .cloned()
            .ok_or(CeremonyError::InvalidProof)?;
        let outcome = self
            .webauthn
            .finish_authentication(&pending.state, response, &credential)
            .map_err(|_| CeremonyError::InvalidProof)?;
        credential.counter = outcome.new_counter;
        let verifier_json =
            serde_json::to_string(&credential).map_err(|_| CeremonyError::Unavailable)?;
        let state = AccountAuth::rebuild(wb.store_ref()).map_err(|_| CeremonyError::Unavailable)?;
        let existing = state
            .webauthn_methods
            .get(&response.id)
            .filter(|record| {
                record.account_id == pending.account_id && record.status == AuthMethodStatus::Active
            })
            .ok_or(CeremonyError::InvalidProof)?;
        let mut updated = existing.clone();
        updated.verifier_json = verifier_json;
        append_facts(wb.store_mut(), &[AccountAuthFact::WebAuthn(updated)])
            .map_err(|_| CeremonyError::Unavailable)?;
        let session = wb
            .mint_account_session(&pending.account_id, "passkey", self.session_ttl_secs)
            .ok_or(CeremonyError::Unavailable)?;
        Ok((pending.account_id, session))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CeremonyError {
    NotConfigured,
    InvalidEmail,
    InvalidProof,
    UnknownOrExpired,
    AlreadyExists,
    DeliveryFailed,
    Unavailable,
}

impl CeremonyError {
    fn response(self) -> Response {
        let (status, message) = match self {
            Self::NotConfigured => (
                StatusCode::NOT_FOUND,
                "passkey account login is not configured",
            ),
            Self::InvalidEmail => (StatusCode::BAD_REQUEST, "invalid email address"),
            Self::InvalidProof | Self::UnknownOrExpired => (
                StatusCode::UNAUTHORIZED,
                "invalid or expired authentication proof",
            ),
            Self::AlreadyExists => (StatusCode::CONFLICT, "account method already exists"),
            Self::DeliveryFailed | Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "account authentication unavailable",
            ),
        };
        (status, message).into_response()
    }
}

#[derive(Deserialize)]
struct BeginEmailRequest {
    email: String,
}

#[derive(Deserialize)]
struct CompleteEmailRequest {
    challenge_id: String,
    code: String,
}

#[derive(Deserialize)]
struct StartRegistrationRequest {
    email_verification: String,
    #[serde(default)]
    display_name: String,
}

#[derive(Deserialize)]
struct FinishRegistrationRequest {
    ceremony_id: String,
    #[serde(default)]
    label: String,
    credential: RegistrationResponse,
}

#[derive(Deserialize)]
struct StartAuthenticationRequest {
    email: String,
}

#[derive(Deserialize)]
struct FinishAuthenticationRequest {
    ceremony_id: String,
    credential: AuthenticationResponse,
}

#[derive(Serialize)]
struct StartCeremonyResponse {
    ceremony_id: String,
    public_key: serde_json::Value,
}

fn runtime(auth: &AuthShellState) -> Result<Arc<AccountAuthRuntime>, CeremonyError> {
    auth.account_auth().ok_or(CeremonyError::NotConfigured)
}

async fn post_email_start(
    Extension(auth): Extension<AuthShellState>,
    Json(body): Json<BeginEmailRequest>,
) -> Response {
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    let now = unix_now();
    let result = tokio::task::spawn_blocking(move || runtime.begin_email(&body.email, now)).await;
    match result.unwrap_or(Err(CeremonyError::Unavailable)) {
        Ok(challenge_id) => (
            StatusCode::ACCEPTED,
            Json(json!({"challenge_id": challenge_id, "expires_in": EMAIL_TTL_SECS})),
        )
            .into_response(),
        Err(error) => error.response(),
    }
}

async fn post_email_complete(
    Extension(auth): Extension<AuthShellState>,
    Json(body): Json<CompleteEmailRequest>,
) -> Response {
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    match runtime.complete_email(&body.challenge_id, &body.code, unix_now()) {
        Ok(ticket) => Json(json!({"email_verification": ticket})).into_response(),
        Err(error) => error.response(),
    }
}

async fn post_registration_start(
    Extension(auth): Extension<AuthShellState>,
    Json(body): Json<StartRegistrationRequest>,
) -> Response {
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    match runtime.start_registration(&body.email_verification, &body.display_name, unix_now()) {
        Ok((ceremony_id, public_key)) => Json(StartCeremonyResponse {
            ceremony_id,
            public_key,
        })
        .into_response(),
        Err(error) => error.response(),
    }
}

async fn post_registration_finish(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    Json(body): Json<FinishRegistrationRequest>,
) -> Response {
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    let result = runtime.finish_registration(
        &mut wb.lock_unpoisoned(),
        &body.ceremony_id,
        &body.credential,
        &body.label,
        unix_now(),
    );
    session_response(result)
}

async fn post_authentication_start(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    Json(body): Json<StartAuthenticationRequest>,
) -> Response {
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    let state = match AccountAuth::rebuild(wb.lock_unpoisoned().store_ref()) {
        Ok(state) => state,
        Err(_) => return CeremonyError::Unavailable.response(),
    };
    match runtime.start_authentication(&state, &body.email, unix_now()) {
        Ok((ceremony_id, public_key)) => Json(StartCeremonyResponse {
            ceremony_id,
            public_key,
        })
        .into_response(),
        Err(error) => error.response(),
    }
}

async fn post_authentication_finish(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    Json(body): Json<FinishAuthenticationRequest>,
) -> Response {
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    let result = runtime.finish_authentication(
        &mut wb.lock_unpoisoned(),
        &body.ceremony_id,
        &body.credential,
        unix_now(),
    );
    session_response(result)
}

fn session_response(result: Result<(String, String), CeremonyError>) -> Response {
    match result {
        Ok((account_id, token)) => {
            let mut response = Json(json!({"account_id": account_id})).into_response();
            crate::auth_oidc::append_session_cookies(&mut response, &token);
            response
        }
        Err(error) => error.response(),
    }
}

pub fn routes() -> axum::Router<SharedWorkbench> {
    use axum::routing::post;
    axum::Router::new()
        .route("/auth/account/email/start", post(post_email_start))
        .route("/auth/account/email/complete", post(post_email_complete))
        .route(
            "/auth/account/passkey/register/start",
            post(post_registration_start),
        )
        .route(
            "/auth/account/passkey/register/finish",
            post(post_registration_finish),
        )
        .route(
            "/auth/account/passkey/login/start",
            post(post_authentication_start),
        )
        .route(
            "/auth/account/passkey/login/finish",
            post(post_authentication_finish),
        )
}

fn sweep(store: &mut PendingCeremonies, now: u64) {
    store.emails.retain(|_, entry| entry.expires_at > now);
    store.verified.retain(|_, entry| entry.expires_at > now);
    store
        .registrations
        .retain(|_, entry| entry.expires_at > now);
    store
        .authentications
        .retain(|_, entry| entry.expires_at > now);
}

fn random_token(bytes: usize) -> Result<String, CeremonyError> {
    let mut value = vec![0_u8; bytes];
    getrandom::getrandom(&mut value).map_err(|_| CeremonyError::Unavailable)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value))
}

fn random_numeric_code() -> Result<String, CeremonyError> {
    const RANGE: u32 = 100_000_000;
    const LIMIT: u32 = u32::MAX - (u32::MAX % RANGE);
    loop {
        let mut bytes = [0_u8; 4];
        getrandom::getrandom(&mut bytes).map_err(|_| CeremonyError::Unavailable)?;
        let value = u32::from_be_bytes(bytes);
        if value < LIMIT {
            return Ok(format!("{:08}", value % RANGE));
        }
    }
}

fn email_code_hash(salt: &[u8; 16], code: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gaugedesk:email-verification:v1");
    digest.update(salt);
    digest.update((code.len() as u64).to_be_bytes());
    digest.update(code.as_bytes());
    digest.finalize().into()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn generate_account_root() -> Result<([u8; 32], String), CeremonyError> {
    for _ in 0..16 {
        let mut seed = [0_u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| CeremonyError::Unavailable)?;
        if let Ok(signing) = gaugedesk_core::signature::SigningKey::from_seed(&seed) {
            return Ok((seed, signing.public_key().as_str().to_owned()));
        }
    }
    Err(CeremonyError::Unavailable)
}

fn account_user_handle(account_id: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gaugedesk:webauthn-user-handle:v1");
    digest.update((account_id.len() as u64).to_be_bytes());
    digest.update(account_id.as_bytes());
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use ciborium::value::Value as CborValue;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_RP_ID: &str = "localhost";
    const TEST_ORIGIN: &str = "http://localhost:3000";
    const FLAG_UP: u8 = 1 << 0;
    const FLAG_UV: u8 = 1 << 2;
    const FLAG_AT: u8 = 1 << 6;

    struct FakeAuthenticator {
        signing: SigningKey,
        credential_id: Vec<u8>,
        counter: u32,
    }

    impl FakeAuthenticator {
        fn new() -> Self {
            let mut seed = [0_u8; 32];
            getrandom::getrandom(&mut seed).unwrap();
            Self {
                signing: SigningKey::from_bytes(&seed),
                credential_id: b"gaugedesk-test-passkey".to_vec(),
                counter: 0,
            }
        }

        fn cose_public_key(&self) -> Vec<u8> {
            let map = CborValue::Map(vec![
                (CborValue::Integer(1.into()), CborValue::Integer(1.into())),
                (
                    CborValue::Integer(3.into()),
                    CborValue::Integer((-8).into()),
                ),
                (
                    CborValue::Integer((-1).into()),
                    CborValue::Integer(6.into()),
                ),
                (
                    CborValue::Integer((-2).into()),
                    CborValue::Bytes(self.signing.verifying_key().to_bytes().to_vec()),
                ),
            ]);
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&map, &mut encoded).unwrap();
            encoded
        }

        fn registration_response_at(&self, challenge: &str, origin: &str) -> RegistrationResponse {
            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&Sha256::digest(TEST_RP_ID.as_bytes()));
            auth_data.push(FLAG_UP | FLAG_UV | FLAG_AT);
            auth_data.extend_from_slice(&self.counter.to_be_bytes());
            auth_data.extend_from_slice(&[0_u8; 16]);
            auth_data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            auth_data.extend_from_slice(&self.credential_id);
            auth_data.extend_from_slice(&self.cose_public_key());

            let attestation = CborValue::Map(vec![
                (
                    CborValue::Text("fmt".into()),
                    CborValue::Text("none".into()),
                ),
                (
                    CborValue::Text("attStmt".into()),
                    CborValue::Map(Vec::new()),
                ),
                (
                    CborValue::Text("authData".into()),
                    CborValue::Bytes(auth_data),
                ),
            ]);
            let mut attestation_bytes = Vec::new();
            ciborium::ser::into_writer(&attestation, &mut attestation_bytes).unwrap();
            RegistrationResponse {
                id: B64URL.encode(&self.credential_id),
                transports: vec!["internal".into()],
                attestation_object: B64URL.encode(attestation_bytes),
                client_data_json: client_data_at("webauthn.create", challenge, origin).1,
            }
        }

        fn registration_response(&self, challenge: &str) -> RegistrationResponse {
            self.registration_response_at(challenge, TEST_ORIGIN)
        }

        fn authentication_response(&mut self, challenge: &str) -> AuthenticationResponse {
            self.counter += 1;
            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&Sha256::digest(TEST_RP_ID.as_bytes()));
            auth_data.push(FLAG_UP | FLAG_UV);
            auth_data.extend_from_slice(&self.counter.to_be_bytes());
            let (client_data_raw, client_data_json) =
                client_data_at("webauthn.get", challenge, TEST_ORIGIN);
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(&client_data_raw));
            AuthenticationResponse {
                id: B64URL.encode(&self.credential_id),
                authenticator_data: B64URL.encode(auth_data),
                signature: B64URL.encode(self.signing.sign(&signed).to_bytes()),
                client_data_json,
                user_handle: None,
            }
        }
    }

    fn client_data_at(kind: &str, challenge: &str, origin: &str) -> (Vec<u8>, String) {
        let raw = format!(
            r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        )
        .into_bytes();
        let encoded = B64URL.encode(&raw);
        (raw, encoded)
    }

    #[derive(Default)]
    struct CapturingSender(Mutex<Vec<(String, String)>>);

    impl EmailChallengeSender for CapturingSender {
        fn send_verification(
            &self,
            email: &str,
            code: &str,
            _expires_in: u64,
        ) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .push((email.to_owned(), code.to_owned()));
            Ok(())
        }
    }

    fn runtime() -> (AccountAuthRuntime, Arc<CapturingSender>) {
        let sender = Arc::new(CapturingSender::default());
        let config =
            AccountAuthConfig::new("localhost", "GaugeDesk", "http://localhost:3000").unwrap();
        (
            AccountAuthRuntime::new(config, sender.clone()).unwrap(),
            sender,
        )
    }

    #[test]
    fn email_proof_is_bounded_single_use_and_normalized() {
        let (runtime, sender) = runtime();
        let challenge = runtime.begin_email(" Alice@Example.COM ", 10).unwrap();
        let sent = sender.0.lock().unwrap()[0].clone();
        assert_eq!(sent.0, "alice@example.com");
        assert_eq!(sent.1.len(), 8);
        assert_eq!(
            runtime.complete_email(&challenge, "wrong", 11),
            Err(CeremonyError::InvalidProof)
        );
        let ticket = runtime.complete_email(&challenge, &sent.1, 12).unwrap();
        assert_eq!(
            runtime.complete_email(&challenge, &sent.1, 13),
            Err(CeremonyError::UnknownOrExpired)
        );
        assert!(runtime.lock().verified.contains_key(&ticket));
    }

    #[test]
    fn expired_email_proof_creates_no_verified_ticket() {
        let (runtime, sender) = runtime();
        let challenge = runtime.begin_email("alice@example.com", 10).unwrap();
        let code = sender.0.lock().unwrap()[0].1.clone();
        assert_eq!(
            runtime.complete_email(&challenge, &code, 10 + EMAIL_TTL_SECS),
            Err(CeremonyError::UnknownOrExpired)
        );
        assert!(runtime.lock().verified.is_empty());
    }

    #[test]
    fn registration_start_consumes_email_and_keeps_provisional_root_material_only_in_memory() {
        let (runtime, sender) = runtime();
        let challenge = runtime.begin_email("alice@example.com", 10).unwrap();
        let code = sender.0.lock().unwrap()[0].1.clone();
        let ticket = runtime.complete_email(&challenge, &code, 11).unwrap();
        let (ceremony, public_key) = runtime.start_registration(&ticket, "Alice", 12).unwrap();
        assert!(public_key.get("challenge").is_some());
        assert!(runtime.lock().registrations.contains_key(&ceremony));
        assert_eq!(
            runtime.start_registration(&ticket, "Alice", 13),
            Err(CeremonyError::UnknownOrExpired)
        );
    }

    #[test]
    fn production_configuration_requires_https_and_exact_rp_host() {
        assert!(AccountAuthConfig::new("example.com", "GaugeDesk", "https://example.com").is_ok());
        assert!(
            AccountAuthConfig::new("https://example.com", "GaugeDesk", "https://example.com")
                .is_err()
        );
        assert!(AccountAuthConfig::new("example.com", "GaugeDesk", "http://example.com").is_err());
        assert!(
            AccountAuthConfig::new("other.example", "GaugeDesk", "https://example.com").is_err()
        );
    }

    #[test]
    fn real_passkey_round_trip_creates_and_reauthenticates_the_same_account() {
        let (runtime, sender) = runtime();
        let email_challenge = runtime.begin_email("alice@example.com", 10).unwrap();
        let email_code = sender.0.lock().unwrap()[0].1.clone();
        let email_ticket = runtime
            .complete_email(&email_challenge, &email_code, 11)
            .unwrap();
        let (registration_id, registration_options) = runtime
            .start_registration(&email_ticket, "Alice", 12)
            .unwrap();
        let challenge = registration_options["challenge"].as_str().unwrap();
        let mut authenticator = FakeAuthenticator::new();
        let registration = authenticator.registration_response(challenge);
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(crate::content_vault::ContentVault::new(
            vault_dir.path(),
            Box::new(crate::at_rest::LoopbackKeyWrap::new([7_u8; 32])),
        ));
        let mut wb = crate::Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap())
            .with_content_vault(vault);

        let (account_id, first_session) = runtime
            .finish_registration(&mut wb, &registration_id, &registration, "Laptop", 13)
            .unwrap();
        assert_eq!(
            wb.account_sessions().resolve(&first_session, 14).as_deref(),
            Some(account_id.as_str())
        );
        let account = AccountAuth::rebuild(wb.store_ref()).unwrap();
        let root = account.roots.get(&account_id).unwrap();
        let seed: [u8; 32] = hex::decode(
            wb.unseal_custodied_account_root(&account_id, &root.sealed_seed)
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        let signing = gaugedesk_core::signature::SigningKey::from_seed(&seed).unwrap();
        assert_eq!(signing.public_key().as_str(), account_id);
        assert_eq!(account.methods_for(&account_id).emails.len(), 1);
        assert_eq!(account.methods_for(&account_id).webauthn.len(), 1);

        let (authentication_id, authentication_options) = runtime
            .start_authentication(&account, "alice@example.com", 15)
            .unwrap();
        let challenge = authentication_options["challenge"].as_str().unwrap();
        let assertion = authenticator.authentication_response(challenge);
        let (authenticated_account, second_session) = runtime
            .finish_authentication(&mut wb, &authentication_id, &assertion, 16)
            .unwrap();
        assert_eq!(authenticated_account, account_id);
        assert_eq!(
            wb.account_sessions()
                .resolve(&second_session, 17)
                .as_deref(),
            Some(account_id.as_str())
        );
        let updated = AccountAuth::rebuild(wb.store_ref()).unwrap();
        let credential = updated.webauthn_methods.values().next().unwrap();
        let verifier: PasskeyCredential = serde_json::from_str(&credential.verifier_json).unwrap();
        assert_eq!(verifier.counter, 1);
    }

    #[test]
    fn wrong_origin_creates_no_account_and_consumes_the_registration() {
        let (runtime, sender) = runtime();
        let email_challenge = runtime.begin_email("alice@example.com", 10).unwrap();
        let email_code = sender.0.lock().unwrap()[0].1.clone();
        let email_ticket = runtime
            .complete_email(&email_challenge, &email_code, 11)
            .unwrap();
        let (registration_id, registration_options) = runtime
            .start_registration(&email_ticket, "Alice", 12)
            .unwrap();
        let challenge = registration_options["challenge"].as_str().unwrap();
        let authenticator = FakeAuthenticator::new();
        let response = authenticator.registration_response_at(challenge, "https://evil.example");
        let mut wb = crate::Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap());

        assert_eq!(
            runtime.finish_registration(&mut wb, &registration_id, &response, "Laptop", 13),
            Err(CeremonyError::InvalidProof)
        );
        assert!(AccountAuth::rebuild(wb.store_ref())
            .unwrap()
            .roots
            .is_empty());
        assert_eq!(
            runtime.finish_registration(&mut wb, &registration_id, &response, "Laptop", 14),
            Err(CeremonyError::UnknownOrExpired)
        );
    }
}
