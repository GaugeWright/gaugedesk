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
    http::{HeaderMap, StatusCode},
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
    append_facts, decide_add_webauthn, decide_consume_recovery_code, decide_verify_email,
    normalize_email_contact, recovery_target_id, AccountAuth, AccountAuthFact, AuthMethodStatus,
    CustodiedAccountRootRecord, RecoveryAttemptOutcome, RecoveryAttemptRecord, VerifiedEmailRecord,
    WebAuthnMethodRecord,
};
use crate::account_session::unix_now;
use crate::{auth_oidc::AuthShellState, LockUnpoisoned, SharedWorkbench};

const EMAIL_TTL_SECS: u64 = 10 * 60;
const EMAIL_ATTEMPTS: u8 = 5;
const CEREMONY_TTL_SECS: u64 = 5 * 60;
const AUTHORIZATION_PROOF_TTL_SECS: u64 = 5 * 60;
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;
const RECOVERY_ATTEMPT_WINDOW_SECS: u64 = 15 * 60;
const RECOVERY_ATTEMPT_LIMIT: usize = 5;
const PENDING_MAX: usize = 512;

pub trait EmailChallengeSender: Send + Sync {
    fn send_verification(&self, email: &str, code: &str, expires_in: u64) -> Result<(), String>;

    fn send_recovery(&self, email: &str, code: &str, expires_in: u64) -> Result<(), String> {
        self.send_verification(email, code, expires_in)
    }
}

/// Provider-neutral delivery relay. Deployments choose the mail provider
/// behind this HTTPS endpoint; GaugeDesk sends no account/root material.
struct WebhookEmailChallengeSender {
    endpoint: String,
    bearer: Option<String>,
}

/// Debug-only delivery sink for browser acceptance. The recovery journey still
/// crosses the production HTTP routes, reducer, custody check, session mint,
/// cookie, and client; only the external mail provider is replaced. Keeping the
/// one-time proof in the isolated test state directory avoids adding a route
/// that could disclose it from a running server.
#[cfg(debug_assertions)]
struct TestFileEmailChallengeSender {
    path: std::path::PathBuf,
}

#[cfg(debug_assertions)]
impl TestFileEmailChallengeSender {
    fn write(&self, email: &str, code: &str, expires_in: u64, purpose: &str) -> Result<(), String> {
        let body = serde_json::to_vec(&json!({
            "email": email,
            "code": code,
            "expires_in": expires_in,
            "purpose": purpose,
        }))
        .map_err(|error| format!("test email serialization failed: {error}"))?;
        std::fs::write(&self.path, body)
            .map_err(|error| format!("test email delivery failed: {error}"))
    }
}

#[cfg(debug_assertions)]
impl EmailChallengeSender for TestFileEmailChallengeSender {
    fn send_verification(&self, email: &str, code: &str, expires_in: u64) -> Result<(), String> {
        self.write(email, code, expires_in, "verification")
    }

    fn send_recovery(&self, email: &str, code: &str, expires_in: u64) -> Result<(), String> {
        self.write(email, code, expires_in, "recovery")
    }
}

impl EmailChallengeSender for WebhookEmailChallengeSender {
    fn send_verification(&self, email: &str, code: &str, expires_in: u64) -> Result<(), String> {
        self.send(email, code, expires_in, "gaugedesk-account-verification")
    }

    fn send_recovery(&self, email: &str, code: &str, expires_in: u64) -> Result<(), String> {
        self.send(email, code, expires_in, "gaugedesk-account-recovery")
    }
}

impl WebhookEmailChallengeSender {
    fn send(&self, email: &str, code: &str, expires_in: u64, template: &str) -> Result<(), String> {
        let mut request = ureq::post(&self.endpoint).set("content-type", "application/json");
        if let Some(bearer) = &self.bearer {
            request = request.set("authorization", &format!("Bearer {bearer}"));
        }
        request
            .send_json(json!({
                "to": email,
                "template": template,
                "code": code,
                "expires_in": expires_in,
            }))
            .map(|_| ())
            .map_err(|error| format!("email delivery failed: {error}"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EmailChallengePurpose {
    Verification,
    Recovery,
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
    purpose: EmailChallengePurpose,
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

struct PendingAuthorization {
    account_id: String,
    operation: String,
    state: AuthenticationState,
    credentials: BTreeMap<String, PasskeyCredential>,
    expires_at: u64,
}

struct AuthorizationProof {
    account_id: String,
    operation: String,
    expires_at: u64,
}

struct PendingAdditionalRegistration {
    account_id: String,
    state: RegistrationState,
    expires_at: u64,
}

#[derive(Default)]
struct PendingCeremonies {
    emails: BTreeMap<String, PendingEmail>,
    verified: BTreeMap<String, VerifiedEmailTicket>,
    registrations: BTreeMap<String, PendingRegistration>,
    authentications: BTreeMap<String, PendingAuthentication>,
    authorizations: BTreeMap<String, PendingAuthorization>,
    authorization_proofs: BTreeMap<String, AuthorizationProof>,
    additional_registrations: BTreeMap<String, PendingAdditionalRegistration>,
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
        #[cfg(debug_assertions)]
        if gaugedesk_env::enabled("TEST_RESET") {
            if let Some(path) = gaugedesk_env::var_os("TEST_AUTH_EMAIL_OUTBOX") {
                let config = AccountAuthConfig::new(&rp_id, "GaugeDesk", &origin).ok()?;
                let sender = Arc::new(TestFileEmailChallengeSender { path: path.into() });
                return Self::new(config, sender).ok().map(Arc::new);
            }
        }
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
        self.begin_email_for(email, EmailChallengePurpose::Verification, now)
    }

    fn begin_recovery(&self, email: &str, now: u64) -> Result<String, CeremonyError> {
        self.begin_email_for(email, EmailChallengePurpose::Recovery, now)
    }

    fn begin_email_for(
        &self,
        email: &str,
        purpose: EmailChallengePurpose,
        now: u64,
    ) -> Result<String, CeremonyError> {
        let email = normalize_email_contact(email).ok_or(CeremonyError::InvalidEmail)?;
        let challenge_id = random_token(24)?;
        let code = random_numeric_code()?;
        let mut salt = [0_u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| CeremonyError::Unavailable)?;
        let pending = PendingEmail {
            email: email.clone(),
            purpose,
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
        let sent = match purpose {
            EmailChallengePurpose::Verification => {
                self.sender.send_verification(&email, &code, EMAIL_TTL_SECS)
            }
            EmailChallengePurpose::Recovery => {
                self.sender.send_recovery(&email, &code, EMAIL_TTL_SECS)
            }
        };
        if sent.is_err() {
            self.lock().emails.remove(&challenge_id);
            return Err(CeremonyError::DeliveryFailed);
        }
        Ok(challenge_id)
    }

    fn recovery_target_for_challenge(&self, challenge_id: &str, now: u64) -> Option<String> {
        let store = self.lock();
        let pending = store.emails.get(challenge_id)?;
        (pending.purpose == EmailChallengePurpose::Recovery && pending.expires_at > now)
            .then(|| recovery_target_id(&pending.email))?
    }

    fn complete_email(
        &self,
        challenge_id: &str,
        code: &str,
        now: u64,
    ) -> Result<String, CeremonyError> {
        self.complete_email_for(challenge_id, code, EmailChallengePurpose::Verification, now)
    }

    fn complete_email_for(
        &self,
        challenge_id: &str,
        code: &str,
        purpose: EmailChallengePurpose,
        now: u64,
    ) -> Result<String, CeremonyError> {
        let mut store = self.lock();
        let Some(pending) = store.emails.get_mut(challenge_id) else {
            return Err(CeremonyError::UnknownOrExpired);
        };
        if pending.expires_at <= now || pending.attempts_left == 0 || pending.purpose != purpose {
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

    fn finish_recovery(
        &self,
        wb: &mut crate::Workbench,
        challenge_id: &str,
        email_code: &str,
        recovery_code: &str,
        now: u64,
    ) -> Result<(String, String), CeremonyError> {
        let target_id = self
            .recovery_target_for_challenge(challenge_id, now)
            .ok_or(CeremonyError::UnknownOrExpired)?;
        let state = AccountAuth::rebuild(wb.store_ref()).map_err(|_| CeremonyError::Unavailable)?;
        if recovery_is_limited(&state, &target_id, now) {
            self.lock().emails.remove(challenge_id);
            record_recovery_attempt(
                wb,
                &target_id,
                None,
                now,
                RecoveryAttemptOutcome::RateLimited,
            )?;
            return Err(CeremonyError::RateLimited);
        }
        let ticket = match self.complete_email_for(
            challenge_id,
            email_code,
            EmailChallengePurpose::Recovery,
            now,
        ) {
            Ok(ticket) => ticket,
            Err(error) => {
                record_recovery_attempt(
                    wb,
                    &target_id,
                    None,
                    now,
                    RecoveryAttemptOutcome::InvalidProof,
                )?;
                return Err(error);
            }
        };
        let verified = self
            .lock()
            .verified
            .remove(&ticket)
            .filter(|ticket| ticket.expires_at > now)
            .ok_or(CeremonyError::UnknownOrExpired)?;
        let account_id = state
            .emails
            .values()
            .find(|record| {
                record.email == verified.email && record.status == AuthMethodStatus::Active
            })
            .map(|record| record.account_id.clone());
        let Some(account_id) = account_id else {
            record_recovery_attempt(
                wb,
                &target_id,
                None,
                now,
                RecoveryAttemptOutcome::InvalidProof,
            )?;
            return Err(CeremonyError::InvalidProof);
        };
        let Some(code) = state.find_active_recovery_code(&account_id, recovery_code) else {
            record_recovery_attempt(
                wb,
                &target_id,
                Some(&account_id),
                now,
                RecoveryAttemptOutcome::InvalidProof,
            )?;
            return Err(CeremonyError::InvalidProof);
        };
        let code_id = code.id.clone();

        let custody_valid = state
            .roots
            .get(&account_id)
            .and_then(|root| wb.unseal_custodied_account_root(&account_id, &root.sealed_seed))
            .and_then(|seed| hex::decode(seed).ok())
            .and_then(|seed| <[u8; 32]>::try_from(seed).ok())
            .and_then(|seed| gaugedesk_core::signature::SigningKey::from_seed(&seed).ok())
            .is_some_and(|signing| signing.public_key().as_str() == account_id);
        if !custody_valid {
            record_recovery_attempt(
                wb,
                &target_id,
                Some(&account_id),
                now,
                RecoveryAttemptOutcome::CustodyUnavailable,
            )?;
            return Err(CeremonyError::Unavailable);
        }

        let mut facts = decide_consume_recovery_code(&state, &account_id, &code_id, now)
            .map_err(|_| CeremonyError::InvalidProof)?;
        facts.push(AccountAuthFact::RecoveryAttempt(recovery_attempt(
            &target_id,
            Some(&account_id),
            now,
            RecoveryAttemptOutcome::Succeeded,
        )?));
        append_facts(wb.store_mut(), &facts).map_err(|_| CeremonyError::Unavailable)?;
        let session = wb
            .mint_account_session(&account_id, "recovery", self.session_ttl_secs)
            .ok_or(CeremonyError::Unavailable)?;
        Ok((account_id, session))
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

    /// Begin a user-verifying passkey ceremony for one named destructive
    /// operation. This is distinct from sign-in: it neither creates nor rotates
    /// an account session, and the resulting proof is useful only for the exact
    /// account and operation recorded here.
    pub fn start_authorization(
        &self,
        state: &AccountAuth,
        account_id: &str,
        operation: &str,
        now: u64,
    ) -> Result<(String, serde_json::Value), CeremonyError> {
        let account_id = account_id.trim();
        let operation = operation.trim();
        if account_id.is_empty() || operation.is_empty() {
            return Err(CeremonyError::InvalidProof);
        }
        let credentials: Vec<PasskeyCredential> = state
            .webauthn_methods
            .values()
            .filter(|record| {
                record.account_id == account_id && record.status == AuthMethodStatus::Active
            })
            .map(|record| serde_json::from_str(&record.verifier_json))
            .collect::<Result<_, _>>()
            .map_err(|_| CeremonyError::Unavailable)?;
        if credentials.is_empty() {
            return Err(CeremonyError::InvalidProof);
        }
        let (challenge, auth_state) = self.webauthn.start_authentication_with_creds_for_user(
            &account_user_handle(account_id),
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
        if pending.authorizations.len() >= PENDING_MAX {
            return Err(CeremonyError::Unavailable);
        }
        pending.authorizations.insert(
            ceremony_id.clone(),
            PendingAuthorization {
                account_id: account_id.to_owned(),
                operation: operation.to_owned(),
                state: auth_state,
                credentials: credential_map,
                expires_at: now.saturating_add(CEREMONY_TTL_SECS),
            },
        );
        Ok((ceremony_id, challenge))
    }

    /// Finish a destructive-operation ceremony and mint a response-only proof.
    /// Only the proof digest is retained. Updating the authenticator counter and
    /// issuing the proof happen after the same verified WebAuthn assertion; a
    /// failed assertion consumes the ceremony and mints nothing.
    pub fn finish_authorization(
        &self,
        wb: &mut crate::Workbench,
        account_id: &str,
        ceremony_id: &str,
        response: &AuthenticationResponse,
        now: u64,
    ) -> Result<String, CeremonyError> {
        let pending = self
            .lock()
            .authorizations
            .remove(ceremony_id)
            .filter(|pending| pending.expires_at > now)
            .ok_or(CeremonyError::UnknownOrExpired)?;
        if pending.account_id != account_id {
            return Err(CeremonyError::InvalidProof);
        }
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

        self.issue_authorization_proof_after_verification(
            &pending.account_id,
            &pending.operation,
            now,
        )
    }

    /// Mint the one-use proof after an authenticator has performed user
    /// verification. This is an internal composition seam rather than an HTTP
    /// route: passkeys call it above, and another accepted authenticator may use
    /// the same proof store only after completing its own verifier ceremony.
    pub fn issue_authorization_proof_after_verification(
        &self,
        account_id: &str,
        operation: &str,
        now: u64,
    ) -> Result<String, CeremonyError> {
        let account_id = account_id.trim();
        let operation = operation.trim();
        if account_id.is_empty() || operation.is_empty() {
            return Err(CeremonyError::InvalidProof);
        }
        let proof = random_token(32)?;
        let proof_id = authorization_proof_id(&proof);
        let mut store = self.lock();
        sweep(&mut store, now);
        if store.authorization_proofs.len() >= PENDING_MAX {
            return Err(CeremonyError::Unavailable);
        }
        store.authorization_proofs.insert(
            proof_id,
            AuthorizationProof {
                account_id: account_id.to_owned(),
                operation: operation.to_owned(),
                expires_at: now.saturating_add(AUTHORIZATION_PROOF_TTL_SECS),
            },
        );
        Ok(proof)
    }

    /// Consume an exact fresh-authorization proof. A presented proof is removed
    /// before its account, operation, or expiry is checked, so a wrong-context
    /// attempt cannot preserve it for replay elsewhere.
    pub fn consume_authorization_proof(
        &self,
        proof: &str,
        account_id: &str,
        operation: &str,
        now: u64,
    ) -> bool {
        let proof_id = authorization_proof_id(proof);
        let Some(record) = self.lock().authorization_proofs.remove(&proof_id) else {
            return false;
        };
        record.expires_at > now && record.account_id == account_id && record.operation == operation
    }

    /// Begin adding a passkey to an already-authenticated account. This is
    /// intentionally separate from initial registration: it neither creates a
    /// root nor re-proves an email, and the resulting verifier can only be
    /// admitted for the exact authenticated account supplied here.
    pub fn start_additional_registration(
        &self,
        state: &AccountAuth,
        account_id: &str,
        display_name: &str,
        now: u64,
    ) -> Result<(String, serde_json::Value), CeremonyError> {
        let account_id = account_id.trim();
        if account_id.is_empty() {
            return Err(CeremonyError::InvalidProof);
        }
        let username = state
            .emails
            .values()
            .find(|record| {
                record.account_id == account_id && record.status == AuthMethodStatus::Active
            })
            .map(|record| record.email.as_str())
            .unwrap_or(account_id);
        let existing = state
            .webauthn_methods
            .values()
            .filter(|record| {
                record.account_id == account_id && record.status == AuthMethodStatus::Active
            })
            .filter_map(|record| {
                serde_json::from_str::<PasskeyCredential>(&record.verifier_json).ok()
            })
            .map(|credential| credential.id)
            .collect::<Vec<_>>();
        let user_handle = account_user_handle(account_id);
        let display_name = display_name.trim();
        let display_name = if display_name.is_empty() {
            username
        } else {
            display_name
        };
        let (challenge, registration_state) =
            self.webauthn
                .start_registration(&user_handle, username, display_name, &existing);
        let ceremony_id = random_token(24)?;
        let challenge = serde_json::to_value(challenge).map_err(|_| CeremonyError::Unavailable)?;
        let mut pending = self.lock();
        sweep(&mut pending, now);
        if pending.additional_registrations.len() >= PENDING_MAX {
            return Err(CeremonyError::Unavailable);
        }
        pending.additional_registrations.insert(
            ceremony_id.clone(),
            PendingAdditionalRegistration {
                account_id: account_id.to_owned(),
                state: registration_state,
                expires_at: now.saturating_add(CEREMONY_TTL_SECS),
            },
        );
        Ok((ceremony_id, challenge))
    }

    /// Consume an add-passkey ceremony and return verifier facts for the caller
    /// to admit atomically with its command receipt. No session is minted: the
    /// person is already authenticated, and adding a method does not replace
    /// the current session.
    pub fn finish_additional_registration(
        &self,
        state: &AccountAuth,
        account_id: &str,
        ceremony_id: &str,
        response: &RegistrationResponse,
        label: &str,
        now: u64,
    ) -> Result<Vec<AccountAuthFact>, CeremonyError> {
        let pending = self
            .lock()
            .additional_registrations
            .remove(ceremony_id)
            .filter(|pending| pending.expires_at > now)
            .ok_or(CeremonyError::UnknownOrExpired)?;
        if pending.account_id != account_id {
            return Err(CeremonyError::InvalidProof);
        }
        let credential = self
            .webauthn
            .finish_registration(&pending.state, response)
            .map_err(|_| CeremonyError::InvalidProof)?;
        let credential_id = credential.id.to_b64url();
        let verifier_json =
            serde_json::to_string(&credential).map_err(|_| CeremonyError::Unavailable)?;
        decide_add_webauthn(
            state,
            WebAuthnMethodRecord::new(account_id, &credential_id, &verifier_json, label, now)
                .map_err(|_| CeremonyError::Unavailable)?,
        )
        .map_err(|_| CeremonyError::AlreadyExists)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyError {
    NotConfigured,
    InvalidEmail,
    InvalidProof,
    UnknownOrExpired,
    AlreadyExists,
    DeliveryFailed,
    RateLimited,
    Unavailable,
}

impl CeremonyError {
    pub fn response(self) -> Response {
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
            Self::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "account recovery is temporarily rate limited",
            ),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishRecoveryRequest {
    challenge_id: String,
    email_code: String,
    recovery_code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartAuthorizationRequest {
    operation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishAuthorizationRequest {
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

async fn post_recovery_start(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    Json(body): Json<BeginEmailRequest>,
) -> Response {
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    let now = unix_now();
    let Some(target_id) = recovery_target_id(&body.email) else {
        return CeremonyError::InvalidEmail.response();
    };
    {
        let mut guard = wb.lock_unpoisoned();
        let state = match AccountAuth::rebuild(guard.store_ref()) {
            Ok(state) => state,
            Err(_) => return CeremonyError::Unavailable.response(),
        };
        if recovery_is_limited(&state, &target_id, now) {
            if record_recovery_attempt(
                &mut guard,
                &target_id,
                None,
                now,
                RecoveryAttemptOutcome::RateLimited,
            )
            .is_err()
            {
                return CeremonyError::Unavailable.response();
            }
            return CeremonyError::RateLimited.response();
        }
    }
    let result =
        tokio::task::spawn_blocking(move || runtime.begin_recovery(&body.email, now)).await;
    match result.unwrap_or(Err(CeremonyError::Unavailable)) {
        Ok(challenge_id) => (
            StatusCode::ACCEPTED,
            Json(json!({"challenge_id": challenge_id, "expires_in": EMAIL_TTL_SECS})),
        )
            .into_response(),
        Err(error) => error.response(),
    }
}

async fn post_recovery_finish(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    Json(body): Json<FinishRecoveryRequest>,
) -> Response {
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    let result = runtime.finish_recovery(
        &mut wb.lock_unpoisoned(),
        &body.challenge_id,
        &body.email_code,
        &body.recovery_code,
        unix_now(),
    );
    session_response(result)
}

fn authenticated_account(wb: &crate::Workbench, headers: &HeaderMap) -> Option<String> {
    let account = wb.actor(crate::net_http::bearer(headers));
    if account == "anonymous" {
        None
    } else {
        Some(account)
    }
}

async fn post_authorization_start(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if crate::net_http::bearer(&headers).is_none()
        && crate::account_signin::hub_session_actor(&wb).is_some()
    {
        return crate::account_signin::proxy_account_authority(
            &wb,
            axum::http::Method::POST,
            "/auth/account/authorization/start".to_owned(),
            headers,
            body,
        )
        .await;
    }
    let body: StartAuthorizationRequest = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid authorization request").into_response()
        }
    };
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    let guard = wb.lock_unpoisoned();
    let Some(account) = authenticated_account(&guard, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            "authenticate before authorizing this operation",
        )
            .into_response();
    };
    let state = match AccountAuth::rebuild(guard.store_ref()) {
        Ok(state) => state,
        Err(_) => return CeremonyError::Unavailable.response(),
    };
    drop(guard);
    match runtime.start_authorization(&state, &account, &body.operation, unix_now()) {
        Ok((ceremony_id, public_key)) => Json(StartCeremonyResponse {
            ceremony_id,
            public_key,
        })
        .into_response(),
        Err(error) => error.response(),
    }
}

async fn post_authorization_finish(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if crate::net_http::bearer(&headers).is_none()
        && crate::account_signin::hub_session_actor(&wb).is_some()
    {
        return crate::account_signin::proxy_account_authority(
            &wb,
            axum::http::Method::POST,
            "/auth/account/authorization/finish".to_owned(),
            headers,
            body,
        )
        .await;
    }
    let body: FinishAuthorizationRequest = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid authorization request").into_response()
        }
    };
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    let mut guard = wb.lock_unpoisoned();
    let Some(account) = authenticated_account(&guard, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            "authenticate before authorizing this operation",
        )
            .into_response();
    };
    match runtime.finish_authorization(
        &mut guard,
        &account,
        &body.ceremony_id,
        &body.credential,
        unix_now(),
    ) {
        Ok(proof) => Json(json!({
            "authorization_proof": proof,
            "expires_in": AUTHORIZATION_PROOF_TTL_SECS,
        }))
        .into_response(),
        Err(error) => error.response(),
    }
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
        .route("/auth/account/recovery/start", post(post_recovery_start))
        .route("/auth/account/recovery/finish", post(post_recovery_finish))
        .route(
            "/auth/account/authorization/start",
            post(post_authorization_start),
        )
        .route(
            "/auth/account/authorization/finish",
            post(post_authorization_finish),
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
    store
        .authorizations
        .retain(|_, entry| entry.expires_at > now);
    store
        .authorization_proofs
        .retain(|_, entry| entry.expires_at > now);
    store
        .additional_registrations
        .retain(|_, entry| entry.expires_at > now);
}

fn authorization_proof_id(proof: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"gaugedesk:fresh-authorization:v1\0");
    digest.update(proof.as_bytes());
    hex::encode(digest.finalize())
}

fn recovery_attempt(
    target_id: &str,
    account_id: Option<&str>,
    attempted_at: u64,
    outcome: RecoveryAttemptOutcome,
) -> Result<RecoveryAttemptRecord, CeremonyError> {
    RecoveryAttemptRecord::new(
        &random_token(24)?,
        target_id,
        account_id,
        attempted_at,
        outcome,
    )
    .map_err(|_| CeremonyError::Unavailable)
}

fn recovery_is_limited(state: &AccountAuth, target_id: &str, now: u64) -> bool {
    state.invalid_recovery_attempts_since(
        target_id,
        now.saturating_sub(RECOVERY_ATTEMPT_WINDOW_SECS),
    ) >= RECOVERY_ATTEMPT_LIMIT
}

fn record_recovery_attempt(
    wb: &mut crate::Workbench,
    target_id: &str,
    account_id: Option<&str>,
    attempted_at: u64,
    outcome: RecoveryAttemptOutcome,
) -> Result<(), CeremonyError> {
    let record = recovery_attempt(target_id, account_id, attempted_at, outcome)?;
    append_facts(wb.store_mut(), &[AccountAuthFact::RecoveryAttempt(record)])
        .map_err(|_| CeremonyError::Unavailable)
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

    fn account_with_recovery_code() -> (
        AccountAuthRuntime,
        Arc<CapturingSender>,
        tempfile::TempDir,
        crate::Workbench,
        String,
    ) {
        let (runtime, sender) = runtime();
        let email_challenge = runtime.begin_email("alice@example.com", 1).unwrap();
        let email_code = sender.0.lock().unwrap().last().unwrap().1.clone();
        let email_ticket = runtime
            .complete_email(&email_challenge, &email_code, 2)
            .unwrap();
        let (registration_id, registration_options) = runtime
            .start_registration(&email_ticket, "Alice", 3)
            .unwrap();
        let authenticator = FakeAuthenticator::new();
        let registration = authenticator
            .registration_response(registration_options["challenge"].as_str().unwrap());
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(crate::content_vault::ContentVault::new(
            vault_dir.path(),
            Box::new(crate::at_rest::LoopbackKeyWrap::new([7_u8; 32])),
        ));
        let mut wb = crate::Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap())
            .with_content_vault(vault);
        let (account_id, _) = runtime
            .finish_registration(&mut wb, &registration_id, &registration, "Laptop", 4)
            .unwrap();
        let state = AccountAuth::rebuild(wb.store_ref()).unwrap();
        let prepared = crate::account_auth::RecoveryCodeRecord::prepare(
            &account_id,
            "batch-1",
            "salt-1",
            "GW-RECOVERY-CODE",
        )
        .unwrap();
        let facts = crate::account_auth::decide_replace_recovery_codes(
            &state,
            &account_id,
            "batch-1",
            5,
            vec![prepared],
        )
        .unwrap();
        append_facts(wb.store_mut(), &facts).unwrap();
        (runtime, sender, vault_dir, wb, account_id)
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

        let (authorization_id, authorization_options) = runtime
            .start_authorization(&updated, &account_id, "organization.delete", 18)
            .unwrap();
        let challenge = authorization_options["challenge"].as_str().unwrap();
        let assertion = authenticator.authentication_response(challenge);
        let proof = runtime
            .finish_authorization(&mut wb, &account_id, &authorization_id, &assertion, 19)
            .unwrap();
        assert!(runtime.consume_authorization_proof(
            &proof,
            &account_id,
            "organization.delete",
            20,
        ));
        assert!(!runtime.consume_authorization_proof(
            &proof,
            &account_id,
            "organization.delete",
            21,
        ));

        let updated = AccountAuth::rebuild(wb.store_ref()).unwrap();
        let (wrong_operation_id, wrong_operation_options) = runtime
            .start_authorization(&updated, &account_id, "organization.delete", 22)
            .unwrap();
        let assertion = authenticator
            .authentication_response(wrong_operation_options["challenge"].as_str().unwrap());
        let wrong_operation_proof = runtime
            .finish_authorization(&mut wb, &account_id, &wrong_operation_id, &assertion, 23)
            .unwrap();
        assert!(!runtime.consume_authorization_proof(
            &wrong_operation_proof,
            &account_id,
            "organization.ownership.transfer",
            24,
        ));
        assert!(!runtime.consume_authorization_proof(
            &wrong_operation_proof,
            &account_id,
            "organization.delete",
            24,
        ));

        let updated = AccountAuth::rebuild(wb.store_ref()).unwrap();
        let (expired_id, expired_options) = runtime
            .start_authorization(&updated, &account_id, "organization.delete", 25)
            .unwrap();
        let assertion =
            authenticator.authentication_response(expired_options["challenge"].as_str().unwrap());
        let expired_proof = runtime
            .finish_authorization(&mut wb, &account_id, &expired_id, &assertion, 26)
            .unwrap();
        assert!(!runtime.consume_authorization_proof(
            &expired_proof,
            &account_id,
            "organization.delete",
            26 + AUTHORIZATION_PROOF_TTL_SECS,
        ));
    }

    #[test]
    fn verified_email_and_one_recovery_code_restore_the_same_custodied_account() {
        let (runtime, sender, _vault_dir, mut wb, account_id) = account_with_recovery_code();
        let challenge = runtime.begin_recovery("Alice@Example.COM", 10).unwrap();
        let email_code = sender.0.lock().unwrap().last().unwrap().1.clone();
        let (recovered_account, session) = runtime
            .finish_recovery(&mut wb, &challenge, &email_code, "GW-RECOVERY-CODE", 11)
            .unwrap();

        assert_eq!(recovered_account, account_id);
        assert_eq!(
            wb.account_sessions().resolve(&session, 12).as_deref(),
            Some(account_id.as_str())
        );
        let state = AccountAuth::rebuild(wb.store_ref()).unwrap();
        assert_eq!(state.unused_recovery_code_count(&account_id), 0);
        assert_eq!(state.recovery_attempts.len(), 1);
        assert_eq!(
            state.recovery_attempts.values().next().unwrap().outcome,
            RecoveryAttemptOutcome::Succeeded
        );
        assert!(state
            .sessions
            .values()
            .any(|session| session.account_id == account_id && session.method == "recovery"));
    }

    #[test]
    fn recovery_attempts_are_one_challenge_each_audited_secret_free_and_rate_limited() {
        let (runtime, sender, _vault_dir, mut wb, account_id) = account_with_recovery_code();
        for now in 10..15 {
            let challenge = runtime.begin_recovery("alice@example.com", now).unwrap();
            let email_code = sender.0.lock().unwrap().last().unwrap().1.clone();
            assert_eq!(
                runtime.finish_recovery(&mut wb, &challenge, &email_code, "WRONG", now + 1),
                Err(CeremonyError::InvalidProof)
            );
            assert_eq!(
                runtime.finish_recovery(&mut wb, &challenge, &email_code, "WRONG", now + 1),
                Err(CeremonyError::UnknownOrExpired)
            );
        }

        let limited_challenge = runtime.begin_recovery("alice@example.com", 20).unwrap();
        let email_code = sender.0.lock().unwrap().last().unwrap().1.clone();
        assert_eq!(
            runtime.finish_recovery(
                &mut wb,
                &limited_challenge,
                &email_code,
                "GW-RECOVERY-CODE",
                21,
            ),
            Err(CeremonyError::RateLimited)
        );
        let state = AccountAuth::rebuild(wb.store_ref()).unwrap();
        assert_eq!(state.unused_recovery_code_count(&account_id), 1);
        assert_eq!(
            state
                .recovery_attempts
                .values()
                .filter(|attempt| attempt.outcome == RecoveryAttemptOutcome::InvalidProof)
                .count(),
            RECOVERY_ATTEMPT_LIMIT
        );
        assert_eq!(
            state
                .recovery_attempts
                .values()
                .filter(|attempt| attempt.outcome == RecoveryAttemptOutcome::RateLimited)
                .count(),
            1
        );
        for row in wb
            .store_ref()
            .records(
                crate::account_auth::ACCOUNT_AUTH_SCOPE,
                "account_auth_recovery_attempt",
            )
            .unwrap()
        {
            assert!(!row.contains("WRONG"));
            assert!(!row.contains("GW-RECOVERY-CODE"));
            assert!(!row.contains("alice@example.com"));
            assert!(!row.contains(&email_code));
        }

        let later = 21 + RECOVERY_ATTEMPT_WINDOW_SECS + 1;
        let challenge = runtime.begin_recovery("alice@example.com", later).unwrap();
        let email_code = sender.0.lock().unwrap().last().unwrap().1.clone();
        let (recovered, _) = runtime
            .finish_recovery(
                &mut wb,
                &challenge,
                &email_code,
                "GW-RECOVERY-CODE",
                later + 1,
            )
            .unwrap();
        assert_eq!(recovered, account_id);
    }

    #[test]
    fn an_invalid_recovery_email_proof_is_audited_without_consuming_a_recovery_code() {
        let (runtime, _sender, _vault_dir, mut wb, account_id) = account_with_recovery_code();
        let challenge = runtime.begin_recovery("alice@example.com", 10).unwrap();
        assert_eq!(
            runtime.finish_recovery(&mut wb, &challenge, "wrong-email-code", "WRONG", 11),
            Err(CeremonyError::InvalidProof)
        );
        let state = AccountAuth::rebuild(wb.store_ref()).unwrap();
        assert_eq!(state.unused_recovery_code_count(&account_id), 1);
        assert_eq!(state.recovery_attempts.len(), 1);
        assert_eq!(
            state.recovery_attempts.values().next().unwrap().outcome,
            RecoveryAttemptOutcome::InvalidProof
        );
    }

    #[test]
    fn recovery_email_cannot_be_replayed_as_account_registration_proof() {
        let (runtime, sender, _vault_dir, mut wb, _) = account_with_recovery_code();
        let challenge = runtime.begin_recovery("alice@example.com", 10).unwrap();
        let email_code = sender.0.lock().unwrap().last().unwrap().1.clone();
        assert_eq!(
            runtime.complete_email(&challenge, &email_code, 11),
            Err(CeremonyError::UnknownOrExpired)
        );
        assert_eq!(
            runtime.finish_recovery(&mut wb, &challenge, &email_code, "GW-RECOVERY-CODE", 12,),
            Err(CeremonyError::UnknownOrExpired)
        );
    }

    #[test]
    fn an_authenticated_account_can_add_a_passkey_without_creating_a_root() {
        let (runtime, _) = runtime();
        let mut wb = crate::Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap());
        append_facts(
            wb.store_mut(),
            &[AccountAuthFact::Email(
                VerifiedEmailRecord::new("person:alice", "alice@example.com", 1).unwrap(),
            )],
        )
        .unwrap();
        let state = AccountAuth::rebuild(wb.store_ref()).unwrap();
        let (ceremony_id, options) = runtime
            .start_additional_registration(&state, "person:alice", "Alice", 2)
            .unwrap();
        let challenge = options["challenge"].as_str().unwrap();
        let authenticator = FakeAuthenticator::new();
        let response = authenticator.registration_response(challenge);
        let facts = runtime
            .finish_additional_registration(
                &state,
                "person:alice",
                &ceremony_id,
                &response,
                "Security key",
                3,
            )
            .unwrap();
        append_facts(wb.store_mut(), &facts).unwrap();

        let updated = AccountAuth::rebuild(wb.store_ref()).unwrap();
        assert_eq!(updated.active_webauthn_count("person:alice"), 1);
        assert!(updated.roots.is_empty());
        assert_eq!(
            runtime.finish_additional_registration(
                &updated,
                "person:alice",
                &ceremony_id,
                &response,
                "Security key",
                4,
            ),
            Err(CeremonyError::UnknownOrExpired)
        );
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
