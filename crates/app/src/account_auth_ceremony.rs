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

/// Whether `host` may assert `rp_id`, per WebAuthn's registrable-suffix rule.
///
/// Suffix matching here is on label boundaries, never raw string ends:
/// `evilgaugewright.com` ends with `gaugewright.com` as text while being an
/// unrelated registration, and accepting it would let that origin mint
/// credentials for this one.
///
/// A bare suffix with no dot is refused except by exact match, so no origin can
/// claim a whole top-level domain as its RP id. Exact match is what keeps
/// single-label development hosts such as `localhost` working.
fn host_admits_rp_id(host: Option<&str>, rp_id: &str) -> bool {
    let Some(host) = host else { return false };
    if host == rp_id {
        return true;
    }
    rp_id.contains('.') && host.ends_with(&format!(".{rp_id}"))
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
        // WebAuthn (§5.1.3) admits an RP id that is the origin's effective
        // domain *or a registrable suffix of it*, and the suffix case is the
        // one a multi-subdomain deployment needs: one passkey created in the
        // Desk UI has to authenticate against the account API on a sibling
        // host. Demanding equality quietly forces the RP id down to a single
        // subdomain, and an RP id is baked into every credential ever
        // registered under it — so the narrow choice cannot be taken back
        // later without invalidating them all.
        if !host_admits_rp_id(parsed.host_str(), rp_id) {
            return Err(
                "WebAuthn RP id must equal the origin host or be a registrable suffix of it".into(),
            );
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

/// The verified provider facts a first-time Google signup carries into the
/// passkey ceremony (ADR 0146 §1).
///
/// It is deliberately not an account, a session, or a credential. It is the
/// evidence that lets `finish_registration` attach one more authenticator in
/// the same atomic append that creates the account — so the Google subject is
/// linked *to* the root rather than standing in for it, and an account never
/// exists whose only way in is a provider login the person could lose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumerSignupContext {
    pub connection_id: String,
    pub issuer: String,
    pub subject: String,
    /// Non-secret label for the native session this signup may hand a desktop.
    pub label: String,
    pub provider_expires_at_ms: u64,
    pub refresh_token: Option<crate::secret::Secret>,
    pub native_return: Option<String>,
    pub native_handoff_challenge: Option<String>,
}

/// What one finished account creation produced. The recovery codes are the one
/// and only plaintext copy; the signup context comes back so the route can hand
/// a desktop its session *after* those codes have been shown.
#[derive(Debug, PartialEq, Eq)]
struct RegistrationOutcome {
    account_id: String,
    session: String,
    recovery_codes: Vec<String>,
    consumer_signup: Option<ConsumerSignupContext>,
}

struct PendingRegistration {
    email: String,
    account_id: String,
    root_seed: [u8; 32],
    state: RegistrationState,
    /// Present only for the provider entrance. `None` is the email-code
    /// entrance, which links no subject.
    consumer_signup: Option<ConsumerSignupContext>,
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
    /// The one origin WebAuthn will accept, kept so the provider callback can
    /// send a first-time signup to exactly the page that can complete it.
    origin: String,
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
            origin: config.origin.clone(),
        })
    }

    /// The exact origin a passkey ceremony must be served from.
    ///
    /// `passkey-auth` compares `clientDataJSON.origin` to this by string
    /// equality, so a signup redirected anywhere else — the API host that
    /// served the provider callback, or the post-login Console — meets the
    /// authenticator and *then* fails verification, after the person has
    /// already been asked for their fingerprint. Reading it off the runtime
    /// rather than re-deriving it from the environment is what makes the two
    /// the same value by construction instead of by convention.
    pub fn origin(&self) -> &str {
        &self.origin
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
        self.start_registration_for_verified_email(&ticket.email, display_name, None, now)
    }

    /// Begin passkey registration for an address whose control is already
    /// proved, whichever way it was proved.
    ///
    /// Step 1 of ADR 0146 §1 is "verify an email address", not "send a code".
    /// An emailed code proves it, and so does an `email_verified` claim on a
    /// signature-verified id-token — the same claim the enterprise lane already
    /// admits as its organization-admission input. The caller owns that proof
    /// and consumes it; nothing in here re-derives it, and nothing in here
    /// accepts an address a request merely asserted.
    fn start_registration_for_verified_email(
        &self,
        email: &str,
        display_name: &str,
        consumer_signup: Option<ConsumerSignupContext>,
        now: u64,
    ) -> Result<(String, serde_json::Value), CeremonyError> {
        let email = normalize_email_contact(email).ok_or(CeremonyError::InvalidEmail)?;
        let (root_seed, account_id) = generate_account_root()?;
        let user_handle = account_user_handle(&account_id);
        let display_name = if display_name.trim().is_empty() {
            email.as_str()
        } else {
            display_name.trim()
        };
        let (challenge, state) =
            self.webauthn
                .start_registration(&user_handle, &email, display_name, &[]);
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
                email,
                account_id,
                root_seed,
                state,
                consumer_signup,
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
    ) -> Result<RegistrationOutcome, CeremonyError> {
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
        // A provider entrance attaches its verified subject here, in this list,
        // and nowhere else. Writing it at the callback instead — or in any
        // follow-up request once the account exists — opens a window in which
        // an account's only authenticator is the Google login, which is exactly
        // the unrecoverable account ADR 0146 §1 forbids. This is the same
        // reducer the link ceremony uses, so a subject already held by another
        // account is refused rather than stolen.
        if let Some(signup) = &pending.consumer_signup {
            facts.extend(
                crate::account_auth::decide_link_external_subject(
                    &state,
                    crate::account_auth::ExternalSubjectRecord::new(
                        &pending.account_id,
                        &signup.connection_id,
                        &signup.issuer,
                        &signup.subject,
                        crate::account_auth::ExternalSubjectKind::ConsumerOidc,
                        now,
                    )
                    .map_err(|_| CeremonyError::Unavailable)?,
                )
                .map_err(|_| CeremonyError::AlreadyExists)?,
            );
        }
        // ADR 0146 §2 requires provider-neutral recovery: a verified email
        // challenge plus one unused recovery code. An account created without a
        // batch can never satisfy that, so the batch is part of creating the
        // account rather than a later step somebody may not take.
        //
        // One mint site for both entrances. A provider signup that minted its
        // own batch somewhere else would be a second place this can be got
        // wrong, and getting it wrong means an account nobody can get back into.
        let (recovery_facts, recovery_codes) =
            mint_recovery_batch(&state, &pending.account_id, now)?;
        facts.extend(recovery_facts);
        // Root custody, verified email, passkey, provider subject and recovery
        // batch in one append: either the whole account exists, with a way back
        // in, or none of it does.
        append_facts(wb.store_mut(), &facts).map_err(|_| CeremonyError::Unavailable)?;
        crate::auth_oidc::provision_web_account(wb, &pending.account_id, true);
        // "passkey" on both entrances, and load-bearing: the person did just
        // prove a passkey, and `independent_account_method` admits it — so they
        // can link a second provider immediately instead of being told to sign
        // in again with the credential they are holding.
        let session = wb
            .mint_account_session(&pending.account_id, "passkey", self.session_ttl_secs)
            .ok_or(CeremonyError::Unavailable)?;
        Ok(RegistrationOutcome {
            account_id: pending.account_id,
            session,
            recovery_codes,
            consumer_signup: pending.consumer_signup,
        })
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
#[serde(deny_unknown_fields)]
struct ClaimConsumerSignupRequest {
    ticket: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartConsumerSignupRegistrationRequest {
    ticket: String,
    #[serde(default)]
    display_name: String,
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
    registration_response(result, &auth)
}

/// What the signup page may read about a parked provider ticket.
///
/// Non-secret projection only: the address the provider attested and the name
/// it offered, so the page can say whose account it is about to create before
/// it asks for a fingerprint. It deliberately does not consume the ticket —
/// rendering a sentence must not spend the credential the ceremony still needs
/// — and it returns nothing that could be replayed anywhere else.
async fn post_consumer_signup_claim(
    Extension(auth): Extension<AuthShellState>,
    headers: HeaderMap,
    Json(body): Json<ClaimConsumerSignupRequest>,
) -> Response {
    if let Err(error) = runtime(&auth) {
        return error.response();
    }
    let presented = crate::net_http::signup_binding_cookie(&headers).unwrap_or_default();
    let Some(signup) = auth
        .pending_consumer_signup_mut()
        .peek(&body.ticket, std::time::Instant::now())
        // The browser that earned the ticket, or nobody. Refused here and not
        // only at registration so a planted link dead-ends before it can print
        // somebody else's address on a card that says "create your account".
        .filter(|signup| {
            crate::auth_oidc::binding_matches(signup.browser_binding.expose(), presented)
        })
        .map(|signup| {
            json!({
                "email": signup.verified_email,
                "display_name": signup.display_name,
                "provider": "google",
            })
        })
    else {
        return CeremonyError::UnknownOrExpired.response();
    };
    Json(signup).into_response()
}

/// Begin passkey creation for a first-time provider signup.
///
/// This is `post_registration_start` with step 1 already satisfied: the ticket
/// is spent here instead of an emailed code, and the address inside it came
/// from a verified id-token rather than from this request. Everything after —
/// the fresh root, the user handle, the WebAuthn ceremony — is the same code
/// the email entrance runs, because there is only one way to create an account.
async fn post_consumer_signup_registration_start(
    Extension(auth): Extension<AuthShellState>,
    headers: HeaderMap,
    Json(body): Json<StartConsumerSignupRegistrationRequest>,
) -> Response {
    let runtime = match runtime(&auth) {
        Ok(runtime) => runtime,
        Err(error) => return error.response(),
    };
    let presented = crate::net_http::signup_binding_cookie(&headers).unwrap_or_default();
    // Checked BEFORE the take, so a mismatched browser cannot spend somebody
    // else's ticket even to fail. `take` is still the only exit that consumes
    // it, so the rightful browser's ticket survives an attacker's attempt.
    let matches_binding = auth
        .pending_consumer_signup_mut()
        .peek(&body.ticket, std::time::Instant::now())
        .map(|signup| crate::auth_oidc::binding_matches(signup.browser_binding.expose(), presented))
        .unwrap_or(false);
    if !matches_binding {
        return CeremonyError::UnknownOrExpired.response();
    }
    let Some(signup) = auth
        .pending_consumer_signup_mut()
        .take(&body.ticket, std::time::Instant::now())
    else {
        return CeremonyError::UnknownOrExpired.response();
    };
    let display_name = if body.display_name.trim().is_empty() {
        signup.display_name.clone().unwrap_or_default()
    } else {
        body.display_name.clone()
    };
    let context = ConsumerSignupContext {
        connection_id: signup.connection_id.clone(),
        issuer: signup.issuer.clone(),
        subject: signup.subject.clone(),
        label: signup.verified_email.clone(),
        provider_expires_at_ms: signup.provider_expires_at_ms,
        refresh_token: signup.refresh_token.clone(),
        native_return: signup.native_return.clone(),
        native_handoff_challenge: signup.native_handoff_challenge.clone(),
    };
    match runtime.start_registration_for_verified_email(
        &signup.verified_email,
        &display_name,
        Some(context),
        unix_now(),
    ) {
        Ok((ceremony_id, public_key)) => Json(StartCeremonyResponse {
            ceremony_id,
            public_key,
        })
        .into_response(),
        Err(error) => error.response(),
    }
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

/// The account-creation response. Carries the one and only copy of the recovery
/// codes: they exist in plaintext for the length of this response and nowhere
/// else, because the store holds salted hashes. A client that drops them cannot
/// ask again — it has to mint a new batch, which invalidates these.
fn registration_response(
    result: Result<RegistrationOutcome, CeremonyError>,
    auth: &AuthShellState,
) -> Response {
    match result {
        Ok(outcome) => {
            let mut body = json!({
                "account_id": outcome.account_id,
                "recovery_codes": outcome.recovery_codes,
            });
            // A desktop signup finished its ceremony in the system browser, so
            // the browser is where the codes are. Return the handoff URL rather
            // than redirecting to it: a 302 to `gaugewright://` raises the
            // desktop window over the one tab that will ever hold these codes,
            // and the person closes it without having read them. The page shows
            // them and navigates only when they say they have saved them.
            let handoff = outcome.consumer_signup.as_ref().and_then(|signup| {
                let native_return = signup.native_return.as_deref()?;
                let challenge = signup.native_handoff_challenge.clone()?;
                let code = auth.issue_account_native_handoff(
                    &outcome.account_id,
                    "passkey",
                    &signup.label,
                    signup.provider_expires_at_ms,
                    signup
                        .refresh_token
                        .as_ref()
                        .map(|token| token.expose().to_owned()),
                    challenge,
                );
                Some(format!("{native_return}#code={code}"))
            });
            let native = handoff.is_some();
            if let (Some(handoff), Some(map)) = (handoff, body.as_object_mut()) {
                map.insert("native_return".into(), json!(handoff));
            }
            let mut response = Json(body).into_response();
            // The same rule the login lane follows, and for the same reason.
            // `requires_account_session(native_login) -> !native_login`
            // (auth_oidc.rs): an ordinary desktop login mints NO browser session
            // — it hands back a single-use code and the sealed grant lives in
            // the control plane. A desktop SIGNUP was leaving a live
            // `gw_session` behind in the system browser as well as issuing that
            // code, so finishing signup silently left a second, longer-lived way
            // into the account on a browser the person may not even think of as
            // signed in, and which the desktop cannot sign out.
            //
            // The page needs no session to finish: the codes are in this body,
            // and the button navigates to the handoff URL already in it.
            if !native {
                crate::auth_oidc::append_session_cookies(&mut response, &outcome.session);
            }
            response
        }
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
        // The provider entrance to the same ceremony (ADR 0146 §1). There is
        // deliberately no `consumer-signup/register/finish`: the finish above
        // keys off the ceremony id and already knows what it is finishing, so a
        // second finish route would be a second place to get atomicity wrong.
        .route(
            "/auth/account/consumer-signup/claim",
            post(post_consumer_signup_claim),
        )
        .route(
            "/auth/account/consumer-signup/register/start",
            post(post_consumer_signup_registration_start),
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

/// How many recovery codes a new account is issued, and how long each is.
///
/// Ten is enough that losing a couple to a bad transcription does not strand
/// anyone, and few enough to be worth writing down. Twelve characters from a
/// 32-symbol alphabet is about 60 bits, against a path that is rate limited and
/// also demands a verified email challenge.
const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_GROUPS: usize = 3;
/// No I, O, 0 or 1: these are read off a screen and typed back, often from
/// paper, and the pairs that collide there are the ones that strand a person on
/// the one path they have left.
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// One recovery code, as `XXXX-XXXX-XXXX`.
///
/// The alphabet is exactly 32 symbols, so every byte maps to one without
/// rejection and without modulo bias.
fn random_recovery_code() -> Result<String, CeremonyError> {
    let mut bytes = vec![0_u8; RECOVERY_CODE_GROUPS * 4];
    getrandom::getrandom(&mut bytes).map_err(|_| CeremonyError::Unavailable)?;
    let symbols: Vec<char> = bytes
        .iter()
        .map(|byte| RECOVERY_ALPHABET[usize::from(*byte) % RECOVERY_ALPHABET.len()] as char)
        .collect();
    Ok(symbols
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-"))
}

/// Mint a fresh batch for `account_id`, returning the facts to append and the
/// plaintext codes to show the person once.
///
/// The store keeps only a salted hash per code (`RecoveryCodeRecord::prepare`),
/// so this is the only moment the plaintext exists anywhere. Nothing reads it
/// back, and there is no route that will print it again.
fn mint_recovery_batch(
    state: &AccountAuth,
    account_id: &str,
    now: u64,
) -> Result<(Vec<AccountAuthFact>, Vec<String>), CeremonyError> {
    let batch_id = random_token(16)?;
    let mut plaintext = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut prepared = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = random_recovery_code()?;
        let salt = random_token(16)?;
        prepared.push(
            crate::account_auth::RecoveryCodeRecord::prepare(account_id, &batch_id, &salt, &code)
                .map_err(|_| CeremonyError::Unavailable)?,
        );
        plaintext.push(code);
    }
    let facts = crate::account_auth::decide_replace_recovery_codes(
        state, account_id, &batch_id, now, prepared,
    )
    .map_err(|_| CeremonyError::Unavailable)?;
    Ok((facts, plaintext))
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
        let RegistrationOutcome {
            account_id,
            recovery_codes: issued_codes,
            ..
        } = runtime
            .finish_registration(&mut wb, &registration_id, &registration, "Laptop", 4)
            .unwrap();
        // Creating the account issues the batch (ADR 0146 §2). This used to seed
        // one by hand, which is exactly why nothing noticed that no production
        // path minted one.
        assert_eq!(issued_codes.len(), RECOVERY_CODE_COUNT);
        assert!(issued_codes
            .iter()
            .all(|code| code.len() == RECOVERY_CODE_GROUPS * 5 - 1));
        assert_eq!(
            issued_codes
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            RECOVERY_CODE_COUNT,
            "every issued code is distinct",
        );
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

    /// The deployed shape: the ceremony runs in the Desk UI while the account
    /// API answers on a sibling host, so one passkey has to span both. Demanding
    /// an exact host match made that unconfigurable — the hosted Hub refused to
    /// start with `gaugewright.com` against `https://desk.gaugewright.com`, and
    /// reported it as three missing variables that were in fact all set.
    #[test]
    fn a_registrable_suffix_rp_id_spans_sibling_hosts() {
        assert!(AccountAuthConfig::new(
            "gaugewright.com",
            "GaugeDesk",
            "https://desk.gaugewright.com"
        )
        .is_ok());
        assert!(AccountAuthConfig::new(
            "example.com",
            "GaugeDesk",
            "https://deep.nested.example.com"
        )
        .is_ok());

        // Suffix matching is on label boundaries. This host merely *ends with*
        // the RP id as text and is an unrelated registration; admitting it would
        // let it mint credentials for the real domain.
        assert!(
            AccountAuthConfig::new("example.com", "GaugeDesk", "https://evilexample.com").is_err()
        );
        // Nothing may claim a whole top-level domain as its RP id.
        assert!(AccountAuthConfig::new("com", "GaugeDesk", "https://example.com").is_err());
        // The parent may not claim a child.
        assert!(
            AccountAuthConfig::new("desk.example.com", "GaugeDesk", "https://example.com").is_err()
        );
        // Exact match is still what single-label development hosts rely on.
        assert!(AccountAuthConfig::new("localhost", "GaugeDesk", "http://localhost:3000").is_ok());
    }

    #[test]
    fn production_configuration_requires_https_and_an_admissible_rp_host() {
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

    fn test_signup_context() -> ConsumerSignupContext {
        ConsumerSignupContext {
            connection_id: "consumer-google".into(),
            issuer: "https://accounts.google.com".into(),
            subject: "google-subject-new".into(),
            label: "new.person@example.com".into(),
            provider_expires_at_ms: 0,
            refresh_token: None,
            native_return: None,
            native_handoff_challenge: None,
        }
    }

    fn signup_workbench() -> (tempfile::TempDir, crate::Workbench) {
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(crate::content_vault::ContentVault::new(
            vault_dir.path(),
            Box::new(crate::at_rest::LoopbackKeyWrap::new([9_u8; 32])),
        ));
        let wb = crate::Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap())
            .with_content_vault(vault);
        (vault_dir, wb)
    }

    /// The whole of ADR 0146 §1 for the Google entrance, in one assertion set.
    ///
    /// The order is the decision: root custody, verified email, passkey, *then*
    /// the provider subject, then the recovery batch — all in the single append
    /// this asserts. Move the link out of here and there is a moment when an
    /// account's only way in is a Google login the person could lose, which is
    /// exactly the unrecoverable account §1 exists to forbid.
    /// A desktop signup must not leave a browser session behind.
    ///
    /// The login lane has always held this rule —
    /// `requires_account_session(native_login) -> !native_login` — because a
    /// native login hands back a single-use code and keeps the sealed grant in
    /// the control plane, deliberately leaving the system browser signed out.
    /// Signup issued that code AND set `gw_session`, so finishing it left a
    /// second, longer-lived way into a brand-new account on a browser the
    /// person may not think of as signed in and the desktop cannot sign out of.
    #[test]
    fn a_native_signup_leaves_no_session_in_the_system_browser() {
        let cookies = |response: &Response| -> Vec<String> {
            response
                .headers()
                .get_all(axum::http::header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(str::to_owned)
                .collect()
        };

        let (runtime, _sender) = runtime();
        let auth = crate::auth_oidc::AuthShellState::default()
            .with_account_auth(std::sync::Arc::new(runtime));

        // The web entrance: no native return, so the browser IS the client and
        // keeps its session exactly as it always has.
        let web = registration_response(
            Ok(RegistrationOutcome {
                account_id: "account:web".into(),
                session: "web-session-token".into(),
                recovery_codes: vec!["AAAA-BBBB-CCCC".into()],
                consumer_signup: None,
            }),
            &auth,
        );
        let web_cookies = cookies(&web);
        assert!(
            web_cookies
                .iter()
                .any(|c| c.starts_with(crate::net_http::SESSION_COOKIE)),
            "a browser signup still gets its session; this rule is about the \
             native lane only",
        );

        // The desktop entrance: a native return and a handoff challenge, so the
        // one-time code is the way back and the browser must stay signed out.
        let native = registration_response(
            Ok(RegistrationOutcome {
                account_id: "account:desk".into(),
                session: "desk-session-token".into(),
                recovery_codes: vec!["DDDD-EEEE-FFFF".into()],
                consumer_signup: Some(ConsumerSignupContext {
                    connection_id: "consumer-google".into(),
                    issuer: "https://accounts.google.com".into(),
                    subject: "google-subject-desk".into(),
                    label: "desk.person@example.com".into(),
                    provider_expires_at_ms: 0,
                    refresh_token: None,
                    native_return: Some("gaugewright://auth/callback".into()),
                    native_handoff_challenge: Some("challenge-1".into()),
                }),
            }),
            &auth,
        );
        let native_cookies = cookies(&native);
        assert!(
            !native_cookies
                .iter()
                .any(|c| c.starts_with(crate::net_http::SESSION_COOKIE)),
            "a desktop signup must not set gw_session in the system browser; \
             got {native_cookies:?}",
        );
    }

    /// The route, not the store. The store's `take` was already single-use and
    /// already tested, and that is exactly why this gap survived review: the
    /// handler is free to call `peek` instead, and nothing noticed. Changing
    /// `post_consumer_signup_registration_start` from `.take(..)` to
    /// `.peek(..).cloned()` left the whole 1294-test suite green while making
    /// one Google callback able to mint unlimited accounts against the same
    /// verified identity for the ticket's ten-minute life.
    ///
    /// So this drives the handler itself, twice, with the same ticket.
    #[tokio::test]
    async fn the_signup_route_spends_its_ticket_exactly_once() {
        const BINDING: &str = "binding-secret-for-this-browser";
        let (runtime, _sender) = runtime();
        let auth = crate::auth_oidc::AuthShellState::default()
            .with_account_auth(std::sync::Arc::new(runtime));

        let ticket = auth
            .pending_consumer_signup_mut()
            .begin(
                crate::auth_oidc::PendingConsumerSignup {
                    verified_email: "new.person@example.com".into(),
                    connection_id: "consumer-google".into(),
                    connection_revision: "rev-1".into(),
                    issuer: "https://accounts.google.com".into(),
                    subject: "google-subject-new".into(),
                    display_name: Some("New Person".into()),
                    refresh_token: None,
                    provider_expires_at_ms: 0,
                    native_return: None,
                    native_handoff_challenge: None,
                    browser_binding: crate::secret::Secret::new(BINDING),
                },
                std::time::Instant::now(),
            )
            .expect("a ticket is minted");

        let request = || StartConsumerSignupRegistrationRequest {
            ticket: ticket.clone(),
            display_name: "New Person".into(),
        };

        // The browser that earned the ticket presents its binding cookie; a
        // planted link arrives without one.
        let bound = || {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::COOKIE,
                format!("gw_signup_binding={BINDING}").parse().unwrap(),
            );
            headers
        };

        let unbound = post_consumer_signup_registration_start(
            Extension(auth.clone()),
            HeaderMap::new(),
            Json(request()),
        )
        .await;
        assert_eq!(
            unbound.status(),
            CeremonyError::UnknownOrExpired.response().status(),
            "a ticket presented without its binding is refused — that is a link \
             planted on somebody else's browser",
        );
        let wrong = {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::COOKIE,
                "gw_signup_binding=not-the-binding".parse().unwrap(),
            );
            post_consumer_signup_registration_start(
                Extension(auth.clone()),
                headers,
                Json(request()),
            )
            .await
        };
        assert_eq!(
            wrong.status(),
            CeremonyError::UnknownOrExpired.response().status(),
            "a wrong binding is refused",
        );
        assert!(
            auth.pending_consumer_signup_mut()
                .peek(&ticket, std::time::Instant::now())
                .is_some(),
            "and neither attempt SPENT the ticket — an attacker must not be able \
             to burn the ticket the rightful browser still needs",
        );

        let first = post_consumer_signup_registration_start(
            Extension(auth.clone()),
            bound(),
            Json(request()),
        )
        .await;
        assert_eq!(
            first.status(),
            axum::http::StatusCode::OK,
            "the first redemption starts the WebAuthn ceremony",
        );

        let second = post_consumer_signup_registration_start(
            Extension(auth.clone()),
            bound(),
            Json(request()),
        )
        .await;
        assert_eq!(
            second.status(),
            CeremonyError::UnknownOrExpired.response().status(),
            "a replayed ticket must find nothing — a bearer for one verified \
             identity that can be redeemed twice is a bearer for two accounts",
        );

        assert!(
            auth.pending_consumer_signup_mut()
                .peek(&ticket, std::time::Instant::now())
                .is_none(),
            "the ticket is gone from the store, not merely refused",
        );
    }

    #[test]
    fn a_google_signup_creates_the_account_its_passkey_its_codes_and_its_link_together() {
        let (runtime, _sender) = runtime();
        let (_vault_dir, mut wb) = signup_workbench();
        let signup = test_signup_context();

        // No emailed code anywhere on this path: step 1 arrived verified.
        let (ceremony_id, options) = runtime
            .start_registration_for_verified_email(
                "New.Person@Example.com",
                "New Person",
                Some(signup.clone()),
                10,
            )
            .unwrap();
        let authenticator = FakeAuthenticator::new();
        let response = authenticator.registration_response(options["challenge"].as_str().unwrap());
        let outcome = runtime
            .finish_registration(&mut wb, &ceremony_id, &response, "Laptop", 11)
            .unwrap();

        // Recovery codes: minted exactly once, by the one mint site, and
        // returned here and nowhere else.
        assert_eq!(outcome.recovery_codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(
            outcome
                .recovery_codes
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            RECOVERY_CODE_COUNT,
        );

        let state = AccountAuth::rebuild(wb.store_ref()).unwrap();
        // The account is the root, not the Google subject.
        assert!(state.roots.contains_key(&outcome.account_id));
        assert_ne!(outcome.account_id, signup.subject);
        // The address Google attested is a verified contact on it, normalized.
        assert_eq!(
            state.account_holding_active_email("new.person@example.com"),
            Some(outcome.account_id.as_str()),
        );
        // A passkey — the independent authenticator §1 requires before the
        // account exists at all.
        assert_eq!(state.active_webauthn_count(&outcome.account_id), 1);
        // Recovery is possible, because a batch exists.
        assert!(state
            .find_active_recovery_code(&outcome.account_id, &outcome.recovery_codes[0])
            .is_some());
        // And Google is linked *onto* that account, which is what makes the
        // next sign-in resolve. This assertion is the one that proves the bug
        // is fixed rather than merely routed around.
        let link = state
            .active_external_subject(
                &signup.connection_id,
                &signup.issuer,
                &signup.subject,
                crate::account_auth::ExternalSubjectKind::ConsumerOidc,
            )
            .expect("the Google subject is linked to the new account");
        assert_eq!(link.account_id, outcome.account_id);

        // The session names the passkey that was just proved, so this person can
        // link a second provider without being asked to authenticate again.
        assert_eq!(
            wb.account_sessions()
                .resolve(&outcome.session, 12)
                .as_deref(),
            Some(outcome.account_id.as_str()),
        );

        // The ceremony is single-use, like the email-code entrance beside it.
        assert_eq!(
            runtime.finish_registration(&mut wb, &ceremony_id, &response, "Laptop", 13),
            Err(CeremonyError::UnknownOrExpired),
        );
    }

    /// The link goes through the same reducer the link ceremony uses, so a
    /// subject another account already holds is refused rather than stolen —
    /// and because the refusal happens before the single append, the attempt
    /// leaves no half-made account behind.
    #[test]
    fn a_google_subject_another_account_holds_is_refused_and_writes_nothing() {
        let (runtime, _sender) = runtime();
        let (_vault_dir, mut wb) = signup_workbench();
        let signup = test_signup_context();

        // Somebody else already holds this subject.
        let existing = crate::account_auth::ExternalSubjectRecord::new(
            "account:alice",
            &signup.connection_id,
            &signup.issuer,
            &signup.subject,
            crate::account_auth::ExternalSubjectKind::ConsumerOidc,
            5,
        )
        .unwrap();
        append_facts(
            wb.store_mut(),
            &[AccountAuthFact::ExternalSubject(existing)],
        )
        .unwrap();
        let before = AccountAuth::rebuild(wb.store_ref()).unwrap();

        let (ceremony_id, options) = runtime
            .start_registration_for_verified_email(
                "new.person@example.com",
                "New Person",
                Some(signup.clone()),
                10,
            )
            .unwrap();
        let authenticator = FakeAuthenticator::new();
        let response = authenticator.registration_response(options["challenge"].as_str().unwrap());
        assert_eq!(
            runtime.finish_registration(&mut wb, &ceremony_id, &response, "Laptop", 11),
            Err(CeremonyError::AlreadyExists),
        );

        let after = AccountAuth::rebuild(wb.store_ref()).unwrap();
        assert_eq!(after.roots.len(), before.roots.len());
        assert_eq!(after.emails.len(), before.emails.len());
        assert_eq!(after.webauthn_methods.len(), before.webauthn_methods.len());
        assert_eq!(after.recovery_batches.len(), before.recovery_batches.len());
        assert_eq!(
            after
                .active_external_subject(
                    &signup.connection_id,
                    &signup.issuer,
                    &signup.subject,
                    crate::account_auth::ExternalSubjectKind::ConsumerOidc,
                )
                .map(|link| link.account_id.clone()),
            Some("account:alice".to_string()),
        );
    }

    /// The email entrance is unchanged by all of this: no context, no link, and
    /// the same batch. Worth pinning, because the shared `finish_registration`
    /// is now the only thing standing between the two entrances.
    #[test]
    fn the_email_entrance_still_links_no_provider_subject() {
        let (runtime, sender) = runtime();
        let (_vault_dir, mut wb) = signup_workbench();
        let challenge = runtime.begin_email("alice@example.com", 10).unwrap();
        let code = sender.0.lock().unwrap()[0].1.clone();
        let ticket = runtime.complete_email(&challenge, &code, 11).unwrap();
        let (ceremony_id, options) = runtime.start_registration(&ticket, "Alice", 12).unwrap();
        let authenticator = FakeAuthenticator::new();
        let response = authenticator.registration_response(options["challenge"].as_str().unwrap());
        let outcome = runtime
            .finish_registration(&mut wb, &ceremony_id, &response, "Laptop", 13)
            .unwrap();
        assert!(outcome.consumer_signup.is_none());
        assert_eq!(outcome.recovery_codes.len(), RECOVERY_CODE_COUNT);
        let state = AccountAuth::rebuild(wb.store_ref()).unwrap();
        assert!(state.external_subjects.is_empty());
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

        let RegistrationOutcome {
            account_id,
            session: first_session,
            ..
        } = runtime
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
