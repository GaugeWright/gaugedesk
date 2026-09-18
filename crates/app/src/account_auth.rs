//! Provider-neutral account authentication facts (`AUTH-1`, ADR 0146).
//!
//! The GaugeDesk account root is the person. This module records only the ways
//! that person may authenticate to the private Hub account service: verified
//! email contacts, WebAuthn public credentials, exact external-subject links,
//! and salted recovery-code hashes. It stores no passkey private key, recovery
//! plaintext, OIDC token, client secret, or plaintext account-root seed. The
//! private Hub may retain only an envelope-encrypted root seed for recovery.
//!
//! Legacy links share one Hub-owned scope. ADR 0170 replaces that payload
//! custody with independently keyed account-auth scopes while retaining an
//! opaque global admission order. During migration, readers fold the legacy
//! projection first and the exact account-scoped facts second; migrated writers
//! never add personal authentication payloads to the legacy scope.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use gaugedesk_store::{AdmitError, CommandRecordFact, Store};

pub use crate::account::RecordOp;

/// The single ordering scope for Hub account-auth facts.
pub const ACCOUNT_AUTH_SCOPE: &str = "account-auth";

const EMAIL_KIND: &str = "account_auth_email";
const WEBAUTHN_KIND: &str = "account_auth_webauthn";
const SUBJECT_KIND: &str = "account_auth_subject";
const RECOVERY_BATCH_KIND: &str = "account_auth_recovery_batch";
const RECOVERY_CODE_KIND: &str = "account_auth_recovery_code";
const RECOVERY_ATTEMPT_KIND: &str = "account_auth_recovery_attempt";
const ROOT_CUSTODY_KIND: &str = "account_auth_root_custody";
const SESSION_KIND: &str = "account_auth_session";

/// Future authentication standing. Revocation is an upsert, never deletion.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethodStatus {
    #[default]
    Active,
    Revoked,
}

/// One verified account contact. The email is a contact/discovery value, not
/// the account id and never an implicit account-merge basis.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEmailRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub account_id: String,
    pub email: String,
    pub verified_at: u64,
    #[serde(default)]
    pub status: AuthMethodStatus,
}

impl VerifiedEmailRecord {
    /// Materialize a verified contact after the email challenge has completed.
    pub fn new(account_id: &str, email: &str, verified_at: u64) -> Result<Self, AuthRejection> {
        let email = normalize_email_contact(email).ok_or(AuthRejection::InvalidEmail)?;
        Ok(Self {
            id: digest_id(b"gaugedesk:verified-email:v1", &[email.as_bytes()]),
            op: RecordOp::Upsert,
            account_id: required(account_id)?,
            email,
            verified_at,
            status: AuthMethodStatus::Active,
        })
    }
}

/// One WebAuthn credential. Only verifier material is durable; the authenticator
/// keeps the private key. Credential ids use base64url at the HTTP boundary;
/// the serialized verifier is validated by the WebAuthn ceremony adapter.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnMethodRecord {
    /// The WebAuthn credential id; globally unique in this Hub auth scope.
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub account_id: String,
    /// Serialized [`passkey_auth::PasskeyCredential`] verifier. It contains
    /// only public key/counter/transport metadata; the authenticator retains
    /// the private key.
    pub verifier_json: String,
    #[serde(default)]
    pub label: String,
    pub created_at: u64,
    #[serde(default)]
    pub status: AuthMethodStatus,
}

impl WebAuthnMethodRecord {
    /// Materialize verifier output after a WebAuthn registration ceremony.
    pub fn new(
        account_id: &str,
        credential_id: &str,
        verifier_json: &str,
        label: &str,
        created_at: u64,
    ) -> Result<Self, AuthRejection> {
        Ok(Self {
            id: required(credential_id)?,
            op: RecordOp::Upsert,
            account_id: required(account_id)?,
            verifier_json: required(verifier_json)?,
            label: label.trim().to_owned(),
            created_at,
            status: AuthMethodStatus::Active,
        })
    }
}

/// Default private-Hub custody for one governance root. `sealed_seed` is an
/// envelope ciphertext produced by the Hub's account-secret encryptor; the
/// plaintext seed never enters the append-only projection.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CustodiedAccountRootRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub sealed_seed: String,
    pub created_at: u64,
}

impl CustodiedAccountRootRecord {
    pub fn new(
        account_id: &str,
        sealed_seed: &str,
        created_at: u64,
    ) -> Result<Self, AuthRejection> {
        Ok(Self {
            id: required(account_id)?,
            op: RecordOp::Upsert,
            sealed_seed: required(sealed_seed)?,
            created_at,
        })
    }
}

/// Consumer convenience or organization-scoped enterprise authentication.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalSubjectKind {
    ConsumerOidc,
    EnterpriseOidc,
    EnterpriseSaml,
}

/// One exact external identity link. Email is deliberately absent: verified
/// `(connection_id, issuer, subject)` is the only external-subject key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExternalSubjectRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub account_id: String,
    pub connection_id: String,
    pub issuer: String,
    pub subject: String,
    pub kind: ExternalSubjectKind,
    pub linked_at: u64,
    #[serde(default)]
    pub status: AuthMethodStatus,
}

impl ExternalSubjectRecord {
    /// Materialize a link only from an already-verified provider assertion.
    pub fn new(
        account_id: &str,
        connection_id: &str,
        issuer: &str,
        subject: &str,
        kind: ExternalSubjectKind,
        linked_at: u64,
    ) -> Result<Self, AuthRejection> {
        let account_id = required(account_id)?;
        let connection_id = required(connection_id)?;
        let issuer = required(issuer)?;
        let subject = required(subject)?;
        Ok(Self {
            id: external_subject_id(&connection_id, &issuer, &subject),
            op: RecordOp::Upsert,
            account_id,
            connection_id,
            issuer,
            subject,
            kind,
            linked_at,
            status: AuthMethodStatus::Active,
        })
    }
}

/// Whether a recovery batch may still satisfy recovery.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryBatchStatus {
    #[default]
    Active,
    Replaced,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RecoveryBatchRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub account_id: String,
    pub created_at: u64,
    #[serde(default)]
    pub status: RecoveryBatchStatus,
}

/// One high-entropy recovery code. `salt` and `code_hash` are safe verifier
/// material; the plaintext code is returned only by the creation shell and is
/// never represented by this type.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RecoveryCodeRecord {
    /// Domain-separated digest of batch + salt + code; never the code itself.
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub account_id: String,
    pub batch_id: String,
    pub salt: String,
    pub code_hash: String,
    #[serde(default)]
    pub consumed_at: Option<u64>,
}

impl RecoveryCodeRecord {
    /// Prepare a durable verifier from shell-generated salt and code.
    pub fn prepare(
        account_id: &str,
        batch_id: &str,
        salt: &str,
        plaintext_code: &str,
    ) -> Result<Self, AuthRejection> {
        let account_id = required(account_id)?;
        let batch_id = required(batch_id)?;
        let salt = required(salt)?;
        let plaintext_code = required(plaintext_code)?;
        let code_hash = recovery_code_hash(&batch_id, &salt, &plaintext_code);
        Ok(Self {
            id: code_hash.clone(),
            op: RecordOp::Upsert,
            account_id,
            batch_id,
            salt,
            code_hash,
            consumed_at: None,
        })
    }
}

/// Secret-free audit result for one account-recovery attempt. Invalid proofs
/// are distinct from service/custody failure so the former can enforce a
/// bounded retry window without an infrastructure outage locking a person out.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryAttemptOutcome {
    Succeeded,
    InvalidProof,
    RateLimited,
    CustodyUnavailable,
}

/// One append-only recovery audit fact. `target_id` is a domain-separated
/// digest of the normalized verified contact, so an invalid attempt records
/// neither the email challenge nor the recovery code. `account_id` is present
/// only when the verified contact resolved to an existing account.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RecoveryAttemptRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub target_id: String,
    #[serde(default)]
    pub account_id: Option<String>,
    pub attempted_at: u64,
    pub outcome: RecoveryAttemptOutcome,
}

impl RecoveryAttemptRecord {
    pub fn new(
        id: &str,
        target_id: &str,
        account_id: Option<&str>,
        attempted_at: u64,
        outcome: RecoveryAttemptOutcome,
    ) -> Result<Self, AuthRejection> {
        Ok(Self {
            id: required(id)?,
            op: RecordOp::Upsert,
            target_id: required(target_id)?,
            account_id: account_id.map(required).transpose()?,
            attempted_at,
            outcome,
        })
    }
}

/// One durable, opaque GaugeDesk account session (`ADR 0147` §1). The record resolves a
/// session token's digest to the account it authenticates **before the person is
/// known** — so `authenticate_bearer` can admit an opaque bearer against one global,
/// ordered projection exactly as the external-subject link resolves a subject. The
/// raw session token is never stored; `id` is its domain-separated digest, which is
/// also the session id the per-session refresh grant (`account::RefreshRecord`) is
/// keyed by. Revocation is a future-only tombstone: a revoked session folds out of
/// the live projection (`INV-18`), so its token stops resolving without rewriting the
/// append-only log (`INV-6`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountSessionRecord {
    /// The session id = domain-separated digest of the opaque token; never the token.
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub account_id: String,
    /// The sign-in method that minted this session. Independent methods are
    /// `"passkey"` and `"recovery"`; a linked consumer session binds its exact
    /// connection as `"consumer-oidc:<connection>"`. Corporate sessions bind
    /// the exact organization connection as `"enterprise-oidc:<connection>"`
    /// or `"enterprise-saml:<connection>"`. The session surface reports only
    /// its safe family label while admission reads the exact value.
    pub method: String,
    /// The trusted device this opaque session was bound to after a completed,
    /// root-authorized enrollment. Empty for an ordinary browser session. Once
    /// present, every use of the bearer is admitted only while that exact device
    /// remains active in the person's account registry.
    #[serde(default)]
    pub device_id: String,
    /// Milliseconds since the Unix epoch when the session was minted.
    #[serde(default)]
    pub issued_at_ms: u64,
    /// Milliseconds since the Unix epoch of the most recent admitted refresh.
    #[serde(default)]
    pub last_seen_ms: u64,
    /// The opaque token's cache-liveness horizon in seconds from mint — the absolute
    /// lifetime for a browser session, the ceremony TTL for a passkey session. Read on
    /// restart to re-seat the cache with the correct expiry rather than over-extending
    /// a short-lived session.
    #[serde(default)]
    pub lifetime_secs: u64,
}

impl AccountSessionRecord {
    /// Materialize a session index record from a computed session id (the token
    /// digest) — the raw token is never handed to this type.
    pub fn new(
        session_id: &str,
        account_id: &str,
        method: &str,
        issued_at_ms: u64,
        lifetime_secs: u64,
    ) -> Result<Self, AuthRejection> {
        Ok(Self {
            id: required(session_id)?,
            op: RecordOp::Upsert,
            account_id: required(account_id)?,
            method: required(method)?,
            device_id: String::new(),
            issued_at_ms,
            last_seen_ms: issued_at_ms,
            lifetime_secs,
        })
    }
}

/// Rebuildable GaugeDesk account-auth projection (`INV-5`).
#[derive(Default, Clone, Debug)]
pub struct AccountAuth {
    pub roots: BTreeMap<String, CustodiedAccountRootRecord>,
    pub emails: BTreeMap<String, VerifiedEmailRecord>,
    pub webauthn_methods: BTreeMap<String, WebAuthnMethodRecord>,
    pub external_subjects: BTreeMap<String, ExternalSubjectRecord>,
    pub recovery_batches: BTreeMap<String, RecoveryBatchRecord>,
    pub recovery_codes: BTreeMap<String, RecoveryCodeRecord>,
    pub recovery_attempts: BTreeMap<String, RecoveryAttemptRecord>,
    /// Live opaque account sessions, keyed by session id (token digest). Tombstoned
    /// (revoked) sessions have folded out (`ADR 0147` §1/§3).
    pub sessions: BTreeMap<String, AccountSessionRecord>,
}

impl AccountAuth {
    /// Rebuild the authoritative transition projection. The admitted custody
    /// catalog, never the caller, selects independently keyed account scopes.
    pub fn rebuild(store: &Store) -> Result<Self, AdmitError> {
        Self::rebuild_current(store)
    }

    /// Rebuild only the legacy global projection. This exists for the operated
    /// migration copy and verification path; product readers use [`rebuild`].
    pub fn rebuild_legacy(store: &Store) -> Result<Self, AdmitError> {
        let mut state = Self::default();
        state.fold_scope(store, ACCOUNT_AUTH_SCOPE)?;
        Ok(state)
    }

    /// Rebuild the bounded transition projection: legacy current truth first,
    /// then each independently keyed account scope. Account-scoped upserts and
    /// tombstones therefore take precedence without editing legacy history.
    pub fn rebuild_with_account_scopes<'a>(
        store: &Store,
        account_ids: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, AdmitError> {
        let mut state = Self::rebuild_legacy(store)?;
        let account_ids: Vec<&str> = account_ids.into_iter().collect();
        // A migrated account must never fall back to legacy payload after its
        // independently keyed scope becomes unreadable or is crypto-erased.
        // Remove its legacy projection first, then fold only what its current
        // account scope can authoritatively disclose.
        for account_id in &account_ids {
            state.remove_account(account_id);
        }
        for account_id in account_ids {
            let scope = crate::account_auth_custody::account_auth_scope(account_id)
                .map_err(|_| AdmitError::Codec("invalid account-auth scope identity".into()))?;
            state.fold_scope(store, &scope)?;
        }
        Ok(state)
    }

    /// Rebuild the authoritative transition projection from the opaque custody
    /// catalog. Callers do not choose whether legacy or account-scoped data is
    /// current; the admitted migration marker does.
    pub fn rebuild_current(store: &Store) -> Result<Self, AdmitError> {
        let catalog = crate::account_auth_custody::AccountAuthCustodyCatalog::rebuild(store)?;
        let account_scoped = catalog.account_scoped_account_ids();
        let authenticatable = catalog.authenticatable_account_scoped_account_ids();
        let mut state = Self::rebuild_with_account_scopes(store, account_scoped)?;
        // A fence must beat every concurrent authentication before any slower
        // continuation evicts hot bearers or destroys the account key. Removing
        // the account here also prevents an erased account from falling back to
        // legacy history while migration-era rows remain retained.
        let authenticatable: BTreeSet<&str> = authenticatable.into_iter().collect();
        for account_id in catalog.account_scoped_account_ids() {
            if !authenticatable.contains(account_id) {
                state.remove_account(account_id);
            }
        }
        Ok(state)
    }

    fn fold_scope(&mut self, store: &Store, scope: &str) -> Result<(), AdmitError> {
        for row in store.records(scope, ROOT_CUSTODY_KIND)? {
            let record: CustodiedAccountRootRecord = serde_json::from_str(&row)?;
            fold(&mut self.roots, record.id.clone(), record.op, record);
        }
        for row in store.records(scope, EMAIL_KIND)? {
            let record: VerifiedEmailRecord = serde_json::from_str(&row)?;
            fold(&mut self.emails, record.id.clone(), record.op, record);
        }
        for row in store.records(scope, WEBAUTHN_KIND)? {
            let record: WebAuthnMethodRecord = serde_json::from_str(&row)?;
            fold(
                &mut self.webauthn_methods,
                record.id.clone(),
                record.op,
                record,
            );
        }
        for row in store.records(scope, SUBJECT_KIND)? {
            let record: ExternalSubjectRecord = serde_json::from_str(&row)?;
            fold(
                &mut self.external_subjects,
                record.id.clone(),
                record.op,
                record,
            );
        }
        for row in store.records(scope, RECOVERY_BATCH_KIND)? {
            let record: RecoveryBatchRecord = serde_json::from_str(&row)?;
            fold(
                &mut self.recovery_batches,
                record.id.clone(),
                record.op,
                record,
            );
        }
        for row in store.records(scope, RECOVERY_CODE_KIND)? {
            let record: RecoveryCodeRecord = serde_json::from_str(&row)?;
            fold(
                &mut self.recovery_codes,
                record.id.clone(),
                record.op,
                record,
            );
        }
        for row in store.records(scope, RECOVERY_ATTEMPT_KIND)? {
            let record: RecoveryAttemptRecord = serde_json::from_str(&row)?;
            fold(
                &mut self.recovery_attempts,
                record.id.clone(),
                record.op,
                record,
            );
        }
        for row in store.records(scope, SESSION_KIND)? {
            let record: AccountSessionRecord = serde_json::from_str(&row)?;
            fold(&mut self.sessions, record.id.clone(), record.op, record);
        }
        Ok(())
    }

    fn remove_account(&mut self, account_id: &str) {
        self.roots.retain(|_, record| record.id != account_id);
        self.emails
            .retain(|_, record| record.account_id != account_id);
        self.webauthn_methods
            .retain(|_, record| record.account_id != account_id);
        self.external_subjects
            .retain(|_, record| record.account_id != account_id);
        self.recovery_batches
            .retain(|_, record| record.account_id != account_id);
        self.recovery_codes
            .retain(|_, record| record.account_id != account_id);
        self.recovery_attempts
            .retain(|_, record| record.account_id.as_deref() != Some(account_id));
        self.sessions
            .retain(|_, record| record.account_id != account_id);
    }

    /// Stable, person-scoped method projection for the Account surface.
    pub fn methods_for(&self, account_id: &str) -> AccountMethods<'_> {
        AccountMethods {
            emails: self
                .emails
                .values()
                .filter(|record| record.account_id == account_id)
                .collect(),
            webauthn: self
                .webauthn_methods
                .values()
                .filter(|record| record.account_id == account_id)
                .collect(),
            external_subjects: self
                .external_subjects
                .values()
                .filter(|record| record.account_id == account_id)
                .collect(),
        }
    }

    /// Resolve one already-verified external subject through the exact active
    /// link. Email is deliberately not an input and revoked links never
    /// authenticate.
    pub fn active_external_subject(
        &self,
        connection_id: &str,
        issuer: &str,
        subject: &str,
        kind: ExternalSubjectKind,
    ) -> Option<&ExternalSubjectRecord> {
        let id = external_subject_id(connection_id, issuer, subject);
        self.external_subjects.get(&id).filter(|record| {
            record.status == AuthMethodStatus::Active
                && record.connection_id == connection_id
                && record.issuer == issuer
                && record.subject == subject
                && record.kind == kind
        })
    }

    /// Any link for this exact provider subject, whatever its status.
    ///
    /// [`active_external_subject`](Self::active_external_subject) answers "may
    /// this subject sign in", and returns `None` both for a subject nobody has
    /// ever linked and for one whose link was revoked. Those two are the same
    /// answer to sign-in and opposite answers to signing *up*: the first person
    /// should be carried into account creation, and the second must not be —
    /// their subject belongs to an account that deliberately let it go.
    pub fn external_subject_of_any_status(
        &self,
        connection_id: &str,
        issuer: &str,
        subject: &str,
    ) -> Option<&ExternalSubjectRecord> {
        let id = external_subject_id(connection_id, issuer, subject);
        self.external_subjects.get(&id)
    }

    /// The account holding this exact address as an active verified contact.
    ///
    /// Callers use this to *refuse*, never to resolve: ADR 0146 §1 says email
    /// is a verified contact and discovery identifier, and is "not silently
    /// trusted as an account-merge key". Matching an address to an account and
    /// then signing that person in would be the takeover this forbids.
    pub fn account_holding_active_email(&self, email: &str) -> Option<&str> {
        self.emails
            .values()
            .find(|record| record.email == email && record.status == AuthMethodStatus::Active)
            .map(|record| record.account_id.as_str())
    }

    pub fn active_webauthn_count(&self, account_id: &str) -> usize {
        self.webauthn_methods
            .values()
            .filter(|record| {
                record.account_id == account_id && record.status == AuthMethodStatus::Active
            })
            .count()
    }

    pub fn unused_recovery_code_count(&self, account_id: &str) -> usize {
        self.recovery_codes
            .values()
            .filter(|code| {
                code.account_id == account_id
                    && code.consumed_at.is_none()
                    && self
                        .recovery_batches
                        .get(&code.batch_id)
                        .is_some_and(|batch| {
                            batch.account_id == account_id
                                && batch.status == RecoveryBatchStatus::Active
                        })
            })
            .count()
    }

    /// Resolve a presented high-entropy recovery code without exposing the
    /// stored verifier through an API. Comparison is constant-time over digests.
    pub fn find_active_recovery_code(
        &self,
        account_id: &str,
        plaintext_code: &str,
    ) -> Option<&RecoveryCodeRecord> {
        self.recovery_codes.values().find(|code| {
            code.account_id == account_id
                && code.consumed_at.is_none()
                && self
                    .recovery_batches
                    .get(&code.batch_id)
                    .is_some_and(|batch| {
                        batch.account_id == account_id
                            && batch.status == RecoveryBatchStatus::Active
                    })
                && constant_time_hex_eq(
                    &code.code_hash,
                    &recovery_code_hash(&code.batch_id, &code.salt, plaintext_code),
                )
        })
    }

    /// Count only bad recovery-code proofs in the current throttle window.
    /// Rate-limit observations and custody outages are audited but do not
    /// extend the window or turn an outage into a self-sustaining lockout.
    pub fn invalid_recovery_attempts_since(&self, target_id: &str, since: u64) -> usize {
        self.recovery_attempts
            .values()
            .filter(|attempt| {
                attempt.target_id == target_id
                    && attempt.attempted_at >= since
                    && attempt.outcome == RecoveryAttemptOutcome::InvalidProof
            })
            .count()
    }

    /// Current authentication payloads belonging to one account, suitable for
    /// an encrypted migration copy. Revoked methods remain current facts;
    /// unresolved recovery attempts are deliberately absent because they have
    /// no account scope.
    pub fn facts_for_account(&self, account_id: &str) -> Vec<AccountAuthFact> {
        let mut facts = Vec::new();
        facts.extend(
            self.roots
                .values()
                .filter(|record| record.id == account_id)
                .cloned()
                .map(AccountAuthFact::RootCustody),
        );
        facts.extend(
            self.emails
                .values()
                .filter(|record| record.account_id == account_id)
                .cloned()
                .map(AccountAuthFact::Email),
        );
        facts.extend(
            self.webauthn_methods
                .values()
                .filter(|record| record.account_id == account_id)
                .cloned()
                .map(AccountAuthFact::WebAuthn),
        );
        facts.extend(
            self.external_subjects
                .values()
                .filter(|record| record.account_id == account_id)
                .cloned()
                .map(AccountAuthFact::ExternalSubject),
        );
        facts.extend(
            self.recovery_batches
                .values()
                .filter(|record| record.account_id == account_id)
                .cloned()
                .map(AccountAuthFact::RecoveryBatch),
        );
        facts.extend(
            self.recovery_codes
                .values()
                .filter(|record| record.account_id == account_id)
                .cloned()
                .map(AccountAuthFact::RecoveryCode),
        );
        facts.extend(
            self.recovery_attempts
                .values()
                .filter(|record| record.account_id.as_deref() == Some(account_id))
                .cloned()
                .map(AccountAuthFact::RecoveryAttempt),
        );
        facts.extend(
            self.sessions
                .values()
                .filter(|record| record.account_id == account_id)
                .cloned()
                .map(AccountAuthFact::Session),
        );
        facts
    }

    /// Every resolved account represented in this projection. Unresolved
    /// recovery attempts deliberately name no account and cannot create one.
    pub fn account_ids(&self) -> BTreeSet<String> {
        self.roots
            .values()
            .map(|record| record.id.clone())
            .chain(self.emails.values().map(|record| record.account_id.clone()))
            .chain(
                self.webauthn_methods
                    .values()
                    .map(|record| record.account_id.clone()),
            )
            .chain(
                self.external_subjects
                    .values()
                    .map(|record| record.account_id.clone()),
            )
            .chain(
                self.recovery_batches
                    .values()
                    .map(|record| record.account_id.clone()),
            )
            .chain(
                self.recovery_codes
                    .values()
                    .map(|record| record.account_id.clone()),
            )
            .chain(
                self.recovery_attempts
                    .values()
                    .filter_map(|record| record.account_id.clone()),
            )
            .chain(
                self.sessions
                    .values()
                    .map(|record| record.account_id.clone()),
            )
            .collect()
    }
}

pub struct AccountMethods<'a> {
    pub emails: Vec<&'a VerifiedEmailRecord>,
    pub webauthn: Vec<&'a WebAuthnMethodRecord>,
    pub external_subjects: Vec<&'a ExternalSubjectRecord>,
}

/// Pure decision output. The imperative shell appends every fact atomically,
/// then rebuilds the projection; commands themselves are never product truth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountAuthFact {
    RootCustody(CustodiedAccountRootRecord),
    Email(VerifiedEmailRecord),
    WebAuthn(WebAuthnMethodRecord),
    ExternalSubject(ExternalSubjectRecord),
    RecoveryBatch(RecoveryBatchRecord),
    RecoveryCode(RecoveryCodeRecord),
    RecoveryAttempt(RecoveryAttemptRecord),
    Session(AccountSessionRecord),
}

impl AccountAuthFact {
    fn kind(&self) -> &'static str {
        match self {
            Self::RootCustody(_) => ROOT_CUSTODY_KIND,
            Self::Email(_) => EMAIL_KIND,
            Self::WebAuthn(_) => WEBAUTHN_KIND,
            Self::ExternalSubject(_) => SUBJECT_KIND,
            Self::RecoveryBatch(_) => RECOVERY_BATCH_KIND,
            Self::RecoveryCode(_) => RECOVERY_CODE_KIND,
            Self::RecoveryAttempt(_) => RECOVERY_ATTEMPT_KIND,
            Self::Session(_) => SESSION_KIND,
        }
    }

    fn json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::RootCustody(record) => serde_json::to_string(record),
            Self::Email(record) => serde_json::to_string(record),
            Self::WebAuthn(record) => serde_json::to_string(record),
            Self::ExternalSubject(record) => serde_json::to_string(record),
            Self::RecoveryBatch(record) => serde_json::to_string(record),
            Self::RecoveryCode(record) => serde_json::to_string(record),
            Self::RecoveryAttempt(record) => serde_json::to_string(record),
            Self::Session(record) => serde_json::to_string(record),
        }
    }

    /// The exact account whose encrypted scope may hold this payload. An
    /// unresolved invalid recovery attempt has no account and therefore cannot
    /// enter durable migrated custody through this API.
    fn account_id(&self) -> Option<&str> {
        match self {
            Self::RootCustody(record) => Some(&record.id),
            Self::Email(record) => Some(&record.account_id),
            Self::WebAuthn(record) => Some(&record.account_id),
            Self::ExternalSubject(record) => Some(&record.account_id),
            Self::RecoveryBatch(record) => Some(&record.account_id),
            Self::RecoveryCode(record) => Some(&record.account_id),
            Self::RecoveryAttempt(record) => record.account_id.as_deref(),
            Self::Session(record) => Some(&record.account_id),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRejection {
    InvalidAccount,
    InvalidEmail,
    InvalidVerifierMaterial,
    CustodyUnavailable,
    CredentialAlreadyLinked,
    SubjectAlreadyLinked,
    MethodNotFound,
    LastIndependentMethod,
    RecoveryBatchNotActive,
    RecoveryCodeAlreadyConsumed,
}

/// Mint a new independent GaugeDesk account root and prepare its encrypted
/// custody fact. It follows the same root-custody boundary as passkey-first
/// registration and is used by admitted first-time enterprise sign-in: an
/// external IdP subject may authenticate a new account, but it never becomes
/// that account's durable identity.
///
/// The seed exists only in this stack frame and the returned fact contains only
/// the Hub-encrypted envelope. The caller commits it atomically with the exact
/// verified external-subject link and any admitted organization membership.
pub fn create_custodied_account_root(
    wb: &crate::Workbench,
    created_at: u64,
) -> Result<(String, AccountAuthFact), AuthRejection> {
    for _ in 0..16 {
        let mut seed = [0_u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| AuthRejection::CustodyUnavailable)?;
        let Ok(signing) = gaugedesk_core::signature::SigningKey::from_seed(&seed) else {
            continue;
        };
        let account_id = signing.public_key().as_str().to_owned();
        let sealed_seed = wb
            .seal_custodied_account_root(&account_id, &hex::encode(seed))
            .ok_or(AuthRejection::CustodyUnavailable)?;
        let record = CustodiedAccountRootRecord::new(&account_id, &sealed_seed, created_at)?;
        return Ok((account_id, AccountAuthFact::RootCustody(record)));
    }
    Err(AuthRejection::CustodyUnavailable)
}

/// Verify a contact without using it to locate or merge another account.
pub fn decide_verify_email(
    state: &AccountAuth,
    record: VerifiedEmailRecord,
) -> Result<Vec<AccountAuthFact>, AuthRejection> {
    if let Some(existing) = state.emails.get(&record.id) {
        if existing.account_id != record.account_id && existing.status == AuthMethodStatus::Active {
            // One active recovery/discovery destination cannot safely route to two
            // accounts. This is uniqueness, not identity merging.
            return Err(AuthRejection::CredentialAlreadyLinked);
        }
    }
    Ok(vec![AccountAuthFact::Email(record)])
}

pub fn decide_add_webauthn(
    state: &AccountAuth,
    record: WebAuthnMethodRecord,
) -> Result<Vec<AccountAuthFact>, AuthRejection> {
    if let Some(existing) = state.webauthn_methods.get(&record.id) {
        if existing.account_id != record.account_id {
            return Err(AuthRejection::CredentialAlreadyLinked);
        }
    }
    Ok(vec![AccountAuthFact::WebAuthn(record)])
}

pub fn decide_revoke_webauthn(
    state: &AccountAuth,
    account_id: &str,
    credential_id: &str,
) -> Result<Vec<AccountAuthFact>, AuthRejection> {
    let existing = state
        .webauthn_methods
        .get(credential_id)
        .filter(|record| record.account_id == account_id)
        .ok_or(AuthRejection::MethodNotFound)?;
    if existing.status == AuthMethodStatus::Revoked {
        return Ok(Vec::new());
    }
    if state.active_webauthn_count(account_id) <= 1 {
        return Err(AuthRejection::LastIndependentMethod);
    }
    let mut revoked = existing.clone();
    revoked.status = AuthMethodStatus::Revoked;
    Ok(vec![AccountAuthFact::WebAuthn(revoked)])
}

pub fn decide_link_external_subject(
    state: &AccountAuth,
    record: ExternalSubjectRecord,
) -> Result<Vec<AccountAuthFact>, AuthRejection> {
    if let Some(existing) = state.external_subjects.get(&record.id) {
        if existing.account_id != record.account_id {
            return Err(AuthRejection::SubjectAlreadyLinked);
        }
    }
    Ok(vec![AccountAuthFact::ExternalSubject(record)])
}

/// Back-link a legacy consumer sign-in so this initiative's linking rule does not
/// lock its own users out (GAUGEAPP-9).
///
/// Before [`ADR 0146`] an account's identity *was* the verified OIDC subject, so a
/// hosted account obtained by Google sign-in carries that subject as its id, holds no
/// passkey, and has no [`ExternalSubjectRecord`]. The callback now resolves such a
/// record before minting a session, and the only route that creates one requires a
/// live passkey-or-recovery session — which that account cannot obtain. Without this
/// it could never sign in again.
///
/// The reconstruction is exact rather than a guess: the legacy id *is* the subject.
///
/// An account is legacy only when it holds no active authentication method at all.
/// Nothing else can reach that state: a passkey account has a WebAuthn method, an
/// enterprise account has an `EnterpriseOidc` subject from the login fold, and a
/// recovery-capable account has an active batch. Restricting it this way matters —
/// minting a subject link for an account that was *not* born of this provider would
/// invent a credential, so the rule refuses everything it cannot prove.
///
/// Returns no fact when the account already resolves, so the pass is idempotent and
/// safe to repeat on every boot.
pub fn decide_backlink_legacy_consumer_subject(
    state: &AccountAuth,
    account_id: &str,
    connection_id: &str,
    issuer: &str,
    now_ms: u64,
) -> Option<AccountAuthFact> {
    if account_id.trim().is_empty() {
        return None;
    }
    let holds_active_method = state
        .webauthn_methods
        .values()
        .any(|m| m.account_id == account_id && m.status == AuthMethodStatus::Active)
        || state
            .external_subjects
            .values()
            .any(|x| x.account_id == account_id && x.status == AuthMethodStatus::Active)
        || state
            .recovery_batches
            .values()
            .any(|b| b.account_id == account_id && b.status == RecoveryBatchStatus::Active);
    if holds_active_method {
        return None;
    }
    let record = ExternalSubjectRecord::new(
        account_id,
        connection_id,
        issuer,
        account_id,
        ExternalSubjectKind::ConsumerOidc,
        now_ms,
    )
    .ok()?;
    // A record whose id is already taken by another account is refused rather than
    // overwritten: two accounts cannot claim one subject.
    match decide_link_external_subject(state, record) {
        Ok(mut facts) if facts.len() == 1 => facts.pop(),
        _ => None,
    }
}

pub fn decide_unlink_external_subject(
    state: &AccountAuth,
    account_id: &str,
    subject_id: &str,
) -> Result<Vec<AccountAuthFact>, AuthRejection> {
    let existing = state
        .external_subjects
        .get(subject_id)
        .filter(|record| record.account_id == account_id)
        .ok_or(AuthRejection::MethodNotFound)?;
    if existing.status == AuthMethodStatus::Revoked {
        return Ok(Vec::new());
    }
    let mut revoked = existing.clone();
    revoked.status = AuthMethodStatus::Revoked;
    Ok(vec![AccountAuthFact::ExternalSubject(revoked)])
}

/// Replace all prior recovery batches for one account and install a new batch
/// in one decision. `prepared_codes` contain hashes only.
pub fn decide_replace_recovery_codes(
    state: &AccountAuth,
    account_id: &str,
    batch_id: &str,
    created_at: u64,
    prepared_codes: Vec<RecoveryCodeRecord>,
) -> Result<Vec<AccountAuthFact>, AuthRejection> {
    let account_id = required(account_id)?;
    let batch_id = required(batch_id)?;
    if prepared_codes.is_empty()
        || prepared_codes
            .iter()
            .any(|code| code.account_id != account_id || code.batch_id != batch_id)
    {
        return Err(AuthRejection::InvalidVerifierMaterial);
    }

    let mut facts = Vec::new();
    for existing in state.recovery_batches.values().filter(|batch| {
        batch.account_id == account_id && batch.status == RecoveryBatchStatus::Active
    }) {
        let mut replaced = existing.clone();
        replaced.status = RecoveryBatchStatus::Replaced;
        facts.push(AccountAuthFact::RecoveryBatch(replaced));
    }
    facts.push(AccountAuthFact::RecoveryBatch(RecoveryBatchRecord {
        id: batch_id,
        op: RecordOp::Upsert,
        account_id,
        created_at,
        status: RecoveryBatchStatus::Active,
    }));
    facts.extend(
        prepared_codes
            .into_iter()
            .map(AccountAuthFact::RecoveryCode),
    );
    Ok(facts)
}

pub fn decide_consume_recovery_code(
    state: &AccountAuth,
    account_id: &str,
    code_id: &str,
    consumed_at: u64,
) -> Result<Vec<AccountAuthFact>, AuthRejection> {
    let existing = state
        .recovery_codes
        .get(code_id)
        .filter(|code| code.account_id == account_id)
        .ok_or(AuthRejection::MethodNotFound)?;
    if existing.consumed_at.is_some() {
        return Err(AuthRejection::RecoveryCodeAlreadyConsumed);
    }
    let batch_active = state
        .recovery_batches
        .get(&existing.batch_id)
        .is_some_and(|batch| {
            batch.account_id == account_id && batch.status == RecoveryBatchStatus::Active
        });
    if !batch_active {
        return Err(AuthRejection::RecoveryBatchNotActive);
    }
    let mut consumed = existing.clone();
    consumed.consumed_at = Some(consumed_at);
    Ok(vec![AccountAuthFact::RecoveryCode(consumed)])
}

/// Append one pure decision's facts in a single SQLite transaction.
pub fn append_facts(store: &mut Store, facts: &[AccountAuthFact]) -> Result<(), AdmitError> {
    let encoded = current_command_record_facts(store, facts)?;
    let borrowed: Vec<(&str, &str, &str)> = encoded
        .iter()
        .map(|fact| {
            (
                fact.scope_id.as_str(),
                fact.kind.as_str(),
                fact.payload.as_str(),
            )
        })
        .collect();
    store.append_records_atomically(&borrowed)?;
    Ok(())
}

/// Encode an authentication decision for admission beside another authoritative
/// command's facts. This is the GaugeApp seam: the caller may atomically commit
/// the auth mutation, command receipt, and change record without learning the
/// private record-kind vocabulary or bypassing the pure reducer.
pub fn command_record_facts(
    facts: &[AccountAuthFact],
) -> Result<Vec<CommandRecordFact>, AdmitError> {
    facts
        .iter()
        .map(|fact| {
            Ok(CommandRecordFact {
                scope_id: ACCOUNT_AUTH_SCOPE.to_owned(),
                kind: fact.kind().to_owned(),
                payload: fact.json()?,
            })
        })
        .collect()
}

/// Encode authentication facts for the exact person's encrypted account-auth
/// scope. This is the ADR 0170 migrated-write seam. It refuses cross-account
/// batches and unresolved recovery attempts before they reach storage.
pub fn account_scoped_command_record_facts(
    account_id: &str,
    facts: &[AccountAuthFact],
) -> Result<Vec<CommandRecordFact>, AdmitError> {
    let scope = crate::account_auth_custody::account_auth_scope(account_id)
        .map_err(|_| AdmitError::Codec("invalid account-auth scope identity".into()))?;
    facts
        .iter()
        .map(|fact| {
            if fact.account_id() != Some(account_id) {
                return Err(AdmitError::Codec(
                    "account-auth fact is unscoped or belongs to another account".into(),
                ));
            }
            Ok(CommandRecordFact {
                scope_id: scope.clone(),
                kind: fact.kind().to_owned(),
                payload: fact.json()?,
            })
        })
        .collect()
}

/// Encode each authentication fact into the scope selected by the admitted
/// custody catalog. This lets one atomic higher-level command span legacy and
/// migrated accounts during rollout without allowing its caller to choose a
/// weaker custody location.
pub fn current_command_record_facts(
    store: &Store,
    facts: &[AccountAuthFact],
) -> Result<Vec<CommandRecordFact>, AdmitError> {
    let catalog = crate::account_auth_custody::AccountAuthCustodyCatalog::rebuild(store)?;
    let scoped: BTreeSet<&str> = catalog.account_scoped_account_ids().into_iter().collect();
    facts
        .iter()
        .map(|fact| {
            if let Some(account_id) = fact.account_id() {
                if !catalog.account(account_id).may_authenticate() {
                    return Err(AdmitError::Codec(
                        "account-auth mutation refused after erasure fence".into(),
                    ));
                }
            }
            let scope_id = match fact.account_id() {
                Some(account_id) if scoped.contains(account_id) => {
                    crate::account_auth_custody::account_auth_scope(account_id).map_err(|_| {
                        AdmitError::Codec("invalid account-auth scope identity".into())
                    })?
                }
                _ => ACCOUNT_AUTH_SCOPE.to_owned(),
            };
            Ok(CommandRecordFact {
                scope_id,
                kind: fact.kind().to_owned(),
                payload: fact.json()?,
            })
        })
        .collect()
}

fn fold<T>(map: &mut BTreeMap<String, T>, id: String, op: RecordOp, record: T) {
    match op {
        RecordOp::Upsert => {
            map.insert(id, record);
        }
        RecordOp::Tombstone => {
            map.remove(&id);
        }
    }
}

fn required(value: &str) -> Result<String, AuthRejection> {
    let value = value.trim();
    if value.is_empty() {
        Err(AuthRejection::InvalidVerifierMaterial)
    } else {
        Ok(value.to_owned())
    }
}

pub fn normalize_email_contact(value: &str) -> Option<String> {
    let normalized = value.trim().to_lowercase();
    let (local, domain) = normalized.rsplit_once('@')?;
    (!local.is_empty()
        && !domain.is_empty()
        && !local.chars().any(char::is_whitespace)
        && !domain.chars().any(char::is_whitespace))
    .then_some(normalized)
}

/// Stable throttle/audit key for a normalized recovery contact. The private
/// account service already holds the verified contact itself; this avoids
/// copying it into every attempt record.
pub fn recovery_target_id(email: &str) -> Option<String> {
    let email = normalize_email_contact(email)?;
    Some(digest_id(
        b"gaugedesk:account-recovery-target:v1",
        &[email.as_bytes()],
    ))
}

fn external_subject_id(connection_id: &str, issuer: &str, subject: &str) -> String {
    digest_id(
        b"gaugedesk:external-subject:v1",
        &[
            connection_id.as_bytes(),
            issuer.as_bytes(),
            subject.as_bytes(),
        ],
    )
}

fn recovery_code_hash(batch_id: &str, salt: &str, plaintext_code: &str) -> String {
    digest_id(
        b"gaugedesk:recovery-code:v1",
        &[
            batch_id.as_bytes(),
            salt.as_bytes(),
            plaintext_code.as_bytes(),
        ],
    )
}

fn digest_id(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    hex::encode(digest.finalize())
}

fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    let Ok(left) = hex::decode(left) else {
        return false;
    };
    let Ok(right) = hex::decode(right) else {
        return false;
    };
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    fn passkey(account: &str, id: &str) -> WebAuthnMethodRecord {
        WebAuthnMethodRecord::new(account, id, "public-verifier", "Security key", 10).unwrap()
    }

    fn apply(state: &mut AccountAuth, facts: &[AccountAuthFact]) {
        for fact in facts {
            match fact {
                AccountAuthFact::RootCustody(record) => fold(
                    &mut state.roots,
                    record.id.clone(),
                    record.op,
                    record.clone(),
                ),
                AccountAuthFact::Email(record) => fold(
                    &mut state.emails,
                    record.id.clone(),
                    record.op,
                    record.clone(),
                ),
                AccountAuthFact::WebAuthn(record) => fold(
                    &mut state.webauthn_methods,
                    record.id.clone(),
                    record.op,
                    record.clone(),
                ),
                AccountAuthFact::ExternalSubject(record) => fold(
                    &mut state.external_subjects,
                    record.id.clone(),
                    record.op,
                    record.clone(),
                ),
                AccountAuthFact::RecoveryBatch(record) => fold(
                    &mut state.recovery_batches,
                    record.id.clone(),
                    record.op,
                    record.clone(),
                ),
                AccountAuthFact::RecoveryCode(record) => fold(
                    &mut state.recovery_codes,
                    record.id.clone(),
                    record.op,
                    record.clone(),
                ),
                AccountAuthFact::RecoveryAttempt(record) => fold(
                    &mut state.recovery_attempts,
                    record.id.clone(),
                    record.op,
                    record.clone(),
                ),
                AccountAuthFact::Session(record) => fold(
                    &mut state.sessions,
                    record.id.clone(),
                    record.op,
                    record.clone(),
                ),
            }
        }
    }

    const LEGACY_CONNECTION: &str = "google-consumer";
    const LEGACY_ISSUER: &str = "https://accounts.google.com";

    fn backlink(state: &AccountAuth, account_id: &str) -> Option<AccountAuthFact> {
        decide_backlink_legacy_consumer_subject(
            state,
            account_id,
            LEGACY_CONNECTION,
            LEGACY_ISSUER,
            99,
        )
    }

    #[test]
    fn a_legacy_consumer_account_is_back_linked_to_the_subject_that_was_its_id() {
        // Before ADR 0146 the verified subject *was* the account id, so the link
        // is reconstructed exactly rather than guessed.
        let state = AccountAuth::default();
        let Some(AccountAuthFact::ExternalSubject(record)) =
            backlink(&state, "110378459139719984149")
        else {
            panic!("a legacy account with no method must be back-linked");
        };
        assert_eq!(record.account_id, "110378459139719984149");
        assert_eq!(record.subject, "110378459139719984149");
        assert_eq!(record.kind, ExternalSubjectKind::ConsumerOidc);
        assert_eq!(record.issuer, LEGACY_ISSUER);
        assert_eq!(record.status, AuthMethodStatus::Active);
    }

    #[test]
    fn the_pass_is_idempotent_across_boots() {
        // It runs on every startup, so a second pass must add nothing.
        let mut state = AccountAuth::default();
        let first = backlink(&state, "subject-legacy").expect("first pass links");
        apply(&mut state, std::slice::from_ref(&first));
        assert!(
            backlink(&state, "subject-legacy").is_none(),
            "an already-linked account must not be linked twice",
        );
    }

    #[test]
    fn an_account_holding_any_active_method_is_not_legacy() {
        // Each active method independently proves the account was not born of
        // consumer sign-in, so none of them may be overwritten with a subject.
        let mut webauthn = AccountAuth::default();
        apply(
            &mut webauthn,
            &[AccountAuthFact::WebAuthn(
                WebAuthnMethodRecord::new("passkey-person", "cred-1", "{}", "key", 10).unwrap(),
            )],
        );
        assert!(
            backlink(&webauthn, "passkey-person").is_none(),
            "a passkey account must never gain a consumer subject",
        );

        let mut enterprise = AccountAuth::default();
        let corporate = ExternalSubjectRecord::new(
            "corporate-person",
            "org-acme-oidc",
            "https://idp.example",
            "subject-42",
            ExternalSubjectKind::EnterpriseOidc,
            10,
        )
        .unwrap();
        apply(
            &mut enterprise,
            &[AccountAuthFact::ExternalSubject(corporate)],
        );
        assert!(
            backlink(&enterprise, "corporate-person").is_none(),
            "an enterprise account must not gain a consumer subject",
        );
    }

    #[test]
    fn a_revoked_method_does_not_keep_an_account_out_of_the_migration() {
        // A revoked passkey authenticates nothing, so such an account is still
        // locked out and still needs its link.
        let mut state = AccountAuth::default();
        apply(
            &mut state,
            &[AccountAuthFact::WebAuthn({
                let mut revoked =
                    WebAuthnMethodRecord::new("subject-legacy", "cred-1", "{}", "key", 10).unwrap();
                revoked.status = AuthMethodStatus::Revoked;
                revoked
            })],
        );
        assert!(
            backlink(&state, "subject-legacy").is_some(),
            "a revoked method leaves the account unable to sign in",
        );
    }

    #[test]
    fn a_subject_another_account_already_holds_is_refused() {
        // Two accounts cannot claim one subject; the migration must not
        // overwrite an existing link to reach that state.
        let mut state = AccountAuth::default();
        let held = ExternalSubjectRecord::new(
            "someone-else",
            LEGACY_CONNECTION,
            LEGACY_ISSUER,
            "subject-legacy",
            ExternalSubjectKind::ConsumerOidc,
            10,
        )
        .unwrap();
        apply(&mut state, &[AccountAuthFact::ExternalSubject(held)]);
        assert!(
            backlink(&state, "subject-legacy").is_none(),
            "the migration must not take a subject another account holds",
        );
    }

    #[test]
    fn an_empty_account_id_is_refused() {
        assert!(backlink(&AccountAuth::default(), "   ").is_none());
    }

    #[test]
    fn one_external_subject_cannot_link_to_two_accounts() {
        let mut state = AccountAuth::default();
        let alice = ExternalSubjectRecord::new(
            "alice-root",
            "org-acme-oidc",
            "https://idp.example",
            "subject-42",
            ExternalSubjectKind::EnterpriseOidc,
            10,
        )
        .unwrap();
        let facts = decide_link_external_subject(&state, alice).unwrap();
        apply(&mut state, &facts);

        let bob = ExternalSubjectRecord::new(
            "bob-root",
            "org-acme-oidc",
            "https://idp.example",
            "subject-42",
            ExternalSubjectKind::EnterpriseOidc,
            11,
        )
        .unwrap();
        assert_eq!(
            decide_link_external_subject(&state, bob),
            Err(AuthRejection::SubjectAlreadyLinked)
        );
    }

    #[test]
    fn email_is_a_contact_not_the_external_subject_key() {
        let first = ExternalSubjectRecord::new(
            "person",
            "google-consumer",
            "https://accounts.google.com",
            "subject-a",
            ExternalSubjectKind::ConsumerOidc,
            1,
        )
        .unwrap();
        let second = ExternalSubjectRecord::new(
            "person",
            "org-acme",
            "https://login.example/acme",
            "subject-b",
            ExternalSubjectKind::EnterpriseOidc,
            2,
        )
        .unwrap();
        assert_ne!(first.id, second.id);
        assert!(!serde_json::to_string(&first).unwrap().contains('@'));
    }

    #[test]
    fn the_last_independent_passkey_cannot_be_removed() {
        let mut state = AccountAuth::default();
        let first = decide_add_webauthn(&state, passkey("person", "credential-1")).unwrap();
        apply(&mut state, &first);
        assert_eq!(
            decide_revoke_webauthn(&state, "person", "credential-1"),
            Err(AuthRejection::LastIndependentMethod)
        );

        let second = decide_add_webauthn(&state, passkey("person", "credential-2")).unwrap();
        apply(&mut state, &second);
        let revoked = decide_revoke_webauthn(&state, "person", "credential-1").unwrap();
        apply(&mut state, &revoked);
        assert_eq!(
            state.webauthn_methods["credential-1"].status,
            AuthMethodStatus::Revoked
        );
        assert_eq!(state.active_webauthn_count("person"), 1);
    }

    #[test]
    fn recovery_batches_replace_and_codes_are_single_use() {
        let mut state = AccountAuth::default();
        let old = RecoveryCodeRecord::prepare("person", "batch-old", "salt-a", "OLD-CODE").unwrap();
        let old_facts =
            decide_replace_recovery_codes(&state, "person", "batch-old", 1, vec![old]).unwrap();
        apply(&mut state, &old_facts);
        assert!(state
            .find_active_recovery_code("person", "OLD-CODE")
            .is_some());

        let new = RecoveryCodeRecord::prepare("person", "batch-new", "salt-b", "NEW-CODE").unwrap();
        let new_facts =
            decide_replace_recovery_codes(&state, "person", "batch-new", 2, vec![new]).unwrap();
        apply(&mut state, &new_facts);
        assert!(state
            .find_active_recovery_code("person", "OLD-CODE")
            .is_none());

        let code_id = state
            .find_active_recovery_code("person", "NEW-CODE")
            .unwrap()
            .id
            .clone();
        let consumed = decide_consume_recovery_code(&state, "person", &code_id, 3).unwrap();
        apply(&mut state, &consumed);
        assert_eq!(state.unused_recovery_code_count("person"), 0);
        assert_eq!(
            decide_consume_recovery_code(&state, "person", &code_id, 4),
            Err(AuthRejection::RecoveryCodeAlreadyConsumed)
        );
    }

    #[test]
    fn durable_projection_contains_verifiers_but_no_recovery_plaintext_or_private_key() {
        let mut store = store();
        let email = VerifiedEmailRecord::new("person", " Person@Example.COM ", 1).unwrap();
        let webauthn = passkey("person", "credential-1");
        let code =
            RecoveryCodeRecord::prepare("person", "batch", "random-salt", "SECRET-CODE").unwrap();
        let facts = vec![
            AccountAuthFact::RootCustody(
                CustodiedAccountRootRecord::new("person", "sealed-root", 1).unwrap(),
            ),
            AccountAuthFact::Email(email),
            AccountAuthFact::WebAuthn(webauthn),
            AccountAuthFact::RecoveryBatch(RecoveryBatchRecord {
                id: "batch".into(),
                op: RecordOp::Upsert,
                account_id: "person".into(),
                created_at: 1,
                status: RecoveryBatchStatus::Active,
            }),
            AccountAuthFact::RecoveryCode(code),
            AccountAuthFact::RecoveryAttempt(
                RecoveryAttemptRecord::new(
                    "attempt-1",
                    &recovery_target_id("person@example.com").unwrap(),
                    Some("person"),
                    2,
                    RecoveryAttemptOutcome::InvalidProof,
                )
                .unwrap(),
            ),
        ];
        append_facts(&mut store, &facts).unwrap();

        let state = AccountAuth::rebuild(&store).unwrap();
        assert_eq!(
            state.methods_for("person").emails[0].email,
            "person@example.com"
        );
        assert_eq!(state.active_webauthn_count("person"), 1);
        assert_eq!(state.unused_recovery_code_count("person"), 1);

        for kind in [
            ROOT_CUSTODY_KIND,
            EMAIL_KIND,
            WEBAUTHN_KIND,
            RECOVERY_BATCH_KIND,
            RECOVERY_CODE_KIND,
            RECOVERY_ATTEMPT_KIND,
        ] {
            for row in store.records(ACCOUNT_AUTH_SCOPE, kind).unwrap() {
                assert!(!row.contains("SECRET-CODE"));
                assert!(!row.contains("private_key"));
                assert!(!row.contains("client_secret"));
                assert!(!row.contains("id_token"));
            }
        }
        let target = recovery_target_id("person@example.com").unwrap();
        assert_eq!(state.invalid_recovery_attempts_since(&target, 0), 1);
    }

    #[test]
    fn credential_and_email_uniqueness_are_global_not_per_account_scope() {
        let mut state = AccountAuth::default();
        let passkey_facts =
            decide_add_webauthn(&state, passkey("alice", "shared-credential")).unwrap();
        apply(&mut state, &passkey_facts);
        assert_eq!(
            decide_add_webauthn(&state, passkey("bob", "shared-credential")),
            Err(AuthRejection::CredentialAlreadyLinked)
        );

        let alice_email = VerifiedEmailRecord::new("alice", "same@example.com", 1).unwrap();
        let email_facts = decide_verify_email(&state, alice_email).unwrap();
        apply(&mut state, &email_facts);
        let bob_email = VerifiedEmailRecord::new("bob", "same@example.com", 2).unwrap();
        assert_eq!(
            decide_verify_email(&state, bob_email),
            Err(AuthRejection::CredentialAlreadyLinked)
        );
    }

    #[test]
    fn migrated_fact_builder_refuses_foreign_and_unresolved_payloads() {
        let alice = AccountAuthFact::Email(
            VerifiedEmailRecord::new("alice", "alice@example.com", 1).unwrap(),
        );
        let encoded = account_scoped_command_record_facts("alice", &[alice]).unwrap();
        assert_eq!(
            encoded[0].scope_id,
            crate::account_auth_custody::account_auth_scope("alice").unwrap()
        );
        assert_eq!(encoded[0].kind, EMAIL_KIND);

        let bob =
            AccountAuthFact::Email(VerifiedEmailRecord::new("bob", "bob@example.com", 1).unwrap());
        assert!(matches!(
            account_scoped_command_record_facts("alice", &[bob]),
            Err(AdmitError::Codec(_))
        ));

        let unresolved = AccountAuthFact::RecoveryAttempt(
            RecoveryAttemptRecord::new(
                "attempt",
                "legacy-target-digest",
                None,
                1,
                RecoveryAttemptOutcome::InvalidProof,
            )
            .unwrap(),
        );
        assert!(matches!(
            account_scoped_command_record_facts("alice", &[unresolved]),
            Err(AdmitError::Codec(_))
        ));
    }

    #[test]
    fn migration_snapshot_contains_only_the_exact_accounts_current_facts() {
        let mut state = AccountAuth::default();
        for fact in [
            AccountAuthFact::Email(
                VerifiedEmailRecord::new("alice", "alice@example.com", 1).unwrap(),
            ),
            AccountAuthFact::Email(VerifiedEmailRecord::new("bob", "bob@example.com", 1).unwrap()),
            AccountAuthFact::Session(
                AccountSessionRecord::new("alice-session", "alice", "passkey", 1, 60).unwrap(),
            ),
        ] {
            apply(&mut state, &[fact]);
        }
        apply(
            &mut state,
            &[AccountAuthFact::RecoveryAttempt(
                RecoveryAttemptRecord::new(
                    "unknown-attempt",
                    "legacy-target-digest",
                    None,
                    1,
                    RecoveryAttemptOutcome::InvalidProof,
                )
                .unwrap(),
            )],
        );

        let alice = state.facts_for_account("alice");
        assert_eq!(alice.len(), 2);
        assert!(alice.iter().all(|fact| fact.account_id() == Some("alice")));
        assert!(account_scoped_command_record_facts("alice", &alice).is_ok());
    }

    #[test]
    fn migrated_scope_is_encrypted_and_never_falls_back_after_erasure() {
        use std::sync::Arc;

        use crate::at_rest::LoopbackKeyWrap;
        use crate::content_vault::ContentVault;

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("account-auth.sqlite");
        let vault = Arc::new(ContentVault::new(
            dir.path().join("keys"),
            Box::new(LoopbackKeyWrap::new([9_u8; 32])),
        ));
        let mut store = Store::open(db.to_str().unwrap())
            .unwrap()
            .with_codec(vault.clone());

        let alice = AccountAuthFact::Email(
            VerifiedEmailRecord::new("alice", "alice@example.com", 1).unwrap(),
        );
        let bob =
            AccountAuthFact::Email(VerifiedEmailRecord::new("bob", "bob@example.com", 1).unwrap());
        append_facts(&mut store, &[alice.clone(), bob]).unwrap();

        let migrated = account_scoped_command_record_facts("alice", &[alice]).unwrap();
        let records: Vec<(&str, &str, &str)> = migrated
            .iter()
            .map(|fact| {
                (
                    fact.scope_id.as_str(),
                    fact.kind.as_str(),
                    fact.payload.as_str(),
                )
            })
            .collect();
        store.append_records_atomically(&records).unwrap();

        let projection = AccountAuth::rebuild_with_account_scopes(&store, ["alice"]).unwrap();
        assert_eq!(projection.methods_for("alice").emails.len(), 1);
        assert_eq!(projection.methods_for("bob").emails.len(), 1);

        let scope = crate::account_auth_custody::account_auth_scope("alice").unwrap();
        let raw = Store::open(db.to_str().unwrap()).unwrap();
        let stored = raw.records(&scope, EMAIL_KIND).unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].starts_with("gwenc:1:"));
        assert!(!stored[0].contains("alice@example.com"));

        assert!(vault.crypto_erase(&scope));
        let after_erasure = AccountAuth::rebuild_with_account_scopes(&store, ["alice"]).unwrap();
        assert!(after_erasure.methods_for("alice").emails.is_empty());
        assert_eq!(after_erasure.methods_for("bob").emails.len(), 1);
    }

    #[test]
    fn custody_catalog_selects_current_reads_and_writes_per_account() {
        use crate::account_auth_custody::{
            command_record_facts as custody_record_facts, AccountAuthCustody, CustodyCommand,
        };

        let mut store = Store::open_in_memory().unwrap();
        let alice_legacy = AccountAuthFact::Email(
            VerifiedEmailRecord::new("alice", "old-alice@example.com", 1).unwrap(),
        );
        let bob_legacy =
            AccountAuthFact::Email(VerifiedEmailRecord::new("bob", "bob@example.com", 1).unwrap());
        for fact in command_record_facts(&[alice_legacy, bob_legacy]).unwrap() {
            store
                .append_record(&fact.scope_id, &fact.kind, &fact.payload)
                .unwrap();
        }
        let started = custody_record_facts(
            "alice",
            &AccountAuthCustody::default(),
            CustodyCommand::BeginMigration {
                operation_id: "migration-alice".into(),
                source_basis: "legacy-position-1".into(),
            },
        )
        .unwrap();
        for fact in started {
            store
                .append_record(&fact.scope_id, &fact.kind, &fact.payload)
                .unwrap();
        }

        let alice_current = AccountAuthFact::Email(
            VerifiedEmailRecord::new("alice", "new-alice@example.com", 2).unwrap(),
        );
        let bob_current = AccountAuthFact::Email(
            VerifiedEmailRecord::new("bob", "new-bob@example.com", 2).unwrap(),
        );
        let encoded =
            current_command_record_facts(&store, &[alice_current.clone(), bob_current.clone()])
                .unwrap();
        assert_eq!(
            encoded[0].scope_id,
            crate::account_auth_custody::account_auth_scope("alice").unwrap()
        );
        assert_eq!(encoded[1].scope_id, ACCOUNT_AUTH_SCOPE);
        append_facts(&mut store, &[alice_current, bob_current]).unwrap();

        let current = AccountAuth::rebuild_current(&store).unwrap();
        assert_eq!(
            current.methods_for("alice").emails[0].email,
            "new-alice@example.com"
        );
        assert_eq!(
            current.methods_for("bob").emails[0].email,
            "new-bob@example.com"
        );
        assert_eq!(
            current.account_ids(),
            BTreeSet::from(["alice".to_owned(), "bob".to_owned()])
        );
        let bob_email_count = current.methods_for("bob").emails.len();

        let copying = crate::account_auth_custody::AccountAuthCustodyCatalog::rebuild(&store)
            .unwrap()
            .account("alice");
        for fact in custody_record_facts(
            "alice",
            &copying,
            CustodyCommand::CompleteMigration {
                operation_id: "migration-alice".into(),
                destination_basis: "account-position-1".into(),
                evidence_id: "copy-verified".into(),
            },
        )
        .unwrap()
        {
            store
                .append_record(&fact.scope_id, &fact.kind, &fact.payload)
                .unwrap();
        }
        let migrated = crate::account_auth_custody::AccountAuthCustodyCatalog::rebuild(&store)
            .unwrap()
            .account("alice");
        for fact in custody_record_facts(
            "alice",
            &migrated,
            CustodyCommand::FenceErasure {
                operation_id: "erase-alice".into(),
                authorization_id: "fresh-passkey-proof".into(),
                review_id: "review-alice".into(),
                blocking_organization_ids: Vec::new(),
            },
        )
        .unwrap()
        {
            store
                .append_record(&fact.scope_id, &fact.kind, &fact.payload)
                .unwrap();
        }

        // The account key still exists at this crash point, but the fence is
        // already authoritative. Explicit migration verification can inspect
        // the copied scope; ordinary authentication and Account reads cannot.
        assert_eq!(
            AccountAuth::rebuild_with_account_scopes(&store, ["alice"])
                .unwrap()
                .methods_for("alice")
                .emails
                .len(),
            1
        );
        let fenced = AccountAuth::rebuild_current(&store).unwrap();
        assert!(fenced.methods_for("alice").emails.is_empty());
        assert_eq!(fenced.methods_for("bob").emails.len(), bob_email_count);
        assert!(!fenced.account_ids().contains("alice"));
        assert!(matches!(
            current_command_record_facts(
                &store,
                &[AccountAuthFact::Session(
                    AccountSessionRecord::new("late", "alice", "passkey", 3, 60).unwrap()
                )]
            ),
            Err(AdmitError::Codec(message))
                if message == "account-auth mutation refused after erasure fence"
        ));
    }
}
