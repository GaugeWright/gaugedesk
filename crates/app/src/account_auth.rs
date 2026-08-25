//! Provider-neutral account authentication facts (`AUTH-1`, ADR 0146).
//!
//! The GaugeDesk account root is the person. This module records only the ways
//! that person may authenticate to the private Hub account service: verified
//! email contacts, WebAuthn public credentials, exact external-subject links,
//! and salted recovery-code hashes. It stores no passkey private key, recovery
//! plaintext, OIDC token, client secret, or account-root seed.
//!
//! All links share one Hub-owned scope. That is intentional: uniqueness of a
//! `(connection, issuer, subject)` or WebAuthn credential id must be decided
//! against one ordered projection, not independently inside two account scopes.
//! The account id on every record keeps the fact attributable and lets the
//! person-scoped Account surface select only its own methods (`INV-1`/`INV-22`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use gaugedesk_store::{AdmitError, Store};

pub use crate::account::RecordOp;

/// The single ordering scope for Hub account-auth facts.
pub const ACCOUNT_AUTH_SCOPE: &str = "account-auth";

const EMAIL_KIND: &str = "account_auth_email";
const WEBAUTHN_KIND: &str = "account_auth_webauthn";
const SUBJECT_KIND: &str = "account_auth_subject";
const RECOVERY_BATCH_KIND: &str = "account_auth_recovery_batch";
const RECOVERY_CODE_KIND: &str = "account_auth_recovery_code";

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
        let email = normalize_email(email).ok_or(AuthRejection::InvalidEmail)?;
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
/// keeps the private key. `public_key_cose` and `credential_id` use base64url at
/// the HTTP boundary, but this projection treats their validated form as opaque.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnMethodRecord {
    /// The WebAuthn credential id; globally unique in this Hub auth scope.
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub account_id: String,
    pub public_key_cose: String,
    #[serde(default)]
    pub sign_count: u32,
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
        public_key_cose: &str,
        sign_count: u32,
        label: &str,
        created_at: u64,
    ) -> Result<Self, AuthRejection> {
        Ok(Self {
            id: required(credential_id)?,
            op: RecordOp::Upsert,
            account_id: required(account_id)?,
            public_key_cose: required(public_key_cose)?,
            sign_count,
            label: label.trim().to_owned(),
            created_at,
            status: AuthMethodStatus::Active,
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

/// Rebuildable Hub account-auth projection (`INV-5`).
#[derive(Default, Clone, Debug)]
pub struct AccountAuth {
    pub emails: BTreeMap<String, VerifiedEmailRecord>,
    pub webauthn_methods: BTreeMap<String, WebAuthnMethodRecord>,
    pub external_subjects: BTreeMap<String, ExternalSubjectRecord>,
    pub recovery_batches: BTreeMap<String, RecoveryBatchRecord>,
    pub recovery_codes: BTreeMap<String, RecoveryCodeRecord>,
}

impl AccountAuth {
    pub fn rebuild(store: &Store) -> Result<Self, AdmitError> {
        let mut state = Self::default();
        for row in store.records(ACCOUNT_AUTH_SCOPE, EMAIL_KIND)? {
            let record: VerifiedEmailRecord = serde_json::from_str(&row)?;
            fold(&mut state.emails, record.id.clone(), record.op, record);
        }
        for row in store.records(ACCOUNT_AUTH_SCOPE, WEBAUTHN_KIND)? {
            let record: WebAuthnMethodRecord = serde_json::from_str(&row)?;
            fold(
                &mut state.webauthn_methods,
                record.id.clone(),
                record.op,
                record,
            );
        }
        for row in store.records(ACCOUNT_AUTH_SCOPE, SUBJECT_KIND)? {
            let record: ExternalSubjectRecord = serde_json::from_str(&row)?;
            fold(
                &mut state.external_subjects,
                record.id.clone(),
                record.op,
                record,
            );
        }
        for row in store.records(ACCOUNT_AUTH_SCOPE, RECOVERY_BATCH_KIND)? {
            let record: RecoveryBatchRecord = serde_json::from_str(&row)?;
            fold(
                &mut state.recovery_batches,
                record.id.clone(),
                record.op,
                record,
            );
        }
        for row in store.records(ACCOUNT_AUTH_SCOPE, RECOVERY_CODE_KIND)? {
            let record: RecoveryCodeRecord = serde_json::from_str(&row)?;
            fold(
                &mut state.recovery_codes,
                record.id.clone(),
                record.op,
                record,
            );
        }
        Ok(state)
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
    Email(VerifiedEmailRecord),
    WebAuthn(WebAuthnMethodRecord),
    ExternalSubject(ExternalSubjectRecord),
    RecoveryBatch(RecoveryBatchRecord),
    RecoveryCode(RecoveryCodeRecord),
}

impl AccountAuthFact {
    fn kind(&self) -> &'static str {
        match self {
            Self::Email(_) => EMAIL_KIND,
            Self::WebAuthn(_) => WEBAUTHN_KIND,
            Self::ExternalSubject(_) => SUBJECT_KIND,
            Self::RecoveryBatch(_) => RECOVERY_BATCH_KIND,
            Self::RecoveryCode(_) => RECOVERY_CODE_KIND,
        }
    }

    fn json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Email(record) => serde_json::to_string(record),
            Self::WebAuthn(record) => serde_json::to_string(record),
            Self::ExternalSubject(record) => serde_json::to_string(record),
            Self::RecoveryBatch(record) => serde_json::to_string(record),
            Self::RecoveryCode(record) => serde_json::to_string(record),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRejection {
    InvalidAccount,
    InvalidEmail,
    InvalidVerifierMaterial,
    CredentialAlreadyLinked,
    SubjectAlreadyLinked,
    MethodNotFound,
    LastIndependentMethod,
    RecoveryBatchNotActive,
    RecoveryCodeAlreadyConsumed,
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
    let encoded: Result<Vec<(&str, String)>, serde_json::Error> = facts
        .iter()
        .map(|fact| Ok((fact.kind(), fact.json()?)))
        .collect();
    let encoded = encoded?;
    let borrowed: Vec<(&str, &str, &str)> = encoded
        .iter()
        .map(|(kind, payload)| (ACCOUNT_AUTH_SCOPE, *kind, payload.as_str()))
        .collect();
    store.append_records_atomically(&borrowed)?;
    Ok(())
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

fn normalize_email(value: &str) -> Option<String> {
    let normalized = value.trim().to_lowercase();
    let (local, domain) = normalized.rsplit_once('@')?;
    (!local.is_empty()
        && !domain.is_empty()
        && !local.chars().any(char::is_whitespace)
        && !domain.chars().any(char::is_whitespace))
    .then_some(normalized)
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
        WebAuthnMethodRecord::new(account, id, "public-cose", 0, "Security key", 10).unwrap()
    }

    fn apply(state: &mut AccountAuth, facts: &[AccountAuthFact]) {
        for fact in facts {
            match fact {
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
            }
        }
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
            EMAIL_KIND,
            WEBAUTHN_KIND,
            RECOVERY_BATCH_KIND,
            RECOVERY_CODE_KIND,
        ] {
            for row in store.records(ACCOUNT_AUTH_SCOPE, kind).unwrap() {
                assert!(!row.contains("SECRET-CODE"));
                assert!(!row.contains("private_key"));
                assert!(!row.contains("client_secret"));
                assert!(!row.contains("id_token"));
            }
        }
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
}
