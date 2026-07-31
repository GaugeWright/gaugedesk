//! Client-independent management Environment admission contract (ADR 0105–0107).
//!
//! HTTP routes authenticate the actor and rebuild an [`EnvironmentSession`] on
//! every request. This module then owns the pure scope/document/command/base/
//! review decision shared by browser controls, literal edits, agents, and
//! CLI-shaped callers. A client label is evidence only; it never changes policy.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use gaugewright_store::{AdmitError, Store};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentKind {
    Hub,
    Administration,
    Vend,
}

impl EnvironmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hub => "hub",
            Self::Administration => "administration",
            Self::Vend => "vend",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentClient {
    Browser,
    Edit,
    Agent,
    Cli,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewPolicy {
    Immediate,
    Human,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvironmentScope {
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvironmentDocumentGrant {
    pub id: String,
    pub path: String,
    pub schema: String,
    pub revision: String,
    pub freshness: String,
    pub readable: bool,
    pub editable: bool,
    pub commands: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvironmentCommandGrant {
    pub id: String,
    pub capability: String,
    pub review: ReviewPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvironmentSession {
    pub id: String,
    pub environment: EnvironmentKind,
    pub scope: EnvironmentScope,
    pub actor: String,
    pub capabilities: Vec<String>,
    pub documents: Vec<EnvironmentDocumentGrant>,
    pub commands: Vec<EnvironmentCommandGrant>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EnvironmentCommandEnvelope {
    pub session_id: String,
    pub environment: EnvironmentKind,
    pub scope: EnvironmentScope,
    pub document_id: String,
    pub command_id: String,
    pub base_revision: String,
    pub payload: Value,
    pub client: EnvironmentClient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDisposition {
    Apply,
    Propose,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentRejection {
    SessionMismatch,
    ScopeMismatch,
    UnknownDocument,
    DocumentNotReadable,
    UnknownCommand,
    CommandNotDeclaredForDocument,
    CapabilityMissing,
    StaleBase,
}

impl EnvironmentRejection {
    pub fn message(&self) -> &'static str {
        match self {
            Self::SessionMismatch => "environment session is stale or does not match",
            Self::ScopeMismatch => "environment scope does not match the admitted session",
            Self::UnknownDocument => "document is not admitted in this environment session",
            Self::DocumentNotReadable => "document is not readable in this environment session",
            Self::UnknownCommand => "command is not admitted in this environment session",
            Self::CommandNotDeclaredForDocument => {
                "command is not declared for this environment document"
            }
            Self::CapabilityMissing => "command capability is not admitted",
            Self::StaleBase => "document base revision is stale",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentAdmission {
    pub disposition: AdmissionDisposition,
    pub command: EnvironmentCommandGrant,
}

/// Decide one command against a freshly rebuilt authenticated session.
///
/// Every client uses this one policy path. Agent-originated mutation is the
/// deliberate strict subset: even a command that is immediate for a person is
/// proposal-only for an agent, which can never review its own proposal.
pub fn decide_environment_command(
    session: &EnvironmentSession,
    envelope: &EnvironmentCommandEnvelope,
) -> Result<EnvironmentAdmission, EnvironmentRejection> {
    if envelope.session_id != session.id || envelope.environment != session.environment {
        return Err(EnvironmentRejection::SessionMismatch);
    }
    if envelope.scope != session.scope {
        return Err(EnvironmentRejection::ScopeMismatch);
    }
    let document = session
        .documents
        .iter()
        .find(|document| document.id == envelope.document_id)
        .ok_or(EnvironmentRejection::UnknownDocument)?;
    if !document.readable {
        return Err(EnvironmentRejection::DocumentNotReadable);
    }
    let command = session
        .commands
        .iter()
        .find(|command| command.id == envelope.command_id)
        .ok_or(EnvironmentRejection::UnknownCommand)?;
    if !document.commands.contains(&command.id) {
        return Err(EnvironmentRejection::CommandNotDeclaredForDocument);
    }
    if !session.capabilities.contains(&command.capability) {
        return Err(EnvironmentRejection::CapabilityMissing);
    }
    if envelope.base_revision != document.revision {
        return Err(EnvironmentRejection::StaleBase);
    }
    Ok(EnvironmentAdmission {
        disposition: if envelope.client == EnvironmentClient::Agent {
            AdmissionDisposition::Propose
        } else {
            match command.review {
                ReviewPolicy::Immediate => AdmissionDisposition::Apply,
                ReviewPolicy::Human => AdmissionDisposition::Propose,
            }
        },
        command: command.clone(),
    })
}

/// Re-run the complete current-session decision at human-review time. A prior
/// proposal is never standing authority: scope, capability, declaration, and
/// base freshness are all checked again before the reviewed command may apply.
pub fn decide_reviewed_environment_command(
    session: &EnvironmentSession,
    envelope: &EnvironmentCommandEnvelope,
) -> Result<EnvironmentAdmission, EnvironmentRejection> {
    let mut admission = decide_environment_command(session, envelope)?;
    admission.disposition = AdmissionDisposition::Apply;
    Ok(admission)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvironmentReceipt {
    pub id: String,
    pub session_id: String,
    pub environment: EnvironmentKind,
    pub scope: EnvironmentScope,
    pub document_id: String,
    pub command_id: String,
    pub base_revision: String,
    pub status: String,
}

pub const ENVIRONMENT_CHANGE_KIND: &str = "environment_change";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentChangeStatus {
    Proposed,
    Applied,
    Rejected,
    Conflict,
}

/// Durable, secret-free management change projection. Payloads enter this record
/// only after the owning Environment parser has validated its closed command
/// schema and rejected secret-bearing fields.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EnvironmentChangeRecord {
    pub id: String,
    pub environment: EnvironmentKind,
    pub scope: EnvironmentScope,
    pub actor: String,
    pub document_id: String,
    pub command_id: String,
    pub base_revision: String,
    pub payload: Value,
    pub client: EnvironmentClient,
    pub status: EnvironmentChangeStatus,
    #[serde(default)]
    pub reviewed_by: Option<String>,
    pub receipt_id: String,
}

pub fn environment_change_id(
    session: &EnvironmentSession,
    envelope: &EnvironmentCommandEnvelope,
    idempotency_key: &str,
) -> String {
    let material = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        session.actor,
        session.environment.as_str(),
        session.scope.kind,
        session.scope.id,
        envelope.document_id,
        envelope.command_id,
        idempotency_key,
    );
    format!(
        "environment-change:{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

pub fn fold_environment_changes(
    store: &Store,
    command_scope: &str,
) -> Result<BTreeMap<String, EnvironmentChangeRecord>, AdmitError> {
    let mut changes = BTreeMap::new();
    for payload in store.records(command_scope, ENVIRONMENT_CHANGE_KIND)? {
        let change: EnvironmentChangeRecord = serde_json::from_str(&payload)?;
        changes.insert(change.id.clone(), change);
    }
    Ok(changes)
}

/// Secret-free stable receipt identity. Payload content is deliberately absent;
/// the store binds the caller idempotency key to its independently hashed input.
pub fn environment_receipt(
    session: &EnvironmentSession,
    envelope: &EnvironmentCommandEnvelope,
    idempotency_key: &str,
    status: &str,
) -> EnvironmentReceipt {
    let material = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        session.actor,
        session.environment.as_str(),
        session.scope.kind,
        session.scope.id,
        envelope.document_id,
        envelope.command_id,
        idempotency_key,
    );
    EnvironmentReceipt {
        id: format!(
            "environment-receipt:{}",
            hex::encode(Sha256::digest(material.as_bytes()))
        ),
        session_id: session.id.clone(),
        environment: session.environment,
        scope: session.scope.clone(),
        document_id: envelope.document_id.clone(),
        command_id: envelope.command_id.clone(),
        base_revision: envelope.base_revision.clone(),
        status: status.to_owned(),
    }
}

/// Session identity is correlation, never a bearer. Routes must rebuild the
/// same actor/scope/capability epoch before accepting an envelope carrying it.
pub fn environment_session_id(
    actor: &str,
    environment: EnvironmentKind,
    scope: &EnvironmentScope,
    authorization_epoch: &str,
) -> String {
    let material = format!(
        "{actor}\n{}\n{}\n{}\n{authorization_epoch}",
        environment.as_str(),
        scope.kind,
        scope.id
    );
    format!(
        "environment-session:{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn session() -> EnvironmentSession {
        let scope = EnvironmentScope {
            kind: "tenant".into(),
            id: "tenant-a".into(),
        };
        EnvironmentSession {
            id: environment_session_id("alice", EnvironmentKind::Administration, &scope, "7"),
            environment: EnvironmentKind::Administration,
            scope,
            actor: "alice".into(),
            capabilities: vec!["manage-members".into(), "configure-security".into()],
            documents: vec![EnvironmentDocumentGrant {
                id: "access".into(),
                path: "access.json".into(),
                schema: "access/v1".into(),
                revision: "42".into(),
                freshness: "live".into(),
                readable: true,
                editable: true,
                commands: vec!["member.invite".into()],
            }],
            commands: vec![EnvironmentCommandGrant {
                id: "member.invite".into(),
                capability: "manage-members".into(),
                review: ReviewPolicy::Human,
            }],
        }
    }

    fn envelope(client: EnvironmentClient) -> EnvironmentCommandEnvelope {
        let session = session();
        EnvironmentCommandEnvelope {
            session_id: session.id,
            environment: session.environment,
            scope: session.scope,
            document_id: "access".into(),
            command_id: "member.invite".into(),
            base_revision: "42".into(),
            payload: serde_json::json!({"authority":"bob"}),
            client,
        }
    }

    #[test]
    fn every_client_shares_one_review_decision() {
        let session = session();
        for client in [
            EnvironmentClient::Browser,
            EnvironmentClient::Edit,
            EnvironmentClient::Agent,
            EnvironmentClient::Cli,
        ] {
            assert_eq!(
                decide_environment_command(&session, &envelope(client))
                    .unwrap()
                    .disposition,
                AdmissionDisposition::Propose
            );
        }
    }

    #[test]
    fn agent_cannot_apply_an_otherwise_immediate_command() {
        let mut session = session();
        session.commands[0].review = ReviewPolicy::Immediate;
        assert_eq!(
            decide_environment_command(&session, &envelope(EnvironmentClient::Browser))
                .unwrap()
                .disposition,
            AdmissionDisposition::Apply,
        );
        assert_eq!(
            decide_environment_command(&session, &envelope(EnvironmentClient::Agent))
                .unwrap()
                .disposition,
            AdmissionDisposition::Propose,
        );
    }

    #[test]
    fn review_rechecks_the_current_base_before_allowing_apply() {
        let session = session();
        assert_eq!(
            decide_reviewed_environment_command(&session, &envelope(EnvironmentClient::Browser))
                .unwrap()
                .disposition,
            AdmissionDisposition::Apply
        );
        let mut stale = envelope(EnvironmentClient::Browser);
        stale.base_revision = "earlier".into();
        assert_eq!(
            decide_reviewed_environment_command(&session, &stale),
            Err(EnvironmentRejection::StaleBase)
        );
    }

    #[test]
    fn scope_base_document_command_and_capability_fail_closed() {
        let session = session();
        let mut command = envelope(EnvironmentClient::Browser);
        command.scope.id = "tenant-b".into();
        assert_eq!(
            decide_environment_command(&session, &command),
            Err(EnvironmentRejection::ScopeMismatch)
        );
        command = envelope(EnvironmentClient::Browser);
        command.base_revision = "41".into();
        assert_eq!(
            decide_environment_command(&session, &command),
            Err(EnvironmentRejection::StaleBase)
        );
        command = envelope(EnvironmentClient::Browser);
        command.document_id = "billing".into();
        assert_eq!(
            decide_environment_command(&session, &command),
            Err(EnvironmentRejection::UnknownDocument)
        );
        command = envelope(EnvironmentClient::Browser);
        command.command_id = "member.deactivate".into();
        assert_eq!(
            decide_environment_command(&session, &command),
            Err(EnvironmentRejection::UnknownCommand)
        );
        let mut no_capability = session.clone();
        no_capability.capabilities.clear();
        assert_eq!(
            decide_environment_command(&no_capability, &envelope(EnvironmentClient::Browser)),
            Err(EnvironmentRejection::CapabilityMissing)
        );
    }

    proptest! {
        #[test]
        fn client_label_never_changes_admission(which in 0u8..4) {
            let client = match which { 0 => EnvironmentClient::Browser, 1 => EnvironmentClient::Edit, 2 => EnvironmentClient::Agent, _ => EnvironmentClient::Cli };
            prop_assert_eq!(decide_environment_command(&session(), &envelope(client)), decide_environment_command(&session(), &envelope(EnvironmentClient::Browser)));
        }

        #[test]
        fn receipt_is_stable_for_retry(key in "[a-z0-9-]{1,40}") {
            let session = session();
            let envelope = envelope(EnvironmentClient::Browser);
            prop_assert_eq!(environment_receipt(&session, &envelope, &key, "proposed"), environment_receipt(&session, &envelope, &key, "proposed"));
        }
    }
}
