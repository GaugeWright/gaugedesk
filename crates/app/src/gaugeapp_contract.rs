//! Client-independent GaugeApp admission contract (ADR 0161).
//!
//! HTTP routes authenticate the actor and rebuild a [`GaugeAppSession`] on
//! every request. This module owns the pure App/scope/page/command/basis/review
//! decision shared by desktop, web, and agent callers. A client label is
//! evidence only; it never changes policy.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use gaugedesk_store::{AdmitError, Store};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GaugeAppKind {
    AccountSettings,
    Administration,
    CommercialOperations,
}

impl GaugeAppKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountSettings => "account-settings",
            Self::Administration => "administration",
            Self::CommercialOperations => "commercial-operations",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GaugeAppClient {
    Desktop,
    Web,
    Agent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewPolicy {
    Immediate,
    Human,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppScope {
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GaugeAppPageAvailability {
    Available,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppPageGrant {
    pub id: String,
    pub read_model: String,
    pub version: u32,
    pub resource_basis: String,
    pub freshness: String,
    pub availability: GaugeAppPageAvailability,
    pub commands: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppCommandGrant {
    pub id: String,
    pub capability: String,
    pub review: ReviewPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppSession {
    pub id: String,
    pub generation: String,
    pub app: GaugeAppKind,
    pub scope: GaugeAppScope,
    pub actor: String,
    pub capabilities: Vec<String>,
    pub pages: Vec<GaugeAppPageGrant>,
    pub commands: Vec<GaugeAppCommandGrant>,
    pub update_cursor: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GaugeAppCommandEnvelope {
    pub session_id: String,
    pub generation: String,
    pub app: GaugeAppKind,
    pub scope: GaugeAppScope,
    pub page_id: String,
    pub command_id: String,
    pub expected_basis: String,
    pub idempotency_key: String,
    pub payload: Value,
    pub client: GaugeAppClient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDisposition {
    Apply,
    Propose,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GaugeAppRejection {
    SessionMismatch,
    ScopeMismatch,
    UnknownPage,
    PageUnavailable,
    UnknownCommand,
    CommandNotDeclaredForPage,
    CapabilityMissing,
    StaleBasis,
    MissingIdempotencyKey,
}

impl GaugeAppRejection {
    pub fn message(&self) -> &'static str {
        match self {
            Self::SessionMismatch => "GaugeApp session is stale or does not match",
            Self::ScopeMismatch => "GaugeApp scope does not match the admitted session",
            Self::UnknownPage => "page is not admitted in this GaugeApp session",
            Self::PageUnavailable => "page is unavailable in this GaugeApp session",
            Self::UnknownCommand => "command is not admitted in this GaugeApp session",
            Self::CommandNotDeclaredForPage => "command is not declared for this GaugeApp page",
            Self::CapabilityMissing => "command capability is not admitted",
            Self::StaleBasis => "page resource basis is stale",
            Self::MissingIdempotencyKey => "command idempotency key is required",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GaugeAppAdmission {
    pub disposition: AdmissionDisposition,
    pub command: GaugeAppCommandGrant,
}

/// Decide one command against a freshly rebuilt authenticated session.
///
/// Every client uses this one policy path. The command's review policy governs
/// disposition for the person and their bounded agent alike; agent tool
/// admission separately limits which commands the model can reach.
pub fn decide_gaugeapp_command(
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
) -> Result<GaugeAppAdmission, GaugeAppRejection> {
    if envelope.session_id != session.id
        || envelope.generation != session.generation
        || envelope.app != session.app
    {
        return Err(GaugeAppRejection::SessionMismatch);
    }
    if envelope.scope != session.scope {
        return Err(GaugeAppRejection::ScopeMismatch);
    }
    if envelope.idempotency_key.trim().is_empty() {
        return Err(GaugeAppRejection::MissingIdempotencyKey);
    }
    let page = session
        .pages
        .iter()
        .find(|page| page.id == envelope.page_id)
        .ok_or(GaugeAppRejection::UnknownPage)?;
    if page.availability != GaugeAppPageAvailability::Available {
        return Err(GaugeAppRejection::PageUnavailable);
    }
    let command = session
        .commands
        .iter()
        .find(|command| command.id == envelope.command_id)
        .ok_or(GaugeAppRejection::UnknownCommand)?;
    if !page.commands.contains(&command.id) {
        return Err(GaugeAppRejection::CommandNotDeclaredForPage);
    }
    if !session.capabilities.contains(&command.capability) {
        return Err(GaugeAppRejection::CapabilityMissing);
    }
    if envelope.expected_basis != page.resource_basis {
        return Err(GaugeAppRejection::StaleBasis);
    }
    Ok(GaugeAppAdmission {
        disposition: match command.review {
            ReviewPolicy::Immediate => AdmissionDisposition::Apply,
            ReviewPolicy::Human => AdmissionDisposition::Propose,
        },
        command: command.clone(),
    })
}

/// Re-run the complete current-session decision at human-review time. A prior
/// proposal is never standing authority: scope, capability, declaration, and
/// base freshness are all checked again before the reviewed command may apply.
pub fn decide_reviewed_gaugeapp_command(
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
) -> Result<GaugeAppAdmission, GaugeAppRejection> {
    let mut admission = decide_gaugeapp_command(session, envelope)?;
    admission.disposition = AdmissionDisposition::Apply;
    Ok(admission)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppReceipt {
    pub id: String,
    pub session_id: String,
    pub generation: String,
    pub app: GaugeAppKind,
    pub scope: GaugeAppScope,
    pub page_id: String,
    pub command_id: String,
    pub expected_basis: String,
    pub status: String,
}

pub const GAUGEAPP_CHANGE_KIND: &str = "gaugeapp_change";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GaugeAppChangeStatus {
    Proposed,
    /// Human approval is durable; the external authority's outcome is not yet
    /// confirmed. This is neither another proposal nor a completed mutation.
    Applying,
    Applied,
    Rejected,
    Conflict,
}

/// Durable, secret-free management change projection. Payloads enter this record
/// only after the owning GaugeApp parser has validated its closed command
/// schema and rejected secret-bearing fields.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GaugeAppChangeRecord {
    pub id: String,
    pub app: GaugeAppKind,
    pub scope: GaugeAppScope,
    pub actor: String,
    pub page_id: String,
    pub command_id: String,
    pub expected_basis: String,
    pub payload: Value,
    pub client: GaugeAppClient,
    pub status: GaugeAppChangeStatus,
    #[serde(default)]
    pub reviewed_by: Option<String>,
    pub receipt_id: String,
}

pub fn gaugeapp_change_id(session: &GaugeAppSession, envelope: &GaugeAppCommandEnvelope) -> String {
    let material = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        session.actor,
        session.app.as_str(),
        session.scope.kind,
        session.scope.id,
        envelope.page_id,
        envelope.command_id,
        envelope.idempotency_key,
    );
    format!(
        "gaugeapp-change:{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

pub fn fold_gaugeapp_changes(
    store: &Store,
    command_scope: &str,
) -> Result<BTreeMap<String, GaugeAppChangeRecord>, AdmitError> {
    let mut changes = BTreeMap::new();
    for payload in store.records(command_scope, GAUGEAPP_CHANGE_KIND)? {
        let change: GaugeAppChangeRecord = serde_json::from_str(&payload)?;
        changes.insert(change.id.clone(), change);
    }
    Ok(changes)
}

/// Secret-free stable receipt identity. Payload content is deliberately absent;
/// the store binds the caller idempotency key to its independently hashed input.
pub fn gaugeapp_receipt(
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
    status: &str,
) -> GaugeAppReceipt {
    let material = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        session.actor,
        session.app.as_str(),
        session.scope.kind,
        session.scope.id,
        envelope.page_id,
        envelope.command_id,
        envelope.idempotency_key,
    );
    GaugeAppReceipt {
        id: format!(
            "gaugeapp-receipt:{}",
            hex::encode(Sha256::digest(material.as_bytes()))
        ),
        session_id: session.id.clone(),
        generation: session.generation.clone(),
        app: session.app,
        scope: session.scope.clone(),
        page_id: envelope.page_id.clone(),
        command_id: envelope.command_id.clone(),
        expected_basis: envelope.expected_basis.clone(),
        status: status.to_owned(),
    }
}

/// Session identity is correlation, never a bearer. Routes must rebuild the
/// same actor/scope/capability epoch before accepting an envelope carrying it.
pub fn gaugeapp_session_id(
    actor: &str,
    app: GaugeAppKind,
    scope: &GaugeAppScope,
    authorization_epoch: &str,
) -> String {
    let material = format!(
        "{actor}\n{}\n{}\n{}\n{authorization_epoch}",
        app.as_str(),
        scope.kind,
        scope.id
    );
    format!(
        "gaugeapp-session:{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn session() -> GaugeAppSession {
        let scope = GaugeAppScope {
            kind: "tenant".into(),
            id: "tenant-a".into(),
        };
        GaugeAppSession {
            id: gaugeapp_session_id("alice", GaugeAppKind::Administration, &scope, "7"),
            generation: "7".into(),
            app: GaugeAppKind::Administration,
            scope,
            actor: "alice".into(),
            capabilities: vec!["manage-members".into(), "configure-security".into()],
            pages: vec![GaugeAppPageGrant {
                id: "access".into(),
                read_model: "administration.people".into(),
                version: 1,
                resource_basis: "42".into(),
                freshness: "live".into(),
                availability: GaugeAppPageAvailability::Available,
                commands: vec!["member.invite".into()],
            }],
            commands: vec![GaugeAppCommandGrant {
                id: "member.invite".into(),
                capability: "manage-members".into(),
                review: ReviewPolicy::Human,
            }],
            update_cursor: "42".into(),
        }
    }

    fn envelope(client: GaugeAppClient) -> GaugeAppCommandEnvelope {
        let session = session();
        GaugeAppCommandEnvelope {
            session_id: session.id,
            generation: session.generation,
            app: session.app,
            scope: session.scope,
            page_id: "access".into(),
            command_id: "member.invite".into(),
            expected_basis: "42".into(),
            idempotency_key: "invite-bob".into(),
            payload: serde_json::json!({"authority":"bob"}),
            client,
        }
    }

    #[test]
    fn every_client_shares_one_review_decision() {
        let session = session();
        for client in [
            GaugeAppClient::Desktop,
            GaugeAppClient::Web,
            GaugeAppClient::Agent,
        ] {
            assert_eq!(
                decide_gaugeapp_command(&session, &envelope(client))
                    .unwrap()
                    .disposition,
                AdmissionDisposition::Propose
            );
        }
    }

    #[test]
    fn agent_and_person_apply_the_same_immediate_command() {
        let mut session = session();
        session.commands[0].review = ReviewPolicy::Immediate;
        assert_eq!(
            decide_gaugeapp_command(&session, &envelope(GaugeAppClient::Web))
                .unwrap()
                .disposition,
            AdmissionDisposition::Apply,
        );
        assert_eq!(
            decide_gaugeapp_command(&session, &envelope(GaugeAppClient::Agent))
                .unwrap()
                .disposition,
            AdmissionDisposition::Apply,
        );
    }

    #[test]
    fn review_rechecks_the_current_basis_before_allowing_apply() {
        let session = session();
        assert_eq!(
            decide_reviewed_gaugeapp_command(&session, &envelope(GaugeAppClient::Web))
                .unwrap()
                .disposition,
            AdmissionDisposition::Apply
        );
        let mut stale = envelope(GaugeAppClient::Web);
        stale.expected_basis = "earlier".into();
        assert_eq!(
            decide_reviewed_gaugeapp_command(&session, &stale),
            Err(GaugeAppRejection::StaleBasis)
        );
    }

    #[test]
    fn scope_basis_page_command_and_capability_fail_closed() {
        let session = session();
        let mut command = envelope(GaugeAppClient::Web);
        command.scope.id = "tenant-b".into();
        assert_eq!(
            decide_gaugeapp_command(&session, &command),
            Err(GaugeAppRejection::ScopeMismatch)
        );
        command = envelope(GaugeAppClient::Web);
        command.expected_basis = "41".into();
        assert_eq!(
            decide_gaugeapp_command(&session, &command),
            Err(GaugeAppRejection::StaleBasis)
        );
        command = envelope(GaugeAppClient::Web);
        command.page_id = "billing".into();
        assert_eq!(
            decide_gaugeapp_command(&session, &command),
            Err(GaugeAppRejection::UnknownPage)
        );
        command = envelope(GaugeAppClient::Web);
        command.command_id = "member.deactivate".into();
        assert_eq!(
            decide_gaugeapp_command(&session, &command),
            Err(GaugeAppRejection::UnknownCommand)
        );
        let mut no_capability = session.clone();
        no_capability.capabilities.clear();
        assert_eq!(
            decide_gaugeapp_command(&no_capability, &envelope(GaugeAppClient::Web)),
            Err(GaugeAppRejection::CapabilityMissing)
        );
    }

    proptest! {
        #[test]
        fn client_label_never_changes_admission(which in 0u8..3) {
            let client = match which { 0 => GaugeAppClient::Desktop, 1 => GaugeAppClient::Web, _ => GaugeAppClient::Agent };
            prop_assert_eq!(decide_gaugeapp_command(&session(), &envelope(client)).unwrap().command, decide_gaugeapp_command(&session(), &envelope(GaugeAppClient::Web)).unwrap().command);
        }

        #[test]
        fn receipt_is_stable_for_retry(key in "[a-z0-9-]{1,40}") {
            let session = session();
            let mut envelope = envelope(GaugeAppClient::Web);
            envelope.idempotency_key = key;
            prop_assert_eq!(gaugeapp_receipt(&session, &envelope, "proposed"), gaugeapp_receipt(&session, &envelope, "proposed"));
        }
    }
}
