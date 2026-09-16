//! Closed, secret-free management requests for the separate organization
//! credential authority (GAUGEAPP-6). This is NOT a Home credential vault.
//!
//! The operated adapter supplies current authentication, the existing GaugeApp
//! human-approval evidence and validated provider/subject admissions. None is
//! deserialized from the management body. Custody submission, OAuth exchange,
//! provider checks, erasure receipts and final fetch use their own trusted paths;
//! a management request cannot manufacture those observations.

use std::collections::BTreeSet;

use gaugedesk_core::ids::{
    AuthorityId, CredentialVersionId, ModelConnectionId, ModelGrantId, ObservationId, ProjectId,
    ScopeId,
};
use gaugedesk_core::model_connection::{
    access, AuthenticationKind, AuthorityBinding, Basis, Capability, Command, ConnectionDefinition,
    ExecutionClass, ModelConnection, ModelPolicy, ModelSelection, Operation, ProviderBinding,
    State,
};
use gaugedesk_core::Rejection;
use gaugedesk_store::{AdmitError, MaterializedAdmission, RequestAdmissionStatus, Store};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub mod projection;

fn reject(reason: &'static str) -> Rejection {
    Rejection { reason }
}
fn require(value: bool, reason: &'static str) -> Result<(), Rejection> {
    if value {
        Ok(())
    } else {
        Err(reject(reason))
    }
}

/// Exact integer transport. JSON numbers (including rounded JS numbers), signs,
/// exponents, whitespace, leading zeros and overflow are refused at the edge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
struct ExactU64(u64);
impl TryFrom<String> for ExactU64 {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parsed = value.parse::<u64>().map_err(|_| "invalid exact integer")?;
        if parsed.to_string() != value {
            return Err("noncanonical exact integer");
        }
        Ok(Self(parsed))
    }
}
impl From<ExactU64> for String {
    fn from(value: ExactU64) -> Self {
        value.0.to_string()
    }
}

fn present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn optional_connection_id<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ModelConnectionId>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|value| ModelConnectionId::parse(&value).map_err(serde::de::Error::custom))
        .transpose()
}

macro_rules! parse_id {
    ($function:ident, $type:ty) => {
        fn $function<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<$type, D::Error> {
            let value = String::deserialize(deserializer)?;
            <$type>::parse(&value).map_err(serde::de::Error::custom)
        }
    };
}
parse_id!(connection_id, ModelConnectionId);
parse_id!(grant_id, ModelGrantId);
parse_id!(version_id, CredentialVersionId);
parse_id!(authority_id, AuthorityId);
parse_id!(project_id, ProjectId);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoneyInput {
    currency: access::Currency,
    micros: ExactU64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapsInput {
    #[serde(deserialize_with = "present_option")]
    tokens: Option<ExactU64>,
    #[serde(deserialize_with = "present_option")]
    money: Option<MoneyInput>,
}
impl CapsInput {
    fn domain(&self) -> access::Caps {
        access::Caps {
            tokens: self.tokens.as_ref().map(|value| value.0),
            money: self.money.as_ref().map(|value| access::Money {
                currency: value.currency.clone(),
                micros: value.micros.0,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SubjectInput {
    Member {
        #[serde(deserialize_with = "authority_id")]
        id: AuthorityId,
    },
    Project {
        #[serde(deserialize_with = "authority_id")]
        authority: AuthorityId,
        #[serde(deserialize_with = "project_id")]
        id: ProjectId,
    },
}
impl SubjectInput {
    fn domain(&self) -> access::Subject {
        match self {
            Self::Member { id } => access::Subject::Member(id.clone()),
            Self::Project { authority, id } => access::Subject::Project(access::Project {
                authority: authority.clone(),
                id: id.clone(),
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyInput {
    models: BTreeSet<String>,
    execution_classes: BTreeSet<ExecutionClass>,
}
impl PolicyInput {
    fn domain(&self) -> ModelPolicy {
        ModelPolicy {
            models: self.models.clone(),
            execution_classes: self.execution_classes.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefinitionInput {
    name: String,
    provider: String,
    endpoint: String,
    policy: PolicyInput,
    #[serde(deserialize_with = "optional_connection_id")]
    reconnects: Option<ModelConnectionId>,
}
impl DefinitionInput {
    fn domain(&self, authentication: AuthenticationKind) -> ConnectionDefinition {
        ConnectionDefinition {
            name: self.name.clone(),
            provider: ProviderBinding {
                provider: self.provider.clone(),
                endpoint: self.endpoint.clone(),
                authentication,
            },
            policy: self.policy.domain(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionInput {
    #[serde(deserialize_with = "connection_id")]
    connection: ModelConnectionId,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantInput {
    #[serde(deserialize_with = "grant_id")]
    grant: ModelGrantId,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateInput {
    #[serde(deserialize_with = "connection_id")]
    connection: ModelConnectionId,
    #[serde(deserialize_with = "version_id")]
    version: CredentialVersionId,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionInput {
    #[serde(deserialize_with = "connection_id")]
    connection: ModelConnectionId,
    model: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "arguments", deny_unknown_fields)]
enum Action {
    #[serde(rename = "organization-provider.api-key.add")]
    BeginApiKey(DefinitionInput),
    #[serde(rename = "organization-provider.account.begin")]
    BeginAccount(DefinitionInput),
    #[serde(rename = "organization-provider.rotate")]
    Replace(ConnectionInput),
    #[serde(rename = "organization-provider.intake.cancel")]
    Cancel(CandidateInput),
    #[serde(rename = "organization-provider.version.activate")]
    Activate(CandidateInput),
    #[serde(rename = "organization-provider.rename")]
    Rename {
        #[serde(deserialize_with = "connection_id")]
        connection: ModelConnectionId,
        name: String,
    },
    #[serde(rename = "organization-provider.model.approve")]
    SetPolicy {
        #[serde(deserialize_with = "connection_id")]
        connection: ModelConnectionId,
        policy: PolicyInput,
    },
    #[serde(rename = "organization-provider.default-model.set")]
    SetDefault {
        #[serde(deserialize_with = "present_option")]
        selection: Option<SelectionInput>,
    },
    #[serde(rename = "organization-provider.suspend")]
    Suspend(ConnectionInput),
    #[serde(rename = "organization-provider.resume")]
    Resume(ConnectionInput),
    #[serde(rename = "organization-provider.revoke")]
    Revoke(ConnectionInput),
    #[serde(rename = "organization-provider.erase")]
    Erase(ConnectionInput),
    #[serde(rename = "organization-provider.grant.create")]
    CreateGrant {
        #[serde(deserialize_with = "connection_id")]
        connection: ModelConnectionId,
        subject: SubjectInput,
        policy: PolicyInput,
        audiences: BTreeSet<access::PrincipalClass>,
        caps: CapsInput,
    },
    #[serde(rename = "organization-provider.grant.cap.set")]
    SetCaps {
        #[serde(deserialize_with = "grant_id")]
        grant: ModelGrantId,
        caps: CapsInput,
    },
    #[serde(rename = "organization-provider.grant.suspend")]
    SuspendGrant(GrantInput),
    #[serde(rename = "organization-provider.grant.resume")]
    ResumeGrant(GrantInput),
    #[serde(rename = "organization-provider.grant.revoke")]
    RevokeGrant(GrantInput),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    v: u8,
    idempotency_key: String,
    expected_revision: ExactU64,
    action: Action,
}

/// Only `parse` constructs a request; untrusted input never deserializes a
/// capability, evidence, secret handle, server time or the core Command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct MetadataRequest(WireRequest);
impl MetadataRequest {
    /// The outer GaugeApp command must name this exact operation. A generic
    /// metadata payload cannot turn a reviewed rename into a different action.
    pub fn operation_id(&self) -> &'static str {
        match self.0.action {
            Action::BeginApiKey(_) => "organization-provider.api-key.add",
            Action::BeginAccount(_) => "organization-provider.account.begin",
            Action::Replace(_) => "organization-provider.rotate",
            Action::Cancel(_) => "organization-provider.intake.cancel",
            Action::Activate(_) => "organization-provider.version.activate",
            Action::Rename { .. } => "organization-provider.rename",
            Action::SetPolicy { .. } => "organization-provider.model.approve",
            Action::SetDefault { .. } => "organization-provider.default-model.set",
            Action::Suspend(_) => "organization-provider.suspend",
            Action::Resume(_) => "organization-provider.resume",
            Action::Revoke(_) => "organization-provider.revoke",
            Action::Erase(_) => "organization-provider.erase",
            Action::CreateGrant { .. } => "organization-provider.grant.create",
            Action::SetCaps { .. } => "organization-provider.grant.cap.set",
            Action::SuspendGrant(_) => "organization-provider.grant.suspend",
            Action::ResumeGrant(_) => "organization-provider.grant.resume",
            Action::RevokeGrant(_) => "organization-provider.grant.revoke",
        }
    }

    pub fn expected_revision(&self) -> u64 {
        self.0.expected_revision.0
    }

    /// Store lookup hint only. The owning stable-request admission still
    /// verifies current permissions and the complete original intent before
    /// returning any receipt; existence never authorizes a new effect.
    pub fn store_key(&self) -> String {
        format!("management:{}", self.0.idempotency_key)
    }

    pub fn required_permission(&self) -> Permission {
        self.permission()
    }

    pub fn parse(value: Value) -> Result<Self, Rejection> {
        let mut request: WireRequest = serde_json::from_value(value)
            .map_err(|_| reject("invalid model-provider command schema"))?;
        require(request.v == 1, "unsupported model-provider command version")?;
        require(
            !request.idempotency_key.trim().is_empty() && request.idempotency_key.len() <= 200,
            "invalid model-provider request key",
        )?;
        let policy: Option<&PolicyInput> = match &mut request.action {
            Action::BeginApiKey(definition) | Action::BeginAccount(definition) => {
                require(
                    !definition.name.trim().is_empty() && !definition.provider.trim().is_empty(),
                    "connection name and provider are required",
                )?;
                let endpoint = url::Url::parse(&definition.endpoint)
                    .map_err(|_| reject("invalid provider endpoint"))?;
                require(
                    endpoint.scheme() == "https"
                        && endpoint.host_str().is_some()
                        && endpoint.username().is_empty()
                        && endpoint.password().is_none()
                        && endpoint.query().is_none()
                        && endpoint.fragment().is_none(),
                    "provider endpoint must be canonical HTTPS without embedded credentials",
                )?;
                definition.endpoint = endpoint.to_string();
                Some(&definition.policy)
            }
            Action::SetPolicy { policy, .. } | Action::CreateGrant { policy, .. } => Some(policy),
            Action::Rename { name, .. } => {
                require(!name.trim().is_empty(), "connection name is required")?;
                None
            }
            Action::SetDefault {
                selection: Some(selection),
            } => {
                require(!selection.model.trim().is_empty(), "model is required")?;
                None
            }
            _ => None,
        };
        if let Some(policy) = policy {
            require(
                policy.models.iter().all(|model| !model.trim().is_empty()),
                "model identities must be nonempty",
            )?;
        }
        Ok(Self(request))
    }
    fn permission(&self) -> Permission {
        match self.0.action {
            Action::CreateGrant { .. }
            | Action::SetCaps { .. }
            | Action::SuspendGrant(_)
            | Action::ResumeGrant(_)
            | Action::RevokeGrant(_) => Permission::ManageGrants,
            _ => Permission::ManageConnections,
        }
    }
    /// The provider registry must validate this entire definition; merely
    /// parsing an HTTPS endpoint does not make it eligible for key custody.
    pub fn requested_definition(&self) -> Option<ConnectionDefinition> {
        match &self.0.action {
            Action::BeginApiKey(value) => Some(value.domain(AuthenticationKind::ApiKey)),
            Action::BeginAccount(value) => {
                Some(value.domain(AuthenticationKind::OrganizationOauth))
            }
            _ => None,
        }
    }

    pub fn requested_subject(&self) -> Option<(ModelConnectionId, access::Subject)> {
        match &self.0.action {
            Action::CreateGrant {
                connection,
                subject,
                ..
            } => Some((connection.clone(), subject.domain())),
            _ => None,
        }
    }

    pub fn requested_policy(&self) -> Option<(ModelConnectionId, ModelPolicy)> {
        match &self.0.action {
            Action::SetPolicy { connection, policy } => Some((connection.clone(), policy.domain())),
            _ => None,
        }
    }

    /// Resumption must read the grant's immutable subject from the authority,
    /// then freshly validate that subject. The caller cannot replace it.
    pub fn grant_to_resume(&self) -> Option<&ModelGrantId> {
        match &self.0.action {
            Action::ResumeGrant(value) => Some(&value.grant),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    ManageConnections,
    ManageGrants,
}

/// Produced by the existing GaugeApp human-review boundary, NEVER from a
/// browser's `approved` flag. The operated service authenticates that boundary.
pub struct Approval {
    pub binding: AuthorityBinding,
    pub actor: AuthorityId,
    pub request: MetadataRequest,
    pub evidence: ObservationId,
}
pub struct SubjectAdmission {
    pub connection: ModelConnectionId,
    pub subject: access::Subject,
    pub evidence: ObservationId,
}
pub struct PolicyAdmission {
    pub connection: ModelConnectionId,
    pub policy: ModelPolicy,
}

/// Materialized only by the authenticating authority adapter. The HTTP body
/// cannot provide any of these fields. Fresh role/approval checks precede even
/// receipt replay; provider and subject proofs are required for NEW effects.
pub struct ManagementContext {
    pub binding: AuthorityBinding,
    pub actor: AuthorityId,
    pub permissions: BTreeSet<Permission>,
    pub approval: Approval,
    pub now: u64,
    pub intake_ttl_seconds: u64,
    pub validated_definition: Option<ConnectionDefinition>,
    pub validated_subject: Option<SubjectAdmission>,
    pub validated_policy: Option<PolicyAdmission>,
}

pub fn store_scope(organization: &ScopeId) -> String {
    format!("organization-model:{}", organization.as_str())
}

#[derive(Serialize)]
struct BoundIntent<'a> {
    binding: &'a AuthorityBinding,
    actor: &'a AuthorityId,
    approval: &'a ObservationId,
    request: &'a MetadataRequest,
}

fn authorize(
    state: &State,
    context: &ManagementContext,
    request: &MetadataRequest,
) -> Result<(), Rejection> {
    require(
        state
            .binding
            .as_ref()
            .is_none_or(|binding| binding == &context.binding),
        "wrong model-provider authority binding",
    )?;
    require(
        context.permissions.contains(&request.permission()),
        "model-provider management capability is missing",
    )?;
    require(
        context.approval.binding == context.binding
            && context.approval.actor == context.actor
            && context.approval.request == *request,
        "human approval does not match this model-provider request",
    )
}

fn materialize(
    state: &State,
    context: &ManagementContext,
    request: &MetadataRequest,
) -> Result<Command, Rejection> {
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&BoundIntent {
            binding: &context.binding,
            actor: &context.actor,
            approval: &context.approval.evidence,
            request,
        })
        .map_err(|_| reject("request cannot be encoded"))?,
    ));
    let candidate = || -> Result<(CredentialVersionId, u64), Rejection> {
        require(context.intake_ttl_seconds > 0, "candidate needs a deadline")?;
        let expires = context
            .now
            .checked_add(context.intake_ttl_seconds)
            .ok_or(reject("candidate deadline overflow"))?;
        Ok((
            CredentialVersionId::new(format!("candidate-{digest}")),
            expires,
        ))
    };
    let operation = match &request.0.action {
        Action::BeginApiKey(input) | Action::BeginAccount(input) => {
            let definition = request.requested_definition().expect("intake definition");
            require(
                context.validated_definition.as_ref() == Some(&definition),
                "provider definition has not been admitted",
            )?;
            let (version, expires_at) = candidate()?;
            Operation::BeginIntake {
                connection: ModelConnectionId::new(format!("connection-{digest}")),
                definition,
                reconnects: input.reconnects.clone(),
                version,
                expires_at,
            }
        }
        Action::Replace(value) => {
            let (version, expires_at) = candidate()?;
            Operation::BeginReplacement {
                connection: value.connection.clone(),
                version,
                expires_at,
            }
        }
        Action::Cancel(value) => Operation::CancelCandidate {
            connection: value.connection.clone(),
            version: value.version.clone(),
        },
        Action::Activate(value) => Operation::Activate {
            connection: value.connection.clone(),
            version: value.version.clone(),
        },
        Action::Rename { connection, name } => Operation::Rename {
            connection: connection.clone(),
            name: name.clone(),
        },
        Action::SetPolicy { connection, policy } => {
            let policy = policy.domain();
            require(
                context.validated_policy.as_ref().is_some_and(|admission| {
                    admission.connection == *connection && admission.policy == policy
                }),
                "provider model policy has not been admitted",
            )?;
            Operation::SetModelPolicy {
                connection: connection.clone(),
                policy,
            }
        }
        Action::SetDefault { selection } => Operation::SetDefault {
            selection: selection.as_ref().map(|value| ModelSelection {
                connection: value.connection.clone(),
                model: value.model.clone(),
            }),
        },
        Action::Suspend(value) => Operation::Suspend {
            connection: value.connection.clone(),
        },
        Action::Resume(value) => Operation::Resume {
            connection: value.connection.clone(),
        },
        Action::Revoke(value) => Operation::Revoke {
            connection: value.connection.clone(),
        },
        Action::Erase(value) => Operation::RequestErasure {
            connection: value.connection.clone(),
        },
        Action::CreateGrant {
            connection,
            subject,
            policy,
            audiences,
            caps,
        } => {
            let subject = subject.domain();
            let admission = context
                .validated_subject
                .as_ref()
                .ok_or(reject("subject admission is missing"))?;
            require(
                admission.connection == *connection && admission.subject == subject,
                "subject admission names different work or funding",
            )?;
            Operation::Grant(access::Operation::Create {
                id: ModelGrantId::new(format!("grant-{digest}")),
                definition: access::GrantDefinition {
                    connection: connection.clone(),
                    subject,
                    policy: policy.domain(),
                    audiences: audiences.clone(),
                    caps: caps.domain(),
                },
                subject_admission: admission.evidence.clone(),
            })
        }
        Action::SetCaps { grant, caps } => Operation::Grant(access::Operation::SetCaps {
            id: grant.clone(),
            caps: caps.domain(),
        }),
        Action::SuspendGrant(value) => Operation::Grant(access::Operation::Suspend {
            id: value.grant.clone(),
        }),
        Action::ResumeGrant(value) => {
            let grant = state
                .grants
                .get(&value.grant)
                .ok_or(reject("unknown model grant"))?;
            let admission = context
                .validated_subject
                .as_ref()
                .ok_or(reject("subject admission is missing"))?;
            require(
                admission.connection == grant.definition.connection
                    && admission.subject == grant.definition.subject,
                "subject admission names different work or funding",
            )?;
            Operation::Grant(access::Operation::Resume {
                id: value.grant.clone(),
                subject_admission: admission.evidence.clone(),
            })
        }
        Action::RevokeGrant(value) => Operation::Grant(access::Operation::Revoke {
            id: value.grant.clone(),
        }),
    };
    Ok(Command {
        binding: context.binding.clone(),
        actor: context.actor.clone(),
        capability: match request.permission() {
            Permission::ManageConnections => Capability::ManageConnections,
            Permission::ManageGrants => Capability::ManageGrants,
        },
        basis: Basis::Metadata(request.0.expected_revision.0),
        now: context.now,
        operation,
    })
}

/// Call only on the selected credential authority's store, after authenticating
/// the current actor and human approval. No local/project metadata mirror is
/// written. The return is internal state; use a secret-free typed projection for
/// HTTP, never serialize custody handles or the materialized command back out.
pub fn admit_metadata(
    store: &mut Store,
    context: &ManagementContext,
    request: &MetadataRequest,
) -> Result<MaterializedAdmission<State>, AdmitError> {
    let intent = BoundIntent {
        binding: &context.binding,
        actor: &context.actor,
        approval: &context.approval.evidence,
        request,
    };
    store.admit_request::<ModelConnection, _>(
        &store_scope(&context.binding.organization),
        &request.store_key(),
        &intent,
        |state| authorize(state, context, request),
        |state| materialize(state, context, request),
    )
}

/// Recover whether this exact authority/actor/approval/request intent was
/// durably applied or durably rejected. Callers must still authenticate the
/// current actor before disclosing either result.
pub fn metadata_admission_status(
    store: &Store,
    context: &ManagementContext,
    request: &MetadataRequest,
) -> Result<Option<RequestAdmissionStatus>, AdmitError> {
    let intent = BoundIntent {
        binding: &context.binding,
        actor: &context.actor,
        approval: &context.approval.evidence,
        request,
    };
    store.request_admission_status::<ModelConnection, _>(
        &store_scope(&context.binding.organization),
        &request.store_key(),
        &intent,
    )
}

#[cfg(test)]
mod tests;
