//! Secret-free wire projection of the selected credential authority's fold.
//! The hosting service authenticates read capability before calling `project`.
//! No connection object, custody handle, work digest, runtime observation or
//! provider body is serialized wholesale into a page, receipt or agent context.

use super::*;
use gaugedesk_core::model_connection::{
    spend, ConnectionStatus, Material, VerificationCheck, VersionPhase,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
struct ExactU128(u128);
impl TryFrom<String> for ExactU128 {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parsed = value.parse::<u128>().map_err(|_| "invalid exact total")?;
        if parsed.to_string() != value {
            return Err("noncanonical exact total");
        }
        Ok(Self(parsed))
    }
}
impl From<ExactU128> for String {
    fn from(value: ExactU128) -> Self {
        value.0.to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    NotConfigured,
    AuthorityUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "availability", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelProvidersPage {
    Available(Box<Snapshot>),
    Unavailable { reason: UnavailableReason },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    binding: Binding,
    management_revision: ExactU64,
    as_of: ExactU64,
    period: Period,
    connections: Vec<ConnectionRow>,
    grants: Vec<GrantRow>,
    #[serde(deserialize_with = "present_option")]
    default_model: Option<DefaultSelection>,
    setup: ModelProviderSetup,
}

/// Current operated admission choices, supplied by the authenticated service.
/// They are not connection state and are never written into the event stream.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProviderSetup {
    pub api_key_intake: bool,
    pub providers: Vec<ProviderOption>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderOption {
    pub provider: String,
    pub endpoint: String,
    pub authentication: AuthenticationKind,
    #[serde(deserialize_with = "present_option")]
    pub verification_check: Option<VerificationCheck>,
    policy: PolicyInput,
}
impl ProviderOption {
    pub fn new(provider: &ProviderBinding, allowed: &ModelPolicy) -> Self {
        Self {
            provider: provider.provider.clone(),
            endpoint: provider.endpoint.clone(),
            authentication: provider.authentication,
            verification_check: None,
            policy: policy(allowed),
        }
    }

    pub fn with_verification_check(mut self, check: Option<VerificationCheck>) -> Self {
        self.verification_check = check;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultSelection {
    #[serde(deserialize_with = "connection_id")]
    connection: ModelConnectionId,
    model: String,
    /// Model/connection standing only, not subject or dispatch permission.
    available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    #[serde(deserialize_with = "authority_id")]
    authority: AuthorityId,
    organization: String,
    environment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Period {
    year: ExactU64,
    month: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionRow {
    #[serde(deserialize_with = "connection_id")]
    id: ModelConnectionId,
    name: String,
    provider: String,
    endpoint: String,
    authentication: AuthenticationKind,
    status: ConnectionStatus,
    #[serde(deserialize_with = "present_option")]
    current_version: Option<CredentialVersionId>,
    erasure_requested: bool,
    overrun_pending: bool,
    policy: PolicyInput,
    versions: Vec<VersionRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CandidatePhase {
    AwaitingSecret,
    Sealed,
    Verified,
    Activated,
    Failed,
    Cancelled,
    Expired,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MaterialState {
    Unobserved,
    Held,
    ErasurePending,
    Erased,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionRow {
    #[serde(deserialize_with = "version_id")]
    id: CredentialVersionId,
    phase: CandidatePhase,
    material: MaterialState,
    expires_at: ExactU64,
    #[serde(deserialize_with = "present_option")]
    verification: Option<VerificationRow>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationRow {
    check: VerificationCheck,
    observed_at: ExactU64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GrantStatus {
    Active,
    Suspended,
    Revoked,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRow {
    #[serde(deserialize_with = "grant_id")]
    id: ModelGrantId,
    #[serde(deserialize_with = "connection_id")]
    connection: ModelConnectionId,
    subject: SubjectInput,
    revision: ExactU64,
    status: GrantStatus,
    policy: PolicyInput,
    audiences: BTreeSet<access::PrincipalClass>,
    caps: CapsInput,
    usage: PeriodUsage,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeriodUsage {
    measured: Totals,
    reserved: Totals,
    accounted_at_bound: Totals,
    unknown_outcomes: ExactU64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Totals {
    tokens: ExactU128,
    money: Vec<MoneyTotal>,
    unknown_money: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoneyTotal {
    currency: access::Currency,
    micros: ExactU128,
}

fn policy(value: &ModelPolicy) -> PolicyInput {
    PolicyInput {
        models: value.models.clone(),
        execution_classes: value.execution_classes.clone(),
    }
}
fn subject(value: &access::Subject) -> SubjectInput {
    match value {
        access::Subject::Member(id) => SubjectInput::Member { id: id.clone() },
        access::Subject::Project(project) => SubjectInput::Project {
            authority: project.authority.clone(),
            id: project.id.clone(),
        },
    }
}
fn caps(value: &access::Caps) -> CapsInput {
    CapsInput {
        tokens: value.tokens.map(ExactU64),
        money: value.money.as_ref().map(|money| MoneyInput {
            currency: money.currency.clone(),
            micros: ExactU64(money.micros),
        }),
    }
}
fn totals(value: spend::Totals) -> Totals {
    Totals {
        tokens: ExactU128(value.tokens),
        money: value
            .money
            .into_iter()
            .map(|(currency, micros)| MoneyTotal {
                currency,
                micros: ExactU128(micros),
            })
            .collect(),
        unknown_money: value.unknown_money,
    }
}

impl ModelProvidersPage {
    pub fn with_setup(mut self, setup: ModelProviderSetup) -> Self {
        if let Self::Available(snapshot) = &mut self {
            snapshot.setup = setup;
        }
        self
    }
    /// Mutation concurrency names authority + management revision, never usage
    /// freshness. Grant/version/policy changes invalidate it; traffic does not.
    pub fn resource_basis(&self) -> String {
        let value = match self {
            Self::Available(snapshot) => {
                serde_json::json!({"v":1,"binding":snapshot.binding,"revision":snapshot.management_revision,"setup":snapshot.setup})
            }
            Self::Unavailable { reason } => serde_json::json!({"v":1,"unavailable":reason}),
        };
        format!(
            "organization-model:v1:{}",
            hex::encode(Sha256::digest(
                serde_json::to_vec(&value).expect("closed model serializes")
            ))
        )
    }
    pub fn management_revision(&self) -> Option<u64> {
        match self {
            Self::Available(snapshot) => Some(snapshot.management_revision.0),
            Self::Unavailable { .. } => None,
        }
    }
    pub fn organization(&self) -> Option<&str> {
        match self {
            Self::Available(snapshot) => Some(&snapshot.binding.organization),
            Self::Unavailable { .. } => None,
        }
    }
    /// Whether the separately authoritative model-provider service still owns
    /// live state for this organization. Historical erased connections and
    /// revoked grants do not block tenant retirement; anything else must be
    /// resolved through its own lifecycle before the tenant authority goes
    /// away. `None` means the authority could not prove either state.
    pub fn has_organization_dependencies(&self) -> Option<bool> {
        match self {
            Self::Available(snapshot) => Some(
                snapshot
                    .connections
                    .iter()
                    .any(|connection| connection.status != ConnectionStatus::Erased)
                    || snapshot
                        .grants
                        .iter()
                        .any(|grant| grant.status != GrantStatus::Revoked),
            ),
            Self::Unavailable { .. } => None,
        }
    }
}

pub fn project(
    state: &State,
    binding: &AuthorityBinding,
    now: u64,
) -> Result<ModelProvidersPage, Rejection> {
    require(
        state
            .binding
            .as_ref()
            .is_none_or(|current| current == binding),
        "wrong model-provider authority binding",
    )?;
    require(
        now > 0 && now >= state.last_at,
        "model-provider observation is stale",
    )?;
    let month = spend::Month::at(now);
    let connections = state
        .connections
        .iter()
        .map(|(id, value)| ConnectionRow {
            id: id.clone(),
            name: value.definition.name.clone(),
            provider: value.definition.provider.provider.clone(),
            endpoint: value.definition.provider.endpoint.clone(),
            authentication: value.definition.provider.authentication,
            status: value.status,
            current_version: value.current_version.clone(),
            erasure_requested: value.erasure_requested,
            overrun_pending: spend::overrun_pending(state, &value.budget_family),
            policy: policy(&value.definition.policy),
            versions: value
                .versions
                .iter()
                .map(|(id, value)| VersionRow {
                    id: id.clone(),
                    expires_at: ExactU64(value.expires_at),
                    verification: value
                        .verification
                        .as_ref()
                        .map(|verification| VerificationRow {
                            check: verification.check,
                            observed_at: ExactU64(verification.observed_at),
                        }),
                    phase: match value.phase {
                        VersionPhase::AwaitingSecret => CandidatePhase::AwaitingSecret,
                        VersionPhase::Sealed => CandidatePhase::Sealed,
                        VersionPhase::Verified { .. } => CandidatePhase::Verified,
                        VersionPhase::Activated { .. } => CandidatePhase::Activated,
                        VersionPhase::Failed { .. } => CandidatePhase::Failed,
                        VersionPhase::Cancelled => CandidatePhase::Cancelled,
                        VersionPhase::Expired => CandidatePhase::Expired,
                    },
                    material: match value.material {
                        Material::Unobserved => MaterialState::Unobserved,
                        Material::Held { .. } => MaterialState::Held,
                        Material::ErasureRequired { .. } => MaterialState::ErasurePending,
                        Material::Erased { .. } => MaterialState::Erased,
                    },
                })
                .collect(),
        })
        .collect();
    let grants = state
        .grants
        .iter()
        .map(|(id, value)| {
            let usage = spend::period_usage(state, &value.budget, month)?;
            Ok(GrantRow {
                id: id.clone(),
                connection: value.definition.connection.clone(),
                subject: subject(&value.definition.subject),
                revision: ExactU64(value.revision),
                status: match value.status {
                    access::GrantStatus::Active => GrantStatus::Active,
                    access::GrantStatus::Suspended => GrantStatus::Suspended,
                    access::GrantStatus::Revoked => GrantStatus::Revoked,
                },
                policy: policy(&value.definition.policy),
                audiences: value.definition.audiences.clone(),
                caps: caps(&value.definition.caps),
                usage: PeriodUsage {
                    measured: totals(usage.measured),
                    reserved: totals(usage.reserved),
                    accounted_at_bound: totals(usage.accounted_at_bound),
                    unknown_outcomes: ExactU64(usage.unknown_outcomes),
                },
            })
        })
        .collect::<Result<Vec<_>, Rejection>>()?;
    Ok(ModelProvidersPage::Available(Box::new(Snapshot {
        binding: Binding {
            authority: binding.authority.clone(),
            organization: binding.organization.as_str().into(),
            environment: binding.environment.clone(),
        },
        management_revision: ExactU64(state.revision),
        as_of: ExactU64(now),
        period: Period {
            year: ExactU64(month.year),
            month: month.month,
        },
        connections,
        grants,
        default_model: state.default.as_ref().map(|value| DefaultSelection {
            connection: value.connection.clone(),
            model: value.model.clone(),
            available: state.available_default().is_some(),
        }),
        setup: ModelProviderSetup::default(),
    })))
}

#[cfg(test)]
mod tests;
