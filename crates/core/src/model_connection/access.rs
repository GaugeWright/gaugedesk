//! Subject grants and exact, current execution admission for ADR 0162.
//! These are pure inputs/facts. The hosted shell must authenticate evidence;
//! none of these structures is a public request-body trust shortcut.

use std::collections::{BTreeMap, BTreeSet};

use super::{connection, require, ExecutionClass, ModelPolicy, ProviderBinding, State};
use crate::ids::{
    AuthorityId, CredentialVersionId, HomeId, ModelConnectionId, ModelGrantId, ObservationId,
    ProjectId,
};
use crate::Rejection;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Project {
    pub authority: AuthorityId,
    pub id: ProjectId,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Subject {
    Member(AuthorityId),
    Project(Project),
}

/// Stable across grant recreation and a connection's explicit reconnection
/// lineage. Model, grant id, rate, credential version and cap are NOT this key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct BudgetKey {
    pub connection_family: ModelConnectionId,
    pub subject: Subject,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalClass {
    Member,
    ExternalParticipant,
    Service,
    PublicSession,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Initiator {
    Member(AuthorityId),
    ExternalParticipant(AuthorityId),
    Service(AuthorityId),
    PublicSession { deployment: String, session: String },
}

impl Initiator {
    pub fn class(&self) -> PrincipalClass {
        match self {
            Self::Member(_) => PrincipalClass::Member,
            Self::ExternalParticipant(_) => PrincipalClass::ExternalParticipant,
            Self::Service(_) => PrincipalClass::Service,
            Self::PublicSession { .. } => PrincipalClass::PublicSession,
        }
    }
}

/// A syntactically parsed currency code. Actual supported rates/currencies are
/// admitted by the provider adapter, not inferred from this code.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Currency(String);

impl TryFrom<String> for Currency {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            Ok(Self(value))
        } else {
            Err("currency must be a three-letter uppercase code")
        }
    }
}

impl From<Currency> for String {
    fn from(value: Currency) -> Self {
        value.0
    }
}

impl Currency {
    pub fn code(&self) -> &str {
        &self.0
    }
}

/// Fixed-point millionths of the named currency, NOT processor minor units.
/// API projections must carry large exact amounts as strings, never JS floats.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Money {
    pub currency: Currency,
    pub micros: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Caps {
    /// None = uncapped in this dimension. Some(0) = no allowance.
    pub tokens: Option<u64>,
    pub money: Option<Money>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GrantStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrantDefinition {
    pub connection: ModelConnectionId,
    pub subject: Subject,
    pub policy: ModelPolicy,
    pub audiences: BTreeSet<PrincipalClass>,
    pub caps: Caps,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Grant {
    pub definition: GrantDefinition,
    pub budget: BudgetKey,
    pub revision: u64,
    pub status: GrantStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Operation {
    SetCaps {
        id: ModelGrantId,
        caps: Caps,
    },
    Create {
        id: ModelGrantId,
        definition: GrantDefinition,
        /// Current subject/funding admission, materialized by the shell.
        /// A project grant does not create membership or payload access.
        subject_admission: ObservationId,
    },
    Edit {
        id: ModelGrantId,
        policy: ModelPolicy,
        audiences: BTreeSet<PrincipalClass>,
        caps: Caps,
    },
    Suspend {
        id: ModelGrantId,
    },
    Resume {
        id: ModelGrantId,
        subject_admission: ObservationId,
    },
    Revoke {
        id: ModelGrantId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Change {
    CapsChanged {
        id: ModelGrantId,
        caps: Caps,
    },
    Created {
        id: ModelGrantId,
        grant: Grant,
        subject_admission: ObservationId,
    },
    Edited {
        id: ModelGrantId,
        policy: ModelPolicy,
        audiences: BTreeSet<PrincipalClass>,
        caps: Caps,
    },
    Suspended {
        id: ModelGrantId,
    },
    Resumed {
        id: ModelGrantId,
        subject_admission: ObservationId,
    },
    Revoked {
        id: ModelGrantId,
    },
}

fn valid_definition(state: &State, definition: &GrantDefinition) -> Result<(), Rejection> {
    let current = connection(state, &definition.connection)?;
    require(current.mutable(), "cannot grant a terminal connection")?;
    require(
        !definition.policy.models.is_empty()
            && definition
                .policy
                .models
                .is_subset(&current.definition.policy.models)
            && !definition.policy.execution_classes.is_empty()
            && definition
                .policy
                .execution_classes
                .is_subset(&current.definition.policy.execution_classes),
        "grant models or execution classes are not approved",
    )?;
    require(
        !definition.audiences.is_empty(),
        "grant requires an admitted audience",
    )?;
    if matches!(definition.subject, Subject::Member(_)) {
        require(
            definition.audiences == [PrincipalClass::Member].into()
                && !definition
                    .policy
                    .execution_classes
                    .contains(&ExecutionClass::PublicDirect),
            "a member grant cannot fund another principal or public deployment",
        )?;
    }
    Ok(())
}

pub(super) fn decide(state: &State, operation: Operation) -> Result<Change, Rejection> {
    match operation {
        Operation::SetCaps { id, caps } => {
            let grant = grant(state, &id)?;
            require(grant.status != GrantStatus::Revoked, "grant is terminal")?;
            require(
                connection(state, &grant.definition.connection)?.mutable(),
                "connection is terminal",
            )?;
            require(
                grant.revision.checked_add(1).is_some(),
                "grant revision exhausted",
            )?;
            // Changing a cap neither changes nor revalidates the grant's model
            // selection. Current connection policy still intersects at use.
            Ok(Change::CapsChanged { id, caps })
        }
        Operation::Create {
            id,
            definition,
            subject_admission,
        } => {
            require(
                !state.grants.contains_key(&id),
                "grant identity already exists",
            )?;
            valid_definition(state, &definition)?;
            let budget = BudgetKey {
                connection_family: connection(state, &definition.connection)?
                    .budget_family
                    .clone(),
                subject: definition.subject.clone(),
            };
            Ok(Change::Created {
                id,
                grant: Grant {
                    definition,
                    budget,
                    revision: 1,
                    status: GrantStatus::Active,
                },
                subject_admission,
            })
        }
        Operation::Edit {
            id,
            policy,
            audiences,
            caps,
        } => {
            let grant = grant(state, &id)?;
            require(grant.status != GrantStatus::Revoked, "grant is terminal")?;
            require(
                grant.revision.checked_add(1).is_some(),
                "grant revision exhausted",
            )?;
            let candidate = GrantDefinition {
                policy: policy.clone(),
                audiences: audiences.clone(),
                caps: caps.clone(),
                ..grant.definition.clone()
            };
            valid_definition(state, &candidate)?;
            Ok(Change::Edited {
                id,
                policy,
                audiences,
                caps,
            })
        }
        Operation::Suspend { id } => {
            let grant = grant(state, &id)?;
            require(grant.status == GrantStatus::Active, "grant is not active")?;
            require(
                grant.revision.checked_add(1).is_some(),
                "grant revision exhausted",
            )?;
            Ok(Change::Suspended { id })
        }
        Operation::Resume {
            id,
            subject_admission,
        } => {
            let grant = grant(state, &id)?;
            require(
                grant.status == GrantStatus::Suspended,
                "grant is not suspended",
            )?;
            require(
                grant.revision.checked_add(1).is_some(),
                "grant revision exhausted",
            )?;
            valid_definition(state, &grant.definition)?;
            Ok(Change::Resumed {
                id,
                subject_admission,
            })
        }
        Operation::Revoke { id } => {
            let grant = grant(state, &id)?;
            require(
                grant.status != GrantStatus::Revoked,
                "grant is already revoked",
            )?;
            require(
                grant.revision.checked_add(1).is_some(),
                "grant revision exhausted",
            )?;
            Ok(Change::Revoked { id })
        }
    }
}

fn grant<'a>(state: &'a State, id: &ModelGrantId) -> Result<&'a Grant, Rejection> {
    state.grants.get(id).ok_or(Rejection {
        reason: "unknown model grant",
    })
}

pub(super) fn evolve(state: &mut State, change: Change) {
    let (id, status) = match change {
        Change::CapsChanged { id, caps } => {
            let grant = state.grants.get_mut(&id).expect("admitted grant");
            grant.definition.caps = caps;
            grant.revision += 1;
            return;
        }
        Change::Created { id, grant, .. } => {
            state.grants.insert(id, grant);
            return;
        }
        Change::Edited {
            id,
            policy,
            audiences,
            caps,
        } => {
            let grant = state.grants.get_mut(&id).expect("admitted grant");
            grant.definition.policy = policy;
            grant.definition.audiences = audiences;
            grant.definition.caps = caps;
            grant.revision += 1;
            return;
        }
        Change::Suspended { id } => (id, GrantStatus::Suspended),
        Change::Resumed { id, .. } => (id, GrantStatus::Active),
        Change::Revoked { id } => (id, GrantStatus::Revoked),
    };
    let grant = state.grants.get_mut(&id).expect("admitted grant");
    grant.status = status;
    grant.revision += 1;
}

/// Exact, secret-free facts for one actual provider request. Work and actor
/// identity come from authenticated admission, not user-controlled labels.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Invocation {
    pub connection: ModelConnectionId,
    pub version: CredentialVersionId,
    pub provider: ProviderBinding,
    pub model: String,
    pub class: ExecutionClass,
    pub initiator: Initiator,
    pub project: Option<Project>,
    pub home: Option<HomeId>,
    pub work: ObservationId,
    pub final_fetch: AuthorityId,
    pub request_digest: [u8; 32],
}

/// Current observations authenticated/materialized by the shell. This must not
/// be read directly from a caller's body. In particular, the observed invocation
/// retains the actual initiating member/project; the caller cannot omit them.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ExecutionEvidence {
    pub observed: Invocation,
    pub current_identity_and_work: bool,
    pub funding_admitted: bool,
    pub private_plaintext_admitted: bool,
    pub public_deployment_and_budget_admitted: bool,
    pub observation: ObservationId,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApplicableGrant {
    pub id: ModelGrantId,
    pub revision: u64,
    pub budget: BudgetKey,
    pub caps: Caps,
}

/// One connection and the models an authenticated organization member may
/// choose for private work after the shell has independently admitted the
/// member and, when present, the exact project. This is discovery only: it
/// neither reserves allowance nor authorizes dispatch, and every invocation
/// must still pass [`applicable`] with fresh work, plaintext-recipient, grant,
/// version and cap evidence.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrivateSelectionOption {
    pub connection: ModelConnectionId,
    pub models: BTreeSet<String>,
}

/// Project Model access may present only current choices actually contributed
/// by an active member or exact-project grant. The organization connection's
/// current policy is intersected again so a narrowed connection cannot leave a
/// stale model in the picker. Caps deliberately do not hide an otherwise valid
/// selection: their remaining allowance depends on the later request bound and
/// is enforced atomically at reservation time.
pub fn private_selection_options(
    state: &State,
    actor: &AuthorityId,
    project: Option<&Project>,
) -> Vec<PrivateSelectionOption> {
    state
        .connections
        .iter()
        .filter_map(|(connection_id, connection)| {
            connection.active_version()?;
            if !connection
                .definition
                .policy
                .execution_classes
                .contains(&ExecutionClass::PrivateBroker)
            {
                return None;
            }
            let models = state
                .grants
                .values()
                .filter(|grant| {
                    grant.status == GrantStatus::Active
                        && grant.definition.connection == *connection_id
                        && grant
                            .definition
                            .policy
                            .execution_classes
                            .contains(&ExecutionClass::PrivateBroker)
                        && grant.definition.audiences.contains(&PrincipalClass::Member)
                        && match &grant.definition.subject {
                            Subject::Member(member) => member == actor,
                            Subject::Project(subject) => project == Some(subject),
                        }
                })
                .flat_map(|grant| grant.definition.policy.models.iter())
                .filter(|model| connection.definition.policy.models.contains(*model))
                .cloned()
                .collect::<BTreeSet<_>>();
            (!models.is_empty()).then(|| PrivateSelectionOption {
                connection: connection_id.clone(),
                models,
            })
        })
        .collect()
}

/// Authorize via at least one grant, but apply ALL active matching subject
/// restrictions. Selecting a model/class through a project grant cannot escape
/// the same member's connection budget. Each stable budget is charged once.
pub(super) fn applicable(
    state: &State,
    invocation: &Invocation,
    evidence: &ExecutionEvidence,
    actor: &AuthorityId,
) -> Result<Vec<ApplicableGrant>, Rejection> {
    require(&invocation.final_fetch == actor, "wrong final-fetch actor")?;
    require(
        evidence.observed == *invocation
            && evidence.current_identity_and_work
            && evidence.funding_admitted,
        "current identity, work or funding admission is missing or mismatched",
    )?;
    match invocation.class {
        ExecutionClass::PrivateBroker => require(
            evidence.private_plaintext_admitted
                && !matches!(invocation.initiator, Initiator::PublicSession { .. })
                && (invocation.project.is_none() || invocation.home.is_some()),
            "private broker is not an admitted plaintext recipient",
        )?,
        ExecutionClass::PublicDirect => require(
            evidence.public_deployment_and_budget_admitted
                && invocation.project.is_some()
                && invocation.home.is_none()
                && matches!(invocation.initiator, Initiator::PublicSession { .. }),
            "public use requires owner-admitted project deployment and budget",
        )?,
    }
    let current = connection(state, &invocation.connection)?;
    require(
        current.active_version() == Some(&invocation.version)
            && current.definition.provider == invocation.provider
            && current.definition.policy.models.contains(&invocation.model)
            && current
                .definition
                .policy
                .execution_classes
                .contains(&invocation.class),
        "connection, version, provider, model or execution class is not current",
    )?;
    let grants: Vec<_> = state.grants.iter().filter(|(_, grant)| {
        grant.status == GrantStatus::Active && grant.definition.connection == invocation.connection
            && match &grant.definition.subject {
                Subject::Member(member) => matches!(&invocation.initiator, Initiator::Member(actual) if actual == member),
                Subject::Project(project) => invocation.project.as_ref() == Some(project),
            }
    }).collect();
    require(
        grants.iter().any(|(_, grant)| {
            grant.definition.policy.models.contains(&invocation.model)
                && grant
                    .definition
                    .policy
                    .execution_classes
                    .contains(&invocation.class)
                && grant
                    .definition
                    .audiences
                    .contains(&invocation.initiator.class())
                && (invocation.class != ExecutionClass::PublicDirect
                    || matches!(grant.definition.subject, Subject::Project(_)))
        }),
        "no current grant authorizes this invocation",
    )?;
    Ok(grants
        .into_iter()
        .map(|(id, grant)| ApplicableGrant {
            id: id.clone(),
            revision: grant.revision,
            budget: grant.budget.clone(),
            caps: grant.definition.caps.clone(),
        })
        .collect())
}

pub(super) fn budgets(grants: &[ApplicableGrant]) -> BTreeMap<BudgetKey, Vec<Caps>> {
    let mut result: BTreeMap<BudgetKey, Vec<Caps>> = BTreeMap::new();
    for grant in grants {
        result
            .entry(grant.budget.clone())
            .or_default()
            .push(grant.caps.clone());
    }
    result
}
