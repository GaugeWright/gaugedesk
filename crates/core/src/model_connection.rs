//! Organization credentials, subject grants and spend (GAUGEAPP-6, ADR 0162).
//!
//! This pure reducer owns connection, grant and provider-attempt transitions. The
//! dedicated custody service authenticates roles and observations before
//! materializing commands. Neither a command role nor an opaque handle is a
//! network credential. A dispatch fact binds one admitted attempt; only the
//! trusted final-fetch adapter may consume it. Replaying a receipt must never
//! trigger another provider call. This module neither resolves keys nor fetches.
//!
//! All events carry the selected authority, organization and environment.
//! Admit the whole batch in that organization's single ordered transaction.
//! Use exact-input idempotency at the shell, not a mutex or client-side state.
//! Secret intake and KMS I/O stay outside the log. Rejected/stale intake must
//! erase any unadmitted material; admitted cleanup obligations survive replay.

use std::collections::{BTreeMap, BTreeSet};

use crate::ids::{
    AuthorityId, CredentialVersionId, ModelAttemptId, ModelConnectionId, ModelGrantId,
    ObservationId, ScopeId, SecretHandleId,
};
use crate::{Lifecycle, Rejection};

pub mod access;
pub mod spend;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorityBinding {
    pub authority: AuthorityId,
    pub organization: ScopeId,
    /// Parsed by the host; production custody must never fall back to dev KMS.
    pub environment: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationKind {
    ApiKey,
    /// Only a provider-supported organization/service-account flow.
    OrganizationOauth,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionClass {
    PrivateBroker,
    PublicDirect,
}

/// Parsed, canonical endpoint and provider, immutable for this connection.
/// A secret verification observation must match the entire binding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProviderBinding {
    pub provider: String,
    pub endpoint: String,
    pub authentication: AuthenticationKind,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModelPolicy {
    pub models: BTreeSet<String>,
    pub execution_classes: BTreeSet<ExecutionClass>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConnectionDefinition {
    pub name: String,
    pub provider: ProviderBinding,
    pub policy: ModelPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
    Erased,
}

/// What custody actually tested. A catalog read is not an inference call,
/// model entitlement, credit check, or permission to dispatch. Provider adapters
/// own the protocol; this closed vocabulary keeps the resulting claim precise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationCheck {
    ModelCatalogRead,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub check: VerificationCheck,
    /// Authority observation time, not a browser-supplied timestamp.
    pub observed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionPhase {
    AwaitingSecret,
    Sealed,
    Verified { evidence: ObservationId },
    Activated { evidence: ObservationId },
    Failed { evidence: ObservationId },
    Cancelled,
    Expired,
}

impl VersionPhase {
    fn open(&self) -> bool {
        matches!(
            self,
            Self::AwaitingSecret | Self::Sealed | Self::Verified { .. }
        )
    }
}

/// No key bytes, wrapped data key, refresh token or secret-derived fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Material {
    /// No seal receipt, not proof that custody contains no material. A process
    /// may have crashed between writing custody and admitting that receipt.
    Unobserved,
    Held {
        handle: SecretHandleId,
    },
    ErasureRequired {
        handle: Option<SecretHandleId>,
    },
    Erased {
        evidence: ObservationId,
    },
}

impl Material {
    fn require_erasure(&mut self) {
        match self {
            Self::Unobserved => *self = Self::ErasureRequired { handle: None },
            Self::Held { handle } => {
                *self = Self::ErasureRequired {
                    handle: Some(handle.clone()),
                };
            }
            Self::ErasureRequired { .. } | Self::Erased { .. } => {}
        }
    }

    fn gone(&self) -> bool {
        matches!(self, Self::Erased { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Version {
    pub expires_at: u64,
    pub phase: VersionPhase,
    pub material: Material,
    /// Older events did not identify the check. Replay preserves that absence;
    /// it must not manufacture evidence or permit a new activation.
    #[serde(default)]
    pub verification: Option<Verification>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Connection {
    pub definition: ConnectionDefinition,
    /// Explicit reconnection lineage preserves consumed subject allowances.
    pub budget_family: ModelConnectionId,
    pub status: ConnectionStatus,
    pub versions: BTreeMap<CredentialVersionId, Version>,
    pub current_version: Option<CredentialVersionId>,
    /// A request was admitted. Only `status == Erased` confirms completion.
    pub erasure_requested: bool,
}

impl Connection {
    /// Credential standing only, NEVER permission to resolve or execute it.
    pub fn active_version(&self) -> Option<&CredentialVersionId> {
        if self.status != ConnectionStatus::Active || self.erasure_requested {
            return None;
        }
        let id = self.current_version.as_ref()?;
        let version = self.versions.get(id)?;
        (matches!(version.phase, VersionPhase::Activated { .. })
            && matches!(version.material, Material::Held { .. }))
        .then_some(id)
    }

    fn mutable(&self) -> bool {
        !matches!(
            self.status,
            ConnectionStatus::Revoked | ConnectionStatus::Erased
        )
    }

    fn material_gone(&self) -> bool {
        self.versions
            .values()
            .all(|version| version.material.gone())
    }

    fn revoke(&mut self) {
        self.status = ConnectionStatus::Revoked;
        for version in self.versions.values_mut() {
            if version.phase.open() {
                version.phase = VersionPhase::Cancelled;
                version.material.require_erasure();
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModelSelection {
    pub connection: ModelConnectionId,
    pub model: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub binding: Option<AuthorityBinding>,
    /// Management revision, not the physical stream position. Provider traffic
    /// does not invalidate every open settings form. The store orders ALL events.
    pub revision: u64,
    pub last_at: u64,
    pub connections: BTreeMap<ModelConnectionId, Connection>,
    pub default: Option<ModelSelection>,
    /// A destroyed handle is never recycled into a different version.
    pub used_handles: BTreeSet<SecretHandleId>,
    pub grants: BTreeMap<ModelGrantId, access::Grant>,
    pub attempts: BTreeMap<ModelAttemptId, spend::Attempt>,
    pub failed_enforcements: BTreeSet<ObservationId>,
}

impl State {
    /// Metadata standing only; subject grants, execution class, data policy and
    /// spend admission remain independent checks. No silent funding fallback.
    pub fn available_default(&self) -> Option<&ModelSelection> {
        let selection = self.default.as_ref()?;
        let connection = self.connections.get(&selection.connection)?;
        connection.active_version()?;
        (connection
            .definition
            .policy
            .models
            .contains(&selection.model)
            && !connection.definition.policy.execution_classes.is_empty())
        .then_some(selection)
    }
}

/// Supplied ONLY by the authenticating shell, never deserialized from a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Capability {
    ManageConnections,
    ManageGrants,
    /// Trusted final fetch WITH independently authenticated work/data bases.
    InvokeProvider,
    /// Trusted final-fetch usage evidence, even after membership is revoked.
    ObserveUsage,
    /// Operated bounds repair evidence, not an administrator allowance reset.
    ReconcileBounds,
    /// Authenticated intake service AND the submitter's current management
    /// capability. A service token by itself does not permit secret submission.
    SealCandidate,
    /// Provider verification evidence authenticated and bound by custody.
    VerifyCandidate,
    ObserveDeadline,
    /// Actual destruction evidence from the erasure-aware custody service.
    ConfirmErasure,
    OrganizationClosure,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Basis {
    Metadata(u64),
    Dispatch {
        metadata: u64,
        attempt: ModelAttemptId,
        revision: u64,
    },
    Attempt {
        id: ModelAttemptId,
        revision: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Command {
    pub binding: AuthorityBinding,
    pub actor: AuthorityId,
    pub capability: Capability,
    pub basis: Basis,
    pub now: u64,
    pub operation: Operation,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Operation {
    Grant(access::Operation),
    Spend(spend::Operation),
    BeginIntake {
        connection: ModelConnectionId,
        definition: ConnectionDefinition,
        reconnects: Option<ModelConnectionId>,
        version: CredentialVersionId,
        expires_at: u64,
    },
    BeginReplacement {
        connection: ModelConnectionId,
        version: CredentialVersionId,
        expires_at: u64,
    },
    RecordSealed {
        connection: ModelConnectionId,
        version: CredentialVersionId,
        handle: SecretHandleId,
    },
    RecordVerification {
        connection: ModelConnectionId,
        version: CredentialVersionId,
        provider: ProviderBinding,
        handle: SecretHandleId,
        evidence: ObservationId,
        check: VerificationCheck,
        passed: bool,
    },
    Activate {
        connection: ModelConnectionId,
        version: CredentialVersionId,
    },
    CancelCandidate {
        connection: ModelConnectionId,
        version: CredentialVersionId,
    },
    ExpireCandidate {
        connection: ModelConnectionId,
        version: CredentialVersionId,
    },
    Rename {
        connection: ModelConnectionId,
        name: String,
    },
    SetModelPolicy {
        connection: ModelConnectionId,
        policy: ModelPolicy,
    },
    SetDefault {
        selection: Option<ModelSelection>,
    },
    Suspend {
        connection: ModelConnectionId,
    },
    Resume {
        connection: ModelConnectionId,
    },
    Revoke {
        connection: ModelConnectionId,
    },
    RequestErasure {
        connection: ModelConnectionId,
    },
    RecordMaterialErased {
        connection: ModelConnectionId,
        version: CredentialVersionId,
        /// Echo the known handle, if any. Evidence must cover the ENTIRE
        /// authority/org/environment/connection/version custody namespace,
        /// fence late writes and purge unadmitted material, not just this handle.
        expected_handle: Option<SecretHandleId>,
        evidence: ObservationId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Event {
    pub binding: AuthorityBinding,
    pub actor: AuthorityId,
    pub at: u64,
    pub change: Change,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Change {
    Grant(access::Change),
    Spend(spend::Change),
    IntakeBegun {
        connection: ModelConnectionId,
        definition: ConnectionDefinition,
        #[serde(default)]
        reconnects: Option<ModelConnectionId>,
        version: CredentialVersionId,
        expires_at: u64,
    },
    ReplacementBegun {
        connection: ModelConnectionId,
        version: CredentialVersionId,
        expires_at: u64,
    },
    CandidateSealed {
        connection: ModelConnectionId,
        version: CredentialVersionId,
        handle: SecretHandleId,
    },
    CandidateVerified {
        connection: ModelConnectionId,
        version: CredentialVersionId,
        evidence: ObservationId,
        #[serde(default)]
        check: Option<VerificationCheck>,
    },
    CandidateFailed {
        connection: ModelConnectionId,
        version: CredentialVersionId,
        evidence: ObservationId,
        #[serde(default)]
        check: Option<VerificationCheck>,
    },
    VersionActivated {
        connection: ModelConnectionId,
        version: CredentialVersionId,
        evidence: ObservationId,
    },
    CandidateCancelled {
        connection: ModelConnectionId,
        version: CredentialVersionId,
    },
    CandidateExpired {
        connection: ModelConnectionId,
        version: CredentialVersionId,
    },
    ConnectionRenamed {
        connection: ModelConnectionId,
        name: String,
    },
    ModelPolicyChanged {
        connection: ModelConnectionId,
        policy: ModelPolicy,
    },
    DefaultChanged {
        selection: Option<ModelSelection>,
    },
    ConnectionSuspended {
        connection: ModelConnectionId,
    },
    ConnectionResumed {
        connection: ModelConnectionId,
    },
    ConnectionRevoked {
        connection: ModelConnectionId,
    },
    ErasureRequested {
        connection: ModelConnectionId,
    },
    MaterialErased {
        connection: ModelConnectionId,
        version: CredentialVersionId,
        evidence: ObservationId,
    },
    ConnectionErased {
        connection: ModelConnectionId,
    },
}

fn require(condition: bool, reason: &'static str) -> Result<(), Rejection> {
    if condition {
        Ok(())
    } else {
        Err(Rejection { reason })
    }
}

fn connection<'a>(state: &'a State, id: &ModelConnectionId) -> Result<&'a Connection, Rejection> {
    state.connections.get(id).ok_or(Rejection {
        reason: "unknown connection",
    })
}

fn candidate<'a>(
    connection: &'a Connection,
    id: &CredentialVersionId,
) -> Result<&'a Version, Rejection> {
    connection.versions.get(id).ok_or(Rejection {
        reason: "unknown credential version",
    })
}

pub fn decide(state: &State, command: Command) -> Result<Vec<Event>, Rejection> {
    use Capability::*;
    use Operation::*;
    let Command {
        binding,
        actor,
        capability,
        basis,
        now,
        operation,
    } = command;
    require(
        state
            .binding
            .as_ref()
            .is_none_or(|current| current == &binding),
        "wrong connection authority, organization or environment",
    )?;
    match &operation {
        Spend(operation) => spend::check_basis(state, operation, &basis)?,
        _ => require(
            basis == Basis::Metadata(state.revision),
            "stale connection authority basis",
        )?,
    }
    require(
        now > 0 && now >= state.last_at,
        "invalid or stale observation time",
    )?;
    let required = match &operation {
        Grant(_) => ManageGrants,
        Spend(operation) => operation.capability(),
        RecordSealed { .. } => SealCandidate,
        RecordVerification { .. } => VerifyCandidate,
        ExpireCandidate { .. } => ObserveDeadline,
        RecordMaterialErased { .. } => ConfirmErasure,
        _ => ManageConnections,
    };
    require(
        capability == required
            || capability == OrganizationClosure
                && matches!(
                    operation,
                    Revoke { .. } | RequestErasure { .. } | Grant(access::Operation::Revoke { .. })
                ),
        "operation not permitted by authenticated capability",
    )?;
    let mut changes = Vec::new();
    match operation {
        Grant(operation) => changes.push(Change::Grant(access::decide(state, operation)?)),
        Spend(operation) => changes.extend(
            spend::decide(state, operation, &actor, now)?
                .into_iter()
                .map(Change::Spend),
        ),
        BeginIntake {
            connection: id,
            definition,
            reconnects,
            version,
            expires_at,
        } => {
            require(
                !state.connections.contains_key(&id),
                "connection identity already exists",
            )?;
            require(expires_at > now, "candidate deadline must be in the future")?;
            if let Some(previous) = &reconnects {
                let previous = connection(state, previous)?;
                require(
                    !previous.mutable() && previous.definition.provider == definition.provider,
                    "reconnection requires a terminal predecessor with the same provider binding",
                )?;
            }
            changes.push(Change::IntakeBegun {
                connection: id,
                definition,
                reconnects,
                version,
                expires_at,
            });
        }
        BeginReplacement {
            connection: id,
            version,
            expires_at,
        } => {
            let current = connection(state, &id)?;
            require(current.mutable(), "connection is terminal")?;
            require(expires_at > now, "candidate deadline must be in the future")?;
            require(
                !current.versions.contains_key(&version),
                "credential version identity already exists",
            )?;
            require(
                !current.versions.values().any(|value| value.phase.open()),
                "finish or cancel the existing candidate",
            )?;
            changes.push(Change::ReplacementBegun {
                connection: id,
                version,
                expires_at,
            });
        }
        RecordSealed {
            connection: id,
            version,
            handle,
        } => {
            let current = connection(state, &id)?;
            let item = candidate(current, &version)?;
            require(
                current.mutable() && now < item.expires_at,
                "candidate is no longer open",
            )?;
            require(
                item.phase == VersionPhase::AwaitingSecret && item.material == Material::Unobserved,
                "candidate already received material",
            )?;
            require(
                !state.used_handles.contains(&handle),
                "secret handle already belongs to another version",
            )?;
            changes.push(Change::CandidateSealed {
                connection: id,
                version,
                handle,
            });
        }
        RecordVerification {
            connection: id,
            version,
            provider,
            handle,
            evidence,
            check,
            passed,
        } => {
            let current = connection(state, &id)?;
            let item = candidate(current, &version)?;
            require(
                current.mutable() && now < item.expires_at,
                "candidate is no longer open",
            )?;
            require(
                current.definition.provider == provider,
                "verification targets a different provider binding",
            )?;
            require(
                item.phase == VersionPhase::Sealed && item.material == (Material::Held { handle }),
                "verification targets different or unsealed material",
            )?;
            changes.push(if passed {
                Change::CandidateVerified {
                    connection: id,
                    version,
                    evidence,
                    check: Some(check),
                }
            } else {
                Change::CandidateFailed {
                    connection: id,
                    version,
                    evidence,
                    check: Some(check),
                }
            });
        }
        Activate {
            connection: id,
            version,
        } => {
            let current = connection(state, &id)?;
            let item = candidate(current, &version)?;
            require(
                current.mutable() && now < item.expires_at,
                "candidate is no longer activatable",
            )?;
            let VersionPhase::Verified { evidence } = &item.phase else {
                return Err(Rejection {
                    reason: "candidate has not passed verification",
                });
            };
            require(
                matches!(item.material, Material::Held { .. }),
                "verified material is unavailable",
            )?;
            require(
                item.verification.is_some(),
                "candidate verification does not identify the tested capability",
            )?;
            changes.push(Change::VersionActivated {
                connection: id,
                version,
                evidence: evidence.clone(),
            });
        }
        CancelCandidate {
            connection: id,
            version,
        } => {
            let item = candidate(connection(state, &id)?, &version)?;
            require(item.phase.open(), "candidate is already terminal")?;
            changes.push(Change::CandidateCancelled {
                connection: id,
                version,
            });
        }
        ExpireCandidate {
            connection: id,
            version,
        } => {
            let item = candidate(connection(state, &id)?, &version)?;
            require(
                item.phase.open() && now >= item.expires_at,
                "candidate has not expired or is terminal",
            )?;
            changes.push(Change::CandidateExpired {
                connection: id,
                version,
            });
        }
        Rename {
            connection: id,
            name,
        } => {
            require(connection(state, &id)?.mutable(), "connection is terminal")?;
            changes.push(Change::ConnectionRenamed {
                connection: id,
                name,
            });
        }
        SetModelPolicy {
            connection: id,
            policy,
        } => {
            require(connection(state, &id)?.mutable(), "connection is terminal")?;
            changes.push(Change::ModelPolicyChanged {
                connection: id,
                policy,
            });
        }
        SetDefault { selection } => {
            if let Some(value) = &selection {
                let current = connection(state, &value.connection)?;
                require(
                    current.active_version().is_some()
                        && current.definition.policy.models.contains(&value.model)
                        && !current.definition.policy.execution_classes.is_empty(),
                    "default is not an active approved model",
                )?;
            }
            changes.push(Change::DefaultChanged { selection });
        }
        Suspend { connection: id } => {
            require(
                connection(state, &id)?.status == ConnectionStatus::Active,
                "only active connections may be suspended",
            )?;
            changes.push(Change::ConnectionSuspended { connection: id });
        }
        Resume { connection: id } => {
            let current = connection(state, &id)?;
            require(
                current.status == ConnectionStatus::Suspended,
                "connection is not suspended",
            )?;
            let usable = current
                .current_version
                .as_ref()
                .and_then(|value| current.versions.get(value))
                .is_some_and(|value| {
                    matches!(value.phase, VersionPhase::Activated { .. })
                        && matches!(value.material, Material::Held { .. })
                });
            require(usable, "current credential is unavailable")?;
            changes.push(Change::ConnectionResumed { connection: id });
        }
        Revoke { connection: id } => {
            let current = connection(state, &id)?;
            require(current.mutable(), "connection is already terminal")?;
            changes.push(Change::ConnectionRevoked { connection: id });
        }
        RequestErasure { connection: id } => {
            let current = connection(state, &id)?;
            require(
                current.status != ConnectionStatus::Erased && !current.erasure_requested,
                "erasure is already requested or complete",
            )?;
            if current.mutable() {
                changes.push(Change::ConnectionRevoked {
                    connection: id.clone(),
                });
            }
            changes.push(Change::ErasureRequested {
                connection: id.clone(),
            });
            if current.material_gone() {
                changes.push(Change::ConnectionErased { connection: id });
            }
        }
        RecordMaterialErased {
            connection: id,
            version,
            expected_handle,
            evidence,
        } => {
            let current = connection(state, &id)?;
            let item = candidate(current, &version)?;
            require(
                item.material
                    == (Material::ErasureRequired {
                        handle: expected_handle,
                    }),
                "erasure does not match an outstanding cleanup obligation",
            )?;
            changes.push(Change::MaterialErased {
                connection: id.clone(),
                version: version.clone(),
                evidence,
            });
            if current.erasure_requested
                && current
                    .versions
                    .iter()
                    .all(|(key, value)| key == &version || value.material.gone())
            {
                changes.push(Change::ConnectionErased { connection: id });
            }
        }
    }
    require(
        state
            .revision
            .checked_add(
                changes
                    .iter()
                    .filter(|change| !matches!(change, Change::Spend(_)))
                    .count() as u64,
            )
            .is_some(),
        "connection authority revision exhausted",
    )?;
    Ok(changes
        .into_iter()
        .map(|change| Event {
            binding: binding.clone(),
            actor: actor.clone(),
            at: now,
            change,
        })
        .collect())
}

fn new_version(expires_at: u64) -> Version {
    Version {
        expires_at,
        phase: VersionPhase::AwaitingSecret,
        material: Material::Unobserved,
        verification: None,
    }
}

fn stored_connection<'a>(state: &'a mut State, id: &ModelConnectionId) -> &'a mut Connection {
    state
        .connections
        .get_mut(id)
        .expect("admitted event names an existing connection")
}

fn stored_version<'a>(
    state: &'a mut State,
    id: &ModelConnectionId,
    version: &CredentialVersionId,
) -> &'a mut Version {
    stored_connection(state, id)
        .versions
        .get_mut(version)
        .expect("admitted event names an existing version")
}

pub fn evolve(state: &State, event: Event) -> State {
    use Change::*;
    let mut next = state.clone();
    next.binding = Some(event.binding);
    if !matches!(event.change, Spend(_)) {
        next.revision += 1;
    }
    next.last_at = event.at;
    match event.change {
        Grant(change) => access::evolve(&mut next, change),
        Spend(change) => spend::evolve(&mut next, change),
        IntakeBegun {
            connection,
            definition,
            reconnects,
            version,
            expires_at,
        } => {
            let budget_family = reconnects
                .as_ref()
                .map(|id| next.connections[id].budget_family.clone())
                .unwrap_or_else(|| connection.clone());
            next.connections.insert(
                connection,
                Connection {
                    definition,
                    budget_family,
                    status: ConnectionStatus::Pending,
                    versions: [(version, new_version(expires_at))].into(),
                    current_version: None,
                    erasure_requested: false,
                },
            );
        }
        ReplacementBegun {
            connection,
            version,
            expires_at,
        } => {
            stored_connection(&mut next, &connection)
                .versions
                .insert(version, new_version(expires_at));
        }
        CandidateSealed {
            connection,
            version,
            handle,
        } => {
            next.used_handles.insert(handle.clone());
            let item = stored_version(&mut next, &connection, &version);
            item.phase = VersionPhase::Sealed;
            item.material = Material::Held { handle };
        }
        CandidateVerified {
            connection,
            version,
            evidence,
            check,
        } => {
            let item = stored_version(&mut next, &connection, &version);
            item.phase = VersionPhase::Verified { evidence };
            item.verification = check.map(|check| Verification {
                check,
                observed_at: event.at,
            });
        }
        CandidateFailed {
            connection,
            version,
            evidence,
            check,
        } => {
            let item = stored_version(&mut next, &connection, &version);
            item.phase = VersionPhase::Failed { evidence };
            item.verification = check.map(|check| Verification {
                check,
                observed_at: event.at,
            });
            item.material.require_erasure();
        }
        CandidateCancelled {
            connection,
            version,
        } => {
            let item = stored_version(&mut next, &connection, &version);
            item.phase = VersionPhase::Cancelled;
            item.material.require_erasure();
        }
        CandidateExpired {
            connection,
            version,
        } => {
            let item = stored_version(&mut next, &connection, &version);
            item.phase = VersionPhase::Expired;
            item.material.require_erasure();
        }
        VersionActivated {
            connection,
            version,
            evidence,
        } => {
            let current = stored_connection(&mut next, &connection);
            current
                .versions
                .get_mut(&version)
                .expect("admitted version")
                .phase = VersionPhase::Activated { evidence };
            current.current_version = Some(version);
            if current.status == ConnectionStatus::Pending {
                current.status = ConnectionStatus::Active;
            }
        }
        ConnectionRenamed { connection, name } => {
            stored_connection(&mut next, &connection).definition.name = name
        }
        ModelPolicyChanged { connection, policy } => {
            stored_connection(&mut next, &connection).definition.policy = policy
        }
        DefaultChanged { selection } => next.default = selection,
        ConnectionSuspended { connection } => {
            stored_connection(&mut next, &connection).status = ConnectionStatus::Suspended
        }
        ConnectionResumed { connection } => {
            stored_connection(&mut next, &connection).status = ConnectionStatus::Active
        }
        ConnectionRevoked { connection } => stored_connection(&mut next, &connection).revoke(),
        ErasureRequested { connection } => {
            let current = stored_connection(&mut next, &connection);
            current.erasure_requested = true;
            for version in current.versions.values_mut() {
                version.material.require_erasure();
            }
        }
        MaterialErased {
            connection,
            version,
            evidence,
        } => {
            stored_version(&mut next, &connection, &version).material =
                Material::Erased { evidence };
        }
        ConnectionErased { connection } => {
            stored_connection(&mut next, &connection).status = ConnectionStatus::Erased
        }
    }
    next
}

pub struct ModelConnection;

impl Lifecycle for ModelConnection {
    type State = State;
    type Command = Command;
    type Event = Event;
    const KIND: &'static str = "organization-model-connection.v1";

    fn decide(state: &State, command: Command) -> Result<Vec<Event>, Rejection> {
        decide(state, command)
    }

    fn evolve(state: &State, event: Event) -> State {
        evolve(state, event)
    }
}

#[cfg(test)]
mod tests;
