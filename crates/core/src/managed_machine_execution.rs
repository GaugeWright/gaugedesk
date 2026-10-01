//! Home-owned managed-Machine execution lifecycle (MACHINE-EXEC).
//!
//! This reducer is the executable counterpart of
//! `specs/models/managed-machine-execution.qnt` and
//! `specs/lifecycles/managed-machine-execution.md`. It owns durable command
//! admission, exact profile selection, fenced worker epochs, evidence intake,
//! cancellation, retry, and settlement. Runtime and Sandbox adapters are
//! imperative shells around this state machine; neither may invent another
//! lifecycle or become project authority.

use std::collections::BTreeSet;

use crate::{Lifecycle, Rejection};

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionProfile {
    DurableWorkflow,
    IsolatedWorkspace,
    DedicatedCompute,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCapability {
    Chat,
    Schedule,
    HttpEffect,
    Document,
    Workspace,
    Process,
    Build,
    Test,
    Docker,
    CustomNetwork,
    CustomKernel,
    StandingDaemon,
}

pub fn profile_capabilities(profile: ExecutionProfile) -> BTreeSet<ExecutionCapability> {
    use ExecutionCapability as C;
    match profile {
        ExecutionProfile::DurableWorkflow => [C::Chat, C::Schedule, C::HttpEffect, C::Document]
            .into_iter()
            .collect(),
        ExecutionProfile::IsolatedWorkspace => [C::Workspace, C::Process, C::Build, C::Test]
            .into_iter()
            .collect(),
        ExecutionProfile::DedicatedCompute => [
            C::Docker,
            C::CustomNetwork,
            C::CustomKernel,
            C::StandingDaemon,
        ]
        .into_iter()
        .collect(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ExecutionResourceBounds {
    pub max_vcpus: u8,
    pub max_memory_mib: u32,
    pub max_disk_mib: u32,
    pub max_wall_seconds: u64,
    pub max_processes: u32,
    pub max_output_bytes: u64,
}

impl ExecutionResourceBounds {
    fn valid(&self) -> bool {
        self.max_vcpus > 0
            && self.max_memory_mib > 0
            && self.max_disk_mib > 0
            && self.max_wall_seconds > 0
            && self.max_processes > 0
            && self.max_output_bytes > 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ExecutionRequest {
    pub home_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub work_target_basis: String,
    pub command_id: String,
    /// Digest of the complete immutable provider payload. Retries may advance
    /// only their worker epoch, never substitute input bytes.
    pub payload_digest: String,
    pub profile: ExecutionProfile,
    pub required_capabilities: BTreeSet<ExecutionCapability>,
    pub credential_class: String,
    pub bounds: ExecutionResourceBounds,
}

impl ExecutionRequest {
    fn valid(&self) -> bool {
        [
            &self.home_id,
            &self.tenant_id,
            &self.project_id,
            &self.work_target_basis,
            &self.command_id,
            &self.payload_digest,
            &self.credential_class,
        ]
        .into_iter()
        .all(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
            && !self.required_capabilities.is_empty()
            && self.bounds.valid()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct WorkspaceAuthorization {
    pub reservation_id: String,
    pub reserved_nanos_usd: u64,
}

impl WorkspaceAuthorization {
    fn valid(&self) -> bool {
        !self.reservation_id.trim().is_empty()
            && !self.reservation_id.chars().any(char::is_control)
            && self.reserved_nanos_usd > 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct WorkerGrant {
    pub profile: ExecutionProfile,
    pub capabilities: BTreeSet<ExecutionCapability>,
    pub credential_class: String,
    pub egress_bounded: bool,
    pub epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ExecutionUsage {
    pub usage_id: String,
    /// Customer-billable measured usage after the configured pricing transform.
    /// Provider cost evidence remains an external reconciliation input.
    pub billable_nanos_usd: u64,
    pub cpu_millis: u64,
    pub memory_mib_seconds: u64,
    pub wall_millis: u64,
}

impl ExecutionUsage {
    fn valid(&self) -> bool {
        !self.usage_id.trim().is_empty()
            && !self.usage_id.chars().any(char::is_control)
            && self.wall_millis > 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ExecutionSettlement {
    pub settlement_id: String,
    pub charged_nanos_usd: u64,
}

impl ExecutionSettlement {
    fn valid(&self) -> bool {
        !self.settlement_id.trim().is_empty() && !self.settlement_id.chars().any(char::is_control)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    #[default]
    Init,
    Prepared,
    Acknowledged,
    Running,
    Retryable,
    Completed,
    Failed,
    Canceled,
    Suspended,
}

impl ExecutionPhase {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Canceled)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ManagedExecutionState {
    pub phase: ExecutionPhase,
    pub request: Option<ExecutionRequest>,
    pub workspace_authorization: Option<WorkspaceAuthorization>,
    pub acknowledged: bool,
    pub selected_profile: Option<ExecutionProfile>,
    pub granted_capabilities: BTreeSet<ExecutionCapability>,
    pub active_epoch: Option<u64>,
    pub last_epoch: u64,
    pub observation_count: u64,
    pub last_evidence_ref: Option<String>,
    pub last_error: Option<String>,
    pub usage: Option<ExecutionUsage>,
    pub settlement: Option<ExecutionSettlement>,
    pub reservation_open: bool,
    pub suspended: bool,
    pub history_events: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum ManagedExecutionCommand {
    Prepare(ExecutionRequest),
    AuthorizeWorkspace(WorkspaceAuthorization),
    Acknowledge,
    Start(WorkerGrant),
    RecordObservation { epoch: u64, evidence_ref: String },
    WorkerLost { epoch: u64, reason: String },
    Retry(WorkerGrant),
    Complete { epoch: u64, usage: ExecutionUsage },
    Fail { epoch: u64, reason: String },
    Settle(ExecutionSettlement),
    Cancel,
    Suspend,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum ManagedExecutionEvent {
    ExecutionPrepared(ExecutionRequest),
    WorkspaceAuthorized(WorkspaceAuthorization),
    CommandAcknowledged,
    WorkerStarted(WorkerGrant),
    ObservationRecorded { epoch: u64, evidence_ref: String },
    WorkerLost { epoch: u64, reason: String },
    WorkerRetried(WorkerGrant),
    ExecutionCompleted { epoch: u64, usage: ExecutionUsage },
    ExecutionFailed { epoch: u64, reason: String },
    ExecutionSettled(ExecutionSettlement),
    ExecutionCanceled { stopped_epoch: Option<u64> },
    MachineSuspended { stopped_epoch: Option<u64> },
}

fn reject(reason: &'static str) -> Result<Vec<ManagedExecutionEvent>, Rejection> {
    Err(Rejection { reason })
}

fn request(state: &ManagedExecutionState) -> Result<&ExecutionRequest, Rejection> {
    state.request.as_ref().ok_or(Rejection {
        reason: "managed execution request is absent",
    })
}

fn grant_is_exact(request: &ExecutionRequest, grant: &WorkerGrant) -> bool {
    grant.profile == request.profile
        && grant.capabilities == request.required_capabilities
        && grant.credential_class == request.credential_class
        && grant.egress_bounded
        && request
            .required_capabilities
            .is_subset(&profile_capabilities(grant.profile))
        && grant.profile != ExecutionProfile::DedicatedCompute
}

pub fn decide(
    state: &ManagedExecutionState,
    command: ManagedExecutionCommand,
) -> Result<Vec<ManagedExecutionEvent>, Rejection> {
    use ExecutionPhase as P;
    use ManagedExecutionCommand as C;
    use ManagedExecutionEvent as E;

    match command {
        C::Prepare(request) => {
            if state.phase != P::Init {
                return reject("prepare: command already exists");
            }
            if !request.valid() {
                return reject("prepare: request identities, requirements or bounds are invalid");
            }
            Ok(vec![E::ExecutionPrepared(request)])
        }
        C::AuthorizeWorkspace(authorization) => {
            let request = request(state)?;
            if state.phase != P::Prepared || request.profile != ExecutionProfile::IsolatedWorkspace
            {
                return reject("authorizeWorkspace: command is not a prepared workspace request");
            }
            if state.workspace_authorization.is_some() {
                return reject("authorizeWorkspace: workspace already authorized");
            }
            if !authorization.valid() {
                return reject("authorizeWorkspace: positive exact reservation required");
            }
            Ok(vec![E::WorkspaceAuthorized(authorization)])
        }
        C::Acknowledge => {
            let request = request(state)?;
            if state.phase != P::Prepared {
                return reject("acknowledge: command is not prepared");
            }
            if request.profile == ExecutionProfile::DedicatedCompute {
                return reject("acknowledge: Dedicated compute is unavailable");
            }
            if !request
                .required_capabilities
                .is_subset(&profile_capabilities(request.profile))
            {
                return reject("acknowledge: requested profile cannot satisfy requirements");
            }
            if request.profile == ExecutionProfile::IsolatedWorkspace
                && state.workspace_authorization.is_none()
            {
                return reject("acknowledge: workspace policy and spend reservation required");
            }
            Ok(vec![E::CommandAcknowledged])
        }
        C::Start(grant) => {
            let request = request(state)?;
            if state.phase != P::Acknowledged || state.suspended {
                return reject("start: command is not acknowledged or Machine is suspended");
            }
            if !grant_is_exact(request, &grant) {
                return reject(
                    "start: profile, capabilities, credential or egress grant is not exact",
                );
            }
            if grant.epoch != 1 || state.last_epoch != 0 || state.active_epoch.is_some() {
                return reject("start: first worker must hold epoch 1");
            }
            Ok(vec![E::WorkerStarted(grant)])
        }
        C::RecordObservation {
            epoch,
            evidence_ref,
        } => {
            if state.phase != P::Running || state.active_epoch != Some(epoch) {
                return reject("recordObservation: stale or inactive worker epoch");
            }
            if evidence_ref.trim().is_empty() || evidence_ref.chars().any(char::is_control) {
                return reject("recordObservation: valid evidence reference required");
            }
            Ok(vec![E::ObservationRecorded {
                epoch,
                evidence_ref,
            }])
        }
        C::WorkerLost { epoch, reason } => {
            if state.phase != P::Running || state.active_epoch != Some(epoch) {
                return reject("workerLost: stale or inactive worker epoch");
            }
            if reason.trim().is_empty() {
                return reject("workerLost: reason required");
            }
            Ok(vec![E::WorkerLost { epoch, reason }])
        }
        C::Retry(grant) => {
            let request = request(state)?;
            if state.phase != P::Retryable || state.suspended {
                return reject("retry: command is not retryable or Machine is suspended");
            }
            if !grant_is_exact(request, &grant) {
                return reject(
                    "retry: profile, capabilities, credential or egress grant is not exact",
                );
            }
            if grant.epoch != state.last_epoch.saturating_add(1) || state.active_epoch.is_some() {
                return reject("retry: worker epoch must advance exactly once");
            }
            Ok(vec![E::WorkerRetried(grant)])
        }
        C::Complete { epoch, usage } => {
            let request = request(state)?;
            if state.phase != P::Running || state.active_epoch != Some(epoch) {
                return reject("complete: stale or inactive worker epoch");
            }
            if !usage.valid() {
                return reject("complete: valid bounded usage evidence required");
            }
            match request.profile {
                ExecutionProfile::DurableWorkflow if usage.billable_nanos_usd != 0 => {
                    return reject(
                        "complete: included Durable workflow cannot create workspace charge",
                    )
                }
                ExecutionProfile::IsolatedWorkspace => {
                    let Some(authorization) = state.workspace_authorization.as_ref() else {
                        return reject("complete: workspace reservation is absent");
                    };
                    if usage.billable_nanos_usd > authorization.reserved_nanos_usd {
                        return reject("complete: billable usage exceeds reservation");
                    }
                }
                ExecutionProfile::DedicatedCompute => {
                    return reject("complete: Dedicated compute is unavailable")
                }
                _ => {}
            }
            Ok(vec![E::ExecutionCompleted { epoch, usage }])
        }
        C::Fail { epoch, reason } => {
            if state.phase != P::Running || state.active_epoch != Some(epoch) {
                return reject("fail: stale or inactive worker epoch");
            }
            if reason.trim().is_empty() {
                return reject("fail: reason required");
            }
            Ok(vec![E::ExecutionFailed { epoch, reason }])
        }
        C::Settle(settlement) => {
            let request = request(state)?;
            if state.phase != P::Completed || state.settlement.is_some() {
                return reject("settle: command is not completed or already settled");
            }
            if !settlement.valid() {
                return reject("settle: valid settlement identity required");
            }
            let Some(usage) = state.usage.as_ref() else {
                return reject("settle: admitted usage is absent");
            };
            if settlement.charged_nanos_usd != usage.billable_nanos_usd {
                return reject("settle: charge must equal admitted billable usage");
            }
            if request.profile == ExecutionProfile::DurableWorkflow
                && settlement.charged_nanos_usd != 0
            {
                return reject("settle: Durable workflow is included");
            }
            if let Some(authorization) = state.workspace_authorization.as_ref() {
                if settlement.charged_nanos_usd > authorization.reserved_nanos_usd {
                    return reject("settle: charge exceeds reservation");
                }
            }
            Ok(vec![E::ExecutionSettled(settlement)])
        }
        C::Cancel => match state.phase {
            P::Prepared | P::Acknowledged | P::Running | P::Retryable => {
                Ok(vec![E::ExecutionCanceled {
                    stopped_epoch: state.active_epoch,
                }])
            }
            _ => reject("cancel: command is not cancelable"),
        },
        C::Suspend => {
            if state.phase == P::Init || state.suspended {
                return reject("suspend: no active command or already suspended");
            }
            Ok(vec![E::MachineSuspended {
                stopped_epoch: state.active_epoch,
            }])
        }
    }
}

pub fn evolve(
    state: &ManagedExecutionState,
    event: ManagedExecutionEvent,
) -> ManagedExecutionState {
    use ExecutionPhase as P;
    use ManagedExecutionEvent as E;

    let mut next = state.clone();
    next.history_events = next.history_events.saturating_add(1);
    match event {
        E::ExecutionPrepared(request) => {
            next.phase = P::Prepared;
            next.request = Some(request);
        }
        E::WorkspaceAuthorized(authorization) => {
            next.workspace_authorization = Some(authorization);
            next.reservation_open = true;
        }
        E::CommandAcknowledged => {
            next.phase = P::Acknowledged;
            next.acknowledged = true;
        }
        E::WorkerStarted(grant) | E::WorkerRetried(grant) => {
            next.phase = P::Running;
            next.selected_profile = Some(grant.profile);
            next.granted_capabilities = grant.capabilities;
            next.active_epoch = Some(grant.epoch);
            next.last_epoch = grant.epoch;
            next.last_error = None;
        }
        E::ObservationRecorded { evidence_ref, .. } => {
            next.observation_count = next.observation_count.saturating_add(1);
            next.last_evidence_ref = Some(evidence_ref);
        }
        E::WorkerLost { reason, .. } => {
            next.phase = P::Retryable;
            next.active_epoch = None;
            next.last_error = Some(reason);
        }
        E::ExecutionCompleted { usage, .. } => {
            next.phase = P::Completed;
            next.active_epoch = None;
            next.usage = Some(usage);
        }
        E::ExecutionFailed { reason, .. } => {
            next.phase = P::Failed;
            next.active_epoch = None;
            next.reservation_open = false;
            next.last_error = Some(reason);
        }
        E::ExecutionSettled(settlement) => {
            next.settlement = Some(settlement);
            next.reservation_open = false;
        }
        E::ExecutionCanceled { .. } => {
            next.phase = P::Canceled;
            next.active_epoch = None;
            next.reservation_open = false;
        }
        E::MachineSuspended { .. } => {
            next.suspended = true;
            next.active_epoch = None;
            next.reservation_open = false;
            if !next.phase.terminal() {
                next.phase = P::Suspended;
            }
        }
    }
    next
}

impl Lifecycle for ManagedExecutionState {
    type State = ManagedExecutionState;
    type Command = ManagedExecutionCommand;
    type Event = ManagedExecutionEvent;

    const KIND: &'static str = "managed_machine_execution";

    fn decide(state: &Self::State, command: Self::Command) -> Result<Vec<Self::Event>, Rejection> {
        decide(state, command)
    }

    fn evolve(state: &Self::State, event: Self::Event) -> Self::State {
        evolve(state, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn capabilities(items: &[ExecutionCapability]) -> BTreeSet<ExecutionCapability> {
        items.iter().copied().collect()
    }

    fn request(profile: ExecutionProfile) -> ExecutionRequest {
        use ExecutionCapability as C;
        let required_capabilities = match profile {
            ExecutionProfile::DurableWorkflow => capabilities(&[C::Chat, C::HttpEffect]),
            ExecutionProfile::IsolatedWorkspace => capabilities(&[C::Workspace, C::Process]),
            ExecutionProfile::DedicatedCompute => capabilities(&[C::Docker]),
        };
        ExecutionRequest {
            home_id: "home-a".into(),
            tenant_id: "tenant-a".into(),
            project_id: "project-a".into(),
            work_target_basis: "basis:abc".into(),
            command_id: "command-a".into(),
            payload_digest: "sha256:payload-a".into(),
            profile,
            required_capabilities,
            credential_class: "private-home:openai".into(),
            bounds: ExecutionResourceBounds {
                max_vcpus: 2,
                max_memory_mib: 8_192,
                max_disk_mib: 16_384,
                max_wall_seconds: 1_800,
                max_processes: 256,
                max_output_bytes: 16 * 1024 * 1024,
            },
        }
    }

    fn grant(request: &ExecutionRequest, epoch: u64) -> WorkerGrant {
        WorkerGrant {
            profile: request.profile,
            capabilities: request.required_capabilities.clone(),
            credential_class: request.credential_class.clone(),
            egress_bounded: true,
            epoch,
        }
    }

    fn apply(
        state: &ManagedExecutionState,
        command: ManagedExecutionCommand,
    ) -> Result<ManagedExecutionState, Rejection> {
        decide(state, command).map(|events| {
            events
                .into_iter()
                .fold(state.clone(), |state, event| evolve(&state, event))
        })
    }

    fn acknowledged(profile: ExecutionProfile) -> ManagedExecutionState {
        let request = request(profile);
        let mut state = apply(
            &ManagedExecutionState::default(),
            ManagedExecutionCommand::Prepare(request),
        )
        .unwrap();
        if profile == ExecutionProfile::IsolatedWorkspace {
            state = apply(
                &state,
                ManagedExecutionCommand::AuthorizeWorkspace(WorkspaceAuthorization {
                    reservation_id: "reserve-a".into(),
                    reserved_nanos_usd: 10_000,
                }),
            )
            .unwrap();
        }
        apply(&state, ManagedExecutionCommand::Acknowledge).unwrap()
    }

    #[test]
    fn durable_workflow_completes_and_settles_without_workspace_charge() {
        let request = request(ExecutionProfile::DurableWorkflow);
        let state = acknowledged(ExecutionProfile::DurableWorkflow);
        let state = apply(&state, ManagedExecutionCommand::Start(grant(&request, 1))).unwrap();
        let state = apply(
            &state,
            ManagedExecutionCommand::RecordObservation {
                epoch: 1,
                evidence_ref: "evidence:one".into(),
            },
        )
        .unwrap();
        let state = apply(
            &state,
            ManagedExecutionCommand::Complete {
                epoch: 1,
                usage: ExecutionUsage {
                    usage_id: "usage:one".into(),
                    billable_nanos_usd: 0,
                    cpu_millis: 10,
                    memory_mib_seconds: 2,
                    wall_millis: 20,
                },
            },
        )
        .unwrap();
        let state = apply(
            &state,
            ManagedExecutionCommand::Settle(ExecutionSettlement {
                settlement_id: "settle:one".into(),
                charged_nanos_usd: 0,
            }),
        )
        .unwrap();
        assert_eq!(state.phase, ExecutionPhase::Completed);
        assert_eq!(state.observation_count, 1);
        assert!(!state.reservation_open);
    }

    #[test]
    fn workspace_requires_reservation_and_fences_retry() {
        let request = request(ExecutionProfile::IsolatedWorkspace);
        let prepared = apply(
            &ManagedExecutionState::default(),
            ManagedExecutionCommand::Prepare(request.clone()),
        )
        .unwrap();
        assert!(apply(&prepared, ManagedExecutionCommand::Acknowledge).is_err());

        let state = acknowledged(ExecutionProfile::IsolatedWorkspace);
        let running = apply(&state, ManagedExecutionCommand::Start(grant(&request, 1))).unwrap();
        let retryable = apply(
            &running,
            ManagedExecutionCommand::WorkerLost {
                epoch: 1,
                reason: "container lost".into(),
            },
        )
        .unwrap();
        assert!(apply(
            &retryable,
            ManagedExecutionCommand::Retry(grant(&request, 1))
        )
        .is_err());
        let retried = apply(
            &retryable,
            ManagedExecutionCommand::Retry(grant(&request, 2)),
        )
        .unwrap();
        assert_eq!(retried.active_epoch, Some(2));

        assert!(apply(
            &retried,
            ManagedExecutionCommand::Complete {
                epoch: 1,
                usage: ExecutionUsage {
                    usage_id: "stale".into(),
                    billable_nanos_usd: 1,
                    cpu_millis: 1,
                    memory_mib_seconds: 1,
                    wall_millis: 1,
                },
            }
        )
        .is_err());
    }

    #[test]
    fn no_profile_fallback_capability_widening_or_credential_substitution() {
        let request = request(ExecutionProfile::DurableWorkflow);
        let state = acknowledged(ExecutionProfile::DurableWorkflow);

        let mut wrong_profile = grant(&request, 1);
        wrong_profile.profile = ExecutionProfile::IsolatedWorkspace;
        assert!(apply(&state, ManagedExecutionCommand::Start(wrong_profile)).is_err());

        let mut widened = grant(&request, 1);
        widened.capabilities.insert(ExecutionCapability::Process);
        assert!(apply(&state, ManagedExecutionCommand::Start(widened)).is_err());

        let mut substituted = grant(&request, 1);
        substituted.credential_class = "public-deployment:openai".into();
        assert!(apply(&state, ManagedExecutionCommand::Start(substituted)).is_err());
    }

    #[test]
    fn dedicated_never_acknowledges_or_starts() {
        let request = request(ExecutionProfile::DedicatedCompute);
        let state = apply(
            &ManagedExecutionState::default(),
            ManagedExecutionCommand::Prepare(request),
        )
        .unwrap();
        assert!(apply(&state, ManagedExecutionCommand::Acknowledge).is_err());
        assert_eq!(state.phase, ExecutionPhase::Prepared);
    }

    #[test]
    fn cancellation_and_suspension_stop_active_epoch_and_preserve_history() {
        let request = request(ExecutionProfile::IsolatedWorkspace);
        let state = acknowledged(ExecutionProfile::IsolatedWorkspace);
        let running = apply(&state, ManagedExecutionCommand::Start(grant(&request, 1))).unwrap();
        let history = running.history_events;
        let canceled = apply(&running, ManagedExecutionCommand::Cancel).unwrap();
        assert_eq!(canceled.phase, ExecutionPhase::Canceled);
        assert_eq!(canceled.active_epoch, None);
        assert!(canceled.history_events > history);

        let running = apply(
            &acknowledged(ExecutionProfile::IsolatedWorkspace),
            ManagedExecutionCommand::Start(grant(&request, 1)),
        )
        .unwrap();
        let suspended = apply(&running, ManagedExecutionCommand::Suspend).unwrap();
        assert_eq!(suspended.phase, ExecutionPhase::Suspended);
        assert!(suspended.suspended);
        assert_eq!(suspended.active_epoch, None);
        assert!(apply(
            &suspended,
            ManagedExecutionCommand::Retry(grant(&request, 2))
        )
        .is_err());
    }

    #[test]
    fn settlement_is_exact_bounded_and_once() {
        let request = request(ExecutionProfile::IsolatedWorkspace);
        let state = acknowledged(ExecutionProfile::IsolatedWorkspace);
        let running = apply(&state, ManagedExecutionCommand::Start(grant(&request, 1))).unwrap();
        let completed = apply(
            &running,
            ManagedExecutionCommand::Complete {
                epoch: 1,
                usage: ExecutionUsage {
                    usage_id: "usage:workspace".into(),
                    billable_nanos_usd: 9_000,
                    cpu_millis: 100,
                    memory_mib_seconds: 20,
                    wall_millis: 200,
                },
            },
        )
        .unwrap();
        assert!(apply(
            &completed,
            ManagedExecutionCommand::Settle(ExecutionSettlement {
                settlement_id: "settle:wrong".into(),
                charged_nanos_usd: 8_999,
            })
        )
        .is_err());
        let settled = apply(
            &completed,
            ManagedExecutionCommand::Settle(ExecutionSettlement {
                settlement_id: "settle:workspace".into(),
                charged_nanos_usd: 9_000,
            }),
        )
        .unwrap();
        assert!(apply(
            &settled,
            ManagedExecutionCommand::Settle(ExecutionSettlement {
                settlement_id: "settle:duplicate".into(),
                charged_nanos_usd: 9_000,
            })
        )
        .is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_epochs_never_make_two_workers_authoritative(
            epochs in prop::collection::vec(0_u64..8, 0..40)
        ) {
            let request = request(ExecutionProfile::IsolatedWorkspace);
            let mut state = acknowledged(ExecutionProfile::IsolatedWorkspace);
            state = apply(
                &state,
                ManagedExecutionCommand::Start(grant(&request, 1)),
            ).unwrap();

            for epoch in epochs {
                let before = state.clone();
                let command = if state.phase == ExecutionPhase::Running {
                    ManagedExecutionCommand::WorkerLost {
                        epoch,
                        reason: "property loss".into(),
                    }
                } else {
                    ManagedExecutionCommand::Retry(grant(&request, epoch))
                };
                state = apply(&state, command).unwrap_or(before);
                prop_assert!(state.active_epoch.is_none() || state.phase == ExecutionPhase::Running);
                prop_assert!(state.active_epoch.into_iter().count() <= 1);
                if let Some(active) = state.active_epoch {
                    prop_assert_eq!(active, state.last_epoch);
                }
            }
        }
    }
}
