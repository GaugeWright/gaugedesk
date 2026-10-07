//! Plans as governed work (DR-0386; GaugeWright DR-0103 row 4). The Home admits
//! a plan's standing — claim, settlement, reopening, supersession — as
//! decisions in a scope it owns, through the pure reducer in
//! `gaugedesk_core::plan`.
//!
//! Standing rides on the project's own task tracker (DR-0199 §3): deciding
//! needs current contribute access to it, and reading needs read access, as
//! `project_tracker.rs` resolves both now. The request commits only while that
//! authority read is still current, under the content codec, keyed by the
//! actor and the caller's request key so a retry replays the original
//! decision. The actor, the time and the lease end are materialized here;
//! nothing the caller sends supplies authority.

use gaugedesk_core::{
    boundary::Authority,
    plan::{EvidenceKind, PlanCommand, PlanState, ReopenCause, SettlementPolicy, StepSpec},
    Rejection,
};
use gaugedesk_store::AdmitError;
use serde::{Deserialize, Serialize};

use crate::{
    identity::AuthenticatedActionContext,
    project_tracker::{TrackerPermission, PROJECT_TASKS},
    Workbench,
};

/// The longest lease one claim may take, as for a tracker claim.
pub const MAX_STEP_LEASE_SECONDS: u32 = 7 * 24 * 60 * 60;

/// A person's decision about one plan. No caller supplies authority, time or
/// storage; a repeated request key replays the original decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideProjectPlan {
    pub project: String,
    pub plan_id: String,
    pub request_id: String,
    pub decision: PlanDecision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlanDecision {
    /// Offer the plan. Without a policy, settlement needs an attestation by
    /// someone other than the step's holder.
    Propose {
        title: String,
        steps: Vec<StepSpec>,
        #[serde(default)]
        policy: Option<SettlementPolicy>,
    },
    /// `stepClaimed`, for the next `lease_seconds`.
    Claim { step: String, lease_seconds: u32 },
    /// Let go of the caller's own live claim.
    Release { step: String },
    /// Record evidence against a step, authored by the caller.
    RecordEvidence {
        step: String,
        evidence: EvidenceKind,
        reference: String,
    },
    /// `stepSettled`, on recorded evidence the current policy epoch accepts.
    Settle { step: String, evidence: String },
    /// `stepReopened`, citing its cause.
    Reopen { step: String, cause: ReopenCause },
    /// Mint the next policy epoch. The proposer's decision.
    RevisePolicy { policy: SettlementPolicy },
    /// `planSuperseded`. The proposer's decision; terminal.
    Supersede { successor: String, reason: String },
}

fn refused(reason: &'static str) -> AdmitError {
    AdmitError::Rejected(Rejection { reason })
}

/// The plan's scope: Home-owned, inside the project's.
pub fn plan_scope(project: &str, plan_id: &str) -> Result<String, AdmitError> {
    if project.trim().is_empty() || plan_id.trim().is_empty() {
        return Err(refused("a plan needs a project and a plan id"));
    }
    Ok(format!(
        "project::{project}::plan::{}",
        hex::encode(plan_id)
    ))
}

fn now_ms() -> Result<u64, AdmitError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|_| refused("the clock is before the epoch"))
}

/// Decisions only the plan's proposer may make.
fn proposer_only(decision: &PlanDecision) -> bool {
    matches!(
        decision,
        PlanDecision::RevisePolicy { .. } | PlanDecision::Supersede { .. }
    )
}

fn materialize(
    plan_id: &str,
    actor: &Authority,
    decision: &PlanDecision,
    at_ms: u64,
) -> Result<PlanCommand, Rejection> {
    let by = actor.clone();
    Ok(match decision.clone() {
        PlanDecision::Propose {
            title,
            steps,
            policy,
        } => PlanCommand::Propose {
            plan_id: plan_id.into(),
            title,
            proposer: by,
            steps,
            policy: policy.unwrap_or_else(SettlementPolicy::independent_attestation),
            at_ms,
        },
        PlanDecision::Claim {
            step,
            lease_seconds,
        } => {
            if lease_seconds == 0 || lease_seconds > MAX_STEP_LEASE_SECONDS {
                return Err(Rejection {
                    reason: "claim: the lease is outside its allowed length",
                });
            }
            PlanCommand::ClaimStep {
                step,
                holder: by,
                at_ms,
                lease_until_ms: at_ms + u64::from(lease_seconds) * 1_000,
            }
        }
        PlanDecision::Release { step } => PlanCommand::ReleaseStep {
            step,
            holder: by,
            at_ms,
        },
        PlanDecision::RecordEvidence {
            step,
            evidence,
            reference,
        } => PlanCommand::RecordEvidence {
            step,
            kind: evidence,
            author: by,
            reference,
            at_ms,
        },
        PlanDecision::Settle { step, evidence } => PlanCommand::SettleStep {
            step,
            evidence,
            by,
            at_ms,
        },
        PlanDecision::Reopen { step, cause } => PlanCommand::ReopenStep {
            step,
            cause,
            by,
            at_ms,
        },
        PlanDecision::RevisePolicy { policy } => {
            PlanCommand::ReviseSettlementPolicy { policy, by, at_ms }
        }
        PlanDecision::Supersede { successor, reason } => PlanCommand::Supersede {
            successor,
            reason,
            by,
            at_ms,
        },
    })
}

impl Workbench {
    /// Admit one decision about a plan as the authenticated person, under
    /// their current contribute access to the project's tasks.
    pub fn decide_project_plan(
        &mut self,
        context: &AuthenticatedActionContext,
        request: &DecideProjectPlan,
    ) -> Result<PlanState, AdmitError> {
        if request.request_id.trim().is_empty() {
            return Err(refused("a plan decision needs a request key"));
        }
        let scope = plan_scope(&request.project, &request.plan_id)?;
        let (_, basis) = self.prepare_project_tracker_read(
            context,
            &request.project,
            PROJECT_TASKS,
            TrackerPermission::Contribute,
        )?;
        let actor = Authority::new(context.actor().as_str());
        let key = format!(
            "plan-decision:{}:{}",
            hex::encode(actor.as_str()),
            hex::encode(&request.request_id)
        );
        let at_ms = now_ms()?;
        let intent = (actor.as_str(), request);
        let admission = self
            .store_mut()
            .with_dispatch_record_admission(&basis, |writer| {
                writer.commit_protected_request::<PlanState, _>(
                    &scope,
                    &key,
                    &intent,
                    |state| {
                        if proposer_only(&request.decision)
                            && state.proposer.as_ref() != Some(&actor)
                        {
                            return Err(Rejection {
                                reason: "only the plan's proposer may revise or supersede it",
                            });
                        }
                        Ok(())
                    },
                    |_| materialize(&request.plan_id, &actor, &request.decision, at_ms),
                )
            })??;
        Ok(admission.state)
    }

    /// Read a plan's standing under current read access to the project's tasks.
    pub fn read_project_plan(
        &self,
        context: &AuthenticatedActionContext,
        project: &str,
        plan_id: &str,
    ) -> Result<PlanState, AdmitError> {
        let scope = plan_scope(project, plan_id)?;
        self.prepare_project_tracker_read(
            context,
            project,
            PROJECT_TASKS,
            TrackerPermission::Read,
        )?;
        let state = self.store_ref().fold::<PlanState>(&scope)?;
        if state.plan_id.is_empty() {
            return Err(refused("no such plan"));
        }
        Ok(state)
    }
}

#[cfg(test)]
#[path = "project_plan_tests.rs"]
mod tests;
