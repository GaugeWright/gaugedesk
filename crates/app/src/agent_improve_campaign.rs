//! Versioned open/private campaign source for Agent improvement. Only the open
//! projection may be given to an edit-chat proposer; checks and sealed inputs
//! remain with the host evaluator.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use whipplescript_core::improve_holdout;
use whipplescript_core::improve_selection::{
    self, Bar, Campaign, Delta, GaugeEvidence, Reach, Reading, Role, Verdict,
};

use gaugedesk_harness::{EgressGate, HarnessFactory, HarnessSpec};
use gaugedesk_workspace::Workspace;

use crate::agent_improve::{
    prepare_native_shadow_pair_from_authoring, run_hosted_shadow_selection,
    run_native_shadow_selection, HostGauge, HostJudge, HostSelection, HostedImprovePairAdmission,
    HostedImprovePairContext, PreparedShadowPair, SelectedShadowPair, ShadowTurn,
};
use crate::agent_improve_adoption::{adopt_candidate, AgentDefinitionSnapshot};
use crate::agent_improve_checkpoint::{HostedImproveInputCut, HostedImproveInputKey};
use crate::agent_improve_funding::ManagedShadowMeter;
use crate::agent_improve_scenario_journal::{HostedImproveScenarioCut, HostedScenarioSelection};
use crate::LockUnpoisoned;
use crate::{library::gen_id, SharedWorkbench};

const OPEN_SCHEMA: &str = "gaugedesk.agent-improve.open.v1";
const PRIVATE_SCHEMA: &str = "gaugedesk.agent-improve.private.v1";
const POOL_SCHEMA: &str = "gaugedesk.agent-improve.pool.v1";
const MAX_SOURCE_BYTES: usize = 512 * 1024;
const MAX_SCENARIOS: usize = 64;
const MAX_GAUGES: usize = 32;
const MAX_PROMPT_BYTES: usize = 16 * 1024;
const MAX_CHECK_BYTES: usize = 8 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OpenSource {
    schema: String,
    gauges: Vec<GaugeSource>,
    selection: SelectionSource,
    scenarios: Vec<OpenScenario>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GaugeSource {
    name: String,
    description: String,
    minimum_pass_rate: Option<f64>,
}

#[derive(Clone, Deserialize, Default, Serialize)]
#[serde(default, deny_unknown_fields)]
struct SelectionSource {
    ascend: BTreeMap<String, Option<Threshold>>,
    sacrifice: BTreeSet<String>,
    within_percent: BTreeMap<String, f64>,
    floors: BTreeMap<String, Threshold>,
    repair: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Threshold {
    ge: bool,
    value: f64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OpenScenario {
    id: String,
    prompt: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateSource {
    schema: String,
    /// Exact checks for every open scenario, keyed by scenario id then gauge.
    open_checks: BTreeMap<String, BTreeMap<String, TextCheck>>,
    #[serde(default)]
    sealed_scenarios: Vec<PrivateScenario>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateScenario {
    id: String,
    prompt: String,
    checks: BTreeMap<String, TextCheck>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum TextCheck {
    #[serde(rename = "assistant-contains")]
    Contains { text: String },
    #[serde(rename = "assistant-excludes")]
    Excludes { text: String },
    #[serde(rename = "assistant-equals")]
    Equals { text: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolSource {
    schema: String,
    gauges: Vec<GaugeSource>,
    selection: SelectionSource,
    scenarios: Vec<PoolScenario>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolScenario {
    id: String,
    prompt: String,
    checks: BTreeMap<String, TextCheck>,
}

struct FingerprintedScenario {
    scenario: PoolScenario,
    fingerprint: String,
    retired: bool,
    wear_before: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PoolAssignment {
    pub schema: String,
    pub campaign_id: String,
    pub pool_ref: String,
    pub cases: Vec<CaseAssignment>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaseAssignment {
    pub id: String,
    pub fingerprint: String,
    pub exposure: String,
    pub wear_before: i64,
}

/// The two source projections and a private assignment are made in one host
/// operation. A sampled partition alone is not a held-out evidence claim.
pub(super) struct SampledPool {
    pub open_json: String,
    pub private_json: String,
    pub assignment_json: String,
}

pub(super) fn sample_pool(
    pool_bytes: &[u8],
    campaign_id: &str,
    account_key: &[u8; 32],
    wear: impl Fn(&str) -> i64,
) -> Result<SampledPool, String> {
    if pool_bytes.is_empty() || pool_bytes.len() > MAX_SOURCE_BYTES {
        return Err("Agent improve case pool is missing or too large".to_owned());
    }
    let pool: PoolSource = serde_json::from_slice(pool_bytes)
        .map_err(|error| format!("invalid Agent improve case pool: {error}"))?;
    if pool.schema != POOL_SCHEMA {
        return Err("unsupported Agent improve case pool schema".to_owned());
    }
    // Validate all prompts and checks before sampling, including the cases
    // that will be hidden from the proposer.
    let all_open = OpenSource {
        schema: OPEN_SCHEMA.to_owned(),
        gauges: pool.gauges.clone(),
        selection: pool.selection.clone(),
        scenarios: pool
            .scenarios
            .iter()
            .map(|case| OpenScenario {
                id: case.id.clone(),
                prompt: case.prompt.clone(),
            })
            .collect(),
    };
    let all_private = PrivateSource {
        schema: PRIVATE_SCHEMA.to_owned(),
        open_checks: pool
            .scenarios
            .iter()
            .map(|case| (case.id.clone(), case.checks.clone()))
            .collect(),
        sealed_scenarios: Vec::new(),
    };
    validate(&all_open, &all_private)?;

    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, account_key);
    let mut fingerprints = BTreeSet::new();
    let scenarios = pool
        .scenarios
        .into_iter()
        .map(|scenario| {
            // IDs are intentionally absent: a rename must not reset wear.
            let canonical = serde_json::to_vec(&(&scenario.prompt, &scenario.checks))
                .map_err(|_| "Agent improve case could not be fingerprinted")?;
            let mut material = b"gaugedesk.agent-improve.case.v1\0".to_vec();
            material.extend_from_slice(&canonical);
            let fingerprint = hex::encode(ring::hmac::sign(&key, &material).as_ref());
            if !fingerprints.insert(fingerprint.clone()) {
                return Err("Agent improve case pool repeats a prompt and checks".to_owned());
            }
            let wear_before = wear(&fingerprint);
            if wear_before < 0 {
                return Err("Agent improve case wear is invalid".to_owned());
            }
            Ok(FingerprintedScenario {
                scenario,
                fingerprint,
                retired: wear_before >= improve_holdout::WEAR_OUT_AT,
                wear_before,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let (open, sealed, _) = improve_holdout::seal_scenarios(
        campaign_id,
        &scenarios,
        |case| case.fingerprint.as_str(),
        |case| case.retired,
    );
    if open.is_empty() {
        return Err("all Agent improve cases are retired".to_owned());
    }
    let open_source = OpenSource {
        schema: OPEN_SCHEMA.to_owned(),
        gauges: pool.gauges,
        selection: pool.selection,
        scenarios: open
            .iter()
            .map(|case| OpenScenario {
                id: case.scenario.id.clone(),
                prompt: case.scenario.prompt.clone(),
            })
            .collect(),
    };
    let private_source = PrivateSource {
        schema: PRIVATE_SCHEMA.to_owned(),
        open_checks: open
            .iter()
            .map(|case| (case.scenario.id.clone(), case.scenario.checks.clone()))
            .collect(),
        sealed_scenarios: sealed
            .iter()
            .map(|case| PrivateScenario {
                id: case.scenario.id.clone(),
                prompt: case.scenario.prompt.clone(),
                checks: case.scenario.checks.clone(),
            })
            .collect(),
    };
    let open_json = serde_json::to_string(&open_source)
        .map_err(|_| "Agent improve open source could not be encoded")?;
    let private_json = serde_json::to_string(&private_source)
        .map_err(|_| "Agent improve private source could not be encoded")?;
    // Apply the same encoded-source size and roster checks as manual intake.
    CampaignSnapshot::parse(open_json.as_bytes(), private_json.as_bytes())?;
    let sealed_ids = sealed
        .iter()
        .map(|case| case.scenario.id.as_str())
        .collect::<BTreeSet<_>>();
    let assignment = PoolAssignment {
        schema: POOL_SCHEMA.to_owned(),
        campaign_id: campaign_id.to_owned(),
        pool_ref: format!(
            "agent-pool:sha256:{}",
            hex::encode(Sha256::digest(pool_bytes))
        ),
        cases: scenarios
            .iter()
            .map(|case| CaseAssignment {
                id: case.scenario.id.clone(),
                fingerprint: case.fingerprint.clone(),
                exposure: if case.retired {
                    "retired"
                } else if sealed_ids.contains(case.scenario.id.as_str()) {
                    "sealed"
                } else {
                    "open"
                }
                .to_owned(),
                wear_before: case.wear_before,
            })
            .collect(),
    };
    let assignment_json = serde_json::to_string(&assignment)
        .map_err(|_| "Agent improve pool assignment could not be encoded")?;
    Ok(SampledPool {
        open_json,
        private_json,
        assignment_json,
    })
}

impl TextCheck {
    fn text(&self) -> &str {
        match self {
            Self::Contains { text } | Self::Excludes { text } | Self::Equals { text } => text,
        }
    }

    fn passes(&self, answer: &str) -> bool {
        match self {
            Self::Contains { text } => answer.contains(text),
            Self::Excludes { text } => !answer.contains(text),
            Self::Equals { text } => answer == text,
        }
    }
}

/// One exact campaign cut. The private source is deliberately not serializable
/// or exposed by the proposer projection.
pub struct CampaignSnapshot {
    open_json: String,
    open: OpenSource,
    private: PrivateSource,
    open_ref: String,
    private_ref: String,
    reference: String,
    sampled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exposure {
    Open,
    Sealed,
}

pub struct EvaluationScenario<'a> {
    pub id: &'a str,
    pub prompt: &'a str,
    pub exposure: Exposure,
}

struct EvaluatedScenario {
    id: String,
    exposure: Exposure,
    readings: Vec<GaugeEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CampaignLineage {
    baseline_main_cut: String,
    baseline_definition_ref: String,
    candidate_definition_ref: String,
    baseline_package_ref: String,
    candidate_package_ref: String,
    baseline_discipline_ref: String,
    candidate_discipline_ref: String,
}

/// Every evaluated scenario used one authored baseline/candidate lineage and
/// one pinned open/private campaign. Sealed scenarios are skipped when the
/// open stage fails. Raw sealed turns remain private.
pub struct SelectedCampaign {
    target_id: String,
    reference: String,
    scenarios: Vec<EvaluatedScenario>,
    open_verdict: Verdict,
    verdict: Verdict,
    sealed_available: usize,
    reservation_id: Option<String>,
    lineage: CampaignLineage,
    baseline_definition: AgentDefinitionSnapshot,
    candidate_definition: AgentDefinitionSnapshot,
}

/// The only evaluation projection an edit-chat optimizer may receive. It is
/// deliberately built from the open-stage verdict, even after a sealed gate
/// has run, so repeated revisions cannot probe hidden checks through feedback.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OptimizerFeedback {
    pub open_scenario_ids: Vec<String>,
    pub open_verdict: ReviewVerdict,
}

/// Immutable reviewer evidence. It contains aggregate judge outputs and exact
/// execution identities, but no sealed scenario inputs, checks, or raw turns.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignEvidenceCard {
    pub target_id: String,
    pub campaign_ref: String,
    pub open_source_ref: String,
    pub private_source_ref: String,
    pub baseline_main_cut: String,
    pub baseline_definition_ref: String,
    pub candidate_definition_ref: String,
    pub baseline_package_ref: String,
    pub candidate_package_ref: String,
    pub baseline_discipline_ref: String,
    pub candidate_discipline_ref: String,
    pub open_count: usize,
    pub sealed_available: usize,
    pub sealed_evaluated: usize,
    /// `held-out` only after Home verifies the sampled assignment and complete
    /// sealed reservation receipt when retaining this reviewer card.
    pub holdout_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation_ref: Option<String>,
    pub open_verdict: ReviewVerdict,
    pub final_verdict: ReviewVerdict,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewVerdict {
    pub proposable: bool,
    pub tradeoff: bool,
    pub reasons: Vec<String>,
    pub lines: Vec<ReviewGaugeLine>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewGaugeLine {
    pub gauge: String,
    pub role: String,
    pub delta: String,
    pub baseline: Option<f64>,
    pub candidate: Option<f64>,
    pub band: f64,
    pub bar_met: Option<bool>,
    pub reach_met: Option<bool>,
    pub direction_up: bool,
}

impl From<&Verdict> for ReviewVerdict {
    fn from(verdict: &Verdict) -> Self {
        Self {
            proposable: verdict.proposable,
            tradeoff: verdict.tradeoff,
            reasons: verdict.reasons.clone(),
            lines: verdict
                .lines
                .iter()
                .map(|line| ReviewGaugeLine {
                    gauge: line.gauge.clone(),
                    role: match line.role {
                        Role::Ascend => "ascend",
                        Role::Sacrifice => "sacrifice",
                        Role::Guard => "guard",
                    }
                    .to_owned(),
                    delta: match line.delta {
                        Delta::Better => "better",
                        Delta::InBand => "in-band",
                        Delta::Worse => "worse",
                        Delta::Unmeasured => "unmeasured",
                    }
                    .to_owned(),
                    baseline: line.baseline,
                    candidate: line.candidate,
                    band: line.band,
                    bar_met: line.bar_met,
                    reach_met: line.reach_met,
                    direction_up: line.direction_up,
                })
                .collect(),
        }
    }
}

impl SelectedCampaign {
    pub(crate) fn adoption_definition(
        &self,
    ) -> Result<Option<crate::agent_improve_adoption::AgentDefinitionSnapshot>, String> {
        if !self.verdict.proposable {
            return Ok(None);
        }
        if self.scenarios.is_empty() {
            return Err("Agent improve campaign has no evaluated scenarios".to_owned());
        }
        Ok(Some(self.candidate_definition.clone()))
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// For a human reviewer, not for optimizer reflection: aggregate values
    /// include the sealed set when one exists.
    pub fn reviewer_verdict(&self) -> &Verdict {
        &self.verdict
    }

    /// The open-stage decision before any sealed case is exposed.
    pub fn open_verdict(&self) -> &Verdict {
        &self.open_verdict
    }

    pub fn optimizer_feedback(&self) -> OptimizerFeedback {
        OptimizerFeedback {
            open_scenario_ids: self
                .open_scenario_ids()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            open_verdict: ReviewVerdict::from(&self.open_verdict),
        }
    }

    pub fn sealed_available(&self) -> usize {
        self.sealed_available
    }

    pub fn open_scenario_ids(&self) -> Vec<&str> {
        self.scenarios
            .iter()
            .filter(|scenario| scenario.exposure == Exposure::Open)
            .map(|scenario| scenario.id.as_str())
            .collect()
    }

    pub fn sealed_count(&self) -> usize {
        self.scenarios
            .iter()
            .filter(|scenario| scenario.exposure == Exposure::Sealed)
            .count()
    }

    pub fn sealed_scenario_ids(&self) -> Vec<&str> {
        self.scenarios
            .iter()
            .filter(|scenario| scenario.exposure == Exposure::Sealed)
            .map(|scenario| scenario.id.as_str())
            .collect()
    }

    pub fn reservation_id(&self) -> Option<&str> {
        self.reservation_id.as_deref()
    }

    pub fn reviewer_card(
        &self,
        campaign: &CampaignSnapshot,
    ) -> Result<CampaignEvidenceCard, String> {
        if self.reference != campaign.reference {
            return Err("Agent improve evidence names another campaign cut".to_owned());
        }
        if self.scenarios.is_empty() {
            return Err("Agent improve campaign has no evaluated scenarios".to_owned());
        }
        Ok(CampaignEvidenceCard {
            target_id: self.target_id.clone(),
            campaign_ref: self.reference.clone(),
            open_source_ref: campaign.open_ref().to_owned(),
            private_source_ref: campaign.private_ref().to_owned(),
            baseline_main_cut: self.lineage.baseline_main_cut.clone(),
            baseline_definition_ref: self.lineage.baseline_definition_ref.clone(),
            candidate_definition_ref: self.lineage.candidate_definition_ref.clone(),
            baseline_package_ref: self.lineage.baseline_package_ref.clone(),
            candidate_package_ref: self.lineage.candidate_package_ref.clone(),
            baseline_discipline_ref: self.lineage.baseline_discipline_ref.clone(),
            candidate_discipline_ref: self.lineage.candidate_discipline_ref.clone(),
            open_count: self.open_scenario_ids().len(),
            sealed_available: self.sealed_available,
            sealed_evaluated: self.sealed_count(),
            holdout_status: "unheld-out".to_owned(),
            reservation_ref: None,
            open_verdict: ReviewVerdict::from(&self.open_verdict),
            final_verdict: ReviewVerdict::from(&self.verdict),
        })
    }
}

/// Evaluate a text-scenario campaign through the same governed native harness
/// for every arm. Each scenario starts with a fresh pair of workspaces and
/// runtime continuity; a changed Agent Main cut or candidate definition
/// invalidates the whole campaign rather than mixing incompatible readings.
pub fn run_native_campaign(
    factory: &gaugedesk_whip_runtime::WhipHarnessFactory,
    template: &HarnessSpec,
    target_id: &str,
    workspace: &dyn Workspace,
    candidate_repo: &Path,
    campaign: &CampaignSnapshot,
    gate: &dyn EgressGate,
) -> Result<SelectedCampaign, String> {
    if campaign.sampled {
        return Err("sampled Agent improve campaign requires Home exposure reservation".to_owned());
    }
    run_campaign_with(
        template,
        target_id,
        workspace,
        candidate_repo,
        campaign,
        |_, _, _, prepared, judge, selection, prompt| {
            run_native_shadow_selection(factory, prepared, gate, prompt, judge, selection)
        },
    )
}

/// Host-held sampled campaigns use this entrypoint. The caller reserves the
/// complete sealed set in Home custody after open dominance, before the first
/// sealed input reaches either execution arm. A failed reservation stops the
/// gate. The callback must reserve through Home's durable ledger; this routine
/// never treats a callback as held-out evidence by itself.
pub struct NativeCampaignGate<'a> {
    pub egress: &'a dyn EgressGate,
    pub reserve_sealed: &'a mut dyn FnMut() -> Result<String, String>,
}

pub fn run_native_campaign_with_reservation(
    factory: &gaugedesk_whip_runtime::WhipHarnessFactory,
    template: &HarnessSpec,
    target_id: &str,
    workspace: &dyn Workspace,
    candidate_repo: &Path,
    campaign: &CampaignSnapshot,
    gate: NativeCampaignGate<'_>,
) -> Result<SelectedCampaign, String> {
    if !campaign.sampled {
        return Err("Agent improve campaign has no sampled Home assignment".to_owned());
    }
    run_campaign_with_reservation(
        template,
        target_id,
        workspace,
        candidate_repo,
        campaign,
        |_, _, _, prepared, judge, selection, prompt| {
            run_native_shadow_selection(factory, prepared, gate.egress, prompt, judge, selection)
        },
        &mut || (gate.reserve_sealed)().map(Some),
    )
}

/// Run a sampled campaign at Home-provisioned hosted placements. Home retains
/// the sampled sources and sealed exposure ledger, supplies one exact signed
/// policy in the template, and meters each baseline/candidate model turn.
/// This entrypoint never provisions a placement or grants a funding plan.
pub fn run_hosted_managed_campaign_with_reservation(
    wb: &SharedWorkbench,
    execution: HostedCampaignExecution<'_>,
    gate: NativeCampaignGate<'_>,
    funding: ManagedCampaignFunding,
) -> Result<SelectedCampaign, String> {
    let HostedCampaignExecution {
        factory,
        pair_admission,
        template,
        agent_id,
        actor,
        target_id,
        workspace,
        candidate_repo,
        campaign,
        operation_id,
        edit_chat_id,
    } = execution;
    if !campaign.sampled {
        return Err("Agent improve campaign has no sampled Home assignment".to_owned());
    }
    if factory.kind() != "whip-do"
        || template
            .runtime_placement_id
            .as_deref()
            .is_none_or(|placement| placement.trim().is_empty())
    {
        return Err("hosted Agent improve needs an admitted WhippleScript placement".to_owned());
    }
    let tenant_id = funding.tenant_scope.clone();
    let current_main_cut = workspace
        .current_main_cut()
        .map_err(|error| error.to_string())?
        .ok_or("hosted improve replay has no Main cut")?;
    let replay = if let Some(operation_id) = operation_id {
        let key = HostedImproveInputKey {
            operation_id,
            actor,
            tenant_id: &tenant_id,
            agent_id,
            edit_chat_id: edit_chat_id.ok_or("hosted improve replay has no edit chat identity")?,
            campaign_ref: campaign.reference(),
            target_id,
            target_main_basis: &current_main_cut,
        };
        let reconciled = pair_admission.reconcile_saved_prefix(&key)?;
        let guard = wb.lock_unpoisoned();
        let cuts = guard.hosted_improve_scenario_cuts(&key)?;
        if reconciled != cuts.len() {
            return Err(
                "hosted improve ledger and scenario journal have different prefixes".into(),
            );
        }
        let definitions = guard
            .hosted_improve_input_cut(&key)?
            .ok_or("hosted improve replay has no retained definition cut")?;
        Some((cuts, definitions))
    } else {
        None
    };
    let engagement_scope = operation_id
        .map(|id| {
            crate::agent_improve_funding::operation_engagement_scope(&tenant_id, agent_id, id)
        })
        .unwrap_or_else(|| gen_id("agent-improve-attempt"));
    let mut meter = ManagedShadowMeter::new(wb, engagement_scope, funding);
    run_campaign_with_reservation_replay(
        CampaignSources {
            template,
            target_id,
            workspace,
            candidate_repo,
            campaign,
        },
        replay
            .as_ref()
            .map(|(cuts, definitions)| CampaignReplay { cuts, definitions }),
        |ordinal, scenario_id, exposure, prepared, judge, selection, prompt| {
            let target_main_basis = prepared
                .baseline_main_cut()
                .ok_or("hosted Agent improve has no authoring Main basis")?;
            let prompt_ref = format!(
                "agent-prompt:sha256:{}",
                hex::encode(Sha256::digest(prompt.as_bytes()))
            );
            let context = HostedImprovePairContext {
                actor,
                tenant_id: &tenant_id,
                agent_id,
                target_id,
                target_main_basis,
                campaign_ref: campaign.reference(),
                scenario_id,
                scenario_ref: prepared.scenario_ref(),
                prompt_ref: &prompt_ref,
            };
            pair_admission.with_pair(
                &context,
                prepared,
                Box::new(|| {
                    run_hosted_shadow_selection(
                        factory,
                        prepared,
                        gate.egress,
                        prompt,
                        judge,
                        selection,
                        &mut meter,
                    )
                }),
                Box::new(|selected, arms| {
                    let cut = HostedImproveScenarioCut::from_selected(
                        HostedScenarioSelection {
                            ordinal,
                            scenario_id,
                            exposure,
                            prompt,
                            campaign_ref: campaign.reference(),
                            prepared,
                            selected,
                        },
                        arms,
                    )?;
                    let Some(operation_id) = operation_id else {
                        return Ok(());
                    };
                    let edit_chat_id =
                        edit_chat_id.ok_or("hosted improve journal has no edit chat identity")?;
                    let key = HostedImproveInputKey {
                        operation_id,
                        actor,
                        tenant_id: &tenant_id,
                        agent_id,
                        edit_chat_id,
                        campaign_ref: campaign.reference(),
                        target_id,
                        target_main_basis,
                    };
                    wb.lock_unpoisoned()
                        .retain_hosted_improve_scenario_cut(&key, &cut)
                }),
            )
        },
        &mut || (gate.reserve_sealed)().map(Some),
    )
}

pub struct HostedCampaignExecution<'a> {
    pub factory: &'a dyn HarnessFactory,
    pub pair_admission: &'a dyn HostedImprovePairAdmission,
    pub template: &'a HarnessSpec,
    pub agent_id: &'a str,
    pub actor: &'a str,
    pub target_id: &'a str,
    pub workspace: &'a dyn Workspace,
    pub candidate_repo: &'a Path,
    pub campaign: &'a CampaignSnapshot,
    pub operation_id: Option<&'a str>,
    pub edit_chat_id: Option<&'a str>,
}

pub struct ManagedCampaignFunding {
    pub account_scope: String,
    pub tenant_scope: String,
    pub billing_scope: String,
    pub funding_ref: String,
    pub provider: String,
    pub funding_authority: crate::managed_funding::FundingAuthority,
}

fn run_campaign_with<F>(
    template: &HarnessSpec,
    target_id: &str,
    workspace: &dyn Workspace,
    candidate_repo: &Path,
    campaign: &CampaignSnapshot,
    run: F,
) -> Result<SelectedCampaign, String>
where
    F: FnMut(
        usize,
        &str,
        Exposure,
        &PreparedShadowPair,
        &dyn HostJudge,
        &HostSelection,
        &str,
    ) -> Result<SelectedShadowPair, String>,
{
    run_campaign_with_reservation(
        template,
        target_id,
        workspace,
        candidate_repo,
        campaign,
        run,
        &mut || Ok(None),
    )
}

fn run_campaign_with_reservation<F>(
    template: &HarnessSpec,
    target_id: &str,
    workspace: &dyn Workspace,
    candidate_repo: &Path,
    campaign: &CampaignSnapshot,
    run: F,
    reserve: &mut dyn FnMut() -> Result<Option<String>, String>,
) -> Result<SelectedCampaign, String>
where
    F: FnMut(
        usize,
        &str,
        Exposure,
        &PreparedShadowPair,
        &dyn HostJudge,
        &HostSelection,
        &str,
    ) -> Result<SelectedShadowPair, String>,
{
    run_campaign_with_reservation_replay(
        CampaignSources {
            template,
            target_id,
            workspace,
            candidate_repo,
            campaign,
        },
        None,
        run,
        reserve,
    )
}

struct CampaignSources<'a> {
    template: &'a HarnessSpec,
    target_id: &'a str,
    workspace: &'a dyn Workspace,
    candidate_repo: &'a Path,
    campaign: &'a CampaignSnapshot,
}

struct CampaignReplay<'a> {
    cuts: &'a [HostedImproveScenarioCut],
    definitions: &'a HostedImproveInputCut,
}

fn run_campaign_with_reservation_replay<F>(
    sources: CampaignSources<'_>,
    replay: Option<CampaignReplay<'_>>,
    mut run: F,
    reserve: &mut dyn FnMut() -> Result<Option<String>, String>,
) -> Result<SelectedCampaign, String>
where
    F: FnMut(
        usize,
        &str,
        Exposure,
        &PreparedShadowPair,
        &dyn HostJudge,
        &HostSelection,
        &str,
    ) -> Result<SelectedShadowPair, String>,
{
    let CampaignSources {
        template,
        target_id,
        workspace,
        candidate_repo,
        campaign,
    } = sources;
    if replay
        .as_ref()
        .is_some_and(|saved| saved.cuts.len() > campaign.evaluation_scenarios().len())
    {
        return Err("hosted improve journal exceeds its campaign".into());
    }
    let selection = campaign.selection();
    let mut scenarios = Vec::new();
    let mut readings: BTreeMap<String, GaugeEvidence> = BTreeMap::new();
    let mut lineage: Option<CampaignLineage> = None;
    let mut definitions: Option<(AgentDefinitionSnapshot, AgentDefinitionSnapshot)> = None;
    let mut open_verdict = None;
    let mut reservation_id = None;
    for (ordinal, scenario) in campaign.evaluation_scenarios().into_iter().enumerate() {
        if scenario.exposure == Exposure::Sealed && open_verdict.is_none() {
            let verdict = aggregate_verdict(
                &readings,
                &selection,
                scenarios.len(),
                campaign.open.gauges.len(),
            )?;
            if !verdict.proposable {
                if replay
                    .as_ref()
                    .is_some_and(|saved| saved.cuts.len() > scenarios.len())
                {
                    return Err(
                        "hosted improve journal contains sealed evidence after a failed open gate"
                            .into(),
                    );
                }
                let (baseline_definition, candidate_definition) =
                    definitions.ok_or("Agent improve campaign has no evaluated definitions")?;
                return Ok(SelectedCampaign {
                    target_id: target_id.to_owned(),
                    reference: campaign.reference.clone(),
                    scenarios,
                    open_verdict: verdict.clone(),
                    verdict,
                    sealed_available: campaign.private.sealed_scenarios.len(),
                    reservation_id,
                    lineage: lineage.ok_or("Agent improve campaign has no evaluated lineage")?,
                    baseline_definition,
                    candidate_definition,
                });
            }
            open_verdict = Some(verdict);
            reservation_id = reserve()?;
        }
        let expected_prompt_ref = format!(
            "agent-prompt:sha256:{}",
            hex::encode(Sha256::digest(scenario.prompt.as_bytes()))
        );
        let (this_lineage, this_definitions, evaluated) = if let Some((saved, cut)) = replay
            .as_ref()
            .and_then(|saved| saved.cuts.get(ordinal).map(|cut| (saved, cut)))
        {
            let exposure = match scenario.exposure {
                Exposure::Open => "open",
                Exposure::Sealed => "sealed",
            };
            if cut.ordinal != ordinal
                || cut.scenario_id != scenario.id
                || cut.exposure != exposure
                || cut.prompt_ref != expected_prompt_ref
                || cut.baseline_definition_ref != saved.definitions.baseline.identity
                || cut.candidate_definition_ref != saved.definitions.candidate.identity
            {
                return Err("hosted improve replay changed its pinned scenario".into());
            }
            let lineage = CampaignLineage {
                baseline_main_cut: cut.baseline_main_cut.clone(),
                baseline_definition_ref: cut.baseline_definition_ref.clone(),
                candidate_definition_ref: cut.candidate_definition_ref.clone(),
                baseline_package_ref: cut.baseline_package_ref.clone(),
                candidate_package_ref: cut.candidate_package_ref.clone(),
                baseline_discipline_ref: cut.baseline_discipline_ref.clone(),
                candidate_discipline_ref: cut.candidate_discipline_ref.clone(),
            };
            let evaluated = EvaluatedScenario {
                id: scenario.id.to_owned(),
                exposure: scenario.exposure,
                readings: cut
                    .gauges
                    .iter()
                    .map(|gauge| gauge.as_evidence())
                    .collect::<Result<Vec<_>, _>>()?,
            };
            (
                lineage,
                (
                    saved.definitions.baseline.clone(),
                    saved.definitions.candidate.clone(),
                ),
                evaluated,
            )
        } else {
            let scenario_root = tempfile::tempdir().map_err(|error| error.to_string())?;
            let prepared = prepare_native_shadow_pair_from_authoring(
                template,
                workspace,
                candidate_repo,
                scenario_root.path(),
            )
            .map_err(|error| error.to_string())?;
            let judge = campaign.judge_for(scenario.id)?;
            let selected = run(
                ordinal,
                scenario.id,
                scenario.exposure,
                &prepared,
                &judge,
                &selection,
                scenario.prompt,
            )?;
            let evidence = selected.evidence();
            if evidence.prompt_ref() != expected_prompt_ref
                || selected.judge_ref() != campaign.reference()
                || selected.selection_ref() != campaign.reference()
            {
                return Err(
                    "Agent improve scenario evidence differs from the pinned campaign".to_owned(),
                );
            }
            let lineage = CampaignLineage {
                baseline_main_cut: evidence.baseline_main_cut().unwrap_or("").to_owned(),
                baseline_definition_ref: evidence.baseline_definition_ref().to_owned(),
                candidate_definition_ref: evidence.candidate_definition_ref().to_owned(),
                baseline_package_ref: evidence.baseline().package_ref().to_owned(),
                candidate_package_ref: evidence.candidate().package_ref().to_owned(),
                baseline_discipline_ref: evidence.baseline().discipline_ref().to_owned(),
                candidate_discipline_ref: evidence.candidate().discipline_ref().to_owned(),
            };
            let definitions = prepared.evaluated_definitions(evidence)?;
            let evaluated = EvaluatedScenario {
                id: scenario.id.to_owned(),
                exposure: scenario.exposure,
                readings: selected.gauges().to_vec(),
            };
            (lineage, definitions, evaluated)
        };
        if this_lineage.baseline_main_cut.is_empty()
            || lineage
                .as_ref()
                .is_some_and(|expected| expected != &this_lineage)
            || definitions
                .as_ref()
                .is_some_and(|expected| expected != &this_definitions)
        {
            return Err(
                "Agent improve campaign mixed authoring cuts or package definitions".to_owned(),
            );
        }
        lineage = Some(this_lineage);
        definitions = Some(this_definitions);
        for gauge in &evaluated.readings {
            let entry = readings
                .entry(gauge.name.clone())
                .or_insert_with(|| GaugeEvidence {
                    name: gauge.name.clone(),
                    direction_up: gauge.direction_up,
                    resource: gauge.resource,
                    bar: gauge.bar.clone(),
                    baseline: Vec::new(),
                    candidate: Vec::new(),
                });
            if entry.direction_up != gauge.direction_up
                || entry.resource != gauge.resource
                || !same_bar(entry.bar.as_ref(), gauge.bar.as_ref())
                || gauge.baseline.len() != 1
                || gauge.candidate.len() != 1
            {
                return Err("Agent improve campaign mixed gauge definitions or readings".to_owned());
            }
            entry.baseline.push(gauge.baseline[0].clone());
            entry.candidate.push(gauge.candidate[0].clone());
        }
        scenarios.push(evaluated);
    }
    let verdict = aggregate_verdict(
        &readings,
        &selection,
        scenarios.len(),
        campaign.open.gauges.len(),
    )?;
    let (baseline_definition, candidate_definition) =
        definitions.ok_or("Agent improve campaign has no evaluated definitions")?;
    Ok(SelectedCampaign {
        target_id: target_id.to_owned(),
        reference: campaign.reference.clone(),
        scenarios,
        open_verdict: open_verdict.unwrap_or_else(|| verdict.clone()),
        verdict,
        sealed_available: campaign.private.sealed_scenarios.len(),
        reservation_id,
        lineage: lineage.ok_or("Agent improve campaign has no evaluated lineage")?,
        baseline_definition,
        candidate_definition,
    })
}

fn aggregate_verdict(
    readings: &BTreeMap<String, GaugeEvidence>,
    selection: &HostSelection,
    scenario_count: usize,
    gauge_count: usize,
) -> Result<Verdict, String> {
    let gauges = readings.values().cloned().collect::<Vec<_>>();
    if gauges.len() != gauge_count
        || gauges.iter().any(|gauge| {
            gauge.baseline.len() != scenario_count || gauge.candidate.len() != scenario_count
        })
    {
        return Err("Agent improve campaign omitted a gauge reading".to_owned());
    }
    Ok(improve_selection::select(&gauges, &selection.campaign))
}

fn same_bar(a: Option<&Bar>, b: Option<&Bar>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.chance == b.chance
                && a.stat == b.stat
                && a.ge == b.ge
                && a.threshold.to_bits() == b.threshold.to_bits()
        }
        _ => false,
    }
}

/// Adopt only an aggregate winner. Every evaluated scenario was checked
/// against one exact Main, definition, package, and discipline lineage.
pub fn adopt_selected_campaign(
    workspace: &dyn Workspace,
    selected: &SelectedCampaign,
) -> Result<Vec<String>, String> {
    if !selected.verdict.proposable {
        return Err("regularized campaign did not propose this Agent candidate".to_owned());
    }
    adopt_candidate(
        workspace,
        &selected.lineage.baseline_main_cut,
        &selected.baseline_definition,
        &selected.candidate_definition,
        &selected.lineage.candidate_package_ref,
        &selected.lineage.candidate_discipline_ref,
    )
}

impl CampaignSnapshot {
    pub(crate) fn gauge_names(&self) -> impl Iterator<Item = &str> {
        self.open.gauges.iter().map(|gauge| gauge.name.as_str())
    }

    /// `private_bytes` must come from host custody, never the Agent authoring
    /// target or a candidate workspace. Both exact sources are pinned together.
    pub fn parse(open_bytes: &[u8], private_bytes: &[u8]) -> Result<Self, String> {
        if open_bytes.is_empty()
            || private_bytes.is_empty()
            || open_bytes.len() > MAX_SOURCE_BYTES
            || private_bytes.len() > MAX_SOURCE_BYTES
        {
            return Err("Agent improve campaign source is missing or too large".to_owned());
        }
        let open_json = std::str::from_utf8(open_bytes)
            .map_err(|_| "open Agent improve source is not UTF-8")?
            .to_owned();
        let open: OpenSource = serde_json::from_slice(open_bytes)
            .map_err(|error| format!("invalid open Agent improve source: {error}"))?;
        let private: PrivateSource = serde_json::from_slice(private_bytes)
            .map_err(|_| "invalid private Agent improve source")?;
        validate(&open, &private)?;
        let open_ref = source_ref("open", open_bytes);
        let private_ref = source_ref("private", private_bytes);
        let mut digest = Sha256::new();
        digest.update((open_bytes.len() as u64).to_be_bytes());
        digest.update(open_bytes);
        digest.update((private_bytes.len() as u64).to_be_bytes());
        digest.update(private_bytes);
        let reference = format!("agent-campaign:sha256:{}", hex::encode(digest.finalize()));
        Ok(Self {
            open_json,
            open,
            private,
            open_ref,
            private_ref,
            reference,
            sampled: false,
        })
    }

    pub(super) fn with_sampled_assignment(mut self) -> Self {
        self.sampled = true;
        self
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn open_ref(&self) -> &str {
        &self.open_ref
    }

    pub fn private_ref(&self) -> &str {
        &self.private_ref
    }

    /// Safe to project into an edit chat: no checks or sealed inputs occur in
    /// this source. The host must never hand it the CampaignSnapshot itself.
    pub fn proposer_open_json(&self) -> &str {
        &self.open_json
    }

    pub fn evaluation_scenarios(&self) -> Vec<EvaluationScenario<'_>> {
        self.open
            .scenarios
            .iter()
            .map(|scenario| EvaluationScenario {
                id: &scenario.id,
                prompt: &scenario.prompt,
                exposure: Exposure::Open,
            })
            .chain(
                self.private
                    .sealed_scenarios
                    .iter()
                    .map(|scenario| EvaluationScenario {
                        id: &scenario.id,
                        prompt: &scenario.prompt,
                        exposure: Exposure::Sealed,
                    }),
            )
            .collect()
    }

    pub fn selection(&self) -> HostSelection {
        let source = &self.open.selection;
        HostSelection {
            reference: self.reference.clone(),
            campaign: Campaign {
                ascend: source
                    .ascend
                    .iter()
                    .map(|(name, reach)| {
                        (
                            name.clone(),
                            reach.as_ref().map(|reach| Reach {
                                ge: reach.ge,
                                threshold: reach.value,
                            }),
                        )
                    })
                    .collect(),
                sacrifice: source.sacrifice.clone(),
                within_percent: source.within_percent.clone(),
                floors: source
                    .floors
                    .iter()
                    .map(|(name, floor)| (name.clone(), (floor.ge, floor.value)))
                    .collect(),
                repair: source.repair,
            },
        }
    }

    pub fn judge_for(&self, scenario_id: &str) -> Result<ScenarioJudge, String> {
        let checks = self
            .private
            .open_checks
            .get(scenario_id)
            .or_else(|| {
                self.private
                    .sealed_scenarios
                    .iter()
                    .find(|scenario| scenario.id == scenario_id)
                    .map(|scenario| &scenario.checks)
            })
            .ok_or("Agent improve scenario is absent from the pinned campaign")?;
        Ok(ScenarioJudge {
            reference: self.reference.clone(),
            gauges: self
                .open
                .gauges
                .iter()
                .map(|gauge| HostGauge {
                    name: gauge.name.clone(),
                    direction_up: true,
                    resource: false,
                    bar: gauge.minimum_pass_rate.map(|threshold| Bar {
                        chance: true,
                        stat: None,
                        ge: true,
                        threshold,
                    }),
                })
                .collect(),
            checks: checks.clone(),
        })
    }
}

fn source_ref(kind: &str, bytes: &[u8]) -> String {
    format!(
        "agent-campaign-{kind}:sha256:{}",
        hex::encode(Sha256::digest(bytes))
    )
}

pub struct ScenarioJudge {
    reference: String,
    gauges: Vec<HostGauge>,
    checks: BTreeMap<String, TextCheck>,
}

impl HostJudge for ScenarioJudge {
    fn reference(&self) -> &str {
        &self.reference
    }

    fn gauges(&self) -> &[HostGauge] {
        &self.gauges
    }

    fn read(
        &self,
        gauge: &HostGauge,
        turn: &ShadowTurn,
        _worktree: &Path,
    ) -> Result<Reading, String> {
        let check = self
            .checks
            .get(&gauge.name)
            .ok_or("pinned Agent improve judge has no reading for a gauge")?;
        let passed = check.passes(&turn.outcome().assistant_text);
        Ok(Reading {
            score: if passed { 1.0 } else { 0.0 },
            passed: Some(passed),
        })
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_prompt(prompt: &str) -> bool {
    !prompt.trim().is_empty() && prompt.len() <= MAX_PROMPT_BYTES
}

fn validate_checks(
    checks: &BTreeMap<String, TextCheck>,
    names: &BTreeSet<String>,
) -> Result<(), String> {
    if checks.keys().cloned().collect::<BTreeSet<_>>() != *names {
        return Err("every Agent improve scenario needs exactly one check per gauge".to_owned());
    }
    if checks
        .values()
        .any(|check| check.text().is_empty() || check.text().len() > MAX_CHECK_BYTES)
    {
        return Err("Agent improve text check is empty or too large".to_owned());
    }
    Ok(())
}

fn validate(open: &OpenSource, private: &PrivateSource) -> Result<(), String> {
    if open.schema != OPEN_SCHEMA || private.schema != PRIVATE_SCHEMA {
        return Err("unsupported Agent improve campaign source schema".to_owned());
    }
    if open.gauges.is_empty()
        || open.gauges.len() > MAX_GAUGES
        || open.scenarios.is_empty()
        || open.scenarios.len() + private.sealed_scenarios.len() > MAX_SCENARIOS
    {
        return Err(
            "Agent improve campaign has no gauges or open scenarios, or exceeds its size limit"
                .to_owned(),
        );
    }
    let mut names = BTreeSet::new();
    for gauge in &open.gauges {
        if !valid_id(&gauge.name)
            || !names.insert(gauge.name.clone())
            || gauge.description.trim().is_empty()
            || gauge.description.len() > 1024
            || gauge
                .minimum_pass_rate
                .is_some_and(|rate| !rate.is_finite() || !(0.0..=1.0).contains(&rate))
        {
            return Err("Agent improve gauge name, description, or bar is invalid".to_owned());
        }
    }
    let selection = &open.selection;
    if (!selection.repair && selection.ascend.is_empty())
        || selection.ascend.keys().any(|name| !names.contains(name))
        || selection
            .sacrifice
            .iter()
            .any(|name| !names.contains(name) || selection.ascend.contains_key(name))
        || selection
            .within_percent
            .iter()
            .any(|(name, percent)| !names.contains(name) || !percent.is_finite() || *percent <= 0.0)
        || selection.floors.iter().any(|(name, floor)| {
            !names.contains(name) || !floor.value.is_finite() || !(0.0..=1.0).contains(&floor.value)
        })
        || selection
            .ascend
            .values()
            .flatten()
            .any(|reach| !reach.value.is_finite() || !(0.0..=1.0).contains(&reach.value))
    {
        return Err(
            "Agent improve selection names unknown gauges or invalid thresholds".to_owned(),
        );
    }
    let mut ids = BTreeSet::new();
    for scenario in &open.scenarios {
        if !valid_id(&scenario.id)
            || !ids.insert(scenario.id.clone())
            || !valid_prompt(&scenario.prompt)
        {
            return Err("Agent improve open scenario id or prompt is invalid".to_owned());
        }
    }
    if private.open_checks.keys().cloned().collect::<BTreeSet<_>>() != ids {
        return Err(
            "private Agent improve checks do not match the open scenario roster".to_owned(),
        );
    }
    for checks in private.open_checks.values() {
        validate_checks(checks, &names)?;
    }
    for scenario in &private.sealed_scenarios {
        if !valid_id(&scenario.id)
            || !ids.insert(scenario.id.clone())
            || !valid_prompt(&scenario.prompt)
        {
            return Err("Agent improve sealed scenario id or prompt is invalid".to_owned());
        }
        validate_checks(&scenario.checks, &names)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_support::LockUnpoisoned;
    use gaugedesk_harness::{
        sandbox::SandboxPolicy, AllowAllGate, Harness, HarnessFactory, Observation, TurnOutcome,
    };
    use std::io;
    use std::sync::Mutex;

    const OPEN: &str = r#"{
      "schema":"gaugedesk.agent-improve.open.v1",
      "gauges":[{"name":"quality","description":"Return the requested token","minimum_pass_rate":1.0}],
      "selection":{"ascend":{"quality":null}},
      "scenarios":[{"id":"open-1","prompt":"Return alpha"}]
    }"#;
    const PRIVATE: &str = r#"{
      "schema":"gaugedesk.agent-improve.private.v1",
      "open_checks":{"open-1":{"quality":{"kind":"assistant-contains","text":"alpha"}}},
      "sealed_scenarios":[{"id":"sealed-1","prompt":"Return beta",
        "checks":{"quality":{"kind":"assistant-contains","text":"beta"}}}]
    }"#;

    #[test]
    fn campaign_identity_and_proposer_view_keep_checks_and_sealed_inputs_private() {
        let campaign = CampaignSnapshot::parse(OPEN.as_bytes(), PRIVATE.as_bytes()).unwrap();
        assert!(campaign.proposer_open_json().contains("Return alpha"));
        assert!(!campaign.proposer_open_json().contains("Return beta"));
        assert!(!campaign.proposer_open_json().contains("assistant-contains"));
        assert_eq!(campaign.evaluation_scenarios().len(), 2);
        assert_eq!(
            campaign.evaluation_scenarios()[1].exposure,
            Exposure::Sealed
        );
        assert_ne!(campaign.open_ref(), campaign.private_ref());
        let changed = PRIVATE.replace("Return beta", "Return gamma");
        assert_ne!(
            campaign.reference(),
            CampaignSnapshot::parse(OPEN.as_bytes(), changed.as_bytes())
                .unwrap()
                .reference()
        );
        let judge = campaign.judge_for("sealed-1").unwrap();
        assert_eq!(judge.reference(), campaign.reference());
        assert_eq!(judge.gauges()[0].name, "quality");
        assert!(campaign.selection().campaign.ascend.contains_key("quality"));
    }

    #[test]
    fn missing_private_checks_and_duplicate_scenario_ids_fail_closed() {
        let no_check = PRIVATE.replace("\"quality\":{\"kind\"", "\"other\":{\"kind\"");
        assert!(
            CampaignSnapshot::parse(OPEN.as_bytes(), no_check.as_bytes())
                .err()
                .unwrap()
                .contains("exactly one check")
        );
        let duplicate = PRIVATE.replace("sealed-1", "open-1");
        assert!(
            CampaignSnapshot::parse(OPEN.as_bytes(), duplicate.as_bytes())
                .err()
                .unwrap()
                .contains("sealed scenario id")
        );
        assert!(CampaignSnapshot::parse(OPEN.as_bytes(), b"")
            .err()
            .unwrap()
            .contains("missing"));
    }

    #[test]
    fn text_checks_are_exact_and_do_not_leak_expected_text_in_errors() {
        let check = TextCheck::Equals {
            text: "exact".to_owned(),
        };
        assert!(check.passes("exact"));
        assert!(!check.passes("exact extra"));
        assert!(TextCheck::Excludes {
            text: "secret".to_owned()
        }
        .passes("safe"));
    }

    struct FakeFactory {
        open_passes: bool,
        sealed_passes: bool,
    }
    struct FakeHarness {
        candidate: bool,
        open_passes: bool,
        sealed_passes: bool,
    }

    impl HarnessFactory for FakeFactory {
        fn kind(&self) -> &'static str {
            "whip"
        }

        fn create(&self, spec: &HarnessSpec) -> io::Result<Box<dyn Harness>> {
            Ok(Box::new(FakeHarness {
                candidate: spec.chat_id.ends_with(":candidate"),
                open_passes: self.open_passes,
                sealed_passes: self.sealed_passes,
            }))
        }

        fn credential_status(
            &self,
            _provider: &str,
            _capability: Option<&dyn gaugedesk_harness::CredentialCapability>,
        ) -> gaugedesk_harness::CredentialProbe {
            gaugedesk_harness::CredentialProbe::Ready
        }
    }

    impl Harness for FakeHarness {
        fn run_turn(
            &mut self,
            _gate: &dyn EgressGate,
            prompt: &str,
            _images: &[gaugedesk_harness::ImageContent],
            _sink: &mut dyn FnMut(&Observation),
        ) -> io::Result<TurnOutcome> {
            Ok(TurnOutcome {
                assistant_text: if self.candidate {
                    if prompt.contains("alpha") && self.open_passes {
                        "alpha"
                    } else if prompt.contains("beta") && self.sealed_passes {
                        "beta"
                    } else {
                        "wrong"
                    }
                } else {
                    "wrong"
                }
                .to_owned(),
                ..Default::default()
            })
        }
    }

    struct HostedFakeFactory;

    #[derive(Default)]
    struct RecordingPairAdmission(Mutex<Vec<String>>, Mutex<Vec<String>>);

    impl HostedImprovePairAdmission for RecordingPairAdmission {
        fn with_pair(
            &self,
            context: &HostedImprovePairContext<'_>,
            prepared: &PreparedShadowPair,
            run: Box<dyn FnOnce() -> Result<SelectedShadowPair, String> + '_>,
            retain: crate::agent_improve::HostedImprovePairRetainer<'_>,
        ) -> Result<SelectedShadowPair, String> {
            if context.actor.is_empty()
                || context.tenant_id.is_empty()
                || context.campaign_ref.is_empty()
                || context.scenario_id.is_empty()
                || context.agent_id.is_empty()
                || context.target_id.is_empty()
                || context.target_main_basis != prepared.baseline_main_cut().unwrap_or("")
                || context.scenario_ref != prepared.scenario_ref()
                || !context.prompt_ref.starts_with("agent-prompt:sha256:")
            {
                return Err("hosted pair identity is incomplete".to_owned());
            }
            let baseline = prepared
                .baseline_spec()
                .runtime_placement_id
                .as_deref()
                .ok_or("baseline has no hosted placement")?;
            let candidate = prepared
                .candidate_spec()
                .runtime_placement_id
                .as_deref()
                .ok_or("candidate has no hosted placement")?;
            if baseline == candidate {
                return Err("hosted arms reused a placement".to_owned());
            }
            self.1
                .lock()
                .unwrap()
                .extend([baseline.to_owned(), candidate.to_owned()]);
            self.0.lock().unwrap().push("admit".to_owned());
            let result = run().and_then(|selected| {
                retain(
                    &selected,
                    [
                        crate::agent_improve::HostedImproveArmTerminal {
                            label: "baseline".into(),
                            command_id: "command:baseline".into(),
                            epoch: 1,
                            evidence_ref: "sha256:baseline".into(),
                            usage_id: "usage:baseline".into(),
                            wall_millis: 1,
                        },
                        crate::agent_improve::HostedImproveArmTerminal {
                            label: "candidate".into(),
                            command_id: "command:candidate".into(),
                            epoch: 1,
                            evidence_ref: "sha256:candidate".into(),
                            usage_id: "usage:candidate".into(),
                            wall_millis: 1,
                        },
                    ],
                )?;
                Ok(selected)
            });
            self.0.lock().unwrap().push(if result.is_ok() {
                "complete".to_owned()
            } else {
                "fail".to_owned()
            });
            result
        }
    }

    impl HarnessFactory for HostedFakeFactory {
        fn kind(&self) -> &'static str {
            "whip-do"
        }

        fn create(&self, spec: &HarnessSpec) -> io::Result<Box<dyn Harness>> {
            if !spec
                .runtime_placement_id
                .as_deref()
                .is_some_and(|placement| {
                    placement.starts_with("improve-placement:")
                        && (placement.ends_with(":baseline") || placement.ends_with(":candidate"))
                })
            {
                return Err(io::Error::other("wrong hosted placement"));
            }
            let candidate = spec.chat_id.ends_with(":candidate");
            let context =
                std::fs::read_to_string(spec.worktree.join(".gaugedesk-runtime/agent/AGENTS.md"))?;
            if context.contains("hosted candidate") != candidate {
                return Err(io::Error::other("hosted Agent context crossed arms"));
            }
            Ok(Box::new(HostedFakeHarness { candidate }))
        }

        fn credential_status(
            &self,
            _provider: &str,
            _capability: Option<&dyn gaugedesk_harness::CredentialCapability>,
        ) -> gaugedesk_harness::CredentialProbe {
            gaugedesk_harness::CredentialProbe::Ready
        }
    }

    struct HostedFakeHarness {
        candidate: bool,
    }

    impl Harness for HostedFakeHarness {
        fn run_turn(
            &mut self,
            _gate: &dyn EgressGate,
            prompt: &str,
            _images: &[gaugedesk_harness::ImageContent],
            _sink: &mut dyn FnMut(&Observation),
        ) -> io::Result<TurnOutcome> {
            Ok(TurnOutcome {
                assistant_text: if self.candidate {
                    prompt.replace("Return ", "")
                } else {
                    "wrong".to_owned()
                },
                managed_usage: Some(gaugedesk_harness::ModelUsage {
                    usage_ref: gen_id("hosted-usage"),
                    provider: "cloudflare-ai-gateway".to_owned(),
                    model: "test-model".to_owned(),
                    input_tokens: 2,
                    output_tokens: 1,
                }),
                ..Default::default()
            })
        }
    }

    #[test]
    fn hosted_campaign_uses_distinct_placements_and_one_turn_meter() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let mut guard = workbench.lock_unpoisoned();
        let billing_scope = crate::account::ACCOUNT_SCOPE.to_owned();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let funding_authority = crate::managed_funding::FundingAuthority::new(
            gaugedesk_core::ids::AuthorityId::new("test-funding-service"),
            crate::managed_funding::FundingEnvironment::Test,
        );
        let plan = crate::managed_inference::ManagedInferencePlan {
            plan: "hosted-test".to_owned(),
            status: crate::managed_inference::ManagedPlanStatus::Active,
            included_tokens: 0,
        };
        let record = crate::managed_funding::FundingRecord {
            record: crate::managed_inference::ManagedPlanRecord {
                id: "managed-inference".to_owned(),
                op: crate::library::RecordOp::Upsert,
                subscription: plan,
            },
            provenance: Some(crate::managed_funding::FundingEvidence {
                v: 1,
                issuer: gaugedesk_core::ids::AuthorityId::new("test-funding-service"),
                scope: gaugedesk_core::ids::ScopeId::new(&billing_scope),
                source_id: "test-subscription".to_owned(),
                environment: crate::managed_funding::FundingEnvironment::Test,
                verified_at: now - 10,
                valid_from: now - 100,
                valid_until: now + 1000,
            }),
        };
        let funding_ref = crate::managed_funding::decide(
            &gaugedesk_core::ids::ScopeId::new(&billing_scope),
            std::slice::from_ref(&record),
            &funding_authority.context(now),
        )
        .unwrap()
        .reference();
        guard
            .store
            .append_record(
                &billing_scope,
                crate::managed_inference::MANAGED_PLAN_KIND,
                &serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let target_root = guard.targets_dir().join(&target_id);
        let workspace = gaugedesk_workspace::Instance::open_at(&target_root);
        let candidate_repo = root.path().join("candidate");
        crate::agent_improve_adoption::AgentDefinitionSnapshot::from_main(&workspace)
            .unwrap()
            .materialize(&candidate_repo)
            .unwrap();
        drop(guard);
        std::fs::write(candidate_repo.join("agent/AGENTS.md"), "hosted candidate\n").unwrap();
        let campaign = CampaignSnapshot::parse(OPEN.as_bytes(), PRIVATE.as_bytes())
            .unwrap()
            .with_sampled_assignment();
        let mut hosted_template = template(root.path());
        hosted_template.runtime_placement_id = Some("improve-placement".to_owned());
        hosted_template.provider = Some("cloudflare-ai-gateway".to_owned());
        hosted_template.credential_ref = Some(funding_ref.clone());
        let mut exposures = 0;
        let pair_admission = RecordingPairAdmission::default();
        let mut reserve_sealed = || {
            exposures += 1;
            Ok("sealed-reservation".to_owned())
        };
        let selected = run_hosted_managed_campaign_with_reservation(
            &workbench,
            HostedCampaignExecution {
                factory: &HostedFakeFactory,
                pair_admission: &pair_admission,
                template: &hosted_template,
                agent_id: "agent:hosted-test",
                actor: "authority:hosted-test",
                target_id: &target_id,
                workspace: &workspace,
                candidate_repo: &candidate_repo,
                campaign: &campaign,
                operation_id: None,
                edit_chat_id: None,
            },
            NativeCampaignGate {
                egress: &AllowAllGate,
                reserve_sealed: &mut reserve_sealed,
            },
            ManagedCampaignFunding {
                account_scope: billing_scope.clone(),
                tenant_scope: crate::org::ORG_SCOPE.to_owned(),
                billing_scope: billing_scope.clone(),
                funding_ref: funding_ref.clone(),
                provider: "cloudflare-ai-gateway".to_owned(),
                funding_authority: funding_authority.clone(),
            },
        )
        .unwrap();
        assert!(selected.reviewer_verdict().proposable);
        assert_eq!(selected.sealed_count(), 1);
        assert_eq!(exposures, 1);
        assert_eq!(
            *pair_admission.0.lock().unwrap(),
            ["admit", "complete", "admit", "complete"]
        );
        let placement_rows = pair_admission.1.lock().unwrap();
        let placements = placement_rows
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(placements.len(), selected.scenarios.len() * 2);
        let guard = workbench.lock_unpoisoned();
        let reservations =
            crate::managed_inference::fold_reservations(guard.store_ref(), &billing_scope).unwrap();
        assert_eq!(reservations.reserved, 4);
        assert_eq!(reservations.settled, 4);
        assert_eq!(reservations.outstanding, 0);
        assert!(!guard
            .store_ref()
            .records(&billing_scope, crate::managed_inference::MANAGED_USAGE_KIND)
            .unwrap()
            .iter()
            .any(|row| row.contains("Return beta")));
        assert_eq!(
            crate::managed_inference::fold_usage(guard.store_ref(), &billing_scope, 0)
                .unwrap()
                .total_tokens,
            12
        );
        drop(guard);
        let mut meter = ManagedShadowMeter::new(
            &workbench,
            gen_id("agent-improve-attempt"),
            ManagedCampaignFunding {
                account_scope: billing_scope.clone(),
                tenant_scope: crate::org::ORG_SCOPE.to_owned(),
                billing_scope: billing_scope.clone(),
                funding_ref,
                provider: "cloudflare-ai-gateway".to_owned(),
                funding_authority,
            },
        );
        let interrupted =
            crate::agent_improve::ShadowTurnMeter::reserve(&mut meter, &hosted_template).unwrap();
        crate::agent_improve::ShadowTurnMeter::settle(&mut meter, &interrupted, None).unwrap();
        let missing_usage =
            crate::agent_improve::ShadowTurnMeter::reserve(&mut meter, &hosted_template).unwrap();
        assert!(crate::agent_improve::ShadowTurnMeter::settle(
            &mut meter,
            &missing_usage,
            Some(&TurnOutcome::default()),
        )
        .unwrap_err()
        .contains("without usage evidence"));
        let mut guard = workbench.lock_unpoisoned();
        let mut suspended = record;
        suspended.record.subscription.status =
            crate::managed_inference::ManagedPlanStatus::Suspended;
        guard
            .store
            .append_record(
                &billing_scope,
                crate::managed_inference::MANAGED_PLAN_KIND,
                &serde_json::to_string(&suspended).unwrap(),
            )
            .unwrap();
        drop(guard);
        assert!(
            crate::agent_improve::ShadowTurnMeter::reserve(&mut meter, &hosted_template)
                .unwrap_err()
                .contains("Suspended")
        );
        let guard = workbench.lock_unpoisoned();
        let reservations =
            crate::managed_inference::fold_reservations(guard.store_ref(), &billing_scope).unwrap();
        assert_eq!(
            (
                reservations.reserved,
                reservations.settled,
                reservations.released
            ),
            (6, 4, 2)
        );
    }

    fn template(root: &Path) -> HarnessSpec {
        let worktree = root.join("template");
        HarnessSpec {
            chat_id: "improve-template".to_owned(),
            worktree: worktree.clone(),
            mode: gaugedesk_harness::ChatMode::Use,
            package_root: None,
            package_version_ref: None,
            policy_epoch: Some(1),
            signed_policy_envelope: Some("same policy".to_owned()),
            provider_binding_ref: None,
            credential_ref: None,
            placement_ceiling_ref: None,
            workspace_targets: Vec::new(),
            runtime_placement_id: None,
            provider: Some("openai".to_owned()),
            model: Some("test-model".to_owned()),
            base_url: None,
            thinking: None,
            system_prompt: None,
            credential_capability: None,
            sandbox: SandboxPolicy::new(vec![worktree.clone()]).read_only(vec![
                worktree.join(".whipple"),
                worktree.join(".gaugedesk-runtime"),
            ]),
            roster: Vec::new(),
        }
    }

    #[test]
    fn campaign_aggregates_open_and_sealed_pairs_before_stale_safe_adoption() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let mut guard = workbench.lock_unpoisoned();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let candidate_repo = root.path().join("candidate");
        crate::agent_improve_adoption::AgentDefinitionSnapshot::from_main(workspace.as_ref())
            .unwrap()
            .materialize(&candidate_repo)
            .unwrap();
        std::fs::write(candidate_repo.join("agent/AGENTS.md"), "selected method\n").unwrap();
        let source = CampaignSnapshot::parse(OPEN.as_bytes(), PRIVATE.as_bytes()).unwrap();
        let run = || {
            run_campaign_with(
                &template(root.path()),
                &target_id,
                workspace.as_ref(),
                &candidate_repo,
                &source,
                |_, _, _, prepared, judge, selection, prompt| {
                    crate::agent_improve::run_shadow_selection_with_factory(
                        &FakeFactory {
                            open_passes: true,
                            sealed_passes: true,
                        },
                        prepared,
                        &AllowAllGate,
                        prompt,
                        judge,
                        selection,
                    )
                },
            )
            .unwrap()
        };
        let selected = run();
        assert_eq!(selected.open_scenario_ids(), vec!["open-1"]);
        assert_eq!(selected.sealed_count(), 1);
        assert!(selected.open_verdict().proposable);
        assert_eq!(selected.sealed_available(), 1);
        assert!(selected.reviewer_verdict().proposable);
        let card = selected.reviewer_card(&source).unwrap();
        let serialized = serde_json::to_string(&card).unwrap();
        assert_eq!(card.holdout_status, "unheld-out");
        assert_eq!(card.sealed_evaluated, 1);
        assert_eq!(card.open_verdict.lines[0].delta, "better");
        assert!(!serialized.contains("Return beta"));
        assert!(!serialized.contains("assistant-contains"));
        assert_eq!(selected.reviewer_verdict().lines[0].baseline, Some(0.0));
        assert_eq!(selected.reviewer_verdict().lines[0].candidate, Some(1.0));
        let unrelated_id = crate::library::gen_id("unrelated-improve-edit");
        let unrelated = workspace.create_engagement(&unrelated_id).unwrap();
        unrelated.write_file("notes.md", "human work").unwrap();
        unrelated.commit_turn("human work").unwrap();
        assert_eq!(
            unrelated.merge_into_main().unwrap(),
            gaugedesk_workspace::MergeOutcome::Clean
        );
        workspace.remove_engagement(&unrelated_id).unwrap();
        assert!(adopt_selected_campaign(workspace.as_ref(), &selected)
            .unwrap_err()
            .contains("draft changed"));
        let selected = run();
        assert_eq!(
            adopt_selected_campaign(workspace.as_ref(), &selected).unwrap(),
            vec!["agent/AGENTS.md"]
        );
        assert_eq!(
            guard
                .register_agent_improve_campaign(
                    crate::DEFAULT_AGENT,
                    OPEN.as_bytes(),
                    PRIVATE.as_bytes(),
                )
                .unwrap(),
            source.reference()
        );
        let other = guard
            .create_archetype("Other".to_owned(), crate::library::AgentKind::Work, None)
            .ok()
            .expect("second Agent is created");
        guard
            .register_agent_improve_campaign(&other.id, OPEN.as_bytes(), PRIVATE.as_bytes())
            .unwrap();
        assert!(guard
            .append_agent_improve_evidence(&other.id, &source, &selected)
            .unwrap_err()
            .contains("another authoring target"));
        let evidence_id = guard
            .append_agent_improve_evidence(crate::DEFAULT_AGENT, &source, &selected)
            .unwrap();
        let rows = guard
            .store
            .records(
                crate::library::LIBRARY_SCOPE,
                "agent_improve_campaign_evidence",
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].contains("Return beta"));
        assert!(!rows[0].contains("selected method"));
        let hosted_id = guard
            .append_hosted_agent_improve_evidence(crate::DEFAULT_AGENT, &source, &selected, "op")
            .unwrap();
        assert_eq!(
            guard
                .append_hosted_agent_improve_evidence(
                    crate::DEFAULT_AGENT,
                    &source,
                    &selected,
                    "op"
                )
                .unwrap(),
            hosted_id
        );
        assert_eq!(
            guard
                .store
                .records(
                    crate::library::LIBRARY_SCOPE,
                    "agent_improve_campaign_evidence"
                )
                .unwrap()
                .len(),
            2
        );
        drop(guard);
        drop(workbench);
        let reopened = crate::open_workbench(root.path()).unwrap();
        let mut guard = reopened.lock_unpoisoned();
        assert_eq!(
            guard
                .append_hosted_agent_improve_evidence(
                    crate::DEFAULT_AGENT,
                    &source,
                    &selected,
                    "op"
                )
                .unwrap(),
            hosted_id
        );
        let evidence = guard
            .agent_improve_evidence(crate::DEFAULT_AGENT, &evidence_id)
            .unwrap();
        assert_eq!(evidence.card.campaign_ref, source.reference());
        assert_eq!(evidence.card.holdout_status, "unheld-out");
        assert!(evidence.card.final_verdict.proposable);
        assert!(
            guard
                .adopt_agent_improve_evidence_for_source_owner(
                    crate::DEFAULT_AGENT,
                    &evidence_id,
                    None,
                )
                .unwrap_err()
                .contains("sealed evaluation is incomplete")
        );
    }

    #[test]
    fn reconciled_scenario_prefix_replays_readings_without_reexecuting_its_arms() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let guard = workbench.lock_unpoisoned();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let candidate_repo = root.path().join("candidate");
        AgentDefinitionSnapshot::from_main(workspace.as_ref())
            .unwrap()
            .materialize(&candidate_repo)
            .unwrap();
        std::fs::write(candidate_repo.join("agent/AGENTS.md"), "selected method\n").unwrap();
        let source = CampaignSnapshot::parse(OPEN.as_bytes(), PRIVATE.as_bytes()).unwrap();
        let template = template(root.path());
        fn evaluate_case(
            _: usize,
            _: &str,
            _: Exposure,
            prepared: &PreparedShadowPair,
            judge: &dyn HostJudge,
            selection: &HostSelection,
            prompt: &str,
        ) -> Result<SelectedShadowPair, String> {
            crate::agent_improve::run_shadow_selection_with_factory(
                &FakeFactory {
                    open_passes: true,
                    sealed_passes: true,
                },
                prepared,
                &AllowAllGate,
                prompt,
                judge,
                selection,
            )
        }
        let original = run_campaign_with_reservation(
            &template,
            &target_id,
            workspace.as_ref(),
            &candidate_repo,
            &source,
            evaluate_case,
            &mut || Ok(Some("reservation:one".into())),
        )
        .unwrap();
        let definitions = HostedImproveInputCut {
            baseline: original.baseline_definition.clone(),
            candidate: original.candidate_definition.clone(),
        };
        let ordered = source.evaluation_scenarios();
        let cuts = original
            .scenarios
            .iter()
            .enumerate()
            .map(|(ordinal, evaluated)| {
                let scenario = &ordered[ordinal];
                HostedImproveScenarioCut {
                    ordinal,
                    scenario_id: evaluated.id.clone(),
                    exposure: match evaluated.exposure {
                        Exposure::Open => "open",
                        Exposure::Sealed => "sealed",
                    }
                    .into(),
                    scenario_ref: format!("scenario:{ordinal}"),
                    prompt_ref: format!(
                        "agent-prompt:sha256:{}",
                        hex::encode(Sha256::digest(scenario.prompt.as_bytes()))
                    ),
                    baseline_main_cut: original.lineage.baseline_main_cut.clone(),
                    baseline_definition_ref: original.lineage.baseline_definition_ref.clone(),
                    candidate_definition_ref: original.lineage.candidate_definition_ref.clone(),
                    baseline_package_ref: original.lineage.baseline_package_ref.clone(),
                    candidate_package_ref: original.lineage.candidate_package_ref.clone(),
                    baseline_discipline_ref: original.lineage.baseline_discipline_ref.clone(),
                    candidate_discipline_ref: original.lineage.candidate_discipline_ref.clone(),
                    gauges: evaluated
                        .readings
                        .iter()
                        .map(crate::agent_improve_scenario_journal::HostedImproveGaugeSample::from_evidence)
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap(),
                    arms: ["baseline", "candidate"].map(|label| {
                        crate::agent_improve::HostedImproveArmTerminal {
                            label: label.into(),
                            command_id: format!("command:{ordinal}:{label}"),
                            epoch: 1,
                            evidence_ref: format!("sha256:{}", "a".repeat(64)),
                            usage_id: format!("usage:{ordinal}:{label}"),
                            wall_millis: 1,
                        }
                    }),
                }
            })
            .collect::<Vec<_>>();
        let sources = || CampaignSources {
            template: &template,
            target_id: &target_id,
            workspace: workspace.as_ref(),
            candidate_repo: &candidate_repo,
            campaign: &source,
        };
        let full = run_campaign_with_reservation_replay(
            sources(),
            Some(CampaignReplay {
                cuts: &cuts,
                definitions: &definitions,
            }),
            |_, _, _, _, _, _, _| panic!("a replayed arm must not execute"),
            &mut || Ok(Some("reservation:one".into())),
        )
        .unwrap();
        assert_eq!(full.scenarios.len(), 2);
        assert_eq!(
            full.reviewer_verdict().proposable,
            original.reviewer_verdict().proposable
        );
        assert_eq!(
            full.reviewer_verdict().lines[0].candidate,
            original.reviewer_verdict().lines[0].candidate
        );
        let mut new_runs = 0;
        let partial = run_campaign_with_reservation_replay(
            sources(),
            Some(CampaignReplay {
                cuts: &cuts[..1],
                definitions: &definitions,
            }),
            |ordinal, id, exposure, prepared, judge, selection, prompt| {
                new_runs += 1;
                evaluate_case(ordinal, id, exposure, prepared, judge, selection, prompt)
            },
            &mut || Ok(Some("reservation:one".into())),
        )
        .unwrap();
        assert_eq!(new_runs, 1);
        assert_eq!(
            partial.reviewer_verdict().proposable,
            original.reviewer_verdict().proposable
        );
        let mut changed = cuts.clone();
        changed[0].prompt_ref = "another prompt".into();
        assert!(run_campaign_with_reservation_replay(
            sources(),
            Some(CampaignReplay {
                cuts: &changed,
                definitions: &definitions,
            }),
            |_, _, _, _, _, _, _| panic!("a changed replay must not execute"),
            &mut || Ok(Some("reservation:one".into())),
        )
        .is_err());
    }

    #[test]
    fn failed_open_stage_does_not_expose_sealed_case() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let guard = workbench.lock_unpoisoned();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let candidate_repo = root.path().join("candidate");
        crate::agent_improve_adoption::AgentDefinitionSnapshot::from_main(workspace.as_ref())
            .unwrap()
            .materialize(&candidate_repo)
            .unwrap();
        std::fs::write(candidate_repo.join("agent/AGENTS.md"), "selected method\n").unwrap();
        let source = CampaignSnapshot::parse(OPEN.as_bytes(), PRIVATE.as_bytes()).unwrap();
        let mut reservations = 0;
        let selected = run_campaign_with_reservation(
            &template(root.path()),
            &target_id,
            workspace.as_ref(),
            &candidate_repo,
            &source,
            |_, _, _, prepared, judge, selection, prompt| {
                crate::agent_improve::run_shadow_selection_with_factory(
                    &FakeFactory {
                        open_passes: false,
                        sealed_passes: true,
                    },
                    prepared,
                    &AllowAllGate,
                    prompt,
                    judge,
                    selection,
                )
            },
            &mut || {
                reservations += 1;
                Ok(Some("test-reservation".to_owned()))
            },
        )
        .unwrap();
        assert!(!selected.open_verdict().proposable);
        assert_eq!(reservations, 0);
        assert!(!selected.reviewer_verdict().proposable);
        assert_eq!(selected.sealed_count(), 0);
        assert_eq!(selected.sealed_available(), 1);
        assert!(adopt_selected_campaign(workspace.as_ref(), &selected).is_err());
    }

    #[test]
    fn failed_sealed_stage_refuses_open_winner() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let guard = workbench.lock_unpoisoned();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let candidate_repo = root.path().join("candidate");
        crate::agent_improve_adoption::AgentDefinitionSnapshot::from_main(workspace.as_ref())
            .unwrap()
            .materialize(&candidate_repo)
            .unwrap();
        std::fs::write(candidate_repo.join("agent/AGENTS.md"), "selected method\n").unwrap();
        let source = CampaignSnapshot::parse(OPEN.as_bytes(), PRIVATE.as_bytes()).unwrap();
        let mut reservations = 0;
        let selected = run_campaign_with_reservation(
            &template(root.path()),
            &target_id,
            workspace.as_ref(),
            &candidate_repo,
            &source,
            |_, _, _, prepared, judge, selection, prompt| {
                crate::agent_improve::run_shadow_selection_with_factory(
                    &FakeFactory {
                        open_passes: true,
                        sealed_passes: false,
                    },
                    prepared,
                    &AllowAllGate,
                    prompt,
                    judge,
                    selection,
                )
            },
            &mut || {
                reservations += 1;
                Ok(Some("test-reservation".to_owned()))
            },
        )
        .unwrap();
        assert!(selected.open_verdict().proposable);
        assert_eq!(reservations, 1);
        assert!(!selected.reviewer_verdict().proposable);
        assert_eq!(selected.sealed_count(), 1);
        assert!(adopt_selected_campaign(workspace.as_ref(), &selected).is_err());

        let failed_feedback = serde_json::to_value(selected.optimizer_feedback()).unwrap();
        let passed = run_campaign_with_reservation(
            &template(root.path()),
            &target_id,
            workspace.as_ref(),
            &candidate_repo,
            &source,
            |_, _, _, prepared, judge, selection, prompt| {
                crate::agent_improve::run_shadow_selection_with_factory(
                    &FakeFactory {
                        open_passes: true,
                        sealed_passes: true,
                    },
                    prepared,
                    &AllowAllGate,
                    prompt,
                    judge,
                    selection,
                )
            },
            &mut || Ok(Some("another-test-reservation".to_owned())),
        )
        .unwrap();
        assert!(passed.reviewer_verdict().proposable);
        assert_eq!(
            failed_feedback,
            serde_json::to_value(passed.optimizer_feedback()).unwrap()
        );
        let feedback_text = failed_feedback.to_string();
        assert!(!feedback_text.contains("sealed-1"));
        assert!(!feedback_text.contains("Return beta"));
        assert!(!feedback_text.contains("reservation"));
    }

    #[test]
    fn failed_reservation_stops_before_a_sealed_input_runs() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let guard = workbench.lock_unpoisoned();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let candidate_repo = root.path().join("candidate");
        crate::agent_improve_adoption::AgentDefinitionSnapshot::from_main(workspace.as_ref())
            .unwrap()
            .materialize(&candidate_repo)
            .unwrap();
        std::fs::write(candidate_repo.join("agent/AGENTS.md"), "selected method\n").unwrap();
        let source = CampaignSnapshot::parse(OPEN.as_bytes(), PRIVATE.as_bytes()).unwrap();
        let mut ran_sealed = false;
        let result = run_campaign_with_reservation(
            &template(root.path()),
            &target_id,
            workspace.as_ref(),
            &candidate_repo,
            &source,
            |_, _, _, prepared, judge, selection, prompt| {
                if prompt == "Return beta" {
                    ran_sealed = true;
                }
                crate::agent_improve::run_shadow_selection_with_factory(
                    &FakeFactory {
                        open_passes: true,
                        sealed_passes: true,
                    },
                    prepared,
                    &AllowAllGate,
                    prompt,
                    judge,
                    selection,
                )
            },
            &mut || Err("sealed exposure exhausted".to_owned()),
        );
        assert_eq!(result.err().as_deref(), Some("sealed exposure exhausted"));
        assert!(!ran_sealed);
    }

    #[test]
    fn home_receipt_promotes_only_complete_sampled_evaluation_to_held_out_evidence() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let mut guard = workbench.lock_unpoisoned();
        let pool = serde_json::to_vec(&serde_json::json!({
            "schema": "gaugedesk.agent-improve.pool.v1",
            "gauges": [{"name":"quality", "description":"Return alpha"}],
            "selection": {"ascend":{"quality":null}},
            "scenarios": (0..4).map(|index| serde_json::json!({
                "id": format!("case-{index}"),
                "prompt": format!("Return alpha case-{index}"),
                "checks": {"quality":{"kind":"assistant-contains", "text":"alpha"}}
            })).collect::<Vec<_>>()
        }))
        .unwrap();
        let reference = guard
            .register_agent_improve_pool(crate::DEFAULT_AGENT, &pool)
            .unwrap();
        let campaign = guard
            .load_agent_improve_campaign(crate::DEFAULT_AGENT, &reference)
            .unwrap();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let candidate_repo = root.path().join("candidate");
        crate::agent_improve_adoption::AgentDefinitionSnapshot::from_main(workspace.as_ref())
            .unwrap()
            .materialize(&candidate_repo)
            .unwrap();
        std::fs::write(candidate_repo.join("agent/AGENTS.md"), "selected method\n").unwrap();
        let reservation_home = crate::open_workbench(root.path()).unwrap();
        let selected = run_campaign_with_reservation(
            &template(root.path()),
            &target_id,
            workspace.as_ref(),
            &candidate_repo,
            &campaign,
            |_, _, _, prepared, judge, selection, prompt| {
                crate::agent_improve::run_shadow_selection_with_factory(
                    &FakeFactory {
                        open_passes: true,
                        sealed_passes: true,
                    },
                    prepared,
                    &AllowAllGate,
                    prompt,
                    judge,
                    selection,
                )
            },
            &mut || {
                reservation_home
                    .lock_unpoisoned()
                    .reserve_agent_improve_sealed_exposure(crate::DEFAULT_AGENT, &reference)
                    .map(Some)
            },
        )
        .unwrap();
        assert_eq!(selected.sealed_count(), 2);
        assert_eq!(
            selected.reviewer_card(&campaign).unwrap().holdout_status,
            "unheld-out"
        );
        let evidence_id = guard
            .append_agent_improve_evidence(crate::DEFAULT_AGENT, &campaign, &selected)
            .unwrap();
        let candidates = guard
            .store
            .records(
                crate::library::LIBRARY_SCOPE,
                "agent_improve_selected_candidate",
            )
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert!(!candidates[0].contains("selected method"));
        let evidence = guard
            .agent_improve_evidence(crate::DEFAULT_AGENT, &evidence_id)
            .unwrap();
        assert_eq!(evidence.card.holdout_status, "held-out");
        assert_eq!(
            evidence.card.reservation_ref.as_deref(),
            selected.reservation_id()
        );
        assert!(guard
            .adopt_agent_improve_evidence_for_source_owner(
                crate::DEFAULT_AGENT,
                &evidence_id,
                Some("another-person"),
            )
            .unwrap_err()
            .contains("source owner"));
        assert!(guard
            .append_agent_improve_evidence(crate::DEFAULT_AGENT, &campaign, &selected)
            .unwrap_err()
            .contains("already recorded"));
        drop(selected);
        drop(guard);
        drop(reservation_home);
        drop(workbench);

        let reopened = crate::open_workbench(root.path()).unwrap();
        let mut guard = reopened.lock_unpoisoned();
        let review = guard
            .agent_improve_evidence(crate::DEFAULT_AGENT, &evidence_id)
            .unwrap();
        assert!(!serde_json::to_string(&review)
            .unwrap()
            .contains("selected method"));
        assert_eq!(
            guard
                .adopt_agent_improve_evidence_for_source_owner(
                    crate::DEFAULT_AGENT,
                    &evidence_id,
                    None,
                )
                .unwrap(),
            vec!["agent/AGENTS.md"]
        );
        assert!(
            guard
                .adopt_agent_improve_evidence_for_source_owner(
                    crate::DEFAULT_AGENT,
                    &evidence_id,
                    None,
                )
                .unwrap_err()
                .contains("draft changed")
        );
    }
}
