//! Account-sealed, append-once scenario results for a hosted Agent improve.
//!
//! The result is retained before managed arm completion, so a recovered worker
//! can reconcile those exact command epochs before using gauge readings. This
//! module only holds the cut; the worker and ledger reconciliation are separate.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use whipplescript_core::improve_selection::GaugeEvidence;

use crate::agent_improve::{PreparedShadowPair, SelectedShadowPair};
use crate::agent_improve_campaign::Exposure;
use crate::agent_improve_checkpoint::{HostedImproveInputKey, HostedImprovePreparedCut};
use crate::library::LIBRARY_SCOPE;
use crate::Workbench;

const RECORD_KIND: &str = "agent_improve_hosted_scenario";
const RECORD_SCHEMA: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedImproveGaugeSample {
    pub name: String,
    pub direction_up: bool,
    pub resource: bool,
    pub bar: Option<HostedImproveBar>,
    pub baseline: HostedImproveReading,
    pub candidate: HostedImproveReading,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedImproveBar {
    pub chance: bool,
    pub stat: Option<String>,
    pub ge: bool,
    pub threshold: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedImproveReading {
    pub score: f64,
    pub passed: Option<bool>,
}

impl HostedImproveGaugeSample {
    fn same_shape(&self, other: &Self) -> bool {
        self.name == other.name
            && self.direction_up == other.direction_up
            && self.resource == other.resource
            && match (&self.bar, &other.bar) {
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

    pub(crate) fn from_evidence(gauge: &GaugeEvidence) -> Result<Self, String> {
        if gauge.baseline.len() != 1 || gauge.candidate.len() != 1 {
            return Err("hosted improve scenario gauge needs one reading per arm".into());
        }
        let sample = Self {
            name: gauge.name.clone(),
            direction_up: gauge.direction_up,
            resource: gauge.resource,
            bar: gauge.bar.as_ref().map(|bar| HostedImproveBar {
                chance: bar.chance,
                stat: bar.stat.clone(),
                ge: bar.ge,
                threshold: bar.threshold,
            }),
            baseline: HostedImproveReading {
                score: gauge.baseline[0].score,
                passed: gauge.baseline[0].passed,
            },
            candidate: HostedImproveReading {
                score: gauge.candidate[0].score,
                passed: gauge.candidate[0].passed,
            },
        };
        sample.validate()?;
        Ok(sample)
    }

    fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty()
            || !self.baseline.score.is_finite()
            || !self.candidate.score.is_finite()
            || self
                .bar
                .as_ref()
                .is_some_and(|bar| !bar.threshold.is_finite())
        {
            return Err("hosted improve scenario gauge is invalid".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostedImproveArmTerminal {
    pub label: String,
    pub command_id: String,
    pub epoch: u64,
    pub evidence_ref: String,
    pub usage_id: String,
    pub wall_millis: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedImproveScenarioCut {
    pub ordinal: usize,
    pub scenario_id: String,
    pub exposure: String,
    pub scenario_ref: String,
    pub prompt_ref: String,
    pub baseline_main_cut: String,
    pub baseline_definition_ref: String,
    pub candidate_definition_ref: String,
    pub baseline_package_ref: String,
    pub candidate_package_ref: String,
    pub baseline_discipline_ref: String,
    pub candidate_discipline_ref: String,
    pub gauges: Vec<HostedImproveGaugeSample>,
    pub arms: [HostedImproveArmTerminal; 2],
}

pub(crate) struct HostedScenarioSelection<'a> {
    pub ordinal: usize,
    pub scenario_id: &'a str,
    pub exposure: Exposure,
    pub prompt: &'a str,
    pub campaign_ref: &'a str,
    pub prepared: &'a PreparedShadowPair,
    pub selected: &'a SelectedShadowPair,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScenarioRecord {
    schema: u32,
    operation_digest: String,
    ordinal: usize,
    sealed_result: String,
}

impl HostedImproveScenarioCut {
    pub(crate) fn from_selected(
        selection: HostedScenarioSelection<'_>,
        arms: [HostedImproveArmTerminal; 2],
    ) -> Result<Self, String> {
        let HostedScenarioSelection {
            ordinal,
            scenario_id,
            exposure,
            prompt,
            campaign_ref,
            prepared,
            selected,
        } = selection;
        let evidence = selected.evidence();
        prepared.evaluated_definitions(evidence)?;
        let prompt_ref = format!(
            "agent-prompt:sha256:{}",
            hex::encode(Sha256::digest(prompt.as_bytes()))
        );
        if evidence.prompt_ref() != prompt_ref
            || selected.judge_ref() != campaign_ref
            || selected.selection_ref() != campaign_ref
        {
            return Err("hosted improve selected pair differs from its scenario".into());
        }
        Ok(Self {
            ordinal,
            scenario_id: scenario_id.to_owned(),
            exposure: match exposure {
                Exposure::Open => "open",
                Exposure::Sealed => "sealed",
            }
            .to_owned(),
            scenario_ref: evidence.scenario_ref().to_owned(),
            prompt_ref,
            baseline_main_cut: evidence
                .baseline_main_cut()
                .ok_or("hosted improve selected pair has no Main cut")?
                .to_owned(),
            baseline_definition_ref: evidence.baseline_definition_ref().to_owned(),
            candidate_definition_ref: evidence.candidate_definition_ref().to_owned(),
            baseline_package_ref: evidence.baseline().package_ref().to_owned(),
            candidate_package_ref: evidence.candidate().package_ref().to_owned(),
            baseline_discipline_ref: evidence.baseline().discipline_ref().to_owned(),
            candidate_discipline_ref: evidence.candidate().discipline_ref().to_owned(),
            gauges: selected
                .gauges()
                .iter()
                .map(HostedImproveGaugeSample::from_evidence)
                .collect::<Result<Vec<_>, _>>()?,
            arms,
        })
    }

    fn validate(
        &self,
        key: &HostedImproveInputKey<'_>,
        prepared: &HostedImprovePreparedCut,
        scenario_id: &str,
        prompt: &str,
        exposure: Exposure,
        gauge_names: &BTreeSet<&str>,
    ) -> Result<(), String> {
        let expected_prompt_ref = format!(
            "agent-prompt:sha256:{}",
            hex::encode(Sha256::digest(prompt.as_bytes()))
        );
        let expected_exposure = match exposure {
            Exposure::Open => "open",
            Exposure::Sealed => "sealed",
        };
        if self.scenario_id != scenario_id
            || self.exposure != expected_exposure
            || self.prompt_ref != expected_prompt_ref
            || self.scenario_ref.trim().is_empty()
            || self.baseline_main_cut != key.target_main_basis
            || self.baseline_definition_ref != prepared.baseline_ref
            || self.candidate_definition_ref != prepared.candidate_ref
            || self.baseline_package_ref != prepared.baseline_package_ref
            || self.candidate_package_ref != prepared.candidate_package_ref
            || self.baseline_discipline_ref != prepared.baseline_discipline_ref
            || self.candidate_discipline_ref != prepared.candidate_discipline_ref
            || self.arms[0].label != "baseline"
            || self.arms[1].label != "candidate"
            || self.arms[0].command_id == self.arms[1].command_id
        {
            return Err("hosted improve scenario differs from its admitted cut".into());
        }
        let mut found = BTreeSet::new();
        for gauge in &self.gauges {
            gauge.validate()?;
            if !found.insert(gauge.name.as_str()) {
                return Err("hosted improve scenario repeats a gauge".into());
            }
        }
        if &found != gauge_names {
            return Err("hosted improve scenario omits a campaign gauge".into());
        }
        for arm in &self.arms {
            if arm.command_id.trim().is_empty()
                || arm.epoch == 0
                || arm
                    .evidence_ref
                    .strip_prefix("sha256:")
                    .is_none_or(|digest| {
                        digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                || arm.usage_id.trim().is_empty()
            {
                return Err("hosted improve scenario has an incomplete arm terminal".into());
            }
        }
        Ok(())
    }
}

impl Workbench {
    /// Complete results form a contiguous prefix of the campaign. A row is
    /// never interpreted as terminal ledger evidence until the hosted worker
    /// checks both command epochs and settles the exact saved arm references.
    pub(crate) fn hosted_improve_scenario_cuts(
        &self,
        key: &HostedImproveInputKey<'_>,
    ) -> Result<Vec<HostedImproveScenarioCut>, String> {
        let digest = key.digest()?;
        let prepared = self
            .hosted_improve_prepared_cut(key)?
            .ok_or("hosted improve has no retained prepared cut")?;
        let campaign = self.load_agent_improve_campaign(key.agent_id, key.campaign_ref)?;
        let expected = campaign.evaluation_scenarios();
        let gauge_names = campaign.gauge_names().collect::<BTreeSet<_>>();
        let mut rows = Vec::new();
        for row in self
            .store
            .records(LIBRARY_SCOPE, RECORD_KIND)
            .map_err(|_| "hosted improve scenario custody is unavailable")?
        {
            let record: ScenarioRecord = serde_json::from_str(&row)
                .map_err(|_| "hosted improve scenario record is invalid")?;
            if record.schema != RECORD_SCHEMA {
                return Err("hosted improve scenario record schema is unsupported".into());
            }
            if record.operation_digest == digest {
                rows.push(record);
            }
        }
        rows.sort_by_key(|row| row.ordinal);
        let mut cuts: Vec<HostedImproveScenarioCut> = Vec::with_capacity(rows.len());
        for (ordinal, row) in rows.into_iter().enumerate() {
            if row.ordinal != ordinal {
                return Err("hosted improve scenario journal has a gap or duplicate".into());
            }
            let scenario = expected
                .get(ordinal)
                .ok_or("hosted improve scenario exceeds its campaign")?;
            let plaintext = self
                .unseal_account_secret(&row.sealed_result)
                .ok_or("hosted improve scenario cut cannot be unsealed")?;
            let cut: HostedImproveScenarioCut = serde_json::from_str(&plaintext)
                .map_err(|_| "hosted improve scenario cut is invalid")?;
            if cut.ordinal != ordinal {
                return Err("hosted improve scenario ordinal changed".into());
            }
            cut.validate(
                key,
                &prepared,
                scenario.id,
                scenario.prompt,
                scenario.exposure,
                &gauge_names,
            )?;
            if let Some(first) = cuts.first() {
                for gauge in &cut.gauges {
                    let prior = first
                        .gauges
                        .iter()
                        .find(|prior: &&HostedImproveGaugeSample| prior.name == gauge.name)
                        .ok_or("hosted improve scenario changed its gauge set")?;
                    if !gauge.same_shape(prior) {
                        return Err("hosted improve scenario changed a gauge definition".into());
                    }
                }
            }
            cuts.push(cut);
        }
        Ok(cuts)
    }

    pub(crate) fn retain_hosted_improve_scenario_cut(
        &mut self,
        key: &HostedImproveInputKey<'_>,
        cut: &HostedImproveScenarioCut,
    ) -> Result<(), String> {
        let digest = key.digest()?;
        let existing = self.hosted_improve_scenario_cuts(key)?;
        if let Some(prior) = existing.get(cut.ordinal) {
            return (prior == cut)
                .then_some(())
                .ok_or("hosted improve scenario cannot be substituted".into());
        }
        if cut.ordinal != existing.len() {
            return Err("hosted improve scenario must extend the complete prefix".into());
        }
        let prepared = self
            .hosted_improve_prepared_cut(key)?
            .ok_or("hosted improve has no retained prepared cut")?;
        let campaign = self.load_agent_improve_campaign(key.agent_id, key.campaign_ref)?;
        let scenarios = campaign.evaluation_scenarios();
        let scenario = scenarios
            .get(cut.ordinal)
            .ok_or("hosted improve scenario exceeds its campaign")?;
        cut.validate(
            key,
            &prepared,
            scenario.id,
            scenario.prompt,
            scenario.exposure,
            &campaign.gauge_names().collect(),
        )?;
        if let Some(first) = existing.first() {
            for gauge in &cut.gauges {
                let prior = first
                    .gauges
                    .iter()
                    .find(|prior| prior.name == gauge.name)
                    .ok_or("hosted improve scenario changed its gauge set")?;
                if !gauge.same_shape(prior) {
                    return Err("hosted improve scenario changed a gauge definition".into());
                }
            }
        }
        if existing.iter().any(|prior| {
            prior.arms.iter().any(|arm| {
                cut.arms
                    .iter()
                    .any(|next| next.command_id == arm.command_id)
            })
        }) {
            return Err("hosted improve scenario reused a managed arm command".into());
        }
        let plaintext = serde_json::to_string(cut)
            .map_err(|_| "hosted improve scenario cut could not be encoded")?;
        let sealed_result = self
            .seal_account_secret(&plaintext)
            .ok_or("hosted improve scenario cut could not be sealed")?;
        let record = ScenarioRecord {
            schema: RECORD_SCHEMA,
            operation_digest: digest.clone(),
            ordinal: cut.ordinal,
            sealed_result,
        };
        let payload = serde_json::to_string(&record)
            .map_err(|_| "hosted improve scenario record could not be encoded")?;
        self.store
            .append_record_with_key(
                LIBRARY_SCOPE,
                &format!("hosted-improve-scenario:{digest}:{}", cut.ordinal),
                RECORD_KIND,
                &payload,
            )
            .map_err(|_| "hosted improve scenario cut could not be retained")?;
        let recovered = self.hosted_improve_scenario_cuts(key)?;
        (recovered.get(cut.ordinal) == Some(cut))
            .then_some(())
            .ok_or("hosted improve scenario cannot be substituted".into())
    }
}
