//! Versioned open/private campaign source for Agent improvement. Only the open
//! projection may be given to an edit-chat proposer; checks and sealed inputs
//! remain with the host evaluator.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use whipplescript_core::improve_selection::{
    self, Bar, Campaign, GaugeEvidence, Reach, Reading, Verdict,
};

use gaugedesk_harness::{EgressGate, HarnessSpec};
use gaugedesk_workspace::Workspace;

use crate::agent_improve::{
    adopt_evaluated_candidate, prepare_native_shadow_pair_from_authoring,
    run_native_shadow_selection, HostGauge, HostJudge, HostSelection, PreparedShadowPair,
    SelectedShadowPair, ShadowTurn,
};

const OPEN_SCHEMA: &str = "gaugedesk.agent-improve.open.v1";
const PRIVATE_SCHEMA: &str = "gaugedesk.agent-improve.private.v1";
const MAX_SOURCE_BYTES: usize = 512 * 1024;
const MAX_SCENARIOS: usize = 64;
const MAX_GAUGES: usize = 32;
const MAX_PROMPT_BYTES: usize = 16 * 1024;
const MAX_CHECK_BYTES: usize = 8 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenSource {
    schema: String,
    gauges: Vec<GaugeSource>,
    selection: SelectionSource,
    scenarios: Vec<OpenScenario>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GaugeSource {
    name: String,
    description: String,
    minimum_pass_rate: Option<f64>,
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct SelectionSource {
    ascend: BTreeMap<String, Option<Threshold>>,
    sacrifice: BTreeSet<String>,
    within_percent: BTreeMap<String, f64>,
    floors: BTreeMap<String, Threshold>,
    repair: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Threshold {
    ge: bool,
    value: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenScenario {
    id: String,
    prompt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateSource {
    schema: String,
    /// Exact checks for every open scenario, keyed by scenario id then gauge.
    open_checks: BTreeMap<String, BTreeMap<String, TextCheck>>,
    #[serde(default)]
    sealed_scenarios: Vec<PrivateScenario>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateScenario {
    id: String,
    prompt: String,
    checks: BTreeMap<String, TextCheck>,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum TextCheck {
    #[serde(rename = "assistant-contains")]
    Contains { text: String },
    #[serde(rename = "assistant-excludes")]
    Excludes { text: String },
    #[serde(rename = "assistant-equals")]
    Equals { text: String },
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
    prepared: PreparedShadowPair,
    selected: SelectedShadowPair,
}

/// Every evaluated scenario used one authored baseline/candidate lineage and
/// one pinned open/private campaign. Sealed scenarios are skipped when the
/// open stage fails. Raw sealed turns remain private.
pub struct SelectedCampaign {
    reference: String,
    scenarios: Vec<EvaluatedScenario>,
    open_verdict: Verdict,
    verdict: Verdict,
    sealed_available: usize,
}

impl SelectedCampaign {
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
}

/// Evaluate a text-scenario campaign through the same governed native harness
/// for every arm. Each scenario starts with a fresh pair of workspaces and
/// runtime continuity; a changed Agent Main cut or candidate definition
/// invalidates the whole campaign rather than mixing incompatible readings.
pub fn run_native_campaign(
    factory: &gaugedesk_whip_runtime::WhipHarnessFactory,
    template: &HarnessSpec,
    workspace: &dyn Workspace,
    candidate_repo: &Path,
    campaign: &CampaignSnapshot,
    gate: &dyn EgressGate,
) -> Result<SelectedCampaign, String> {
    run_campaign_with(
        template,
        workspace,
        candidate_repo,
        campaign,
        |prepared, judge, selection, prompt| {
            run_native_shadow_selection(factory, prepared, gate, prompt, judge, selection)
        },
    )
}

fn run_campaign_with<F>(
    template: &HarnessSpec,
    workspace: &dyn Workspace,
    candidate_repo: &Path,
    campaign: &CampaignSnapshot,
    mut run: F,
) -> Result<SelectedCampaign, String>
where
    F: FnMut(
        &PreparedShadowPair,
        &dyn HostJudge,
        &HostSelection,
        &str,
    ) -> Result<SelectedShadowPair, String>,
{
    let selection = campaign.selection();
    let mut scenarios = Vec::new();
    let mut readings: BTreeMap<String, GaugeEvidence> = BTreeMap::new();
    let mut lineage: Option<(String, String, String, String, String, String, String)> = None;
    let mut open_verdict = None;
    for scenario in campaign.evaluation_scenarios() {
        if scenario.exposure == Exposure::Sealed && open_verdict.is_none() {
            let verdict = aggregate_verdict(
                &readings,
                &selection,
                scenarios.len(),
                campaign.open.gauges.len(),
            )?;
            if !verdict.proposable {
                return Ok(SelectedCampaign {
                    reference: campaign.reference.clone(),
                    scenarios,
                    open_verdict: verdict.clone(),
                    verdict,
                    sealed_available: campaign.private.sealed_scenarios.len(),
                });
            }
            open_verdict = Some(verdict);
        }
        let scenario_root = tempfile::tempdir().map_err(|error| error.to_string())?;
        let prepared = prepare_native_shadow_pair_from_authoring(
            template,
            workspace,
            candidate_repo,
            scenario_root.path(),
        )
        .map_err(|error| error.to_string())?;
        let judge = campaign.judge_for(scenario.id)?;
        let selected = run(&prepared, &judge, &selection, scenario.prompt)?;
        let evidence = selected.evidence();
        let expected_prompt_ref = format!(
            "agent-prompt:sha256:{}",
            hex::encode(Sha256::digest(scenario.prompt.as_bytes()))
        );
        if evidence.prompt_ref() != expected_prompt_ref
            || selected.judge_ref() != campaign.reference()
            || selected.selection_ref() != campaign.reference()
        {
            return Err(
                "Agent improve scenario evidence differs from the pinned campaign".to_owned(),
            );
        }
        let this_lineage = (
            evidence.baseline_main_cut().unwrap_or("").to_owned(),
            evidence.baseline_definition_ref().to_owned(),
            evidence.candidate_definition_ref().to_owned(),
            evidence.baseline().package_ref().to_owned(),
            evidence.candidate().package_ref().to_owned(),
            evidence.baseline().discipline_ref().to_owned(),
            evidence.candidate().discipline_ref().to_owned(),
        );
        if this_lineage.0.is_empty()
            || lineage
                .as_ref()
                .is_some_and(|expected| expected != &this_lineage)
        {
            return Err(
                "Agent improve campaign mixed authoring cuts or package definitions".to_owned(),
            );
        }
        lineage = Some(this_lineage);
        for gauge in selected.gauges() {
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
        scenarios.push(EvaluatedScenario {
            id: scenario.id.to_owned(),
            exposure: scenario.exposure,
            prepared,
            selected,
        });
    }
    let verdict = aggregate_verdict(
        &readings,
        &selection,
        scenarios.len(),
        campaign.open.gauges.len(),
    )?;
    Ok(SelectedCampaign {
        reference: campaign.reference.clone(),
        scenarios,
        open_verdict: open_verdict.unwrap_or_else(|| verdict.clone()),
        verdict,
        sealed_available: campaign.private.sealed_scenarios.len(),
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

/// Adopt only an aggregate winner. The first pair's exact Main-cut fence is
/// sufficient because every evaluated scenario was checked against that same
/// baseline/candidate lineage before the aggregate verdict was made.
pub fn adopt_selected_campaign(
    workspace: &dyn Workspace,
    selected: &SelectedCampaign,
) -> Result<Vec<String>, String> {
    if !selected.verdict.proposable {
        return Err("regularized campaign did not propose this Agent candidate".to_owned());
    }
    let first = selected
        .scenarios
        .first()
        .ok_or("Agent improve campaign has no evaluated scenarios")?;
    adopt_evaluated_candidate(workspace, &first.prepared, first.selected.evidence())
}

impl CampaignSnapshot {
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
        })
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
        let run = || {
            run_campaign_with(
                &template(root.path()),
                workspace.as_ref(),
                &candidate_repo,
                &source,
                |prepared, judge, selection, prompt| {
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
        let selected = run_campaign_with(
            &template(root.path()),
            workspace.as_ref(),
            &candidate_repo,
            &source,
            |prepared, judge, selection, prompt| {
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
        )
        .unwrap();
        assert!(!selected.open_verdict().proposable);
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
        let selected = run_campaign_with(
            &template(root.path()),
            workspace.as_ref(),
            &candidate_repo,
            &source,
            |prepared, judge, selection, prompt| {
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
        )
        .unwrap();
        assert!(selected.open_verdict().proposable);
        assert!(!selected.reviewer_verdict().proposable);
        assert_eq!(selected.sealed_count(), 1);
        assert!(adopt_selected_campaign(workspace.as_ref(), &selected).is_err());
    }
}
