//! One-turn, native shadow comparison for two complete Agent package cuts.
//! Gauge scoring and draft adoption sit above this seam; a comparison itself
//! has no route to a published version or live placement.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gaugedesk_harness::{
    ChatMode, EgressGate, HarnessFactory, HarnessSpec, Observation, TurnOutcome,
};
use gaugedesk_workspace::Workspace;
use sha2::{Digest, Sha256};
use whipplescript_core::improve_selection::{self, Bar, Campaign, GaugeEvidence, Reading, Verdict};

use crate::agent_improve_adoption::{adopt_candidate, AgentDefinitionSnapshot};

pub struct ShadowTurn {
    package_ref: String,
    discipline_ref: String,
    outcome: TurnOutcome,
    observations: Vec<Observation>,
}

pub struct ShadowPair {
    baseline: ShadowTurn,
    candidate: ShadowTurn,
    baseline_definition_ref: String,
    candidate_definition_ref: String,
    baseline_main_cut: Option<String>,
    scenario_ref: String,
    prompt_ref: String,
}

impl ShadowTurn {
    pub fn package_ref(&self) -> &str {
        &self.package_ref
    }

    pub fn discipline_ref(&self) -> &str {
        &self.discipline_ref
    }

    pub fn outcome(&self) -> &TurnOutcome {
        &self.outcome
    }

    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }
}

impl ShadowPair {
    pub fn baseline(&self) -> &ShadowTurn {
        &self.baseline
    }

    pub fn candidate(&self) -> &ShadowTurn {
        &self.candidate
    }

    pub fn baseline_definition_ref(&self) -> &str {
        &self.baseline_definition_ref
    }

    pub fn candidate_definition_ref(&self) -> &str {
        &self.candidate_definition_ref
    }

    pub fn baseline_main_cut(&self) -> Option<&str> {
        self.baseline_main_cut.as_deref()
    }

    pub fn scenario_ref(&self) -> &str {
        &self.scenario_ref
    }

    pub fn prompt_ref(&self) -> &str {
        &self.prompt_ref
    }
}

/// A gauge definition supplied by the host, outside either editable Agent
/// package. The judge reads the same definition for both arms.
#[derive(Clone)]
pub struct HostGauge {
    pub name: String,
    pub direction_up: bool,
    pub resource: bool,
    pub bar: Option<Bar>,
}

pub trait HostJudge {
    /// Immutable identity of the evaluator and its gauge definitions.
    fn reference(&self) -> &str;
    fn gauges(&self) -> &[HostGauge];
    fn read(
        &self,
        gauge: &HostGauge,
        turn: &ShadowTurn,
        worktree: &Path,
    ) -> Result<Reading, String>;
}

/// Selection intent is pinned independently from the editable Agent package.
#[derive(Clone)]
pub struct HostSelection {
    pub reference: String,
    pub campaign: Campaign,
}

/// The only public draft-adoption input. Its verdict and evaluated pair are
/// created together, and neither can be replaced by the caller afterward.
pub struct SelectedShadowPair {
    pair: ShadowPair,
    verdict: Verdict,
    gauges: Vec<GaugeEvidence>,
    judge_ref: String,
    selection_ref: String,
}

impl SelectedShadowPair {
    pub fn verdict(&self) -> &Verdict {
        &self.verdict
    }

    pub fn judge_ref(&self) -> &str {
        &self.judge_ref
    }

    pub fn selection_ref(&self) -> &str {
        &self.selection_ref
    }

    pub fn evidence(&self) -> &ShadowPair {
        &self.pair
    }

    pub fn gauges(&self) -> &[GaugeEvidence] {
        &self.gauges
    }
}

/// Owns the two disposable workspaces through evaluation and evidence capture.
pub struct PreparedShadowPair {
    _scratch: tempfile::TempDir,
    baseline_definition: AgentDefinitionSnapshot,
    candidate_definition: AgentDefinitionSnapshot,
    baseline_main_cut: Option<String>,
    scenario_ref: String,
    baseline: HarnessSpec,
    candidate: HarnessSpec,
    baseline_discipline_ref: String,
    candidate_discipline_ref: String,
}

impl PreparedShadowPair {
    pub fn baseline_spec(&self) -> &HarnessSpec {
        &self.baseline
    }

    pub fn candidate_spec(&self) -> &HarnessSpec {
        &self.candidate
    }

    pub fn baseline_definition_ref(&self) -> &str {
        &self.baseline_definition.identity
    }

    pub fn candidate_definition_ref(&self) -> &str {
        &self.candidate_definition.identity
    }

    pub fn scenario_ref(&self) -> &str {
        &self.scenario_ref
    }

    pub(crate) fn evaluated_candidate_definition(
        &self,
        evidence: &ShadowPair,
    ) -> Result<AgentDefinitionSnapshot, String> {
        if !evidence_matches(self, evidence) {
            return Err("shadow evidence does not identify the evaluated Agent pair".to_owned());
        }
        Ok(self.candidate_definition.clone())
    }
}

/// Prepare two exact Agent/discipline snapshots from separate authoring cuts.
/// `scenario_root` contains only the scenario's work files; host-owned mounts
/// are regenerated independently for each candidate.
pub fn prepare_native_shadow_pair(
    template: &HarnessSpec,
    baseline_repo: &Path,
    candidate_repo: &Path,
    scenario_root: &Path,
) -> io::Result<PreparedShadowPair> {
    if template.mode != ChatMode::Use || template.system_prompt.is_some() {
        return Err(invalid(
            "shadow template must be a work harness without a prompt override",
        ));
    }
    require_definition_read_only(template)?;
    let scratch = tempfile::tempdir()?;
    let baseline_definition = AgentDefinitionSnapshot::capture(baseline_repo).map_err(invalid)?;
    let candidate_definition = AgentDefinitionSnapshot::capture(candidate_repo).map_err(invalid)?;
    let baseline_repo = scratch.path().join("authored-baseline");
    let candidate_repo = scratch.path().join("authored-candidate");
    baseline_definition
        .materialize(&baseline_repo)
        .map_err(invalid)?;
    candidate_definition
        .materialize(&candidate_repo)
        .map_err(invalid)?;
    let (baseline, baseline_discipline_ref) = prepare_one(
        template,
        &baseline_repo,
        scenario_root,
        scratch.path(),
        "baseline",
    )?;
    let (candidate, candidate_discipline_ref) = prepare_one(
        template,
        &candidate_repo,
        scenario_root,
        scratch.path(),
        "candidate",
    )?;
    let scenario_ref = scenario_identity(&scenario_files(&baseline.worktree)?)?;
    Ok(PreparedShadowPair {
        _scratch: scratch,
        baseline_definition,
        candidate_definition,
        baseline_main_cut: None,
        scenario_ref,
        baseline,
        candidate,
        baseline_discipline_ref,
        candidate_discipline_ref,
    })
}

/// Prepare a candidate against the authoritative Agent draft. The baseline
/// bytes and Main cut are observed together; only this preparation can later
/// adopt its evaluated candidate into that draft.
pub fn prepare_native_shadow_pair_from_authoring(
    template: &HarnessSpec,
    workspace: &dyn Workspace,
    candidate_repo: &Path,
    scenario_root: &Path,
) -> io::Result<PreparedShadowPair> {
    let cut = workspace
        .current_main_cut()
        .map_err(invalid)?
        .ok_or_else(|| invalid("Agent authoring target has no Main cut"))?;
    let baseline = AgentDefinitionSnapshot::from_main(workspace).map_err(invalid)?;
    if workspace.current_main_cut().map_err(invalid)?.as_deref() != Some(&cut) {
        return Err(invalid(
            "Agent authoring Main changed while capturing baseline",
        ));
    }
    let source = tempfile::tempdir()?;
    baseline.materialize(source.path()).map_err(invalid)?;
    let mut prepared =
        prepare_native_shadow_pair(template, source.path(), candidate_repo, scenario_root)?;
    if prepared.baseline_definition != baseline {
        return Err(invalid("prepared Agent baseline differs from its Main cut"));
    }
    prepared.baseline_main_cut = Some(cut);
    Ok(prepared)
}

fn prepare_one(
    template: &HarnessSpec,
    repo: &Path,
    scenario_root: &Path,
    scratch: &Path,
    label: &str,
) -> io::Result<(HarnessSpec, String)> {
    let worktree = scratch.join(label);
    std::fs::create_dir(&worktree)?;
    copy_scenario(scenario_root, &worktree)?;
    let package_root = worktree.join(".whipple/versions/improve");
    let package = crate::agent_release::snapshot_authored_package(repo, &package_root)?;
    let discipline_root = worktree.join(".whipple/discipline/versions/improve");
    let discipline =
        crate::agent_release::snapshot_authored_discipline(repo, &discipline_root, &package)?;
    mount_agent_context(&worktree, &package_root, &package, &discipline)?;

    let mut spec = template.clone();
    let nonce = scratch
        .file_name()
        .ok_or_else(|| invalid("shadow scratch root has no identity"))?
        .to_string_lossy();
    spec.chat_id = format!("{}:improve:{nonce}:{label}", template.chat_id);
    spec.worktree = worktree.clone();
    spec.package_root = Some(package_root);
    spec.package_version_ref = Some(package.version_ref().to_owned());
    spec.sandbox.writable_roots = rebase_roots(
        &template.worktree,
        &worktree,
        &template.sandbox.writable_roots,
    )?;
    spec.sandbox.read_only_roots = rebase_roots(
        &template.worktree,
        &worktree,
        &template.sandbox.read_only_roots,
    )?;
    Ok((spec, discipline.reference))
}

fn rebase_roots(old: &Path, new: &Path, roots: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    relative_roots(old, roots)
        .map(|relative| relative.into_iter().map(|path| new.join(path)).collect())
}

fn copy_scenario(source: &Path, destination: &Path) -> io::Result<()> {
    fn copy_entries(source: &Path, destination: &Path, top: bool) -> io::Result<()> {
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let name = entry.file_name();
            if top && (name == ".whipple" || name == ".gaugedesk-runtime") {
                return Err(invalid("scenario cannot supply host-owned runtime files"));
            }
            let target = destination.join(&name);
            let kind = entry.file_type()?;
            if kind.is_dir() {
                std::fs::create_dir(&target)?;
                copy_entries(&entry.path(), &target, false)?;
            } else if kind.is_file() {
                std::fs::copy(entry.path(), target)?;
            } else {
                return Err(invalid(
                    "scenario must contain regular files and directories",
                ));
            }
        }
        Ok(())
    }
    copy_entries(source, destination, true)
}

fn mount_agent_context(
    worktree: &Path,
    package_root: &Path,
    package: &gaugedesk_whip_runtime::AuthoredAgentPackage,
    discipline: &crate::discipline::DisciplineBundle,
) -> io::Result<()> {
    let runtime = worktree.join(".gaugedesk-runtime");
    let agent = runtime.join("agent");
    if package.project_context_document().is_some() {
        std::fs::create_dir_all(agent.join("skills"))?;
        for name in ["AGENTS.md", "HUMANS.md"] {
            let source = package_root.join(name);
            if source.is_file() {
                std::fs::copy(source, agent.join(name))?;
            }
        }
        if !package.system_prompt_document().is_empty() {
            std::fs::write(agent.join("SYSTEM.md"), package.system_prompt_document())?;
        }
    }
    for (path, body) in &discipline.files {
        if package.project_context_document().is_some() {
            let visible = path
                .strip_prefix("agent-files/")
                .map(str::to_owned)
                .or_else(|| {
                    path.strip_prefix("agent-skills/")
                        .map(|rest| format!("skills/{rest}"))
                });
            if let Some(visible) = visible {
                let destination = agent.join(visible);
                if let Some(parent) = destination.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(destination, body)?;
            }
        }
        let destination = runtime.join("discipline").join(path);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(destination, body)?;
    }
    for name in ["artifacts", "work"] {
        std::fs::create_dir_all(worktree.join(name))?;
    }
    Ok(())
}

/// Run the same prompt in two isolated native work harnesses. The caller
/// prepares package and discipline snapshots and supplies the admitted gate;
/// this function refuses different run configuration or scenario files. In
/// particular, it cannot silently fall back to executing a package's `.whip`
/// as a standalone CLI program.
pub fn run_native_shadow_pair(
    factory: &gaugedesk_whip_runtime::WhipHarnessFactory,
    prepared: &PreparedShadowPair,
    gate: &dyn EgressGate,
    prompt: &str,
) -> io::Result<ShadowPair> {
    let runtime = tempfile::tempdir_in(prepared._scratch.path())?;
    let isolated = factory.isolated_native_shadow(runtime.path())?;
    run_shadow_pair_with_factory(&isolated, prepared, gate, prompt)
}

/// Pin the host judge and selection intent before either native turn runs.
/// The only public selection path keeps candidate output from choosing its
/// own evaluator after the fact.
pub fn run_native_shadow_selection(
    factory: &gaugedesk_whip_runtime::WhipHarnessFactory,
    prepared: &PreparedShadowPair,
    gate: &dyn EgressGate,
    prompt: &str,
    judge: &dyn HostJudge,
    selection: &HostSelection,
) -> Result<SelectedShadowPair, String> {
    let runtime =
        tempfile::tempdir_in(prepared._scratch.path()).map_err(|error| error.to_string())?;
    let isolated = factory
        .isolated_native_shadow(runtime.path())
        .map_err(|error| error.to_string())?;
    run_shadow_selection_with_factory(&isolated, prepared, gate, prompt, judge, selection)
}

pub(crate) fn run_shadow_selection_with_factory(
    factory: &dyn HarnessFactory,
    prepared: &PreparedShadowPair,
    gate: &dyn EgressGate,
    prompt: &str,
    judge: &dyn HostJudge,
    selection: &HostSelection,
) -> Result<SelectedShadowPair, String> {
    let judge_ref = judge.reference().to_owned();
    let gauge_ref = gauge_identity(judge.gauges());
    let selection = selection.clone();
    let pair = run_shadow_pair_with_factory(factory, prepared, gate, prompt)
        .map_err(|error| error.to_string())?;
    if judge.reference() != judge_ref || gauge_identity(judge.gauges()) != gauge_ref {
        return Err("host judge changed while the shadow pair was running".to_owned());
    }
    let selected = select_shadow_pair(prepared, pair, judge, &selection)?;
    if judge.reference() != judge_ref || gauge_identity(judge.gauges()) != gauge_ref {
        return Err("host judge changed while scoring the shadow pair".to_owned());
    }
    Ok(selected)
}

fn gauge_identity(gauges: &[HostGauge]) -> String {
    let mut digest = Sha256::new();
    for gauge in gauges {
        digest.update((gauge.name.len() as u64).to_be_bytes());
        digest.update(gauge.name.as_bytes());
        digest.update([u8::from(gauge.direction_up), u8::from(gauge.resource)]);
        match &gauge.bar {
            None => digest.update([0]),
            Some(bar) => {
                digest.update([1, u8::from(bar.chance), u8::from(bar.ge)]);
                let stat = bar.stat.as_deref().unwrap_or("");
                digest.update((stat.len() as u64).to_be_bytes());
                digest.update(stat.as_bytes());
                digest.update(bar.threshold.to_bits().to_be_bytes());
            }
        }
    }
    format!("agent-gauges:sha256:{}", hex::encode(digest.finalize()))
}

/// Internal draft-merge boundary for an exact evaluated pair.
pub(crate) fn adopt_evaluated_candidate(
    workspace: &dyn Workspace,
    prepared: &PreparedShadowPair,
    evidence: &ShadowPair,
) -> Result<Vec<String>, String> {
    let expected_main_cut = prepared
        .baseline_main_cut
        .as_deref()
        .ok_or("shadow comparison was not bound to an Agent authoring Main cut")?;
    if !evidence_matches(prepared, evidence) {
        return Err("shadow evidence does not identify the evaluated Agent pair".to_owned());
    }
    adopt_candidate(
        workspace,
        expected_main_cut,
        &prepared.baseline_definition,
        &prepared.candidate_definition,
        &evidence.candidate.package_ref,
        &evidence.candidate.discipline_ref,
    )
}

fn evidence_matches(prepared: &PreparedShadowPair, evidence: &ShadowPair) -> bool {
    evidence.baseline_definition_ref == prepared.baseline_definition.identity
        && evidence.candidate_definition_ref == prepared.candidate_definition.identity
        && evidence.baseline_main_cut == prepared.baseline_main_cut
        && evidence.scenario_ref == prepared.scenario_ref
        && evidence.baseline.package_ref
            == prepared
                .baseline
                .package_version_ref
                .as_deref()
                .unwrap_or("")
        && evidence.candidate.package_ref
            == prepared
                .candidate
                .package_version_ref
                .as_deref()
                .unwrap_or("")
        && evidence.baseline.discipline_ref == prepared.baseline_discipline_ref
        && evidence.candidate.discipline_ref == prepared.candidate_discipline_ref
        && evidence.baseline.outcome.error.is_none()
        && evidence.candidate.outcome.error.is_none()
        && evidence.baseline.outcome.pending_approvals.is_empty()
        && evidence.candidate.outcome.pending_approvals.is_empty()
}

/// Score the paired run with one host-owned judge, then use WhippleScript's
/// regularized selector. The editable packages cannot supply gauge definitions
/// or readings. A missing reading refuses the whole comparison.
fn select_shadow_pair(
    prepared: &PreparedShadowPair,
    pair: ShadowPair,
    judge: &dyn HostJudge,
    selection: &HostSelection,
) -> Result<SelectedShadowPair, String> {
    if prepared.baseline_main_cut.is_none() || !evidence_matches(prepared, &pair) {
        return Err("shadow evidence is not bound to the evaluated Agent authoring cut".to_owned());
    }
    let judge_ref = judge.reference().to_owned();
    if judge_ref.is_empty() || selection.reference.is_empty() {
        return Err("host judge and selection require immutable references".to_owned());
    }
    let mut names = BTreeSet::new();
    let mut gauges = Vec::new();
    for gauge in judge.gauges() {
        if gauge.name.is_empty() || !names.insert(gauge.name.clone()) {
            return Err("host judge has an empty or duplicate gauge name".to_owned());
        }
        if let Some(bar) = &gauge.bar {
            if !bar.threshold.is_finite()
                || (bar.chance && bar.stat.is_some())
                || (!bar.chance && !valid_bar_stat(bar.stat.as_deref()))
            {
                return Err(format!("host gauge `{}` has an invalid bar", gauge.name));
            }
        }
        let baseline = judge.read(gauge, &pair.baseline, &prepared.baseline.worktree)?;
        let candidate = judge.read(gauge, &pair.candidate, &prepared.candidate.worktree)?;
        if !baseline.score.is_finite()
            || !candidate.score.is_finite()
            || (gauge.bar.as_ref().is_some_and(|bar| bar.chance)
                && (baseline.passed.is_none() || candidate.passed.is_none()))
        {
            return Err(format!(
                "host gauge `{}` has a missing or invalid reading",
                gauge.name
            ));
        }
        gauges.push(GaugeEvidence {
            name: gauge.name.clone(),
            direction_up: gauge.direction_up,
            resource: gauge.resource,
            bar: gauge.bar.clone(),
            baseline: vec![baseline],
            candidate: vec![candidate],
        });
    }
    if gauges.is_empty() || judge.reference() != judge_ref {
        return Err("host judge changed or has no gauges".to_owned());
    }
    let campaign = &selection.campaign;
    if campaign.ascend.iter().any(|(name, reach)| {
        !names.contains(name) || reach.as_ref().is_some_and(|r| !r.threshold.is_finite())
    }) || campaign.sacrifice.iter().any(|name| !names.contains(name))
        || campaign
            .within_percent
            .iter()
            .any(|(name, percent)| !names.contains(name) || !percent.is_finite() || *percent <= 0.0)
        || campaign
            .floors
            .iter()
            .any(|(name, (_, floor))| !names.contains(name) || !floor.is_finite())
    {
        return Err("host selection refers to an unknown gauge or invalid threshold".to_owned());
    }
    let verdict = improve_selection::select(&gauges, campaign);
    Ok(SelectedShadowPair {
        pair,
        verdict,
        gauges,
        judge_ref,
        selection_ref: selection.reference.clone(),
    })
}

fn valid_bar_stat(stat: Option<&str>) -> bool {
    match stat {
        None | Some("mean") => true,
        Some(stat) => stat
            .strip_prefix('p')
            .and_then(|number| number.parse::<u8>().ok())
            .is_some_and(|percentile| percentile <= 100),
    }
}

/// Apply only a candidate selected from the same frozen pair and host judge.
/// The exact Main-cut fence is checked again under the workspace merge lock.
pub fn adopt_selected_candidate(
    workspace: &dyn Workspace,
    prepared: &PreparedShadowPair,
    selected: &SelectedShadowPair,
) -> Result<Vec<String>, String> {
    if !selected.verdict.proposable {
        return Err("regularized gauge selection did not propose this Agent candidate".to_owned());
    }
    adopt_evaluated_candidate(workspace, prepared, &selected.pair)
}

fn run_shadow_pair_with_factory(
    factory: &dyn HarnessFactory,
    prepared: &PreparedShadowPair,
    gate: &dyn EgressGate,
    prompt: &str,
) -> io::Result<ShadowPair> {
    let baseline = &prepared.baseline;
    let candidate = &prepared.candidate;
    validate_pair(factory, baseline, candidate)?;
    if scenario_identity(&scenario_files(&baseline.worktree)?)? != prepared.scenario_ref {
        return Err(invalid(
            "shadow scenario changed after its identity was pinned",
        ));
    }
    validate_discipline(baseline, &prepared.baseline_discipline_ref)?;
    validate_discipline(candidate, &prepared.candidate_discipline_ref)?;
    let baseline_turn = run_one(
        factory,
        baseline,
        &prepared.baseline_discipline_ref,
        gate,
        prompt,
    )?;
    let candidate_turn = run_one(
        factory,
        candidate,
        &prepared.candidate_discipline_ref,
        gate,
        prompt,
    )?;
    Ok(ShadowPair {
        baseline: baseline_turn,
        candidate: candidate_turn,
        baseline_definition_ref: prepared.baseline_definition.identity.clone(),
        candidate_definition_ref: prepared.candidate_definition.identity.clone(),
        baseline_main_cut: prepared.baseline_main_cut.clone(),
        scenario_ref: prepared.scenario_ref.clone(),
        prompt_ref: source_identity("agent-prompt", prompt.as_bytes()),
    })
}

fn run_one(
    factory: &dyn HarnessFactory,
    spec: &HarnessSpec,
    discipline_ref: &str,
    gate: &dyn EgressGate,
    prompt: &str,
) -> io::Result<ShadowTurn> {
    let mut harness = factory.create(spec)?;
    let mut observations = Vec::new();
    let outcome = harness.run_turn(gate, prompt, &[], &mut |event| {
        observations.push(event.clone());
    })?;
    harness.shutdown()?;
    Ok(ShadowTurn {
        package_ref: spec.package_version_ref.clone().expect("validated package"),
        discipline_ref: discipline_ref.to_owned(),
        outcome,
        observations,
    })
}

fn validate_discipline(spec: &HarnessSpec, expected: &str) -> io::Result<()> {
    let package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(
        spec.package_root
            .as_deref()
            .expect("validated package root"),
    )
    .map_err(invalid)?;
    let root = spec.worktree.join(".whipple/discipline/versions/improve");
    let bundle =
        crate::discipline::load(&root, package.capabilities().iter().cloned()).map_err(invalid)?;
    if bundle.reference != expected {
        return Err(invalid(
            "shadow discipline bytes do not match their declared reference",
        ));
    }
    let mount = spec.worktree.join(".gaugedesk-runtime/discipline");
    for (path, body) in &bundle.files {
        if std::fs::read_to_string(mount.join(path))? != *body {
            return Err(invalid(
                "shadow runtime mount differs from the evaluated discipline",
            ));
        }
        if package.project_context_document().is_some() {
            let visible = path
                .strip_prefix("agent-files/")
                .map(str::to_owned)
                .or_else(|| {
                    path.strip_prefix("agent-skills/")
                        .map(|rest| format!("skills/{rest}"))
                });
            if let Some(visible) = visible {
                let agent_file = spec.worktree.join(".gaugedesk-runtime/agent").join(visible);
                if std::fs::read_to_string(agent_file)? != *body {
                    return Err(invalid(
                        "shadow Agent mount differs from the evaluated discipline",
                    ));
                }
            }
        }
    }
    if let Some(context) = package.project_context_document() {
        let agent = spec.worktree.join(".gaugedesk-runtime/agent");
        if std::fs::read_to_string(agent.join("AGENTS.md"))? != context.content {
            return Err(invalid(
                "shadow AGENTS.md mount differs from the evaluated package",
            ));
        }
        if !package.system_prompt_document().is_empty()
            && std::fs::read_to_string(agent.join("SYSTEM.md"))? != package.system_prompt_document()
        {
            return Err(invalid(
                "shadow SYSTEM.md mount differs from the evaluated package",
            ));
        }
    }
    Ok(())
}

fn validate_pair(
    factory: &dyn HarnessFactory,
    baseline: &HarnessSpec,
    candidate: &HarnessSpec,
) -> io::Result<()> {
    if factory.kind() != "whip" {
        return Err(invalid(
            "shadow comparison requires the native governed WhippleScript host",
        ));
    }
    if baseline.mode != ChatMode::Use
        || candidate.mode != ChatMode::Use
        || baseline.system_prompt.is_some()
        || candidate.system_prompt.is_some()
        || baseline.chat_id == candidate.chat_id
        || baseline.worktree == candidate.worktree
        || baseline.package_root == candidate.package_root
    {
        return Err(invalid(
            "shadow runs require distinct work chats and workspaces with no prompt override",
        ));
    }
    if baseline.policy_epoch != candidate.policy_epoch
        || baseline.signed_policy_envelope != candidate.signed_policy_envelope
        || baseline.provider_binding_ref != candidate.provider_binding_ref
        || baseline.credential_ref != candidate.credential_ref
        || baseline.placement_ceiling_ref != candidate.placement_ceiling_ref
        || baseline.runtime_placement_id != candidate.runtime_placement_id
        || !same_credential_capability(baseline, candidate)
        || baseline.provider != candidate.provider
        || baseline.model != candidate.model
        || baseline.base_url != candidate.base_url
        || baseline.thinking != candidate.thinking
        || baseline.workspace_targets != candidate.workspace_targets
        || baseline.roster != candidate.roster
        || baseline.sandbox.network != candidate.sandbox.network
        || baseline.sandbox.allowed_hosts != candidate.sandbox.allowed_hosts
        || relative_roots(&baseline.worktree, &baseline.sandbox.writable_roots)?
            != relative_roots(&candidate.worktree, &candidate.sandbox.writable_roots)?
        || relative_roots(&baseline.worktree, &baseline.sandbox.read_only_roots)?
            != relative_roots(&candidate.worktree, &candidate.sandbox.read_only_roots)?
    {
        return Err(invalid(
            "shadow runs have different policy, provider, grants, or target bindings",
        ));
    }
    for spec in [baseline, candidate] {
        require_definition_read_only(spec)?;
        let root = spec
            .package_root
            .as_deref()
            .ok_or_else(|| invalid("shadow package root is missing"))?;
        let expected = spec
            .package_version_ref
            .as_deref()
            .ok_or_else(|| invalid("shadow package reference is missing"))?;
        let package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(root).map_err(invalid)?;
        if package.version_ref() != expected {
            return Err(invalid(
                "shadow package bytes do not match their declared reference",
            ));
        }
    }
    if scenario_files(&baseline.worktree)? != scenario_files(&candidate.worktree)? {
        return Err(invalid("shadow workspaces have different scenario files"));
    }
    Ok(())
}

fn require_definition_read_only(spec: &HarnessSpec) -> io::Result<()> {
    let roots = relative_roots(&spec.worktree, &spec.sandbox.read_only_roots)?;
    if !roots.iter().any(|root| root == Path::new(".whipple"))
        || !roots
            .iter()
            .any(|root| root == Path::new(".gaugedesk-runtime"))
    {
        return Err(invalid(
            "shadow harness must keep package and runtime mounts read-only",
        ));
    }
    Ok(())
}

fn same_credential_capability(a: &HarnessSpec, b: &HarnessSpec) -> bool {
    match (&a.credential_capability, &b.credential_capability) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

fn relative_roots(worktree: &Path, roots: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    roots
        .iter()
        .map(|root| {
            root.strip_prefix(worktree)
                .map(Path::to_path_buf)
                .map_err(invalid)
        })
        .collect()
}

/// Ignore only host-owned package/context mounts. Every scenario file that the
/// agent may work on must be identical before the first turn.
fn scenario_files(root: &Path) -> io::Result<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(invalid)?;
            if relative.starts_with(".whipple") || relative.starts_with(".gaugedesk-runtime") {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                visit(root, &path, files)?;
            } else if kind.is_file() {
                files.insert(relative.to_path_buf(), std::fs::read(path)?);
            } else {
                return Err(invalid("shadow scenario contains a non-file entry"));
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

fn scenario_identity(files: &BTreeMap<PathBuf, Vec<u8>>) -> io::Result<String> {
    let mut digest = Sha256::new();
    for (path, body) in files {
        let path = path
            .to_str()
            .ok_or_else(|| invalid("shadow scenario path is not UTF-8"))?;
        digest.update((path.len() as u64).to_be_bytes());
        digest.update(path.as_bytes());
        digest.update((body.len() as u64).to_be_bytes());
        digest.update(body);
    }
    Ok(format!(
        "agent-scenario:sha256:{}",
        hex::encode(digest.finalize())
    ))
}

fn source_identity(kind: &str, bytes: &[u8]) -> String {
    format!("{kind}:sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_support::LockUnpoisoned;
    use gaugedesk_harness::{sandbox::SandboxPolicy, AllowAllGate, Harness, Observation};

    struct FakeFactory;
    struct FakeHarness;

    impl HarnessFactory for FakeFactory {
        fn kind(&self) -> &'static str {
            "whip"
        }

        fn create(&self, _spec: &HarnessSpec) -> io::Result<Box<dyn Harness>> {
            Ok(Box::new(FakeHarness))
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
            sink: &mut dyn FnMut(&Observation),
        ) -> io::Result<TurnOutcome> {
            sink(&Observation {
                kind: "text",
                detail: prompt.to_owned(),
                tool: None,
            });
            Ok(TurnOutcome {
                assistant_text: prompt.to_owned(),
                ..Default::default()
            })
        }
    }

    fn shadow_spec(root: &Path, id: &str, context: &str) -> HarnessSpec {
        let worktree = root.join(id);
        let package_root = worktree.join(".whipple/versions/improve");
        std::fs::create_dir_all(&package_root).unwrap();
        std::fs::create_dir_all(worktree.join(".gaugedesk-runtime")).unwrap();
        for (path, body) in gaugedesk_boundary::definition::package_documents_v1(
            "",
            context,
            "method",
            gaugedesk_boundary::definition::PackageCapabilities::default(),
        ) {
            let path = path.trim_start_matches('/');
            std::fs::write(package_root.join(path), body).unwrap();
        }
        std::fs::write(package_root.join("HUMANS.md"), "guide").unwrap();
        let package_ref = gaugedesk_whip_runtime::AuthoredAgentPackage::load(&package_root)
            .unwrap()
            .version_ref()
            .to_owned();
        std::fs::write(worktree.join("scenario.txt"), "same task").unwrap();
        HarnessSpec {
            chat_id: id.to_owned(),
            worktree: worktree.clone(),
            mode: ChatMode::Use,
            package_root: Some(package_root),
            package_version_ref: Some(package_ref),
            policy_epoch: Some(1),
            signed_policy_envelope: Some("same policy".to_owned()),
            provider_binding_ref: Some("same provider binding".to_owned()),
            credential_ref: Some("same credential".to_owned()),
            placement_ceiling_ref: Some("same ceiling".to_owned()),
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
    fn shadow_pair_refuses_a_changed_scenario() {
        let root = tempfile::tempdir().unwrap();
        let baseline = shadow_spec(root.path(), "baseline", "baseline instructions");
        let candidate = shadow_spec(root.path(), "candidate", "candidate instructions");
        validate_pair(&FakeFactory, &baseline, &candidate).unwrap();
        assert_ne!(baseline.package_version_ref, candidate.package_version_ref);

        std::fs::write(candidate.worktree.join("scenario.txt"), "different task").unwrap();
        assert!(validate_pair(&FakeFactory, &baseline, &candidate)
            .unwrap_err()
            .to_string()
            .contains("different scenario"));
    }

    fn authored_repo(root: &Path, context: &str) {
        let draft = root.join(gaugedesk_boundary::definition::DRAFT_ROOT);
        std::fs::create_dir_all(&draft).unwrap();
        std::fs::create_dir_all(root.join("agent")).unwrap();
        for (path, body) in gaugedesk_boundary::definition::package_documents_v1(
            gaugedesk_boundary::definition::DRAFT_ROOT,
            "generated context",
            "generated system",
            gaugedesk_boundary::definition::PackageCapabilities::default(),
        ) {
            std::fs::write(root.join(path), body).unwrap();
        }
        std::fs::write(root.join("agent/AGENTS.md"), context).unwrap();
        std::fs::write(root.join("agent/HUMANS.md"), "guide").unwrap();
        std::fs::write(root.join("agent/SYSTEM.md"), "authored system").unwrap();
        let package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(&draft).unwrap();
        let discipline = root.join(crate::discipline::DISCIPLINE_DRAFT_ROOT);
        std::fs::create_dir_all(&discipline).unwrap();
        std::fs::write(
            discipline.join(crate::discipline::DISCIPLINE_MANIFEST),
            crate::discipline::default_manifest(package.capabilities().iter().cloned()),
        )
        .unwrap();
    }

    #[test]
    fn preparation_uses_authored_context_and_isolated_matching_scenarios() {
        let root = tempfile::tempdir().unwrap();
        let baseline_repo = root.path().join("baseline-repo");
        let candidate_repo = root.path().join("candidate-repo");
        authored_repo(&baseline_repo, "baseline instructions");
        authored_repo(&candidate_repo, "candidate instructions");
        for (repo, body) in [
            (&baseline_repo, "Use the baseline checklist."),
            (&candidate_repo, "Use the candidate checklist."),
        ] {
            let skill = repo.join("agent/skills/triage");
            std::fs::create_dir_all(&skill).unwrap();
            std::fs::write(
                skill.join("SKILL.md"),
                format!("---\nname: triage\ndescription: Triage work\n---\n{body}\n"),
            )
            .unwrap();
        }
        let scenario = root.path().join("scenario");
        std::fs::create_dir(&scenario).unwrap();
        std::fs::write(scenario.join("task.txt"), "same task").unwrap();
        let template = shadow_spec(root.path(), "template", "template instructions");
        let prepared =
            prepare_native_shadow_pair(&template, &baseline_repo, &candidate_repo, &scenario)
                .unwrap();
        assert_ne!(
            prepared.baseline.package_version_ref,
            prepared.candidate.package_version_ref
        );
        assert_ne!(
            prepared.baseline_discipline_ref,
            prepared.candidate_discipline_ref
        );
        assert_ne!(
            prepared.baseline_definition.identity,
            prepared.candidate_definition.identity
        );
        std::fs::write(
            candidate_repo.join("agent/AGENTS.md"),
            "changed after preparation",
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(prepared.baseline.worktree.join("task.txt")).unwrap(),
            "same task"
        );
        assert_eq!(
            std::fs::read_to_string(
                prepared
                    .candidate
                    .worktree
                    .join(".gaugedesk-runtime/agent/AGENTS.md")
            )
            .unwrap(),
            "candidate instructions"
        );
        assert!(std::fs::read_to_string(
            prepared
                .candidate
                .worktree
                .join(".gaugedesk-runtime/agent/skills/triage/SKILL.md")
        )
        .unwrap()
        .contains("candidate checklist"));
        let result =
            run_shadow_pair_with_factory(&FakeFactory, &prepared, &AllowAllGate, "same prompt")
                .unwrap();
        assert_eq!(result.baseline.outcome.assistant_text, "same prompt");
        assert_eq!(result.candidate.outcome.assistant_text, "same prompt");
        assert_eq!(
            result.baseline.discipline_ref,
            prepared.baseline_discipline_ref
        );
        assert_eq!(result.candidate.observations[0].detail, "same prompt");
        assert_eq!(
            result.candidate_definition_ref,
            prepared.candidate_definition.identity
        );
        for spec in [&prepared.baseline, &prepared.candidate] {
            std::fs::write(spec.worktree.join("task.txt"), "changed task").unwrap();
        }
        assert!(run_shadow_pair_with_factory(
            &FakeFactory,
            &prepared,
            &AllowAllGate,
            "same prompt"
        )
        .err()
        .unwrap()
        .to_string()
        .contains("after its identity was pinned"));
        for spec in [&prepared.baseline, &prepared.candidate] {
            std::fs::write(spec.worktree.join("task.txt"), "same task").unwrap();
        }
        std::fs::write(
            prepared
                .candidate
                .worktree
                .join(".gaugedesk-runtime/agent/skills/triage/SKILL.md"),
            "substituted skill",
        )
        .unwrap();
        assert!(run_shadow_pair_with_factory(
            &FakeFactory,
            &prepared,
            &AllowAllGate,
            "same prompt"
        )
        .err()
        .unwrap()
        .to_string()
        .contains("Agent mount differs"));
    }

    #[test]
    fn evaluated_pair_adopts_only_its_exact_candidate_definition() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let guard = workbench.lock_unpoisoned();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let baseline = AgentDefinitionSnapshot::from_main(workspace.as_ref()).unwrap();
        let cut = workspace.current_main_cut().unwrap().unwrap();
        let baseline_repo = root.path().join("baseline-repo");
        let candidate_repo = root.path().join("candidate-repo");
        baseline.materialize(&baseline_repo).unwrap();
        baseline.materialize(&candidate_repo).unwrap();
        std::fs::write(candidate_repo.join("agent/AGENTS.md"), "selected method\n").unwrap();
        let scenario = root.path().join("scenario");
        std::fs::create_dir(&scenario).unwrap();
        std::fs::write(scenario.join("task.txt"), "same task").unwrap();
        let template = shadow_spec(root.path(), "template", "template instructions");
        let unbound =
            prepare_native_shadow_pair(&template, &baseline_repo, &candidate_repo, &scenario)
                .unwrap();
        let unbound_evidence =
            run_shadow_pair_with_factory(&FakeFactory, &unbound, &AllowAllGate, "same prompt")
                .unwrap();
        assert!(
            adopt_evaluated_candidate(workspace.as_ref(), &unbound, &unbound_evidence)
                .unwrap_err()
                .contains("not bound")
        );
        let prepared = prepare_native_shadow_pair_from_authoring(
            &template,
            workspace.as_ref(),
            &candidate_repo,
            &scenario,
        )
        .unwrap();
        let mut evidence =
            run_shadow_pair_with_factory(&FakeFactory, &prepared, &AllowAllGate, "same prompt")
                .unwrap();
        assert_eq!(evidence.baseline_main_cut.as_deref(), Some(cut.as_str()));
        evidence.baseline_main_cut = Some("substituted cut".to_owned());
        assert!(
            adopt_evaluated_candidate(workspace.as_ref(), &prepared, &evidence)
                .unwrap_err()
                .contains("does not identify")
        );
        evidence.baseline_main_cut = Some(cut);
        let package_ref = evidence.candidate.package_ref.clone();
        evidence.candidate.package_ref = "substituted package".to_owned();
        assert!(
            adopt_evaluated_candidate(workspace.as_ref(), &prepared, &evidence)
                .unwrap_err()
                .contains("does not identify")
        );
        evidence.candidate.package_ref = package_ref;
        let unrelated_id = crate::library::gen_id("unrelated-agent-edit");
        let unrelated = workspace.create_engagement(&unrelated_id).unwrap();
        unrelated.write_file("notes.md", "human work").unwrap();
        unrelated.commit_turn("human work").unwrap();
        assert_eq!(
            unrelated.merge_into_main().unwrap(),
            gaugedesk_workspace::MergeOutcome::Clean
        );
        workspace.remove_engagement(&unrelated_id).unwrap();
        assert!(
            adopt_evaluated_candidate(workspace.as_ref(), &prepared, &evidence)
                .unwrap_err()
                .contains("draft changed")
        );
        let prepared = prepare_native_shadow_pair_from_authoring(
            &template,
            workspace.as_ref(),
            &candidate_repo,
            &scenario,
        )
        .unwrap();
        let evidence =
            run_shadow_pair_with_factory(&FakeFactory, &prepared, &AllowAllGate, "same prompt")
                .unwrap();
        assert_eq!(
            adopt_evaluated_candidate(workspace.as_ref(), &prepared, &evidence).unwrap(),
            vec!["agent/AGENTS.md"]
        );
        assert_eq!(
            workspace
                .read_main_file("agent/AGENTS.md")
                .unwrap()
                .as_deref(),
            Some("selected method\n")
        );
    }

    struct PackageJudge {
        gauges: Vec<HostGauge>,
        baseline_ref: String,
        guard_candidate: f64,
    }

    impl HostJudge for PackageJudge {
        fn reference(&self) -> &str {
            "host-judge:fixture-v1"
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
            let baseline = turn.package_ref == self.baseline_ref;
            let score = match gauge.name.as_str() {
                "quality" if baseline => 0.1,
                "quality" => 0.9,
                "guard" if baseline => 0.9,
                "guard" => self.guard_candidate,
                _ => return Err("unknown gauge".to_owned()),
            };
            Ok(Reading {
                score,
                passed: None,
            })
        }
    }

    #[test]
    fn host_judge_and_regularized_selector_gate_agent_adoption() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let guard = workbench.lock_unpoisoned();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let candidate_repo = root.path().join("candidate-repo");
        AgentDefinitionSnapshot::from_main(workspace.as_ref())
            .unwrap()
            .materialize(&candidate_repo)
            .unwrap();
        std::fs::write(candidate_repo.join("agent/AGENTS.md"), "selected method\n").unwrap();
        let scenario = root.path().join("scenario");
        std::fs::create_dir(&scenario).unwrap();
        std::fs::write(scenario.join("task.txt"), "same task").unwrap();
        let template = shadow_spec(root.path(), "template", "template instructions");
        let prepared = prepare_native_shadow_pair_from_authoring(
            &template,
            workspace.as_ref(),
            &candidate_repo,
            &scenario,
        )
        .unwrap();
        let gauges = vec![
            HostGauge {
                name: "quality".to_owned(),
                direction_up: true,
                resource: false,
                bar: None,
            },
            HostGauge {
                name: "guard".to_owned(),
                direction_up: true,
                resource: false,
                bar: None,
            },
        ];
        let selection = HostSelection {
            reference: "host-selection:fixture-v1".to_owned(),
            campaign: Campaign {
                ascend: [("quality".to_owned(), None)].into(),
                ..Default::default()
            },
        };
        let mut judge = PackageJudge {
            gauges,
            baseline_ref: prepared.baseline.package_version_ref.clone().unwrap(),
            guard_candidate: 0.1,
        };
        let mut substituted =
            run_shadow_pair_with_factory(&FakeFactory, &prepared, &AllowAllGate, "same prompt")
                .unwrap();
        substituted.scenario_ref = "substituted scenario".to_owned();
        assert!(
            select_shadow_pair(&prepared, substituted, &judge, &selection)
                .err()
                .unwrap()
                .contains("not bound")
        );
        judge.guard_candidate = f64::NAN;
        assert!(run_shadow_selection_with_factory(
            &FakeFactory,
            &prepared,
            &AllowAllGate,
            "same prompt",
            &judge,
            &selection,
        )
        .err()
        .unwrap()
        .contains("invalid reading"));
        judge.guard_candidate = 0.1;
        let selected = run_shadow_selection_with_factory(
            &FakeFactory,
            &prepared,
            &AllowAllGate,
            "same prompt",
            &judge,
            &selection,
        )
        .unwrap();
        assert!(!selected.verdict().proposable);
        assert!(
            adopt_selected_candidate(workspace.as_ref(), &prepared, &selected)
                .unwrap_err()
                .contains("did not propose")
        );
        assert_eq!(selected.evidence().scenario_ref, prepared.scenario_ref);
        assert_eq!(selected.gauges().len(), 2);
        assert!(selected
            .evidence()
            .prompt_ref()
            .starts_with("agent-prompt:sha256:"));
        judge.guard_candidate = 0.9;
        let selected = run_shadow_selection_with_factory(
            &FakeFactory,
            &prepared,
            &AllowAllGate,
            "same prompt",
            &judge,
            &selection,
        )
        .unwrap();
        assert!(selected.verdict().proposable);
        assert_eq!(selected.judge_ref(), "host-judge:fixture-v1");
        assert_eq!(selected.selection_ref(), "host-selection:fixture-v1");
        assert_eq!(
            adopt_selected_candidate(workspace.as_ref(), &prepared, &selected).unwrap(),
            vec!["agent/AGENTS.md"]
        );
    }
}
