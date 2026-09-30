//! Immutable reviewer evidence for native Agent improve campaigns. These
//! records contain aggregate selection results and lineage, never sealed
//! scenario inputs, checks, or raw turns.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::agent_improve_adoption::{adopt_candidate, AgentDefinitionSnapshot};
use crate::agent_improve_campaign::{
    CampaignEvidenceCard, CampaignSnapshot, Exposure, SelectedCampaign,
};
use crate::library::{gen_id, LIBRARY_SCOPE};
use crate::Workbench;

const RECORD_KIND: &str = "agent_improve_campaign_evidence";
const CANDIDATE_KIND: &str = "agent_improve_selected_candidate";
const RECORD_SCHEMA: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentImproveEvidenceRecord {
    pub schema: u32,
    pub id: String,
    pub target_id: String,
    pub captured_unix_ms: u64,
    pub card: CampaignEvidenceCard,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateRecord {
    schema: u32,
    evidence_id: String,
    target_id: String,
    sealed_candidate: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateCapsule {
    schema: u32,
    evidence_id: String,
    target_id: String,
    definition_json: String,
}

impl Workbench {
    /// Persist one reviewable result of a trusted native campaign evaluation.
    /// The source must be the exact revision already retained in Home custody.
    /// This record is evidence only; draft adoption keeps its separate Main
    /// cut and evaluated-byte checks.
    pub fn append_agent_improve_evidence(
        &mut self,
        agent_id: &str,
        campaign: &CampaignSnapshot,
        selected: &SelectedCampaign,
    ) -> Result<String, String> {
        let target_id = self.improve_authoring_target(agent_id)?;
        if selected.target_id() != target_id {
            return Err("Agent improve evidence belongs to another authoring target".to_owned());
        }
        let retained = self.load_agent_improve_campaign(agent_id, campaign.reference())?;
        if retained.open_ref() != campaign.open_ref()
            || retained.private_ref() != campaign.private_ref()
        {
            return Err("Agent improve evidence differs from the retained campaign".to_owned());
        }
        let mut card = selected.reviewer_card(&retained)?;
        if let Some(reservation_id) = selected.reservation_id() {
            if selected.sealed_count() == 0
                || selected.sealed_count() != selected.sealed_available()
                || !selected.open_verdict().proposable
            {
                return Err("Agent improve sealed evaluation is incomplete".to_owned());
            }
            self.verify_agent_improve_sealed_reservation(
                agent_id,
                campaign.reference(),
                reservation_id,
                &selected.sealed_scenario_ids(),
            )?;
            card.holdout_status = "held-out".to_owned();
            card.reservation_ref = Some(reservation_id.to_owned());
        }
        let workspace = self
            .targets
            .get(&target_id)
            .ok_or("Agent improve authoring target is unavailable")?;
        let current = workspace
            .current_main_cut()
            .map_err(|_| "Agent improve authoring Main cut is unavailable")?
            .ok_or("Agent improve authoring Main cut is missing")?;
        if current != card.baseline_main_cut
            && !workspace
                .cut_descends_from(&current, &card.baseline_main_cut)
                .map_err(|_| "Agent improve authoring cut lineage is unavailable")?
        {
            return Err("Agent improve evidence Main cut belongs to another target".to_owned());
        }
        let captured_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Agent improve evidence clock is unavailable")?
            .as_millis()
            .try_into()
            .map_err(|_| "Agent improve evidence timestamp is too large")?;
        let record = AgentImproveEvidenceRecord {
            schema: RECORD_SCHEMA,
            id: gen_id("agent-improve-evidence"),
            target_id,
            captured_unix_ms,
            card,
        };
        let sealed_candidate = selected
            .adoption_definition()?
            .map(|definition| {
                if definition.identity != record.card.candidate_definition_ref {
                    return Err(
                        "Agent improve selected definition differs from reviewer evidence"
                            .to_owned(),
                    );
                }
                let capsule = CandidateCapsule {
                    schema: RECORD_SCHEMA,
                    evidence_id: record.id.clone(),
                    target_id: record.target_id.clone(),
                    definition_json: definition.retained_json()?,
                };
                let json = serde_json::to_string(&capsule)
                    .map_err(|_| "Agent improve candidate could not be encoded".to_owned())?;
                self.seal_account_secret(&json)
                    .ok_or("Agent improve candidate could not be sealed".to_owned())
            })
            .transpose()?;
        if let Some(sealed_candidate) = sealed_candidate {
            let candidate = CandidateRecord {
                schema: RECORD_SCHEMA,
                evidence_id: record.id.clone(),
                target_id: record.target_id.clone(),
                sealed_candidate,
            };
            let payload = serde_json::to_string(&candidate)
                .map_err(|_| "Agent improve candidate record could not be encoded")?;
            let key = format!("agent-improve-candidate:{}", record.id);
            let (_, inserted) = self
                .store
                .append_record_with_key(LIBRARY_SCOPE, &key, CANDIDATE_KIND, &payload)
                .map_err(|_| "Agent improve candidate could not be retained")?;
            if !inserted {
                return Err("Agent improve candidate was already retained".to_owned());
            }
        }
        let payload = serde_json::to_string(&record)
            .map_err(|_| "Agent improve evidence could not be encoded")?;
        if let Some(reservation_id) = record.card.reservation_ref.as_deref() {
            let key = format!(
                "agent-improve-evidence:{}:{reservation_id}",
                record.target_id
            );
            let (_, inserted) = self
                .store
                .append_record_with_key(LIBRARY_SCOPE, &key, RECORD_KIND, &payload)
                .map_err(|_| "Agent improve evidence could not be retained")?;
            if !inserted {
                return Err("Agent improve reservation was already recorded".to_owned());
            }
        } else {
            self.store
                .append_record(LIBRARY_SCOPE, RECORD_KIND, &payload)
                .map_err(|_| "Agent improve evidence could not be retained")?;
        }
        Ok(record.id)
    }

    /// Human-review projection for one exact Agent and evidence id. Callers
    /// must authorize the reviewer before exposing this aggregate card.
    pub fn agent_improve_evidence(
        &self,
        agent_id: &str,
        evidence_id: &str,
    ) -> Result<AgentImproveEvidenceRecord, String> {
        let target_id = self.improve_authoring_target(agent_id)?;
        let rows = self
            .store
            .records(LIBRARY_SCOPE, RECORD_KIND)
            .map_err(|_| "Agent improve evidence records are unavailable")?;
        for row in rows.into_iter().rev() {
            let record: AgentImproveEvidenceRecord = serde_json::from_str(&row)
                .map_err(|_| "Agent improve evidence record is invalid")?;
            if record.schema != RECORD_SCHEMA {
                return Err("Agent improve evidence record schema is unsupported".to_owned());
            }
            if record.target_id == target_id && record.id == evidence_id {
                return Ok(record);
            }
        }
        Err("Agent improve evidence record is unavailable".to_owned())
    }

    fn selected_agent_improve_candidate(
        &self,
        target_id: &str,
        evidence_id: &str,
    ) -> Result<String, String> {
        let rows = self
            .store
            .records(LIBRARY_SCOPE, CANDIDATE_KIND)
            .map_err(|_| "Agent improve candidate records are unavailable")?;
        for row in rows.into_iter().rev() {
            let record: CandidateRecord = serde_json::from_str(&row)
                .map_err(|_| "Agent improve candidate record is invalid")?;
            if record.schema != RECORD_SCHEMA {
                return Err("Agent improve candidate record schema is unsupported".to_owned());
            }
            if record.target_id == target_id && record.evidence_id == evidence_id {
                return Ok(record.sealed_candidate);
            }
        }
        Err("Agent improve selected candidate was not retained".to_owned())
    }

    /// Apply a reviewed winner after a restart. The Home seal binds the exact
    /// candidate bytes to this evidence id; adoption then repeats the package,
    /// discipline, baseline-definition and Main-cut checks at the merge lock.
    pub fn adopt_agent_improve_evidence_for_source_owner(
        &mut self,
        agent_id: &str,
        evidence_id: &str,
        actor: Option<&str>,
    ) -> Result<Vec<String>, String> {
        self.verify_agent_improve_source_owner(agent_id, actor)?;
        let review = self.agent_improve_evidence(agent_id, evidence_id)?;
        let card = &review.card;
        if !card.final_verdict.proposable {
            return Err("regularized campaign did not propose this Agent candidate".to_owned());
        }
        let campaign = self.load_agent_improve_campaign(agent_id, &card.campaign_ref)?;
        if card.open_source_ref != campaign.open_ref()
            || card.private_source_ref != campaign.private_ref()
        {
            return Err("Agent improve reviewer evidence differs from its campaign".to_owned());
        }
        if card.sealed_available > 0 {
            if card.holdout_status != "held-out" || card.sealed_evaluated != card.sealed_available {
                return Err("Agent improve sealed evaluation is incomplete".to_owned());
            }
            let reservation = card
                .reservation_ref
                .as_deref()
                .ok_or("Agent improve sealed reservation is missing")?;
            let sealed_ids = campaign
                .evaluation_scenarios()
                .into_iter()
                .filter(|scenario| scenario.exposure == Exposure::Sealed)
                .map(|scenario| scenario.id)
                .collect::<Vec<_>>();
            self.verify_agent_improve_sealed_reservation(
                agent_id,
                &card.campaign_ref,
                reservation,
                &sealed_ids,
            )?;
        }
        let sealed = self.selected_agent_improve_candidate(&review.target_id, evidence_id)?;
        let json = self
            .unseal_account_secret(&sealed)
            .ok_or("Agent improve selected candidate is unavailable")?;
        let capsule: CandidateCapsule = serde_json::from_str(&json)
            .map_err(|_| "Agent improve selected candidate is invalid")?;
        if capsule.schema != RECORD_SCHEMA
            || capsule.evidence_id != evidence_id
            || capsule.target_id != review.target_id
        {
            return Err(
                "Agent improve selected candidate belongs to another evidence record".to_owned(),
            );
        }
        let candidate = AgentDefinitionSnapshot::from_retained_json(&capsule.definition_json)?;
        if candidate.identity != card.candidate_definition_ref {
            return Err(
                "Agent improve selected candidate differs from evaluated definition".to_owned(),
            );
        }
        let workspace = self
            .targets
            .get(&review.target_id)
            .ok_or("Agent improve authoring target is unavailable")?;
        let baseline = AgentDefinitionSnapshot::from_main(workspace.as_ref())?;
        if baseline.identity != card.baseline_definition_ref {
            return Err("Agent draft changed since the baseline was evaluated".to_owned());
        }
        adopt_candidate(
            workspace.as_ref(),
            &card.baseline_main_cut,
            &baseline,
            &candidate,
            &card.candidate_package_ref,
            &card.candidate_discipline_ref,
        )
    }
}
