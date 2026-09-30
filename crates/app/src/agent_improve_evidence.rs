//! Immutable reviewer evidence for native Agent improve campaigns. These
//! records contain aggregate selection results and lineage, never sealed
//! scenario inputs, checks, or raw turns.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::agent_improve_campaign::{CampaignEvidenceCard, CampaignSnapshot, SelectedCampaign};
use crate::library::{gen_id, LIBRARY_SCOPE};
use crate::Workbench;

const RECORD_KIND: &str = "agent_improve_campaign_evidence";
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
        let card = selected.reviewer_card(&retained)?;
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
        let payload = serde_json::to_string(&record)
            .map_err(|_| "Agent improve evidence could not be encoded")?;
        self.store
            .append_record(LIBRARY_SCOPE, RECORD_KIND, &payload)
            .map_err(|_| "Agent improve evidence could not be retained")?;
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
}
