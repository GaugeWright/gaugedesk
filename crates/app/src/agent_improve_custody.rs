//! Durable Home custody for native Agent improvement campaigns. No Agent
//! authoring target or edit chat stores the private evaluator source.

use serde::{Deserialize, Serialize};

use crate::agent_improve_campaign::CampaignSnapshot;
use crate::library::LIBRARY_SCOPE;
use crate::Workbench;

const RECORD_KIND: &str = "agent_improve_campaign_source";
const RECORD_SCHEMA: u32 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceRecord {
    schema: u32,
    target_id: String,
    campaign_ref: String,
    open_ref: String,
    private_ref: String,
    open_json: String,
    sealed_private_json: String,
}

impl Workbench {
    pub(crate) fn improve_authoring_target(&self, agent_id: &str) -> Result<String, String> {
        let target = self
            .library
            .authoring_target_for(agent_id)
            .ok_or("Agent improve authoring target does not exist")?;
        if !self.targets.contains_key(&target.id) {
            return Err("Agent improve authoring target is unavailable".to_owned());
        }
        Ok(target.id.clone())
    }

    /// Admit one exact source revision under Home custody. A retry with the
    /// same target and source is idempotent; a source edit creates a new cut.
    pub fn register_agent_improve_campaign(
        &mut self,
        agent_id: &str,
        open_bytes: &[u8],
        private_bytes: &[u8],
    ) -> Result<String, String> {
        let target_id = self.improve_authoring_target(agent_id)?;
        let campaign = CampaignSnapshot::parse(open_bytes, private_bytes)?;
        let private_json = std::str::from_utf8(private_bytes)
            .map_err(|_| "invalid private Agent improve source")?;
        let sealed_private_json = self
            .seal_account_secret(private_json)
            .ok_or("Agent improve private source could not be sealed")?;
        let record = SourceRecord {
            schema: RECORD_SCHEMA,
            target_id: target_id.clone(),
            campaign_ref: campaign.reference().to_owned(),
            open_ref: campaign.open_ref().to_owned(),
            private_ref: campaign.private_ref().to_owned(),
            open_json: campaign.proposer_open_json().to_owned(),
            sealed_private_json,
        };
        let payload = serde_json::to_string(&record)
            .map_err(|_| "Agent improve source record could not be encoded")?;
        let key = format!(
            "agent-improve-campaign:{target_id}:{}",
            campaign.reference()
        );
        self.store
            .append_record_with_key(LIBRARY_SCOPE, &key, RECORD_KIND, &payload)
            .map_err(|_| "Agent improve source record could not be retained")?;
        Ok(campaign.reference().to_owned())
    }

    fn improve_source_record(
        &self,
        agent_id: &str,
        reference: &str,
    ) -> Result<SourceRecord, String> {
        let target_id = self.improve_authoring_target(agent_id)?;
        let rows = self
            .store
            .records(LIBRARY_SCOPE, RECORD_KIND)
            .map_err(|_| "Agent improve source records are unavailable")?;
        for row in rows.into_iter().rev() {
            let record: SourceRecord =
                serde_json::from_str(&row).map_err(|_| "Agent improve source record is invalid")?;
            if record.schema != RECORD_SCHEMA {
                return Err("Agent improve source record schema is unsupported".to_owned());
            }
            if record.target_id == target_id && record.campaign_ref == reference {
                return Ok(record);
            }
        }
        Err("Agent improve campaign cut is unavailable".to_owned())
    }

    /// The sole projection suitable for an edit-chat proposer. It opens the
    /// pinned record for validation but returns no private checks or inputs.
    pub fn agent_improve_open_source(
        &self,
        agent_id: &str,
        reference: &str,
    ) -> Result<String, String> {
        Ok(self
            .load_agent_improve_campaign(agent_id, reference)?
            .proposer_open_json()
            .to_owned())
    }

    /// Trusted evaluator access to the exact retained revision. All refs are
    /// recomputed after decryption, so a corrupt or substituted row fails shut.
    pub fn load_agent_improve_campaign(
        &self,
        agent_id: &str,
        reference: &str,
    ) -> Result<CampaignSnapshot, String> {
        let record = self.improve_source_record(agent_id, reference)?;
        let private_json = self
            .unseal_account_secret(&record.sealed_private_json)
            .ok_or("Agent improve private source is unavailable")?;
        let campaign =
            CampaignSnapshot::parse(record.open_json.as_bytes(), private_json.as_bytes())?;
        if campaign.reference() != reference
            || campaign.open_ref() != record.open_ref
            || campaign.private_ref() != record.private_ref
        {
            return Err("Agent improve campaign source identity changed".to_owned());
        }
        Ok(campaign)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_support::LockUnpoisoned;

    const OPEN: &str = r#"{
      "schema":"gaugedesk.agent-improve.open.v1",
      "gauges":[{"name":"quality","description":"Return the requested token"}],
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
    fn private_source_survives_restart_but_never_enters_proposer_or_store_projection() {
        let root = tempfile::tempdir().unwrap();
        let agent_id = crate::DEFAULT_AGENT;
        let reference = {
            let wb = crate::open_workbench(root.path()).unwrap();
            let mut guard = wb.lock_unpoisoned();
            let reference = guard
                .register_agent_improve_campaign(agent_id, OPEN.as_bytes(), PRIVATE.as_bytes())
                .unwrap();
            assert_eq!(
                reference,
                guard
                    .register_agent_improve_campaign(agent_id, OPEN.as_bytes(), PRIVATE.as_bytes())
                    .unwrap()
            );
            let rows = guard.store.records(LIBRARY_SCOPE, RECORD_KIND).unwrap();
            assert_eq!(rows.len(), 1);
            assert!(!rows[0].contains("Return beta"));
            assert!(!rows[0].contains("assistant-contains"));
            assert!(!guard
                .agent_improve_open_source(agent_id, &reference)
                .unwrap()
                .contains("Return beta"));
            reference
        };
        let wb = crate::open_workbench(root.path()).unwrap();
        let guard = wb.lock_unpoisoned();
        assert!(guard
            .load_agent_improve_campaign("another-agent", &reference)
            .is_err());
        let loaded = guard
            .load_agent_improve_campaign(agent_id, &reference)
            .unwrap();
        assert_eq!(loaded.reference(), reference);
        assert_eq!(loaded.evaluation_scenarios().len(), 2);
        assert_eq!(loaded.evaluation_scenarios()[1].prompt, "Return beta");
        assert!(guard
            .load_agent_improve_campaign(agent_id, "agent-campaign:sha256:other")
            .is_err());
    }

    #[test]
    fn changed_source_appends_a_new_cut_and_keeps_the_old_one_pinned() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut guard = wb.lock_unpoisoned();
        let agent_id = crate::DEFAULT_AGENT;
        let first = guard
            .register_agent_improve_campaign(agent_id, OPEN.as_bytes(), PRIVATE.as_bytes())
            .unwrap();
        let changed = PRIVATE.replace("Return beta", "Return gamma");
        let second = guard
            .register_agent_improve_campaign(agent_id, OPEN.as_bytes(), changed.as_bytes())
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            guard
                .load_agent_improve_campaign(agent_id, &first)
                .unwrap()
                .evaluation_scenarios()[1]
                .prompt,
            "Return beta"
        );
        assert_eq!(
            guard
                .load_agent_improve_campaign(agent_id, &second)
                .unwrap()
                .evaluation_scenarios()[1]
                .prompt,
            "Return gamma"
        );
        assert_eq!(
            guard
                .store
                .records(LIBRARY_SCOPE, RECORD_KIND)
                .unwrap()
                .len(),
            2
        );
    }
}
