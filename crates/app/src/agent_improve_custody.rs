//! Durable Home custody for native Agent improvement campaigns. No Agent
//! authoring target or edit chat stores the private evaluator source.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use whipplescript_core::improve_holdout::WEAR_OUT_AT;

use crate::agent_improve_campaign::{sample_pool, CampaignSnapshot, Exposure, PoolAssignment};
use crate::library::LIBRARY_SCOPE;
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};

const RECORD_KIND: &str = "agent_improve_campaign_source";
const RECORD_SCHEMA: u32 = 1;
const EXPOSURE_KIND: &str = "agent_improve_sealed_exposure";
const EXPOSURE_SCHEMA: u32 = 1;

/// Returned to the operator surface after Home has fixed and retained the
/// sampled partition. The source reference stays in the UI; only `open_source`
/// may be passed to the edit chat.
#[derive(Debug, Serialize)]
pub struct AgentImprovePoolStart {
    pub campaign_ref: String,
    pub open_source: String,
}

/// The desktop command's admission stays in the Home crate: a webview may use
/// its signed-in Home session, or the explicitly selected local posture.
/// A selected but unadmitted/expired account cannot fall through to solo.
pub fn start_agent_improve_pool_from_desktop(
    wb: &SharedWorkbench,
    agent_id: &str,
    pool_bytes: &[u8],
) -> Result<AgentImprovePoolStart, String> {
    let bearer = desktop_improve_bearer(wb)?;
    let mut guard = wb.lock_unpoisoned();
    let actor = desktop_improve_actor(&guard, bearer.as_deref())?;
    guard.start_agent_improve_pool_for_source_owner(agent_id, pool_bytes, actor.as_deref())
}

pub fn latest_agent_improve_pool_from_desktop(
    wb: &SharedWorkbench,
    agent_id: &str,
) -> Result<Option<AgentImprovePoolStart>, String> {
    let bearer = desktop_improve_bearer(wb)?;
    let guard = wb.lock_unpoisoned();
    let actor = desktop_improve_actor(&guard, bearer.as_deref())?;
    guard.latest_agent_improve_pool_for_source_owner(agent_id, actor.as_deref())
}

pub(crate) fn desktop_improve_bearer(wb: &SharedWorkbench) -> Result<Option<String>, String> {
    let bearer = crate::desktop_session::home_session(wb);
    if bearer.is_none() && !crate::account_signin::local_operator_selected(wb) {
        return Err("Select an admitted Home account or the local operator".to_owned());
    }
    Ok(bearer)
}

pub(crate) fn desktop_improve_actor(
    wb: &Workbench,
    bearer: Option<&str>,
) -> Result<Option<String>, String> {
    bearer
        .map(|token| {
            wb.authenticate_bearer(token)
                .map(|authority| authority.as_str().to_owned())
                .ok_or("Home account session is unavailable".to_owned())
        })
        .transpose()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExposureRecord {
    schema: u32,
    target_id: String,
    campaign_ref: String,
    reservation_id: String,
    fingerprint: String,
    ordinal: i64,
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed_assignment_json: Option<String>,
}

impl Workbench {
    /// Intake from a human authoring surface. A signed-in actor must be the
    /// verified source owner of the Agent's current version. The signed-out
    /// desktop posture is admitted only for a genuinely unclaimed solo Home
    /// and an Agent version with no account owner.
    pub fn start_agent_improve_pool_for_source_owner(
        &mut self,
        agent_id: &str,
        pool_bytes: &[u8],
        actor: Option<&str>,
    ) -> Result<AgentImprovePoolStart, String> {
        self.verify_agent_improve_source_owner(agent_id, actor)?;
        let campaign_ref = self.register_agent_improve_pool(agent_id, pool_bytes)?;
        let open_source = self.agent_improve_open_source(agent_id, &campaign_ref)?;
        Ok(AgentImprovePoolStart {
            campaign_ref,
            open_source,
        })
    }

    /// Recover the latest sampled source after a UI restart. A corrupt or
    /// undecipherable private cut stops the read rather than returning an open
    /// projection that can no longer be evaluated.
    pub fn latest_agent_improve_pool_for_source_owner(
        &self,
        agent_id: &str,
        actor: Option<&str>,
    ) -> Result<Option<AgentImprovePoolStart>, String> {
        self.verify_agent_improve_source_owner(agent_id, actor)?;
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
            if record.target_id == target_id && record.sealed_assignment_json.is_some() {
                let open_source = self.agent_improve_open_source(agent_id, &record.campaign_ref)?;
                return Ok(Some(AgentImprovePoolStart {
                    campaign_ref: record.campaign_ref,
                    open_source,
                }));
            }
        }
        Ok(None)
    }

    pub(crate) fn verify_agent_improve_source_owner(
        &self,
        agent_id: &str,
        actor: Option<&str>,
    ) -> Result<(), String> {
        let agent = self
            .library
            .agents
            .get(agent_id)
            .ok_or("Agent improve source Agent does not exist")?;
        let version = agent
            .versions
            .get(&agent.current_version)
            .ok_or("Agent improve source version is unavailable")?;
        match actor {
            Some(actor)
                if !actor.is_empty()
                    && version.source_owner_authority.as_deref() == Some(actor) => {}
            None if self.idp.is_none()
                && !crate::workbench_auth::web_account_mode()
                && !self.hosted_home_mode()
                && self.home_owner_account().is_none()
                && version.source_owner_authority.is_none() => {}
            _ => return Err("Agent improve pool requires the Agent source owner".to_owned()),
        }
        Ok(())
    }

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
        self.register_campaign_source(agent_id, open_bytes, private_bytes, None)
    }

    /// Sample one complete case pool inside Home custody. The caller receives
    /// the campaign ref, then may request only the open proposer projection.
    pub fn register_agent_improve_pool(
        &mut self,
        agent_id: &str,
        pool_bytes: &[u8],
    ) -> Result<String, String> {
        let target_id = self.improve_authoring_target(agent_id)?;
        let wear = self.improve_case_wear(&target_id)?;
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random)
            .map_err(|_| "Agent improve campaign randomness is unavailable")?;
        let campaign_id = hex::encode(random);
        let sampled = sample_pool(
            pool_bytes,
            &campaign_id,
            &self.account_key(),
            |fingerprint| wear.get(fingerprint).copied().unwrap_or(0),
        )?;
        self.register_campaign_source(
            agent_id,
            sampled.open_json.as_bytes(),
            sampled.private_json.as_bytes(),
            Some(&sampled.assignment_json),
        )
    }

    fn improve_case_wear(&self, target_id: &str) -> Result<BTreeMap<String, i64>, String> {
        let rows = self
            .store
            .records(LIBRARY_SCOPE, EXPOSURE_KIND)
            .map_err(|_| "Agent improve exposure records are unavailable")?;
        let mut counts = BTreeMap::<String, i64>::new();
        for row in rows {
            let event: ExposureRecord = serde_json::from_str(&row)
                .map_err(|_| "Agent improve exposure record is invalid")?;
            if event.schema != EXPOSURE_SCHEMA
                || event.fingerprint.len() != 64
                || !event
                    .fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || event.ordinal < 1
            {
                return Err("Agent improve exposure record is invalid".to_owned());
            }
            if event.target_id == target_id {
                let count = counts.entry(event.fingerprint).or_default();
                if event.ordinal != *count + 1 {
                    return Err("Agent improve exposure history is inconsistent".to_owned());
                }
                *count = event.ordinal;
            }
        }
        Ok(counts)
    }

    fn improve_pool_assignment(
        &self,
        agent_id: &str,
        campaign_ref: &str,
    ) -> Result<PoolAssignment, String> {
        let record = self.improve_source_record(agent_id, campaign_ref)?;
        let sealed = record
            .sealed_assignment_json
            .as_deref()
            .ok_or("Agent improve campaign has no sampled pool assignment")?;
        let json = self
            .unseal_account_secret(sealed)
            .ok_or("Agent improve pool assignment is unavailable")?;
        let assignment: PoolAssignment =
            serde_json::from_str(&json).map_err(|_| "Agent improve pool assignment is invalid")?;
        if assignment.schema != "gaugedesk.agent-improve.pool.v1"
            || assignment.campaign_id.len() != 64
            || !assignment
                .campaign_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !assignment.pool_ref.starts_with("agent-pool:sha256:")
        {
            return Err("Agent improve pool assignment is invalid".to_owned());
        }
        let campaign = self.load_agent_improve_campaign(agent_id, campaign_ref)?;
        let admitted = campaign
            .evaluation_scenarios()
            .into_iter()
            .map(|case| (case.id.to_owned(), case.exposure))
            .collect::<BTreeMap<_, _>>();
        let mut seen_ids = BTreeSet::new();
        let mut seen_fingerprints = BTreeSet::new();
        let mut assigned = BTreeMap::new();
        for case in &assignment.cases {
            if !seen_ids.insert(&case.id)
                || !seen_fingerprints.insert(&case.fingerprint)
                || case.fingerprint.len() != 64
                || !case
                    .fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || case.wear_before < 0
            {
                return Err("Agent improve pool assignment is invalid".to_owned());
            }
            let exposure = match case.exposure.as_str() {
                "open" => Some(Exposure::Open),
                "sealed" => Some(Exposure::Sealed),
                "retired" => None,
                _ => return Err("Agent improve pool assignment is invalid".to_owned()),
            };
            if let Some(exposure) = exposure {
                assigned.insert(case.id.clone(), exposure);
            } else if admitted.contains_key(&case.id) {
                return Err("Agent improve retired case entered the campaign".to_owned());
            }
        }
        if assigned != admitted {
            return Err("Agent improve pool assignment differs from campaign cut".to_owned());
        }
        Ok(assignment)
    }

    /// Reserve all sealed cases before the promotion gate runs either arm.
    /// A conflicting writer or exhausted case refuses the whole gate. A
    /// failure after this reservation still consumes the wear slot.
    pub fn reserve_agent_improve_sealed_exposure(
        &mut self,
        agent_id: &str,
        campaign_ref: &str,
    ) -> Result<String, String> {
        let target_id = self.improve_authoring_target(agent_id)?;
        let assignment = self.improve_pool_assignment(agent_id, campaign_ref)?;
        let sealed = assignment
            .cases
            .iter()
            .filter(|case| case.exposure == "sealed")
            .collect::<Vec<_>>();
        if sealed.is_empty() {
            return Err("Agent improve campaign has no sealed cases to reserve".to_owned());
        }
        let counts = self.improve_case_wear(&target_id)?;
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random)
            .map_err(|_| "Agent improve reservation randomness is unavailable")?;
        let reservation_id = format!("agent-improve-reservation:{}", hex::encode(random));
        let mut records = Vec::with_capacity(sealed.len());
        for case in sealed {
            let prior = counts.get(&case.fingerprint).copied().unwrap_or(0);
            if prior >= WEAR_OUT_AT {
                return Err("Agent improve sealed case is retired".to_owned());
            }
            let ordinal = prior + 1;
            let event = ExposureRecord {
                schema: EXPOSURE_SCHEMA,
                target_id: target_id.clone(),
                campaign_ref: campaign_ref.to_owned(),
                reservation_id: reservation_id.clone(),
                fingerprint: case.fingerprint.clone(),
                ordinal,
            };
            let payload = serde_json::to_string(&event)
                .map_err(|_| "Agent improve exposure could not be encoded")?;
            let key = format!(
                "agent-improve-exposure:{target_id}:{}:{ordinal}",
                case.fingerprint
            );
            records.push((key, payload));
        }
        let borrowed = records
            .iter()
            .map(|(key, payload)| (LIBRARY_SCOPE, key.as_str(), EXPOSURE_KIND, payload.as_str()))
            .collect::<Vec<_>>();
        self.store
            .append_records_with_keys_atomically(&borrowed)
            .map_err(|_| "Agent improve exposure could not be reserved")?
            .ok_or("Agent improve sealed case exposure was concurrently reserved")?;
        Ok(reservation_id)
    }

    /// Verify the runner's receipt against Home's sampled assignment and the
    /// exact sealed cases it evaluated. A caller-supplied label is never proof.
    pub(crate) fn verify_agent_improve_sealed_reservation(
        &self,
        agent_id: &str,
        campaign_ref: &str,
        reservation_id: &str,
        evaluated_sealed_ids: &[&str],
    ) -> Result<(), String> {
        let target_id = self.improve_authoring_target(agent_id)?;
        let suffix = reservation_id
            .strip_prefix("agent-improve-reservation:")
            .ok_or("Agent improve reservation reference is invalid")?;
        if suffix.len() != 64 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Agent improve reservation reference is invalid".to_owned());
        }
        let assignment = self.improve_pool_assignment(agent_id, campaign_ref)?;
        let assigned = assignment
            .cases
            .iter()
            .filter(|case| case.exposure == "sealed")
            .map(|case| (case.id.as_str(), case.fingerprint.as_str()))
            .collect::<BTreeMap<_, _>>();
        let evaluated = evaluated_sealed_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if assigned.is_empty()
            || assigned.keys().copied().collect::<BTreeSet<_>>() != evaluated
            || evaluated.len() != evaluated_sealed_ids.len()
        {
            return Err("Agent improve sealed evaluation differs from its assignment".to_owned());
        }
        let expected = assigned.values().copied().collect::<BTreeSet<_>>();
        self.improve_case_wear(&target_id)?;
        let rows = self
            .store
            .records(LIBRARY_SCOPE, EXPOSURE_KIND)
            .map_err(|_| "Agent improve exposure records are unavailable")?;
        let mut found = BTreeSet::new();
        for row in rows {
            let event: ExposureRecord = serde_json::from_str(&row)
                .map_err(|_| "Agent improve exposure record is invalid")?;
            if event.reservation_id != reservation_id {
                continue;
            }
            if event.schema != EXPOSURE_SCHEMA
                || event.target_id != target_id
                || event.campaign_ref != campaign_ref
                || event.ordinal < 1
                || event.ordinal > WEAR_OUT_AT
                || !found.insert(event.fingerprint)
            {
                return Err("Agent improve reservation differs from its campaign".to_owned());
            }
        }
        if found.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected {
            return Err("Agent improve reservation omits a sealed case".to_owned());
        }
        Ok(())
    }

    fn register_campaign_source(
        &mut self,
        agent_id: &str,
        open_bytes: &[u8],
        private_bytes: &[u8],
        assignment_json: Option<&str>,
    ) -> Result<String, String> {
        let target_id = self.improve_authoring_target(agent_id)?;
        let campaign = CampaignSnapshot::parse(open_bytes, private_bytes)?;
        let private_json = std::str::from_utf8(private_bytes)
            .map_err(|_| "invalid private Agent improve source")?;
        let sealed_private_json = self
            .seal_account_secret(private_json)
            .ok_or("Agent improve private source could not be sealed")?;
        let sealed_assignment_json = assignment_json
            .map(|assignment| {
                self.seal_account_secret(assignment)
                    .ok_or("Agent improve pool assignment could not be sealed".to_owned())
            })
            .transpose()?;
        let record = SourceRecord {
            schema: RECORD_SCHEMA,
            target_id: target_id.clone(),
            campaign_ref: campaign.reference().to_owned(),
            open_ref: campaign.open_ref().to_owned(),
            private_ref: campaign.private_ref().to_owned(),
            open_json: campaign.proposer_open_json().to_owned(),
            sealed_private_json,
            sealed_assignment_json,
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
        Ok(if record.sealed_assignment_json.is_some() {
            campaign.with_sampled_assignment()
        } else {
            campaign
        })
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

    fn case_pool(count: usize) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "gaugedesk.agent-improve.pool.v1",
            "gauges": [{"name":"quality", "description":"Return the requested token"}],
            "selection": {"ascend":{"quality":null}},
            "scenarios": (0..count).map(|index| serde_json::json!({
                "id": format!("case-{index}"),
                "prompt": format!("Return token-{index}"),
                "checks": {"quality":{"kind":"assistant-contains", "text":format!("token-{index}")}}
            })).collect::<Vec<_>>()
        }))
        .unwrap()
    }

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

    #[test]
    fn sampled_pool_keeps_assignment_and_sealed_inputs_in_home_custody() {
        let root = tempfile::tempdir().unwrap();
        let reference = {
            let wb = crate::open_workbench(root.path()).unwrap();
            let mut guard = wb.lock_unpoisoned();
            let reference = guard
                .register_agent_improve_pool(crate::DEFAULT_AGENT, &case_pool(10))
                .unwrap();
            let open = guard
                .agent_improve_open_source(crate::DEFAULT_AGENT, &reference)
                .unwrap();
            let source: serde_json::Value = serde_json::from_str(&open).unwrap();
            assert_eq!(source["scenarios"].as_array().unwrap().len(), 8);
            assert!(!open.contains("assistant-contains"));
            let campaign = guard
                .load_agent_improve_campaign(crate::DEFAULT_AGENT, &reference)
                .unwrap();
            let sealed = campaign
                .evaluation_scenarios()
                .into_iter()
                .filter(|scenario| {
                    scenario.exposure == crate::agent_improve_campaign::Exposure::Sealed
                })
                .map(|scenario| scenario.prompt.to_owned())
                .collect::<Vec<_>>();
            assert_eq!(sealed.len(), 2);
            for prompt in &sealed {
                assert!(!open.contains(prompt));
            }
            let rows = guard.store.records(LIBRARY_SCOPE, RECORD_KIND).unwrap();
            assert_eq!(rows.len(), 1);
            for prompt in &sealed {
                assert!(!rows[0].contains(prompt));
            }
            assert!(!rows[0].contains("assistant-contains"));
            let record: SourceRecord = serde_json::from_str(&rows[0]).unwrap();
            let assignment = guard
                .unseal_account_secret(record.sealed_assignment_json.as_deref().unwrap())
                .unwrap();
            let assignment: serde_json::Value = serde_json::from_str(&assignment).unwrap();
            assert_eq!(assignment["cases"].as_array().unwrap().len(), 10);
            assert_eq!(
                assignment["cases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|case| case["exposure"] == "sealed")
                    .count(),
                2
            );
            reference
        };
        let wb = crate::open_workbench(root.path()).unwrap();
        let guard = wb.lock_unpoisoned();
        assert_eq!(
            guard
                .load_agent_improve_campaign(crate::DEFAULT_AGENT, &reference)
                .unwrap()
                .reference(),
            reference
        );
    }

    #[test]
    fn operator_pool_intake_requires_the_current_source_owner() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut guard = wb.lock_unpoisoned();
        let local = guard
            .start_agent_improve_pool_for_source_owner(crate::DEFAULT_AGENT, &case_pool(4), None)
            .unwrap();
        assert!(!local.open_source.contains("assistant-contains"));
        assert!(local
            .open_source
            .contains("gaugedesk.agent-improve.open.v1"));
        assert!(guard
            .start_agent_improve_pool_for_source_owner(
                crate::DEFAULT_AGENT,
                &case_pool(4),
                Some("unverified-person"),
            )
            .unwrap_err()
            .contains("source owner"));

        let agent = guard.library.agents.get_mut(crate::DEFAULT_AGENT).unwrap();
        agent
            .versions
            .get_mut(&agent.current_version)
            .unwrap()
            .source_owner_authority = Some("person-1".to_owned());
        assert!(guard
            .start_agent_improve_pool_for_source_owner(crate::DEFAULT_AGENT, &case_pool(4), None)
            .unwrap_err()
            .contains("source owner"));
        assert!(guard
            .start_agent_improve_pool_for_source_owner(
                crate::DEFAULT_AGENT,
                &case_pool(4),
                Some("person-2"),
            )
            .unwrap_err()
            .contains("source owner"));
        assert!(guard
            .latest_agent_improve_pool_for_source_owner(crate::DEFAULT_AGENT, Some("person-2"))
            .unwrap_err()
            .contains("source owner"));
        let signed_in = guard
            .start_agent_improve_pool_for_source_owner(
                crate::DEFAULT_AGENT,
                &case_pool(4),
                Some("person-1"),
            )
            .unwrap();
        assert_ne!(local.campaign_ref, signed_in.campaign_ref);
    }

    #[tokio::test]
    async fn desktop_pool_intake_requires_the_selected_local_operator() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        assert!(
            start_agent_improve_pool_from_desktop(&wb, crate::DEFAULT_AGENT, &case_pool(4))
                .unwrap_err()
                .contains("Select an admitted")
        );
        crate::account_signin::post_signin_select_local(
            axum::extract::State(wb.clone()),
            Some(axum::Extension(crate::account_signin::DesktopOperatorPlane)),
        )
        .await;
        let prepared =
            start_agent_improve_pool_from_desktop(&wb, crate::DEFAULT_AGENT, &case_pool(4))
                .unwrap();
        assert!(!prepared.open_source.contains("assistant-contains"));
        let recovered = latest_agent_improve_pool_from_desktop(&wb, crate::DEFAULT_AGENT)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.campaign_ref, prepared.campaign_ref);
        assert_eq!(recovered.open_source, prepared.open_source);
    }

    #[test]
    fn latest_pool_survives_restart_and_ignores_manual_sources() {
        let root = tempfile::tempdir().unwrap();
        let first = {
            let wb = crate::open_workbench(root.path()).unwrap();
            let mut guard = wb.lock_unpoisoned();
            let first = guard
                .start_agent_improve_pool_for_source_owner(
                    crate::DEFAULT_AGENT,
                    &case_pool(4),
                    None,
                )
                .unwrap();
            guard
                .register_agent_improve_campaign(
                    crate::DEFAULT_AGENT,
                    OPEN.as_bytes(),
                    PRIVATE.as_bytes(),
                )
                .unwrap();
            first
        };
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut guard = wb.lock_unpoisoned();
        let recovered = guard
            .latest_agent_improve_pool_for_source_owner(crate::DEFAULT_AGENT, None)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.campaign_ref, first.campaign_ref);
        assert_eq!(recovered.open_source, first.open_source);

        let mut corrupt = guard
            .improve_source_record(crate::DEFAULT_AGENT, &first.campaign_ref)
            .unwrap();
        corrupt.sealed_private_json = "not a Home seal".to_owned();
        guard
            .store
            .append_record(
                LIBRARY_SCOPE,
                RECORD_KIND,
                &serde_json::to_string(&corrupt).unwrap(),
            )
            .unwrap();
        assert!(guard
            .latest_agent_improve_pool_for_source_owner(crate::DEFAULT_AGENT, None)
            .unwrap_err()
            .contains("private source is unavailable"));
    }

    #[test]
    fn small_pool_is_open_and_duplicate_case_content_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut guard = wb.lock_unpoisoned();
        let reference = guard
            .register_agent_improve_pool(crate::DEFAULT_AGENT, &case_pool(3))
            .unwrap();
        let campaign = guard
            .load_agent_improve_campaign(crate::DEFAULT_AGENT, &reference)
            .unwrap();
        assert_eq!(campaign.evaluation_scenarios().len(), 3);
        assert!(campaign
            .evaluation_scenarios()
            .iter()
            .all(|case| case.exposure == crate::agent_improve_campaign::Exposure::Open));
        let mut duplicate: serde_json::Value = serde_json::from_slice(&case_pool(4)).unwrap();
        duplicate["scenarios"][1]["prompt"] = duplicate["scenarios"][0]["prompt"].clone();
        duplicate["scenarios"][1]["checks"] = duplicate["scenarios"][0]["checks"].clone();
        assert!(guard
            .register_agent_improve_pool(
                crate::DEFAULT_AGENT,
                &serde_json::to_vec(&duplicate).unwrap()
            )
            .unwrap_err()
            .contains("repeats"));
    }

    #[test]
    fn renaming_a_case_preserves_its_private_fingerprint_and_assignment() {
        let source = case_pool(10);
        let mut renamed: serde_json::Value = serde_json::from_slice(&source).unwrap();
        renamed["scenarios"][0]["id"] = serde_json::json!("renamed-case");
        let renamed = serde_json::to_vec(&renamed).unwrap();
        let first = sample_pool(&source, "fixed-campaign", &[7; 32], |_| 0).unwrap();
        let second = sample_pool(&renamed, "fixed-campaign", &[7; 32], |_| 0).unwrap();
        let first: serde_json::Value = serde_json::from_str(&first.assignment_json).unwrap();
        let second: serde_json::Value = serde_json::from_str(&second.assignment_json).unwrap();
        let first_cases = first["cases"].as_array().unwrap();
        let second_cases = second["cases"].as_array().unwrap();
        assert_eq!(first_cases.len(), second_cases.len());
        for (before, after) in first_cases.iter().zip(second_cases) {
            assert_eq!(before["fingerprint"], after["fingerprint"]);
            assert_eq!(before["exposure"], after["exposure"]);
        }
        assert_ne!(first_cases[0]["id"], second_cases[0]["id"]);
    }

    #[test]
    fn sealed_reservations_retire_cases_across_restart_and_names() {
        let root = tempfile::tempdir().unwrap();
        let source = case_pool(4);
        let (campaign_ref, retired_fingerprints) = {
            let wb = crate::open_workbench(root.path()).unwrap();
            let mut guard = wb.lock_unpoisoned();
            let campaign_ref = guard
                .register_agent_improve_pool(crate::DEFAULT_AGENT, &source)
                .unwrap();
            let assignment = guard
                .improve_pool_assignment(crate::DEFAULT_AGENT, &campaign_ref)
                .unwrap();
            let retired_fingerprints = assignment
                .cases
                .iter()
                .filter(|case| case.exposure == "sealed")
                .map(|case| case.fingerprint.clone())
                .collect::<BTreeSet<_>>();
            assert_eq!(retired_fingerprints.len(), 2);
            let sealed_ids = assignment
                .cases
                .iter()
                .filter(|case| case.exposure == "sealed")
                .map(|case| case.id.as_str())
                .collect::<Vec<_>>();
            for _ in 0..WEAR_OUT_AT {
                let receipt = guard
                    .reserve_agent_improve_sealed_exposure(crate::DEFAULT_AGENT, &campaign_ref)
                    .unwrap();
                guard
                    .verify_agent_improve_sealed_reservation(
                        crate::DEFAULT_AGENT,
                        &campaign_ref,
                        &receipt,
                        &sealed_ids,
                    )
                    .unwrap();
                assert!(guard
                    .verify_agent_improve_sealed_reservation(
                        crate::DEFAULT_AGENT,
                        &campaign_ref,
                        &receipt,
                        &sealed_ids[..1],
                    )
                    .is_err());
            }
            assert!(guard
                .reserve_agent_improve_sealed_exposure(crate::DEFAULT_AGENT, &campaign_ref)
                .unwrap_err()
                .contains("retired"));
            let target = guard
                .improve_authoring_target(crate::DEFAULT_AGENT)
                .unwrap();
            let wear = guard.improve_case_wear(&target).unwrap();
            for fingerprint in &retired_fingerprints {
                assert_eq!(wear[fingerprint], WEAR_OUT_AT);
            }
            (campaign_ref, retired_fingerprints)
        };
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut guard = wb.lock_unpoisoned();
        let mut renamed: serde_json::Value = serde_json::from_slice(&source).unwrap();
        for (index, case) in renamed["scenarios"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            case["id"] = serde_json::json!(format!("renamed-{index}"));
        }
        let next_ref = guard
            .register_agent_improve_pool(
                crate::DEFAULT_AGENT,
                &serde_json::to_vec(&renamed).unwrap(),
            )
            .unwrap();
        assert_ne!(campaign_ref, next_ref);
        let assignment = guard
            .improve_pool_assignment(crate::DEFAULT_AGENT, &next_ref)
            .unwrap();
        assert_eq!(
            assignment
                .cases
                .iter()
                .filter(|case| case.exposure == "retired")
                .map(|case| case.fingerprint.clone())
                .collect::<BTreeSet<_>>(),
            retired_fingerprints
        );
        let campaign = guard
            .load_agent_improve_campaign(crate::DEFAULT_AGENT, &next_ref)
            .unwrap();
        assert_eq!(campaign.evaluation_scenarios().len(), 2);
        assert!(campaign
            .evaluation_scenarios()
            .iter()
            .all(|case| case.exposure == Exposure::Open));
        assert!(guard
            .reserve_agent_improve_sealed_exposure(crate::DEFAULT_AGENT, &next_ref)
            .is_err());
    }

    #[test]
    fn manually_chosen_private_cases_cannot_reserve_sampled_wear() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut guard = wb.lock_unpoisoned();
        let reference = guard
            .register_agent_improve_campaign(
                crate::DEFAULT_AGENT,
                OPEN.as_bytes(),
                PRIVATE.as_bytes(),
            )
            .unwrap();
        assert!(guard
            .reserve_agent_improve_sealed_exposure(crate::DEFAULT_AGENT, &reference)
            .unwrap_err()
            .contains("no sampled pool assignment"));
    }
}
