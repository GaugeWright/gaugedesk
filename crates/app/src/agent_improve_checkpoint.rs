//! Sealed, immutable input cuts for a hosted Agent improve campaign run.
//!
//! A restarted job must recover the definition bytes it admitted, rather than
//! reading a possibly changed edit chat or Main projection. The signed
//! execution template is a second immutable cut; scenario progress still needs
//! a journal before these cuts can drive a hosted route.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_improve_adoption::AgentDefinitionSnapshot;
use crate::library::LIBRARY_SCOPE;
use crate::Workbench;

const RECORD_KIND: &str = "agent_improve_hosted_input";
const RECORD_SCHEMA: u32 = 1;
const PREPARED_KIND: &str = "agent_improve_hosted_prepared";
const PREPARED_SCHEMA: u32 = 1;

pub(crate) struct HostedImproveInputKey<'a> {
    pub operation_id: &'a str,
    pub actor: &'a str,
    pub tenant_id: &'a str,
    pub agent_id: &'a str,
    pub edit_chat_id: &'a str,
    pub campaign_ref: &'a str,
    pub target_id: &'a str,
    pub target_main_basis: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostedImproveInputCut {
    pub baseline: AgentDefinitionSnapshot,
    pub candidate: AgentDefinitionSnapshot,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputRecord {
    schema: u32,
    operation_digest: String,
    actor: String,
    tenant_id: String,
    agent_id: String,
    edit_chat_id: String,
    campaign_ref: String,
    target_id: String,
    target_main_basis: String,
    baseline_ref: String,
    candidate_ref: String,
    sealed_definitions: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Definitions {
    baseline_json: String,
    candidate_json: String,
}

/// The policy-bearing part of the Home preparation, without ephemeral paths
/// or credentials. Recovered scratch paths and sandbox roots are rebuilt from
/// this cut; all inputs that affect a managed command remain pinned.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedImprovePreparedCut {
    pub baseline_ref: String,
    pub candidate_ref: String,
    pub baseline_package_ref: String,
    pub candidate_package_ref: String,
    pub baseline_discipline_ref: String,
    pub candidate_discipline_ref: String,
    pub config_json: String,
    pub isolated: bool,
    pub allow_unfiltered_egress: bool,
    pub chat_id: String,
    pub placement_id: String,
    pub policy_epoch: u64,
    pub signed_policy_envelope: String,
    pub provider_binding_ref: String,
    pub credential_ref: String,
    pub placement_ceiling_ref: String,
    pub provider: String,
    pub model: String,
    pub base_url: Option<String>,
    pub thinking: Option<String>,
    pub roster: Vec<(String, String)>,
    pub account_scope: String,
    pub billing_scope: String,
    pub funding_ref: String,
}

impl HostedImprovePreparedCut {
    fn validate(&self) -> Result<(), String> {
        if [
            &self.baseline_ref,
            &self.candidate_ref,
            &self.baseline_package_ref,
            &self.candidate_package_ref,
            &self.baseline_discipline_ref,
            &self.candidate_discipline_ref,
            &self.config_json,
            &self.chat_id,
            &self.placement_id,
            &self.signed_policy_envelope,
            &self.provider_binding_ref,
            &self.credential_ref,
            &self.placement_ceiling_ref,
            &self.provider,
            &self.model,
            &self.account_scope,
            &self.billing_scope,
            &self.funding_ref,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
            || self.policy_epoch == 0
            || self.credential_ref != self.funding_ref
        {
            return Err("hosted improve prepared cut is incomplete".to_owned());
        }
        gaugedesk_boundary::AgentConfig::from_json(&self.config_json)
            .map_err(|_| "hosted improve prepared config is invalid")?;
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PreparedRecord {
    schema: u32,
    operation_digest: String,
    baseline_ref: String,
    candidate_ref: String,
    sealed_prepared: String,
}

impl HostedImproveInputKey<'_> {
    pub(crate) fn digest(&self) -> Result<String, String> {
        if self.operation_id.is_empty()
            || self.operation_id.len() > 256
            || self.operation_id.chars().any(char::is_control)
            || [
                self.actor,
                self.tenant_id,
                self.agent_id,
                self.edit_chat_id,
                self.campaign_ref,
                self.target_id,
                self.target_main_basis,
            ]
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err("hosted improve checkpoint has an invalid identity".to_owned());
        }
        Ok(hex::encode(Sha256::digest(self.operation_id.as_bytes())))
    }

    fn matches(&self, record: &InputRecord) -> bool {
        record.actor == self.actor
            && record.tenant_id == self.tenant_id
            && record.agent_id == self.agent_id
            && record.edit_chat_id == self.edit_chat_id
            && record.campaign_ref == self.campaign_ref
            && record.target_id == self.target_id
            && record.target_main_basis == self.target_main_basis
    }
}

impl Workbench {
    pub(crate) fn hosted_improve_prepared_cut(
        &self,
        key: &HostedImproveInputKey<'_>,
    ) -> Result<Option<HostedImprovePreparedCut>, String> {
        let digest = key.digest()?;
        let input = self
            .hosted_improve_input_cut(key)?
            .ok_or("hosted improve has no retained input cut")?;
        let mut found = None;
        for row in self
            .store
            .records(LIBRARY_SCOPE, PREPARED_KIND)
            .map_err(|_| "hosted improve prepared custody is unavailable")?
        {
            let record: PreparedRecord = serde_json::from_str(&row)
                .map_err(|_| "hosted improve prepared record is invalid")?;
            if record.schema != PREPARED_SCHEMA {
                return Err("hosted improve prepared record schema is unsupported".to_owned());
            }
            if record.operation_digest != digest {
                continue;
            }
            if found.is_some()
                || record.baseline_ref != input.baseline.identity
                || record.candidate_ref != input.candidate.identity
            {
                return Err("hosted improve prepared cut differs from its input".to_owned());
            }
            found = Some(record);
        }
        let Some(record) = found else {
            return Ok(None);
        };
        let plaintext = self
            .unseal_account_secret(&record.sealed_prepared)
            .ok_or("hosted improve prepared cut cannot be unsealed")?;
        let cut: HostedImprovePreparedCut = serde_json::from_str(&plaintext)
            .map_err(|_| "hosted improve prepared cut is invalid")?;
        cut.validate()?;
        if cut.baseline_ref != input.baseline.identity
            || cut.candidate_ref != input.candidate.identity
        {
            return Err("hosted improve prepared bytes differ from input refs".to_owned());
        }
        Ok(Some(cut))
    }

    pub(crate) fn retain_hosted_improve_prepared_cut(
        &mut self,
        key: &HostedImproveInputKey<'_>,
        cut: &HostedImprovePreparedCut,
    ) -> Result<(), String> {
        let digest = key.digest()?;
        cut.validate()?;
        let input = self
            .hosted_improve_input_cut(key)?
            .ok_or("hosted improve has no retained input cut")?;
        if cut.baseline_ref != input.baseline.identity
            || cut.candidate_ref != input.candidate.identity
        {
            return Err("hosted improve prepared cut differs from its input".to_owned());
        }
        if let Some(existing) = self.hosted_improve_prepared_cut(key)? {
            return (existing == *cut)
                .then_some(())
                .ok_or("hosted improve operation cannot substitute prepared policy".to_owned());
        }
        let plaintext = serde_json::to_string(cut)
            .map_err(|_| "hosted improve prepared cut could not be encoded")?;
        let sealed_prepared = self
            .seal_account_secret(&plaintext)
            .ok_or("hosted improve prepared cut could not be sealed")?;
        let record = PreparedRecord {
            schema: PREPARED_SCHEMA,
            operation_digest: digest.clone(),
            baseline_ref: cut.baseline_ref.clone(),
            candidate_ref: cut.candidate_ref.clone(),
            sealed_prepared,
        };
        let payload = serde_json::to_string(&record)
            .map_err(|_| "hosted improve prepared record could not be encoded")?;
        self.store
            .append_record_with_key(
                LIBRARY_SCOPE,
                &format!("hosted-improve-prepared:{digest}"),
                PREPARED_KIND,
                &payload,
            )
            .map_err(|_| "hosted improve prepared cut could not be retained")?;
        let recovered = self
            .hosted_improve_prepared_cut(key)?
            .ok_or("hosted improve prepared cut was not retained")?;
        (recovered == *cut)
            .then_some(())
            .ok_or("hosted improve operation cannot substitute prepared policy".to_owned())
    }

    /// Read an admitted input cut after rechecking the source owner, target,
    /// Main basis, and campaign. A missing cut is distinct from unreadable or
    /// conflicting custody: neither may be treated as a fresh run.
    pub(crate) fn hosted_improve_input_cut(
        &self,
        key: &HostedImproveInputKey<'_>,
    ) -> Result<Option<HostedImproveInputCut>, String> {
        let digest = key.digest()?;
        self.verify_hosted_improve_pair_subject(
            key.actor,
            key.agent_id,
            key.target_id,
            key.target_main_basis,
            key.campaign_ref,
        )?;
        let mut found = None;
        for row in self
            .store
            .records(LIBRARY_SCOPE, RECORD_KIND)
            .map_err(|_| "hosted improve input custody is unavailable")?
        {
            let record: InputRecord =
                serde_json::from_str(&row).map_err(|_| "hosted improve input record is invalid")?;
            if record.schema != RECORD_SCHEMA {
                return Err("hosted improve input record schema is unsupported".to_owned());
            }
            if record.operation_digest != digest {
                continue;
            }
            if found.is_some() || !key.matches(&record) {
                return Err("hosted improve operation is bound to another input".to_owned());
            }
            found = Some(record);
        }
        let Some(record) = found else {
            return Ok(None);
        };
        let plaintext = self
            .unseal_account_secret(&record.sealed_definitions)
            .ok_or("hosted improve input definitions cannot be unsealed")?;
        let definitions: Definitions = serde_json::from_str(&plaintext)
            .map_err(|_| "hosted improve input definitions are invalid")?;
        let baseline = AgentDefinitionSnapshot::from_retained_json(&definitions.baseline_json)?;
        let candidate = AgentDefinitionSnapshot::from_retained_json(&definitions.candidate_json)?;
        if baseline.identity != record.baseline_ref || candidate.identity != record.candidate_ref {
            return Err("hosted improve input bytes differ from their retained refs".to_owned());
        }
        if baseline.changed_paths(&candidate).is_empty() {
            return Err("hosted improve input has no candidate change".to_owned());
        }
        Ok(Some(HostedImproveInputCut {
            baseline,
            candidate,
        }))
    }

    /// Seal the exact editable definition pair before any managed arm is
    /// acknowledged. Retrying the same operation with different bytes refuses
    /// substitution, while recovery reads the original cut above.
    pub(crate) fn retain_hosted_improve_input_cut(
        &mut self,
        key: &HostedImproveInputKey<'_>,
        cut: &HostedImproveInputCut,
    ) -> Result<(), String> {
        let digest = key.digest()?;
        if cut.baseline.changed_paths(&cut.candidate).is_empty() {
            return Err("hosted improve input has no candidate change".to_owned());
        }
        if let Some(existing) = self.hosted_improve_input_cut(key)? {
            return (existing == *cut)
                .then_some(())
                .ok_or("hosted improve operation cannot substitute definition bytes".to_owned());
        }
        let definitions = Definitions {
            baseline_json: cut.baseline.retained_json()?,
            candidate_json: cut.candidate.retained_json()?,
        };
        let plaintext = serde_json::to_string(&definitions)
            .map_err(|_| "hosted improve definitions could not be encoded")?;
        let sealed_definitions = self
            .seal_account_secret(&plaintext)
            .ok_or("hosted improve definitions could not be sealed")?;
        let record = InputRecord {
            schema: RECORD_SCHEMA,
            operation_digest: digest.clone(),
            actor: key.actor.to_owned(),
            tenant_id: key.tenant_id.to_owned(),
            agent_id: key.agent_id.to_owned(),
            edit_chat_id: key.edit_chat_id.to_owned(),
            campaign_ref: key.campaign_ref.to_owned(),
            target_id: key.target_id.to_owned(),
            target_main_basis: key.target_main_basis.to_owned(),
            baseline_ref: cut.baseline.identity.clone(),
            candidate_ref: cut.candidate.identity.clone(),
            sealed_definitions,
        };
        let payload = serde_json::to_string(&record)
            .map_err(|_| "hosted improve input record could not be encoded")?;
        self.store
            .append_record_with_key(
                LIBRARY_SCOPE,
                &format!("hosted-improve-input:{digest}"),
                RECORD_KIND,
                &payload,
            )
            .map_err(|_| "hosted improve input could not be retained")?;
        let recovered = self
            .hosted_improve_input_cut(key)?
            .ok_or("hosted improve input was not retained")?;
        (recovered == *cut)
            .then_some(())
            .ok_or("hosted improve operation cannot substitute definition bytes".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LockUnpoisoned;

    const OPEN: &str = r#"{"schema":"gaugedesk.agent-improve.open.v1","gauges":[{"name":"quality","description":"quality"}],"selection":{"ascend":{"quality":null}},"scenarios":[{"id":"open-1","prompt":"Return alpha"}]}"#;
    const PRIVATE: &str = r#"{"schema":"gaugedesk.agent-improve.private.v1","open_checks":{"open-1":{"quality":{"kind":"assistant-contains","text":"alpha"}}},"sealed_scenarios":[]}"#;

    #[test]
    fn sealed_definition_cut_survives_restart_and_refuses_substitution() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let (target, main, campaign) = {
            let mut guard = wb.lock_unpoisoned();
            let agent = guard.library.agents.get_mut(crate::DEFAULT_AGENT).unwrap();
            agent
                .versions
                .get_mut(&agent.current_version)
                .unwrap()
                .source_owner_authority = Some("owner:one".into());
            let campaign = guard
                .register_agent_improve_campaign(
                    crate::DEFAULT_AGENT,
                    OPEN.as_bytes(),
                    PRIVATE.as_bytes(),
                )
                .unwrap();
            let target = guard
                .improve_authoring_target(crate::DEFAULT_AGENT)
                .unwrap();
            let main = guard
                .targets
                .get(&target)
                .unwrap()
                .current_main_cut()
                .unwrap()
                .unwrap();
            (target, main, campaign)
        };
        let key = HostedImproveInputKey {
            operation_id: "request:one",
            actor: "owner:one",
            tenant_id: "tenant:one",
            agent_id: crate::DEFAULT_AGENT,
            edit_chat_id: "edit:one",
            campaign_ref: &campaign,
            target_id: &target,
            target_main_basis: &main,
        };
        let baseline = AgentDefinitionSnapshot::from_retained_json(
            r#"{"agent/AGENTS.md":"baseline",".whipple/draft/main.whip":"go"}"#,
        )
        .unwrap();
        let candidate = AgentDefinitionSnapshot::from_retained_json(
            r#"{"agent/AGENTS.md":"candidate-private-marker",".whipple/draft/main.whip":"go"}"#,
        )
        .unwrap();
        let cut = HostedImproveInputCut {
            baseline,
            candidate,
        };
        let prepared = HostedImprovePreparedCut {
            baseline_ref: cut.baseline.identity.clone(),
            candidate_ref: cut.candidate.identity.clone(),
            baseline_package_ref: "package:baseline".into(),
            candidate_package_ref: "package:candidate".into(),
            baseline_discipline_ref: "discipline:baseline".into(),
            candidate_discipline_ref: "discipline:candidate".into(),
            config_json: "{}".into(),
            isolated: true,
            allow_unfiltered_egress: false,
            chat_id: "chat:one".into(),
            placement_id: "placement:one".into(),
            policy_epoch: 1,
            signed_policy_envelope: "private-signed-policy-marker".into(),
            provider_binding_ref: "provider:one".into(),
            credential_ref: "funding:one".into(),
            placement_ceiling_ref: "ceiling:one".into(),
            provider: "cloudflare-ai-gateway".into(),
            model: "model:one".into(),
            base_url: Some("https://example.test".into()),
            thinking: None,
            roster: vec![("owner:one".into(), "Owner".into())],
            account_scope: "account:one".into(),
            billing_scope: "billing:one".into(),
            funding_ref: "funding:one".into(),
        };
        {
            let mut guard = wb.lock_unpoisoned();
            guard.retain_hosted_improve_input_cut(&key, &cut).unwrap();
            guard.retain_hosted_improve_input_cut(&key, &cut).unwrap();
            guard
                .retain_hosted_improve_prepared_cut(&key, &prepared)
                .unwrap();
            guard
                .retain_hosted_improve_prepared_cut(&key, &prepared)
                .unwrap();
            let rows = guard.store.records(LIBRARY_SCOPE, RECORD_KIND).unwrap();
            assert_eq!(rows.len(), 1);
            assert!(!rows[0].contains("candidate-private-marker"));
            let prepared_rows = guard.store.records(LIBRARY_SCOPE, PREPARED_KIND).unwrap();
            assert_eq!(prepared_rows.len(), 1);
            assert!(!prepared_rows[0].contains("private-signed-policy-marker"));
            let mut changed_policy = prepared.clone();
            changed_policy.signed_policy_envelope = "substitute".into();
            assert!(guard
                .retain_hosted_improve_prepared_cut(&key, &changed_policy)
                .is_err());
            let mut altered = cut.clone();
            altered.candidate =
                AgentDefinitionSnapshot::from_retained_json(r#"{"agent/AGENTS.md":"substitute"}"#)
                    .unwrap();
            assert!(guard
                .retain_hosted_improve_input_cut(&key, &altered)
                .is_err());
        }
        drop(wb);
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut guard = wb.lock_unpoisoned();
        let agent = guard.library.agents.get_mut(crate::DEFAULT_AGENT).unwrap();
        agent
            .versions
            .get_mut(&agent.current_version)
            .unwrap()
            .source_owner_authority = Some("owner:one".into());
        assert_eq!(guard.hosted_improve_input_cut(&key).unwrap(), Some(cut));
        assert_eq!(
            guard.hosted_improve_prepared_cut(&key).unwrap(),
            Some(prepared)
        );
        let wrong_tenant = HostedImproveInputKey {
            tenant_id: "tenant:other",
            ..key
        };
        assert!(guard
            .hosted_improve_input_cut(&wrong_tenant)
            .unwrap_err()
            .contains("another input"));
        let wrong_actor = HostedImproveInputKey {
            actor: "owner:other",
            ..key
        };
        assert!(guard.hosted_improve_input_cut(&wrong_actor).is_err());
    }
}
