//! Home-owned funding admission for hosted Agent improvement turns.

use std::time::{SystemTime, UNIX_EPOCH};

use gaugedesk_core::ids::ScopeId;
use gaugedesk_harness::{HarnessSpec, TurnOutcome};

use crate::agent_improve::ShadowTurnMeter;
use crate::agent_improve_campaign::ManagedCampaignFunding;
use crate::library::gen_id;
use crate::{managed_funding, managed_inference};
use crate::{LockUnpoisoned, SharedWorkbench};

/// One campaign attempt uses its own private engagement scope. The billing
/// scope is resolved again before every arm, so a plan suspended between
/// baseline and candidate cannot fund the candidate by stale preparation.
pub(crate) struct ManagedShadowMeter<'a> {
    wb: &'a SharedWorkbench,
    engagement_scope: String,
    account_scope: String,
    tenant_scope: String,
    billing_scope: String,
    funding_ref: String,
    provider: String,
    funding_authority: managed_funding::FundingAuthority,
}

impl<'a> ManagedShadowMeter<'a> {
    pub(crate) fn new(
        wb: &'a SharedWorkbench,
        engagement_scope: String,
        funding: ManagedCampaignFunding,
    ) -> Self {
        let ManagedCampaignFunding {
            account_scope,
            tenant_scope,
            billing_scope,
            funding_ref,
            provider,
            funding_authority,
        } = funding;
        Self {
            wb,
            engagement_scope,
            account_scope,
            tenant_scope,
            billing_scope,
            funding_ref,
            provider,
            funding_authority,
        }
    }
}

impl ShadowTurnMeter for ManagedShadowMeter<'_> {
    fn reserve(&mut self, spec: &HarnessSpec) -> Result<String, String> {
        if self.provider != managed_inference::METERED_GATEWAY_PROVIDER
            || spec.provider.as_deref() != Some(&self.provider)
            || spec.credential_ref.as_deref() != Some(&self.funding_ref)
            || spec
                .runtime_placement_id
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err("managed Agent improve model binding or placement changed".to_owned());
        }
        let mut guard = self.wb.lock_unpoisoned();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("{error:?}"))?
            .as_secs();
        let grant = managed_funding::resolve_plan(
            guard.store_ref(),
            &ScopeId::new(&self.account_scope),
            &ScopeId::new(&self.tenant_scope),
            &self.funding_authority.context(now),
        )
        .map_err(|error| format!("{error:?}"))?
        .map_err(|denial| format!("managed Agent improve funding refused: {denial:?}"))?;
        if grant.evidence().scope.as_str() != self.billing_scope
            || grant.reference() != self.funding_ref
        {
            return Err("managed Agent improve funding source changed".to_owned());
        }
        let reservation_id = gen_id("agent-improve-managed");
        managed_inference::reserve_turn(
            &mut guard.store,
            &self.engagement_scope,
            &self.billing_scope,
            &self.funding_ref,
            &reservation_id,
        )
        .map_err(|error| format!("{error:?}"))?;
        Ok(reservation_id)
    }

    fn settle(
        &mut self,
        reservation_id: &str,
        outcome: Option<&TurnOutcome>,
    ) -> Result<(), String> {
        let mut guard = self.wb.lock_unpoisoned();
        let usage = outcome.and_then(|outcome| outcome.managed_usage.as_ref());
        if usage.is_some_and(|usage| usage.provider != self.provider) {
            return Err("managed Agent improve usage does not match its provider".to_owned());
        }
        if outcome.is_some_and(|outcome| outcome.error.is_none()) && usage.is_none() {
            managed_inference::settle_reservation(
                &mut guard.store,
                &self.engagement_scope,
                &self.billing_scope,
                reservation_id,
                None,
                "model_completed_without_usage_evidence",
            )
            .map_err(|error| format!("{error:?}"))?;
            return Err("managed Agent improve completed without usage evidence".to_owned());
        }
        if let Some(usage) = usage {
            if usage.usage_ref.trim().is_empty() {
                // Keep this reservation outstanding for recovery; no reliable
                // usage key exists to make an append and settlement idempotent.
                return Err("managed Agent improve usage has no evidence reference".to_owned());
            }
            let observed_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("{error:?}"))?
                .as_secs();
            managed_inference::append_funded_usage(
                &mut guard.store,
                &self.engagement_scope,
                &self.billing_scope,
                usage,
                &self.funding_ref,
                observed_at,
            )
            .map_err(|error| format!("{error:?}"))?;
        }
        managed_inference::settle_reservation(
            &mut guard.store,
            &self.engagement_scope,
            &self.billing_scope,
            reservation_id,
            usage.map(|usage| usage.usage_ref.as_str()),
            "model_transport_failed_without_usage",
        )
        .map_err(|error| format!("{error:?}"))?;
        Ok(())
    }
}
