//! Verified future-spend evidence, separate from editable billing settings.
//!
//! The funding authority admits `FundingRecord` to the existing plan stream
//! after authenticating/reconciling its source. These types are not an HTTP
//! command or a way to trust caller-supplied evidence. In particular, the old
//! `ManagedPlanRecord` remains readable but carries no funding authority.
//!
//! `decide` is pure. The store adapters load admitted records; callers supply
//! the execution boundary's issuer/environment and time, never browser input.
//! A grant proves eligibility at that instant, not an enduring reservation:
//! dispatch must recheck current evidence before spending.

use gaugedesk_core::ids::{AuthorityId, ScopeId};
use gaugedesk_store::{AdmitError, Store};
use serde::{Deserialize, Serialize};

use crate::library::RecordOp;
use crate::managed_inference::{
    ManagedInferencePlan, ManagedPlanRecord, ManagedPlanStatus, MANAGED_PLAN_KIND,
};

pub const FUNDING_REFERENCE_PREFIX: &str = "gaugedesk:managed-plan:v2:";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FundingEnvironment {
    Test,
    Live,
}

impl FundingEnvironment {
    fn label(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Live => "live",
        }
    }
}

/// Non-secret provenance admitted by the funding service, not by billing forms.
/// The issuer is provider-neutral: the private service owns processor details.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FundingEvidence {
    pub v: u8,
    pub issuer: AuthorityId,
    pub scope: ScopeId,
    pub source_id: String,
    pub environment: FundingEnvironment,
    pub verified_at: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

/// Extends the original record without rewriting historical records. Missing
/// provenance is expressly *not* a default live service grant.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FundingRecord {
    #[serde(flatten)]
    pub record: ManagedPlanRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<FundingEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingContext {
    pub issuer: AuthorityId,
    pub environment: FundingEnvironment,
    pub now: u64,
}

/// Server-owned half of a funding context. Route composition supplies this
/// after choosing the authenticated producer and processor environment; an HTTP
/// caller can supply neither. The request handler adds only its current clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingAuthority {
    issuer: AuthorityId,
    environment: FundingEnvironment,
}

impl FundingAuthority {
    pub fn new(issuer: AuthorityId, environment: FundingEnvironment) -> Self {
        Self {
            issuer,
            environment,
        }
    }

    pub fn context(&self, now: u64) -> FundingContext {
        FundingContext {
            issuer: self.issuer.clone(),
            environment: self.environment,
            now,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingDenial {
    InvalidContext,
    NotConfigured,
    Unverified,
    WrongContext,
    InvalidEvidence,
    Revoked,
    Suspended,
    Lapsed,
    NotYetValid,
    Expired,
    InvalidReference,
    SourceChanged,
}

/// Constructible only through `decide`, after all bindings have been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedFundingGrant {
    plan: ManagedInferencePlan,
    evidence: FundingEvidence,
}

impl ManagedFundingGrant {
    pub fn plan(&self) -> &ManagedInferencePlan {
        &self.plan
    }

    pub fn evidence(&self) -> &FundingEvidence {
        &self.evidence
    }

    /// Stable across renewals of this source, distinct across replacements,
    /// issuers, scopes and environments. A reference alone authorizes nothing.
    pub fn reference(&self) -> String {
        format!(
            "{FUNDING_REFERENCE_PREFIX}{}:{}:{}:{}:{}",
            hex::encode(self.evidence.scope.as_str()),
            hex::encode(&self.plan.plan),
            hex::encode(self.evidence.issuer.as_str()),
            self.evidence.environment.label(),
            hex::encode(&self.evidence.source_id),
        )
    }
}

pub type FundingResolution = Result<ManagedFundingGrant, FundingDenial>;

/// Recover the exact account scope named by a v2 reference without treating
/// the reference as authorization. This is used only to close an already
/// admitted reservation after the plan has lapsed or been revoked; new spend
/// must still pass [`resolve_reference`].
pub fn reference_scope(reference: &str) -> Option<ScopeId> {
    let encoded = reference.strip_prefix(FUNDING_REFERENCE_PREFIX)?;
    let parts = encoded.split(':').collect::<Vec<_>>();
    if parts.len() != 5 {
        return None;
    }
    hex::decode(parts[0])
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|scope| ScopeId::parse(scope).ok())
}

/// Read only the selected scope's ordered stream. Another known financial
/// context cannot overwrite its current evidence. An unclassified later change
/// is a barrier until fresh matching evidence is admitted, including when the
/// unclassified change was a tombstone from an older service version.
pub fn decide(
    scope: &ScopeId,
    records: &[FundingRecord],
    context: &FundingContext,
) -> FundingResolution {
    if context.now == 0
        || context.issuer.as_str().trim().is_empty()
        || scope.as_str().trim().is_empty()
    {
        return Err(FundingDenial::InvalidContext);
    }
    let mut selected = Err(if records.is_empty() {
        FundingDenial::NotConfigured
    } else {
        FundingDenial::WrongContext
    });
    for record in records {
        let Some(provenance) = &record.provenance else {
            selected = Err(FundingDenial::Unverified);
            continue;
        };
        if provenance.v != 1 || provenance.issuer.as_str().trim().is_empty() {
            selected = Err(FundingDenial::Unverified);
        } else if provenance.issuer == context.issuer
            && provenance.environment == context.environment
        {
            selected = Ok(record);
        }
    }
    let record = selected?;
    let evidence = record
        .provenance
        .as_ref()
        .ok_or(FundingDenial::Unverified)?;
    if evidence.scope != *scope || evidence.source_id.trim().is_empty() {
        return Err(FundingDenial::InvalidEvidence);
    }
    if record.record.op == RecordOp::Tombstone {
        return Err(FundingDenial::Revoked);
    }
    if record.record.id.trim().is_empty()
        || record.record.subscription.plan.trim().is_empty()
        || evidence.verified_at == 0
        || evidence.verified_at > context.now
        || evidence.valid_from == 0
        || evidence.valid_until <= evidence.valid_from
    {
        return Err(FundingDenial::InvalidEvidence);
    }
    match record.record.subscription.status {
        ManagedPlanStatus::Suspended => return Err(FundingDenial::Suspended),
        ManagedPlanStatus::Lapsed => return Err(FundingDenial::Lapsed),
        ManagedPlanStatus::Active => {}
    }
    if context.now < evidence.valid_from {
        return Err(FundingDenial::NotYetValid);
    }
    if context.now >= evidence.valid_until {
        return Err(FundingDenial::Expired);
    }
    Ok(ManagedFundingGrant {
        plan: record.record.subscription.clone(),
        evidence: evidence.clone(),
    })
}

fn read_records(store: &Store, scope: &ScopeId) -> Result<Vec<FundingRecord>, AdmitError> {
    store
        .records(scope.as_str(), MANAGED_PLAN_KIND)?
        .into_iter()
        .map(|row| serde_json::from_str(&row).map_err(AdmitError::from))
        .collect()
}

/// Resolve organization-first billing. Once an organization has any funding
/// selection, failure never silently charges the person instead. Historical
/// Org.billing is an unverified selection, not an issuer of a paid service.
pub fn resolve_plan(
    store: &Store,
    account_scope: &ScopeId,
    tenant_scope: &ScopeId,
    context: &FundingContext,
) -> Result<FundingResolution, AdmitError> {
    let records = read_records(store, tenant_scope)?;
    if !records.is_empty() {
        return Ok(decide(tenant_scope, &records, context));
    }
    let org = crate::org::Org::rebuild_in(store, tenant_scope.as_str())?;
    if org
        .billing
        .and_then(|billing| billing.managed_inference)
        .is_some()
    {
        return Ok(Err(FundingDenial::Unverified));
    }
    Ok(decide(
        account_scope,
        &read_records(store, account_scope)?,
        context,
    ))
}

/// Public callers cannot select a funding scope by falling back to a logged-in
/// account. Decode the exact v2 reference, re-evaluate that scope, and require
/// the current source to reconstruct the identical reference. Legacy v1 needs
/// fresh owner admission rather than an invented issuer or environment.
pub fn resolve_reference(
    store: &Store,
    reference: &str,
    context: &FundingContext,
) -> Result<FundingResolution, AdmitError> {
    let Some(scope) = reference_scope(reference) else {
        return Ok(Err(FundingDenial::InvalidReference));
    };
    let result = decide(&scope, &read_records(store, &scope)?, context).and_then(|grant| {
        if grant.reference() == reference {
            Ok(grant)
        } else {
            Err(FundingDenial::SourceChanged)
        }
    });
    Ok(result)
}

#[cfg(test)]
#[path = "managed_funding_tests.rs"]
mod tests;
