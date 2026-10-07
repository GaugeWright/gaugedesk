//! Credit funding for managed work-chat turns (GaugeWright DR-0203, WS-619).
//!
//! A managed work chat is paid from the paying account's credits, on the same
//! allowance ledger the public edge settles against. Three rules shape it, and
//! each is a refusal rather than a convention:
//!
//! **A verified grant, at every call.** The turn is admitted against the
//! current verified funding evidence, and each provider call re-resolves it,
//! so a plan suspended mid-turn cannot fund the next call by stale admission.
//!
//! **A bounded hold before each call.** Before the runtime may send a prepared
//! call, the call's input tokens plus its full output limit are held at the
//! selected model's price plus GaugeWright's margin. A model with no known
//! price is refused rather than held at a guess: the shipped card has no
//! fallback rate, on purpose (`gaugedesk_core::whip_pricing`). Every call the
//! runtime makes is held, a compaction summary included. Input tokens are
//! bounded by the request's serialized size, since no tokenizer emits more
//! tokens than the bytes it reads.
//!
//! **An unknown outcome keeps its hold.** A call admitted once is never
//! admitted again under the same identity, so a replayed call is refused
//! rather than sent twice; and a turn that ends without the runtime's usage
//! leaves its holds open until they are reconciled, instead of releasing money
//! that may already have been spent.
//!
//! Settlement prefers the gateway's measured cost plus the margin, and falls
//! back to the card's estimate only there, recording which basis it used.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use gaugedesk_core::ids::ScopeId;
use gaugedesk_core::whip_pricing::{ModelRates, RateCard};
use gaugedesk_harness::{ManagedCallMeter, ManagedModelCall, ModelUsage};
use gaugedesk_store::{AdmitError, Store};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::deployment_pricing::MARGIN_BASIS_POINTS;
use crate::managed_funding::{FundingAuthority, FundingDenial, ManagedFundingGrant};
use crate::managed_inference::{
    self, ManagedAllowanceCommand, ManagedAllowanceLedger, ManagedAllowanceReserve,
    ManagedAllowanceSettle, ManagedReservationRecord,
};
use crate::{LockUnpoisoned, SharedWorkbench};

/// Each call's cost basis, beside the ledger's settlement.
pub const WORK_CHAT_CALL_COST_KIND: &str = "managed_inference_call_cost";

/// Why a managed work chat may not start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkChatRefusal {
    Funding(FundingDenial),
    /// The selected model has no price on the card, so no hold can be sized.
    Unpriced {
        model: String,
    },
}

impl WorkChatRefusal {
    /// The coded failure a chat shows for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Funding(FundingDenial::Suspended | FundingDenial::Lapsed) => {
                "managed_plan_suspended"
            }
            Self::Funding(_) => "managed_plan_required",
            Self::Unpriced { .. } => "managed_model_unpriced",
        }
    }

    pub fn reason(&self) -> String {
        match self {
            Self::Funding(FundingDenial::Suspended | FundingDenial::Lapsed) => {
                "Managed inference is suspended for this account; future model runs are paused while prior usage and history remain unchanged.".to_owned()
            }
            Self::Funding(denial) => format!(
                "Managed inference needs a verified, current plan ({denial:?}). Open Account settings or ask a billing admin to choose a plan."
            ),
            Self::Unpriced { model } => format!(
                "The managed model `{model}` has no known price, so no credit can be held for it. Choose another model."
            ),
        }
    }
}

/// The hold one call takes before it is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallHold {
    pub maximum_tokens: u64,
    pub maximum_nanos_usd: u64,
}

/// Apply GaugeWright's margin, rounding up so no amount bills below cost plus
/// margin (the same rule as [`crate::deployment_pricing`]).
pub fn with_margin(cost_nanos_usd: u64) -> u64 {
    let billed = u128::from(cost_nanos_usd) * u128::from(10_000 + MARGIN_BASIS_POINTS);
    u64::try_from(billed.div_ceil(10_000)).unwrap_or(u64::MAX)
}

/// Upstream cost of a token count at the card's per-million micro-USD rates,
/// in nanos USD, rounded up. One micro-USD per million tokens is one
/// thousandth of a nano per token, so the sum divides by a thousand.
fn upstream_nanos_usd(terms: &[(u64, u64)]) -> u64 {
    let micro_tokens = terms.iter().fold(0_u128, |total, (tokens, rate)| {
        total.saturating_add(u128::from(*tokens) * u128::from(*rate))
    });
    u64::try_from(micro_tokens.div_ceil(1_000)).unwrap_or(u64::MAX)
}

/// The most one input token can cost on this card: a prompt may be written to
/// a cache, read from one, or neither, and the hold must cover the dearest.
fn dearest_input_rate(rates: &ModelRates) -> u64 {
    rates
        .input_uncached
        .max(rates.input_cache_read)
        .max(rates.input_cache_write)
}

/// The hold for one call: every input token at the dearest input rate and the
/// whole output limit at the output rate, plus margin.
pub fn call_hold(rates: &ModelRates, input_tokens: u64, output_limit: u64) -> CallHold {
    CallHold {
        maximum_tokens: input_tokens.saturating_add(output_limit),
        maximum_nanos_usd: with_margin(upstream_nanos_usd(&[
            (input_tokens, dearest_input_rate(rates)),
            (output_limit, rates.output),
        ])),
    }
}

/// The card's estimate of what reported tokens cost, plus margin. Used only at
/// settlement, and only when the gateway's measured cost is unavailable.
pub fn estimated_cost(rates: &ModelRates, input_tokens: u64, output_tokens: u64) -> u64 {
    with_margin(upstream_nanos_usd(&[
        (input_tokens, rates.input_uncached),
        (output_tokens, rates.output),
    ]))
}

/// No tokenizer emits more tokens than the bytes it reads, so the request's
/// serialized size bounds its input tokens from above.
pub fn input_token_bound(body: &serde_json::Value) -> Result<u64, String> {
    serde_json::to_vec(body)
        .map(|bytes| bytes.len() as u64)
        .map_err(|_| "managed model request cannot be measured".to_owned())
}

/// Split `total` across holds in call order: each takes up to its own hold and
/// the last takes whatever remains, so the parts always sum to the total.
pub fn allocate(holds: &[u64], total: u64) -> Vec<u64> {
    let mut remaining = total;
    let mut parts = Vec::with_capacity(holds.len());
    for (index, hold) in holds.iter().enumerate() {
        let part = if index + 1 == holds.len() {
            remaining
        } else {
            (*hold).min(remaining)
        };
        remaining -= part;
        parts.push(part);
    }
    parts
}

/// A call's reservation id. Stable across a recovered turn, so a replay finds
/// the call it already admitted; length-prefixed, so no caller-chosen part
/// can alias another chat, turn or call.
pub fn call_reservation_id(
    engagement_scope: &str,
    user_entry_id: i64,
    command_id: &str,
    ordinal: u64,
) -> String {
    let mut digest = Sha256::new();
    for part in [
        engagement_scope,
        &user_entry_id.to_string(),
        command_id,
        &ordinal.to_string(),
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("work-chat-call:{}", hex::encode(digest.finalize()))
}

fn now_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| format!("{error:?}"))
}

/// What a turn was admitted under: the exact verified source and the selected
/// model's price.
#[derive(Clone, Debug)]
pub struct WorkChatFunding {
    pub account_scope: String,
    pub tenant_scope: String,
    pub billing_scope: String,
    pub funding_ref: String,
    pub model: String,
    pub rates: ModelRates,
    pub rate_card_version: String,
}

/// Admit a managed work-chat turn: a verified, current grant and a priced model.
pub fn admit(
    store: &Store,
    authority: &FundingAuthority,
    now: u64,
    account_scope: &str,
    tenant_scope: &str,
    model: &str,
    card: &RateCard,
) -> Result<Result<WorkChatFunding, WorkChatRefusal>, AdmitError> {
    let grant = match crate::managed_funding::resolve_plan(
        store,
        &ScopeId::new(account_scope),
        &ScopeId::new(tenant_scope),
        &authority.context(now),
    )? {
        Ok(grant) => grant,
        Err(denial) => return Ok(Err(WorkChatRefusal::Funding(denial))),
    };
    // Holds and draws are in US dollars; a card in any other currency prices
    // nothing this ledger can hold.
    let Some(rates) = card
        .models
        .get(model)
        .filter(|_| card.currency.code() == "USD")
    else {
        return Ok(Err(WorkChatRefusal::Unpriced {
            model: model.to_owned(),
        }));
    };
    Ok(Ok(WorkChatFunding {
        account_scope: account_scope.to_owned(),
        tenant_scope: tenant_scope.to_owned(),
        billing_scope: grant.evidence().scope.as_str().to_owned(),
        funding_ref: grant.reference(),
        model: model.to_owned(),
        rates: rates.clone(),
        rate_card_version: card.version.clone(),
    }))
}

/// The call being held, as the turn remembers it until settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldCall {
    pub reservation_id: String,
    pub hold: CallHold,
}

/// Why a call was not admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallRefusal {
    Funding(FundingDenial),
    SourceChanged,
    CreditsExhausted,
    /// This exact call was admitted before. Its outcome is unknown, so it is
    /// never sent a second time; its hold stays until reconciled.
    AlreadyAdmitted,
}

impl CallRefusal {
    pub fn reason(&self) -> String {
        match self {
            Self::Funding(denial) => format!("managed inference funding refused: {denial:?}"),
            Self::SourceChanged => "managed inference funding source changed".to_owned(),
            Self::CreditsExhausted => "managed inference credits are exhausted".to_owned(),
            Self::AlreadyAdmitted => {
                "managed model call was already admitted; an unknown outcome is not replayed"
                    .to_owned()
            }
        }
    }
}

/// Hold credit for one call against a freshly re-resolved grant. The caller
/// holds the store's ordering lock across this whole function.
#[allow(clippy::too_many_arguments)]
pub fn reserve_call(
    store: &mut Store,
    authority: &FundingAuthority,
    funding: &WorkChatFunding,
    engagement_scope: &str,
    reservation_id: &str,
    hold: CallHold,
    now: u64,
) -> Result<Result<(), CallRefusal>, AdmitError> {
    let grant: ManagedFundingGrant = match crate::managed_funding::resolve_plan(
        store,
        &ScopeId::new(&funding.account_scope),
        &ScopeId::new(&funding.tenant_scope),
        &authority.context(now),
    )? {
        Ok(grant) => grant,
        Err(denial) => return Ok(Err(CallRefusal::Funding(denial))),
    };
    if grant.evidence().scope.as_str() != funding.billing_scope
        || grant.reference() != funding.funding_ref
    {
        return Ok(Err(CallRefusal::SourceChanged));
    }
    let billing_scope = funding.billing_scope.as_str();
    let allowance = store.fold::<ManagedAllowanceLedger>(billing_scope)?;
    if allowance.reservations.contains_key(reservation_id) {
        return Ok(Err(CallRefusal::AlreadyAdmitted));
    }
    let used = managed_inference::fold_usage_for_funding_period(
        store,
        billing_scope,
        &funding.funding_ref,
        grant.evidence().valid_from,
        grant.evidence().valid_until,
        grant.plan().included_tokens,
    )?
    .total_tokens;
    let record = ManagedReservationRecord {
        id: reservation_id.to_owned(),
        engagement_id: engagement_scope.to_owned(),
        funding_ref: funding.funding_ref.clone(),
        maximum_tokens: hold.maximum_tokens,
        admitted_at: Some(now),
        valid_from: Some(grant.evidence().valid_from),
        valid_until: Some(grant.evidence().valid_until),
        maximum_nanos_usd: hold.maximum_nanos_usd,
    };
    let admitted = store.admit_materialized::<ManagedAllowanceLedger>(
        billing_scope,
        &format!("managed-allowance-reserve:{reservation_id}"),
        ManagedAllowanceCommand::Reserve(ManagedAllowanceReserve {
            reservation: record.clone(),
            observed_tokens: used,
            included_tokens: grant.plan().included_tokens,
        }),
    );
    match admitted {
        Ok(admission) if admission.replayed => return Ok(Err(CallRefusal::AlreadyAdmitted)),
        Ok(_) => {}
        Err(AdmitError::Rejected(rejection))
            if rejection.reason == "managed inference credits exhausted" =>
        {
            return Ok(Err(CallRefusal::CreditsExhausted));
        }
        Err(error) => return Err(error),
    }
    managed_inference::reserve_bounded_turn(store, billing_scope, record.clone())?;
    if engagement_scope != billing_scope {
        store.append_record_with_key(
            engagement_scope,
            &format!("managed-reserve:{reservation_id}"),
            managed_inference::MANAGED_RESERVATION_KIND,
            &serde_json::to_string(&record)?,
        )?;
    }
    Ok(Ok(()))
}

/// Where a settled cost came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostBasis {
    /// The gateway's own logged cost, plus margin.
    Measured,
    /// The rate card applied to the runtime's token counts, plus margin.
    Estimated,
}

/// One call's settled cost, beside the ledger's settlement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallCostRecord {
    pub reservation_id: String,
    pub usage_ref: String,
    pub drawn_nanos_usd: u64,
    pub cost_basis: CostBasis,
    pub rate_card_version: String,
    pub margin_basis_points: u64,
}

/// What a turn's settlement drew.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettledTurn {
    pub drawn_nanos_usd: u64,
    pub cost_basis: CostBasis,
}

/// Settle every call a turn held from the runtime's usage for the turn.
///
/// `measured_upstream_nanos_usd` is the gateway's logged cost for those calls,
/// before margin; without it the card estimates. The cost is split across the
/// holds in call order, so the ledger draws exactly the turn's cost.
#[allow(clippy::too_many_arguments)]
pub fn settle_calls(
    store: &mut Store,
    funding: &WorkChatFunding,
    engagement_scope: &str,
    calls: &[HeldCall],
    usage: &ModelUsage,
    measured_upstream_nanos_usd: Option<u64>,
    observed_at: u64,
) -> Result<SettledTurn, String> {
    if calls.is_empty() {
        return Err("managed usage arrived for a turn that held no call".to_owned());
    }
    if usage.usage_ref.trim().is_empty() {
        // No reliable key would make the append and settlement idempotent;
        // the holds stay for reconciliation.
        return Err("managed usage has no evidence reference".to_owned());
    }
    if usage.model != funding.model {
        return Err("managed usage does not match the admitted model".to_owned());
    }
    let (total, cost_basis) = match measured_upstream_nanos_usd {
        Some(measured) => (with_margin(measured), CostBasis::Measured),
        None => (
            estimated_cost(&funding.rates, usage.input_tokens, usage.output_tokens),
            CostBasis::Estimated,
        ),
    };
    let holds = calls
        .iter()
        .map(|call| call.hold.maximum_nanos_usd)
        .collect::<Vec<_>>();
    let costs = allocate(&holds, total);
    let token_holds = calls
        .iter()
        .map(|call| call.hold.maximum_tokens)
        .collect::<Vec<_>>();
    let tokens = allocate(
        &token_holds,
        usage.input_tokens.saturating_add(usage.output_tokens),
    );
    let billing_scope = funding.billing_scope.as_str();
    managed_inference::append_funded_usage(
        store,
        engagement_scope,
        billing_scope,
        usage,
        &funding.funding_ref,
        observed_at,
    )
    .map_err(|error| format!("{error:?}"))?;
    for ((call, drawn), actual_tokens) in calls.iter().zip(costs).zip(tokens) {
        let call_usage_ref = format!("{}#{}", usage.usage_ref, call.reservation_id);
        store
            .admit_materialized::<ManagedAllowanceLedger>(
                billing_scope,
                &format!("managed-allowance-settle:{}", call.reservation_id),
                ManagedAllowanceCommand::Settle(ManagedAllowanceSettle {
                    reservation_id: call.reservation_id.clone(),
                    usage_ref: call_usage_ref.clone(),
                    actual_tokens,
                    actual_nanos_usd: Some(drawn),
                }),
            )
            .map_err(|error| format!("{error:?}"))?;
        let cost = CallCostRecord {
            reservation_id: call.reservation_id.clone(),
            usage_ref: call_usage_ref.clone(),
            drawn_nanos_usd: drawn,
            cost_basis,
            rate_card_version: funding.rate_card_version.clone(),
            margin_basis_points: MARGIN_BASIS_POINTS,
        };
        store
            .append_record_with_key(
                billing_scope,
                &format!("managed-call-cost:{}", call.reservation_id),
                WORK_CHAT_CALL_COST_KIND,
                &serde_json::to_string(&cost).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("{error:?}"))?;
        managed_inference::settle_reservation(
            store,
            engagement_scope,
            billing_scope,
            &call.reservation_id,
            Some(&call_usage_ref),
            "",
        )
        .map_err(|error| format!("{error:?}"))?;
    }
    Ok(SettledTurn {
        drawn_nanos_usd: total,
        cost_basis,
    })
}

/// Where a meter reaches the ledger. Each operation runs under the store's
/// ordering lock, so two chats on one account cannot both spend its last
/// credit.
pub trait LedgerAccess: Send + Sync {
    fn with_store(
        &self,
        operation: &mut dyn FnMut(&mut Store) -> Result<(), String>,
    ) -> Result<(), String>;
}

impl LedgerAccess for SharedWorkbench {
    fn with_store(
        &self,
        operation: &mut dyn FnMut(&mut Store) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut guard = self.lock_unpoisoned();
        operation(&mut guard.store)
    }
}

impl LedgerAccess for Mutex<Store> {
    fn with_store(
        &self,
        operation: &mut dyn FnMut(&mut Store) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut store = self.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        operation(&mut store)
    }
}

#[derive(Default)]
struct MeterState {
    /// The chat and its turn's user entry, known once the turn is admitted.
    turn: Option<(String, i64)>,
    held: Vec<HeldCall>,
}

/// Holds credit for a managed work-chat turn's calls as the runtime prepares
/// them, and settles them when the turn's usage arrives.
pub struct WorkChatMeter {
    ledger: Arc<dyn LedgerAccess>,
    authority: FundingAuthority,
    funding: WorkChatFunding,
    state: Mutex<MeterState>,
}

impl WorkChatMeter {
    pub fn new(
        ledger: Arc<dyn LedgerAccess>,
        authority: FundingAuthority,
        funding: WorkChatFunding,
    ) -> Self {
        Self {
            ledger,
            authority,
            funding,
            state: Mutex::new(MeterState::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, MeterState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn funding(&self) -> &WorkChatFunding {
        &self.funding
    }

    /// Name the turn whose calls follow. Called once the user's entry exists.
    pub fn begin_turn(&self, engagement_scope: &str, user_entry_id: i64) {
        let mut state = self.state();
        state.turn = Some((engagement_scope.to_owned(), user_entry_id));
        state.held.clear();
    }

    /// The calls held so far, in order.
    pub fn held(&self) -> Vec<HeldCall> {
        self.state().held.clone()
    }

    /// Settle the turn's held calls from the runtime's usage. Without usage
    /// the holds stay open: the calls' outcome is unknown, and releasing them
    /// could free money already spent.
    pub fn settle(
        &self,
        usage: &ModelUsage,
        measured_upstream_nanos_usd: Option<u64>,
    ) -> Result<SettledTurn, String> {
        let (engagement, calls) = {
            let state = self.state();
            let (engagement, _) = state
                .turn
                .clone()
                .ok_or_else(|| "managed turn was never begun".to_owned())?;
            (engagement, state.held.clone())
        };
        let observed_at = now_secs()?;
        let mut settled = None;
        self.ledger.with_store(&mut |store| {
            settled = Some(settle_calls(
                store,
                &self.funding,
                &engagement,
                &calls,
                usage,
                measured_upstream_nanos_usd,
                observed_at,
            )?);
            Ok(())
        })?;
        settled.ok_or_else(|| "managed settlement did not run".to_owned())
    }
}

impl ManagedCallMeter for WorkChatMeter {
    fn admit_call(&self, call: &ManagedModelCall<'_>) -> Result<(), String> {
        let (engagement, user_entry_id) = self
            .state()
            .turn
            .clone()
            .ok_or_else(|| "managed model call arrived before its turn".to_owned())?;
        if call.command_id.trim().is_empty() || call.ordinal == 0 || call.output_limit == 0 {
            return Err("managed model call has no stable identity or output bound".to_owned());
        }
        let hold = call_hold(
            &self.funding.rates,
            input_token_bound(call.body)?,
            call.output_limit,
        );
        let reservation_id =
            call_reservation_id(&engagement, user_entry_id, call.command_id, call.ordinal);
        let now = now_secs()?;
        self.ledger.with_store(&mut |store| {
            reserve_call(
                store,
                &self.authority,
                &self.funding,
                &engagement,
                &reservation_id,
                hold,
                now,
            )
            .map_err(|error| format!("{error:?}"))?
            .map_err(|refusal| refusal.reason())
        })?;
        self.state().held.push(HeldCall {
            reservation_id,
            hold,
        });
        Ok(())
    }
}

#[cfg(test)]
#[path = "work_chat_funding_tests.rs"]
pub(crate) mod tests;
