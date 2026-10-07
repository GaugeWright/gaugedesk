use std::collections::BTreeMap;

use gaugedesk_core::ids::AuthorityId;
use gaugedesk_core::model_connection::access::Currency;

use super::*;
use crate::library::RecordOp;
use crate::managed_funding::{FundingEnvironment, FundingEvidence, FundingRecord};
use crate::managed_inference::{
    ManagedAllowanceStatus, ManagedCreditGrant, ManagedInferencePlan, ManagedPlanRecord,
    ManagedPlanStatus, MANAGED_PLAN_KIND,
};

const ACCOUNT: &str = "account::person";
pub(crate) const TENANT: &str = "org::acme";
const CHAT: &str = "chat::one";
pub(crate) const MODEL: &str = "test-model";

pub(crate) fn authority() -> FundingAuthority {
    FundingAuthority::new(
        AuthorityId::new("funding-service"),
        FundingEnvironment::Live,
    )
}

fn now() -> u64 {
    now_secs().unwrap()
}

fn plan(status: ManagedPlanStatus) -> FundingRecord {
    FundingRecord {
        record: ManagedPlanRecord {
            id: "managed-inference".into(),
            op: RecordOp::Upsert,
            subscription: ManagedInferencePlan {
                plan: "team".into(),
                status,
                included_tokens: 0,
            },
        },
        provenance: Some(FundingEvidence {
            v: 1,
            issuer: AuthorityId::new("funding-service"),
            scope: ScopeId::new(TENANT),
            source_id: "subscription:one".into(),
            environment: FundingEnvironment::Live,
            verified_at: 1,
            valid_from: 1,
            valid_until: now() + 86_400,
        }),
    }
}

fn rates() -> ModelRates {
    ModelRates {
        input_uncached: 3_000_000,
        input_cache_read: 300_000,
        input_cache_write: 3_750_000,
        output: 15_000_000,
        source: "test fixture".into(),
        as_of: "2026-10-06".into(),
    }
}

fn card() -> RateCard {
    RateCard {
        version: "test-v1".into(),
        currency: Currency::try_from("USD".to_owned()).unwrap(),
        models: BTreeMap::from([(MODEL.to_owned(), rates())]),
    }
}

pub(crate) fn funded_store(credit_nanos_usd: u64) -> Store {
    let mut store = Store::open_in_memory().unwrap();
    store
        .append_record(
            TENANT,
            MANAGED_PLAN_KIND,
            &serde_json::to_string(&plan(ManagedPlanStatus::Active)).unwrap(),
        )
        .unwrap();
    store
        .admit_materialized::<ManagedAllowanceLedger>(
            TENANT,
            "grant:test",
            ManagedAllowanceCommand::Grant(ManagedCreditGrant {
                grant_id: "test".into(),
                nanos_usd: credit_nanos_usd,
                reason: "operator".into(),
                granted_at: 1,
            }),
        )
        .unwrap();
    store
}

pub(crate) fn funding(store: &Store) -> WorkChatFunding {
    admit(store, &authority(), now(), ACCOUNT, TENANT, MODEL, &card())
        .unwrap()
        .unwrap()
}

fn meter(store: Store) -> (Arc<Mutex<Store>>, WorkChatMeter) {
    let funding = funding(&store);
    let ledger = Arc::new(Mutex::new(store));
    let meter = WorkChatMeter::new(ledger.clone(), authority(), funding);
    meter.begin_turn(CHAT, 7);
    (ledger, meter)
}

fn body(text: &str) -> serde_json::Value {
    serde_json::json!({ "model": MODEL, "input": text })
}

fn call<'a>(ordinal: u64, body: &'a serde_json::Value) -> ManagedModelCall<'a> {
    ManagedModelCall {
        command_id: "command:1",
        ordinal,
        url: "https://gateway.test/v1/responses",
        body,
        output_limit: 8_192,
    }
}

pub(crate) fn usage(input: u64, output: u64) -> ModelUsage {
    ModelUsage {
        usage_ref: "whip:usage:1".into(),
        provider: "cloudflare-ai-gateway".into(),
        model: MODEL.into(),
        input_tokens: input,
        output_tokens: output,
    }
}

pub(crate) fn ledger_state(
    ledger: &Mutex<Store>,
) -> crate::managed_inference::ManagedAllowanceState {
    ledger
        .lock()
        .unwrap()
        .fold::<ManagedAllowanceLedger>(TENANT)
        .unwrap()
}

#[test]
fn a_call_holds_its_input_and_whole_output_limit_at_the_model_price_plus_margin() {
    // 1,000 input tokens at the dearest input rate ($3.75/M, a cache write)
    // and 8,192 output tokens at $15/M: $0.12663 upstream, $0.151956 billed.
    let hold = call_hold(&rates(), 1_000, 8_192);
    assert_eq!(hold.maximum_tokens, 9_192);
    assert_eq!(hold.maximum_nanos_usd, 151_956_000);
}

#[test]
fn margin_never_rounds_below_cost_plus_twenty_percent() {
    assert_eq!(with_margin(0), 0);
    assert_eq!(with_margin(1), 2);
    assert_eq!(with_margin(10), 12);
    assert_eq!(with_margin(11), 14);
}

#[test]
fn the_estimate_prices_reported_tokens_at_the_uncached_input_rate() {
    // 1,000 in at $3/M + 100 out at $15/M = $0.0045, $0.0054 billed.
    assert_eq!(estimated_cost(&rates(), 1_000, 100), 5_400_000);
}

#[test]
fn input_is_bounded_by_the_requests_serialized_size() {
    let body = body("hello");
    assert_eq!(
        input_token_bound(&body).unwrap(),
        serde_json::to_vec(&body).unwrap().len() as u64
    );
}

#[test]
fn allocation_fills_holds_in_order_and_the_last_call_takes_any_excess() {
    assert_eq!(allocate(&[10, 10, 10], 15), vec![10, 5, 0]);
    assert_eq!(allocate(&[10, 10], 25), vec![10, 15]);
    assert_eq!(allocate(&[10], 0), vec![0]);
}

#[test]
fn call_ids_are_stable_and_isolated_by_chat_turn_command_and_ordinal() {
    let id = call_reservation_id("chat", 1, "command", 1);
    assert_eq!(id, call_reservation_id("chat", 1, "command", 1));
    assert_ne!(id, call_reservation_id("chat2", 1, "command", 1));
    assert_ne!(id, call_reservation_id("chat", 2, "command", 1));
    assert_ne!(id, call_reservation_id("chat", 1, "command2", 1));
    assert_ne!(id, call_reservation_id("chat", 1, "command", 2));
    assert_ne!(
        call_reservation_id("ab", 1, "c", 1),
        call_reservation_id("a", 1, "bc", 1)
    );
}

#[test]
fn a_turn_needs_a_verified_current_grant() {
    let store = Store::open_in_memory().unwrap();
    assert_eq!(
        admit(&store, &authority(), now(), ACCOUNT, TENANT, MODEL, &card())
            .unwrap()
            .unwrap_err()
            .code(),
        "managed_plan_required"
    );

    let mut legacy = Store::open_in_memory().unwrap();
    legacy
        .append_record(
            TENANT,
            MANAGED_PLAN_KIND,
            &serde_json::to_string(&plan(ManagedPlanStatus::Active).record).unwrap(),
        )
        .unwrap();
    assert_eq!(
        admit(
            &legacy,
            &authority(),
            now(),
            ACCOUNT,
            TENANT,
            MODEL,
            &card()
        )
        .unwrap()
        .unwrap_err(),
        WorkChatRefusal::Funding(FundingDenial::Unverified)
    );

    let mut suspended = Store::open_in_memory().unwrap();
    suspended
        .append_record(
            TENANT,
            MANAGED_PLAN_KIND,
            &serde_json::to_string(&plan(ManagedPlanStatus::Suspended)).unwrap(),
        )
        .unwrap();
    assert_eq!(
        admit(
            &suspended,
            &authority(),
            now(),
            ACCOUNT,
            TENANT,
            MODEL,
            &card()
        )
        .unwrap()
        .unwrap_err()
        .code(),
        "managed_plan_suspended"
    );
}

#[test]
fn a_model_with_no_known_price_is_refused_not_held_at_a_guess() {
    let store = funded_store(1_000_000_000);
    let refusal = admit(
        &store,
        &authority(),
        now(),
        ACCOUNT,
        TENANT,
        "unpriced-model",
        &card(),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(refusal.code(), "managed_model_unpriced");

    let mut other_currency = card();
    other_currency.currency = Currency::try_from("EUR".to_owned()).unwrap();
    assert!(admit(
        &store,
        &authority(),
        now(),
        ACCOUNT,
        TENANT,
        MODEL,
        &other_currency
    )
    .unwrap()
    .is_err());

    // The shipped card prices nothing yet, so every managed model is refused.
    let shipped = gaugedesk_whip_runtime::whip_stats::repository_rate_card().unwrap();
    assert!(admit(
        &store,
        &authority(),
        now(),
        ACCOUNT,
        TENANT,
        MODEL,
        &shipped
    )
    .unwrap()
    .is_err());
}

#[test]
fn each_call_holds_credit_against_the_verified_source_before_it_is_sent() {
    let (ledger, meter) = meter(funded_store(1_000_000_000));
    let first = body("one");
    let second = body("summary of a long conversation");
    meter.admit_call(&call(1, &first)).unwrap();
    // A compaction summary is a call like any other and holds its own credit.
    meter.admit_call(&call(2, &second)).unwrap();

    let held = meter.held();
    assert_eq!(held.len(), 2);
    let state = ledger_state(&ledger);
    assert_eq!(state.reservations.len(), 2);
    let expected = held
        .iter()
        .map(|call| call.hold.maximum_nanos_usd)
        .sum::<u64>();
    assert_eq!(state.held_nanos_usd(), expected);
    for call in &held {
        let reservation = &state.reservations[&call.reservation_id].record;
        assert_eq!(reservation.engagement_id, CHAT);
        assert_eq!(reservation.funding_ref, meter.funding().funding_ref);
        assert!(reservation.admitted_at.is_some());
        assert!(reservation.valid_from.is_some() && reservation.valid_until.is_some());
    }
}

#[test]
fn a_call_the_credits_cannot_cover_is_refused_and_holds_nothing() {
    // Less than one call's hold.
    let (ledger, meter) = meter(funded_store(1_000_000));
    let request = body("hello");
    let error = meter.admit_call(&call(1, &request)).unwrap_err();
    assert!(error.contains("credits are exhausted"), "{error}");
    assert!(meter.held().is_empty());
    assert!(ledger_state(&ledger).reservations.is_empty());
}

#[test]
fn an_admitted_call_is_never_admitted_again() {
    let (ledger, meter) = meter(funded_store(1_000_000_000));
    let request = body("hello");
    meter.admit_call(&call(1, &request)).unwrap();
    let error = meter.admit_call(&call(1, &request)).unwrap_err();
    assert!(error.contains("not replayed"), "{error}");
    assert_eq!(meter.held().len(), 1);
    assert_eq!(ledger_state(&ledger).reservations.len(), 1);
}

#[test]
fn a_call_after_the_plan_is_suspended_is_refused() {
    let (ledger, meter) = meter(funded_store(1_000_000_000));
    ledger
        .lock()
        .unwrap()
        .append_record(
            TENANT,
            MANAGED_PLAN_KIND,
            &serde_json::to_string(&plan(ManagedPlanStatus::Suspended)).unwrap(),
        )
        .unwrap();
    let request = body("hello");
    let error = meter.admit_call(&call(1, &request)).unwrap_err();
    assert!(error.contains("Suspended"), "{error}");
}

#[test]
fn settlement_draws_the_estimate_when_the_gateway_cost_is_unknown() {
    let (ledger, meter) = meter(funded_store(1_000_000_000));
    let first = body("one");
    let second = body("two");
    meter.admit_call(&call(1, &first)).unwrap();
    meter.admit_call(&call(2, &second)).unwrap();

    let settled = meter.settle(&usage(1_000, 100), None).unwrap();
    assert_eq!(settled.cost_basis, CostBasis::Estimated);
    assert_eq!(settled.drawn_nanos_usd, 5_400_000);

    let store = ledger.lock().unwrap();
    let state = store.fold::<ManagedAllowanceLedger>(TENANT).unwrap();
    assert_eq!(state.drawn_nanos_usd, 5_400_000);
    assert_eq!(state.held_nanos_usd(), 0);
    assert!(state
        .reservations
        .values()
        .all(|held| held.status == ManagedAllowanceStatus::Settled));
    assert_eq!(state.available_nanos_usd(), 1_000_000_000 - 5_400_000);

    // The usage carries its exact funding source and server time, so it
    // counts toward the current period rather than being unattributed.
    let summary = crate::managed_inference::fold_usage_for_funding_period(
        &store,
        TENANT,
        &meter.funding().funding_ref,
        1,
        u64::MAX,
        0,
    )
    .unwrap();
    assert_eq!(summary.runs, 1);
    assert_eq!(summary.total_tokens, 1_100);
    assert_eq!(summary.unattributed_runs, 0);

    let costs = store
        .records(TENANT, WORK_CHAT_CALL_COST_KIND)
        .unwrap()
        .into_iter()
        .map(|row| serde_json::from_str::<CallCostRecord>(&row).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(costs.len(), 2);
    assert!(costs
        .iter()
        .all(|cost| cost.cost_basis == CostBasis::Estimated && cost.margin_basis_points == 2_000));
    assert_eq!(
        costs.iter().map(|cost| cost.drawn_nanos_usd).sum::<u64>(),
        5_400_000
    );
    assert_eq!(
        crate::managed_inference::fold_reservations(&store, CHAT)
            .unwrap()
            .outstanding,
        0
    );
}

#[test]
fn settlement_prefers_the_measured_gateway_cost_plus_margin() {
    let (ledger, meter) = meter(funded_store(1_000_000_000));
    let request = body("one");
    meter.admit_call(&call(1, &request)).unwrap();
    let settled = meter.settle(&usage(1_000, 100), Some(4_800)).unwrap();
    assert_eq!(settled.cost_basis, CostBasis::Measured);
    assert_eq!(settled.drawn_nanos_usd, 5_760);
    assert_eq!(ledger_state(&ledger).drawn_nanos_usd, 5_760);
}

#[test]
fn settling_twice_draws_once() {
    let (ledger, meter) = meter(funded_store(1_000_000_000));
    let request = body("one");
    meter.admit_call(&call(1, &request)).unwrap();
    meter.settle(&usage(1_000, 100), None).unwrap();
    meter.settle(&usage(1_000, 100), None).unwrap();
    assert_eq!(ledger_state(&ledger).drawn_nanos_usd, 5_400_000);
}

#[test]
fn an_unknown_outcome_keeps_its_hold_until_reconciled() {
    let (ledger, meter) = meter(funded_store(1_000_000_000));
    let request = body("one");
    meter.admit_call(&call(1, &request)).unwrap();
    let hold = meter.held()[0].hold.maximum_nanos_usd;

    // Usage that cannot be keyed is refused, and nothing is released.
    let mut unkeyed = usage(1_000, 100);
    unkeyed.usage_ref = " ".into();
    assert!(meter.settle(&unkeyed, None).is_err());
    let state = ledger_state(&ledger);
    assert_eq!(state.held_nanos_usd(), hold);
    assert_eq!(state.drawn_nanos_usd, 0);
}

#[test]
fn usage_for_another_model_is_not_settled_against_this_turn() {
    let (ledger, meter) = meter(funded_store(1_000_000_000));
    let request = body("one");
    meter.admit_call(&call(1, &request)).unwrap();
    let mut other = usage(1_000, 100);
    other.model = "other-model".into();
    assert!(meter.settle(&other, None).is_err());
    assert_eq!(ledger_state(&ledger).drawn_nanos_usd, 0);
}

#[test]
fn a_call_before_its_turn_is_named_is_refused() {
    let store = funded_store(1_000_000_000);
    let funding = funding(&store);
    let meter = WorkChatMeter::new(Arc::new(Mutex::new(store)), authority(), funding);
    let request = body("one");
    assert!(meter.admit_call(&call(1, &request)).is_err());
}
