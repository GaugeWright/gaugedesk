//! Managed-inference subscription and metering projections (LLM-3, ADR 0062).
//!
//! Provider secrets remain in the managed host TCB. GaugeDesk stores only the
//! future-run entitlement and a narrow token-count observation whose
//! `usage_ref` points back to WhippleScript-owned evidence.

use std::collections::BTreeMap;

use gaugedesk_harness::ModelUsage;
use gaugedesk_store::{AdmitError, Store};
use serde::{Deserialize, Serialize};

use crate::library::RecordOp;

pub const MANAGED_PLAN_KIND: &str = "managed_inference_plan";
pub const MANAGED_USAGE_KIND: &str = "managed_inference_usage";
pub const MANAGED_RESERVATION_KIND: &str = "managed_inference_reservation";
pub const MANAGED_SETTLEMENT_KIND: &str = "managed_inference_settlement";
const MANAGED_FUNDING_PREFIX: &str = "gaugedesk:managed-plan:v1:";

/// Stable, non-secret identity for the exact plan selected to fund a turn.
/// Hex-encoding keeps arbitrary scope/plan names unambiguous inside the ref.
pub fn funding_ref(scope: &str, plan: &ManagedInferencePlan) -> String {
    format!(
        "{MANAGED_FUNDING_PREFIX}{}:{}",
        hex::encode(scope.as_bytes()),
        hex::encode(plan.plan.as_bytes())
    )
}

pub fn is_managed_funding_ref(reference: &str) -> bool {
    reference.starts_with(MANAGED_FUNDING_PREFIX)
}

/// The funding-reference prefix, as the **edge** must also spell it.
///
/// `gaugewright-cloud`'s `isManagedFunding` recognises managed funding by this
/// same literal, and nothing at compile time relates the two. That is the shape
/// of defect that let the collection ECIES construction diverge for a whole
/// slice — two languages agreeing by inspection until they silently stopped.
///
/// A drift here is quieter than that one was: the edge would treat a
/// managed-funded deployment as BYOK, demand a credential it does not have, and
/// refuse to publish. Annoying rather than dangerous — but it would present as
/// "publishing is broken", not as "a constant moved". This test is the tell.
#[cfg(test)]
mod cross_language_prefix {
    #[test]
    fn the_edge_and_this_crate_spell_managed_funding_the_same_way() {
        assert_eq!(super::MANAGED_FUNDING_PREFIX, "gaugedesk:managed-plan:v1:");
        // Sanity: a reference built by `funding_ref` is recognised by the same
        // predicate the edge mirrors, so the round trip holds locally even if
        // the far side drifts.
        let reference = super::funding_ref(
            "tenant::acme",
            &super::ManagedInferencePlan {
                plan: "stripe-cloud".to_owned(),
                ..Default::default()
            },
        );
        assert!(super::is_managed_funding_ref(&reference));
        assert!(!super::is_managed_funding_ref(
            "credential:public:abc:openai:def"
        ));
    }
}

/// Resolve the exact plan named by a previously admitted funding reference.
/// Public deployments have no logged-in account actor at turn time, so they
/// must re-check the owner-selected scope encoded in the grant rather than
/// falling back to the desktop singleton account/organization scopes.
pub fn resolve_funding_ref(
    store: &Store,
    reference: &str,
) -> Result<Option<(ManagedInferencePlan, String)>, AdmitError> {
    let Some(encoded) = reference.strip_prefix(MANAGED_FUNDING_PREFIX) else {
        return Ok(None);
    };
    let Some((scope_hex, plan_hex)) = encoded.split_once(':') else {
        return Ok(None);
    };
    let Some(scope) = hex::decode(scope_hex)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let Some(plan_name) = hex::decode(plan_hex)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let Some(plan) = fold_plan(store, &scope)? else {
        return Ok(None);
    };
    if plan.plan != plan_name || funding_ref(&scope, &plan) != reference {
        return Ok(None);
    }
    Ok(Some((plan, scope)))
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedPlanStatus {
    Active,
    #[default]
    Suspended,
    Lapsed,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct ManagedInferencePlan {
    #[serde(default)]
    pub plan: String,
    #[serde(default)]
    pub status: ManagedPlanStatus,
    /// Monthly included input + output tokens. Zero means no included grant;
    /// the private billing rail may still price all observed usage.
    #[serde(default)]
    pub included_tokens: u64,
}

impl ManagedInferencePlan {
    pub fn admits_future_run(&self) -> bool {
        !self.plan.trim().is_empty() && self.status == ManagedPlanStatus::Active
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct ManagedPlanRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(flatten)]
    pub subscription: ManagedInferencePlan,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedUsageRecord {
    pub id: String,
    pub engagement_id: String,
    pub usage_ref: String,
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedReservationRecord {
    pub id: String,
    pub engagement_id: String,
    pub funding_ref: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ManagedSettlementRecord {
    Settled {
        id: String,
        reservation_id: String,
        usage_ref: String,
    },
    Released {
        id: String,
        reservation_id: String,
        reason: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManagedReservationSummary {
    pub reserved: u64,
    pub settled: u64,
    pub released: u64,
    pub outstanding: u64,
}

impl ManagedUsageRecord {
    pub fn from_runtime(engagement_id: &str, usage: &ModelUsage) -> Self {
        Self {
            id: usage.usage_ref.clone(),
            engagement_id: engagement_id.to_owned(),
            usage_ref: usage.usage_ref.clone(),
            provider: usage.provider.clone(),
            model: usage.model.clone(),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct ManagedUsageSummary {
    pub runs: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub included_tokens: u64,
    pub overage_tokens: u64,
}

pub fn fold_plan(store: &Store, scope: &str) -> Result<Option<ManagedInferencePlan>, AdmitError> {
    let mut plan = None;
    for row in store.records(scope, MANAGED_PLAN_KIND)? {
        let record: ManagedPlanRecord = serde_json::from_str(&row)?;
        match record.op {
            RecordOp::Upsert => plan = Some(record.subscription),
            RecordOp::Tombstone => plan = None,
        }
    }
    Ok(plan)
}

/// Resolve the subscription that funds a managed turn. An organization plan,
/// when configured, governs and bills the tenant; otherwise the person's own
/// account plan applies. A suspended org plan does not silently fall through to
/// personal billing.
pub fn resolve_plan(
    store: &Store,
    account_scope: &str,
    tenant_scope: &str,
) -> Result<Option<(ManagedInferencePlan, String)>, AdmitError> {
    let org = crate::org::Org::rebuild_in(store, tenant_scope)?;
    if let Some(plan) = org.billing.and_then(|billing| billing.managed_inference) {
        return Ok(Some((plan, tenant_scope.to_owned())));
    }
    if let Some(plan) = fold_plan(store, tenant_scope)? {
        return Ok(Some((plan, tenant_scope.to_owned())));
    }
    Ok(fold_plan(store, account_scope)?.map(|plan| (plan, account_scope.to_owned())))
}

pub fn fold_usage(
    store: &Store,
    scope: &str,
    included_tokens: u64,
) -> Result<ManagedUsageSummary, AdmitError> {
    // The runtime usage reference is the idempotency key. A replay may append
    // the same projection again, but it can never double-bill the fold.
    let mut observations = BTreeMap::new();
    for row in store.records(scope, MANAGED_USAGE_KIND)? {
        let record: ManagedUsageRecord = serde_json::from_str(&row)?;
        observations.insert(record.id.clone(), record);
    }
    let mut summary = ManagedUsageSummary {
        runs: observations.len() as u64,
        included_tokens,
        ..ManagedUsageSummary::default()
    };
    for observation in observations.values() {
        summary.input_tokens = summary
            .input_tokens
            .saturating_add(observation.input_tokens);
        summary.output_tokens = summary
            .output_tokens
            .saturating_add(observation.output_tokens);
    }
    summary.total_tokens = summary.input_tokens.saturating_add(summary.output_tokens);
    summary.overage_tokens = summary.total_tokens.saturating_sub(included_tokens);
    Ok(summary)
}

pub fn append_usage(
    store: &mut Store,
    engagement_scope: &str,
    billing_scope: &str,
    usage: &ModelUsage,
) -> Result<(), AdmitError> {
    let record = ManagedUsageRecord::from_runtime(engagement_scope, usage);
    let payload = serde_json::to_string(&record)?;
    if billing_scope == engagement_scope {
        store.append_record(engagement_scope, MANAGED_USAGE_KIND, &payload)?;
    } else {
        store.append_records_atomically(&[
            (engagement_scope, MANAGED_USAGE_KIND, &payload),
            (billing_scope, MANAGED_USAGE_KIND, &payload),
        ])?;
    }
    Ok(())
}

/// Persist the managed funding authorization before the runtime may call the provider.
/// The caller-stable reservation id makes a recovered command idempotent.
pub fn reserve_turn(
    store: &mut Store,
    engagement_scope: &str,
    billing_scope: &str,
    funding_ref: &str,
    reservation_id: &str,
) -> Result<(), AdmitError> {
    let record = ManagedReservationRecord {
        id: reservation_id.to_owned(),
        engagement_id: engagement_scope.to_owned(),
        funding_ref: funding_ref.to_owned(),
    };
    let payload = serde_json::to_string(&record)?;
    store.append_record_with_key(
        billing_scope,
        &format!("managed-reserve:{reservation_id}"),
        MANAGED_RESERVATION_KIND,
        &payload,
    )?;
    if billing_scope != engagement_scope {
        store.append_record_with_key(
            engagement_scope,
            &format!("managed-reserve:{reservation_id}"),
            MANAGED_RESERVATION_KIND,
            &payload,
        )?;
    }
    Ok(())
}

pub fn settle_reservation(
    store: &mut Store,
    engagement_scope: &str,
    billing_scope: &str,
    reservation_id: &str,
    usage_ref: Option<&str>,
    release_reason: &str,
) -> Result<(), AdmitError> {
    let record = match usage_ref {
        Some(usage_ref) => ManagedSettlementRecord::Settled {
            id: format!("settled:{reservation_id}"),
            reservation_id: reservation_id.to_owned(),
            usage_ref: usage_ref.to_owned(),
        },
        None => ManagedSettlementRecord::Released {
            id: format!("released:{reservation_id}"),
            reservation_id: reservation_id.to_owned(),
            reason: release_reason.to_owned(),
        },
    };
    let payload = serde_json::to_string(&record)?;
    let key = format!("managed-settle:{reservation_id}");
    store.append_record_with_key(billing_scope, &key, MANAGED_SETTLEMENT_KIND, &payload)?;
    if billing_scope != engagement_scope {
        store.append_record_with_key(engagement_scope, &key, MANAGED_SETTLEMENT_KIND, &payload)?;
    }
    Ok(())
}

pub fn fold_reservations(
    store: &Store,
    scope: &str,
) -> Result<ManagedReservationSummary, AdmitError> {
    let mut reservations = BTreeMap::new();
    for row in store.records(scope, MANAGED_RESERVATION_KIND)? {
        let record: ManagedReservationRecord = serde_json::from_str(&row)?;
        reservations.insert(record.id.clone(), record);
    }
    let mut terminal = BTreeMap::new();
    for row in store.records(scope, MANAGED_SETTLEMENT_KIND)? {
        let record: ManagedSettlementRecord = serde_json::from_str(&row)?;
        let reservation_id = match &record {
            ManagedSettlementRecord::Settled { reservation_id, .. }
            | ManagedSettlementRecord::Released { reservation_id, .. } => reservation_id,
        };
        terminal.insert(reservation_id.clone(), record);
    }
    let mut summary = ManagedReservationSummary {
        reserved: reservations.len() as u64,
        ..ManagedReservationSummary::default()
    };
    for reservation_id in reservations.keys() {
        match terminal.get(reservation_id) {
            Some(ManagedSettlementRecord::Settled { .. }) => summary.settled += 1,
            Some(ManagedSettlementRecord::Released { .. }) => summary.released += 1,
            None => summary.outstanding += 1,
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_fold_is_idempotent_and_reports_overage() {
        let mut store = Store::open_in_memory().unwrap();
        let usage = ModelUsage {
            usage_ref: "whip:evidence:usage:1".into(),
            provider: "cloudflare-workers-ai".into(),
            model: "model-a".into(),
            input_tokens: 7,
            output_tokens: 5,
        };
        append_usage(&mut store, "chat-1", "account", &usage).unwrap();
        append_usage(&mut store, "chat-1", "account", &usage).unwrap();
        assert_eq!(
            fold_usage(&store, "account", 10).unwrap(),
            ManagedUsageSummary {
                runs: 1,
                input_tokens: 7,
                output_tokens: 5,
                total_tokens: 12,
                included_tokens: 10,
                overage_tokens: 2,
            }
        );
    }

    #[test]
    fn suspension_is_future_only_plan_policy() {
        let historical = ManagedUsageSummary {
            runs: 3,
            total_tokens: 99,
            ..ManagedUsageSummary::default()
        };
        let plan = ManagedInferencePlan {
            plan: "managed".into(),
            status: ManagedPlanStatus::Suspended,
            included_tokens: 1_000,
        };
        assert!(!plan.admits_future_run());
        assert_eq!(historical.runs, 3);
        assert_eq!(historical.total_tokens, 99);
    }

    #[test]
    fn reservation_and_release_are_idempotent_in_billing_and_engagement_scopes() {
        let mut store = Store::open_in_memory().unwrap();
        for _ in 0..2 {
            reserve_turn(
                &mut store,
                "chat-1",
                "account",
                "gaugedesk:managed-plan:v1:test",
                "reservation-1",
            )
            .unwrap();
            settle_reservation(
                &mut store,
                "chat-1",
                "account",
                "reservation-1",
                None,
                "transport_failed",
            )
            .unwrap();
        }

        let expected = ManagedReservationSummary {
            reserved: 1,
            settled: 0,
            released: 1,
            outstanding: 0,
        };
        assert_eq!(fold_reservations(&store, "account").unwrap(), expected);
        assert_eq!(fold_reservations(&store, "chat-1").unwrap(), expected);
    }

    #[test]
    fn organization_plan_governs_before_personal_plan() {
        let mut store = Store::open_in_memory().unwrap();
        let personal = ManagedPlanRecord {
            id: "managed-inference".into(),
            op: RecordOp::Upsert,
            subscription: ManagedInferencePlan {
                plan: "personal".into(),
                status: ManagedPlanStatus::Active,
                included_tokens: 10,
            },
        };
        store
            .append_record(
                "account",
                MANAGED_PLAN_KIND,
                &serde_json::to_string(&personal).unwrap(),
            )
            .unwrap();
        let org = crate::org::BillingRecord {
            id: crate::org::ORG_ID.into(),
            op: RecordOp::Upsert,
            plan: "business".into(),
            seats: 5,
            managed_inference: Some(ManagedInferencePlan {
                plan: "org".into(),
                status: ManagedPlanStatus::Suspended,
                included_tokens: 20,
            }),
        };
        store
            .append_record(
                crate::org::ORG_SCOPE,
                "billing",
                &serde_json::to_string(&org).unwrap(),
            )
            .unwrap();

        let (resolved, scope) =
            resolve_plan(&store, crate::account::ACCOUNT_SCOPE, crate::org::ORG_SCOPE)
                .unwrap()
                .unwrap();
        assert_eq!(scope, crate::org::ORG_SCOPE);
        assert_eq!(resolved.plan, "org");
        assert!(!resolved.admits_future_run());
    }

    #[test]
    fn server_owned_tenant_plan_governs_before_personal_plan() {
        let mut store = Store::open_in_memory().unwrap();
        for (scope, plan) in [("account", "personal"), ("tenant::acme", "stripe-cloud")] {
            let record = ManagedPlanRecord {
                id: "managed-inference".into(),
                op: RecordOp::Upsert,
                subscription: ManagedInferencePlan {
                    plan: plan.into(),
                    status: ManagedPlanStatus::Active,
                    included_tokens: 10,
                },
            };
            store
                .append_record(
                    scope,
                    MANAGED_PLAN_KIND,
                    &serde_json::to_string(&record).unwrap(),
                )
                .unwrap();
        }

        let (resolved, scope) = resolve_plan(&store, "account", "tenant::acme")
            .unwrap()
            .unwrap();
        assert_eq!(scope, "tenant::acme");
        assert_eq!(resolved.plan, "stripe-cloud");
    }

    #[test]
    fn funding_ref_binds_scope_and_plan_without_delimiter_ambiguity() {
        let plan = ManagedInferencePlan {
            plan: "managed:team".into(),
            status: ManagedPlanStatus::Active,
            included_tokens: 10,
        };
        assert_eq!(
            funding_ref("org::acme", &plan),
            "gaugedesk:managed-plan:v1:6f72673a3a61636d65:6d616e616765643a7465616d"
        );
        assert!(is_managed_funding_ref(&funding_ref("org::acme", &plan)));
        assert!(!is_managed_funding_ref("credential:openai"));
    }

    #[test]
    fn funding_ref_resolves_only_the_exact_current_scope_and_plan() {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "org::personal:owner";
        let active = ManagedInferencePlan {
            plan: "founder-proof".into(),
            status: ManagedPlanStatus::Active,
            included_tokens: 0,
        };
        let record = ManagedPlanRecord {
            id: "managed-inference".into(),
            op: RecordOp::Upsert,
            subscription: active.clone(),
        };
        store
            .append_record(
                scope,
                MANAGED_PLAN_KIND,
                &serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
        let reference = funding_ref(scope, &active);
        assert_eq!(
            resolve_funding_ref(&store, &reference).unwrap(),
            Some((active.clone(), scope.into()))
        );
        assert_eq!(resolve_funding_ref(&store, "managed:guess").unwrap(), None);

        let replacement = ManagedPlanRecord {
            id: "managed-inference".into(),
            op: RecordOp::Upsert,
            subscription: ManagedInferencePlan {
                plan: "replacement".into(),
                ..active
            },
        };
        store
            .append_record(
                scope,
                MANAGED_PLAN_KIND,
                &serde_json::to_string(&replacement).unwrap(),
            )
            .unwrap();
        assert_eq!(resolve_funding_ref(&store, &reference).unwrap(), None);
    }
}

// ---- the metered rail's address (ADR 0085 §3, `FUND-1`) --------------------

/// The provider a managed-funded release declares.
///
/// The edge refuses managed funding against any other provider, so this is what
/// makes a release *eligible* to be paid for from GaugeWright's credits rather
/// than an owner's key.
pub const METERED_GATEWAY_PROVIDER: &str = "cloudflare-ai-gateway";

/// The company Cloudflare account holding the gateways (`specs/systems.md`).
///
/// Non-secret: an account id appears in every wrangler config and in the
/// gateway's own public endpoint. It is a constant rather than configuration
/// because a deployment pointed at somebody else's gateway is not a
/// misconfiguration to tolerate — it is a bill sent to the wrong company.
pub const METERED_GATEWAY_ACCOUNT: &str = "1689dd452ba2d2d8eb1f3c364c92b3f4";

/// The gateway public deployments run on.
///
/// Deliberately **not** the same gateway as the private hosted runtime's
/// (`gaugewright-hosted`). A gateway's spend limit is gateway-wide while a
/// deployment's cap is per deployment, so sharing one would let a busy panel
/// hard-stop the private runtime — see `specs/systems.md`.
pub const METERED_GATEWAY_PANELS: &str = "gaugewright-panels";

#[cfg(debug_assertions)]
const DEVELOPMENT_GATEWAY_ID_ENV: &str = "GAUGEWRIGHT_DEV_AI_GATEWAY_ID";

fn valid_gateway_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(debug_assertions)]
fn metered_gateway_id() -> String {
    match std::env::var(DEVELOPMENT_GATEWAY_ID_ENV) {
        Ok(value) if valid_gateway_id(&value) => value,
        Ok(_) => panic!("{DEVELOPMENT_GATEWAY_ID_ENV} is not a valid exact gateway id"),
        Err(std::env::VarError::NotPresent) => METERED_GATEWAY_PANELS.to_owned(),
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("{DEVELOPMENT_GATEWAY_ID_ENV} is not Unicode")
        }
    }
}

#[cfg(not(debug_assertions))]
fn metered_gateway_id() -> String {
    METERED_GATEWAY_PANELS.to_owned()
}

/// Where a managed release reaches its model: the endpoint it is admitted
/// against and the name to ask that endpoint for.
///
/// These travel together because they have to agree. The gateway fronts two
/// surfaces that spell models differently — unified `provider/model` on the
/// compat shim, a bare provider-native id on `/anthropic` — so handing them out
/// separately invites a pairing that routes nowhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeteredRoute {
    /// The egress grant: the runtime proves a metered request never leaves this
    /// origin and path.
    pub base_url: String,
    pub model: String,
}

/// Route a managed model through the gateway surface that fits it.
///
/// Anthropic models take the provider-native `/anthropic` surface rather than
/// the OpenAI-compatible shim. Same gateway, same BYOK key, same metered log —
/// but the shim **drops `cache_control`**, and Anthropic caching is opt-in, so a
/// Claude model behind it can never use the prompt cache and pays full price on
/// every re-sent prefix. Measured 2026-08-11 against `gaugewright-panels`: on an
/// identical prefix the native route bills 1.25x on the cache write and 0.1x on
/// the read — 9.25x cheaper on the cached span — while the gateway still logs
/// `cost`, so measured-cost settlement is unaffected.
///
/// Everything else keeps the compat shim and its unified `provider/model`
/// naming, which is what unified billing routes by.
pub fn metered_route(model: &str) -> MeteredRoute {
    let gateway = metered_gateway_id();
    let base = format!("https://gateway.ai.cloudflare.com/v1/{METERED_GATEWAY_ACCOUNT}/{gateway}");
    let model = model.trim();
    let native = model.strip_prefix("anthropic/").unwrap_or(model);
    if is_anthropic_model(native) {
        return MeteredRoute {
            base_url: format!("{base}/anthropic"),
            // The native surface selects the provider by path, so the name it
            // takes carries no prefix. Sending `anthropic/claude-opus-5` there
            // asks for a model that does not exist.
            model: native.to_owned(),
        };
    }
    MeteredRoute {
        base_url: format!("{base}/compat"),
        // A bare name is not addressable through unified billing. One that
        // already carries a provider is left alone; a bare one is qualified with
        // `openai`, the only other provider a public release admits today.
        model: if model.contains('/') {
            model.to_owned()
        } else {
            format!("openai/{model}")
        },
    }
}

/// Whether a bare model id names an Anthropic model.
///
/// Needed because the native surface takes unprefixed names, so a bare
/// `claude-opus-5` has to be recognized rather than qualified — and a release
/// may declare its model either way.
fn is_anthropic_model(model: &str) -> bool {
    model.starts_with("claude-")
}

#[cfg(test)]
mod metered_rail {
    #[test]
    fn the_base_url_is_the_panels_gateway_and_ends_at_compat() {
        let url = super::metered_route("gpt-4.1-mini").base_url;
        // The runtime appends `/chat/completions`, so the admitted base must end
        // exactly at `/compat` or the egress proof fails on every turn.
        assert!(url.ends_with("/compat"), "{url}");
        assert!(url.contains(super::METERED_GATEWAY_PANELS));
        assert!(url.starts_with("https://gateway.ai.cloudflare.com/v1/"));
        // Never the private runtime's gateway: sharing one gateway shares its
        // spend limit, and a busy panel would hard-stop the private runtime.
        assert!(!url.contains("gaugewright-hosted"));
    }

    /// An Anthropic model must reach the provider-native surface. On `/compat`
    /// the shim drops `cache_control`, so caching is impossible and every
    /// re-sent prefix bills at full price — silently, because a compat endpoint
    /// ignoring a cache hint is not an error.
    #[test]
    fn an_anthropic_model_routes_to_the_native_surface_with_a_bare_name() {
        let route = super::metered_route("claude-opus-5");
        // The runtime appends `/v1/messages` here, not `/chat/completions`.
        assert!(route.base_url.ends_with("/anthropic"), "{}", route.base_url);
        assert!(route.base_url.contains(super::METERED_GATEWAY_PANELS));
        assert_eq!(route.model, "claude-opus-5");

        // A release may declare the model either way; both reach the same place,
        // and the prefix is stripped because the path already selects Anthropic.
        let qualified = super::metered_route("anthropic/claude-opus-5");
        assert_eq!(qualified, route);
        assert_eq!(super::metered_route("  claude-opus-5 "), route);
    }

    #[test]
    fn development_gateway_ids_are_single_safe_path_segments() {
        assert!(super::valid_gateway_id("gaugewright-development"));
        assert!(super::valid_gateway_id("dev_2"));
        assert!(!super::valid_gateway_id(""));
        assert!(!super::valid_gateway_id("../gaugewright-panels"));
        assert!(!super::valid_gateway_id("gateway/compat"));
    }

    #[test]
    fn a_bare_model_is_qualified_and_a_qualified_one_is_left_alone() {
        assert_eq!(
            super::metered_route("gpt-4.1-mini").model,
            "openai/gpt-4.1-mini"
        );
        assert_eq!(
            super::metered_route("openai/gpt-4.1").model,
            "openai/gpt-4.1"
        );
        assert_eq!(
            super::metered_route("  gpt-5-mini ").model,
            "openai/gpt-5-mini"
        );
        // Double-qualifying would produce a model the gateway cannot route.
        assert_eq!(
            super::metered_route(&super::metered_route("gpt-4.1-mini").model).model,
            "openai/gpt-4.1-mini",
        );
        // A non-Anthropic model stays on the compat shim, which is what unified
        // billing routes by.
        assert!(super::metered_route("gpt-4.1-mini")
            .base_url
            .ends_with("/compat"));
    }
}
