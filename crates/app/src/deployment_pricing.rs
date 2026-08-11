//! What a public deployment's owner is billed per token (ADR 0085 §6, `FUND-1`).
//!
//! **Who pays is settled and is not a knob here.** ADR 0085 §6: public work
//! charges "only to the deployment owner's explicitly selected funding source
//! under its public quota/cap", and "visitor identity never becomes funding
//! authority". A visitor is anonymous by design, so a visitor-funded panel would
//! need an anonymous funding handle — a fraud surface, and the opposite of the
//! premise that a stranger needs no account. The publisher pays for their own
//! visitors and prices that into whatever they sell.
//!
//! **What this module owns is the rate card**: upstream cost, plus GaugeWright's
//! margin for fronting the metered rail. The edge stores these rates in the
//! deployment record at publish and applies them at settlement, so a published
//! deployment keeps the rates it was published under — changing the card here
//! never silently reprices work already sold.
//!
//! The margin is one named constant rather than pre-multiplied numbers, so the
//! base cost stays auditable against a real invoice. Pre-multiplying would make
//! "is our upstream cost right?" and "is our margin right?" the same
//! unanswerable question.
//!
//! **The cost basis here is interim and should stop existing.** The AI Gateway
//! logs API reports *actual* cost per request alongside token counts, so
//! settlement can bill measured cost × the margin and skip the rate table
//! entirely — which is what ADR 0085 already asks for ("managed gateway
//! telemetry reconciles the authoritative WhippleScript meter"). Keep
//! [`MARGIN_BASIS_POINTS`]; retire [`DEFAULT_UPSTREAM`] once telemetry is wired.
//! `FUND-1` carries that, blocked on an *AI Gateway: Read* scope the company
//! token does not yet have.

/// GaugeWright's margin over upstream cost for operating the metered rail
/// (founder's call, 2026-07-30). Applied to every per-token rate.
pub const MARGIN_BASIS_POINTS: u64 = 2_000; // 20%

/// Identifies the rate card a deployment was published under. **Bump this
/// whenever a rate or the margin changes**: the edge keeps it beside the rates
/// it stored, so support can answer "what was this deployment billed at" from
/// the record instead of from the deploy date and a guess.
pub const PRICING_VERSION: &str = "gateway-passthrough-margin-20-v1";

/// Upstream cost per token in nanos USD, before margin.
///
/// **A fallback now, not the basis for billing.** Settlement bills measured
/// gateway cost; these rates apply only to a round whose cost could not be
/// measured, which should be rare and is recorded as such on the reservation.
///
/// They were never a safe basis. The card has exactly one job — settlement, since
/// reservations pre-authorise a flat `reserve_cents_per_turn` and never consult
/// it — and it carries three fixed per-token constants with **no model
/// dimension**, while real model pricing spans more than an order of magnitude.
/// So it over-bills a cheap model and under-bills an expensive one, and no
/// refresh of the constants can fix that: a single number is standing in for
/// something that varies per model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamRates {
    pub input_nanos_usd_per_token: u64,
    pub cached_input_nanos_usd_per_token: u64,
    pub output_nanos_usd_per_token: u64,
}

/// The default upstream cost basis.
///
/// **Measured 2026-07-30 and found badly wrong for small models.** A real
/// metered round through `gaugewright-panels` (8 input, 1 output,
/// `gpt-4.1-mini`) cost **4,800 nanos USD**; this basis prices the same round at
/// 30,000 — a **6.2× overestimate**, so a publisher billed from the card pays
/// **7.5× true cost** rather than cost plus 20%. The rates are per-token
/// constants with no model dimension, while real pricing varies by model over
/// more than an order of magnitude.
///
/// This is why `FUND-1` bills from the gateway's measured cost rather than from
/// this table, and why the margin is a separate constant: the margin was always
/// right and the basis was always guessed. Until measured-cost settlement lands,
/// treat any figure derived from this as an upper bound, not a price.
pub const DEFAULT_UPSTREAM: UpstreamRates = UpstreamRates {
    input_nanos_usd_per_token: 2_500,
    cached_input_nanos_usd_per_token: 250,
    output_nanos_usd_per_token: 10_000,
};

/// Apply the margin, rounding **up**.
///
/// Up rather than nearest: a rate that rounds down bills less than cost plus
/// margin on every single token, and the shortfall is unrecoverable because
/// settlement is per turn. Rounding up costs a publisher at most one nano per
/// token.
fn with_margin(cost_nanos: u64) -> u64 {
    let numerator = cost_nanos * (10_000 + MARGIN_BASIS_POINTS);
    numerator.div_ceil(10_000)
}

/// The billed rate card for a deployment, ready for the edge's `pricing` block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BilledRates {
    pub input_nanos_usd_per_token: u64,
    pub cached_input_nanos_usd_per_token: u64,
    pub output_nanos_usd_per_token: u64,
}

pub fn billed_rates(upstream: UpstreamRates) -> BilledRates {
    BilledRates {
        input_nanos_usd_per_token: with_margin(upstream.input_nanos_usd_per_token),
        cached_input_nanos_usd_per_token: with_margin(upstream.cached_input_nanos_usd_per_token),
        output_nanos_usd_per_token: with_margin(upstream.output_nanos_usd_per_token),
    }
}

/// The `pricing` block the edge validates and stores.
pub fn pricing_block() -> serde_json::Value {
    let billed = billed_rates(DEFAULT_UPSTREAM);
    serde_json::json!({
        "input_nanos_usd_per_token": billed.input_nanos_usd_per_token,
        "cached_input_nanos_usd_per_token": billed.cached_input_nanos_usd_per_token,
        "output_nanos_usd_per_token": billed.output_nanos_usd_per_token,
        "pricing_version": PRICING_VERSION,
        // Carried on the deployment so the edge can bill **measured** gateway
        // cost plus this margin, instead of the per-token rates above. Travelling
        // with the deployment is what keeps a later margin change from repricing
        // work already sold — the same reason the rates travel.
        //
        // The rates remain as the fallback for a round whose cost cannot be
        // measured, and only for that.
        "margin_basis_points": MARGIN_BASIS_POINTS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_margin_is_twenty_percent_over_upstream_cost() {
        let billed = billed_rates(DEFAULT_UPSTREAM);
        assert_eq!(billed.input_nanos_usd_per_token, 3_000); // 2_500 × 1.2
        assert_eq!(billed.cached_input_nanos_usd_per_token, 300); // 250 × 1.2
        assert_eq!(billed.output_nanos_usd_per_token, 12_000); // 10_000 × 1.2
    }

    #[test]
    fn a_rate_never_rounds_below_cost_plus_margin() {
        // Settlement is per turn, so a rate rounding down under-bills every
        // token forever with no way to recover the difference.
        for cost in [1_u64, 3, 7, 999, 1_001] {
            let billed = with_margin(cost);
            assert!(
                billed as f64 >= cost as f64 * 1.2,
                "cost {cost} billed {billed}, below cost+margin",
            );
        }
        // A one-nano cost cannot round to one nano: that would be zero margin.
        assert_eq!(with_margin(1), 2);
    }

    #[test]
    fn cached_input_stays_cheaper_than_fresh_input() {
        // The edge refuses a card whose cached rate exceeds its input rate, so
        // a margin that broke this ordering would fail every publish.
        let billed = billed_rates(DEFAULT_UPSTREAM);
        assert!(billed.cached_input_nanos_usd_per_token < billed.input_nanos_usd_per_token);
    }

    #[test]
    fn every_billed_rate_is_positive() {
        // `validPositiveInteger` at the edge rejects zero, so a rate that
        // rounded to nothing would be a publish that fails late.
        let billed = billed_rates(DEFAULT_UPSTREAM);
        for rate in [
            billed.input_nanos_usd_per_token,
            billed.cached_input_nanos_usd_per_token,
            billed.output_nanos_usd_per_token,
        ] {
            assert!(rate > 0);
        }
    }

    #[test]
    fn the_pricing_version_names_the_margin_so_a_record_is_self_describing() {
        // Support answers "what was this billed at" from the stored record, not
        // from the deploy date. A card change that kept the old version string
        // would make two different rate cards indistinguishable.
        assert!(PRICING_VERSION.contains("20"));
        assert_ne!(PRICING_VERSION, "openai-public-v1");
        let block = pricing_block();
        assert_eq!(block["pricing_version"], PRICING_VERSION);
        assert_eq!(block["input_nanos_usd_per_token"], 3_000);
    }
}

/// The funding-source boundary at publish (ADR 0085 §1, `FUND-1`).
///
/// Colocated with the rate card because the two are the same decision seen from
/// two sides: who pays, and what they are charged.
#[cfg(test)]
mod funding_boundary {
    use crate::managed_inference::{funding_ref, is_managed_funding_ref, ManagedInferencePlan};

    fn managed() -> String {
        funding_ref(
            "tenant::acme",
            &ManagedInferencePlan {
                plan: "stripe-cloud".to_owned(),
                ..Default::default()
            },
        )
    }

    #[test]
    fn a_managed_plan_is_never_mistaken_for_a_credential() {
        // The whole safety of "absence of a credential means managed" rests on
        // these two reference spaces being disjoint.
        let plan = managed();
        assert!(is_managed_funding_ref(&plan));
        assert!(!plan.starts_with("credential:"));
        for credential in [
            "credential:public:abc123:openai:def456",
            "credential:production:openai:v1",
            "credential:project:alpha:v3",
        ] {
            assert!(
                !is_managed_funding_ref(credential),
                "{credential} must not read as managed funding",
            );
        }
    }

    #[test]
    fn the_billed_card_is_what_a_managed_deployment_publishes() {
        // A managed deployment is billed from the rate card rather than from a
        // provider invoice, so the card must be the one carrying the margin.
        let block = super::pricing_block();
        assert_eq!(block["pricing_version"], super::PRICING_VERSION);
        let upstream = super::DEFAULT_UPSTREAM;
        let billed = super::billed_rates(upstream);
        assert!(
            billed.output_nanos_usd_per_token > upstream.output_nanos_usd_per_token,
            "the publisher is billed above upstream cost, not at it",
        );
    }
}

/// A managed-funded publish builds a release for the metered rail (`FUND-1`).
///
/// The edge refuses managed funding against any other provider, so if this
/// pairing ever came apart the failure would be a 422 at admission — after the
/// author thought they had published.
#[cfg(test)]
mod metered_release {
    use crate::managed_inference::{metered_route, METERED_GATEWAY_PROVIDER};

    #[test]
    fn the_release_the_edge_demands_is_the_release_managed_publishing_builds() {
        // The edge's check is `release.provider !== "cloudflare-ai-gateway"`.
        assert_eq!(METERED_GATEWAY_PROVIDER, "cloudflare-ai-gateway");
        // And the runtime proves the request never leaves this origin+path, so
        // the admitted base URL is the egress grant for every metered turn. The
        // runtime admits exactly the gateway's two surfaces and nothing else.
        for model in ["gpt-4.1-mini", "claude-opus-5"] {
            let route = metered_route(model);
            assert!(
                route.base_url.ends_with("/compat") || route.base_url.ends_with("/anthropic"),
                "{}",
                route.base_url
            );
            assert!(!route.model.is_empty());
        }
        // A bare model name is not routable through unified billing.
        assert!(metered_route("gpt-4.1-mini").model.contains('/'));
    }
}
