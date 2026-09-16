//! What a WhippleScript run cost, from what the runtime recorded.
//!
//! **The runtime meters; the desk prices** (`specs/primitives/runtime.md`).
//! WhippleScript owns usage evidence and folds it into a stats report
//! (`whipplescript.stats_report.v0`, its DR-0114); GaugeDesk never establishes
//! usage truth from its own counters, and this module never counts anything. It
//! takes recorded token counts and a rate card and returns money.
//!
//! Two properties are load-bearing, and both are inherited from the meter
//! rather than invented here.
//!
//! **Unrecorded is not zero** (WhippleScript DR-0116). The report distinguishes
//! a count the log establishes from one it does not carry, and a measure it does
//! not carry arrives as `None`. Pricing `None` as zero would report that a run
//! whose usage was never recorded was free, which is the one answer that is
//! certainly wrong. So a gap makes the *total* absent — [`Priced::amount`] is
//! `None` — while [`Priced::recorded_cost`] still says what the counts the log
//! does carry came to. That figure is not a total and a surface must not render
//! it as one; it is also deliberately not called a bound, because it is not one
//! in either direction. An unrecorded bucket may be tokens that were never
//! spent, or tokens that were spent and belong at a different rate than the
//! recorded buckets were priced at.
//!
//! **A model with no rate is not free.** The rate card has no fallback rate, on
//! purpose. [`crate::model_connection`]'s neighbouring deployment rate table
//! carries per-token constants with no model dimension, and measurement found it
//! over-billing a small model by 6.2x — a single number standing in for
//! something that varies by more than an order of magnitude. A card that
//! defaults would make that failure silent instead of visible, so an unknown
//! model produces a [`Gap::NoRate`] naming it, which is exactly the list of
//! rates an operator has to supply.
//!
//! **The buckets are disjoint**, which is what makes pricing a multiply and a
//! sum with no subtraction anywhere. WhippleScript's kernel convention splits
//! the input side into `input_uncached`, `input_cache_read` and
//! `input_cache_write`, each counting tokens the others do not. The *inclusive*
//! convention some provider payloads use — where a cached count is part of the
//! input count — would double-count every cached token if fed in here, so the
//! adapter that builds a [`MeteredUsage`] owes this module the disjoint form.
//!
//! No floating point, matching the rest of the money surface: a rate is an
//! integer and the accumulator is exact until it is rendered.

use std::collections::BTreeMap;

use crate::model_connection::access::{Currency, Money};

/// Micros of the card's currency per **million** tokens.
///
/// Per million rather than per token because that is the unit published rates
/// are quoted in, and because a per-token rate in micros cannot express a cheap
/// model at all: at 0.8 micros per token it would round to zero or to one and be
/// wrong by 25% either way. A million-token denominator holds every published
/// rate exactly as an integer.
pub type RatePerMillion = u64;

/// The four disjoint token buckets a rate is quoted for.
///
/// Named rather than anonymous so a gap can say *which* count was missing: an
/// operator repairing a report needs to know it lost cache-write tokens, not
/// that something somewhere was unrecorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Bucket {
    InputUncached,
    InputCacheRead,
    InputCacheWrite,
    Output,
}

impl Bucket {
    /// Every bucket, which is also the order a report renders them in.
    pub const ALL: [Bucket; 4] = [
        Bucket::InputUncached,
        Bucket::InputCacheRead,
        Bucket::InputCacheWrite,
        Bucket::Output,
    ];

    /// The measure name this bucket is priced from, spelled as
    /// `whipplescript.stats_report.v0` spells it.
    ///
    /// The spelling is part of the cross-repository contract rather than a
    /// local convenience: `scripts/check-whipplescript-stats-report.mjs` reads
    /// these names out of the pinned schema, so renaming a measure upstream
    /// fails this repository's gate instead of silently pricing nothing.
    pub fn measure_name(self) -> &'static str {
        match self {
            Bucket::InputUncached => "input_uncached",
            Bucket::InputCacheRead => "input_cache_read",
            Bucket::InputCacheWrite => "input_cache_write",
            Bucket::Output => "output",
        }
    }
}

/// What one model charges per bucket, and where that came from.
///
/// `source` and `as_of` are required rather than decorative. A rate is a fact
/// about someone else's price list on a particular day; without its provenance
/// there is no way to tell a rate that was checked this week from one that was
/// guessed a year ago, and the neighbouring table's history is exactly what
/// happens when nobody can tell.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModelRates {
    pub input_uncached: RatePerMillion,
    pub input_cache_read: RatePerMillion,
    pub input_cache_write: RatePerMillion,
    pub output: RatePerMillion,
    /// Where this rate was read from — a published price list, an invoice, a
    /// measured round. Free text for a human, never parsed.
    pub source: String,
    /// The day `source` said it, as `YYYY-MM-DD`.
    pub as_of: String,
}

impl ModelRates {
    fn rate(&self, bucket: Bucket) -> RatePerMillion {
        match bucket {
            Bucket::InputUncached => self.input_uncached,
            Bucket::InputCacheRead => self.input_cache_read,
            Bucket::InputCacheWrite => self.input_cache_write,
            Bucket::Output => self.output,
        }
    }
}

/// The rates in force, for one currency.
///
/// One currency per card, so no sum in this module can mix two. A second
/// currency is a second card and a second report, which is the only shape in
/// which "what did this cost" has an answer at all.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RateCard {
    /// Names the card a figure was produced under, so a past report can be
    /// re-explained without guessing which rates were in force. Bump it
    /// whenever any rate changes.
    pub version: String,
    pub currency: Currency,
    /// Keyed by the model identifier the runtime recorded — the report's
    /// `model` dimension, verbatim. A model absent here is unpriced, never
    /// free.
    pub models: BTreeMap<String, ModelRates>,
}

/// What the runtime recorded for one group of the report.
///
/// Every field is `Option` for one reason: the report distinguishes a count it
/// establishes from one it does not carry, and flattening that distinction to
/// zero is the defect this whole module is shaped around.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MeteredUsage {
    pub input_uncached: Option<u64>,
    pub input_cache_read: Option<u64>,
    pub input_cache_write: Option<u64>,
    pub output: Option<u64>,
}

impl MeteredUsage {
    fn tokens(&self, bucket: Bucket) -> Option<u64> {
        match bucket {
            Bucket::InputUncached => self.input_uncached,
            Bucket::InputCacheRead => self.input_cache_read,
            Bucket::InputCacheWrite => self.input_cache_write,
            Bucket::Output => self.output,
        }
    }
}

/// One group of the report, as this module needs it: which model ran, and what
/// it used.
///
/// `model` is `Option` because the report's dimensions are all optional — a row
/// grouped by something other than `model` carries no model, and a row whose
/// model the log did not record carries `null`. Neither can be priced, and the
/// two are told apart in [`Gap`] because their repairs differ: one is a caller
/// asking the wrong query, the other is a hole in the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeteredRow {
    pub model: Option<String>,
    pub usage: MeteredUsage,
}

/// Why a total is absent.
///
/// A gap is a repair instruction, so it names the thing to repair.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Gap {
    /// Tokens were spent and the row does not say which model spent them, so no
    /// rate can apply. Either the query did not group by `model`, or the log
    /// did not record one.
    ModelUnrecorded,
    /// A model spent tokens and the card has no rate for it.
    NoRate { model: String },
    /// The log does not carry this count. `model` is absent when the row does
    /// not name one either — both halves missing is still one hole.
    Unrecorded {
        model: Option<String>,
        bucket: Bucket,
    },
}

/// The result of pricing.
///
/// Carries the exact accumulator rather than a rounded figure, so that pricing
/// two halves of a report and adding them equals pricing the whole — the same
/// additivity the meter itself guarantees. Rounding happens once, at
/// [`Priced::amount`] or [`Priced::recorded_cost`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Priced {
    currency: Currency,
    /// Micros x 1_000_000, summed exactly across every priced bucket.
    numerator: u128,
    gaps: Vec<Gap>,
}

impl Priced {
    /// The total, or `None` when anything at all was missing.
    ///
    /// Absent rather than partial: a sum that is missing a term is not a
    /// smaller total, it is not a total. Callers that want the part that did
    /// price ask for [`Priced::recorded_cost`], whose name says what it is.
    pub fn amount(&self) -> Option<Money> {
        self.gaps.is_empty().then(|| self.recorded_cost())
    }

    /// What the counts the log does carry came to, at the card's rates.
    ///
    /// Equal to [`Priced::amount`] when there are no gaps. When there are, it
    /// answers "what did the recorded part cost" and nothing else. It is **not**
    /// a bound: an unrecorded input-cache count might be tokens that were never
    /// read from cache, or tokens that were, and were therefore charged at a
    /// rate this sum applied to no one. Pair it with [`Priced::gaps`] or do not
    /// show it.
    pub fn recorded_cost(&self) -> Money {
        let micros = self.numerator.div_ceil(1_000_000);
        Money {
            currency: self.currency.clone(),
            // Saturating rather than wrapping: a figure that wrapped would be
            // small and plausible, which is worse than one that is obviously
            // pegged. u64 micros is ~18 trillion currency units.
            micros: u64::try_from(micros).unwrap_or(u64::MAX),
        }
    }

    /// Everything that stopped a total, deduplicated and ordered.
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    /// The exact accumulator, in micros x 1_000_000. Exposed for the additivity
    /// property, which cannot be stated about a rounded figure.
    pub fn numerator(&self) -> u128 {
        self.numerator
    }
}

impl RateCard {
    /// Price a whole report.
    ///
    /// Rows are independent: one row's gap does not stop another row's tokens
    /// from being priced, it only stops the *total* from existing.
    ///
    /// **A recorded zero costs zero at every rate, so it needs none.** This is
    /// not a shortcut, it is what makes a whole-store report priceable at all.
    /// The meter groups by grain, and a population that could not make a model
    /// call — a `none`-grain row for an effect that wrote a file — carries a
    /// complete recorded zero in every token bucket and names no model. Calling
    /// that a gap would put every report permanently out of reach of a total
    /// while nothing was actually unknown. An unrecorded count is the opposite
    /// and is treated as the opposite.
    pub fn price(&self, rows: &[MeteredRow]) -> Priced {
        let mut numerator: u128 = 0;
        let mut gaps: Vec<Gap> = Vec::new();
        for row in rows {
            let model = row.model.as_deref();
            let rates = model.and_then(|model| self.models.get(model));
            for bucket in Bucket::ALL {
                let Some(tokens) = row.usage.tokens(bucket) else {
                    gaps.push(Gap::Unrecorded {
                        model: row.model.clone(),
                        bucket,
                    });
                    continue;
                };
                if tokens == 0 {
                    continue;
                }
                match (model, rates.as_ref()) {
                    (_, Some(rates)) => {
                        numerator += u128::from(tokens) * u128::from(rates.rate(bucket));
                    }
                    (Some(model), None) => gaps.push(Gap::NoRate {
                        model: model.to_owned(),
                    }),
                    (None, None) => gaps.push(Gap::ModelUnrecorded),
                }
            }
        }
        gaps.sort();
        gaps.dedup();
        Priced {
            currency: self.currency.clone(),
            numerator,
            gaps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd() -> Currency {
        Currency::try_from("USD".to_owned()).expect("three-letter code")
    }

    fn rates(input: u64, read: u64, write: u64, output: u64) -> ModelRates {
        ModelRates {
            input_uncached: input,
            input_cache_read: read,
            input_cache_write: write,
            output,
            source: "test fixture".to_owned(),
            as_of: "2026-09-15".to_owned(),
        }
    }

    fn card() -> RateCard {
        RateCard {
            version: "test-v1".to_owned(),
            currency: usd(),
            models: BTreeMap::from([(
                "test-model".to_owned(),
                // 3.00 / 0.30 / 3.75 / 15.00 currency units per million tokens,
                // in micros: a shape real published rates have, so the
                // arithmetic is exercised at a realistic magnitude.
                rates(3_000_000, 300_000, 3_750_000, 15_000_000),
            )]),
        }
    }

    fn recorded(input: u64, read: u64, write: u64, output: u64) -> MeteredUsage {
        MeteredUsage {
            input_uncached: Some(input),
            input_cache_read: Some(read),
            input_cache_write: Some(write),
            output: Some(output),
        }
    }

    fn row(model: &str, usage: MeteredUsage) -> MeteredRow {
        MeteredRow {
            model: Some(model.to_owned()),
            usage,
        }
    }

    #[test]
    fn a_fully_recorded_row_on_a_rated_model_has_a_total() {
        let priced = card().price(&[row("test-model", recorded(1_000_000, 0, 0, 0))]);
        assert_eq!(priced.gaps(), &[]);
        assert_eq!(priced.amount().expect("no gaps").micros, 3_000_000);
    }

    #[test]
    fn every_bucket_is_priced_at_its_own_rate_and_none_is_double_counted() {
        // Disjoint buckets: the input side is 100 fresh + 200 read + 40 write,
        // and the total is each at its own rate, never the input rate applied
        // to the cached counts as well.
        let priced = card().price(&[row("test-model", recorded(100, 200, 40, 10))]);
        let expected: u128 = 100 * 3_000_000 + 200 * 300_000 + 40 * 3_750_000 + 10 * 15_000_000;
        assert_eq!(priced.numerator(), expected);
        assert_eq!(priced.recorded_cost().micros, 660);
    }

    #[test]
    fn an_unrecorded_bucket_leaves_no_total_and_is_never_priced_as_zero() {
        let usage = MeteredUsage {
            input_uncached: Some(1_000_000),
            input_cache_read: None,
            input_cache_write: Some(0),
            output: Some(0),
        };
        let priced = card().price(&[row("test-model", usage)]);
        assert_eq!(priced.amount(), None, "a missing count is not a total");
        assert_eq!(
            priced.gaps(),
            &[Gap::Unrecorded {
                model: Some("test-model".to_owned()),
                bucket: Bucket::InputCacheRead,
            }]
        );
        // The recorded part is still reported, because an operator closing the
        // gap needs to know what the run has already been priced at.
        assert_eq!(priced.recorded_cost().micros, 3_000_000);
    }

    #[test]
    fn a_recorded_zero_is_a_complete_answer_and_prices_as_zero() {
        let priced = card().price(&[row("test-model", recorded(0, 0, 0, 0))]);
        assert_eq!(priced.gaps(), &[]);
        assert_eq!(priced.amount().expect("no gaps").micros, 0);
    }

    #[test]
    fn a_model_with_no_rate_is_unpriced_rather_than_free() {
        let priced = card().price(&[
            row("test-model", recorded(1_000_000, 0, 0, 0)),
            row("unrated-model", recorded(1_000_000, 0, 0, 0)),
        ]);
        assert_eq!(priced.amount(), None);
        assert_eq!(
            priced.gaps(),
            &[Gap::NoRate {
                model: "unrated-model".to_owned()
            }]
        );
        // Only the rated model was priced. If the unrated one had defaulted to
        // any rate at all this would be larger, and wrong.
        assert_eq!(priced.recorded_cost().micros, 3_000_000);
    }

    #[test]
    fn a_row_that_spends_tokens_without_saying_which_model_is_unpriced() {
        let priced = card().price(&[MeteredRow {
            model: None,
            usage: recorded(1_000_000, 0, 0, 0),
        }]);
        assert_eq!(priced.amount(), None);
        assert_eq!(priced.gaps(), &[Gap::ModelUnrecorded]);
        assert_eq!(priced.recorded_cost().micros, 0);
    }

    #[test]
    fn a_row_that_spent_nothing_needs_no_model_and_still_has_a_total() {
        // What the meter emits for a population that could not make a model
        // call: `none` grain, no model, a complete recorded zero everywhere. It
        // is priced, at zero, because nothing about it is unknown.
        let priced = card().price(&[
            MeteredRow {
                model: None,
                usage: recorded(0, 0, 0, 0),
            },
            row("test-model", recorded(1_000_000, 0, 0, 0)),
        ]);
        assert_eq!(priced.gaps(), &[]);
        assert_eq!(priced.amount().expect("no gaps").micros, 3_000_000);
    }

    #[test]
    fn an_unrated_model_that_spent_nothing_is_not_a_gap() {
        // The same rule one step along: a rate nothing would multiply is a rate
        // nobody has to supply.
        let priced = card().price(&[row("unrated-model", recorded(0, 0, 0, 0))]);
        assert_eq!(priced.gaps(), &[]);
        assert_eq!(priced.amount().expect("no gaps").micros, 0);
    }

    #[test]
    fn pricing_two_halves_and_adding_equals_pricing_the_whole() {
        // The meter's own additivity, carried through the price. Stated on the
        // exact accumulator because it is not true of rounded figures.
        let card = card();
        let left = [row("test-model", recorded(7, 11, 13, 17))];
        let right = [row("test-model", recorded(19, 23, 29, 31))];
        let whole: Vec<MeteredRow> = left.iter().chain(right.iter()).cloned().collect();
        assert_eq!(
            card.price(&left).numerator() + card.price(&right).numerator(),
            card.price(&whole).numerator(),
        );
    }

    #[test]
    fn a_sub_micro_amount_rounds_up_rather_than_vanishing() {
        // One token of a cheap model costs 0.3 micros. Rounding it down would
        // report a run that cost something as having cost nothing, which is the
        // same failure as pricing unrecorded usage at zero, arrived at by
        // arithmetic instead of by semantics.
        let priced = card().price(&[row("test-model", recorded(0, 1, 0, 0))]);
        assert_eq!(priced.amount().expect("no gaps").micros, 1);
    }

    #[test]
    fn the_currency_of_the_figure_is_the_card_s() {
        let priced = card().price(&[row("test-model", recorded(1, 1, 1, 1))]);
        assert_eq!(priced.recorded_cost().currency, usd());
    }

    #[test]
    fn repeated_gaps_are_reported_once() {
        let priced = card().price(&[
            row("unrated-model", recorded(1, 1, 1, 1)),
            row("unrated-model", recorded(2, 2, 2, 2)),
        ]);
        assert_eq!(
            priced.gaps(),
            &[Gap::NoRate {
                model: "unrated-model".to_owned()
            }]
        );
    }
}
