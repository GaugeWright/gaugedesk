//! Reading WhippleScript's meter, so [`gaugedesk_core::whip_pricing`] can price
//! it.
//!
//! The runtime owns usage evidence (`specs/primitives/runtime.md`) and folds it
//! into `whipplescript.stats_report.v0` — a pure fold over its own durable log,
//! not a second stream (its DR-0114). GaugeDesk reads that fold. It does not
//! count tokens, keep a parallel tally, or reconstruct usage from a transcript.
//!
//! There are two ways to hold the same report, and both are here on purpose.
//!
//! * [`usage_by_model`] folds a local runtime store through the runtime's own
//!   kernel, which is the path a desk on this machine takes. It is typed, so a
//!   change in the pinned runtime is a compile error rather than a silent
//!   mis-read.
//! * [`usage_from_report`] reads the published JSON, which is the path anything
//!   holding a report takes — a hosted instance answering
//!   `/host/instances/:id/stats`, or a report someone saved.
//!
//! They must agree, and `the_two_ways_to_hold_a_report_price_the_same` is what
//! says so. That test is also the answer to a question WhippleScript cannot ask
//! on its own side of the boundary: **is the report sufficient to price from?**
//! Its own records state that it meters and does not price, leaving the
//! sufficiency of the meter to be demonstrated by a consumer. The JSON path
//! sees nothing but the published document, so if the document ever stopped
//! carrying what a price needs, that test would be the thing that could not be
//! written.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use gaugedesk_core::whip_pricing::{Bucket, MeteredRow, MeteredUsage, RateCard};
use serde_json::Value;
use whipplescript_kernel::stats::{self, Dimension, Measure, Query, Row};

/// The report document this module reads, as its schema names itself.
pub const STATS_REPORT_SCHEMA: &str = "whipplescript.stats_report.v0";

/// Every model's token usage in one runtime store.
///
/// Opens the store the harness or gate writes as a second read-only connection,
/// exactly as [`crate::instance_views`] does, so a running instance is metered
/// as it runs. Observation never initializes or migrates a store.
///
/// Grouped by model, which is the only dimension a rate can attach to, and
/// across every instance the store holds: a store is one workspace's runs, and
/// "what did this cost" is asked of the workspace rather than of one run.
pub fn usage_by_model(store_path: &Path) -> io::Result<Vec<MeteredRow>> {
    let store_io = |error: whipplescript_store::StoreError| io::Error::other(format!("{error:?}"));
    let store = whipplescript_store::SqliteStore::open_read_only(store_path).map_err(store_io)?;
    let mut inputs = stats::FoldInputs::default();
    for instance in store.list_instances().map_err(store_io)? {
        inputs.absorb(stats::inputs_for_instance(&store, &instance.instance_id).map_err(store_io)?);
    }
    let rows = inputs.rows(&Query {
        by: vec![Dimension::Model],
        ..Query::default()
    });
    Ok(rows.iter().map(metered_row).collect())
}

/// The same usage, read out of a published report document instead.
///
/// Refuses a document that does not name itself as the schema this was written
/// against. A report whose shape changed is not a report to price quietly from:
/// the buckets are a convention (disjoint, never inclusive), and a reader that
/// guessed wrong would double-count every cached token without failing.
pub fn usage_from_report(report: &Value) -> Result<Vec<MeteredRow>, String> {
    match report.get("schema").and_then(Value::as_str) {
        Some(STATS_REPORT_SCHEMA) => {}
        Some(other) => return Err(format!("unexpected stats report schema {other:?}")),
        None => return Err("stats report names no schema".to_owned()),
    }
    let rows = report
        .get("rows")
        .and_then(Value::as_array)
        .ok_or_else(|| "stats report carries no rows array".to_owned())?;
    rows.iter().map(metered_row_from_json).collect()
}

fn metered_row(row: &Row) -> MeteredRow {
    MeteredRow {
        model: row
            .key
            .iter()
            .find(|(dimension, _)| *dimension == Dimension::Model)
            .and_then(|(_, value)| value.clone()),
        usage: MeteredUsage {
            input_uncached: tokens(row.measures.input_uncached),
            input_cache_read: tokens(row.measures.input_cache_read),
            input_cache_write: tokens(row.measures.input_cache_write),
            output: tokens(row.measures.output),
        },
    }
}

/// An unrecorded measure stays unrecorded. A negative one cannot be a token
/// count, and is dropped to unrecorded rather than saturated to zero: zero is
/// the one reading that would price as certainly free.
fn tokens(measure: Measure) -> Option<u64> {
    measure.value().and_then(|value| u64::try_from(value).ok())
}

fn metered_row_from_json(row: &Value) -> Result<MeteredRow, String> {
    let model = match row.pointer("/key/model") {
        None | Some(Value::Null) => None,
        Some(Value::String(model)) => Some(model.clone()),
        Some(other) => return Err(format!("a model dimension must be a string, found {other}")),
    };
    let mut usage = MeteredUsage::default();
    for bucket in Bucket::ALL {
        // Absent and null are the same answer: the report does not carry this
        // count. Only `measures` the schema requires are always present, and a
        // token bucket is not one of them.
        let recorded = match row
            .get("measures")
            .and_then(|m| m.get(bucket.measure_name()))
        {
            None | Some(Value::Null) => None,
            Some(Value::Number(number)) => Some(
                number
                    .as_u64()
                    .ok_or_else(|| format!("{} is not a token count", bucket.measure_name()))?,
            ),
            Some(other) => {
                return Err(format!(
                    "measure {} must be an integer or null, found {other}",
                    bucket.measure_name()
                ))
            }
        };
        match bucket {
            Bucket::InputUncached => usage.input_uncached = recorded,
            Bucket::InputCacheRead => usage.input_cache_read = recorded,
            Bucket::InputCacheWrite => usage.input_cache_write = recorded,
            Bucket::Output => usage.output = recorded,
        }
    }
    Ok(MeteredRow { model, usage })
}

/// The rate card this build ships, verbatim.
///
/// Embedded rather than read at run time so a shipped binary carries the rates
/// it was built with and cannot be pointed at a different card by accident. It
/// is validated in shape — never in value — by
/// `scripts/check-whipplescript-stats-report.mjs`.
pub const REPOSITORY_RATE_CARD: &str = include_str!("../../../contracts/model-token-rates.json");

/// Parse the shipped card.
///
/// **It ships with no rates in it, and that is a decision rather than an
/// oversight.** A rate is a fact about someone else's price list on a
/// particular day, and this repository's own history with guessed rates is
/// specific: `deployment_pricing`'s per-token constants were measured against a
/// real metered round and found to over-bill a small model by 6.2x. Seeding
/// this card from memory would repeat that with a wider blast radius and no
/// measurement to catch it. So the card starts empty, every model a run touches
/// arrives as a named `NoRate` gap, and the report says exactly which rates an
/// operator has to supply and for which models. Nothing is ever priced at a
/// default, because there is no default to price at.
pub fn repository_rate_card() -> Result<RateCard, String> {
    serde_json::from_str(REPOSITORY_RATE_CARD)
        .map_err(|error| format!("the shipped rate card does not parse: {error}"))
}

/// Everything unpriced in a report, as a count per model.
///
/// Not part of pricing — a gap already names itself — but what a surface needs
/// to say "3 models have no rate" without re-walking the rows.
pub fn models_seen(rows: &[MeteredRow]) -> BTreeMap<Option<String>, usize> {
    let mut seen: BTreeMap<Option<String>, usize> = BTreeMap::new();
    for row in rows {
        *seen.entry(row.model.clone()).or_default() += 1;
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::model_connection::access::Currency;
    use gaugedesk_core::whip_pricing::{Gap, ModelRates, RateCard};
    use serde_json::json;
    use whipplescript_kernel::stats::Measures;

    fn card() -> RateCard {
        RateCard {
            version: "test-v1".to_owned(),
            currency: Currency::try_from("USD".to_owned()).expect("code"),
            models: BTreeMap::from([(
                "test-model".to_owned(),
                ModelRates {
                    input_uncached: 3_000_000,
                    input_cache_read: 300_000,
                    input_cache_write: 3_750_000,
                    output: 15_000_000,
                    source: "test fixture".to_owned(),
                    as_of: "2026-09-15".to_owned(),
                },
            )]),
        }
    }

    fn measures(input: Measure, read: Measure, write: Measure, output: Measure) -> Measures {
        Measures {
            input_uncached: input,
            input_cache_read: read,
            input_cache_write: write,
            output,
            ..Measures::zero()
        }
    }

    /// The same two rows, written twice and independently: once as the kernel
    /// hands them over, once as the published document spells them.
    fn typed_fixture() -> Vec<Row> {
        vec![
            Row {
                key: vec![(Dimension::Model, Some("test-model".to_owned()))],
                measures: measures(
                    Measure::recorded(100),
                    Measure::recorded(200),
                    Measure::recorded(40),
                    Measure::recorded(10),
                ),
            },
            Row {
                key: vec![(Dimension::Model, None)],
                measures: measures(
                    Measure::recorded(0),
                    Measure::recorded(0),
                    Measure::recorded(0),
                    Measure::recorded(0),
                ),
            },
        ]
    }

    fn report_fixture() -> Value {
        json!({
            "schema": STATS_REPORT_SCHEMA,
            "rows": [
                {
                    "key": { "model": "test-model", "grain": "call" },
                    "measures": {
                        "effects": 1, "runs": 1, "retries": 0, "calls": 1,
                        "input_uncached": 100,
                        "input_cache_read": 200,
                        "input_cache_write": 40,
                        "output": 10
                    }
                },
                {
                    "key": { "model": null, "grain": "none" },
                    "measures": {
                        "effects": 1, "runs": 1, "retries": 0, "calls": 0,
                        "input_uncached": 0,
                        "input_cache_read": 0,
                        "input_cache_write": 0,
                        "output": 0
                    }
                }
            ]
        })
    }

    #[test]
    fn the_two_ways_to_hold_a_report_price_the_same() {
        // The cross-repository claim, verified on this side because it cannot be
        // verified on the other: the published document carries everything a
        // price needs. If it stopped carrying the model dimension, or folded the
        // disjoint buckets into one, the JSON half of this could not reach the
        // same figure as the typed half.
        let typed: Vec<MeteredRow> = typed_fixture().iter().map(metered_row).collect();
        let published = usage_from_report(&report_fixture()).expect("the fixture is a report");
        assert_eq!(typed, published);

        let card = card();
        assert_eq!(card.price(&typed), card.price(&published));
        assert_eq!(
            card.price(&published).amount().expect("no gaps").micros,
            660
        );
    }

    #[test]
    fn an_absent_token_bucket_is_unrecorded_and_not_zero() {
        // The schema requires `effects`, `runs`, `retries`, `calls` and
        // `output`; a token bucket may simply be absent. Absent must mean what
        // null means, or a report that omits a bucket prices as though that
        // bucket were free.
        let report = json!({
            "schema": STATS_REPORT_SCHEMA,
            "rows": [{
                "key": { "model": "test-model", "grain": "turn" },
                "measures": { "effects": 1, "runs": 1, "retries": 0, "calls": 1, "output": 10 }
            }]
        });
        let rows = usage_from_report(&report).expect("a report");
        assert_eq!(rows[0].usage.input_uncached, None);
        let priced = card().price(&rows);
        assert_eq!(priced.amount(), None);
        assert!(priced.gaps().contains(&Gap::Unrecorded {
            model: Some("test-model".to_owned()),
            bucket: Bucket::InputUncached,
        }));
    }

    #[test]
    fn an_explicitly_null_measure_is_unrecorded() {
        let report = json!({
            "schema": STATS_REPORT_SCHEMA,
            "rows": [{
                "key": { "model": "test-model", "grain": "turn" },
                "measures": {
                    "effects": 1, "runs": 1, "retries": 0, "calls": null,
                    "input_uncached": null, "input_cache_read": 0,
                    "input_cache_write": 0, "output": 10
                }
            }]
        });
        let rows = usage_from_report(&report).expect("a report");
        assert_eq!(rows[0].usage.input_uncached, None);
        assert_eq!(rows[0].usage.input_cache_read, Some(0));
    }

    #[test]
    fn a_document_of_another_schema_is_refused_rather_than_read() {
        let report = json!({ "schema": "whipplescript.instance_view.v0", "rows": [] });
        assert!(usage_from_report(&report).is_err());
        assert!(usage_from_report(&json!({ "rows": [] })).is_err());
    }

    #[test]
    fn an_unrecorded_measure_stays_unrecorded_through_the_typed_path() {
        let row = Row {
            key: vec![(Dimension::Model, Some("test-model".to_owned()))],
            measures: measures(
                Measure::unrecorded(),
                Measure::recorded(0),
                Measure::recorded(0),
                Measure::recorded(7),
            ),
        };
        assert_eq!(metered_row(&row).usage.input_uncached, None);
    }

    #[test]
    fn an_empty_runtime_store_meters_nothing_and_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("runtime.sqlite");
        drop(whipplescript_store::SqliteStore::open(&path).expect("open"));
        assert!(usage_by_model(&path).expect("read").is_empty());
    }

    #[test]
    fn metering_an_unavailable_runtime_does_not_initialize_storage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing.sqlite");
        assert!(usage_by_model(&path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn the_shipped_rate_card_parses_and_rates_nothing_yet() {
        let card = repository_rate_card().expect("the shipped card parses");
        assert!(
            card.models.is_empty(),
            "a rate seeded from memory rather than from a source is the failure this avoids",
        );
        // And an empty card is safe rather than free: every model that spent
        // anything comes back named.
        let rows = usage_from_report(&report_fixture()).expect("a report");
        let priced = card.price(&rows);
        assert_eq!(priced.amount(), None);
        assert_eq!(priced.recorded_cost().micros, 0);
        assert_eq!(
            priced.gaps(),
            &[Gap::NoRate {
                model: "test-model".to_owned()
            }],
        );
    }

    #[test]
    fn every_model_a_report_names_is_countable_including_the_unrecorded_one() {
        let rows = usage_from_report(&report_fixture()).expect("a report");
        let seen = models_seen(&rows);
        assert_eq!(seen.get(&Some("test-model".to_owned())), Some(&1));
        assert_eq!(seen.get(&None), Some(&1));
    }
}
