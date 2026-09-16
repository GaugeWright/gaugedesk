//! What a project's whips have cost, from what the runtime recorded.
//!
//! **The runtime meters; the desk prices** (`specs/primitives/runtime.md`).
//! This is the surface half of that rule: it reads WhippleScript's own fold
//! over its durable log through [`gaugedesk_whip_runtime::whip_stats`], applies
//! the rate card, and reports the figure with everything that stopped it from
//! being a total.
//!
//! Three refusals travel from the layer below into this document, and each one
//! is a shape rather than a convention a client has to remember.
//!
//! **`amount_micros` is null whenever anything is missing.** Not smaller —
//! absent. A sum missing a term is not a total, and the only way to make a
//! client render that correctly is to withhold the number rather than to
//! annotate it.
//!
//! **`recorded_micros` says what it is in its name.** It is what the counts the
//! log carries came to at the card's rates, and it is not a bound in either
//! direction: an unrecorded cache bucket may be tokens never spent, or tokens
//! spent at a rate this sum never applied. It travels beside `gaps`, never
//! instead of them.
//!
//! **A store that will not open is a gap, not a zero.** This is the same
//! distinction `whip_views` keeps between nothing-to-see and could-not-see
//! (ACTION-7), arriving at the same answer from the other direction: a store
//! the desk could not read has an unknown cost, and unknown costs make the
//! total absent exactly as an unrecorded token count does. Silently pricing the
//! stores that did open would report a project as cheaper than it is, which is
//! the one direction a cost report must never be wrong in by accident.

use std::collections::BTreeMap;
use std::path::Path;

use gaugedesk_core::whip_pricing::{Gap, MeteredRow, Priced, RateCard};
use serde_json::{json, Value};

use crate::Workbench;

pub const PROJECT_WHIP_COSTS_SCHEMA: &str = "gaugedesk.project_whip_costs.v1";

impl Workbench {
    /// `None` when there is no such project. A project that has run nothing
    /// still answers, with a complete recorded zero: nothing ran, so nothing
    /// cost anything, and that zero is an answer rather than a gap.
    pub fn project_whip_costs_value(&self, project_id: &str) -> Option<Value> {
        self.library.projects.get(project_id)?;
        let card = match gaugedesk_whip_runtime::whip_stats::repository_rate_card() {
            Ok(card) => card,
            Err(error) => {
                // The card ships with the binary, so this is a build fault
                // rather than an operator's. Reported as an unreadable surface
                // rather than as a free project.
                tracing::error!(error = %error, "whip costs: the shipped rate card does not parse");
                return Some(json!({
                    "schema": PROJECT_WHIP_COSTS_SCHEMA,
                    "project": project_id,
                    "complete": false,
                    "unread": crate::whip_views::UNREADABLE,
                    "rate_card": Value::Null,
                    "whips": [],
                }));
            }
        };

        let root = self.root_path();
        let mut whips = Vec::new();

        let target = crate::library_state::managed_project_target_id(project_id);
        let gate_path = crate::library::target_id_path_v1(&target)
            .map(|encoded| format!("targets/{encoded}/{}", crate::gate::GATE_PROGRAM_PATH))
            .unwrap_or_else(|_| crate::gate::GATE_PROGRAM_PATH.to_owned());
        // Every store is read ONCE, and the project figure is the fold of what
        // those reads produced. Re-reading for the total would be two answers
        // to one question, and they could disagree while a store was being
        // written beside them — which is exactly when a cost is asked for.
        let runtime_root = crate::whip_views::chat_runtime_root(&root);
        let mut stores = vec![(
            json!({ "path": gate_path, "program": "gate", "chat": Value::Null }),
            crate::whip_views::gate_runtime_store(&root, project_id),
        )];
        for chat in self.library.project_chats(project_id) {
            stores.push((
                json!({ "path": Value::Null, "program": Value::Null, "chat": chat.id }),
                gaugedesk_whip_runtime::chat_runtime_database(&runtime_root, &chat.id),
            ));
        }

        let mut rows: Vec<MeteredRow> = Vec::new();
        let mut unread = false;
        for (identity, store) in stores {
            let whip = metered(&card, identity, &store);
            unread |= whip.unread;
            rows.extend(whip.rows);
            whips.push(whip.value);
        }

        // Priced once over every row rather than by adding rendered figures:
        // the accumulator is exact and the rounding happens at the edge, so the
        // whole equals the sum of its parts (the meter's own additivity,
        // carried through the price).
        let total = card.price(&rows);

        Some(json!({
            "schema": PROJECT_WHIP_COSTS_SCHEMA,
            "project": project_id,
            // One place a reader looks to learn the figure is partial, beside
            // the same word `whip_views` uses for the same condition.
            "complete": !unread && total.gaps().is_empty(),
            "unread": if unread { Value::String(crate::whip_views::UNREADABLE.to_owned()) } else { Value::Null },
            "rate_card": json!({
                "version": card.version,
                "currency": card.currency.code(),
                "rated_models": card.models.len(),
            }),
            "total": priced_json(&total, unread),
            "gaps": gaps_json(total.gaps()),
            "whips": whips,
        }))
    }
}

/// One store's reading: what it is, what it metered, and whether it answered.
struct Metered {
    value: Value,
    rows: Vec<MeteredRow>,
    unread: bool,
}

/// One store, priced.
///
/// An absent store is a complete answer — nothing has run — and prices to a
/// recorded zero. A store that exists and will not open is the opposite, and
/// says so instead of answering with a zero nobody can tell from the first.
fn metered(card: &RateCard, identity: Value, store: &Path) -> Metered {
    let mut whip = identity;
    let object = whip.as_object_mut().expect("identity is an object");
    let (rows, unread) = match (store.exists(), store) {
        (false, _) => (Vec::new(), None),
        (true, store) => match gaugedesk_whip_runtime::whip_stats::usage_by_model(store) {
            Ok(rows) => (rows, None),
            Err(error) => {
                tracing::warn!(store = %store.display(), error = %error, "whip costs: could not read a runtime store");
                (Vec::new(), Some(crate::whip_views::UNREADABLE))
            }
        },
    };
    let priced = card.price(&rows);
    object.insert(
        "unread".to_owned(),
        unread.map_or(Value::Null, |reason| Value::String(reason.to_owned())),
    );
    object.insert("total".to_owned(), priced_json(&priced, unread.is_some()));
    object.insert("gaps".to_owned(), gaps_json(priced.gaps()));
    object.insert(
        "models".to_owned(),
        Value::Array(
            rows.iter()
                .filter_map(|row| row.model.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    Metered {
        value: whip,
        rows,
        unread: unread.is_some(),
    }
}

/// A figure, with its total withheld whenever anything is missing.
///
/// `unread` joins the gaps in withholding it. A store the desk could not open
/// might hold any cost at all, so a total computed without it is not a smaller
/// total — it is a different project's.
fn priced_json(priced: &Priced, unread: bool) -> Value {
    let amount = if unread {
        None
    } else {
        priced.amount().map(|money| money.micros)
    };
    json!({
        "currency": priced.recorded_cost().currency.code(),
        "amount_micros": amount,
        "recorded_micros": priced.recorded_cost().micros,
    })
}

/// Every gap, as a repair instruction rather than a count.
///
/// Grouped by reason and named, because "3 gaps" tells an operator nothing they
/// can act on while "no rate for `claude-sonnet-5`" is the next thing to do.
fn gaps_json(gaps: &[Gap]) -> Value {
    let mut by_model: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut out = Vec::new();
    for gap in gaps {
        match gap {
            Gap::ModelUnrecorded => out.push(json!({ "reason": "model_unrecorded" })),
            Gap::NoRate { model } => by_model
                .entry(model.clone())
                .or_default()
                .push(json!({ "reason": "no_rate" })),
            Gap::Unrecorded { model, bucket } => by_model
                .entry(model.clone().unwrap_or_default())
                .or_default()
                .push(json!({ "reason": "unrecorded", "measure": bucket.measure_name() })),
        }
    }
    for (model, reasons) in by_model {
        for mut reason in reasons {
            if let Some(object) = reason.as_object_mut() {
                object.insert("model".to_owned(), Value::String(model.clone()));
            }
            out.push(reason);
        }
    }
    Value::Array(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::model_connection::access::Currency;
    use gaugedesk_core::whip_pricing::ModelRates;

    fn card(models: &[&str]) -> RateCard {
        RateCard {
            version: "whip-costs-test-v1".to_owned(),
            currency: Currency::try_from("USD".to_owned()).expect("a three-letter code"),
            models: models
                .iter()
                .map(|model| {
                    (
                        (*model).to_owned(),
                        ModelRates {
                            input_uncached: 3_000_000,
                            input_cache_read: 300_000,
                            input_cache_write: 3_750_000,
                            output: 15_000_000,
                            source: "test fixture".to_owned(),
                            as_of: "2026-09-16".to_owned(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn identity() -> Value {
        json!({ "path": "gates/inbound.whip", "program": "gate", "chat": Value::Null })
    }

    #[test]
    fn a_store_that_never_existed_costs_a_complete_zero() {
        // The ordinary state of a project nothing has run in. Absent is a
        // complete answer, so the figure is a real zero and not a gap.
        let dir = tempfile::tempdir().expect("tempdir");
        let metered = metered(&card(&[]), identity(), &dir.path().join("runtime.sqlite"));
        assert!(!metered.unread);
        assert_eq!(metered.value["unread"], Value::Null);
        assert_eq!(metered.value["total"]["amount_micros"], json!(0));
        assert_eq!(metered.value["total"]["recorded_micros"], json!(0));
        assert_eq!(metered.value["gaps"], json!([]));
    }

    #[test]
    fn a_store_that_will_not_open_withholds_the_total_rather_than_lowering_it() {
        // The whole reason this projection carries `unread` at all. A store the
        // desk could not read might hold any cost, so a figure computed without
        // it is not a smaller total — it is a different project's. Reporting it
        // as a total would say a project cost less than it did, which is the
        // one direction a cost report must never be wrong in by accident.
        //
        // This is `whip_views`' nothing-to-see / could-not-see distinction
        // (ACTION-7) reached from the other side, and it lands on the same rule
        // the meter already holds for an unrecorded count.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("runtime.sqlite");
        std::fs::write(&store, b"this is not a sqlite database").expect("write");

        let metered = metered(&card(&[]), identity(), &store);
        assert!(metered.unread);
        assert_eq!(
            metered.value["unread"],
            json!(crate::whip_views::UNREADABLE)
        );
        assert_eq!(
            metered.value["total"]["amount_micros"],
            Value::Null,
            "a store that did not answer cannot leave a total behind"
        );
    }

    #[test]
    fn an_unreadable_store_is_told_apart_from_an_absent_one() {
        // Both used to arrive as an empty vector. The difference is the whole
        // point: one is a project with no runs, the other is a project whose
        // runs nobody could see, and only the first has a total.
        let dir = tempfile::tempdir().expect("tempdir");
        let absent = metered(&card(&[]), identity(), &dir.path().join("absent.sqlite"));
        let unreadable = {
            let store = dir.path().join("corrupt.sqlite");
            std::fs::write(&store, b"not a database").expect("write");
            metered(&card(&[]), identity(), &store)
        };
        assert_eq!(absent.value["total"]["amount_micros"], json!(0));
        assert_eq!(unreadable.value["total"]["amount_micros"], Value::Null);
        assert_ne!(absent.value["unread"], unreadable.value["unread"]);
    }
}
