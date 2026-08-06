//! RF-C4 — cross-lifecycle integration proptest: the protection chain
//! (context grant → run/observe → engagement-scoped taint → review/export
//! consent) holds over **random interleavings**, end-to-end through the Store.
//!
//! The per-reducer proptests in `gaugedesk-core` prove each lifecycle in isolation;
//! this drives the *integration glue* the app layer adds and that no single
//! reducer can see:
//! - reads recorded durably per turn and the output's stakeholders derived from
//!   the **persisted** records (`resource_store::mint_output`, ADR 0026), so a
//!   revoke/tombstone after the read does not launder the taint;
//! - the review/export `required` sets derived from the **resource**, never
//!   supplied by the caller (mirroring `post_resource_export` /
//!   `post_resource_review` — `INV-13`/`INV-16`);
//! - the SOUND end-to-end property (`INV-22`): if an export reaches `Exported`
//!   or a review reaches `Released`, every owner of anything the engagement had
//!   read up to the minted output consented in that lifecycle.

use std::collections::BTreeSet;

use proptest::prelude::*;

use gaugedesk_app::resource_store;
use gaugedesk_core::resource_export::{ExportCommand, ExportPhase, ExportState};
use gaugedesk_core::review::{ReviewCommand, ReviewPhase, ReviewState};
use gaugedesk_core::run::{RunCommand, RunState};
use gaugedesk_core::Lifecycle;
use gaugedesk_store::{AdmitError, Store};

const ENG: &str = "eng-chain";
const OWNER: &str = "local-user";

/// The closed universe: three context folders with distinct owners, so taint
/// has real multi-authority structure even in the single-process test.
const CONTEXTS: [(&str, &str); 3] = [
    ("/ctx/local-notes", "local-user"),
    ("/ctx/client-a-data", "client-A"),
    ("/ctx/client-b-data", "client-B"),
];
const AUTHORITIES: [&str; 4] = ["local-user", "client-A", "client-B", "outsider"];

#[derive(Clone, Debug)]
enum Op {
    /// Open a context folder (mints + auto-grants, like the context panel).
    MintContext(usize),
    /// One engine turn: run admission → observation → reads recorded →
    /// output minted from the durable read-set (engine.rs step 6 order).
    Turn,
    /// Tombstone a context's payload (content-erasure outcome).
    Tombstone(usize),
    /// Propose export/review of the output with the resource-derived set.
    ProposeExport,
    ProposeReview,
    /// Lifecycle steps, possibly out of order / by the wrong authority —
    /// the reducers must hold the gate regardless.
    ExportConsent(usize),
    ExportTargetAdmit,
    ExportNow,
    ReviewConsent(usize),
    ReviewRelease,
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..CONTEXTS.len()).prop_map(Op::MintContext),
        Just(Op::Turn),
        (0..CONTEXTS.len()).prop_map(Op::Tombstone),
        Just(Op::ProposeExport),
        Just(Op::ProposeReview),
        (0..AUTHORITIES.len()).prop_map(Op::ExportConsent),
        Just(Op::ExportTargetAdmit),
        Just(Op::ExportNow),
        (0..AUTHORITIES.len()).prop_map(Op::ReviewConsent),
        Just(Op::ReviewRelease),
    ]
}

/// Admit, treating a fail-closed rejection as a legal no-op (the gate held);
/// any other error is a real failure.
fn admit_ok<L: Lifecycle>(
    store: &mut Store,
    scope: &str,
    cmd: L::Command,
) -> Result<(), TestCaseError> {
    match store.admit::<L>(scope, cmd) {
        Ok(_) | Err(AdmitError::Rejected(_)) => Ok(()),
        Err(e) => Err(TestCaseError::fail(format!("admit error: {e:?}"))),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// SOUND across the whole chain: whatever the interleaving, a crossing
    /// (export `Exported`, review `Released`) implies conjunctive consent of
    /// the owners of everything the engagement had read into the output —
    /// and the consent requirement itself always equals the persisted
    /// stakeholder set (derived, never caller-chosen).
    #[test]
    fn protection_chain_is_sound_over_random_interleavings(
        ops in prop::collection::vec(arb_op(), 0..60),
    ) {
        let mut store = Store::open_in_memory().unwrap();
        let out_id = resource_store::output_id(ENG);
        let export_scope = resource_store::export_scope(ENG, &out_id);
        let review_scope = resource_store::review_scope(ENG, &out_id);

        // Ghost model: owners of everything ever read, as of the last mint.
        let mut ghost_read_owners: BTreeSet<String> = BTreeSet::new();
        let mut minted = false;
        // The stakeholder set each proposal was derived from, at propose time.
        let mut export_required_ghost: Option<BTreeSet<String>> = None;
        let mut review_required_ghost: Option<BTreeSet<String>> = None;

        for op in ops {
            match op {
                Op::MintContext(i) => {
                    let (path, owner) = CONTEXTS[i];
                    resource_store::mint_context(&mut store, ENG, owner, path, "c0").unwrap();
                }
                Op::Turn => {
                    // Engine order: run admission → execution evidence → reads
                    // recorded → output minted from the durable read-set.
                    let scope = ENG;
                    admit_ok::<RunState>(&mut store, scope, RunCommand::RequestRun)?;
                    admit_ok::<RunState>(&mut store, scope, RunCommand::AdmitRun)?;
                    admit_ok::<RunState>(&mut store, scope, RunCommand::StartRun)?;
                    admit_ok::<RunState>(&mut store, scope, RunCommand::RecordObservation)?;
                    admit_ok::<RunState>(&mut store, scope, RunCommand::CompleteRun)?;

                    let reads = resource_store::granted_context(&store, ENG).unwrap();
                    for id in &reads {
                        let owner = CONTEXTS
                            .iter()
                            .find(|(p, _)| &resource_store::context_id(p) == id)
                            .map(|(_, o)| o.to_string())
                            .expect("read of a known context");
                        ghost_read_owners.insert(owner);
                    }
                    resource_store::record_reads(&mut store, ENG, &reads).unwrap();
                    let rec = resource_store::mint_output(&mut store, ENG, OWNER, "c1").unwrap();
                    minted = true;

                    // The integration claim itself: persisted stakeholders ==
                    // owners of everything the engagement ever read (ADR 0026),
                    // including reads of since-tombstoned contexts.
                    let got: BTreeSet<String> =
                        rec.stakeholders.iter().map(|a| a.as_str().to_string()).collect();
                    prop_assert_eq!(
                        &got, &ghost_read_owners,
                        "output stakeholders must be the owners of the full read history"
                    );
                }
                Op::Tombstone(i) => {
                    let id = resource_store::context_id(CONTEXTS[i].0);
                    let _ = resource_store::tombstone(&mut store, ENG, &id);
                    // Note: ghost_read_owners is NOT reduced — taint must survive.
                }
                Op::ProposeExport => {
                    if let Ok(Some(rec)) = resource_store::get(&store, ENG, &out_id) {
                        // Mirror post_resource_export: required is DERIVED.
                        let required: BTreeSet<String> =
                            rec.stakeholders.iter().map(|a| a.as_str().to_string()).collect();
                        let before = store.fold::<ExportState>(&export_scope).unwrap().phase;
                        admit_ok::<ExportState>(
                            &mut store,
                            &export_scope,
                            ExportCommand::ProposeExport {
                                source_required: required.iter().map(|s| s.as_str().into()).collect(),
                            },
                        )?;
                        let after = store.fold::<ExportState>(&export_scope).unwrap().phase;
                        if before == ExportPhase::Init && after == ExportPhase::Requested {
                            export_required_ghost = Some(required);
                        }
                    }
                }
                Op::ProposeReview => {
                    if let Ok(Some(rec)) = resource_store::get(&store, ENG, &out_id) {
                        let required: BTreeSet<String> =
                            rec.stakeholders.iter().map(|a| a.as_str().to_string()).collect();
                        let before = store.fold::<ReviewState>(&review_scope).unwrap().phase;
                        admit_ok::<ReviewState>(
                            &mut store,
                            &review_scope,
                            ReviewCommand::Propose {
                                required: required.iter().map(|s| s.as_str().into()).collect(),
                            },
                        )?;
                        let after = store.fold::<ReviewState>(&review_scope).unwrap().phase;
                        if before == ReviewPhase::Init && after == ReviewPhase::Proposed {
                            review_required_ghost = Some(required);
                        }
                    }
                }
                Op::ExportConsent(i) => {
                    admit_ok::<ExportState>(
                        &mut store,
                        &export_scope,
                        ExportCommand::SourceConsent(AUTHORITIES[i].into()),
                    )?;
                }
                Op::ExportTargetAdmit => {
                    admit_ok::<ExportState>(&mut store, &export_scope, ExportCommand::TargetAdmit)?;
                }
                Op::ExportNow => {
                    admit_ok::<ExportState>(&mut store, &export_scope, ExportCommand::Export)?;
                }
                Op::ReviewConsent(i) => {
                    admit_ok::<ReviewState>(
                        &mut store,
                        &review_scope,
                        ReviewCommand::Consent(AUTHORITIES[i].into()),
                    )?;
                }
                Op::ReviewRelease => {
                    admit_ok::<ReviewState>(&mut store, &review_scope, ReviewCommand::Release)?;
                }
            }

            // ---- The standing cross-lifecycle invariants, checked after EVERY op.
            let export = store.fold::<ExportState>(&export_scope).unwrap();
            if export.phase == ExportPhase::Exported {
                let required = export_required_ghost
                    .as_ref()
                    .expect("an export crossed without a recorded proposal");
                // INV-13/INV-16: the requirement was the derived stakeholder set…
                let state_required: BTreeSet<String> = export
                    .source_required
                    .iter()
                    .map(|a| a.as_str().to_string())
                    .collect();
                prop_assert_eq!(&state_required, required);
                // …and INV-22/SOUND: every owner of the read history behind the
                // proposed output consented before the crossing.
                let consented: BTreeSet<String> = export
                    .source_consented
                    .iter()
                    .map(|a| a.as_str().to_string())
                    .collect();
                prop_assert!(
                    consented.is_superset(required),
                    "exported without full conjunctive consent: consented={consented:?} required={required:?}"
                );
            }
            let review = store.fold::<ReviewState>(&review_scope).unwrap();
            if review.phase == ReviewPhase::Released {
                let required = review_required_ghost
                    .as_ref()
                    .expect("a review released without a recorded proposal");
                let consented: BTreeSet<String> = review
                    .consented
                    .iter()
                    .map(|a| a.as_str().to_string())
                    .collect();
                prop_assert!(
                    consented.is_superset(required),
                    "released without full conjunctive consent: consented={consented:?} required={required:?}"
                );
            }
            // INV-10: the output handle resolves only via the persisted record;
            // a minted output always has its record present (handles never dangle).
            if minted {
                prop_assert!(resource_store::get(&store, ENG, &out_id).unwrap().is_some());
            }
        }
    }
}
