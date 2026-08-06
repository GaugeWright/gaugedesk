//! RF-E2 — two local authorities share one project; neither can unilaterally
//! release. A deterministic end-to-end scenario (the narrative complement to the
//! RF-C4 protection-chain proptest) that exercises **conjunctive consent for
//! real** — not the single-user collapse where the lone authority both requires
//! and grants, making consent vacuous.
//!
//! The shape (the "two-local-authorities" collapse of the M2 multi-authority
//! flow, on one machine, no remote substrate): an `expert` authority contributes
//! a method resource and a `client` authority contributes a context resource into
//! one engagement scope. A run reads both, so the minted output is tainted by
//! BOTH owners (engagement-scoped taint, ADR 0026). Releasing that output —
//! whether by review (declassification, INV-16) or export across the edge
//! (INV-13) — then requires the conjunctive consent of *both* stakeholders: each
//! authority alone is insufficient, and only once both have consented does the
//! output clear. This is the protection property the product sells, demonstrated
//! with two distinct authorities rather than a vacuous single-user grant.

use std::collections::BTreeSet;

use gaugedesk_app::resource_store;
use gaugedesk_core::resource::{ContentLocator, Resource, ResourceKind, ResourceRecord};
use gaugedesk_core::resource_export::{ExportCommand, ExportPhase, ExportState};
use gaugedesk_core::review::{ReviewCommand, ReviewPhase, ReviewState};
use gaugedesk_store::Store;

const ENG: &str = "shared-project-chat";
const EXPERT: &str = "expert";
const CLIENT: &str = "client";

/// Put a granted context resource owned by `owner` into the engagement and
/// register it as read this turn (so it taints the output).
fn contribute_context(store: &mut Store, owner: &str, path: &str) {
    // mint_context auto-grants for its owner (trust-by-default within the owner's
    // own authority); here each authority contributes its own resource.
    resource_store::mint_context(store, ENG, owner, path, "c0").unwrap();
    let id = resource_store::context_id(path);
    resource_store::record_reads(store, ENG, &[id]).unwrap();
}

/// Build the two-authority output: expert's method + client's context both read,
/// so the output's stakeholders are {expert, client}. Returns that stakeholder set.
fn mint_two_authority_output(store: &mut Store) -> BTreeSet<String> {
    // expert's method resource (owned by expert), read this turn.
    let method_id = gaugedesk_core::resource::ResourceId::new("method::expert-skill".to_string());
    let method = ResourceRecord::new(
        Resource::input(method_id.clone(), ResourceKind::method(), EXPERT.into()),
        ContentLocator::Workspace {
            path: ".pi/SYSTEM.md".into(),
            commit: "c0".into(),
        },
        |_| EXPERT.into(),
    );
    resource_store::put(store, ENG, &method).unwrap();
    resource_store::record_reads(store, ENG, &[method_id]).unwrap();

    // client's context resource (owned by client), read this turn.
    contribute_context(store, CLIENT, "/client/private-data");

    let out = resource_store::mint_output(store, ENG, EXPERT, "c1").unwrap();
    out.stakeholders
        .iter()
        .map(|a| a.as_str().to_string())
        .collect()
}

#[test]
fn an_output_from_two_authorities_is_tainted_by_both() {
    let mut store = Store::open_in_memory().unwrap();
    let stakeholders = mint_two_authority_output(&mut store);
    assert!(
        stakeholders.contains(EXPERT) && stakeholders.contains(CLIENT),
        "the output is tainted by BOTH contributing authorities: {stakeholders:?}"
    );
}

#[test]
fn neither_authority_can_export_the_shared_output_alone() {
    let mut store = Store::open_in_memory().unwrap();
    let stakeholders = mint_two_authority_output(&mut store);
    let out_id = resource_store::output_id(ENG);
    let scope = resource_store::export_scope(ENG, &out_id);

    // Propose export with the derived (two-authority) required set.
    store
        .admit::<ExportState>(
            &scope,
            ExportCommand::ProposeExport {
                source_required: stakeholders.iter().map(|s| s.as_str().into()).collect(),
            },
        )
        .unwrap();

    // The expert consents and the target admits — but the CLIENT has not, so the
    // export does NOT cross. A single authority cannot release shared content.
    store
        .admit::<ExportState>(&scope, ExportCommand::SourceConsent(EXPERT.into()))
        .unwrap();
    store
        .admit::<ExportState>(&scope, ExportCommand::TargetAdmit)
        .unwrap();
    let s = store
        .admit::<ExportState>(&scope, ExportCommand::Export)
        .unwrap_or_else(|_| store.fold::<ExportState>(&scope).unwrap());
    assert_ne!(
        s.phase,
        ExportPhase::Exported,
        "expert-only consent must NOT export the client's tainted output"
    );

    // Now the client consents too — conjunctive consent is satisfied; it crosses.
    store
        .admit::<ExportState>(&scope, ExportCommand::SourceConsent(CLIENT.into()))
        .unwrap();
    let s = store
        .admit::<ExportState>(&scope, ExportCommand::Export)
        .unwrap();
    assert_eq!(
        s.phase,
        ExportPhase::Exported,
        "only with BOTH authorities' consent does the shared output cross"
    );
}

#[test]
fn review_release_of_the_shared_output_needs_both_authorities() {
    let mut store = Store::open_in_memory().unwrap();
    let stakeholders = mint_two_authority_output(&mut store);
    let out_id = resource_store::output_id(ENG);
    let scope = resource_store::review_scope(ENG, &out_id);

    store
        .admit::<ReviewState>(
            &scope,
            ReviewCommand::Propose {
                required: stakeholders.iter().map(|s| s.as_str().into()).collect(),
            },
        )
        .unwrap();

    // client-only consent: not enough to declassify.
    store
        .admit::<ReviewState>(&scope, ReviewCommand::Consent(CLIENT.into()))
        .unwrap();
    let s = store
        .admit::<ReviewState>(&scope, ReviewCommand::Release)
        .unwrap_or_else(|_| store.fold::<ReviewState>(&scope).unwrap());
    assert_ne!(
        s.phase,
        ReviewPhase::Released,
        "client-only consent must NOT release the expert's method-tainted output"
    );

    // expert consents too → released.
    store
        .admit::<ReviewState>(&scope, ReviewCommand::Consent(EXPERT.into()))
        .unwrap();
    let s = store
        .admit::<ReviewState>(&scope, ReviewCommand::Release)
        .unwrap();
    assert_eq!(
        s.phase,
        ReviewPhase::Released,
        "declassification needs the conjunctive consent of both authorities"
    );
}
