//! The GaugeWright package manifest is real and registrable (ADR 0113, ASK-1).
//!
//! This is the first GaugeWright-owned artifact in WhippleScript's manifest
//! format. A manifest that parses as JSON but which the runtime refuses would
//! surface as a capability that silently never admits anything — so it is
//! registered here against a real store rather than merely deserialized.

use gaugewright_app::agent_question::{GAUGEWRIGHT_PACKAGE_MANIFEST, QUESTION_ASK_CAPABILITY};
use whipplescript_store::SqliteStore;

#[test]
fn the_manifest_registers_into_a_real_store() {
    let store = SqliteStore::open_in_memory().expect("opens");
    store
        .register_package_manifest(GAUGEWRIGHT_PACKAGE_MANIFEST)
        .expect("the GaugeWright manifest registers");
    // Idempotent, like the std set: registering on every open must not accumulate.
    store
        .register_package_manifest(GAUGEWRIGHT_PACKAGE_MANIFEST)
        .expect("re-registers");
}

#[test]
fn it_declares_the_ask_capability_and_a_provider_behind_it() {
    let manifest: serde_json::Value =
        serde_json::from_str(GAUGEWRIGHT_PACKAGE_MANIFEST).expect("parses");
    assert!(
        manifest["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == QUESTION_ASK_CAPABILITY),
        "the capability is what admits the tool; without it the ceiling has nothing to grant",
    );
    assert!(
        manifest["providers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["capability"] == QUESTION_ASK_CAPABILITY),
        "a capability with no provider admits an effect nothing can execute",
    );
}

#[test]
fn the_binding_report_names_the_channel_and_the_party() {
    // The two things `askHuman` left implicit (DR-0050). A report that said
    // outbound-only or anonymous would describe a channel that cannot carry an
    // answer back to an attributable person.
    let manifest: serde_json::Value =
        serde_json::from_str(GAUGEWRIGHT_PACKAGE_MANIFEST).expect("parses");
    let report = &manifest["bindings"][0]["config"]["report"];
    assert_eq!(report["direction"], "bidirectional");
    assert_eq!(report["identity"], "authenticated_actor");
}
