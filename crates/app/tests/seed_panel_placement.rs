//! `seed-panel-placement` exists so a suite outside this crate can reach the
//! publisher at all.
//!
//! Publishing needs a Panel-kind placement whose agent version carries a frozen
//! public profile. Authoring one is an agent-driven flow, every other release
//! subcommand takes a placement that already exists, and this repository's own
//! tests build the state in-process against library types — so an external
//! driver had no way in. gaugewright-cloud's composition test is what paid for
//! that: it drives the release binary against a fresh workbench, and every run
//! failed before the publisher read anything.
//!
//! These tests hold the seed to the three conditions the publisher actually
//! checks, and to the two it must refuse.

use gaugedesk_app::agent_release::PublishDeploymentRequest;
use gaugedesk_app::library::PanelPublicProfile;
use gaugedesk_app::{open_workbench, LockUnpoisoned};

fn profile_with_panels(components: &[&str]) -> PanelPublicProfile {
    let mut profile = PanelPublicProfile::default();
    profile.panels.components = components.iter().map(|name| (*name).to_owned()).collect();
    profile
}

fn publish_request(placement_id: &str) -> PublishDeploymentRequest {
    serde_json::from_value(serde_json::json!({
        "placement_id": placement_id,
        "deployment_id": "seedtest",
        // Unreachable on purpose: this asserts how far the publisher gets
        // before it needs a network, never that a deploy succeeds.
        "edge_origin": "http://127.0.0.1:1",
        "allowed_origins": ["https://customer.example"],
        "per_visitor_turn_limit": 5,
        "max_concurrent_sessions": 5,
        "funding_ref": "gaugedesk:managed-plan:v1:seed",
        "credential_ref": "",
        "audience": { "anonymous_allowed": true },
        "white_label": false,
        "retention_idle_ttl_seconds": 3_600,
        "retention_absolute_ttl_seconds": 86_400,
        "end_sessions": false,
    }))
    .expect("the request fixture matches the published contract")
}

/// The gap itself: a fresh workbench cannot be published from, and says so.
#[test]
fn a_fresh_workbench_has_no_placement_a_publish_can_name() {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    let error = workbench
        .lock_unpoisoned()
        .publish_agent_deployment(publish_request("inst-seeded"))
        .expect_err("an unseeded workbench has no Panel placement");
    assert!(
        error.to_string().contains("Panel-agent project placement"),
        "the refusal names what is missing: {error}"
    );
}

#[test]
fn the_seed_reports_the_ceiling_it_froze() {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    let panels = ["gw-chat", "gw-viewer", "gw-files", "gw-chats"];

    let seeded = workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-seeded", profile_with_panels(&panels))
        .expect("a fresh workbench can be seeded");

    assert_eq!(seeded["placement_id"], "inst-seeded");
    assert!(
        seeded["project_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "the placement is reported with an owning project: {seeded}"
    );
    // Sorted, because the manifest holds a set. The caller needs to know what
    // was frozen: this becomes the deployment's panel ceiling, and a publisher
    // that asked for four panels and got one would find out at the edge.
    assert_eq!(
        seeded["panels"],
        serde_json::json!(["gw-chat", "gw-chats", "gw-files", "gw-viewer"]),
    );
}

/// The point of the seed is to get *past* the placement gate. Proving that
/// needs the publisher to fail somewhere else — here, on a port nothing serves.
#[test]
fn a_seeded_workbench_reaches_the_publisher() {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-seeded", PanelPublicProfile::default())
        .unwrap();

    let error = workbench
        .lock_unpoisoned()
        .publish_agent_deployment(publish_request("inst-seeded"))
        .expect_err("the edge origin is deliberately unreachable");
    let message = error.to_string();
    for refusal in [
        "Panel-agent project placement",
        "panel placement has no owning project",
        "panel placement has no frozen public profile",
    ] {
        assert!(
            !message.contains(refusal),
            "the seed cleared this gate, so the failure must be elsewhere: {message}"
        );
    }
}

#[test]
fn seeding_never_overwrites_what_is_already_there() {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-seeded", PanelPublicProfile::default())
        .unwrap();

    let same_id = workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-seeded", PanelPublicProfile::default())
        .expect_err("a placement id in use is refused");
    assert!(
        same_id.to_string().contains("already exists"),
        "the refusal says why: {same_id}"
    );

    // The built-in Default placement is a work placement that every fresh
    // workbench already has. Seeding must not quietly convert it.
    let builtin = workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-placement-default", PanelPublicProfile::default())
        .expect_err("the built-in placement is refused");
    assert!(
        builtin.to_string().contains("already exists"),
        "the refusal says why: {builtin}"
    );

    // A second seed under its own id is fine: it builds its own archetype.
    workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-second", PanelPublicProfile::default())
        .expect("a distinct id seeds its own agent");
}

/// The frozen profile has to survive the workbench being closed and opened.
///
/// It did not. Opening a workbench reconciles every archetype version against
/// the bytes published in its authoring target, and the resolver that reads
/// those bytes cannot know an authored profile — so it answered `None`, the
/// reconciliation saw a difference, and it wrote the version back with the
/// profile removed. A validator on the same path compared the same way and
/// refused to open at all. Between them, a Panel agent could be published
/// exactly until something reopened the workbench.
#[test]
fn a_frozen_profile_survives_reopening_the_workbench() {
    let dir = tempfile::tempdir().unwrap();
    {
        let workbench = open_workbench(dir.path()).unwrap();
        workbench
            .lock_unpoisoned()
            .seed_panel_placement("inst-seeded", PanelPublicProfile::default())
            .unwrap();
    }

    // Reopening runs the reconciliation and the validation that used to strip
    // and then reject the profile. Opening at all is half the assertion.
    let reopened = open_workbench(dir.path()).expect("a seeded workbench reopens");
    let error = reopened
        .lock_unpoisoned()
        .publish_agent_deployment(publish_request("inst-seeded"))
        .expect_err("the edge origin is deliberately unreachable");
    assert!(
        !error
            .to_string()
            .contains("panel placement has no frozen public profile"),
        "the profile survived the reopen: {error}"
    );
}
