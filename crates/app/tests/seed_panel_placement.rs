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

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use gaugedesk_app::agent_release::{PublishDeploymentRequest, StartPanelPreviewRequest};
use gaugedesk_app::library::{
    DeploymentBindingStatus, InstanceRecord, PanelCollectionRecipient, PanelPublicProfile,
    PublicDeploymentBindingRecord, LIBRARY_SCOPE,
};
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
        "funding_ref": "credential:public:seedtest:openai:key",
        "credential_ref": "credential:public:seedtest:openai:key",
        "audience": { "anonymous_allowed": true },
        "white_label": false,
        "retention_idle_ttl_seconds": 3_600,
        "retention_absolute_ttl_seconds": 86_400,
        "end_sessions": false,
    }))
    .expect("the request fixture matches the published contract")
}

#[derive(Default)]
struct PublisherEdgeState {
    config: Option<serde_json::Value>,
    active_release: Option<String>,
    reject_update: bool,
    mutation_bodies: Vec<serde_json::Value>,
}

/// A publisher-protocol stand-in that admits one initial deployment and can
/// subsequently reject an update. It records the exact mutation bodies so the
/// client-side contract is tested at the HTTP seam, not by re-serializing the
/// same Rust structure in an assertion.
fn publisher_edge() -> (String, Arc<Mutex<PublisherEdgeState>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(PublisherEdgeState::default()));
    let shared = Arc::clone(&state);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default();
            let path = parts.next().unwrap_or_default();
            let mut length = 0_usize;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header.trim().is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or_default();
                }
            }
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).unwrap();
            let body = serde_json::from_slice::<serde_json::Value>(&bytes).ok();

            let (status, response) = {
                let mut state = shared.lock().unwrap();
                if method == "GET"
                    && path.starts_with("/v1/deployments/")
                    && !path.ends_with("/control")
                {
                    match (&state.config, &state.active_release) {
                        (Some(config), Some(release)) => (
                            200,
                            serde_json::json!({
                                "deployment": {
                                    "config": config,
                                    "active_release_id": release,
                                    "lifecycle": "active",
                                    "activation_revision": 1,
                                    "spent_cents": 0,
                                    "reserved_cents": 0,
                                    "sessions": 0,
                                    "settled_turns": 0
                                },
                                "audience": []
                            }),
                        ),
                        _ => (404, serde_json::json!({ "error": "not found" })),
                    }
                } else if method == "PUT" && path.starts_with("/v1/releases/") {
                    (200, serde_json::json!({ "stored": true }))
                } else if (method == "PUT" || method == "POST")
                    && path.starts_with("/v1/deployments/")
                {
                    if let Some(body) = body {
                        state.mutation_bodies.push(body.clone());
                        if state.reject_update && state.active_release.is_some() {
                            (
                                409,
                                serde_json::json!({ "error": "synthetic update rejection" }),
                            )
                        } else {
                            if method == "PUT" {
                                state.config = body.get("config").cloned();
                                state.active_release = body
                                    .get("initial_release_id")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned);
                            } else {
                                state.active_release = body
                                    .get("release_id")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned);
                            }
                            (
                                200,
                                serde_json::json!({ "deployment": { "lifecycle": "active" } }),
                            )
                        }
                    } else {
                        (400, serde_json::json!({ "error": "missing body" }))
                    }
                } else {
                    (
                        404,
                        serde_json::json!({ "error": "unknown synthetic route" }),
                    )
                }
            };
            let response = serde_json::to_vec(&response).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(&response).unwrap();
        }
    });
    (origin, state)
}

fn deployment_records(
    workbench: &gaugedesk_app::SharedWorkbench,
) -> Vec<PublicDeploymentBindingRecord> {
    workbench
        .lock_unpoisoned()
        .store_ref()
        .records(LIBRARY_SCOPE, "public_deployment_binding")
        .unwrap()
        .into_iter()
        .map(|row| serde_json::from_str(&row).unwrap())
        .collect()
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
fn a_rejected_update_preserves_the_active_binding_and_operational_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-seeded", PanelPublicProfile::default())
        .unwrap();
    let (edge, state) = publisher_edge();
    let mut initial = publish_request("inst-seeded");
    initial.edge_origin = edge.clone();
    let admitted = workbench
        .lock_unpoisoned()
        .publish_agent_deployment(initial)
        .expect("the synthetic edge admits the first publication");

    state.lock().unwrap().reject_update = true;
    let mut update = publish_request("inst-seeded");
    update.edge_origin = edge;
    update.allowed_origins = vec!["https://changed.example".to_owned()];
    let error = workbench
        .lock_unpoisoned()
        .publish_agent_deployment(update)
        .expect_err("the synthetic edge rejects the update");
    assert!(error.to_string().contains("synthetic update rejection"));

    let records = deployment_records(&workbench);
    let latest = records
        .last()
        .expect("the first publication made a binding");
    assert_eq!(latest.status, DeploymentBindingStatus::Active);
    assert_eq!(
        latest.active_release_id.as_deref(),
        Some(admitted.release_id.as_str())
    );
    assert_eq!(
        latest.operational.allowed_origins,
        vec!["https://customer.example"],
        "the rejected operational snapshot was never made authoritative",
    );
    assert_eq!(
        records.len(),
        2,
        "only pending + active records from the successful first publication exist",
    );
}

#[test]
fn the_session_cutover_instruction_reaches_both_edge_mutation_shapes() {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-seeded", PanelPublicProfile::default())
        .unwrap();
    let (edge, state) = publisher_edge();
    let mut initial = publish_request("inst-seeded");
    initial.edge_origin = edge.clone();
    initial.end_sessions = true;
    workbench
        .lock_unpoisoned()
        .publish_agent_deployment(initial)
        .unwrap();

    let mut same_config = publish_request("inst-seeded");
    same_config.edge_origin = edge.clone();
    same_config.end_sessions = true;
    workbench
        .lock_unpoisoned()
        .publish_agent_deployment(same_config)
        .unwrap();

    let mut changed_config = publish_request("inst-seeded");
    changed_config.edge_origin = edge;
    changed_config.allowed_origins = vec!["https://second.example".to_owned()];
    changed_config.end_sessions = true;
    workbench
        .lock_unpoisoned()
        .publish_agent_deployment(changed_config)
        .unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.mutation_bodies.len(), 3);
    assert_eq!(
        state.mutation_bodies[0]["config"]["deployment_id"],
        "seedtest"
    );
    assert_eq!(
        state.mutation_bodies[1]["end_sessions"], true,
        "same-config activation carries the explicit session instruction",
    );
    assert_eq!(
        state.mutation_bodies[2]["end_sessions"], true,
        "configuration replacement carries the explicit session instruction",
    );
}

#[test]
fn a_hub_signed_managed_entitlement_is_carried_to_the_edge_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    let route = gaugedesk_app::managed_inference::metered_route("gpt-5.6-terra");
    let mut profile = PanelPublicProfile::default();
    profile.provider.provider =
        gaugedesk_app::managed_inference::METERED_GATEWAY_PROVIDER.to_owned();
    profile.provider.model = route.model;
    profile.provider.base_url = route.base_url;
    profile.provider.credential_class = "managed-openai".to_owned();
    workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-seeded", profile)
        .unwrap();
    let publisher = workbench.lock_unpoisoned().public_publisher_key().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = gaugedesk_app::managed_entitlement::build_claims(
        "tenant:synthetic",
        "canary",
        &publisher,
        now,
    );
    let hub_key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let entitlement: gaugedesk_app::managed_entitlement::Entitlement =
        serde_json::from_str(&gaugedesk_app::managed_entitlement::sign(&hub_key, &claims).unwrap())
            .unwrap();
    let (edge, state) = publisher_edge();
    let mut request = publish_request("inst-seeded");
    request.edge_origin = edge;
    request.funding_ref =
        gaugedesk_app::managed_inference::funding_ref_for(&claims.scope, &claims.plan);
    request.credential_ref.clear();
    request.managed_tenant_id = Some("tenant:synthetic".to_owned());
    request.funding_entitlement = Some(entitlement.clone());
    workbench
        .lock_unpoisoned()
        .publish_agent_deployment(request)
        .unwrap();

    let state = state.lock().unwrap();
    let carried = state.mutation_bodies[0]["config"]["funding_entitlement"]
        .as_str()
        .expect("managed configuration carries the signed entitlement");
    assert_eq!(
        serde_json::from_str::<gaugedesk_app::managed_entitlement::Entitlement>(carried).unwrap(),
        entitlement,
    );
    assert_eq!(
        state.mutation_bodies[0]["config"]["credential_ref"], "",
        "managed funding never smuggles an owner provider credential",
    );
}

#[test]
fn an_unchanged_managed_release_update_reuses_the_admitted_funding_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    let route = gaugedesk_app::managed_inference::metered_route("gpt-5.6-terra");
    let mut profile = PanelPublicProfile::default();
    profile.provider.provider =
        gaugedesk_app::managed_inference::METERED_GATEWAY_PROVIDER.to_owned();
    profile.provider.model = route.model;
    profile.provider.base_url = route.base_url;
    profile.provider.credential_class = "managed-openai".to_owned();
    workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-seeded", profile)
        .unwrap();
    let publisher = workbench.lock_unpoisoned().public_publisher_key().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = gaugedesk_app::managed_entitlement::build_claims(
        "tenant:synthetic",
        "canary",
        &publisher,
        now,
    );
    let hub_key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let entitlement: gaugedesk_app::managed_entitlement::Entitlement =
        serde_json::from_str(&gaugedesk_app::managed_entitlement::sign(&hub_key, &claims).unwrap())
            .unwrap();
    let (edge, state) = publisher_edge();
    let mut initial = publish_request("inst-seeded");
    initial.edge_origin = edge.clone();
    initial.funding_ref =
        gaugedesk_app::managed_inference::funding_ref_for(&claims.scope, &claims.plan);
    initial.credential_ref.clear();
    initial.managed_tenant_id = Some("tenant:synthetic".to_owned());
    initial.funding_entitlement = Some(entitlement);
    workbench
        .lock_unpoisoned()
        .publish_agent_deployment(initial)
        .expect("the first publication admits the managed funding snapshot");

    let mut update = publish_request("inst-seeded");
    update.edge_origin = edge;
    update.funding_ref =
        gaugedesk_app::managed_inference::funding_ref_for(&claims.scope, &claims.plan);
    update.credential_ref.clear();
    let outcome = workbench
        .lock_unpoisoned()
        .publish_agent_deployment(update)
        .expect("an exact release update reuses unchanged admitted funding");

    let state = state.lock().unwrap();
    assert_eq!(state.mutation_bodies.len(), 2);
    assert_eq!(
        state.mutation_bodies[1]["release_id"], outcome.release_id,
        "the update activates the exact newly signed release",
    );
    assert!(
        state.mutation_bodies[1].get("config").is_none(),
        "unchanged admitted funding is never resubmitted without an entitlement",
    );
    let records = deployment_records(&workbench);
    assert_eq!(
        records.last().unwrap().active_release_id.as_deref(),
        Some(outcome.release_id.as_str()),
        "the local binding advances only after hosted activation",
    );
}

#[test]
fn a_disposable_preview_uses_the_public_edge_without_creating_a_project_binding() {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    workbench
        .lock_unpoisoned()
        .seed_panel_placement("inst-seeded", PanelPublicProfile::default())
        .unwrap();
    let (edge, state) = publisher_edge();
    let request: StartPanelPreviewRequest = serde_json::from_value(serde_json::json!({
        "agent_id": "inst-seeded-agent",
        "edge_origin": edge,
        "allowed_origin": "https://desk.example",
        "funding_ref": "credential:public:preview:openai:key",
        "credential_ref": "credential:public:preview:openai:key"
    }))
    .unwrap();
    let outcome = workbench
        .lock_unpoisoned()
        .start_panel_preview(request)
        .expect("the draft publishes to a bounded disposable deployment");
    assert!(outcome.deployment_id.starts_with("panel-preview-"));
    assert!(deployment_records(&workbench).is_empty());

    {
        let state = state.lock().unwrap();
        let config = &state.mutation_bodies[0]["config"];
        assert_eq!(config["max_concurrent_sessions"], 1);
        assert_eq!(
            config["allowed_origins"],
            serde_json::json!(["https://desk.example"])
        );
        assert!(config["preview_expires_at_unix_ms"].as_u64().is_some());
        assert!(config.get("collection").is_none());
    }

    workbench
        .lock_unpoisoned()
        .stop_panel_preview(&outcome.preview_id)
        .expect("closing Preview revokes its hosted deployment");
    let second_stop = workbench
        .lock_unpoisoned()
        .stop_panel_preview(&outcome.preview_id)
        .expect_err("the in-memory handle was retired");
    assert_eq!(second_stop.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(
        state.lock().unwrap().mutation_bodies[1]["command"],
        "revoke"
    );
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

#[test]
fn collecting_seed_binds_the_recipient_only_to_the_project_placement() {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    let profile = PanelPublicProfile {
        collection: Some(gaugedesk_core::agent_release::CollectionPolicy {
            exportable_paths: Vec::new(),
            transcript_eligible: true,
            schema_ref: "composition.collection.v1".to_owned(),
            recipient_class: "collection:tenant".to_owned(),
            max_artifact_bytes: 1_000_000,
        }),
        ..PanelPublicProfile::default()
    };
    workbench
        .lock_unpoisoned()
        .seed_panel_placement_with_recipient(
            "inst-collecting",
            profile,
            Some(PanelCollectionRecipient {
                recipient_ref: "project-panel".to_owned(),
                recipient_public_keys: vec!["04aa".to_owned()],
            }),
        )
        .unwrap();

    let guard = workbench.lock_unpoisoned();
    let instances = guard
        .store_ref()
        .records(LIBRARY_SCOPE, "instance")
        .unwrap()
        .into_iter()
        .filter_map(|row| serde_json::from_str::<InstanceRecord>(&row).ok())
        .collect::<Vec<_>>();
    let placement = instances
        .iter()
        .rfind(|instance| instance.id == "inst-collecting")
        .unwrap();
    assert_eq!(
        placement
            .collection_recipient
            .as_ref()
            .unwrap()
            .recipient_ref,
        "project-panel"
    );
    assert!(instances
        .iter()
        .rfind(|instance| instance.id == "inst-collecting-agent-authoring")
        .unwrap()
        .collection_recipient
        .is_none());
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
