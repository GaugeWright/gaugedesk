use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};

use super::*;
use crate::library::{ProjectRecord, RecordOp, LIBRARY_RECORD_SCHEMA};

const INSTALL: &str = "install-root";

fn projection(root: Option<&str>, keeps_hand_overs: bool) -> Projection {
    Projection {
        root: root.map(str::to_owned),
        keeps_hand_overs,
    }
}

#[test]
fn what_a_computer_does_follows_what_it_holds_and_what_the_hub_names() {
    let publish = |mint, announce| RootStep::Publish { mint, announce };
    // The account's first computer mints, then announces.
    assert_eq!(
        plan(&projection(None, true), None, INSTALL, false),
        publish(true, Announce::Root)
    );
    assert_eq!(
        plan(&projection(None, true), Some("r"), INSTALL, false),
        publish(false, Announce::Root)
    );
    assert_eq!(
        plan(&projection(Some("r"), true), Some("r"), INSTALL, false),
        publish(false, Announce::Nothing)
    );
    // The claimant moves off the install key, which signs the hand-over.
    assert_eq!(
        plan(&projection(Some(INSTALL), true), None, INSTALL, true),
        publish(true, Announce::HandOverFromInstall)
    );
    assert_eq!(
        plan(&projection(Some(INSTALL), false), None, INSTALL, true),
        RootStep::HubPredatesHandOvers
    );
    // The install key is the claimant's to hand over, nobody else's.
    assert_eq!(
        plan(&projection(Some(INSTALL), true), None, INSTALL, false),
        RootStep::NeedsEnrollment
    );
    // Another computer holds the account's root, or replaced the one held here.
    assert_eq!(
        plan(&projection(Some("other"), true), None, INSTALL, false),
        RootStep::NeedsEnrollment
    );
    assert_eq!(
        plan(&projection(Some("other"), true), Some("r"), INSTALL, true),
        RootStep::NeedsEnrollment
    );
}

#[test]
fn a_hub_without_hand_overs_is_told_apart_by_its_projection() {
    let new = Projection::from_json(&json!({ "root_pubkey": "r", "transitions": [] }));
    assert_eq!(new, projection(Some("r"), true));
    let old = Projection::from_json(&json!({ "root_pubkey": "r" }));
    assert_eq!(old, projection(Some("r"), false));
    assert_eq!(
        Projection::from_json(&json!({ "root_pubkey": "" })).root,
        None
    );
}

/// The blind directory, one entry list per root, fenced per computer.
#[derive(Default)]
struct Directory {
    entries: BTreeMap<String, Vec<SignedDirectoryPut>>,
}

/// The Hub's account directory projection, keeping hand-overs as #1200 does.
#[derive(Default)]
struct Hub {
    root: Option<String>,
    transitions: Vec<RootTransition>,
}

#[derive(Clone, Default)]
struct World {
    directory: Arc<Mutex<Directory>>,
    hub: Arc<Mutex<Hub>>,
}

async fn list_entries(State(world): State<World>, Path(root): Path<String>) -> impl IntoResponse {
    let directory = world.directory.lock().unwrap();
    let mut latest: BTreeMap<String, &SignedDirectoryPut> = BTreeMap::new();
    for put in directory.entries.get(&root).into_iter().flatten() {
        latest.insert(put.entry.device.clone(), put);
    }
    let puts: Vec<String> = latest
        .values()
        .map(|put| serde_json::to_string(put).unwrap())
        .collect();
    Json(json!({ "version": 1, "puts": puts }))
}

async fn put_entry(
    State(world): State<World>,
    Path(root): Path<String>,
    Json(put): Json<SignedDirectoryPut>,
) -> impl IntoResponse {
    if !gaugedesk_directory_protocol::put_verifies(&put) || put.entry.directory.root_pubkey != root
    {
        return StatusCode::UNAUTHORIZED;
    }
    let mut directory = world.directory.lock().unwrap();
    let held = directory.entries.entry(root).or_default();
    let current = held
        .iter()
        .filter(|held| held.entry.device == put.entry.device)
        .map(|held| held.entry.generation)
        .max()
        .unwrap_or(0);
    if put.entry.generation != current + 1 {
        return StatusCode::CONFLICT;
    }
    held.push(put);
    StatusCode::NO_CONTENT
}

async fn get_projection(State(world): State<World>) -> axum::response::Response {
    let hub = world.hub.lock().unwrap();
    match &hub.root {
        Some(root) => Json(json!({
            "root_pubkey": root,
            "transitions": hub.transitions,
            "origin": "",
        }))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn post_challenge() -> Json<Value> {
    Json(json!({ "challenge": crate::root_publication::issue_challenge("acct").unwrap() }))
}

async fn post_projection(State(world): State<World>, Json(body): Json<Value>) -> StatusCode {
    let mut hub = world.hub.lock().unwrap();
    let root = body["root_pubkey"].as_str().unwrap().to_owned();
    // ADR 0133 §2: the root's own device proves the publication.
    let proof: crate::root_publication::PublicationProof =
        serde_json::from_value(body["proof"].clone()).expect("a publication carries a proof");
    if crate::root_publication::verify(&proof, "acct", &root, "", true, now_secs()).is_err() {
        return StatusCode::FORBIDDEN;
    }
    if let Some(transition) = body.get("transition") {
        let transition: RootTransition = serde_json::from_value(transition.clone()).unwrap();
        if !gaugedesk_directory_protocol::root_transition_verifies(&transition)
            || hub.root.as_deref() != Some(transition.from.as_str())
            || transition.to != root
        {
            return StatusCode::CONFLICT;
        }
        hub.transitions.push(transition);
    }
    hub.root = Some(root);
    StatusCode::OK
}

/// Serve the world on a thread of its own, since the publisher blocks.
fn serve(world: &World) -> String {
    let app = Router::new()
        .route("/directory/{root}/entries", get(list_entries))
        .route("/directory/{root}", axum::routing::put(put_entry))
        .route(
            "/account/directory",
            get(get_projection).post(post_projection),
        )
        .route(
            "/account/directory/challenge",
            axum::routing::post(post_challenge),
        )
        .with_state(world.clone());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let _ = axum::serve(listener, app).await;
            });
    });
    format!("http://{address}")
}

fn computer() -> (tempfile::TempDir, SharedWorkbench) {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    (root, wb)
}

fn owned_route(wb: &SharedWorkbench, project: &str, owner: &str) {
    let mut guard = wb.lock_unpoisoned();
    let home_id = guard.home_id().clone();
    guard.write_project_record(ProjectRecord {
        schema: LIBRARY_RECORD_SCHEMA,
        extra: serde_json::from_value(json!({ "owner": owner })).unwrap(),
        id: project.into(),
        op: RecordOp::Upsert,
        name: project.into(),
        is_default: false,
        home_id: home_id.clone(),
        network_isolated: false,
        run_purpose: None,
        deployment_mode: None,
    });
    let route = crate::account::HomeRouteRecord {
        id: project.into(),
        op: crate::account::RecordOp::Upsert,
        home_id,
        endpoint: format!("https://{project}.example"),
        relay: None,
        author_authority: String::new(),
        author_root_pubkey: String::new(),
        author_signature: None,
    };
    guard
        .write_account_record_in(crate::account::ACCOUNT_SCOPE, "home_route", project, &route)
        .unwrap();
}

#[test]
fn an_accounts_first_computer_mints_publishes_and_announces_and_withdraws_alone() {
    let world = World::default();
    let base = serve(&world);
    let (_root, wb) = computer();
    owned_route(&wb, "p-mine", "acct-a");
    owned_route(&wb, "p-theirs", "acct-b");

    let published = publish_from_here(&wb, "acct-a", &base, "bearer", &base).unwrap();
    let Published::Entry {
        root,
        generation,
        announced,
    } = published
    else {
        panic!("the first computer publishes: {published:?}");
    };
    assert_eq!((generation, announced), (1, true));
    assert_eq!(
        world.hub.lock().unwrap().root.as_deref(),
        Some(root.as_str())
    );
    let keys = wb
        .lock_unpoisoned()
        .account_key_store()
        .held("acct-a", now_secs())
        .unwrap()
        .unwrap();
    assert_eq!(keys.root.public_key().as_str(), root);
    assert_ne!(
        root,
        wb.lock_unpoisoned().governance_public_key().as_str(),
        "the account's root is its own, not the install's"
    );
    {
        let directory = world.directory.lock().unwrap();
        let entry = &directory.entries[&root][0].entry;
        assert_eq!(entry.device, device_name(&keys));
        let projects: Vec<_> = entry
            .directory
            .home_routes
            .iter()
            .map(|route| route.project.as_str())
            .collect();
        assert_eq!(projects, ["p-mine"], "only the account's own projects");
        // The project's own key places it, and this host's key locates it.
        let route = &entry.directory.home_routes[0];
        let placement = route
            .placement
            .as_ref()
            .expect("the route carries its placement");
        assert!(gaugedesk_directory_protocol::placement_verifies(
            route,
            &placement.project_key
        ));
        assert_eq!(
            placement.project_key,
            wb.lock_unpoisoned()
                .project_authority_identity("p-mine")
                .unwrap()
                .1
                .as_str()
        );
        assert!(
            crate::account::open_account_blob(keys.account_key, &entry.sealed_blob).is_some(),
            "the account's state is sealed under its own key"
        );
    }

    // Publishing again advances this computer's generation and announces nothing.
    assert_eq!(
        publish_from_here(&wb, "acct-a", &base, "bearer", &base).unwrap(),
        Published::Entry {
            root: root.clone(),
            generation: 2,
            announced: false
        }
    );

    // A second computer, with no keys, defers to the one that holds them.
    let (_other_root, other) = computer();
    assert_eq!(
        publish_from_here(&other, "acct-a", &base, "bearer", &base).unwrap(),
        Published::NeedsEnrollment
    );

    // Signing out withdraws this computer's entry, once.
    assert!(withdraw_from_here(&wb, "acct-a", &base).unwrap());
    assert!(!withdraw_from_here(&wb, "acct-a", &base).unwrap());
    // And signing in again publishes past the withdrawal.
    assert_eq!(
        publish_from_here(&wb, "acct-a", &base, "bearer", &base).unwrap(),
        Published::Entry {
            root,
            generation: 4,
            announced: false
        }
    );
}

#[test]
fn the_claimant_moves_off_the_install_key_under_a_hand_over_it_signs() {
    let world = World::default();
    let base = serve(&world);
    let (_root, wb) = computer();
    let install = wb
        .lock_unpoisoned()
        .governance_public_key()
        .as_str()
        .to_owned();
    world.hub.lock().unwrap().root = Some(install.clone());
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            crate::account::ACCOUNT_SCOPE,
            crate::project_owner::INSTALL_SCOPE_OWNER_KIND,
            &json!({ "account": "acct-claimant" }).to_string(),
        )
        .unwrap();

    // Another account on the same computer cannot move the claimant's root.
    assert_eq!(
        publish_from_here(&wb, "acct-other", &base, "bearer", &base).unwrap(),
        Published::NeedsEnrollment
    );

    let Published::Entry {
        root, announced, ..
    } = publish_from_here(&wb, "acct-claimant", &base, "bearer", &base).unwrap()
    else {
        panic!("the claimant publishes under fresh keys");
    };
    assert!(announced);
    let hub = world.hub.lock().unwrap();
    assert_eq!(hub.root.as_deref(), Some(root.as_str()));
    assert!(gaugedesk_directory_protocol::root_chain_reaches(
        &install,
        &root,
        &hub.transitions
    ));
}

#[test]
fn the_account_surfaces_see_what_publishing_last_managed() {
    let (_root, wb) = computer();
    assert_eq!(reach_of(&wb, "acct-a"), None, "nothing tried yet");
    record_reach(&wb, "acct-a", &Ok(Published::NeedsEnrollment));
    assert_eq!(reach_of(&wb, "acct-a"), Some(Reach::NeedsApproval));
    record_reach(&wb, "acct-a", &Err("refused".into()));
    assert_eq!(reach_of(&wb, "acct-a"), Some(Reach::Failed));
    record_reach(
        &wb,
        "acct-a",
        &Ok(Published::Entry {
            root: "r".into(),
            generation: 1,
            announced: true,
        }),
    );
    assert_eq!(reach_of(&wb, "acct-a"), Some(Reach::Published));
    assert_eq!(reach_of(&wb, "acct-b"), None, "per account");
    assert_eq!(
        serde_json::to_value(Reach::NeedsApproval).unwrap(),
        "needs_approval"
    );
}

#[test]
fn a_members_entry_vouches_for_the_shared_project_its_pin_names() {
    use gaugedesk_core::signature::SigningKey;
    let world = World::default();
    let base = serve(&world);

    // The owner's computer publishes the project's route, placed by the
    // project's own key, under the owner's root.
    let (owner_root, project_key, host) = (
        SigningKey::from_seed(&[31; 32]).unwrap(),
        SigningKey::from_seed(&[32; 32]).unwrap(),
        SigningKey::from_seed(&[33; 32]).unwrap(),
    );
    let placed = gaugedesk_directory_protocol::sign_placement(
        crate::home::OpaqueHomeRoute {
            project: "p-shared".into(),
            home_id: gaugedesk_core::ids::HomeId::new("home:owner"),
            endpoint: "https://owner.example".into(),
            relay: None,
            author_authority: String::new(),
            author_root_pubkey: String::new(),
            author_signature: None,
            placement: None,
        },
        &project_key,
        &host,
    )
    .unwrap();
    let mut owner_entry =
        gaugedesk_directory_protocol::retraction_entry(owner_root.public_key().as_str().into(), 1);
    owner_entry.retracted = false;
    owner_entry.directory.home_routes = vec![placed];
    owner_entry.device = "owner-laptop".into();
    let owner_put = gaugedesk_directory_protocol::sign_entry(owner_entry, &owner_root).unwrap();
    world
        .directory
        .lock()
        .unwrap()
        .entries
        .insert(owner_root.public_key().as_str().into(), vec![owner_put]);

    // The member accepted the invitation here and keeps its pin.
    let (_root, wb) = computer();
    wb.lock_unpoisoned()
        .keep_shared_project_pin(
            "acct-member",
            &crate::shared_project_pins::SharedProjectPin {
                id: "p-shared".into(),
                home_id: "home:owner".into(),
                project_key: project_key.public_key().as_str().into(),
                owner_root: owner_root.public_key().as_str().into(),
            },
        )
        .unwrap();
    let Published::Entry { root, .. } =
        publish_from_here(&wb, "acct-member", &base, "bearer", &base).unwrap()
    else {
        panic!("the member's computer publishes");
    };
    let directory = world.directory.lock().unwrap();
    let routes = &directory.entries[&root][0].entry.directory.home_routes;
    assert_eq!(routes.len(), 1, "the shared project's route, vouched for");
    assert!(gaugedesk_directory_protocol::placement_verifies(
        &routes[0],
        project_key.public_key().as_str()
    ));
}
