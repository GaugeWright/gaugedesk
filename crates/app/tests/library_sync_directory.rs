//! A device and one blind directory
//! ([ADR 0154](../../../specs/decisions/0154-the-signed-directory-record-is-a-snapshot-of-the-routes-it-owns.md)).
//!
//! The record is a **snapshot** of the routes it owns, so a publish overwrites
//! rather than appends, and the generation fence makes each overwrite durable.
//! That makes §6 — a publish reads the head it is about to overwrite —
//! load-bearing rather than tidy, and §2's absence-retracts the same. Both were
//! tested a device at a time against a hand-built record; their behaviour
//! against a real directory rested on an argument about the fence.
//!
//! **Only the root-holding device publishes.** An enrolled device recovers the
//! account *sealing* key — wrapped under its own device seed at
//! `<root>/account/account-key.sealed` — and never the root signing seed, so it
//! cannot sign a record. The interesting case is therefore not two publishers
//! racing; it is **one publisher whose local view is poorer than the
//! directory's**, which is what a reinstall or a restored backup looks like.
//! Publishing blind there would erase the account's live routing.
//!
//! So the fixture is the honest one: a record the account root already signed,
//! carrying a route to a Home this device does not serve — exactly the class
//! §2 makes the record authority for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use gaugedesk_app::directory_sync::SignedDirectoryPut;
use gaugedesk_app::{open_control_plane, Workbench};
use gaugedesk_core::ids::AuthorityId;
use gaugedesk_store::Store;

/// The blind directory, as much of it as this behaviour depends on: it stores
/// the record opaquely, admits only a put that advances the generation by
/// exactly one, and serves the **whole signed put** back so a reader can verify
/// it. It never opens the blob and never inspects a route.
type Held = Arc<Mutex<HashMap<String, SignedDirectoryPut>>>;

async fn get_directory(
    State(held): State<Held>,
    Path(root): Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match held.lock().unwrap().get(&root).cloned() {
        // A retracted latest entry folds to `410 Gone` (ADR 0153), body included.
        Some(put) if put.entry.retracted => {
            (StatusCode::GONE, Json(serde_json::to_value(&put).unwrap())).into_response()
        }
        Some(put) => (StatusCode::OK, Json(serde_json::to_value(&put).unwrap())).into_response(),
        None => (StatusCode::NOT_FOUND, "no record").into_response(),
    }
}

async fn put_directory(
    State(held): State<Held>,
    Path(root): Path<String>,
    Json(put): Json<SignedDirectoryPut>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !gaugedesk_app::directory_sync::put_verifies(&put) || put.entry.directory.root_pubkey != root
    {
        return (
            StatusCode::FORBIDDEN,
            "signature does not hold for this root",
        )
            .into_response();
    }
    let mut guard = held.lock().unwrap();
    let expected = guard.get(&root).map_or(1, |held| held.entry.generation + 1);
    if put.entry.generation != expected {
        // The fence: a publisher that read a stale head is refused and must
        // re-read, which is what keeps a snapshot overwrite ordered.
        return (
            StatusCode::CONFLICT,
            "generation must advance by exactly one",
        )
            .into_response();
    }
    guard.insert(root, put);
    (StatusCode::OK, "stored").into_response()
}

/// One stub for the whole binary, because the directory origin is resolved from
/// a process-wide environment variable and tests in one binary share a process.
fn directory() -> Held {
    static DIRECTORY: OnceLock<Held> = OnceLock::new();
    DIRECTORY
        .get_or_init(|| {
            let held: Held = Arc::new(Mutex::new(HashMap::new()));
            let app = Router::new()
                .route("/directory/{root}", get(get_directory).put(put_directory))
                .with_state(Arc::clone(&held));
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind directory");
            let address = listener.local_addr().expect("directory address");
            listener.set_nonblocking(true).expect("nonblocking");
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("directory runtime");
                runtime.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).expect("adopt");
                    let _ = axum::serve(listener, app).await;
                });
            });
            std::env::set_var("GAUGEDESK_DIRECTORY_URL", format!("http://{address}"));
            held
        })
        .clone()
}

/// A device of the account rooted at `keys`: same authority, same root key, so
/// the same directory identity and the same account key.
fn device(keys: Option<&std::path::Path>) -> (Router, Arc<Mutex<Workbench>>, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    if let Some(source) = keys {
        std::fs::create_dir_all(root.path().join("keys")).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(
                entry.path(),
                root.path().join("keys").join(entry.file_name()),
            )
            .unwrap();
        }
    }
    let wb = Workbench::new(Store::open_in_memory().unwrap())
        .with_authority(AuthorityId::new("person"))
        .with_root(root.path());
    let shared = Arc::new(Mutex::new(wb));
    (open_control_plane(shared.clone()), shared, root)
}

async fn post(app: &Router, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    // A mutating route is idempotency-keyed (ADR 0137 §3). Each call composes
    // its own key, because these are distinct acts rather than one resent act.
    static NEXT_KEY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let key = NEXT_KEY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("Idempotency-Key", format!("test-{key}"));
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned())),
    )
}

async fn enable_library_sync(app: &Router) {
    let (status, body) = post(
        app,
        "/account/facilities",
        Some(
            json!({ "id": "library-sync", "kind": "library_sync", "display_name": "Library sync" }),
        ),
    )
    .await;
    assert!(status.is_success(), "facility must attach: {body}");
}

fn seed_project(wb: &Arc<Mutex<Workbench>>, project: &str) {
    let mut guard = wb.lock().unwrap();
    let home = guard.home_id().as_str().to_owned();
    guard
        .store_mut()
        .append_record(
            "library",
            "project",
            &json!({
                "id": project, "op": "upsert", "name": project,
                "is_default": false, "home_id": home, "network_isolated": false
            })
            .to_string(),
        )
        .unwrap();
    guard.rebuild_library();
}

/// Author this device's routes for the projects it serves, the way the
/// reachability reconcile does at startup.
fn author_routes(wb: &Arc<Mutex<Workbench>>, endpoint: &str) {
    let reach = gaugedesk_app::home_reachability::HomeReachability {
        endpoint: endpoint.to_owned(),
        relay: None,
    };
    assert!(
        wb.lock().unwrap().author_home_routes(&reach) > 0,
        "the serving Home must author a route for the project it holds"
    );
}

fn published_routes(held: &Held, root: &str) -> Vec<(String, String)> {
    let guard = held.lock().unwrap();
    let mut routes: Vec<(String, String)> = guard
        .get(root)
        .expect("the directory holds a record for this root")
        .entry
        .directory
        .home_routes
        .iter()
        .map(|route| (route.project.clone(), route.home_id.as_str().to_owned()))
        .collect();
    routes.sort();
    routes
}

/// Sign a record under the account root this device holds, and publish it as the
/// directory's current head. This is the account's own prior publish — the state
/// a reinstalled device wakes up to.
fn seed_published_record(
    held: &Held,
    keys: &std::path::Path,
    authority: &str,
    generation: u64,
    routes: Vec<gaugedesk_app::home::OpaqueHomeRoute>,
) -> String {
    // The key store hex-namespaces the authority and suffixes `.key`.
    let seed = std::fs::read(keys.join(format!("{}.key", hex::encode(authority))))
        .expect("the device's root seed");
    let signing = gaugedesk_core::signature::SigningKey::from_seed(
        &<[u8; 32]>::try_from(seed.as_slice()).expect("a 32-byte seed"),
    )
    .expect("a valid root key");
    let root = signing.public_key().as_str().to_owned();
    let entry = gaugedesk_app::directory_sync::DirectoryEntry {
        generation,
        directory: gaugedesk_directory_protocol::DirectoryRecord {
            root_pubkey: root.clone(),
            device_pubkeys: Vec::new(),
            placement_pointers: Vec::new(),
            home_routes: routes,
        },
        // Opaque to the directory, which never opens it — but a reader does,
        // under the account key derived from this same root seed, and refuses
        // the whole pull if it will not open. So a record that stands in for a
        // real publish has to carry a real one.
        sealed_blob: gaugedesk_app::account::seal_account_blob(
            gaugedesk_app::account::account_key_from_seed(&signing.to_seed_bytes()),
            &gaugedesk_app::account::Account::default(),
        )
        .expect("seals under this account's key"),
        retracted: false,
    };
    let put = gaugedesk_directory_protocol::sign_entry(entry, &signing).expect("signs");
    held.lock().unwrap().insert(root.clone(), put);
    root
}

/// A route to a Home this device does not serve — the class ADR 0154 §2 makes
/// the record authority for, and the only class a device may learn from it.
fn route_elsewhere(project: &str) -> gaugedesk_app::home::OpaqueHomeRoute {
    gaugedesk_app::home::OpaqueHomeRoute {
        project: project.to_owned(),
        home_id: gaugedesk_core::ids::HomeId::new("home:elsewhere"),
        endpoint: "https://elsewhere.example".to_owned(),
        relay: None,
        author_authority: String::new(),
        author_root_pubkey: String::new(),
        author_signature: None,
    }
}

/// ADR 0154 §6, against a real directory for the first time: a publish reads the
/// head it is about to overwrite.
///
/// The record is a snapshot, so a device that publishes what it happens to hold
/// erases everything it does not — and the fence makes that erasure durable
/// rather than transient. A reinstalled device holds its keys and none of its
/// route history, so without §6 its first publish silently withdraws every route
/// the account had, and every reader then folds them away because a verified
/// record's silence retracts.
#[tokio::test]
async fn a_publish_carries_forward_the_routes_the_directory_already_holds() {
    let held = directory();
    let (device, wb, root_dir) = device(None);
    let keys = root_dir.path().join("keys");
    enable_library_sync(&device).await;
    // Resolve the key store before seeding, so the seed file exists to read.
    let root_pubkey = wb.lock().unwrap().library_sync_root();

    seed_published_record(
        &held,
        &keys,
        "person",
        4,
        vec![route_elsewhere("project-elsewhere")],
    );
    assert_eq!(
        published_routes(&held, &root_pubkey),
        vec![(
            "project-elsewhere".to_string(),
            "home:elsewhere".to_string()
        )],
        "the account's prior publish is the directory's head"
    );

    // This device serves its own project and knows nothing of the other route.
    seed_project(&wb, "project-here");
    author_routes(&wb, "https://here.example");
    let (status, body) = post(&device, "/account/library-sync", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let mut expected = vec![
        (
            "project-elsewhere".to_string(),
            "home:elsewhere".to_string(),
        ),
        (
            "project-here".to_string(),
            wb.lock().unwrap().home_id().as_str().to_owned(),
        ),
    ];
    expected.sort();
    assert_eq!(
        published_routes(&held, &root_pubkey),
        expected,
        "the publish added its own route and kept the one it did not author"
    );
}

/// ADR 0154 §2, against a real directory: a verified record's silence retracts
/// the routes it owns, which is what makes ADR 0131 §7's departure real.
///
/// The pull half was tested against a hand-built record; this drives the actual
/// `POST /account/library-sync/pull` handler over HTTP against a directory that
/// serves the whole signed put, so the signature the reader checks is one that
/// genuinely crossed the wire.
#[tokio::test]
async fn a_verified_records_silence_retracts_a_route_the_device_had_pulled() {
    let held = directory();
    let (device, wb, root_dir) = device(None);
    let keys = root_dir.path().join("keys");
    enable_library_sync(&device).await;
    let root_pubkey = wb.lock().unwrap().library_sync_root();

    seed_published_record(
        &held,
        &keys,
        "person",
        1,
        vec![route_elsewhere("project-moves")],
    );
    let (status, body) = post(&device, "/account/library-sync/pull", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["routes_verified"], true,
        "the record verified under the root this device holds: {body}"
    );
    assert!(
        gaugedesk_app::account::Account::rebuild(wb.lock().unwrap().store_ref())
            .unwrap()
            .home_routes
            .contains_key("project-moves"),
        "the device learns the route from the signed record"
    );

    // The serving Home departs the project, so the account's next record simply
    // does not mention it. Nothing says "retract"; the silence is the retraction.
    seed_published_record(&held, &keys, "person", 2, Vec::new());
    let (status, body) = post(&device, "/account/library-sync/pull", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["retracted"], 1, "the silence retracted it: {body}");
    assert!(
        !gaugedesk_app::account::Account::rebuild(wb.lock().unwrap().store_ref())
            .unwrap()
            .home_routes
            .contains_key("project-moves"),
        "a relocated project must not keep a live pointer at its former Home"
    );
    let _ = root_pubkey;
}
