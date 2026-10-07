//! RAWCTX-1 transport qualification. Captures are installed only by the real
//! engine/Whip runtime. The provider is synthetic; application replies are not.
//! The loopback IdP is a hermetic adapter, not production account evidence.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Json, Router};
use gaugedesk_core::{abac::AuthorityAttributes, ids::AuthorityId};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::{identity::LoopbackIdentityProvider, LockUnpoisoned, SharedWorkbench};

const READER: &str = "raw-reader";
const PUBLISHER: &str = "raw-publisher";
const STRANGER: &str = "raw-stranger";
const MARKER: &str = "synthetic-raw-context-user";
static REQUEST: AtomicU64 = AtomicU64::new(0);

struct ProviderCall {
    body: Value,
    finish: oneshot::Sender<(StatusCode, Value)>,
}

#[derive(Clone)]
struct Provider(mpsc::Sender<ProviderCall>);

async fn provider(State(provider): State<Provider>, bytes: Bytes) -> axum::response::Response {
    use axum::response::IntoResponse;
    let body: Value = serde_json::from_slice(&bytes).expect("actual provider JSON");
    let (finish, completed) = oneshot::channel();
    provider
        .0
        .send(ProviderCall { body, finish })
        .await
        .expect("provider observer");
    let (status, response) = completed.await.expect("explicit provider response");
    // The generic provider speaks its production chat-completions wire. A held
    // response is a real pending HTTP request, never a seeded capture callback.
    if status != StatusCode::OK {
        return (status, Json(response)).into_response();
    }
    let message = &response["choices"][0]["message"];
    let delta = json!({"choices":[{"index":0,"delta":message,
        "finish_reason": if message.get("tool_calls").is_some() { "tool_calls" } else { "stop" }}]});
    let wire = format!(
        "data: {delta}\n\ndata: {}\n\ndata: [DONE]\n\n",
        json!({"choices":[],"usage":response["usage"]})
    );
    ([("content-type", "text/event-stream")], wire).into_response()
}

fn answer(text: &str, usage: u64) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":text}}],
        "usage":{"prompt_tokens":usage,"completion_tokens":1}})
}

fn tool(name: &str, arguments: Value, id: &str, usage: u64) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":"",
        "tool_calls":[{"id":id,"type":"function","function":{
            "name":name,"arguments":arguments.to_string()}}]}}],
        "usage":{"prompt_tokens":usage,"completion_tokens":1}})
}

struct Fixture {
    _root: Option<tempfile::TempDir>,
    wb: SharedWorkbench,
    chat: String,
    origin: String,
    owned_listeners: Vec<String>,
    headers: Vec<(String, String)>,
    calls: Mutex<mpsc::Receiver<ProviderCall>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    turns: std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(Some(interrupt)) = crate::engine::request_turn_stop(&self.chat) {
            interrupt();
        }
        for turn in self.turns.lock().unwrap().drain(..) {
            turn.abort();
        }
        let servers = std::mem::take(&mut self.tasks);
        let root = self._root.take();
        let chat = self.chat.clone();
        // Panic cleanup still owns the root while the real runtime observes
        // cancellation. No detached client request may retain its fixture.
        tokio::spawn(async move {
            for _ in 0..100 {
                if !crate::engine::turn_is_live(&chat) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            for server in servers {
                server.abort();
                let _ = server.await;
            }
            drop(root);
        });
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::new_with_provider(None).await
    }

    async fn new_with_provider(external_provider: Option<String>) -> Self {
        Self::new_with_setup_probe(external_provider, |_| {}).await
    }

    async fn new_with_setup_probe(
        external_provider: Option<String>,
        setup_probe: impl FnOnce(&Self) + Send,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let chat = {
            let mut guard = wb.lock_unpoisoned();
            guard.set_identity_provider(Some(Arc::new(
                LoopbackIdentityProvider::new()
                    .enroll(
                        READER,
                        AuthorityId::new(READER),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        PUBLISHER,
                        AuthorityId::new(PUBLISHER),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        STRANGER,
                        AuthorityId::new(STRANGER),
                        AuthorityAttributes::default(),
                    ),
            )));
            // Actual admission resolves these fixture memberships through the
            // ordinary IdP/Home middleware. No actor extensions are injected.
            for actor in [READER, PUBLISHER, STRANGER] {
                guard
                    .store_mut()
                    .append_record(
                        crate::org::ORG_SCOPE,
                        "membership",
                        &json!({"id":actor,"op":"upsert","org_id":crate::org::ORG_ID,
                        "authority":actor,"email":format!("{actor}@example.test"),
                        "role":"owner","status":"active","managed_by_scim":false,
                        "team":null})
                        .to_string(),
                    )
                    .unwrap();
            }
            let chat = guard
                .create_default_engagement(
                    format!("raw-runtime-{}", REQUEST.fetch_add(1, Ordering::Relaxed)),
                    "Raw runtime".into(),
                )
                .unwrap_or_else(|_| panic!("fixture engagement creation failed"));
            let mut record = guard.library.chats[&chat.id].clone();
            record.owner = Some(READER.into());
            guard.write_chat_record(record);
            let instance =
                guard.library.instances[&guard.library.chats[&chat.id].instance_id].clone();
            let mut agent = guard.library.agents[&instance.agent_id].clone();
            agent
                .versions
                .get_mut(&instance.version)
                .unwrap()
                .source_owner_authority = Some(PUBLISHER.into());
            guard.write_agent_record(agent);
            // Project standing is per account (DR-0268): directory roles do
            // not admit a chat route. The reader owns the chat's project and
            // the publisher holds an ordinary member grant on it; the stranger
            // has neither, so its refusals below come from standing, not from
            // any relaxed admission.
            let project_id = guard
                .library
                .project_of_chat(&chat.id)
                .expect("fixture chat belongs to a project")
                .to_owned();
            let mut project = guard.library.projects[&project_id].clone();
            project.extra.insert(
                crate::project_owner::PROJECT_OWNER_EXTRA.into(),
                json!(READER),
            );
            guard.write_project_record(project);
            guard
                .store_mut()
                .append_record(
                    crate::org::ORG_SCOPE,
                    "member_grant",
                    &serde_json::to_string(&crate::org::MemberGrantRecord {
                        id: crate::org::MemberGrantRecord::make_id(PUBLISHER, &project_id),
                        op: crate::library::RecordOp::Upsert,
                        authority: PUBLISHER.into(),
                        project_id: project_id.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            chat.id
        };
        let (tx, calls) = mpsc::channel(16);
        // Install the cleanup owner before the first listener or asynchronous
        // setup operation. Failed admission/setup must retain every partial
        // server and the root just like a fully constructed fixture.
        let mut fixture = Self {
            _root: Some(root),
            wb,
            chat,
            origin: String::new(),
            owned_listeners: Vec::new(),
            headers: Vec::new(),
            calls: Mutex::new(calls),
            tasks: Vec::new(),
            turns: std::sync::Mutex::new(Vec::new()),
        };
        let provider_origin = if let Some(origin) = external_provider {
            assert!(
                origin.starts_with("http://127.0.0.1:"),
                "fixture provider must be loopback"
            );
            origin
        } else {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            fixture.owned_listeners.push(origin.clone());
            fixture.tasks.push(tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new()
                        .route("/v1/chat/completions", post(provider))
                        .with_state(Provider(tx)),
                )
                .await
                .unwrap();
            }));
            origin
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        fixture.owned_listeners.push(origin.clone());
        fixture.origin = origin.clone();
        let app = crate::open_route_stack::open_control_plane(fixture.wb.clone()).layer(
            axum::middleware::from_fn_with_state(
                fixture.wb.clone(),
                crate::home_routes::require_home_admission,
            ),
        );
        fixture.tasks.push(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        // A test-only probe can fail this actual partial construction after
        // both servers are owned, before any admission or task is attempted.
        setup_probe(&fixture);
        let client = reqwest::Client::new();
        for actor in [READER, PUBLISHER, STRANGER] {
            let response = client
                .post(format!("{origin}/home/admissions"))
                .bearer_auth(actor)
                .header(
                    "idempotency-key",
                    format!("raw-admit-{}", REQUEST.fetch_add(1, Ordering::Relaxed)),
                )
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::CREATED);
            let bytes = response.bytes().await.unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            fixture
                .headers
                .push((actor.into(), body["admission"].as_str().unwrap().into()));
        }
        let linked = fixture
            .request(
                READER,
                "POST",
                "/account/credentials",
                Some(json!({"provider":"openai-generic","token":"synthetic-only",
                "base_url":format!("{provider_origin}/v1")})),
            )
            .await;
        assert_eq!(linked.0, 200, "credential route: {}", linked.1);
        let config = fixture
            .request(
                READER,
                "PUT",
                &format!("/chats/{}/config", fixture.chat),
                Some(json!({"provider":"openai-generic","model":"raw-fixture-untracked"})),
            )
            .await;
        assert_eq!(config.0, 200, "configuration: {}", config.1);
        fixture
    }

    fn client_request(&self, actor: &str, method: &str, path: &str) -> reqwest::RequestBuilder {
        let mut request = reqwest::Client::new()
            .request(method.parse().unwrap(), format!("{}{path}", self.origin))
            .header(
                "idempotency-key",
                format!("raw-command-{}", REQUEST.fetch_add(1, Ordering::Relaxed)),
            );
        if let Some((_, admission)) = self.headers.iter().find(|(who, _)| who == actor) {
            request = request
                .bearer_auth(actor)
                .header(crate::home_admission::HOME_ADMISSION_HEADER, admission);
        }
        request
    }

    async fn request(
        &self,
        actor: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = self.client_request(actor, method, path);
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let bytes = response.bytes().await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)})),
        )
    }

    fn start(&self, prompt: &str) -> tokio::task::JoinHandle<(u16, Value)> {
        self.start_with_images(prompt, Vec::new())
    }

    fn start_with_images(
        &self,
        prompt: &str,
        images: Vec<Value>,
    ) -> tokio::task::JoinHandle<(u16, Value)> {
        let request = self
            .client_request(READER, "POST", &format!("/chats/{}/task", self.chat))
            .header("content-type", "application/json")
            .body(json!({"prompt":prompt,"images":images}).to_string());
        let turn = tokio::spawn(async move {
            let response = request.send().await.unwrap();
            let status = response.status().as_u16();
            let bytes = response.bytes().await.unwrap();
            (
                status,
                serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)})),
            )
        });
        self.turns.lock().unwrap().push(turn.abort_handle());
        turn
    }

    async fn next_call(&self) -> ProviderCall {
        tokio::time::timeout(Duration::from_secs(30), self.calls.lock().await.recv())
            .await
            .expect("actual provider request within bound")
            .expect("provider open")
    }

    async fn capture(&self) -> Value {
        let response = self
            .client_request(
                READER,
                "GET",
                &format!("/chats/{}/model-context", self.chat),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
    }

    fn import_source(&self, owner: &str, label: &str, name: &str, body: &[u8]) -> Value {
        let mut guard = self.wb.lock_unpoisoned();
        let files = [(name.to_owned(), body.to_vec())];
        let (_, cut) = guard
            .ingest_upload_into_engagement(&self.chat, &files, None)
            .unwrap()
            .unwrap();
        let record = guard
            .mint_resource_context(&self.chat, owner, label, &cut, Default::default())
            .unwrap();
        guard
            .bind_uploaded_context(&self.chat, &record.resource.id, &files, None)
            .unwrap();
        let path = guard.engagement_workspace_path(&self.chat, name);
        let target = &guard
            .library
            .current_target_set(&self.chat)
            .unwrap()
            .members[0]
            .target_id;
        json!({"rid":record.resource.id.as_str(), "path":path,
            "public_path":format!("{}/{name}",guard.library.work_targets[target].name),
            "owner":owner, "digest":whipplescript_store::stable_hash_bytes_hex(body)})
    }

    async fn shutdown(mut self) {
        if let Some(Some(interrupt)) = crate::engine::request_turn_stop(&self.chat) {
            interrupt();
        }
        for _ in 0..100 {
            if !crate::engine::turn_is_live(&self.chat) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !crate::engine::turn_is_live(&self.chat),
            "owned runtime must retire before teardown"
        );
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        for origin in &self.owned_listeners {
            let port = origin.strip_prefix("http://").unwrap();
            assert!(
                tokio::net::TcpStream::connect(port).await.is_err(),
                "owned listener closed"
            );
        }
        self.turns.lock().unwrap().clear();
        self._root.take();
    }

    async fn grant_method(&self) {
        assert_eq!(
            self.request(
                READER,
                "POST",
                &format!("/chats/{}/method-inspection/request", self.chat),
                None
            )
            .await
            .0,
            200
        );
        assert_eq!(
            self.request(
                PUBLISHER,
                "POST",
                &format!("/chats/{}/method-inspection/{READER}/approve", self.chat),
                None
            )
            .await
            .0,
            200
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_request_requires_current_method_grant_and_retires_after_completion() {
    let fixture = Fixture::new().await;
    let turn = fixture.start(MARKER);
    let call = fixture.next_call().await;
    assert!(call.body.to_string().contains(MARKER));
    assert_eq!(
        fixture
            .request(
                STRANGER,
                "GET",
                &format!("/chats/{}/model-context", fixture.chat),
                None
            )
            .await
            .0,
        403
    );
    assert_eq!(
        fixture
            .request(
                "",
                "GET",
                &format!("/chats/{}/model-context", fixture.chat),
                None
            )
            .await
            .0,
        401
    );
    let denied = fixture.capture().await;
    assert!(denied["calls"]
        .as_array()
        .unwrap()
        .iter()
        .any(|call| call["redacted"] == true));
    fixture.grant_method().await;
    let admitted = fixture.capture().await;
    assert_eq!(
        admitted["calls"][0]["body"], call.body,
        "actual provider body, not a capture fixture"
    );
    assert_eq!(
        fixture
            .request(
                PUBLISHER,
                "POST",
                &format!("/chats/{}/method-inspection/{READER}/revoke", fixture.chat),
                None
            )
            .await
            .0,
        200
    );
    let revoked = fixture.capture().await;
    assert!(revoked["calls"]
        .as_array()
        .unwrap()
        .iter()
        .any(|call| call["redacted"] == true));
    call.finish
        .send((StatusCode::OK, answer("Done.", 1)))
        .unwrap();
    assert_eq!(turn.await.unwrap().0, 200);
    assert_eq!(fixture.capture().await["available"], false);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_tool_round_keeps_wire_order_and_rechecks_changed_source_bytes() {
    let fixture = Fixture::new().await;
    let (path, public_path) = {
        let guard = fixture.wb.lock_unpoisoned();
        let path = guard.engagement_workspace_path(&fixture.chat, "raw-notes.txt");
        let engagement = &guard.engagements[&fixture.chat];
        engagement
            .write_file(&path, "synthetic-private-file\n")
            .unwrap();
        engagement.commit_turn("fixture current cut").unwrap();
        let target = &guard
            .library
            .current_target_set(&fixture.chat)
            .unwrap()
            .members[0]
            .target_id;
        (
            path,
            format!("{}/raw-notes.txt", guard.library.work_targets[target].name),
        )
    };
    fixture.grant_method().await;
    let turn = fixture.start("Read the synthetic notes.");
    let first = fixture.next_call().await;
    first
        .finish
        .send((
            StatusCode::OK,
            tool("read", json!({"path":public_path}), "raw-read", 1),
        ))
        .unwrap();
    let second = fixture.next_call().await;
    assert!(second.body.to_string().contains("synthetic-private-file"));
    let before = fixture.capture().await;
    assert_eq!(before["calls"][0]["ordinal"], 0);
    assert_eq!(before["calls"][1]["ordinal"], 1);
    assert_ne!(
        before["calls"][1]["redacted"], true,
        "this case requires an authorized current-cut witness, not honest unknown: {before}"
    );
    assert_eq!(before["calls"][1]["body"], second.body);
    let expected_source = format!(
        "workspace-file:{}:{}:{}",
        fixture.chat,
        whipplescript_store::stable_hash_bytes_hex(b"synthetic-private-file\n"),
        path
    );
    // Read the already installed real runtime handle for provenance custody;
    // the public route intentionally projects these labels away. Never bind one.
    let handle = crate::engine::running_turn_model_context(&fixture.chat).unwrap();
    let raw: Value = serde_json::from_str(
        &tokio::task::spawn_blocking(move || handle())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(raw["calls"][1]["body"], second.body);
    assert!(
        raw["calls"][1]["ordered_provenance"]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label["complete"] == true
                && label["source_handles"]
                    .as_array()
                    .is_some_and(|handles| handles
                        .iter()
                        .any(|source| source == &expected_source))),
        "actual read must carry its exact retained file witness: {before}"
    );
    let changed = fixture
        .client_request(READER, "PUT", &format!("/chats/{}/file", fixture.chat))
        .query(&[("path", &path)])
        .body("changed source\n")
        .send()
        .await
        .unwrap();
    assert_eq!(changed.status(), reqwest::StatusCode::OK);
    let _ = changed.bytes().await.unwrap();
    // Changed bytes no longer match the call's witness: the already-sent
    // block closes, and the current bytes are never substituted for it.
    let after = fixture.capture().await;
    assert_eq!(after["calls"][1]["redacted"], true, "{after}");
    assert!(!after["calls"][1]
        .to_string()
        .contains("synthetic-private-file"));
    assert!(!after.to_string().contains("changed source"));
    second
        .finish
        .send((StatusCode::OK, answer("Done.", 1)))
        .unwrap();
    assert_eq!(turn.await.unwrap().0, 200);
    assert_eq!(fixture.capture().await["available"], false);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_provider_failure_retires_capture_without_transcript_fallback() {
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let turn = fixture.start(MARKER);
    let call = fixture.next_call().await;
    assert_eq!(fixture.capture().await["calls"][0]["body"], call.body);
    call.finish
        .send((
            StatusCode::BAD_REQUEST,
            json!({"error":{"message":"synthetic refusal"}}),
        ))
        .unwrap();
    let (status, result) = turn.await.unwrap();
    assert_eq!(status, 200, "actual engine receipt: {result}");
    assert_eq!(result["run_phase"], "Failed");
    assert!(result["error"]
        .as_str()
        .is_some_and(|error| error.contains("synthetic refusal")));
    assert_eq!(fixture.capture().await["available"], false);
    assert!(
        fixture.calls.lock().await.try_recv().is_err(),
        "one provider request, no hidden retry"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "WS-79 remaining: Stop is accepted but the turn does not settle while the provider request is held open"]
async fn actual_cancel_retires_the_held_provider_request() {
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let turn = fixture.start(MARKER);
    let call = fixture.next_call().await;
    assert_eq!(fixture.capture().await["calls"][0]["body"], call.body);
    let stopped = fixture
        .request(
            READER,
            "POST",
            &format!("/chats/{}/stop", fixture.chat),
            None,
        )
        .await;
    assert_eq!(stopped.0, 200, "actual stop receipt: {stopped:?}");
    assert_eq!(stopped.1["stopped"], true);
    // Observe the owning canceled receipt before releasing the provider; an
    // ordinary successful completion cannot satisfy this cancellation proof.
    let (status, result) = tokio::time::timeout(Duration::from_secs(30), turn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, 499, "actual stopped terminal receipt: {result}");
    assert_eq!(result["error"], "stopped");
    assert_eq!(fixture.capture().await["available"], false);
    let _ = call.finish.send((StatusCode::OK, answer("After stop.", 1)));
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_live_image_is_exact_and_retires_with_its_turn() {
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let turn = fixture.start_with_images(
        MARKER,
        vec![json!({
            "mimeType":"image/png", "data":"aW1hZ2U="
        })],
    );
    let call = fixture.next_call().await;
    assert!(
        call.body.to_string().contains("aW1hZ2U="),
        "actual provider image wire"
    );
    assert_eq!(fixture.capture().await["calls"][0]["body"], call.body);
    let handle = crate::engine::running_turn_model_context(&fixture.chat).unwrap();
    let raw: Value = serde_json::from_str(
        &tokio::task::spawn_blocking(move || handle())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(raw["calls"][0]["ordered_provenance"]["messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|label| label["source_handles"]
            .as_array()
            .is_some_and(|handles| handles.iter().any(|source| source
                .as_str()
                .is_some_and(|s| s.starts_with("turn-image:"))))));
    call.finish
        .send((StatusCode::OK, answer("Done.", 1)))
        .unwrap();
    assert_eq!(turn.await.unwrap().1["run_phase"], "Completed");
    let retired = fixture.capture().await;
    assert_eq!(retired["available"], false);
    assert!(!retired.to_string().contains("aW1hZ2U="));
    fixture.shutdown().await;
}

async fn actual_compaction_case(usage: u64, expect_fold: bool) {
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let public_path = {
        let guard = fixture.wb.lock_unpoisoned();
        let path = guard.engagement_workspace_path(&fixture.chat, "compact.txt");
        let engagement = &guard.engagements[&fixture.chat];
        engagement
            .write_file(&path, "synthetic-recent-tool-result\n")
            .unwrap();
        engagement
            .commit_turn("fixture retained compaction source")
            .unwrap();
        let target = &guard
            .library
            .current_target_set(&fixture.chat)
            .unwrap()
            .members[0]
            .target_id;
        format!("{}/compact.txt", guard.library.work_targets[target].name)
    };
    let turn = fixture.start("Read the compaction fixture three times.");
    let mut bodies = Vec::new();
    for index in 0..3 {
        let call = fixture.next_call().await;
        bodies.push(call.body.clone());
        let mut response = tool(
            "read",
            json!({"path":public_path}),
            &format!("compact-{index}"),
            if index == 2 { usage } else { 1 },
        );
        if index == 0 {
            response["choices"][0]["message"]["content"] =
                format!("synthetic-old-fold-marker:{}", "x".repeat(90_000)).into();
        }
        call.finish.send((StatusCode::OK, response)).unwrap();
    }
    let next = fixture.next_call().await;
    if expect_fold {
        assert!(
            next.body
                .get("tools")
                .is_none_or(|tools| tools.as_array().is_some_and(Vec::is_empty)),
            "actual summary request must not offer tools: {}",
            next.body
        );
        assert!(next.body.to_string().contains("synthetic-old-fold-marker"));
        bodies.push(next.body.clone());
        next.finish
            .send((StatusCode::OK, answer("synthetic-summary-handoff", 1)))
            .unwrap();
        let resumed = fixture.next_call().await;
        assert!(resumed
            .body
            .to_string()
            .contains("synthetic-summary-handoff"));
        assert!(resumed
            .body
            .to_string()
            .contains("synthetic-recent-tool-result"));
        assert!(!resumed
            .body
            .to_string()
            .contains("synthetic-old-fold-marker"));
        bodies.push(resumed.body.clone());
        let handle = crate::engine::running_turn_model_context(&fixture.chat).unwrap();
        let raw: Value = serde_json::from_str(
            &tokio::task::spawn_blocking(move || handle())
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["calls"].as_array().unwrap().len(), bodies.len());
        for (ordinal, body) in bodies.iter().enumerate() {
            assert_eq!(raw["calls"][ordinal]["ordinal"], ordinal);
            assert_eq!(&raw["calls"][ordinal]["body"], body);
        }
        // The public projection must independently remain current-grant safe;
        // incomplete executor provenance cannot be promoted by this comparison.
        let public = fixture.capture().await;
        for call in public["calls"].as_array().unwrap() {
            if call["redacted"] != true {
                assert_eq!(
                    &call["body"],
                    &bodies[call["ordinal"].as_u64().unwrap() as usize]
                );
            }
        }
        resumed
            .finish
            .send((StatusCode::OK, answer("Done.", 1)))
            .unwrap();
    } else {
        assert!(
            next.body.to_string().contains("synthetic-old-fold-marker"),
            "below-threshold main request must retain the old prefix"
        );
        assert!(!next.body.to_string().contains("synthetic-summary-handoff"));
        next.finish
            .send((StatusCode::OK, answer("Done.", 1)))
            .unwrap();
    }
    assert_eq!(turn.await.unwrap().1["run_phase"], "Completed");
    assert_eq!(fixture.capture().await["available"], false);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "WS-79 remaining: synthetic usage at 90% of the 128k window does not yet drive a summarization request on this path, so the fourth call is an ordinary main call"]
async fn actual_summary_and_resumed_main_preserve_ordered_capture() {
    // Structurally valid synthetic provider usage drives the production
    // generic-model 128k window's 90% predicate; this is not billing evidence.
    actual_compaction_case(115_200, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "WS-79 remaining: vacuous until its above-threshold pair observes a real summarization request"]
async fn below_threshold_does_not_replace_the_actual_main_prefix() {
    actual_compaction_case(115_199, false).await;
}

/// What happens to another person's admitted import after the reader's grant.
#[derive(Clone, Copy)]
enum SourceChange {
    RevokeGrant,
    EraseResource,
    ChangeBytes,
}

async fn actual_imported_file_case(change: SourceChange) {
    let fixture = Fixture::new().await;
    let source = fixture.import_source(
        PUBLISHER,
        "raw-shared-source",
        "shared.txt",
        b"synthetic-shared-private\n",
    );
    let rid = source["rid"].as_str().unwrap();
    fixture.grant_method().await;
    let turn = fixture.start("Read the shared file.");
    let first = fixture.next_call().await;
    first
        .finish
        .send((
            StatusCode::OK,
            tool(
                "read",
                json!({"path":source["public_path"]}),
                "shared-read",
                1,
            ),
        ))
        .unwrap();
    let second = fixture.next_call().await;
    assert!(
        second.body.to_string().contains("synthetic-shared-private"),
        "runtime actually read the admitted source"
    );
    let denied = fixture.capture().await;
    assert_eq!(denied["calls"][1]["redacted"], true);
    assert!(!denied["calls"][1]
        .to_string()
        .contains("synthetic-shared-private"));
    assert_eq!(
        fixture
            .request(
                READER,
                "POST",
                &format!("/chats/{}/contexts/{rid}/inspection/request", fixture.chat),
                None
            )
            .await
            .0,
        200
    );
    assert_eq!(
        fixture
            .request(
                STRANGER,
                "POST",
                &format!(
                    "/chats/{}/contexts/{rid}/inspection/{READER}/approve",
                    fixture.chat
                ),
                None
            )
            .await
            .0,
        403
    );
    assert_eq!(
        fixture
            .request(
                PUBLISHER,
                "POST",
                &format!(
                    "/chats/{}/contexts/{rid}/inspection/{READER}/approve",
                    fixture.chat
                ),
                None
            )
            .await
            .0,
        200
    );
    let visible = fixture.capture().await;
    assert_ne!(
        visible["calls"][1]["redacted"], true,
        "granted current source must actually be visible: {visible}"
    );
    assert_eq!(visible["calls"][1]["body"], second.body);
    match change {
        SourceChange::RevokeGrant | SourceChange::EraseResource => {
            let mutation = if matches!(change, SourceChange::EraseResource) {
                format!("/chats/{}/resources/{rid}/tombstone", fixture.chat)
            } else {
                format!(
                    "/chats/{}/contexts/{rid}/inspection/{READER}/revoke",
                    fixture.chat
                )
            };
            assert_eq!(
                fixture.request(PUBLISHER, "POST", &mutation, None).await.0,
                200
            );
        }
        SourceChange::ChangeBytes => {
            // The grant stands; only the bound file's bytes move away from the
            // witnessed digest, which must close the already-sent block.
            let changed = fixture
                .client_request(READER, "PUT", &format!("/chats/{}/file", fixture.chat))
                .query(&[("path", source["path"].as_str().unwrap())])
                .body("changed source\n")
                .send()
                .await
                .unwrap();
            assert_eq!(changed.status(), reqwest::StatusCode::OK);
            let _ = changed.bytes().await.unwrap();
        }
    }
    let after = fixture.capture().await;
    assert_eq!(after["calls"][1]["redacted"], true);
    assert!(!after["calls"][1]
        .to_string()
        .contains("synthetic-shared-private"));
    second
        .finish
        .send((StatusCode::OK, answer("Done.", 1)))
        .unwrap();
    assert_eq!(turn.await.unwrap().1["run_phase"], "Completed");
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_imported_file_rechecks_reader_grant_revocation() {
    actual_imported_file_case(SourceChange::RevokeGrant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_imported_file_rechecks_resource_erasure() {
    actual_imported_file_case(SourceChange::EraseResource).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_imported_file_rechecks_changed_source_bytes() {
    actual_imported_file_case(SourceChange::ChangeBytes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "WS-79 remaining: the native work chat no longer offers the legacy `ask` tool, so this carrier needs a different entry point"]
async fn actual_legacy_answer_operation_carries_owned_lineage_to_the_next_request() {
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let turn = fixture.start("Ask the synthetic question.");
    let first = fixture.next_call().await;
    first
        .finish
        .send((
            StatusCode::OK,
            tool(
                "ask",
                json!({"question":"Which synthetic region?",
        "choices":["synthetic-answer-region"],"to":READER}),
                "raw-question",
                1,
            ),
        ))
        .unwrap();
    let acknowledged = fixture.next_call().await;
    acknowledged
        .finish
        .send((StatusCode::OK, answer("Question recorded.", 1)))
        .unwrap();
    assert_eq!(turn.await.unwrap().1["run_phase"], "Completed");
    // This is the existing native domain carrier. There is no invented HTTP
    // legacy-answer route, and this does not prove public answer delivery.
    {
        let mut guard = fixture.wb.lock_unpoisoned();
        let questions =
            crate::agent_question::open_questions(guard.store_ref(), &fixture.chat).unwrap();
        assert_eq!(
            questions.len(),
            1,
            "actual ask execution produced a durable question"
        );
        assert!(guard
            .answer_question(
                &fixture.chat,
                &questions[0].id,
                "synthetic-answer-region",
                READER
            )
            .unwrap());
    }
    let turn = fixture.start("Continue with the answer.");
    let actual = fixture.next_call().await;
    assert!(actual.body.to_string().contains("synthetic-answer-region"));
    let handle = crate::engine::running_turn_model_context(&fixture.chat).unwrap();
    let raw: Value = serde_json::from_str(
        &tokio::task::spawn_blocking(move || handle())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(raw["calls"][0]["body"], actual.body);
    assert!(raw["calls"][0]["ordered_provenance"]["messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|label| label["complete"] == true
            && label["source_handles"]
                .as_array()
                .is_some_and(|handles| handles.iter().any(|source| source
                    .as_str()
                    .is_some_and(|s| s.starts_with("question-answer:"))))));
    assert_eq!(
        fixture.capture().await["calls"][0]["body"],
        actual.body,
        "normal current-source projection must admit the actual owned answer"
    );
    actual
        .finish
        .send((StatusCode::OK, answer("Done.", 1)))
        .unwrap();
    assert_eq!(turn.await.unwrap().1["run_phase"], "Completed");
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "WS-79 remaining: an IdP-admitted chat owner's choice answer is refused \"respondent has no chat standing\" because the roster reads account::global, not the admitting directory"]
async fn actual_choice_answer_request_has_a_current_answer_record_witness() {
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let turn = fixture.start("Ask a synthetic choice card.");
    let first = fixture.next_call().await;
    first
        .finish
        .send((
            StatusCode::OK,
            tool(
                "ask_choices",
                json!({"questions":[{
        "prompt":"Which synthetic choice?","options":[{"label":"synthetic-choice-answer",
        "description":"Synthetic only"},{"label":"synthetic-choice-other",
        "description":"Synthetic only"}]}]}),
                "raw-choice",
                1,
            ),
        ))
        .unwrap();
    let acknowledgment = fixture.next_call().await;
    acknowledgment
        .finish
        .send((StatusCode::OK, answer("Choice recorded.", 1)))
        .unwrap();
    assert_eq!(turn.await.unwrap().1["run_phase"], "Completed");
    let cards = fixture
        .request(
            READER,
            "GET",
            &format!("/chats/{}/choice-cards", fixture.chat),
            None,
        )
        .await;
    assert_eq!(cards.0, 200);
    assert_eq!(
        cards.1.as_array().unwrap().len(),
        1,
        "actual tool created one choice card"
    );
    let card = &cards.1[0];
    let request = fixture.client_request(READER,"POST",&format!("/chats/{}/choice-cards/{}/answer",
        fixture.chat,card["id"].as_str().unwrap()))
        .header("content-type", "application/json")
        .body(json!({"selections":[{
        "question_id":card["questions"][0]["id"],"option_ids":[card["questions"][0]["options"][0]["id"]]}]}).to_string());
    let mut continuation = tokio::spawn(async move {
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let bytes = response.bytes().await.unwrap();
        let body: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)}));
        (status, body)
    });
    fixture
        .turns
        .lock()
        .unwrap()
        .push(continuation.abort_handle());
    let actual = tokio::select! {
        call = fixture.next_call() => call,
        answered = &mut continuation => panic!("choice answer settled without a model request: {answered:?}"),
    };
    assert!(
        actual.body.to_string().contains("synthetic-choice-answer"),
        "actual choice continuation reached provider"
    );
    let handle = crate::engine::running_turn_model_context(&fixture.chat).unwrap();
    let raw: Value = serde_json::from_str(
        &tokio::task::spawn_blocking(move || handle())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(raw["calls"][0]["body"], actual.body);
    let witnessed = {
        let guard = fixture.wb.lock_unpoisoned();
        raw["calls"][0]["ordered_provenance"]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|label| label["source_handles"].as_array())
            .flatten()
            .filter_map(Value::as_str)
            .any(|source| {
                source.starts_with("question-answer:")
                    && crate::agent_question::current_answer_source(
                        guard.store_ref(),
                        &fixture.chat,
                        source,
                    )
            })
    };
    // This intentionally fails if the current public carrier labels an exact
    // answer only as ordinary chat text. It does not invent a new source kind,
    // bind a capture, or treat mere visible answer text as lineage proof.
    assert!(
        witnessed,
        "actual choice continuation has no current answered-record witness: {}",
        raw["calls"][0]["ordered_provenance"]
    );
    actual
        .finish
        .send((StatusCode::OK, answer("Done.", 1)))
        .unwrap();
    assert_eq!(continuation.await.unwrap().0, 200);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_partial_setup_closes_owned_listeners_and_scratch() {
    let (observed, state) = oneshot::channel();
    let failed = tokio::spawn(async move {
        Fixture::new_with_setup_probe(None, move |fixture| {
            observed
                .send((
                    fixture._root.as_ref().unwrap().path().to_owned(),
                    fixture.owned_listeners.clone(),
                ))
                .unwrap();
            panic!("deliberate setup failure before admission, not a product failure");
        })
        .await
    });
    let (root, listeners) = state.await.unwrap();
    assert_eq!(listeners.len(), 2, "both actual partial servers are owned");
    assert!(matches!(failed.await, Err(error) if error.is_panic()));
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut all_closed = true;
            for origin in &listeners {
                all_closed &=
                    tokio::net::TcpStream::connect(origin.strip_prefix("http://").unwrap())
                        .await
                        .is_err();
            }
            if all_closed && !root.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("partial setup cleanup while owning runtime remains alive");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "WS-79 remaining: shares the held-provider cancellation gap; the turn stays live after its interrupt fires"]
async fn panic_unwind_retires_only_its_owned_runtime_listeners_and_scratch() {
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let root = fixture._root.as_ref().unwrap().path().to_owned();
    let listeners = fixture.owned_listeners.clone();
    let chat = fixture.chat.clone();
    let _turn = fixture.start(MARKER);
    let _held = fixture.next_call().await;
    let failed = tokio::spawn(async move {
        let _owned = fixture;
        panic!("deliberate fixture unwind, not a product failure");
    })
    .await;
    assert!(failed.unwrap_err().is_panic());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut all_closed = true;
            for origin in &listeners {
                all_closed &=
                    tokio::net::TcpStream::connect(origin.strip_prefix("http://").unwrap())
                        .await
                        .is_err();
            }
            if !crate::engine::turn_is_live(&chat) && all_closed && !root.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("panic cleanup while owning runtime remains alive");
    // This proves ordinary unwind cleanup only, not process abort or a runtime
    // torn down before its asynchronous cleanup task can run.
}

/// Infrastructure only: the maintained browser launcher invokes this exact
/// ignored entry point. Its ignored discovery is never counted as product proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit e2e:raw-context infrastructure; not a product verdict"]
async fn raw_context_browser_fixture() {
    let ready = std::path::PathBuf::from(
        std::env::var("WS79_FIXTURE_READY").expect("explicit private readiness path"),
    );
    let complete = std::path::PathBuf::from(
        std::env::var("WS79_FIXTURE_COMPLETE").expect("explicit private completion path"),
    );
    let origin = std::env::var("WS79_PROVIDER_ORIGIN").expect("explicit loopback provider");
    let fixture = Fixture::new_with_provider(Some(origin)).await;
    let imported = fixture.import_source(
        PUBLISHER,
        "raw-shared-source",
        "shared.txt",
        b"synthetic-shared-private\n",
    );
    let own_import = fixture.import_source(
        READER,
        "raw-own-source",
        "own.txt",
        b"synthetic-own-private\n",
    );
    let governance = {
        let guard = fixture.wb.lock_unpoisoned();
        json!({"signer":guard.authority().as_str(), "public_key":guard.governance_public_key().as_str()})
    };
    let manifest = json!({"protocol":"gaugedesk.raw-context-fixture.v1", "origin":fixture.origin,
        "chat":fixture.chat,"reader":READER,"publisher":PUBLISHER,"stranger":STRANGER,
        "admissions":fixture.headers,"governance":governance, "sources":{"shared":imported,"own":own_import}});
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&ready).unwrap();
        file.write_all(manifest.to_string().as_bytes()).unwrap();
        file.sync_all().unwrap();
    }
    let outcome = tokio::time::timeout(Duration::from_secs(600), async {
        while !complete.exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        serde_json::from_slice::<Value>(&std::fs::read(&complete).unwrap()).unwrap()
    })
    .await;
    fixture.shutdown().await;
    let _ = std::fs::remove_file(&ready);
    let _ = std::fs::remove_file(&complete);
    assert_eq!(
        outcome.expect("bounded explicit fixture completion")["ok"],
        true
    );
}
