//! WS-71: authenticated Panel authorship over the production socket surface.
//! Session issuance is a controlled identity boundary; every product operation
//! goes through the ordinary router, bearer authentication and command shell.
use crate::{LockUnpoisoned, SharedWorkbench};
use serde_json::{json, Value};
use sha2::Digest;
use std::sync::Arc;
use tokio::task::JoinHandle;

struct Fixture {
    root: tempfile::TempDir,
    wb: SharedWorkbench,
    service: Option<JoinHandle<()>>,
    base: String,
    owner: String,
    other: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // This fixture never starts turns. Abort the owned listener even if
        // setup or an assertion panics; normal paths also await its retirement.
        if let Some(service) = &self.service {
            service.abort();
        }
    }
}

impl Fixture {
    async fn new() -> Self {
        eprintln!("WS71_BOOT creating owned root");
        let root = tempfile::tempdir().unwrap();
        eprintln!("WS71_BOOT opening workbench");
        let wb = crate::open_workbench(root.path()).unwrap();
        eprintln!("WS71_BOOT issuing fixture sessions");
        let (owner, other) = {
            let mut guard = wb.lock_unpoisoned();
            // An IdP makes an absent bearer fail authentication rather than
            // selecting the single-user local channel. No actor is injected.
            guard.set_identity_provider(Some(Arc::new(
                crate::identity::LoopbackIdentityProvider::new(),
            )));
            (
                guard
                    .mint_account_session("local-user", "passkey", 3600)
                    .unwrap(),
                guard
                    .mint_account_session("panel-other", "passkey", 3600)
                    .unwrap(),
            )
        };
        let mut fixture = Self {
            root,
            wb,
            service: None,
            base: String::new(),
            owner,
            other,
        };
        eprintln!("WS71_BOOT binding listener");
        fixture.listen().await;
        fixture
    }

    async fn listen(&mut self) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        self.base = format!("http://{}", listener.local_addr().unwrap());
        let app = crate::open_api::open_control_plane(self.wb.clone());
        // The ownership guard already exists before this first spawn.
        self.service = Some(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
    }

    async fn stop(&mut self) {
        if let Some(service) = self.service.take() {
            service.abort();
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), service)
                .await
                .expect("owned listener retires");
            assert!(result.is_err_and(|error| error.is_cancelled()));
        }
    }

    async fn reopen(&mut self) {
        self.stop().await;
        self.wb = crate::open_workbench(self.root.path()).unwrap();
        self.wb
            .lock_unpoisoned()
            .set_identity_provider(Some(Arc::new(
                crate::identity::LoopbackIdentityProvider::new(),
            )));
        self.listen().await;
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Value,
        token: Option<&str>,
        key: &str,
    ) -> (u16, Value) {
        let mut request = reqwest::Client::new()
            .request(method.parse().unwrap(), format!("{}{path}", self.base))
            .timeout(std::time::Duration::from_secs(20))
            .header("content-type", "application/json")
            .header("idempotency-key", key);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if method != "GET" {
            request = request.body(serde_json::to_vec(&body).unwrap());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let bytes = response.bytes().await.unwrap();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"text": String::from_utf8_lossy(&bytes)}));
        (status, value)
    }

    async fn owner(&self, method: &str, path: &str, body: Value, key: &str) -> Value {
        let (status, value) = self
            .request(method, path, body, Some(&self.owner), key)
            .await;
        assert!(
            (200..300).contains(&status),
            "{method} {path}: {status} {value}"
        );
        value
    }

    async fn create(&self, kind: &str) -> String {
        self.owner(
            "POST",
            "/archetypes",
            json!({"name":"Socket-authored Agent", "kind":kind}),
            &crate::library::gen_id("panel-proof"),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn applied_replay(&self, method: &str, path: &str, body: Value, key: &str) -> String {
        let before = self.durable_shape();
        let mut command_id = None;
        let mut stored_receipt = None;
        for _ in 0..2 {
            let (status, receipt) = self
                .request(method, path, body.clone(), Some(&self.owner), key)
                .await;
            assert_eq!(status, 409, "{receipt}");
            assert_eq!(receipt["command_status"], "applied");
            let id = receipt["command_id"].as_str().unwrap();
            assert!(!id.is_empty());
            if let Some(prior) = &command_id {
                assert_eq!(id, prior);
            }
            let record = self
                .wb
                .lock_unpoisoned()
                .store_ref()
                .command(id)
                .unwrap()
                .unwrap();
            assert_eq!(record.command_id, id);
            assert_eq!(record.idempotency_key, key);
            assert_eq!(record.status, "applied");
            let snapshot: Value = serde_json::from_str(&record.snapshot_json).unwrap();
            assert_eq!(snapshot["method"], method);
            assert_eq!(snapshot["path"], path);
            assert_eq!(
                snapshot["body_sha256"],
                hex::encode(sha2::Sha256::digest(serde_json::to_vec(&body).unwrap()))
            );
            if let Some(prior) = &stored_receipt {
                assert_eq!(&record, prior);
            }
            stored_receipt = Some(record);
            command_id = Some(id.to_owned());
            assert_eq!(
                self.durable_shape(),
                before,
                "exact replay never runs the handler again"
            );
        }
        command_id.unwrap()
    }

    async fn mismatched_replay(
        &self,
        method: &str,
        path: &str,
        changed: Value,
        key: &str,
        command_id: &str,
    ) {
        let before = self.durable_shape();
        let original_receipt = self
            .wb
            .lock_unpoisoned()
            .store_ref()
            .command(command_id)
            .unwrap()
            .unwrap();
        let (status, receipt) = self
            .request(method, path, changed, Some(&self.owner), key)
            .await;
        assert_eq!(status, 409, "{receipt}");
        assert_eq!(receipt["command_status"], "key-reused-with-different-input");
        assert_eq!(receipt["command_id"], command_id);
        assert_eq!(
            self.wb
                .lock_unpoisoned()
                .store_ref()
                .command(command_id)
                .unwrap()
                .unwrap(),
            original_receipt,
            "changed input leaves original applied/key/snapshot receipt intact"
        );
        assert_eq!(
            self.durable_shape(),
            before,
            "different input cannot replace admitted intent"
        );
    }

    fn source_manifest(&self, agent: &str) -> std::collections::BTreeMap<String, String> {
        let guard = self.wb.lock_unpoisoned();
        let target = guard.library.authoring_target_for(agent).unwrap();
        guard
            .targets
            .get(&target.id)
            .unwrap()
            .main_manifest()
            .unwrap()
    }

    fn durable_shape(&self) -> Value {
        let guard = self.wb.lock_unpoisoned();
        json!({"agents": guard.library.agents, "projects": guard.library.projects,
            "instances": guard.library.instances, "chats": guard.library.chats,
            "deployments": guard.library.public_deployments})
    }

    async fn denied_without_mutation(&self, method: &str, path: &str, body: Value) {
        for token in [Some(self.other.as_str()), None, Some("not-a-session")] {
            let before = self.durable_shape();
            let (status, value) = self
                .request(
                    method,
                    path,
                    body.clone(),
                    token,
                    &crate::library::gen_id("panel-proof"),
                )
                .await;
            assert!(
                [401, 403].contains(&status),
                "{method} {path}: {status} {value}"
            );
            assert_eq!(
                self.durable_shape(),
                before,
                "denial preserves all library state"
            );
        }
    }
}

// panel-authoring-contract / panel-authoring-authority / panel-authoring-property
#[tokio::test]
async fn copy_authenticates_and_preserves_source_and_replay_identity() {
    let mut f = Fixture::new().await;
    let source = f.create("work").await;
    let (status, other_agent) = f
        .request(
            "POST",
            "/archetypes",
            json!({"name":"Other author source", "kind":"work"}),
            Some(&f.other),
            "other-author-source",
        )
        .await;
    assert_eq!(
        status, 201,
        "distinct authenticated author can create own Agent: {other_agent}"
    );
    let other_id = other_agent["id"].as_str().unwrap();
    assert_eq!(
        f.request(
            "GET",
            &format!("/archetypes/{other_id}"),
            Value::Null,
            Some(&f.other),
            "other-author-read"
        )
        .await
        .0,
        200
    );
    let source_bytes = f.source_manifest(&source);
    assert!(!source_bytes.is_empty());
    let source_before =
        serde_json::to_value(&f.wb.lock_unpoisoned().library.agents[&source]).unwrap();
    let path = format!("/archetypes/{source}/copy-as-panel");
    f.denied_without_mutation("POST", &path, json!({"name":"Forbidden copy"}))
        .await;
    let body = json!({"name":"Public socket copy"});
    let first = f.owner("POST", &path, body.clone(), "same-copy").await;
    let after_first = f.durable_shape();
    let command_id = f.applied_replay("POST", &path, body, "same-copy").await;
    f.mismatched_replay(
        "POST",
        &path,
        json!({"name":"Changed copy intent"}),
        "same-copy",
        &command_id,
    )
    .await;
    assert_eq!(
        f.durable_shape(),
        after_first,
        "no duplicate Panel or changed original intent"
    );
    let projection = f
        .owner(
            "GET",
            &format!("/archetypes/{}", first["id"].as_str().unwrap()),
            Value::Null,
            "copied-projection",
        )
        .await;
    for field in ["id", "name", "kind"] {
        assert_eq!(projection[field], first[field]);
    }
    assert_ne!(first["id"], source);
    assert_eq!(first["kind"], "panel");
    assert_eq!(
        serde_json::to_value(&f.wb.lock_unpoisoned().library.agents[&source]).unwrap(),
        source_before
    );
    assert_eq!(
        f.source_manifest(&source),
        source_bytes,
        "copy leaves every authored source byte unchanged"
    );
    f.stop().await;
}

#[tokio::test]
async fn profile_wire_roundtrip_reopens_and_invalid_or_unowned_writes_preserve_state() {
    let mut f = Fixture::new().await;
    let id = f.create("panel").await;
    let path = format!("/archetypes/{id}/panel-profile");
    let original = f.owner("GET", &path, Value::Null, "read-original").await;
    f.denied_without_mutation("GET", &path, Value::Null).await;
    f.denied_without_mutation("PUT", &path, original.clone())
        .await;
    // Finite metamorphic sweep: identity and request order must not affect a
    // valid write/read/replay; invalid edits cannot change the admitted result.
    for (n, components) in [
        json!(["gw-chat"]),
        json!(["gw-chat", "gw-files"]),
        json!(["gw-chat", "gw-viewer"]),
    ]
    .into_iter()
    .enumerate()
    {
        let mut body = original.clone();
        body["panels"]["components"] = components;
        let key = format!("profile-{n}");
        let saved = f.owner("PUT", &path, body.clone(), &key).await;
        let command_id = f.applied_replay("PUT", &path, body.clone(), &key).await;
        let mut changed = body;
        changed["model"]["max_output_tokens"] = json!(1234);
        f.mismatched_replay("PUT", &path, changed, &key, &command_id)
            .await;
        assert_eq!(f.owner("GET", &path, Value::Null, "reread").await, saved);
        for invalid in [
            json!({"components":[],"default_component":"gw-chat"}),
            json!({"components":["unregistered-panel"],"default_component":"unregistered-panel"}),
        ] {
            let mut bad = saved.clone();
            bad["panels"]["components"] = invalid["components"].clone();
            bad["panels"]["default_component"] = invalid["default_component"].clone();
            let before = f.durable_shape();
            let (status, _) = f
                .request(
                    "PUT",
                    &path,
                    bad,
                    Some(&f.owner),
                    &crate::library::gen_id("panel-proof"),
                )
                .await;
            assert_eq!(status, 422);
            assert_eq!(f.durable_shape(), before);
        }
        let mut bad = saved.clone();
        bad["public_abilities"] = json!(["command.run"]);
        let before = f.durable_shape();
        assert_eq!(
            f.request(
                "PUT",
                &path,
                bad,
                Some(&f.owner),
                &crate::library::gen_id("panel-proof")
            )
            .await
            .0,
            422
        );
        assert_eq!(
            f.durable_shape(),
            before,
            "ungranted capability remains refused"
        );
        f.reopen().await;
        assert_eq!(
            f.owner("GET", &path, Value::Null, "after-reopen").await,
            saved
        );
    }
    f.stop().await;
}

#[tokio::test]
async fn draft_and_pinned_preview_are_hidden_isolated_replaced_and_deleted() {
    let mut f = Fixture::new().await;
    let id = f.create("panel").await;
    let profile_path = format!("/archetypes/{id}/panel-profile");
    let mut profile = f
        .owner("GET", &profile_path, Value::Null, "initial-profile")
        .await;
    profile["initial_workspace"] = json!([gaugedesk_core::agent_release::ReleaseFile::new(
        "workspace/frozen.txt",
        "text/plain",
        b"frozen".to_vec()
    )]);
    f.owner("PUT", &profile_path, profile.clone(), "profile-frozen")
        .await;
    let published = f
        .owner(
            "POST",
            &format!("/archetypes/{id}/publish"),
            json!({}),
            "publish-panel",
        )
        .await;
    let project = f
        .owner(
            "POST",
            "/projects",
            json!({"name":"Authoring proof project"}),
            "authoring-project",
        )
        .await;
    let placed = f
        .owner(
            "POST",
            &format!("/projects/{}/placements", project["id"].as_str().unwrap()),
            json!({"agent_id":id}),
            "place-frozen",
        )
        .await;
    let placement = placed["instance_id"].as_str().unwrap();
    let preview_path = format!("/archetypes/{id}/preview");
    f.denied_without_mutation("POST", &preview_path, json!({}))
        .await;
    let before = f
        .owner("GET", "/workspace", Value::Null, "workspace-before")
        .await;
    profile["initial_workspace"] = json!([gaugedesk_core::agent_release::ReleaseFile::new(
        "workspace/draft.txt",
        "text/plain",
        b"draft".to_vec()
    )]);
    f.owner("PUT", &profile_path, profile, "profile-draft")
        .await;
    let pinned = f
        .owner(
            "POST",
            &preview_path,
            json!({"placement_id":placement}),
            "preview-pinned",
        )
        .await;
    let draft = f
        .owner("POST", &preview_path, json!({}), "preview-draft")
        .await;
    let pinned_id = pinned["id"].as_str().unwrap();
    let first_draft = draft["id"].as_str().unwrap();
    let mut hidden: Vec<_> = {
        let guard = f.wb.lock_unpoisoned();
        assert_eq!(guard.panel_previews_of(&id).len(), 2);
        for (chat, expected, absent) in [
            (pinned_id, "frozen.txt", "draft.txt"),
            (first_draft, "draft.txt", "frozen.txt"),
        ] {
            let record = &guard.library.chats[chat];
            let instance = &guard.library.instances[&record.instance_id];
            let hidden_project = instance.project_id.as_deref().unwrap();
            assert!(guard.is_panel_preview_project_id(hidden_project));
            assert!(guard
                .placement_abilities(&record.instance_id)
                .unwrap()
                .is_empty());
            let target = guard
                .library
                .work_targets
                .values()
                .find(|target| guard.library.project_of_target(&target.id) == Some(hidden_project))
                .unwrap();
            let workspace = guard.targets.get(&target.id).unwrap();
            assert_eq!(
                workspace.read_main_file(expected).unwrap().as_deref(),
                Some(expected.trim_end_matches(".txt"))
            );
            assert_eq!(workspace.read_main_file(absent).unwrap(), None);
        }
        let version = guard
            .panel_previews_of(&id)
            .into_iter()
            .find(|preview| preview.placement_id.is_some())
            .unwrap()
            .version
            .unwrap();
        assert_eq!(json!(version), published["version"]);
        assert!(guard.library.public_deployments.is_empty());
        guard
            .panel_previews_of(&id)
            .into_iter()
            .map(|preview| preview.project_id)
            .collect()
    };
    let mut hidden_forks: Vec<String> = {
        let guard = f.wb.lock_unpoisoned();
        hidden
            .iter()
            .map(|project| {
                crate::panel_preview::preview_marker(&guard.library.projects[project])
                    .unwrap()
                    .preview_agent_id
                    .unwrap()
            })
            .collect()
    };
    let after = f
        .owner("GET", "/workspace", Value::Null, "workspace-after")
        .await;
    assert_eq!(after["projects"], before["projects"]);
    assert_eq!(after["recent"], before["recent"]);
    assert_eq!(
        after["archetypes"].as_array().unwrap().len(),
        before["archetypes"].as_array().unwrap().len()
    );
    let replacement = f
        .owner("POST", &preview_path, json!({}), "replace-draft")
        .await;
    assert_ne!(replacement["id"], first_draft);
    {
        let guard = f.wb.lock_unpoisoned();
        assert!(!guard.library.chats.contains_key(first_draft));
        assert!(
            hidden
                .iter()
                .filter(|project| guard.library.projects.contains_key(*project))
                .count()
                == 1,
            "only the pinned original hidden project remains after replacement"
        );
        assert_eq!(
            hidden_forks
                .iter()
                .filter(|agent| guard.library.agents.contains_key(*agent))
                .count(),
            1,
            "draft replacement retires its hidden fork as well as its project"
        );
        for preview in guard.panel_previews_of(&id) {
            hidden_forks.push(
                crate::panel_preview::preview_marker(&guard.library.projects[&preview.project_id])
                    .unwrap()
                    .preview_agent_id
                    .unwrap(),
            );
            hidden.push(preview.project_id);
        }
    }
    let (old_pinned_project, old_pinned_fork) = {
        let guard = f.wb.lock_unpoisoned();
        let project = guard.panel_preview_project_of_chat(pinned_id).unwrap();
        let fork = crate::panel_preview::preview_marker(&guard.library.projects[&project])
            .unwrap()
            .preview_agent_id
            .unwrap();
        (project, fork)
    };
    let pinned_replacement = f
        .owner(
            "POST",
            &preview_path,
            json!({"placement_id":placement}),
            "replace-pinned",
        )
        .await;
    assert_ne!(pinned_replacement["id"], pinned_id);
    {
        let guard = f.wb.lock_unpoisoned();
        assert!(!guard.library.chats.contains_key(pinned_id));
        assert!(!guard.library.projects.contains_key(&old_pinned_project));
        assert!(
            !guard.library.agents.contains_key(&old_pinned_fork),
            "pinned replacement retires its prior fork"
        );
        let preview = guard
            .panel_previews_of(&id)
            .into_iter()
            .find(|preview| preview.chat_id == pinned_replacement["id"].as_str().unwrap())
            .unwrap();
        assert_eq!(json!(preview.version), published["version"]);
        hidden_forks.push(
            crate::panel_preview::preview_marker(&guard.library.projects[&preview.project_id])
                .unwrap()
                .preview_agent_id
                .unwrap(),
        );
        hidden.push(preview.project_id);
    }
    for chat in [
        pinned_replacement["id"].as_str().unwrap(),
        replacement["id"].as_str().unwrap(),
    ] {
        f.owner(
            "DELETE",
            &format!("/chats/{chat}"),
            Value::Null,
            &crate::library::gen_id("panel-proof"),
        )
        .await;
    }
    {
        let guard = f.wb.lock_unpoisoned();
        assert!(guard.panel_previews_of(&id).is_empty());
        assert!(hidden
            .iter()
            .all(|project| !guard.library.projects.contains_key(project)));
        assert!(
            hidden_forks
                .iter()
                .all(|agent| !guard.library.agents.contains_key(agent)),
            "DELETE retires every preview fork archetype"
        );
    }
    f.stop().await;
}

/// Long-lived infrastructure only. The socket client launcher must explicitly
/// invoke this exact ignored entrypoint and await its ready protocol; its ignored
/// status is never counted as a functional verdict.
#[tokio::test]
#[ignore]
async fn serve() {
    let mut f = Fixture::new().await;
    println!(
        "WS71_READY {}",
        json!({"protocol":"gaugedesk.panel-authoring-fixture.v1", "base":f.base,"owner":f.owner,"other":f.other})
    );
    tokio::task::spawn_blocking(|| {
        let _ = std::io::Read::read(&mut std::io::stdin(), &mut [0u8; 1]);
    })
    .await
    .unwrap();
    f.stop().await;
}

// Additional Home proof, deliberately separate from the ordinary router cases.
// Production middleware alone creates verified Actor/action-context extensions.
struct HomeFixture {
    inner: Fixture,
}
impl HomeFixture {
    async fn new() -> Self {
        let mut inner = Fixture::new().await;
        inner.stop().await;
        {
            let mut wb = inner.wb.lock_unpoisoned();
            wb.enable_hosted_home_mode();
            for (authority, role) in [("local-user", "owner"), ("panel-other", "owner")] {
                let membership = crate::org::MembershipRecord {
                    id: authority.into(),
                    op: crate::library::RecordOp::Upsert,
                    org_id: crate::org::ORG_ID.into(),
                    authority: authority.into(),
                    email: format!("{authority}@example.test"),
                    role: role.into(),
                    status: crate::org::MembershipStatus::Active,
                    managed_by_scim: false,
                    team: None,
                };
                wb.store_mut()
                    .append_record(
                        crate::org::ORG_SCOPE,
                        "membership",
                        &serde_json::to_string(&membership).unwrap(),
                    )
                    .unwrap();
            }
        }
        let mut f = Self { inner };
        f.listen().await;
        f
    }
    async fn listen(&mut self) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        self.inner.base = format!("http://{}", listener.local_addr().unwrap());
        let wb = self.inner.wb.clone();
        let app = crate::open_api::open_control_plane(wb.clone()).layer(
            axum::middleware::from_fn_with_state(wb, crate::home_routes::require_home_admission),
        );
        self.inner.service = Some(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
    }
    async fn reopen(&mut self) {
        self.inner.stop().await;
        self.inner.wb = crate::open_workbench(self.inner.root.path()).unwrap();
        {
            let mut wb = self.inner.wb.lock_unpoisoned();
            wb.set_identity_provider(Some(Arc::new(
                crate::identity::LoopbackIdentityProvider::new(),
            )));
            wb.enable_hosted_home_mode();
        }
        self.listen().await;
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Value,
        bearer: &str,
        admission: Option<&str>,
    ) -> (u16, Value) {
        let mut request = reqwest::Client::new()
            .request(
                method.parse().unwrap(),
                format!("{}{path}", self.inner.base),
            )
            .timeout(std::time::Duration::from_secs(20))
            .bearer_auth(bearer)
            .header("content-type", "application/json")
            .header("idempotency-key", crate::library::gen_id("home-panel"));
        if let Some(admission) = admission {
            request = request.header(crate::home_admission::HOME_ADMISSION_HEADER, admission);
        }
        if method != "GET" {
            request = request.body(serde_json::to_vec(&body).unwrap());
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
    async fn admit(&self, bearer: &str) -> String {
        let (status, value) = self
            .request("POST", "/home/admissions", Value::Null, bearer, None)
            .await;
        assert_eq!(status, 201, "{value}");
        assert_eq!(
            value["home"],
            self.inner.wb.lock_unpoisoned().home_id().as_str()
        );
        value["admission"].as_str().unwrap().to_owned()
    }
    async fn owner(&self, admission: &str, method: &str, path: &str, body: Value) -> Value {
        let (status, value) = self
            .request(method, path, body, &self.inner.owner, Some(admission))
            .await;
        assert!(
            (200..300).contains(&status),
            "{method} {path}: {status} {value}"
        );
        value
    }
    async fn denied(
        &self,
        admission: &str,
        revoked: &str,
        other_admission: &str,
        method: &str,
        path: &str,
        body: Value,
    ) {
        for (bearer, token, expected) in [
            (self.inner.owner.as_str(), None, 401),
            (self.inner.other.as_str(), Some(admission), 403),
            (self.inner.owner.as_str(), Some(other_admission), 403),
            (self.inner.owner.as_str(), Some(revoked), 403),
            // A genuinely admitted other identity still cannot author this Panel.
            (self.inner.other.as_str(), Some(other_admission), 403),
        ] {
            let before = self.inner.durable_shape();
            let (status, value) = self
                .request(method, path, body.clone(), bearer, token)
                .await;
            assert_eq!(status, expected, "{method} {path}: {value}");
            assert_eq!(
                self.inner.durable_shape(),
                before,
                "Home/author denial never mutates selected durable state"
            );
        }
    }
}

#[tokio::test]
async fn home_admission_all_four_routes_refuse_missing_mismatched_and_revoked_credentials() {
    let mut f = HomeFixture::new().await;
    let owner = f.admit(&f.inner.owner).await;
    let other = f.admit(&f.inner.other).await;
    let revoked = f.admit(&f.inner.owner).await;
    assert_ne!(owner, other);
    assert_ne!(owner, revoked);
    assert_eq!(
        f.request(
            "DELETE",
            "/home/admissions",
            Value::Null,
            &f.inner.owner,
            Some(&revoked)
        )
        .await
        .0,
        204
    );
    let (status, own_other) = f
        .request(
            "POST",
            "/archetypes",
            json!({"name":"Other Home author","kind":"panel"}),
            &f.inner.other,
            Some(&other),
        )
        .await;
    assert_eq!(status, 201, "{own_other}");
    assert_eq!(
        f.request(
            "GET",
            &format!("/archetypes/{}", own_other["id"].as_str().unwrap()),
            Value::Null,
            &f.inner.other,
            Some(&other)
        )
        .await
        .0,
        200
    );
    let source = f
        .owner(
            &owner,
            "POST",
            "/archetypes",
            json!({"name":"Home work source","kind":"work"}),
        )
        .await;
    let source = source["id"].as_str().unwrap();
    let before_source = f.inner.source_manifest(source);
    let copy_path = format!("/archetypes/{source}/copy-as-panel");
    f.denied(
        &owner,
        &revoked,
        &other,
        "POST",
        &copy_path,
        json!({"name":"Forbidden"}),
    )
    .await;
    let copy = f
        .owner(&owner, "POST", &copy_path, json!({"name":"Home Panel"}))
        .await;
    let id = copy["id"].as_str().unwrap();
    assert_ne!(id, source);
    assert_eq!(f.inner.source_manifest(source), before_source);
    let profile_path = format!("/archetypes/{id}/panel-profile");
    let profile = f.owner(&owner, "GET", &profile_path, Value::Null).await;
    f.denied(&owner, &revoked, &other, "GET", &profile_path, Value::Null)
        .await;
    f.denied(
        &owner,
        &revoked,
        &other,
        "PUT",
        &profile_path,
        profile.clone(),
    )
    .await;
    let mut changed = profile.clone();
    changed["panels"]["components"] = json!(["gw-chat", "gw-viewer"]);
    let saved = f.owner(&owner, "PUT", &profile_path, changed).await;
    assert_eq!(
        f.owner(&owner, "GET", &profile_path, Value::Null).await,
        saved
    );
    let published = f
        .owner(
            &owner,
            "POST",
            &format!("/archetypes/{id}/publish"),
            json!({}),
        )
        .await;
    let project = f
        .owner(
            &owner,
            "POST",
            "/projects",
            json!({"name":"Home preview project"}),
        )
        .await;
    let placed = f
        .owner(
            &owner,
            "POST",
            &format!("/projects/{}/placements", project["id"].as_str().unwrap()),
            json!({"agent_id":id}),
        )
        .await;
    let preview_path = format!("/archetypes/{id}/preview");
    f.denied(&owner, &revoked, &other, "POST", &preview_path, json!({}))
        .await;
    let before = f.owner(&owner, "GET", "/workspace", Value::Null).await;
    let pinned = f
        .owner(
            &owner,
            "POST",
            &preview_path,
            json!({"placement_id":placed["instance_id"]}),
        )
        .await;
    let draft = f.owner(&owner, "POST", &preview_path, json!({})).await;
    let replacement = f.owner(&owner, "POST", &preview_path, json!({})).await;
    assert_ne!(draft["id"], replacement["id"]);
    {
        let wb = f.inner.wb.lock_unpoisoned();
        assert!(!wb.library.chats.contains_key(draft["id"].as_str().unwrap()));
        assert_eq!(
            wb.panel_previews_of(id)
                .iter()
                .find(|p| p.chat_id == pinned["id"].as_str().unwrap())
                .unwrap()
                .version
                .map(|v| json!(v)),
            Some(published["version"].clone())
        );
    }
    for preview in [&pinned, &replacement] {
        f.owner(
            &owner,
            "DELETE",
            &format!("/chats/{}", preview["id"].as_str().unwrap()),
            Value::Null,
        )
        .await;
    }
    let after = f.owner(&owner, "GET", "/workspace", Value::Null).await;
    assert_eq!(after["projects"], before["projects"]);
    assert_eq!(after["recent"], before["recent"]);
    assert!(f
        .inner
        .wb
        .lock_unpoisoned()
        .panel_previews_of(id)
        .is_empty());
    f.reopen().await;
    let before = f.inner.durable_shape();
    assert_eq!(
        f.request(
            "GET",
            &profile_path,
            Value::Null,
            &f.inner.owner,
            Some(&owner)
        )
        .await
        .0,
        403
    );
    assert_eq!(f.inner.durable_shape(), before);
    let fresh = f.admit(&f.inner.owner).await;
    assert_ne!(fresh, owner);
    assert_eq!(
        f.owner(&fresh, "GET", &profile_path, Value::Null).await,
        saved
    );
    f.inner.stop().await;
}

#[tokio::test]
#[ignore]
async fn serve_home() {
    let mut f = HomeFixture::new().await;
    println!(
        "WS71_HOME_READY {}",
        json!({"protocol":"gaugedesk.panel-authoring-home-fixture.v1","base":f.inner.base,"owner":f.inner.owner,"other":f.inner.other})
    );
    tokio::task::spawn_blocking(|| {
        let _ = std::io::Read::read(&mut std::io::stdin(), &mut [0u8; 1]);
    })
    .await
    .unwrap();
    f.inner.stop().await;
}
