//! DR-0453, two accounts end to end over a real test relay: a member of a
//! shared project authors, tries, publishes and deploys the Agent placed in
//! it, as the owner would, while the deployment stays the owner's. A viewer of
//! the same project does none of it; the member reaches none of the owner's
//! other Agents; and taking the grant away ends it.
use super::reachability_tests::{carried_json, reachable_home_and_workbench, routed};
use crate::LockUnpoisoned;
use serde_json::json;

const OWNER: &str = "account-root";
const MEMBER: &str = "invitee-account";

/// The owner invites `email` to the shared project with `role`, from the
/// computer, as Project Settings does; the invitee accepts over the relay
/// and is admitted. Answers the headers its calls carry.
async fn invited(
    wb: &crate::SharedWorkbench,
    client: std::net::SocketAddr,
    email: &str,
    role: &str,
    bearer: &'static str,
) -> Vec<(&'static str, String)> {
    let owner_session = {
        let wb = wb.clone();
        tokio::task::spawn_blocking(move || crate::desktop_session::home_session(&wb))
            .await
            .unwrap()
            .expect("the owner's window session")
    };
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {owner_session}").parse().unwrap(),
    );
    let created = crate::home_invitation::post_invitation(
        axum::extract::State(wb.clone()),
        headers,
        axum::Json(
            serde_json::from_value(json!({
                "email": email,
                "project": "proj-shared",
                "role": role,
                "endpoint": "",
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(created.status(), axum::http::StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(created.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let authorization = format!("Bearer {bearer}");
    let (status, accepted) = carried_json(
        client,
        "POST",
        "/home/invitations/accept",
        &[("authorization", authorization.as_str())],
        Some(json!({ "invite": created["invite"] })),
    )
    .await;
    assert_eq!(status, 200, "{email} accepts over the relay: {accepted}");
    let (status, admitted) = carried_json(
        client,
        "POST",
        "/home/admissions",
        &[("authorization", authorization.as_str())],
        None,
    )
    .await;
    assert_eq!(status, 201, "{email} is admitted: {admitted}");
    vec![
        ("authorization", authorization),
        (
            "x-gaugewright-home-admission",
            admitted["admission"].as_str().unwrap().to_owned(),
        ),
    ]
}

/// One call over the relay as the account `headers` admit.
async fn call(
    client: std::net::SocketAddr,
    headers: &[(&'static str, String)],
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value) {
    let headers: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    carried_json(client, method, path, &headers, body).await
}

/// The ids of the Agents the caller's Workshop lists.
fn workshop(workspace: &serde_json::Value) -> Vec<String> {
    workspace["archetypes"]
        .as_array()
        .expect("archetypes")
        .iter()
        .filter_map(|agent| agent["id"].as_str().map(str::to_owned))
        .collect()
}

/// The Panel profile the member saves: the draft's, pinned to a model the
/// owner's key serves and with a shorter resumption window.
fn edited_profile() -> serde_json::Value {
    let mut profile = crate::library::PanelPublicProfile::default();
    profile.model.pinned = Some("gpt-5.5".to_owned());
    profile.retention.idle_ttl_seconds = 3_600;
    serde_json::to_value(profile).unwrap()
}

#[tokio::test]
async fn a_member_authors_tests_publishes_and_deploys_the_shared_projects_agent() {
    let _fake_agent = crate::test_support::fake_agent_env();
    let (_relay, root, wb, client, tasks) = reachable_home_and_workbench().await;
    // The owner's Panel agent, placed in the shared project, and another of
    // the owner's Agents placed only in its own private project.
    let (agent, private_agent) = {
        let mut guard = wb.lock_unpoisoned();
        for (id, name) in [("proj-shared", "Shared"), ("proj-private", "Private")] {
            let mut extra = std::collections::BTreeMap::new();
            crate::project_owner::record_owner(&mut extra, OWNER);
            crate::library_routes::create_named_project_with_extra(&mut guard, id, name, extra)
                .expect("project");
        }
        let mut agents = Vec::new();
        for (name, project) in [
            ("Customer panel", "proj-shared"),
            ("Owner's own panel", "proj-private"),
        ] {
            let created = guard
                .create_archetype(
                    name.to_owned(),
                    crate::library::AgentKind::Panel,
                    Some(OWNER.to_owned()),
                )
                .unwrap_or_else(|_| panic!("the owner creates {name}"));
            let placement = guard
                .bind_agent_to_project(project, &created.id, None)
                .unwrap_or_else(|_| panic!("the owner places {name}"));
            assert_eq!(
                guard.agent_authoring_owner(&created.id).as_deref(),
                Some(OWNER),
                "the owner authors {name}"
            );
            agents.push((created.id, placement));
        }
        (agents[0].clone(), agents[1].clone())
    };
    let ((agent, placement), (private_agent, private_placement)) = (
        (agent.0.as_str(), agent.1.as_str()),
        (private_agent.0.as_str(), private_agent.1.as_str()),
    );
    assert!(routed(&wb, "proj-shared").await, "a relay route");

    let member = invited(
        &wb,
        client,
        "invitee@example.test",
        "member",
        "invitee-bearer",
    )
    .await;
    let viewer = invited(
        &wb,
        client,
        "viewer@example.test",
        "viewer",
        "viewer-bearer",
    )
    .await;

    // The member's Workshop lists the shared project's Agent, and none of
    // the owner's others; a viewer's lists neither.
    let (status, workspace) = call(client, &member, "GET", "/workspace", None).await;
    assert_eq!(status, 200, "{workspace}");
    assert_eq!(workshop(&workspace), [agent], "{workspace}");
    assert_eq!(
        workspace["archetypes"][0]["shared_through"],
        json!(["proj-shared"]),
        "the member's Workshop names the project it reaches the Agent through"
    );
    let (status, workspace) = call(client, &viewer, "GET", "/workspace", None).await;
    assert_eq!(status, 200, "{workspace}");
    assert!(workshop(&workspace).is_empty(), "{workspace}");

    // The member opens the Agent's authoring chat and talks to it.
    let (status, chat) = call(
        client,
        &member,
        "POST",
        &format!("/archetypes/{agent}/chats"),
        Some(json!({ "title": "Customer edits" })),
    )
    .await;
    assert_eq!(status, 201, "the member opens an edit chat: {chat}");
    let edit_chat = chat["id"].as_str().expect("an edit chat").to_owned();
    let (status, answer) = call(
        client,
        &member,
        "POST",
        &format!("/chats/{edit_chat}/task"),
        Some(json!({ "prompt": "Greet visitors by name." })),
    )
    .await;
    assert_eq!(status, 200, "the member's edit chat answers: {answer}");
    let (status, transcript) = call(
        client,
        &member,
        "GET",
        &format!("/chats/{edit_chat}/transcript"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{transcript}");
    assert!(
        transcript.to_string().contains("Greet visitors by name."),
        "{transcript}"
    );
    {
        let guard = wb.lock_unpoisoned();
        assert_eq!(
            guard.library.chats[&edit_chat].owner.as_deref(),
            Some(MEMBER),
            "the edit chat is the member's own"
        );
        assert_eq!(
            guard
                .member_authoring_project_of_chat(&edit_chat, MEMBER)
                .as_deref(),
            Some("proj-shared"),
            "the member's edit chat spends the shared project's credentials"
        );
    }

    // The member changes Agent Settings: abilities and the Panel profile, and
    // opens the settings app the settings assistant works in.
    let (status, abilities) = call(
        client,
        &member,
        "PUT",
        &format!("/archetypes/{agent}/abilities"),
        Some(json!({ "abilities": ["workspace.read", "workspace.write"] })),
    )
    .await;
    assert_eq!(status, 200, "the member sets abilities: {abilities}");
    let (status, profile) = call(
        client,
        &member,
        "PUT",
        &format!("/archetypes/{agent}/panel-profile"),
        Some(edited_profile()),
    )
    .await;
    assert_eq!(status, 200, "the member sets the Panel profile: {profile}");
    let (status, session) = call(
        client,
        &member,
        "POST",
        &format!("/archetypes/{agent}/settings/sessions"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200, "the member opens Agent Settings: {session}");

    // The member tries the draft in a preview chat of its own.
    let (status, preview) = call(
        client,
        &member,
        "POST",
        &format!("/archetypes/{agent}/preview"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 201, "the member starts a preview: {preview}");
    let preview_chat = preview["id"].as_str().expect("a preview chat").to_owned();
    let (status, answer) = call(
        client,
        &member,
        "POST",
        &format!("/chats/{preview_chat}/task"),
        Some(json!({ "prompt": "Hello, Panel." })),
    )
    .await;
    assert_eq!(status, 200, "the member's preview answers: {answer}");
    {
        let guard = wb.lock_unpoisoned();
        let project = guard
            .panel_preview_project_of_chat(&preview_chat)
            .expect("a preview's hidden project");
        assert_eq!(
            guard.panel_preview_started_by(&project).as_deref(),
            Some(MEMBER)
        );
        assert_eq!(
            guard
                .member_authoring_project_of_chat(&preview_chat, MEMBER)
                .as_deref(),
            Some("proj-shared"),
            "the member's preview spends the shared project's credentials"
        );
    }

    // The member publishes a new version: the owner stays its publisher.
    let (status, published) = call(
        client,
        &member,
        "POST",
        &format!("/archetypes/{agent}/publish"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200, "the member publishes: {published}");
    assert_eq!(published["version"], 2, "{published}");
    {
        let guard = wb.lock_unpoisoned();
        let version = &guard.library.agents[agent].versions[&2];
        assert_eq!(version.source_owner_authority.as_deref(), Some(OWNER));
        assert_eq!(version.requested_by.as_deref(), Some(MEMBER));
        assert_eq!(
            version
                .panel_profile
                .as_ref()
                .map(|profile| profile.retention.idle_ttl_seconds),
            Some(3_600),
            "the member's settings are what was published"
        );
    }

    // The member upgrades the Panel placement and deploys it.
    let (status, upgraded) = call(
        client,
        &member,
        "POST",
        &format!("/placements/{placement}/upgrade"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200, "the member upgrades the placement: {upgraded}");
    assert_eq!(upgraded["version"], 2, "{upgraded}");

    let (edge, seen) = crate::project_owner::tests::recording_edge();
    let deployment = json!({
        "placement_id": placement,
        "deployment_id": "customer",
        "edge_origin": edge,
        "allowed_origins": ["https://customer.example"],
        "per_visitor_turn_limit": 5,
        "max_concurrent_sessions": 5,
        "funding": { "kind": "byok", "credential_ref": "credential:public:mine:openai:key" },
        "audience": { "anonymous_allowed": true },
        "white_label": false,
        "retention_idle_ttl_seconds": 3_600,
        "retention_absolute_ttl_seconds": 86_400,
        "end_sessions": false,
    });
    let encoded_edge = edge.replace(':', "%3A").replace('/', "%2F");
    let (status, key) = call(
        client,
        &member,
        "GET",
        &format!(
            "/public-deployments/publisher-authority?placement_id={placement}&edge_origin={encoded_edge}&deployment_id=customer"
        ),
        None,
    )
    .await;
    assert_eq!(status, 200, "the member reads the publication's key: {key}");
    let (status, listed) = call(
        client,
        &member,
        "POST",
        "/public-deployments/credentials/list",
        Some(json!({ "edge_origin": edge, "placement_id": placement })),
    )
    .await;
    assert_eq!(status, 200, "the member lists the owner's keys: {listed}");
    let (status, deployed) = call(
        client,
        &member,
        "POST",
        "/public-deployments",
        Some(deployment.clone()),
    )
    .await;
    assert_eq!(status, 200, "the member deploys: {deployed}");

    let owner_key = wb
        .lock_unpoisoned()
        .project_publisher_credential("proj-shared")
        .expect("the owner's publisher")
        .public_key();
    assert_eq!(key["public_key"], owner_key, "{key}");
    {
        let seen = seen.lock().unwrap();
        assert!(
            seen.iter()
                .any(|(command, ..)| command.starts_with("PUT /v1/releases/")),
            "{seen:?}"
        );
        for (command, _, presented, _) in seen.iter() {
            assert_eq!(
                presented, &owner_key,
                "{command} was signed by the owner's key"
            );
        }
        let release = seen
            .iter()
            .find(|(command, ..)| command.starts_with("PUT /v1/releases/"))
            .map(|(.., body)| body)
            .unwrap();
        let release: gaugedesk_core::agent_release::SignedAgentRelease =
            ciborium::from_reader(release.as_slice()).unwrap();
        assert_eq!(release.signer_public_key.as_str(), owner_key);
    }
    let keys = std::fs::read_dir(root.path().join("keys"))
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        !keys.iter().any(|name| name.contains(MEMBER)),
        "the member was given no publisher key here: {keys:?}"
    );
    {
        let guard = wb.lock_unpoisoned();
        let binding = guard
            .library
            .public_deployments
            .values()
            .find(|binding| binding.hosted_deployment_id == "customer")
            .expect("a binding");
        assert_eq!(binding.project_id, "proj-shared");
        assert_eq!(
            binding.extra[crate::agent_release::BINDING_REQUESTED_BY_EXTRA],
            MEMBER,
            "the binding records who asked"
        );
        let audit = crate::audit::list(guard.store_ref());
        for action in ["agent.publish", "placement.upgrade", "deployment.publish"] {
            assert!(
                audit
                    .iter()
                    .any(|entry| entry.actor == MEMBER && entry.action == action),
                "the audit names the member for {action}: {audit:?}"
            );
        }
    }

    // A viewer does none of it.
    for (method, path, body) in [
        ("GET", format!("/archetypes/{agent}"), None),
        (
            "POST",
            format!("/archetypes/{agent}/chats"),
            Some(json!({ "title": "no" })),
        ),
        (
            "PUT",
            format!("/archetypes/{agent}/abilities"),
            Some(json!({ "abilities": ["workspace.read"] })),
        ),
        (
            "PUT",
            format!("/archetypes/{agent}/panel-profile"),
            Some(edited_profile()),
        ),
        (
            "POST",
            format!("/archetypes/{agent}/settings/sessions"),
            Some(json!({})),
        ),
        (
            "POST",
            format!("/archetypes/{agent}/preview"),
            Some(json!({})),
        ),
        (
            "POST",
            format!("/archetypes/{agent}/publish"),
            Some(json!({})),
        ),
        (
            "POST",
            format!("/placements/{placement}/upgrade"),
            Some(json!({})),
        ),
        (
            "POST",
            "/public-deployments".to_owned(),
            Some(deployment.clone()),
        ),
        (
            "POST",
            "/public-deployments/inspect".to_owned(),
            Some(json!({ "deployment_id": "customer", "edge_origin": edge })),
        ),
        (
            "POST",
            format!("/chats/{edit_chat}/task"),
            Some(json!({ "prompt": "not yours" })),
        ),
    ] {
        let (status, answer) = call(client, &viewer, method, &path, body).await;
        assert_eq!(status, 403, "a viewer reached {method} {path}: {answer}");
    }

    // The member reaches none of the owner's other Agents, and none of what
    // stays the owner's own about this one.
    for (method, path, body) in [
        ("GET", format!("/archetypes/{private_agent}"), None),
        (
            "POST",
            format!("/archetypes/{private_agent}/chats"),
            Some(json!({ "title": "no" })),
        ),
        (
            "PUT",
            format!("/archetypes/{private_agent}/abilities"),
            Some(json!({ "abilities": ["workspace.read"] })),
        ),
        (
            "POST",
            format!("/archetypes/{private_agent}/settings/sessions"),
            Some(json!({})),
        ),
        (
            "POST",
            format!("/archetypes/{private_agent}/preview"),
            Some(json!({})),
        ),
        (
            "POST",
            format!("/archetypes/{private_agent}/publish"),
            Some(json!({})),
        ),
        (
            "POST",
            format!("/placements/{private_placement}/upgrade"),
            Some(json!({})),
        ),
        ("DELETE", format!("/archetypes/{agent}"), None),
        ("POST", format!("/archetypes/{agent}/fork"), Some(json!({}))),
        (
            "POST",
            "/archetypes".to_owned(),
            Some(json!({ "name": "mine" })),
        ),
        (
            "POST",
            "/public-deployments/control".to_owned(),
            Some(json!({
                "deployment_id": "customer",
                "edge_origin": edge,
                "command": "pause",
                "expected_revision": 1,
            })),
        ),
        (
            "POST",
            "/public-deployments/credentials/list".to_owned(),
            Some(json!({ "edge_origin": edge })),
        ),
        (
            "GET",
            "/public-deployments/publisher-authority".to_owned(),
            None,
        ),
    ] {
        let (status, answer) = call(client, &member, method, &path, body).await;
        assert_eq!(status, 403, "the member reached {method} {path}: {answer}");
    }

    // Taking the grant away ends it at once.
    {
        let mut guard = wb.lock_unpoisoned();
        let revoked = crate::org::MemberGrantRecord {
            id: crate::org::MemberGrantRecord::make_id(MEMBER, "proj-shared"),
            op: crate::org::RecordOp::Tombstone,
            authority: MEMBER.to_owned(),
            project_id: "proj-shared".to_owned(),
        };
        guard
            .store_mut()
            .append_record(
                crate::org::ORG_SCOPE,
                "member_grant",
                &serde_json::to_string(&revoked).unwrap(),
            )
            .unwrap();
        assert!(!guard.agent_authoring_visible(agent, Some(MEMBER)));
    }
    for (method, path, body) in [
        (
            "POST",
            format!("/archetypes/{agent}/chats"),
            Some(json!({ "title": "after" })),
        ),
        (
            "POST",
            format!("/chats/{edit_chat}/task"),
            Some(json!({ "prompt": "still here?" })),
        ),
        (
            "POST",
            format!("/archetypes/{agent}/publish"),
            Some(json!({})),
        ),
        ("POST", "/public-deployments".to_owned(), Some(deployment)),
    ] {
        let (status, answer) = call(client, &member, method, &path, body).await;
        assert_eq!(
            status, 403,
            "a revoked member reached {method} {path}: {answer}"
        );
    }
    tasks.iter().for_each(|task| task.abort());
}
