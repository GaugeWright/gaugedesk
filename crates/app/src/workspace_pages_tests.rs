//! SCALE-3: paged workspace reads agree exactly with the whole workspace,
//! stay stable while chats are admitted, and never list what the caller may
//! not see.
use std::collections::{BTreeSet, HashSet};

use axum::{body::Body, http::Request, Router};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::*;
use crate::library_routes::general_placement_id;

async fn get(app: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn post(app: &Router, uri: &str, body: &str, key: &str) -> serde_json::Value {
    let response = app
        .clone()
        .oneshot(
            Request::post(uri)
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        status.is_success(),
        "{uri}: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

struct Fixture {
    _root: tempfile::TempDir,
    wb: SharedWorkbench,
    app: Router,
    keys: usize,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::workbench_state::open_lean_workbench(root.path()).unwrap();
        let app = crate::open_route_stack::open_control_plane(wb.clone());
        Self {
            _root: root,
            wb,
            app,
            keys: 0,
        }
    }

    fn key(&mut self) -> String {
        self.keys += 1;
        format!("workspace-pages-{}", self.keys)
    }

    /// A project and the target its general placement's chats run on.
    async fn project(&mut self, name: &str) -> (String, String) {
        let key = self.key();
        let project = post(
            &self.app,
            "/projects",
            &format!(r#"{{"name":"{name}"}}"#),
            &key,
        )
        .await;
        (
            project["id"].as_str().unwrap().to_owned(),
            project["target_id"].as_str().unwrap().to_owned(),
        )
    }

    async fn chat(&mut self, project: &(String, String), title: &str) -> String {
        let (project_id, target_id) = project;
        let key = self.key();
        let chat = post(
            &self.app,
            &format!(
                "/projects/{project_id}/placements/{}/chats",
                general_placement_id(project_id)
            ),
            &format!(r#"{{"title":"{title}","target_id":"{target_id}"}}"#),
            &key,
        )
        .await;
        chat["id"].as_str().unwrap().to_owned()
    }

    /// Every row of a lens, a page at a time, with the cursors it followed.
    async fn traverse(&self, query: &str, limit: usize) -> Vec<serde_json::Value> {
        let mut rows = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let mut uri = format!("/workspace/chats?limit={limit}{query}");
            if let Some(cursor) = &after {
                uri.push_str(&format!("&after={}", urlencode(cursor)));
            }
            let (status, page) = get(&self.app, &uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}: {page}");
            let page_rows = page["rows"].as_array().unwrap();
            assert!(page_rows.len() <= limit);
            rows.extend(page_rows.iter().cloned());
            match page["next_cursor"].as_str() {
                Some(cursor) => after = Some(cursor.to_owned()),
                None => return rows,
            }
        }
    }
}

fn urlencode(raw: &str) -> String {
    raw.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn ids(rows: &[serde_json::Value]) -> Vec<String> {
    rows.iter()
        .map(|row| row["id"].as_str().unwrap().to_owned())
        .collect()
}

fn placement<'a>(workspace: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    workspace["projects"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|project| project["placements"].as_array().unwrap())
        .find(|placement| placement["placement_id"] == id)
        .unwrap()
}

/// Strip what the outline leaves to pages, so the two shapes compare whole.
fn without_chat_rows(mut workspace: serde_json::Value) -> serde_json::Value {
    let object = workspace.as_object_mut().unwrap();
    object.remove("recent");
    object.remove("chat_rows");
    for agent in workspace["archetypes"].as_array_mut().unwrap() {
        agent.as_object_mut().unwrap().remove("chats");
        for preview in agent["previews"].as_array_mut().unwrap() {
            preview.as_object_mut().unwrap().remove("chat");
        }
    }
    for project in workspace["projects"].as_array_mut().unwrap() {
        for placement in project["placements"].as_array_mut().unwrap() {
            placement.as_object_mut().unwrap().remove("chats");
        }
    }
    workspace
}

#[tokio::test]
async fn pages_traverse_exactly_the_whole_workspace() {
    let mut fixture = Fixture::new();
    let acme = fixture.project("acme").await;
    let peach = fixture.project("peach").await;
    for n in 0..5 {
        fixture.chat(&acme, &format!("acme {n}")).await;
        fixture.chat(&peach, &format!("peach {n}")).await;
    }
    let (status, whole) = get(&fixture.app, "/workspace").await;
    assert_eq!(status, StatusCode::OK);

    // Recent, a page of two at a time, is the whole Recent list row for row.
    let recent = fixture.traverse("", 2).await;
    assert_eq!(&serde_json::Value::from(recent), &whole["recent"]);

    // A placement's pages are its inline chat list row for row.
    let root = general_placement_id(&acme.0);
    let rows = fixture.traverse(&format!("&root={root}"), 3).await;
    assert_eq!(
        &serde_json::Value::from(rows),
        &placement(&whole, &root)["chats"]
    );

    // An Agent's authoring root pages the same way as its inline edit chats.
    let agent = whole["archetypes"].as_array().unwrap()[0].clone();
    let rows = fixture
        .traverse(
            &format!("&root={}", agent["instance_id"].as_str().unwrap()),
            1,
        )
        .await;
    assert_eq!(serde_json::Value::from(rows), agent["chats"]);

    // The outline is the whole tree with no chat row in it.
    let (status, outline) = get(&fixture.app, "/workspace/outline").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(outline["chat_rows"], "paged");
    assert!(outline.get("recent").is_none());
    assert!(placement(&outline, &root).get("chats").is_none());
    assert_eq!(without_chat_rows(outline), without_chat_rows(whole));
}

/// A Panel agent's preview chat is a chat row like any other: the whole tree
/// projects it under `previews[].chat`, and the outline keeps the preview and
/// its `chat_id` without building the row.
#[tokio::test]
async fn the_outline_names_a_preview_chat_without_projecting_it() {
    let mut fixture = Fixture::new();
    let key = fixture.key();
    let agent = post(
        &fixture.app,
        "/archetypes",
        r#"{"name":"Intake","kind":"panel"}"#,
        &key,
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap().to_owned();
    let key = fixture.key();
    let chat = post(
        &fixture.app,
        &format!("/archetypes/{agent_id}/preview"),
        "{}",
        &key,
    )
    .await;
    let chat_id = chat["id"].as_str().unwrap().to_owned();

    let panel = |workspace: &serde_json::Value| {
        workspace["archetypes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["id"] == agent_id.as_str())
            .unwrap()
            .clone()
    };
    let (status, whole) = get(&fixture.app, "/workspace").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(panel(&whole)["previews"][0]["chat"]["id"], chat_id.as_str());

    let (status, outline) = get(&fixture.app, "/workspace/outline").await;
    assert_eq!(status, StatusCode::OK);
    let preview = &panel(&outline)["previews"][0];
    assert_eq!(preview["chat_id"], chat_id.as_str());
    assert!(preview.get("chat").is_none(), "{preview}");
    assert_eq!(without_chat_rows(outline), without_chat_rows(whole));
}

#[tokio::test]
async fn a_traversal_neither_repeats_nor_drops_a_row_while_chats_are_admitted() {
    let mut fixture = Fixture::new();
    let acme = fixture.project("acme").await;
    for n in 0..6 {
        fixture.chat(&acme, &format!("before {n}")).await;
    }
    let root = general_placement_id(&acme.0);
    for query in [String::new(), format!("&root={root}")] {
        let (_, whole) = get(&fixture.app, "/workspace").await;
        let expected: BTreeSet<String> = if query.is_empty() {
            ids(whole["recent"].as_array().unwrap())
                .into_iter()
                .collect()
        } else {
            ids(placement(&whole, &root)["chats"].as_array().unwrap())
                .into_iter()
                .collect()
        };

        let mut seen = Vec::new();
        let mut admitted = HashSet::new();
        let mut after: Option<String> = None;
        loop {
            let mut uri = format!("/workspace/chats?limit=2{query}");
            if let Some(cursor) = &after {
                uri.push_str(&format!("&after={}", urlencode(cursor)));
            }
            let (status, page) = get(&fixture.app, &uri).await;
            assert_eq!(status, StatusCode::OK, "{page}");
            seen.extend(ids(page["rows"].as_array().unwrap()));
            // Two chats are admitted between each of the first pairs of
            // pages. A root's admits sort at its tail and are read, so they
            // stop before the traversal could chase them forever.
            for _ in 0..if admitted.len() < 6 { 2 } else { 0 } {
                let title = format!("during {}", admitted.len());
                admitted.insert(fixture.chat(&acme, &title).await);
            }
            match page["next_cursor"].as_str() {
                Some(cursor) => after = Some(cursor.to_owned()),
                None => break,
            }
        }
        let unique: BTreeSet<String> = seen.iter().cloned().collect();
        assert_eq!(unique.len(), seen.len(), "no row repeats: {seen:?}");
        let original: BTreeSet<String> = unique
            .iter()
            .filter(|id| !admitted.contains(*id))
            .cloned()
            .collect();
        assert_eq!(original, expected, "every row that existed is read once");
        if query.is_empty() {
            // Recent is newest first, so a chat admitted mid-traversal sorts
            // ahead of the cursor and is left to the event stream.
            assert!(seen.iter().all(|id| !admitted.contains(id)));
        }
    }
}

#[tokio::test]
async fn a_page_lists_only_what_the_caller_may_see() {
    let mut fixture = Fixture::new();
    let acme = fixture.project("acme").await;
    let peach = fixture.project("peach").await;
    for n in 0..3 {
        fixture.chat(&acme, &format!("acme {n}")).await;
        fixture.chat(&peach, &format!("peach {n}")).await;
    }
    let wb = fixture.wb.lock_unpoisoned();
    let vis = ProjectVisibility::Only(BTreeSet::from([acme.0.clone()]));
    let actor = Some("member");
    let scoped = scope_workspace_value(&wb, wb.workspace_value(), &vis, actor);

    let mut rows = Vec::new();
    let mut after = None;
    loop {
        let page = chat_page_value(
            &wb,
            &ChatPageQuery {
                root: None,
                after,
                limit: Some(2),
            },
            &vis,
            actor,
        )
        .unwrap();
        rows.extend(page["rows"].as_array().unwrap().iter().cloned());
        match page["next_cursor"].as_str() {
            Some(cursor) => after = Some(cursor.to_owned()),
            None => break,
        }
    }
    assert_eq!(serde_json::Value::from(rows.clone()), scoped["recent"]);
    assert_eq!(rows.len(), 3);
    assert!(rows
        .iter()
        .all(|row| wb.library.project_of_chat(row["id"].as_str().unwrap()) == Some(&acme.0)));

    // A root the caller may not see is answered as one that does not exist.
    for root in [general_placement_id(&peach.0), "no-such-root".to_owned()] {
        let refused = chat_page_value(
            &wb,
            &ChatPageQuery {
                root: Some(root),
                after: None,
                limit: None,
            },
            &vis,
            actor,
        );
        assert_eq!(refused.unwrap_err(), ChatPageError::NoSuchRoot);
    }
    // An Agent's edit chats are its author's alone.
    let agent_root = wb
        .library
        .agents
        .values()
        .next()
        .unwrap()
        .instance_id
        .clone();
    let refused = chat_page_value(
        &wb,
        &ChatPageQuery {
            root: Some(agent_root),
            after: None,
            limit: None,
        },
        &vis,
        actor,
    );
    assert_eq!(refused.unwrap_err(), ChatPageError::NoSuchRoot);
}

#[tokio::test]
async fn an_unreadable_request_is_refused() {
    let mut fixture = Fixture::new();
    let acme = fixture.project("acme").await;
    fixture.chat(&acme, "one").await;
    for (uri, status) in [
        ("/workspace/chats?after=nonsense", StatusCode::BAD_REQUEST),
        ("/workspace/chats?after=12:", StatusCode::BAD_REQUEST),
        ("/workspace/chats?limit=0", StatusCode::BAD_REQUEST),
        ("/workspace/chats?limit=201", StatusCode::BAD_REQUEST),
        ("/workspace/chats?root=no-such-root", StatusCode::NOT_FOUND),
    ] {
        let (actual, body) = get(&fixture.app, uri).await;
        assert_eq!(actual, status, "{uri}: {body}");
    }
}

#[test]
fn a_cursor_round_trips_an_id_containing_its_separator() {
    let cursor = WorkspaceChatCursor {
        position: 42,
        id: "chat:with:colons".into(),
    };
    assert_eq!(WorkspaceChatCursor::decode(&cursor.encode()), Some(cursor));
    assert_eq!(WorkspaceChatCursor::decode("x:chat"), None);
}
