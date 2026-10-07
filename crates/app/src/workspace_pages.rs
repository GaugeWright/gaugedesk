//! Paged workspace reads (SCALE-3).
//!
//! `GET /workspace` returns the whole facet tree with every chat row inline,
//! and stays that way for the clients that read it. Beside it:
//!
//! - `GET /workspace/outline` — the same tree, scoped the same way, with no
//!   chat rows. It builds no chat row and observes no chat workspace, and it
//!   says `"chat_rows": "paged"` so an omitted list never reads as an empty
//!   one.
//! - `GET /workspace/chats` — one page of chat rows, either Recent
//!   (`created_position` newest first) or one chat root's (an Agent's
//!   authoring instance or a project placement, oldest first, the tree's
//!   order). The caller's visibility is applied to records before a row is
//!   built, so an invisible chat is never projected and its workspace never
//!   observed.
//!
//! The cursor is the last returned row's `(created_position, id)`, by value.
//! Positions are store positions, so a chat admitted while a reader pages
//! sorts at the head of Recent or the tail of a root and can never repeat or
//! displace a row that existed when traversal began; a row removed meanwhile
//! is simply absent. Changes during traversal reach the reader through
//! `/workspace/events`, as they always have.

use std::cmp::Ordering;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use gaugedesk_core::freshness::Freshness;
use serde::Deserialize;

use crate::library::{self, ChatRecord, InstanceKind};
use crate::library_routes::{own_product_project, recent_row_visible, scope_workspace_value};
use crate::workbench_auth::ProjectVisibility;
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};

/// Rows a page carries when the reader names no limit.
pub const DEFAULT_PAGE_ROWS: usize = 50;
/// The most rows one page carries, whatever the reader asks for.
pub const MAX_PAGE_ROWS: usize = 200;

/// Whether a workspace projection carries its chat rows inline.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WorkspaceChatRows {
    /// Every chat row, as `GET /workspace` has always served.
    Inline,
    /// No chat rows; they are read a page at a time.
    Paged,
}

/// Which list of chats a page walks.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WorkspaceChatLens {
    /// Recent: every listed chat, newest first.
    Recent,
    /// One chat root — an Agent's authoring instance or a project placement —
    /// in the tree's order, oldest first.
    Root(String),
}

impl WorkspaceChatLens {
    fn compare(&self, a: (i64, &str), b: (i64, &str)) -> Ordering {
        match self {
            Self::Recent => b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)),
            Self::Root(_) => a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)),
        }
    }

    /// The lens's total order. It equals the inline projection's order: Recent
    /// is a stable newest-first sort over id order, a root's list a stable
    /// oldest-first one.
    pub fn order(&self, a: &ChatRecord, b: &ChatRecord) -> Ordering {
        self.compare(
            (a.created_position, a.id.as_str()),
            (b.created_position, b.id.as_str()),
        )
    }

    /// Whether `chat` sorts strictly after the row `cursor` names.
    pub fn follows(&self, cursor: &WorkspaceChatCursor, chat: &ChatRecord) -> bool {
        self.compare(
            (cursor.position, cursor.id.as_str()),
            (chat.created_position, chat.id.as_str()),
        ) == Ordering::Less
    }
}

/// The last row a page returned, by value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WorkspaceChatCursor {
    position: i64,
    id: String,
}

impl WorkspaceChatCursor {
    pub fn of(chat: &ChatRecord) -> Self {
        Self {
            position: chat.created_position,
            id: chat.id.clone(),
        }
    }

    /// The wire form. Readers treat it as opaque.
    pub fn encode(&self) -> String {
        format!("{}:{}", self.position, self.id)
    }

    pub fn decode(raw: &str) -> Option<Self> {
        let (position, id) = raw.split_once(':')?;
        let position = position.parse().ok()?;
        (!id.is_empty()).then(|| Self {
            position,
            id: id.to_owned(),
        })
    }
}

/// One page of chat rows and the cursor of the next, if there is one.
#[derive(Debug)]
pub struct WorkspaceChatPage {
    pub rows: Vec<serde_json::Value>,
    pub next: Option<WorkspaceChatCursor>,
}

/// `GET /workspace/outline`: the facet tree without chat rows.
pub async fn get_workspace_outline(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let vis = wb.project_visibility_in(
        crate::net_http::bearer(&headers),
        &crate::workbench_auth::req_scope(&headers),
    );
    let actor = crate::library_routes::workspace_actor(&wb, &headers);
    Json(scope_workspace_value(
        &wb,
        wb.workspace_value_shaped(WorkspaceChatRows::Paged),
        &vis,
        actor.as_deref(),
    ))
    .into_response()
}

#[derive(Deserialize, Default)]
pub struct ChatPageQuery {
    /// A chat root's id; absent for Recent.
    pub root: Option<String>,
    /// The previous page's `next_cursor`.
    pub after: Option<String>,
    pub limit: Option<usize>,
}

/// Why a page request is refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ChatPageError {
    BadCursor,
    BadLimit,
    /// No such root, or one the caller may not see — the two are one answer.
    NoSuchRoot,
}

impl IntoResponse for ChatPageError {
    fn into_response(self) -> axum::response::Response {
        let (status, error) = match self {
            Self::BadCursor => (StatusCode::BAD_REQUEST, "unreadable chat page cursor"),
            Self::BadLimit => (
                StatusCode::BAD_REQUEST,
                "a chat page limit is between 1 and 200",
            ),
            Self::NoSuchRoot => (StatusCode::NOT_FOUND, "no such chat root"),
        };
        (status, Json(serde_json::json!({ "error": error }))).into_response()
    }
}

/// `GET /workspace/chats`: one page of chat rows the caller may see.
pub async fn get_workspace_chats(
    State(wb): State<SharedWorkbench>,
    Query(query): Query<ChatPageQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let vis = wb.project_visibility_in(
        crate::net_http::bearer(&headers),
        &crate::workbench_auth::req_scope(&headers),
    );
    let actor = crate::library_routes::workspace_actor(&wb, &headers);
    match chat_page_value(&wb, &query, &vis, actor.as_deref()) {
        Ok(value) => Json(value).into_response(),
        Err(error) => error.into_response(),
    }
}

/// The body of `GET /workspace/chats`, separated from the handler so tests
/// can read it under any visibility.
pub fn chat_page_value(
    wb: &Workbench,
    query: &ChatPageQuery,
    vis: &ProjectVisibility,
    actor: Option<&str>,
) -> Result<serde_json::Value, ChatPageError> {
    let limit = match query.limit {
        None => DEFAULT_PAGE_ROWS,
        Some(limit) if (1..=MAX_PAGE_ROWS).contains(&limit) => limit,
        Some(_) => return Err(ChatPageError::BadLimit),
    };
    let after = query
        .after
        .as_deref()
        .map(|raw| WorkspaceChatCursor::decode(raw).ok_or(ChatPageError::BadCursor))
        .transpose()?;
    let page = match query.root.as_deref() {
        None => wb.workspace_chat_page(&WorkspaceChatLens::Recent, after.as_ref(), limit, |chat| {
            recent_row_visible(wb, &chat.id, vis, actor)
        }),
        Some(root) => {
            let authoring = root_visibility(wb, root, vis, actor)?;
            wb.workspace_chat_page(
                &WorkspaceChatLens::Root(root.to_owned()),
                after.as_ref(),
                limit,
                |chat| !authoring || wb.authoring_chat_visible(&chat.id, actor) == Some(true),
            )
        }
    };
    let generated_at = wb.lifecycle_projection_generated_at(library::LIBRARY_SCOPE);
    Ok(serde_json::json!({
        "rows": page.rows,
        "next_cursor": page.next.as_ref().map(WorkspaceChatCursor::encode),
        "freshness": Freshness::live(generated_at),
    }))
}

/// Whether the caller may list `root`'s chats, exactly as the scoped whole
/// workspace would show them; `Ok(true)` for an Agent's authoring root, whose
/// chats are then filtered one by one.
fn root_visibility(
    wb: &Workbench,
    root: &str,
    vis: &ProjectVisibility,
    actor: Option<&str>,
) -> Result<bool, ChatPageError> {
    let instance = wb
        .library
        .instances
        .get(root)
        .ok_or(ChatPageError::NoSuchRoot)?;
    match instance.kind {
        InstanceKind::Authoring => {
            let listed = wb
                .library
                .agents
                .get(&instance.agent_id)
                .is_some_and(|agent| {
                    agent.instance_id == root
                        && !crate::panel_preview::is_panel_preview_agent(agent)
                        && wb.agent_authoring_visible(&agent.id, actor)
                });
            listed.then_some(true).ok_or(ChatPageError::NoSuchRoot)
        }
        InstanceKind::Using => {
            let listed = instance.project_id.as_deref().is_some_and(|project_id| {
                wb.library.projects.get(project_id).is_some_and(|project| {
                    wb.owns_project(project_id)
                        && !crate::panel_preview::is_panel_preview_project(project)
                        && own_product_project(wb, project_id, actor)
                        && (matches!(vis, ProjectVisibility::All) || vis.allows(project_id))
                })
            });
            listed.then_some(false).ok_or(ChatPageError::NoSuchRoot)
        }
    }
}

#[cfg(test)]
#[path = "workspace_pages_tests.rs"]
mod tests;
