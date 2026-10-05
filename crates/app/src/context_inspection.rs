//! Reader-specific inspection of an exact imported context revision.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use gaugedesk_core::{
    boundary::Authority,
    resource::{ResourceId, ResourceKind, ResourceRecord},
    resource_access::{AccessCommand, AccessPhase, AccessState},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    err_response, method_access, net_http, resource_store, LockUnpoisoned, SharedWorkbench,
    Workbench,
};

struct SourceBasis {
    scope: String,
    required: BTreeSet<Authority>,
    revision: u64,
}

const REQUEST_KIND: &str = "context-inspection-request";

#[derive(Serialize, Deserialize)]
struct InspectionRequest {
    resource_id: String,
    revision: u64,
    reader: String,
}

fn source_basis(wb: &Workbench, chat_id: &str, rid: &str, reader: &str) -> Option<SourceBasis> {
    if reader.is_empty() || reader == "anonymous" {
        return None;
    }
    let record =
        resource_store::get(wb.store_ref(), chat_id, &ResourceId::new(rid.to_owned())).ok()??;
    if record.tombstoned || record.resource.kind != ResourceKind::context() {
        return None;
    }
    if resource_store::access_phase(wb.store_ref(), chat_id, &record.resource.id).ok()?
        != AccessPhase::Granted
    {
        return None;
    }
    let import = resource_store::context_imports(wb.store_ref(), chat_id)
        .ok()?
        .remove(rid)?;
    if !import.complete || import.files.is_empty() {
        return None;
    }
    let required = record.stakeholders;
    if required.is_empty()
        || required
            .iter()
            .any(|party| party.as_str().is_empty() || party.as_str() == "anonymous")
    {
        return None;
    }
    let key =
        serde_json::to_vec(&(chat_id, rid, import.revision, reader, "context-inspection")).ok()?;
    Some(SourceBasis {
        scope: format!("context-inspection::{}", hex::encode(Sha256::digest(key))),
        required,
        revision: import.revision,
    })
}

fn phase_label(phase: AccessPhase) -> &'static str {
    match phase {
        AccessPhase::Init => "init",
        AccessPhase::Requested => "requested",
        AccessPhase::Granted => "granted",
        AccessPhase::Revoked => "revoked",
        AccessPhase::Denied => "denied",
    }
}

pub(crate) fn source_granted(wb: &Workbench, chat_id: &str, rid: &str, reader: &str) -> bool {
    let Some(basis) = source_basis(wb, chat_id, rid, reader) else {
        return false;
    };
    wb.store_ref()
        .fold::<AccessState>(&basis.scope)
        .is_ok_and(|state| state.phase == AccessPhase::Granted && state.required == basis.required)
}

fn current_claims(wb: &Workbench, chat_id: &str, path: &str) -> Vec<(ResourceRecord, String)> {
    let Ok(imports) = resource_store::context_imports(wb.store_ref(), chat_id) else {
        return Vec::new();
    };
    let Ok(resources) = resource_store::list(wb.store_ref(), chat_id) else {
        return Vec::new();
    };
    // An older or failed import has no bounded path set. It might have
    // supplied this very path, so another resource's hash cannot prove
    // exclusive ownership until every context import is bound.
    if resources.iter().any(|record| {
        record.resource.kind == ResourceKind::context()
            && imports
                .get(record.resource.id.as_str())
                .is_none_or(|import| !import.complete)
    }) {
        return Vec::new();
    }
    let by_id: BTreeMap<_, _> = resources
        .into_iter()
        .map(|record| (record.resource.id.as_str().to_owned(), record))
        .collect();
    imports
        .into_iter()
        .filter_map(|(rid, import)| {
            let hash = import.files.get(path)?.clone();
            Some((by_id.get(&rid)?.clone(), hash))
        })
        .collect()
}

/// Exact import ownership, current source grant and retained bytes all hold at
/// the time of a viewer read. A path claimed by two current imports is unknown.
pub(crate) fn file_readable(
    wb: &Workbench,
    chat_id: &str,
    viewer: &str,
    path: &str,
    expected_hash: Option<&str>,
) -> bool {
    if !crate::engagement_routes::current_workspace_source_scope(wb, chat_id, path, true) {
        return false;
    }
    let claims = current_claims(wb, chat_id, path);
    let [(record, hash)] = claims.as_slice() else {
        return false;
    };
    if expected_hash.is_some_and(|expected| expected != hash) {
        return false;
    }
    if !source_granted(wb, chat_id, record.resource.id.as_str(), viewer) {
        return false;
    }
    let Some(bytes) = wb
        .read_engagement_file_bytes(chat_id, path, 8 * 1024 * 1024)
        .and_then(Result::ok)
        .flatten()
    else {
        return false;
    };
    hash == &whipplescript_store::stable_hash_bytes_hex(&bytes)
        && wb
            .engagement_recorded_file_cut(chat_id, path, &bytes)
            .and_then(Result::ok)
            .flatten()
            .is_some()
}

/// Whether `viewer` may read a worktree file of an account-backed chat.
///
/// A source grant protects someone else's imported content (DR-0242). A file
/// no one but the reader has a stake in — the agent's output, the reader's own
/// edits, the reader's own upload — is the chat's own work, readable by whoever
/// may read the chat, as it is in every other chat (DR-0317). Everything else is
/// read under [`file_readable`]'s exact source grant.
pub(crate) fn worktree_file_readable(
    wb: &Workbench,
    chat_id: &str,
    viewer: &str,
    path: &str,
    expected_hash: Option<&str>,
) -> bool {
    !others_have_a_stake(wb, chat_id, viewer, path)
        || file_readable(wb, chat_id, viewer, path, expected_hash)
}

/// Whether anyone but `viewer` may have supplied `path`, or erasure closed it:
/// an import that claims it for another person, or claims it for content since
/// erased, or another person's import whose path set is unknown and so might
/// have supplied any path. An unreadable resource store answers yes, so the
/// read falls to the grant.
fn others_have_a_stake(wb: &Workbench, chat_id: &str, viewer: &str, path: &str) -> bool {
    let (Ok(imports), Ok(resources)) = (
        resource_store::context_imports(wb.store_ref(), chat_id),
        resource_store::list(wb.store_ref(), chat_id),
    ) else {
        return true;
    };
    resources
        .iter()
        .filter(|record| record.resource.kind == ResourceKind::context())
        .any(|record| {
            let readers_alone = !record.stakeholders.is_empty()
                && record
                    .stakeholders
                    .iter()
                    .all(|party| party.as_str() == viewer);
            match imports.get(record.resource.id.as_str()) {
                Some(import) if import.complete => {
                    import.files.contains_key(path) && (record.tombstoned || !readers_alone)
                }
                _ => !readers_alone,
            }
        })
}

pub(crate) fn file_readable_from_resource(
    wb: &Workbench,
    chat_id: &str,
    viewer: &str,
    rid: &str,
    path: &str,
) -> bool {
    let claims = current_claims(wb, chat_id, path);
    let [(record, _)] = claims.as_slice() else {
        return false;
    };
    record.resource.id.as_str() == rid && worktree_file_readable(wb, chat_id, viewer, path, None)
}

/// A directory witness includes negative facts, so every current entry below
/// it must have an authorized file source. Empty directories have no owner
/// proof yet and remain redacted.
pub(crate) fn directory_readable(wb: &Workbench, chat_id: &str, viewer: &str, path: &str) -> bool {
    if !crate::engagement_routes::current_workspace_source_scope(wb, chat_id, path, true) {
        return false;
    }
    let Some(Ok(entries)) = wb.engagement_tree(chat_id) else {
        return false;
    };
    let prefix = format!("{path}/");
    let mut saw_file = false;
    for entry in entries
        .iter()
        .filter(|entry| entry.path.starts_with(&prefix))
    {
        if !entry.is_dir {
            saw_file = true;
            if !worktree_file_readable(wb, chat_id, viewer, &entry.path, None) {
                return false;
            }
        } else if !entries.iter().any(|candidate| {
            !candidate.is_dir && candidate.path.starts_with(&format!("{}/", entry.path))
        }) {
            return false;
        }
    }
    saw_file
}

/// The Files tree may show a directory name once it contains a file the
/// viewer may read, or while it holds no file at all and nobody else's import
/// could account for it. This does not authorize a Raw directory listing's
/// negative facts.
pub(crate) fn directory_visible(wb: &Workbench, chat_id: &str, viewer: &str, path: &str) -> bool {
    let Some(Ok(entries)) = wb.engagement_tree(chat_id) else {
        return false;
    };
    let prefix = format!("{path}/");
    let mut files = entries
        .iter()
        .filter(|entry| !entry.is_dir && entry.path.starts_with(&prefix))
        .peekable();
    if files.peek().is_none() {
        return !others_have_a_stake(wb, chat_id, viewer, path);
    }
    files.any(|entry| worktree_file_readable(wb, chat_id, viewer, &entry.path, None))
}

fn admitted_actor(
    wb: &Workbench,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, &'static str)> {
    let token = net_http::bearer(headers).ok_or((StatusCode::UNAUTHORIZED, "authenticate"))?;
    let verified = wb
        .authenticate_bearer(token)
        .ok_or((StatusCode::UNAUTHORIZED, "authenticate"))?;
    match wb.admit_data_request(Some(token), None) {
        Ok(actor) if actor == verified.as_str() => Ok(actor),
        _ => Err((StatusCode::UNAUTHORIZED, "authenticate")),
    }
}

pub(crate) async fn phase(
    State(shared): State<SharedWorkbench>,
    Path((chat_id, rid)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = shared.lock_unpoisoned();
    let reader = match method_access::chat_reader(&wb, &chat_id, &headers) {
        Ok(reader) => reader,
        Err(error) => return error.into_response(),
    };
    if !method_access::account_backed_chat(&wb, &chat_id, &headers) {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"phase":"unavailable"})),
        )
            .into_response();
    }
    let Some(basis) = source_basis(&wb, &chat_id, &rid, &reader) else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"phase":"unavailable"})),
        )
            .into_response();
    };
    match wb.store_ref().fold::<AccessState>(&basis.scope) {
        Ok(state) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "phase": phase_label(state.phase),
                "revision": basis.revision,
                "can_approve": basis.required.contains(&Authority::from(reader)),
            })),
        )
            .into_response(),
        Err(error) => err_response(error),
    }
}

pub(crate) async fn request(
    State(shared): State<SharedWorkbench>,
    Path((chat_id, rid)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = shared.lock_unpoisoned();
    let reader = match method_access::chat_reader(&wb, &chat_id, &headers) {
        Ok(reader) => reader,
        Err(error) => return error.into_response(),
    };
    if !method_access::account_backed_chat(&wb, &chat_id, &headers) {
        return (StatusCode::BAD_REQUEST, "solo inspection needs no grant").into_response();
    }
    let Some(basis) = source_basis(&wb, &chat_id, &rid, &reader) else {
        return (StatusCode::NOT_FOUND, "source import unavailable").into_response();
    };
    let request = InspectionRequest {
        resource_id: rid.clone(),
        revision: basis.revision,
        reader: reader.clone(),
    };
    let required = basis.required.clone();
    if let Err(error) = wb.store_mut().admit::<AccessState>(
        &basis.scope,
        AccessCommand::RequestAccess {
            required: required.clone(),
        },
    ) {
        return err_response(error);
    }
    let encoded = match serde_json::to_string(&request) {
        Ok(encoded) => encoded,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "request unavailable").into_response()
        }
    };
    if let Err(error) = wb
        .store_mut()
        .append_record(&chat_id, REQUEST_KIND, &encoded)
    {
        return err_response(error);
    }
    if required.len() == 1 && required.contains(&Authority::from(reader.clone())) {
        if let Err(error) = wb.store_mut().admit::<AccessState>(
            &basis.scope,
            AccessCommand::Approve(Authority::from(reader)),
        ) {
            return err_response(error);
        }
        return (StatusCode::OK, Json(serde_json::json!({"phase":"granted"}))).into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"phase":"requested"})),
    )
        .into_response()
}

pub(crate) async fn pending_requests(
    State(shared): State<SharedWorkbench>,
    Path((chat_id, rid)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = shared.lock_unpoisoned();
    let actor = match admitted_actor(&wb, &headers) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let Some(basis) = source_basis(&wb, &chat_id, &rid, &actor) else {
        return (StatusCode::NOT_FOUND, "source import unavailable").into_response();
    };
    if !basis.required.contains(&Authority::from(actor.clone())) {
        return (StatusCode::FORBIDDEN, "source approver required").into_response();
    }
    let rows = match wb.store_ref().records(&chat_id, REQUEST_KIND) {
        Ok(rows) => rows,
        Err(error) => return err_response(error),
    };
    let mut readers = BTreeSet::new();
    let mut granted = BTreeSet::new();
    for row in rows {
        let Ok(request) = serde_json::from_str::<InspectionRequest>(&row) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "request evidence unavailable",
            )
                .into_response();
        };
        if request.resource_id != rid || request.revision != basis.revision {
            continue;
        }
        let Some(reader_basis) = source_basis(&wb, &chat_id, &rid, &request.reader) else {
            continue;
        };
        if let Ok(state) = wb.store_ref().fold::<AccessState>(&reader_basis.scope) {
            if state.required != basis.required {
                continue;
            }
            if state.phase == AccessPhase::Requested
                && !state.approvals.contains(&Authority::from(actor.clone()))
            {
                readers.insert(request.reader);
            } else if state.phase == AccessPhase::Granted {
                granted.insert(request.reader);
            }
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"readers":readers,"granted":granted})),
    )
        .into_response()
}

pub(crate) async fn approve(
    State(shared): State<SharedWorkbench>,
    Path((chat_id, rid, reader)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = shared.lock_unpoisoned();
    let actor = match admitted_actor(&wb, &headers) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let Some(basis) = source_basis(&wb, &chat_id, &rid, &reader) else {
        return (StatusCode::NOT_FOUND, "source import unavailable").into_response();
    };
    if !basis.required.contains(&Authority::from(actor.clone())) {
        return (StatusCode::FORBIDDEN, "source approver required").into_response();
    }
    match wb
        .store_mut()
        .admit::<AccessState>(&basis.scope, AccessCommand::Approve(Authority::from(actor)))
    {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"approved":true}))).into_response(),
        Err(error) => err_response(error),
    }
}

pub(crate) async fn revoke(
    State(shared): State<SharedWorkbench>,
    Path((chat_id, rid, reader)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = shared.lock_unpoisoned();
    let actor = match admitted_actor(&wb, &headers) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let Some(basis) = source_basis(&wb, &chat_id, &rid, &reader) else {
        return (StatusCode::NOT_FOUND, "source import unavailable").into_response();
    };
    if actor != reader && !basis.required.contains(&Authority::from(actor)) {
        return (StatusCode::FORBIDDEN, "source grant party required").into_response();
    }
    match wb
        .store_mut()
        .admit::<AccessState>(&basis.scope, AccessCommand::Revoke)
    {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"phase":"revoked"}))).into_response(),
        Err(error) => err_response(error),
    }
}

pub(crate) async fn revoke_own(
    State(shared): State<SharedWorkbench>,
    Path((chat_id, rid)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = shared.lock_unpoisoned();
    let reader = match method_access::chat_reader(&wb, &chat_id, &headers) {
        Ok(reader) => reader,
        Err(error) => return error.into_response(),
    };
    let Some(basis) = source_basis(&wb, &chat_id, &rid, &reader) else {
        return (StatusCode::NOT_FOUND, "source import unavailable").into_response();
    };
    match wb
        .store_mut()
        .admit::<AccessState>(&basis.scope, AccessCommand::Revoke)
    {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"phase":"revoked"}))).into_response(),
        Err(error) => err_response(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{directory_visible, file_readable, source_basis, worktree_file_readable};
    use crate::{LockUnpoisoned, Workbench};
    use axum::{
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
    };
    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::{
        boundary::Authority,
        ids::AuthorityId,
        resource_access::{AccessCommand, AccessState},
    };
    use std::sync::Arc;

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers
    }

    fn imported(
        wb: &mut Workbench,
        chat_id: &str,
        owner: &str,
        label: &str,
        body: &[u8],
    ) -> (String, String) {
        let files = [("report.txt".to_owned(), body.to_vec())];
        let (_, cut) = wb
            .ingest_upload_into_engagement(chat_id, &files, None)
            .unwrap()
            .unwrap();
        let record = wb
            .mint_resource_context(chat_id, owner, label, &cut, Default::default())
            .unwrap();
        wb.bind_uploaded_context(chat_id, &record.resource.id, &files, None)
            .unwrap();
        let path = wb.engagement_workspace_path(chat_id, "report.txt");
        (record.resource.id.as_str().to_owned(), path)
    }

    fn grant(wb: &mut Workbench, chat_id: &str, rid: &str, reader: &str) {
        let basis = source_basis(wb, chat_id, rid, reader).unwrap();
        wb.store_mut()
            .admit::<AccessState>(
                &basis.scope,
                AccessCommand::RequestAccess {
                    required: basis.required.clone(),
                },
            )
            .unwrap();
        for approver in basis.required {
            wb.store_mut()
                .admit::<AccessState>(&basis.scope, AccessCommand::Approve(approver))
                .unwrap();
        }
    }

    #[test]
    fn imported_file_needs_exact_reader_revision_and_current_bytes() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        let chat = wb
            .create_default_engagement("source-grant-chat".into(), "Source grant".into())
            .unwrap_or_else(|_| panic!("create source grant chat"));
        let (rid, path) = imported(&mut wb, &chat.id, "alice", "upload-a", b"first");
        assert!(!file_readable(&wb, &chat.id, "bob", &path, None));
        grant(&mut wb, &chat.id, &rid, "bob");
        assert!(file_readable(&wb, &chat.id, "bob", &path, None));
        assert!(!file_readable(&wb, &chat.id, "carol", &path, None));
        assert!(!file_readable(&wb, &chat.id, "bob", &path, Some("wrong")));

        // Re-ingest replaces the binding revision, even with the same resource
        // handle and reader. The old grant cannot carry forward.
        let (same_rid, same_path) = imported(&mut wb, &chat.id, "alice", "upload-a", b"second");
        assert_eq!(rid, same_rid);
        assert_eq!(path, same_path);
        assert!(!file_readable(&wb, &chat.id, "bob", &path, None));
        grant(&mut wb, &chat.id, &rid, "bob");
        assert!(file_readable(&wb, &chat.id, "bob", &path, None));
        wb.engagements
            .get(&chat.id)
            .unwrap()
            .write_file(&path, "changed")
            .unwrap();
        assert!(!file_readable(&wb, &chat.id, "bob", &path, None));
    }

    #[test]
    fn collision_revocation_and_erasure_close_the_file() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        let chat = wb
            .create_default_engagement("source-collision-chat".into(), "Collision".into())
            .unwrap_or_else(|_| panic!("create collision chat"));
        let (first, path) = imported(&mut wb, &chat.id, "alice", "upload-a", b"shared");
        grant(&mut wb, &chat.id, &first, "bob");
        assert!(file_readable(&wb, &chat.id, "bob", &path, None));

        let (second, _) = imported(&mut wb, &chat.id, "carol", "upload-b", b"shared");
        grant(&mut wb, &chat.id, &second, "bob");
        assert!(!file_readable(&wb, &chat.id, "bob", &path, None));
        wb.tombstone_resource_context(&chat.id, &gaugedesk_core::resource::ResourceId::new(second))
            .unwrap();
        // A surviving path claim from an erased import still makes ownership
        // ambiguous. Erasure cannot reveal another source's copy by accident.
        assert!(!file_readable(&wb, &chat.id, "bob", &path, None));
        let basis = source_basis(&wb, &chat.id, &first, "bob").unwrap();
        wb.store_mut()
            .admit::<AccessState>(&basis.scope, AccessCommand::Revoke)
            .unwrap();
        assert!(!file_readable(&wb, &chat.id, "bob", &path, None));
        assert!(basis.required.contains(&Authority::from("alice")));
    }

    #[test]
    fn an_unbound_legacy_import_cannot_be_assumed_not_to_own_a_path() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        let chat = wb
            .create_default_engagement("source-legacy-chat".into(), "Legacy".into())
            .unwrap_or_else(|_| panic!("create legacy chat"));
        let (rid, path) = imported(&mut wb, &chat.id, "alice", "bound-upload", b"shared");
        grant(&mut wb, &chat.id, &rid, "bob");
        assert!(file_readable(&wb, &chat.id, "bob", &path, None));
        wb.mint_resource_context(
            &chat.id,
            "carol",
            "legacy-unbound",
            "older-cut",
            Default::default(),
        )
        .unwrap();
        assert!(!file_readable(&wb, &chat.id, "bob", &path, None));
    }

    /// Write a file into the chat's worktree that no import claims, as the
    /// agent's output or the reader's own edit is.
    fn written(wb: &mut Workbench, chat_id: &str, name: &str) -> String {
        let path = wb.engagement_workspace_path(chat_id, name);
        wb.engagements
            .get(chat_id)
            .unwrap()
            .write_file(&path, "the chat's own work")
            .unwrap();
        path
    }

    /// The hosted file reader: what Files opens for an account-backed viewer.
    fn opens(wb: &Workbench, chat_id: &str, viewer: &str, path: &str) -> bool {
        matches!(
            wb.read_engagement_file_bytes_for_viewer(chat_id, path, 1024, Some(viewer), true),
            Some(Ok(Some(_)))
        )
    }

    #[test]
    fn a_file_no_one_else_has_a_stake_in_needs_no_grant() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        let chat = wb
            .create_default_engagement("own-files-chat".into(), "Own files".into())
            .unwrap_or_else(|_| panic!("create own files chat"));
        let (rid, upload) = imported(&mut wb, &chat.id, "alice", "alice-upload", b"mine");
        let output = written(&mut wb, &chat.id, "agent-note.txt");

        // The chat's own work is readable by whoever may read the chat.
        for viewer in ["alice", "bob"] {
            assert!(worktree_file_readable(&wb, &chat.id, viewer, &output, None));
            assert!(opens(&wb, &chat.id, viewer, &output));
        }
        // An upload is its source's: alice reads her own, bob needs her grant.
        assert!(worktree_file_readable(
            &wb, &chat.id, "alice", &upload, None
        ));
        assert!(opens(&wb, &chat.id, "alice", &upload));
        assert!(!worktree_file_readable(&wb, &chat.id, "bob", &upload, None));
        assert!(!opens(&wb, &chat.id, "bob", &upload));
        grant(&mut wb, &chat.id, &rid, "bob");
        assert!(opens(&wb, &chat.id, "bob", &upload));

        // The Files tree shows what the viewer may open, folders included.
        let folder = upload
            .rsplit_once('/')
            .map(|(folder, _)| folder.to_owned())
            .unwrap();
        assert!(directory_visible(&wb, &chat.id, "alice", &folder));

        // Erasure closes the upload even to its source; the chat's own work stays.
        wb.tombstone_resource_context(&chat.id, &gaugedesk_core::resource::ResourceId::new(rid))
            .unwrap();
        assert!(!worktree_file_readable(
            &wb, &chat.id, "alice", &upload, None
        ));
        assert!(worktree_file_readable(
            &wb, &chat.id, "alice", &output, None
        ));
    }

    #[test]
    fn another_persons_unbounded_import_keeps_unclaimed_files_closed() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        let chat = wb
            .create_default_engagement("unbounded-import-chat".into(), "Unbounded".into())
            .unwrap_or_else(|_| panic!("create unbounded import chat"));
        let output = written(&mut wb, &chat.id, "agent-note.txt");
        // The reader's own legacy import could only have supplied their own bytes.
        let legacy = wb
            .mint_resource_context(
                &chat.id,
                "alice",
                "alice-legacy",
                "older-cut",
                Default::default(),
            )
            .unwrap();
        assert!(worktree_file_readable(
            &wb, &chat.id, "alice", &output, None
        ));
        assert!(!worktree_file_readable(&wb, &chat.id, "bob", &output, None));
        // Erasing it, as a fork that inherits an erased upload does, closes
        // nothing more to its source: whatever it supplied was hers.
        wb.tombstone_resource_context(&chat.id, &legacy.resource.id)
            .unwrap();
        assert!(worktree_file_readable(
            &wb, &chat.id, "alice", &output, None
        ));
        assert!(!worktree_file_readable(&wb, &chat.id, "bob", &output, None));
        // Another person's might have supplied any path, so nothing is assumed.
        wb.mint_resource_context(
            &chat.id,
            "carol",
            "carol-legacy",
            "older-cut",
            Default::default(),
        )
        .unwrap();
        assert!(!worktree_file_readable(
            &wb, &chat.id, "alice", &output, None
        ));
        assert!(!opens(&wb, &chat.id, "alice", &output));
    }

    #[tokio::test]
    async fn source_owner_approves_only_the_requested_reader() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let (chat_id, rid, path) = {
            let mut wb = shared.lock_unpoisoned();
            let chat = wb
                .create_default_engagement("source-route-chat".into(), "Source route".into())
                .unwrap_or_else(|_| panic!("create source route chat"));
            let (rid, path) = imported(&mut wb, &chat.id, "alice", "alice-upload", b"secret");
            wb.library.chats.get_mut(&chat.id).unwrap().owner = Some("bob".into());
            for (person, role) in [("alice", "owner"), ("bob", "owner"), ("carol", "member")] {
                let member = crate::org::MembershipRecord {
                    id: person.into(),
                    op: crate::org::RecordOp::Upsert,
                    org_id: crate::org::ORG_ID.into(),
                    authority: person.into(),
                    email: String::new(),
                    role: role.into(),
                    status: crate::org::MembershipStatus::Active,
                    managed_by_scim: false,
                    team: None,
                };
                wb.store_mut()
                    .append_record(
                        crate::org::ORG_SCOPE,
                        "membership",
                        &serde_json::to_string(&member).unwrap(),
                    )
                    .unwrap();
            }
            let project = wb.library.project_of_chat(&chat.id).unwrap().to_owned();
            for person in ["alice", "bob"] {
                let grant = crate::org::MemberGrantRecord {
                    id: crate::org::MemberGrantRecord::make_id(person, &project),
                    op: crate::org::RecordOp::Upsert,
                    authority: person.into(),
                    project_id: project.clone(),
                };
                wb.store_mut()
                    .append_record(
                        crate::org::ORG_SCOPE,
                        "member_grant",
                        &serde_json::to_string(&grant).unwrap(),
                    )
                    .unwrap();
            }
            wb.set_identity_provider(Some(Arc::new(
                crate::identity::LoopbackIdentityProvider::new()
                    .enroll(
                        "bob-token",
                        AuthorityId::new("bob"),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        "alice-token",
                        AuthorityId::new("alice"),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        "carol-token",
                        AuthorityId::new("carol"),
                        AuthorityAttributes::default(),
                    ),
            )));
            (chat.id, rid, path)
        };
        assert!(crate::method_access::chat_reader(
            &shared.lock_unpoisoned(),
            &chat_id,
            &bearer("alice-token")
        )
        .is_ok());
        assert!(crate::method_access::chat_reader(
            &shared.lock_unpoisoned(),
            &chat_id,
            &bearer("carol-token")
        )
        .is_err());
        assert!(!file_readable(
            &shared.lock_unpoisoned(),
            &chat_id,
            "bob",
            &path,
            None
        ));
        let requested = super::request(
            State(shared.clone()),
            Path((chat_id.clone(), rid.clone())),
            bearer("bob-token"),
        )
        .await
        .into_response();
        assert_eq!(requested.status(), StatusCode::OK);
        let denied = super::pending_requests(
            State(shared.clone()),
            Path((chat_id.clone(), rid.clone())),
            bearer("carol-token"),
        )
        .await
        .into_response();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let pending = super::pending_requests(
            State(shared.clone()),
            Path((chat_id.clone(), rid.clone())),
            bearer("alice-token"),
        )
        .await
        .into_response();
        assert_eq!(pending.status(), StatusCode::OK);
        let denied_approve = super::approve(
            State(shared.clone()),
            Path((chat_id.clone(), rid.clone(), "bob".into())),
            bearer("carol-token"),
        )
        .await
        .into_response();
        assert_eq!(denied_approve.status(), StatusCode::FORBIDDEN);
        let approved = super::approve(
            State(shared.clone()),
            Path((chat_id.clone(), rid.clone(), "bob".into())),
            bearer("alice-token"),
        )
        .await
        .into_response();
        assert_eq!(approved.status(), StatusCode::OK);
        assert!(file_readable(
            &shared.lock_unpoisoned(),
            &chat_id,
            "bob",
            &path,
            None
        ));
        let revoked = super::revoke_own(
            State(shared.clone()),
            Path((chat_id.clone(), rid)),
            bearer("bob-token"),
        )
        .await
        .into_response();
        assert_eq!(revoked.status(), StatusCode::OK);
        assert!(!file_readable(
            &shared.lock_unpoisoned(),
            &chat_id,
            "bob",
            &path,
            None
        ));
    }
}
