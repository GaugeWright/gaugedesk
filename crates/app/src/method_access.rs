//! A reader's access to one installed Agent method version. The access reducer
//! is shared with context resources; this scope binds its missing recipient,
//! purpose, chat and immutable package reference before a command reaches it.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use gaugedesk_core::{
    boundary::Authority,
    resource_access::{AccessCommand, AccessPhase, AccessState},
};
use sha2::{Digest, Sha256};

use crate::{err_response, net_http, LockUnpoisoned, SharedWorkbench, Workbench};

struct MethodBasis {
    scope: String,
    package_ref: String,
    source_owner: String,
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

pub(crate) fn account_backed(wb: &Workbench, headers: &HeaderMap) -> bool {
    wb.idp.is_some()
        || crate::workbench_auth::web_account_mode()
        || net_http::bearer(headers)
            .is_some_and(|token| wb.resolve_account_session(token).is_some())
}

pub(crate) fn account_backed_chat(wb: &Workbench, chat_id: &str, headers: &HeaderMap) -> bool {
    account_backed(wb, headers)
        || wb.library.chats.get(chat_id).is_some_and(|chat| {
            chat.owner
                .as_deref()
                .is_some_and(|owner| owner != wb.authority().as_str())
        })
}

impl Workbench {
    /// Draft and runtime surfaces belong to the authoring owner. Imported
    /// context at the target root still needs its separate inspection grant.
    pub(crate) fn authoring_draft_readable(
        &self,
        chat_id: &str,
        path: &str,
        actor: Option<&str>,
    ) -> bool {
        self.authoring_chat_visible(chat_id, actor) == Some(true)
            && !path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            && (path == "agent"
                || path.starts_with("agent/")
                || path == "work"
                || path.starts_with("work/")
                || path == "artifacts"
                || path.starts_with("artifacts/")
                || path == ".whipple"
                || path.starts_with(".whipple/")
                || gaugedesk_boundary::is_method_surface_path(path)
                || gaugedesk_boundary::is_control_surface_path(path))
    }

    /// An Agent with no recorded owner belongs, on a local Project Host, to
    /// the account that claimed the computer, as its projects do, or to the
    /// local account where nobody claimed it (DR-0313, narrowing DR-0271). The
    /// built-in Agents stay the local account's: they are the library's own,
    /// placed for everyone and edited by no account. Compatibility ownership
    /// never supplies the frozen source provenance used by installed-method
    /// grants.
    pub(crate) fn agent_authoring_owner(&self, id: &str) -> Option<String> {
        self.agent_authoring_owner_in(&self.library, id)
    }

    pub(crate) fn agent_authoring_owner_in(
        &self,
        library: &crate::library::Library,
        id: &str,
    ) -> Option<String> {
        self.project_owner_resolver()
            .agent_owner_in(library, id, &self.legacy_project_owner())
    }

    /// Whether `actor` may place Agent `id` on a project: a built-in Agent,
    /// or one the actor owns (DR-0268 §5). Accounts are independent, so one
    /// account's Agent is not another's to place.
    pub(crate) fn agent_placeable_by(&self, id: &str, actor: &str) -> bool {
        crate::app_support::is_builtin_agent(id)
            || self.agent_authoring_owner(id).as_deref() == Some(actor)
    }

    pub(crate) fn agent_authoring_visible(&self, id: &str, actor: Option<&str>) -> bool {
        actor.is_some_and(|actor| self.agent_authoring_owner(id).as_deref() == Some(actor))
    }

    /// None denotes a work chat, whose project admission remains separate.
    pub(crate) fn authoring_chat_visible(&self, id: &str, actor: Option<&str>) -> Option<bool> {
        let chat = self.library.chats.get(id)?;
        let instance = self.library.instances.get(&chat.instance_id)?;
        if instance.kind != crate::library::InstanceKind::Authoring {
            return None;
        }
        Some(
            self.agent_authoring_visible(&instance.agent_id, actor)
                && actor.is_some_and(|actor| {
                    chat.owner
                        .clone()
                        .or_else(|| self.agent_authoring_owner(&instance.agent_id))
                        .as_deref()
                        == Some(actor)
                }),
        )
    }
}

/// Admit the exact authoring owner before draft reads. Work-chat method
/// inspection retains its separate verified reader and project admission.
pub(crate) fn chat_reader(
    wb: &Workbench,
    chat_id: &str,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, &'static str)> {
    let chat = wb
        .library
        .chats
        .get(chat_id)
        .ok_or((StatusCode::NOT_FOUND, "chat not found"))?;
    let actor = wb.admit_data_request_with_client(
        net_http::bearer(headers),
        wb.library.project_of_chat(chat_id),
        &crate::workbench_auth::req_scope(headers),
        crate::client_admission::ClientBuild::from_headers(headers),
        false,
    )?;
    if let Some(visible) = wb.authoring_chat_visible(chat_id, Some(&actor)) {
        return if visible {
            Ok(actor)
        } else {
            Err((StatusCode::FORBIDDEN, "chat is unavailable"))
        };
    }
    if account_backed_chat(wb, chat_id, headers) {
        let verified = net_http::bearer(headers).and_then(|token| wb.authenticate_bearer(token));
        let shared_project_reader = wb.library.project_of_chat(chat_id).is_some()
            && crate::org::Org::rebuild(wb.store_ref()).is_ok_and(|org| {
                org.members
                    .values()
                    .any(|member| member.status == crate::org::MembershipStatus::Active)
            });
        if verified
            .as_ref()
            .is_none_or(|authority| authority.as_str() != actor)
            || (chat.owner.as_deref() != Some(&actor) && !shared_project_reader)
        {
            return Err((StatusCode::FORBIDDEN, "chat is unavailable"));
        }
    }
    Ok(actor)
}

fn basis(wb: &Workbench, chat_id: &str, reader: &str) -> Option<MethodBasis> {
    let chat = wb.library.chats.get(chat_id)?;
    let instance = wb.library.instances.get(&chat.instance_id)?;
    if instance.kind != crate::library::InstanceKind::Using {
        return None;
    }
    let version = wb
        .library
        .agents
        .get(&instance.agent_id)?
        .versions
        .get(&instance.version)?;
    let owner = version.source_owner_authority.as_deref()?;
    if owner == "anonymous" || owner.is_empty() || reader.is_empty() || reader == "anonymous" {
        return None;
    }
    let package_ref = version.package_ref.clone();
    let key = serde_json::to_vec(&(
        chat_id,
        reader,
        "method-inspection",
        instance.version,
        &package_ref,
    ))
    .ok()?;
    let digest = Sha256::digest(key);
    Some(MethodBasis {
        scope: format!("method-inspection::{}", hex::encode(digest)),
        package_ref,
        source_owner: owner.to_owned(),
    })
}

impl Workbench {
    /// The exact selected package and recipient must still match at the read.
    /// A missing, legacy, revoked or erased source fails closed.
    pub(crate) fn method_inspection_granted(
        &self,
        chat_id: &str,
        reader: &str,
        package_ref: &str,
    ) -> bool {
        let Some(basis) = basis(self, chat_id, reader) else {
            return false;
        };
        if basis.package_ref != package_ref {
            return false;
        }
        let Some((version, selected_ref)) = self.package_selection_for_chat(chat_id) else {
            return false;
        };
        if selected_ref != package_ref
            || self
                .package_root_for_chat(chat_id, version)
                .and_then(|root| gaugedesk_whip_runtime::AuthoredAgentPackage::load(&root).ok())
                .is_none_or(|package| package.version_ref() != package_ref)
        {
            return false;
        }
        self.store_ref()
            .fold::<AccessState>(&basis.scope)
            .is_ok_and(|state| state.phase == AccessPhase::Granted)
    }
}

fn admit_actor(wb: &Workbench, headers: &HeaderMap) -> Result<String, (StatusCode, &'static str)> {
    let Some(token) = net_http::bearer(headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authenticate to inspect an Agent method",
        ));
    };
    let Some(verified) = wb.authenticate_bearer(token) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authenticate to inspect an Agent method",
        ));
    };
    match wb.admit_data_request(net_http::bearer(headers), None) {
        Ok(actor) if actor == verified.as_str() => Ok(actor),
        Ok(_) => Err((
            StatusCode::UNAUTHORIZED,
            "authenticate to inspect an Agent method",
        )),
        Err(error) => Err(error),
    }
}

/// A reader requests the exact version selected in their own chat.
pub(crate) async fn request(
    State(shared): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = shared.lock_unpoisoned();
    if !account_backed_chat(&wb, &id, &headers) {
        return (
            StatusCode::BAD_REQUEST,
            "solo method inspection needs no grant",
        )
            .into_response();
    }
    let reader = match chat_reader(&wb, &id, &headers) {
        Ok(reader) => reader,
        Err(error) => return error.into_response(),
    };
    let Some(basis) = basis(&wb, &id, &reader) else {
        return (
            StatusCode::FORBIDDEN,
            "method source ownership is unverified",
        )
            .into_response();
    };
    let required = [Authority::from(basis.source_owner.clone())]
        .into_iter()
        .collect();
    match wb
        .store_mut()
        .admit::<AccessState>(&basis.scope, AccessCommand::RequestAccess { required })
    {
        Ok(_) if basis.source_owner == reader => {
            match wb.store_mut().admit::<AccessState>(
                &basis.scope,
                AccessCommand::Approve(Authority::from(reader)),
            ) {
                Ok(_) => {
                    (StatusCode::OK, Json(serde_json::json!({"phase":"granted"}))).into_response()
                }
                Err(error) => err_response(error),
            }
        }
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({"phase":"requested"})),
        )
            .into_response(),
        Err(error) => err_response(error),
    }
}

/// The verified publisher, and only that publisher, approves a reader's
/// requested basis. The reader name is supplied to find a scope, not trusted as
/// an authority or package ref.
pub(crate) async fn approve(
    State(shared): State<SharedWorkbench>,
    Path((id, reader)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = shared.lock_unpoisoned();
    if !account_backed_chat(&wb, &id, &headers) {
        return (
            StatusCode::BAD_REQUEST,
            "solo method inspection needs no grant",
        )
            .into_response();
    }
    let actor = match admit_actor(&wb, &headers) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let Some(basis) = basis(&wb, &id, &reader) else {
        return (StatusCode::NOT_FOUND, "method basis unavailable").into_response();
    };
    if actor != basis.source_owner {
        return (
            StatusCode::FORBIDDEN,
            "only the method source owner may approve",
        )
            .into_response();
    }
    match wb
        .store_mut()
        .admit::<AccessState>(&basis.scope, AccessCommand::Approve(Authority::from(actor)))
    {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"phase":"granted"}))).into_response(),
        Err(error) => err_response(error),
    }
}

/// Either party can close the basis. A revoked scope is terminal for this
/// reader and version.
pub(crate) async fn revoke(
    State(shared): State<SharedWorkbench>,
    Path((id, reader)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = shared.lock_unpoisoned();
    if !account_backed_chat(&wb, &id, &headers) {
        return (
            StatusCode::BAD_REQUEST,
            "solo method inspection has no grant",
        )
            .into_response();
    }
    let actor = match admit_actor(&wb, &headers) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let Some(basis) = basis(&wb, &id, &reader) else {
        return (StatusCode::NOT_FOUND, "method basis unavailable").into_response();
    };
    if actor != reader && actor != basis.source_owner {
        return (StatusCode::FORBIDDEN, "only a grant party may revoke").into_response();
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
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = shared.lock_unpoisoned();
    if !account_backed_chat(&wb, &id, &headers) {
        return (
            StatusCode::BAD_REQUEST,
            "solo method inspection has no grant",
        )
            .into_response();
    }
    let reader = match chat_reader(&wb, &id, &headers) {
        Ok(reader) => reader,
        Err(error) => return error.into_response(),
    };
    let Some(basis) = basis(&wb, &id, &reader) else {
        return (StatusCode::NOT_FOUND, "method basis unavailable").into_response();
    };
    match wb
        .store_mut()
        .admit::<AccessState>(&basis.scope, AccessCommand::Revoke)
    {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"phase":"revoked"}))).into_response(),
        Err(error) => err_response(error),
    }
}

pub(crate) async fn phase(
    State(shared): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = shared.lock_unpoisoned();
    if !account_backed_chat(&wb, &id, &headers) {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"phase":"unavailable"})),
        )
            .into_response();
    }
    let reader = match chat_reader(&wb, &id, &headers) {
        Ok(reader) => reader,
        Err(error) => return error.into_response(),
    };
    let Some(basis) = basis(&wb, &id, &reader) else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"phase":"unavailable"})),
        )
            .into_response();
    };
    match wb.store_ref().fold::<AccessState>(&basis.scope) {
        Ok(state) => (
            StatusCode::OK,
            Json(serde_json::json!({"phase":phase_label(state.phase),"package_ref":basis.package_ref,"can_approve":basis.source_owner == reader})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "method access unavailable",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Path, State},
        response::IntoResponse,
    };
    use gaugedesk_core::{abac::AuthorityAttributes, ids::AuthorityId};
    use std::sync::Arc;

    fn headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    #[test]
    fn published_owner_survives_workspace_reconciliation() {
        let root = tempfile::tempdir().unwrap();
        let agent_id = {
            let shared = crate::open_workbench(root.path()).unwrap();
            let mut wb = shared.lock_unpoisoned();
            wb.create_archetype(
                "Owned method".into(),
                crate::library::AgentKind::Work,
                Some("publisher".into()),
            )
            .unwrap_or_else(|_| panic!("create Agent"))
            .id
        };
        let shared = crate::open_workbench(root.path()).unwrap();
        let wb = shared.lock_unpoisoned();
        assert_eq!(
            wb.library
                .agents
                .get(&agent_id)
                .unwrap()
                .versions
                .get(&1)
                .unwrap()
                .source_owner_authority
                .as_deref(),
            Some("publisher")
        );
    }

    #[tokio::test]
    async fn solo_agent_creation_does_not_claim_a_person_source_owner() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let created = crate::library_routes::create_agent(
            State(shared.clone()),
            HeaderMap::new(),
            Json(crate::library_routes::CreateAgent {
                name: "Solo method".into(),
                kind: crate::library::AgentKind::Work,
            }),
        )
        .await
        .into_response();
        assert_eq!(created.status(), StatusCode::CREATED);
        let agent_id = {
            let wb = shared.lock_unpoisoned();
            let agent = wb
                .library
                .agents
                .values()
                .find(|agent| agent.name == "Solo method")
                .unwrap();
            assert_eq!(
                agent.authoring_owner.as_deref(),
                Some(wb.authority().as_str())
            );
            assert!(agent.versions[&1].source_owner_authority.is_none());
            agent.id.clone()
        };
        let response = crate::library_routes::create_chat_under_agent(
            State(shared.clone()),
            Path(agent_id),
            HeaderMap::new(),
            Json(crate::library_routes::CreateChat {
                title: "Local edit".into(),
                target_id: None,
                target_ids: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let wb = shared.lock_unpoisoned();
        let chat = wb
            .library
            .chats
            .values()
            .find(|chat| chat.title == "Local edit")
            .unwrap();
        assert_eq!(chat.owner.as_deref(), Some(wb.authority().as_str()));
        assert!(
            !account_backed_chat(&wb, &chat.id, &HeaderMap::new()),
            "local ownership preserves the solo context-ingest posture"
        );
    }

    #[tokio::test]
    async fn account_backed_agent_chats_claim_the_authenticated_creator() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let agent_id = {
            let mut wb = shared.lock_unpoisoned();
            let agent_id = wb
                .create_archetype(
                    "Shared method".into(),
                    crate::library::AgentKind::Work,
                    Some("publisher".into()),
                )
                .unwrap_or_else(|_| panic!("create Agent"))
                .id;
            wb.set_identity_provider(Some(Arc::new(
                crate::identity::LoopbackIdentityProvider::new()
                    .enroll(
                        "reader-token",
                        AuthorityId::new("reader"),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        "publisher-token",
                        AuthorityId::new("publisher"),
                        AuthorityAttributes::default(),
                    ),
            )));
            agent_id
        };
        let new_chat = |title: &str| {
            Json(crate::library_routes::CreateChat {
                title: title.into(),
                target_id: None,
                target_ids: None,
            })
        };
        let anonymous = crate::library_routes::use_archetype(
            State(shared.clone()),
            Path(agent_id.clone()),
            HeaderMap::new(),
            new_chat("Anonymous"),
        )
        .await
        .into_response();
        assert_ne!(anonymous.status(), StatusCode::CREATED);
        let work = crate::library_routes::use_archetype(
            State(shared.clone()),
            Path(agent_id.clone()),
            headers("reader-token"),
            new_chat("Reader work"),
        )
        .await
        .into_response();
        assert_eq!(work.status(), StatusCode::CREATED);
        let forbidden_edit = crate::library_routes::create_chat_under_agent(
            State(shared.clone()),
            Path(agent_id.clone()),
            headers("reader-token"),
            new_chat("Reader edit"),
        )
        .await
        .into_response();
        assert_eq!(forbidden_edit.status(), StatusCode::FORBIDDEN);
        let edit = crate::library_routes::create_chat_under_agent(
            State(shared.clone()),
            Path(agent_id),
            headers("publisher-token"),
            new_chat("Publisher edit"),
        )
        .await
        .into_response();
        assert_eq!(edit.status(), StatusCode::CREATED);
        let mut wb = shared.lock_unpoisoned();
        let work_chat_id = wb
            .library
            .chats
            .values()
            .find(|chat| chat.title == "Reader work")
            .unwrap()
            .id
            .clone();
        assert_eq!(
            wb.library
                .chats
                .values()
                .find(|chat| chat.title == "Reader work")
                .and_then(|chat| chat.owner.as_deref()),
            Some("reader")
        );
        assert_eq!(
            wb.library
                .chats
                .values()
                .find(|chat| chat.title == "Publisher edit")
                .and_then(|chat| chat.owner.as_deref()),
            Some("publisher")
        );
        assert!(chat_reader(&wb, &work_chat_id, &HeaderMap::new()).is_err());
        wb.set_identity_provider(None);
        assert!(chat_reader(&wb, &work_chat_id, &HeaderMap::new()).is_err());
    }

    #[tokio::test]
    async fn method_grant_binds_verified_owner_reader_chat_and_exact_version() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let (chat_id, package_ref) = {
            let mut wb = shared.lock_unpoisoned();
            let chat = wb
                .create_default_engagement("method-grant-chat".into(), "Method grant".into())
                .unwrap_or_else(|_| panic!("create work chat"));
            let mut chat_record = wb.library.chats.get(&chat.id).unwrap().clone();
            chat_record.owner = Some("reader".into());
            wb.write_chat_record(chat_record);
            let instance = wb
                .library
                .instances
                .get(&wb.library.chats.get(&chat.id).unwrap().instance_id)
                .unwrap();
            let mut agent = wb.library.agents.get(&instance.agent_id).unwrap().clone();
            let version = agent.versions.get_mut(&instance.version).unwrap();
            let package_ref = version.package_ref.clone();
            version.source_owner_authority = Some("publisher".into());
            wb.write_agent_record(agent);
            let idp = crate::identity::LoopbackIdentityProvider::new()
                .enroll(
                    "reader-token",
                    AuthorityId::new("reader"),
                    AuthorityAttributes::default(),
                )
                .enroll(
                    "publisher-token",
                    AuthorityId::new("publisher"),
                    AuthorityAttributes::default(),
                )
                .enroll(
                    "stranger-token",
                    AuthorityId::new("stranger"),
                    AuthorityAttributes::default(),
                );
            wb.set_identity_provider(Some(Arc::new(idp)));
            assert!(!wb.method_inspection_granted(&chat.id, "reader", &package_ref));
            assert!(wb
                .read_engagement_file_bytes_for_viewer(
                    &chat.id,
                    "agent/AGENTS.md",
                    1024 * 1024,
                    Some("reader"),
                    true,
                )
                .unwrap()
                .is_err());
            (chat.id, package_ref)
        };

        let turn_claim = crate::engine::claim_turn(&chat_id).unwrap();
        let raw = serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {"messages": ["private Agent method"]},
                "ordered_provenance": {
                    "messages": [{"source_handles": [format!("package:{package_ref}")], "complete": true}],
                    "tools": {"source_handles": ["runtime"], "complete": true},
                    "wire": {
                        "format": "open-ai-chat-compat",
                        "items": [{"source_handles": [format!("package:{package_ref}")], "complete": true}],
                        "system": null
                    }
                },
                "provenance_complete": true
            }],
            "incomplete": false
        });
        crate::engine::bind_turn_model_context(&chat_id, Arc::new(move || Ok(raw.to_string())));
        let read_raw = |shared: SharedWorkbench| {
            let chat_id = chat_id.clone();
            async move {
                let response = crate::engagement_routes::get_model_context(
                    State(shared),
                    Path(chat_id),
                    headers("reader-token"),
                )
                .await
                .into_response();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            }
        };
        assert_eq!(read_raw(shared.clone()).await["calls"][0]["redacted"], true);

        let requested = request(
            State(shared.clone()),
            Path(chat_id.clone()),
            headers("reader-token"),
        )
        .await
        .into_response();
        assert_eq!(requested.status(), StatusCode::OK);
        let denied = approve(
            State(shared.clone()),
            Path((chat_id.clone(), "reader".into())),
            headers("stranger-token"),
        )
        .await
        .into_response();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let granted = approve(
            State(shared.clone()),
            Path((chat_id.clone(), "reader".into())),
            headers("publisher-token"),
        )
        .await
        .into_response();
        assert_eq!(granted.status(), StatusCode::OK);
        {
            let wb = shared.lock_unpoisoned();
            assert!(wb.method_inspection_granted(&chat_id, "reader", &package_ref));
            assert!(!wb.method_inspection_granted(&chat_id, "stranger", &package_ref));
            assert!(!wb.method_inspection_granted(&chat_id, "reader", "other-package"));
            assert!(wb
                .read_engagement_file_bytes_for_viewer(
                    &chat_id,
                    "agent/AGENTS.md",
                    1024 * 1024,
                    Some("reader"),
                    true,
                )
                .unwrap()
                .unwrap()
                .is_some());
        }
        assert_eq!(
            read_raw(shared.clone()).await["calls"][0]["body"]["messages"][0],
            "private Agent method"
        );
        let revoked = revoke(
            State(shared.clone()),
            Path((chat_id.clone(), "reader".into())),
            headers("publisher-token"),
        )
        .await
        .into_response();
        assert_eq!(revoked.status(), StatusCode::OK);
        {
            let wb = shared.lock_unpoisoned();
            assert!(!wb.method_inspection_granted(&chat_id, "reader", &package_ref));
            assert!(wb
                .read_engagement_file_bytes_for_viewer(
                    &chat_id,
                    "agent/AGENTS.md",
                    1024 * 1024,
                    Some("reader"),
                    true,
                )
                .unwrap()
                .is_err());
        }
        assert_eq!(read_raw(shared).await["calls"][0]["redacted"], true);
        drop(turn_claim);
    }
}

#[cfg(test)]
mod workshop_upgrade_tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    async fn read(app: &axum::Router, path: &str, token: Option<&str>) -> (StatusCode, String) {
        let mut req = Request::builder().uri(path);
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// Persist the pre-owner record shape, rather than testing an empty startup
    /// or substituting a mocked file API for the production router.
    #[tokio::test]
    async fn workshop_upgrade_preserves_legacy_files_across_account_switches() {
        let root = tempfile::tempdir().unwrap();
        let (local_agent, local_chat, owned_agent, owned_chat, local_actor) = {
            let shared = crate::open_workbench(root.path()).unwrap();
            let mut wb = shared.lock_unpoisoned();
            let local_actor = wb.authority().as_str().to_owned();
            let mut legacy = |name: &str, publisher: Option<String>| {
                let id = wb
                    .create_archetype(name.into(), crate::library::AgentKind::Work, publisher)
                    .unwrap_or_else(|_| panic!("create old Agent"))
                    .id;
                let chat = wb
                    .create_chat_under_agent(&id, name)
                    .unwrap_or_else(|_| panic!("create old edit chat"))["id"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let mut old = serde_json::to_value(wb.library.agents.get(&id).unwrap()).unwrap();
                old.as_object_mut().unwrap().remove("authoring_owner");
                wb.store_mut()
                    .append_record(crate::library::LIBRARY_SCOPE, "agent", &old.to_string())
                    .unwrap();
                assert!(wb.library.chats[&chat].owner.is_none());
                (id, chat)
            };
            let (local_agent, local_chat) = legacy("Old local Agent", None);
            let (owned_agent, owned_chat) =
                legacy("Old signed-in Agent", Some("account-root".into()));
            (
                local_agent,
                local_chat,
                owned_agent,
                owned_chat,
                local_actor,
            )
        };
        let shared = crate::open_workbench(root.path()).unwrap();
        let app = crate::open_control_plane(shared.clone());
        // Which context sees the Agent drafted signed out, and which the one
        // drafted signed in.
        let assert_context = |token: Option<String>, local: bool, owned: bool| {
            let app = app.clone();
            let (local_agent, local_chat, owned_agent, owned_chat) = (
                local_agent.clone(),
                local_chat.clone(),
                owned_agent.clone(),
                owned_chat.clone(),
            );
            async move {
                let (status, body) = read(&app, "/workspace", token.as_deref()).await;
                assert_eq!(status, StatusCode::OK);
                let workspace: serde_json::Value = serde_json::from_str(&body).unwrap();
                for (agent, chat, visible) in [
                    (&local_agent, &local_chat, local),
                    (&owned_agent, &owned_chat, owned),
                ] {
                    assert_eq!(
                        workspace["archetypes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|a| a["id"] == *agent),
                        visible
                    );
                    let (status, body) = read(
                        &app,
                        &format!("/projections/library/workspace/archetype/{agent}"),
                        token.as_deref(),
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK);
                    let delta: serde_json::Value = serde_json::from_str(&body).unwrap();
                    assert_eq!(
                        delta["value"]["archetypes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|a| a["id"] == *agent),
                        visible,
                        "a streamed refresh must obey the same Workshop discovery rule"
                    );
                    assert_eq!(
                        workspace["recent"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|c| c["id"] == *chat),
                        visible
                    );
                    let (status, body) =
                        read(&app, &format!("/chats/{chat}/tree"), token.as_deref()).await;
                    assert_eq!(
                        status,
                        if visible {
                            StatusCode::OK
                        } else {
                            StatusCode::FORBIDDEN
                        }
                    );
                    if visible {
                        let tree: serde_json::Value = serde_json::from_str(&body).unwrap();
                        assert!(
                            tree["files"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|f| f["path"] == "agent/AGENTS.md"),
                            "draft files must be present: {body}"
                        );
                    }
                    let (status, body) = read(
                        &app,
                        &format!("/chats/{chat}/file?path=agent/AGENTS.md"),
                        token.as_deref(),
                    )
                    .await;
                    assert_eq!(
                        status,
                        if visible {
                            StatusCode::OK
                        } else {
                            StatusCode::FORBIDDEN
                        }
                    );
                    if visible {
                        assert!(!body.trim().is_empty());
                    }
                    assert_eq!(
                        read(&app, &format!("/archetypes/{agent}"), token.as_deref())
                            .await
                            .0,
                        if visible {
                            StatusCode::OK
                        } else {
                            StatusCode::FORBIDDEN
                        }
                    );
                }
            }
        };
        assert_context(None, true, false).await;
        crate::account_signin::store_session_for_test(&shared);
        crate::home_owner::claim_if_never_claimed(&shared).unwrap();
        let signed = crate::desktop_session::home_session(&shared).unwrap();
        // DR-0313: the claim gives the claimant the computer's earlier Agents,
        // as DR-0309 gave it the projects.
        assert_context(Some(signed.clone()), true, true).await;
        // Another independently admitted account still cannot borrow either
        // account's draft, even with org-wide project visibility.
        let other = shared
            .lock_unpoisoned()
            .mint_account_session("account-other", "test", 3600)
            .unwrap();
        let (status, body) = read(&app, "/workspace", Some(&other)).await;
        assert_eq!(status, StatusCode::OK);
        let workspace: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(workspace["archetypes"].as_array().unwrap().is_empty());
        for chat in [&local_chat, &owned_chat] {
            assert_eq!(
                read(&app, &format!("/chats/{chat}/tree"), Some(&other))
                    .await
                    .0,
                StatusCode::FORBIDDEN
            );
            let denied = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/chats/{chat}/file?path=agent/AGENTS.md"))
                        .header("authorization", format!("Bearer {other}"))
                        .header("idempotency-key", format!("foreign-save-{chat}"))
                        .body(Body::from("foreign edit must not be applied"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                denied.status(),
                StatusCode::FORBIDDEN,
                "a guessed draft URL must not permit another account to edit"
            );
        }
        // Use the real native account-selection route. It revokes the prior
        // window session and returns to the stable local actor.
        let desktop = crate::open_runtime::desktop_operator_plane(shared.clone());
        let response = desktop
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/account/hub-session/select-local")
                    .header("idempotency-key", "workshop-upgrade-select-local")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_context(None, false, false).await;
        assert_eq!(shared.lock_unpoisoned().authority().as_str(), local_actor);
        assert!(
            shared.lock_unpoisoned().library.agents[&local_agent].versions[&1]
                .source_owner_authority
                .is_none(),
            "compatibility ownership must not manufacture publisher provenance"
        );
        assert!(shared
            .lock_unpoisoned()
            .resolve_account_session(&signed)
            .is_none());
        drop(desktop);
        drop(app);
        drop(shared);
        let reopened = crate::open_workbench(root.path()).unwrap();
        assert_eq!(
            reopened
                .lock_unpoisoned()
                .agent_authoring_owner(&local_agent),
            Some("account-root".to_owned())
        );
        assert_eq!(
            reopened
                .lock_unpoisoned()
                .agent_authoring_owner(&owned_agent),
            Some("account-root".to_owned())
        );
    }

    #[test]
    fn hosted_legacy_workshop_does_not_infer_local_ownership() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        assert!(wb.agent_authoring_owner(crate::DEFAULT_AGENT).is_some());
        wb.enable_hosted_home_mode();
        assert!(wb.agent_authoring_owner(crate::DEFAULT_AGENT).is_none());
    }
}
