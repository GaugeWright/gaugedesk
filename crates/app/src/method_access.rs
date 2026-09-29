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
        || wb
            .library
            .chats
            .get(chat_id)
            .is_some_and(|chat| chat.owner.is_some())
}

/// Authenticate a reader before showing even method handle metadata. An
/// account-backed legacy chat with no verified owner cannot supply a reader.
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
    let actor = wb.admit_data_request(
        net_http::bearer(headers),
        wb.library.project_of_chat(chat_id),
    )?;
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
        let wb = shared.lock_unpoisoned();
        let agent = wb
            .library
            .agents
            .values()
            .find(|agent| agent.name == "Solo method")
            .unwrap();
        assert!(agent
            .versions
            .get(&1)
            .unwrap()
            .source_owner_authority
            .is_none());
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
                    "tools": {"source_handles": ["runtime"], "complete": true}
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
