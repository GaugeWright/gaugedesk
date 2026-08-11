//! Administration adapter for the client-independent management Environment
//! protocol (ADRs 0105–0107). The registry below is the single route inventory:
//! discovery, admission, document parsing, and dispatch all consume it.

// Axum's concrete Response is the native error value throughout this route
// adapter; boxing it would add indirection to every handler and call site.
#![allow(clippy::result_large_err)]

use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use gaugedesk_app::environment_agent::{
    append_environment_agent_exchange, environment_agent_transcript, run_environment_agent_turn,
    EnvironmentAgentContext, EnvironmentAgentDocument, EnvironmentAgentError,
};
use gaugedesk_app::environment_contract::{
    decide_environment_command, decide_reviewed_environment_command, environment_change_id,
    environment_receipt, environment_session_id, fold_environment_changes, AdmissionDisposition,
    EnvironmentChangeRecord, EnvironmentChangeStatus, EnvironmentClient,
    EnvironmentCommandEnvelope, EnvironmentCommandGrant, EnvironmentDocumentGrant, EnvironmentKind,
    EnvironmentScope, EnvironmentSession, ReviewPolicy, ENVIRONMENT_CHANGE_KIND,
};
use gaugedesk_app::org::{
    sha256_hex, ArchetypeApprovalPolicyRecord, BillingRecord, GroupMappingRecord,
    MemberGrantRecord, MembershipRecord, MembershipStatus, Org, OrgKind, OrgRecord,
    PlacementPolicyRecord, PolicyRecord, RecordOp, ScimTokenRecord, SecurityPolicyRecord,
    SoftwarePolicyRecord, SsoConnectionRecord, ORG_ID,
};
use gaugedesk_app::{LockUnpoisoned, SharedWorkbench, Workbench};
use gaugedesk_core::abac::Policy;
use gaugedesk_core::rbac::Capability;
use gaugedesk_store::{AdmitError, CommandRecordFact};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::org_routes::{bearer, req_scope};

const ENVIRONMENT: EnvironmentKind = EnvironmentKind::Administration;

#[derive(Clone, Copy)]
struct DocumentPolicy {
    id: &'static str,
    path: &'static str,
    schema: &'static str,
    read: &'static [Capability],
}

#[derive(Clone, Copy)]
struct CommandPolicy {
    id: &'static str,
    document: &'static str,
    capability: Capability,
    review: ReviewPolicy,
    method: &'static str,
    legacy_path: &'static str,
}

#[derive(Clone, Debug)]
pub struct AdministrationExtensionCommand {
    pub id: String,
    pub capability: Capability,
    pub review: ReviewPolicy,
}

#[derive(Clone, Debug)]
pub struct AdministrationExtensionDocument {
    pub id: String,
    pub path: String,
    pub schema: String,
    pub freshness: String,
    pub editable: bool,
    pub content: Value,
    pub commands: Vec<AdministrationExtensionCommand>,
}

#[derive(Clone, Debug)]
pub struct AdministrationMutationPlan {
    pub facts: Vec<CommandRecordFact>,
    pub notices: Vec<(&'static str, String, &'static str)>,
    pub audit_action: &'static str,
    pub audit_target: String,
    pub transient_result: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct AdministrationExtensionError {
    pub status: StatusCode,
    pub message: String,
}

impl AdministrationExtensionError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

/// Cloud and other enterprise compositions may contribute selected-tenant
/// Administration documents and closed reducers without minting another route
/// family. The common adapter still owns authentication, exact scope, base
/// revision, review, idempotency, durable receipt, and audit admission.
pub trait AdministrationEnvironmentExtension: Send + Sync {
    fn project(
        &self,
        wb: &Workbench,
        tenant_id: &str,
        store_scope: &str,
        actor: &str,
        capabilities: &[Capability],
    ) -> Result<Vec<AdministrationExtensionDocument>, AdministrationExtensionError>;

    fn plan(
        &self,
        wb: &Workbench,
        tenant_id: &str,
        store_scope: &str,
        actor: &str,
        command: &EnvironmentCommandEnvelope,
    ) -> Result<Option<AdministrationMutationPlan>, AdministrationExtensionError>;

    /// Run an exact idempotent external effect, if this command owns one, and
    /// return the final fact plan committed with the receipt. Implementations
    /// must bind provider/runtime requests to `operation_key` so crash retry
    /// repeats the same effect rather than widening it. Human-reviewed changes
    /// receive their durable change id; immediate commands receive the request
    /// idempotency key.
    #[allow(clippy::too_many_arguments)]
    fn apply(
        &self,
        _wb: &Workbench,
        _tenant_id: &str,
        _store_scope: &str,
        _actor: &str,
        _command: &EnvironmentCommandEnvelope,
        _operation_key: &str,
        plan: AdministrationMutationPlan,
    ) -> Result<AdministrationMutationPlan, AdministrationExtensionError> {
        Ok(plan)
    }
}

pub type AdministrationEnvironmentExtensionHandle = Arc<dyn AdministrationEnvironmentExtension>;

/// Machine-checkable inventory of every management mutation represented by
/// the Administration adapter. The legacy route is evidence for migration and
/// must disappear from browser clients; admission uses `command_id` only.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ManagementRouteInventoryEntry {
    pub environment: &'static str,
    pub command_id: &'static str,
    pub document_id: &'static str,
    pub authentication: &'static str,
    pub scope_policy: &'static str,
    pub capability: &'static str,
    pub base_revision_required: bool,
    pub idempotency_required: bool,
    pub review: &'static str,
    pub submit_method: &'static str,
    pub submit_path: &'static str,
    pub review_method: &'static str,
    pub review_path: &'static str,
    pub capability_rechecked_on_review: bool,
    pub legacy_method: &'static str,
    pub legacy_path: &'static str,
}

const DOCUMENTS: &[DocumentPolicy] = &[
    DocumentPolicy {
        id: "administration.overview",
        path: "overview.json",
        schema: "gw://schemas/administration/overview/v1",
        read: &Capability::ALL,
    },
    DocumentPolicy {
        id: "administration.organization",
        path: "organization.json",
        schema: "gw://schemas/administration/organization/v1",
        read: &[Capability::EditOrgSettings],
    },
    DocumentPolicy {
        id: "administration.access",
        path: "access.json",
        schema: "gw://schemas/administration/access/v1",
        read: &[Capability::ManageMembers],
    },
    DocumentPolicy {
        id: "administration.identity",
        path: "identity.json",
        schema: "gw://schemas/administration/identity/v1",
        read: &[Capability::ConfigureSso, Capability::ConfigureProvisioning],
    },
    DocumentPolicy {
        id: "administration.policy",
        path: "policy.json",
        schema: "gw://schemas/administration/policy/v1",
        read: &[Capability::ConfigureSecurity],
    },
    DocumentPolicy {
        id: "administration.software-policy",
        path: "software-policy.json",
        schema: "gw://schemas/administration/software-policy/v1",
        read: &[Capability::ConfigureSecurity],
    },
    DocumentPolicy {
        id: "administration.clients",
        path: "clients.json",
        schema: "gw://schemas/administration/clients/v1",
        read: &[Capability::ConfigureSecurity],
    },
    DocumentPolicy {
        id: "administration.machines",
        path: "machines.json",
        schema: "gw://schemas/administration/machines/v1",
        read: &[Capability::ConfigureSecurity],
    },
    DocumentPolicy {
        id: "administration.audit",
        path: "audit.json",
        schema: "gw://schemas/administration/audit/v1",
        read: &[Capability::ViewAudit],
    },
    DocumentPolicy {
        id: "administration.billing",
        path: "billing.json",
        schema: "gw://schemas/administration/billing/v1",
        read: &[Capability::ManageBilling],
    },
];

// Human review is intentionally uniform for durable tenant changes. A caller's
// UI/edit/agent/CLI label cannot turn one of these into an immediate write.
const COMMANDS: &[CommandPolicy] = &[
    CommandPolicy {
        id: "organization.update",
        document: "administration.organization",
        capability: Capability::EditOrgSettings,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/org",
    },
    CommandPolicy {
        id: "domain.verify",
        document: "administration.organization",
        capability: Capability::EditOrgSettings,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/domains/verify",
    },
    CommandPolicy {
        id: "member.invite",
        document: "administration.access",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/members",
    },
    CommandPolicy {
        id: "member.role.set",
        document: "administration.access",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/members/:id/role",
    },
    CommandPolicy {
        id: "member.deactivate",
        document: "administration.access",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/members/:id/deactivate",
    },
    CommandPolicy {
        id: "grant.add",
        document: "administration.access",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/grants",
    },
    CommandPolicy {
        id: "grant.revoke",
        document: "administration.access",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
        method: "DELETE",
        legacy_path: "/admin/grants",
    },
    CommandPolicy {
        id: "sso.configure",
        document: "administration.identity",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/sso",
    },
    CommandPolicy {
        id: "scim-token.rotate",
        document: "administration.identity",
        capability: Capability::ConfigureProvisioning,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/scim/token",
    },
    CommandPolicy {
        id: "group-mapping.set",
        document: "administration.identity",
        capability: Capability::ConfigureProvisioning,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/scim/group-mapping",
    },
    CommandPolicy {
        id: "policy.update",
        document: "administration.policy",
        capability: Capability::ConfigureSecurity,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/policy|placement-policy|security|archetype-approval",
    },
    CommandPolicy {
        id: "software-policy.update",
        document: "administration.software-policy",
        capability: Capability::ConfigureSecurity,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/software-policy",
    },
    CommandPolicy {
        id: "billing.update",
        document: "administration.billing",
        capability: Capability::ManageBilling,
        review: ReviewPolicy::Human,
        method: "POST",
        legacy_path: "/admin/billing",
    },
];

pub fn administration_route_inventory() -> Vec<ManagementRouteInventoryEntry> {
    COMMANDS
        .iter()
        .map(|command| ManagementRouteInventoryEntry {
            environment: "administration",
            command_id: command.id,
            document_id: command.document,
            authentication: "enterprise authenticated actor + admitted Environment session",
            scope_policy: "request tenant scope must exactly match session scope",
            capability: command.capability.as_str(),
            base_revision_required: true,
            idempotency_required: true,
            review: match command.review {
                ReviewPolicy::Immediate => "immediate",
                ReviewPolicy::Human => "human",
            },
            submit_method: "POST",
            submit_path: "/environments/administration/commands",
            review_method: "POST",
            review_path: "/environments/administration/changes/:id/review",
            capability_rechecked_on_review: true,
            legacy_method: command.method,
            legacy_path: command.legacy_path,
        })
        .collect()
}

pub fn routes() -> Router<SharedWorkbench> {
    Router::new()
        .route("/environments/administration/sessions", post(open_session))
        .route(
            "/environments/administration/documents/{id}",
            get(read_document),
        )
        .route(
            "/environments/administration/agent/messages",
            get(agent_messages).post(agent_message),
        )
        .route(
            "/environments/administration/domain-verification",
            get(domain_verification_challenge),
        )
        .route(
            "/environments/administration/commands",
            post(submit_command),
        )
        .route(
            "/environments/administration/changes",
            get(list_changes).post(submit_change),
        )
        .route(
            "/environments/administration/changes/{id}/review",
            post(review_change),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentMessageBody {
    session_id: String,
    scope: EnvironmentScope,
    message: String,
}

fn agent_error(error: EnvironmentAgentError) -> Response {
    let status = match error {
        EnvironmentAgentError::NoModelAccess => StatusCode::CONFLICT,
        EnvironmentAgentError::Credential(_) => StatusCode::SERVICE_UNAVAILABLE,
        EnvironmentAgentError::Provider(_) => StatusCode::BAD_GATEWAY,
        EnvironmentAgentError::InvalidOutput(_) | EnvironmentAgentError::Rejected(_) => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        EnvironmentAgentError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": error.to_string() }))).into_response()
}

fn tenant_id(headers: &HeaderMap) -> String {
    headers
        .get("x-gaugewright-tenant")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(ORG_ID)
        .to_owned()
}

fn command_scope(headers: &HeaderMap) -> String {
    format!("environment:administration:{}", req_scope(headers))
}

fn has_capability(capabilities: &[Capability], capability: Capability) -> bool {
    capabilities.contains(&capability)
}

fn can_read(capabilities: &[Capability], policy: DocumentPolicy) -> bool {
    policy
        .read
        .iter()
        .any(|capability| has_capability(capabilities, *capability))
}

fn revision(content: &Value) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            serde_json::to_vec(content).expect("JSON serializes")
        ))
    )
}

fn public_sso(connection: Option<&SsoConnectionRecord>) -> Value {
    connection.map_or(Value::Null, |connection| {
        json!({
            "protocol": connection.protocol,
            "issuer": connection.issuer,
            "audiences": connection.audiences,
            "enforce_sso": connection.enforce_sso,
            "claim_mapping": connection.claim_mapping,
            "metadata_configured": !connection.metadata.is_empty(),
        })
    })
}

fn project_document(
    wb: &Workbench,
    store_scope: &str,
    policy: DocumentPolicy,
) -> Result<Value, AdmitError> {
    let org = Org::rebuild_in(wb.store_ref(), store_scope)?;
    let value = match policy.id {
        "administration.organization" => org.org.map_or(Value::Null, |record| {
            json!({
                "display_name": record.display_name,
                "verified_domains": record.verified_domains,
                "default_region": record.default_region,
                "kind": record.kind,
            })
        }),
        "administration.access" => json!({
            "members": org.members.values().collect::<Vec<_>>(),
            "grants": org.grants.values().collect::<Vec<_>>(),
        }),
        "administration.identity" => json!({
            "sso": public_sso(org.sso.as_ref()),
            "group_mappings": org.group_mappings.values().collect::<Vec<_>>(),
        }),
        "administration.policy" => json!({
            "resource": org.policy(),
            "security": org.security,
            "placement": org.effective_placement_policy(),
            "archetype_approval": { "require_approval": org.effective_require_archetype_approval() },
        }),
        "administration.software-policy" => json!(org.software_policy.unwrap_or_default()),
        "administration.clients" => json!({ "sessions": wb.session_roster() }),
        "administration.machines" => {
            let workspace = gaugedesk_app::library_routes::workspace_value(wb);
            json!({ "homes": [{
                "id": wb.home_id().as_str(), "kind": "local", "endpoint": "",
                "state": "live", "repair_hint": Value::Null,
                "projects": workspace.get("projects").cloned().unwrap_or_else(|| json!([])),
            }] })
        }
        "administration.audit" => json!({
            "integrity": gaugedesk_app::audit::verify_in(wb.store_ref(), store_scope, Some(&wb.governance_public_key())),
            "entries": gaugedesk_app::audit::list_in(wb.store_ref(), store_scope),
        }),
        "administration.billing" => {
            let included = org
                .billing
                .as_ref()
                .and_then(|billing| billing.managed_inference.as_ref())
                .map_or(0, |plan| plan.included_tokens);
            let usage = gaugedesk_app::managed_inference::fold_usage(
                wb.store_ref(),
                store_scope,
                included,
            )?;
            json!({ "billing": org.billing, "seats_used": org.seats_used(), "managed_usage": usage })
        }
        "administration.overview" => json!({
            "organization": org.org.as_ref().map(|record| json!({
                "display_name": record.display_name,
                "verified_domains": record.verified_domains,
                "default_region": record.default_region,
                "kind": record.kind,
            })),
            "member_count": org.members.len(),
            "sso": public_sso(org.sso.as_ref()),
            "security": org.security,
            "placement": org.effective_placement_policy(),
            "audit_integrity": gaugedesk_app::audit::verify_in(wb.store_ref(), store_scope, Some(&wb.governance_public_key())),
        }),
        _ => Value::Null,
    };
    Ok(value)
}

fn extension_error(error: AdministrationExtensionError) -> Response {
    (error.status, Json(json!({ "error": error.message }))).into_response()
}

fn build_session(
    wb: &Workbench,
    headers: &HeaderMap,
    extension: Option<&AdministrationEnvironmentExtensionHandle>,
) -> Result<(EnvironmentSession, Vec<AdministrationExtensionDocument>), Response> {
    let store_scope = req_scope(headers);
    let capabilities = wb
        .admin_capabilities(bearer(headers), &store_scope)
        .map_err(|(status, message)| (status, Json(json!({ "error": message }))).into_response())?;
    if capabilities.is_empty() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "no Administration capability in this tenant" })),
        )
            .into_response());
    }
    let actor = wb.actor(bearer(headers));
    let tenant = tenant_id(headers);
    let mut projected = Vec::new();
    for policy in DOCUMENTS
        .iter()
        .copied()
        .filter(|policy| can_read(&capabilities, *policy))
    {
        let content = project_document(wb, &store_scope, policy).map_err(internal)?;
        projected.push(AdministrationExtensionDocument {
            id: policy.id.to_owned(),
            path: policy.path.to_owned(),
            schema: policy.schema.to_owned(),
            freshness: if policy.id == "administration.machines" {
                "target-live"
            } else {
                "live"
            }
            .to_owned(),
            editable: matches!(
                policy.id,
                "administration.organization"
                    | "administration.policy"
                    | "administration.software-policy"
                    | "administration.billing"
            ),
            content,
            commands: COMMANDS
                .iter()
                .filter(|command| {
                    command.document == policy.id
                        && has_capability(&capabilities, command.capability)
                })
                .map(|command| AdministrationExtensionCommand {
                    id: command.id.to_owned(),
                    capability: command.capability,
                    review: command.review,
                })
                .collect(),
        });
    }
    if let Some(extension) = extension {
        let contributed = extension
            .project(wb, &tenant, &store_scope, &actor, &capabilities)
            .map_err(extension_error)?;
        for document in contributed {
            if let Some(index) = projected.iter().position(|current| {
                current.id == document.id
                    && current.path == document.path
                    && current.schema == document.schema
            }) {
                projected[index] = document;
                continue;
            }
            if projected.iter().any(|current| current.id == document.id)
                || projected
                    .iter()
                    .any(|current| current.path == document.path)
            {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "Administration extension declared a duplicate document" })),
                )
                    .into_response());
            }
            projected.push(document);
        }
    }
    let document_grants = projected
        .iter()
        .map(|document| EnvironmentDocumentGrant {
            id: document.id.clone(),
            path: document.path.clone(),
            schema: document.schema.clone(),
            revision: revision(&document.content),
            freshness: document.freshness.clone(),
            readable: true,
            editable: document.editable,
            commands: document
                .commands
                .iter()
                .map(|command| command.id.clone())
                .collect(),
        })
        .collect::<Vec<_>>();
    let mut command_grants: Vec<EnvironmentCommandGrant> = Vec::new();
    for document in &projected {
        for command in &document.commands {
            if command_grants
                .iter()
                .any(|current| current.id == command.id)
            {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(
                        json!({ "error": "Administration extension declared a duplicate command" }),
                    ),
                )
                    .into_response());
            }
            if has_capability(&capabilities, command.capability) {
                command_grants.push(EnvironmentCommandGrant {
                    id: command.id.clone(),
                    capability: command.capability.as_str().to_owned(),
                    review: command.review,
                });
            }
        }
    }
    let scope = EnvironmentScope {
        kind: "tenant".into(),
        id: tenant,
    };
    let capability_names = capabilities
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect::<Vec<_>>();
    // Session identity tracks authorization, not mutable projection content.
    // Each document carries its own exact base revision; folding document hashes
    // into the session id would make the proposal's own audit row invalidate the
    // session before a human could review it.
    let epoch = revision(&json!({ "actor": actor, "capabilities": capability_names }));
    let session = EnvironmentSession {
        id: environment_session_id(&actor, ENVIRONMENT, &scope, &epoch),
        environment: ENVIRONMENT,
        scope,
        actor,
        capabilities: capability_names,
        documents: document_grants,
        commands: command_grants,
    };
    Ok((session, projected))
}

fn internal(error: impl std::fmt::Debug) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": format!("environment projection unavailable: {error:?}") })),
    )
        .into_response()
}

fn extension_ref(
    extension: &Option<Extension<AdministrationEnvironmentExtensionHandle>>,
) -> Option<&AdministrationEnvironmentExtensionHandle> {
    extension.as_ref().map(|Extension(extension)| extension)
}

#[derive(Deserialize)]
struct OpenBody {
    #[serde(default)]
    scope: Option<EnvironmentScope>,
}

async fn open_session(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationEnvironmentExtensionHandle>>,
    headers: HeaderMap,
    Json(body): Json<OpenBody>,
) -> Response {
    let guard = wb.lock_unpoisoned();
    match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok((session, _))
            if body
                .scope
                .as_ref()
                .is_some_and(|scope| scope != &session.scope) =>
        {
            (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "requested scope is not the admitted tenant" })),
            )
                .into_response()
        }
        Ok((session, _)) => (StatusCode::OK, Json(json!({ "session": session }))).into_response(),
        Err(response) => response,
    }
}

#[derive(Deserialize)]
struct SessionQuery {
    session: String,
    scope: String,
}

#[derive(Deserialize)]
struct DomainChallengeQuery {
    session: String,
    scope: String,
    domain: String,
}

async fn domain_verification_challenge(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationEnvironmentExtensionHandle>>,
    Query(query): Query<DomainChallengeQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if query.session != session.id || query.scope != session.scope.id {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "environment session is stale or cross-scope" })),
        )
            .into_response();
    }
    if !session
        .commands
        .iter()
        .any(|command| command.id == "domain.verify")
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "domain verification is not admitted" })),
        )
            .into_response();
    }
    let domain = query.domain.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "domain is required" })),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(json!({
            "domain": domain,
            "record_name": format!("_gaugewright-challenge.{domain}"),
            "record_type": "TXT",
            "value": crate::org_routes::expected_txt(&domain),
        })),
    )
        .into_response()
}

async fn read_document(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationEnvironmentExtensionHandle>>,
    Path(id): Path<String>,
    Query(query): Query<SessionQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let (session, projected) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if query.session != session.id || query.scope != session.scope.id {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "environment session is stale or cross-scope" })),
        )
            .into_response();
    }
    let Some(document) = projected.into_iter().find(|document| document.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "document is not admitted" })),
        )
            .into_response();
    };
    let grant = session
        .documents
        .iter()
        .find(|document| document.id == id)
        .expect("projected document has grant");
    (
        StatusCode::OK,
        Json(json!({ "document": {
            "id": document.id, "path": document.path, "schema": document.schema,
            "revision": grant.revision, "freshness": grant.freshness, "content": document.content,
    } })),
    )
        .into_response()
}

async fn agent_message(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationEnvironmentExtensionHandle>>,
    headers: HeaderMap,
    Json(body): Json<AgentMessageBody>,
) -> Response {
    let context = {
        let guard = wb.lock_unpoisoned();
        let (session, projected) = match build_session(&guard, &headers, extension_ref(&extension))
        {
            Ok(value) => value,
            Err(response) => return response,
        };
        if body.session_id != session.id || body.scope != session.scope {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "agent session is stale or cross-scope" })),
            )
                .into_response();
        }
        let documents = projected
            .into_iter()
            .map(|document| {
                let grant = session
                    .documents
                    .iter()
                    .find(|grant| grant.id == document.id)
                    .expect("projected Administration document has a grant");
                EnvironmentAgentDocument {
                    id: grant.id.clone(),
                    path: grant.path.clone(),
                    revision: grant.revision.clone(),
                    content: document.content,
                    commands: grant.commands.clone(),
                }
            })
            .collect();
        EnvironmentAgentContext { session, documents }
    };
    let transcript_session = context.session.clone();
    let transcript_user = body.message.clone();
    let runtime_wb = wb.clone();
    match tokio::task::spawn_blocking(move || {
        run_environment_agent_turn(&runtime_wb, context, &body.message)
    })
    .await
    {
        Ok(Ok(turn)) => match append_environment_agent_exchange(
            &wb,
            &transcript_session,
            &transcript_user,
            &turn.message,
        ) {
            Ok(transcript) => (
                StatusCode::OK,
                Json(json!({ "turn": turn, "transcript": transcript })),
            )
                .into_response(),
            Err(error) => agent_error(error),
        },
        Ok(Err(error)) => agent_error(error),
        Err(_) => agent_error(EnvironmentAgentError::Provider("agent task failed".into())),
    }
}

async fn agent_messages(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationEnvironmentExtensionHandle>>,
    Query(query): Query<SessionQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if query.session != session.id || query.scope != session.scope.id {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "agent session is stale or cross-scope" })),
        )
            .into_response();
    }
    match environment_agent_transcript(guard.store_ref(), &session) {
        Ok(transcript) => {
            (StatusCode::OK, Json(json!({ "transcript": transcript }))).into_response()
        }
        Err(error) => agent_error(EnvironmentAgentError::Store(format!("{error:?}"))),
    }
}

fn command_policy(id: &str) -> Option<CommandPolicy> {
    COMMANDS.iter().copied().find(|command| command.id == id)
}

fn reject_environment(
    error: gaugedesk_app::environment_contract::EnvironmentRejection,
) -> Response {
    let status = if matches!(
        error,
        gaugedesk_app::environment_contract::EnvironmentRejection::StaleBase
    ) {
        StatusCode::CONFLICT
    } else {
        StatusCode::FORBIDDEN
    };
    (
        status,
        Json(json!({ "error": error.message(), "rejection": error })),
    )
        .into_response()
}

fn contains_secret(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            matches!(
                key.as_str(),
                "password"
                    | "secret"
                    | "token"
                    | "private_key"
                    | "credential"
                    | "refresh_token"
                    | "access_token"
            ) || contains_secret(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret),
        _ => false,
    }
}

type MutationPlan = AdministrationMutationPlan;

fn fact(
    scope: &str,
    kind: &str,
    value: impl serde::Serialize,
) -> Result<CommandRecordFact, Response> {
    Ok(CommandRecordFact {
        scope_id: scope.to_owned(),
        kind: kind.to_owned(),
        payload: serde_json::to_string(&value).map_err(internal)?,
    })
}

#[derive(Deserialize)]
struct OrganizationPayload {
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    verified_domains: Vec<String>,
    #[serde(default)]
    default_region: Option<String>,
    #[serde(default)]
    kind: OrgKind,
}
#[derive(Deserialize)]
struct DomainPayload {
    domain: String,
}
#[derive(Deserialize)]
struct InvitePayload {
    #[serde(default)]
    id: Option<String>,
    authority: String,
    #[serde(default)]
    email: String,
    role: String,
    #[serde(default)]
    team: Option<String>,
}
#[derive(Deserialize)]
struct MemberRolePayload {
    id: String,
    role: String,
}
#[derive(Deserialize)]
struct MemberPayload {
    id: String,
}
#[derive(Deserialize)]
struct GrantPayload {
    authority: String,
    project_id: String,
}
#[derive(Deserialize)]
struct PolicyPayload {
    resource: Policy,
    security: SecurityPolicyRecord,
    placement: gaugedesk_core::boundary_lifecycle::PlacementPolicy,
    archetype_approval: ArchetypeApprovalPolicyRecord,
}

fn parse<T: serde::de::DeserializeOwned>(payload: &Value) -> Result<T, Response> {
    serde_json::from_value(payload.clone()).map_err(|error| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": format!("invalid command payload: {error}") })),
        )
            .into_response()
    })
}

fn plan_command(
    wb: &Workbench,
    headers: &HeaderMap,
    command: &EnvironmentCommandEnvelope,
    extension: Option<&AdministrationEnvironmentExtensionHandle>,
) -> Result<MutationPlan, Response> {
    if command_policy(&command.command_id).is_none() {
        if let Some(extension) = extension {
            let actor = wb.actor(bearer(headers));
            if let Some(plan) = extension
                .plan(
                    wb,
                    &tenant_id(headers),
                    &req_scope(headers),
                    &actor,
                    command,
                )
                .map_err(extension_error)?
            {
                return Ok(plan);
            }
        }
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "unknown Administration command" })),
        )
            .into_response());
    }
    if contains_secret(&command.payload) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "secret-bearing fields are forbidden in Environment commands" })),
        )
            .into_response());
    }
    let scope = req_scope(headers);
    let org = Org::rebuild_in(wb.store_ref(), &scope).map_err(internal)?;
    let plan = match command.command_id.as_str() {
        "organization.update" => {
            let value: OrganizationPayload = parse(&command.payload)?;
            let current_domains = org
                .org
                .as_ref()
                .map(|record| record.verified_domains.clone())
                .unwrap_or_default();
            if value.verified_domains != current_domains {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "verified domains require the domain-verification command" })),
                )
                    .into_response());
            }
            let record = OrgRecord {
                id: ORG_ID.into(),
                op: RecordOp::Upsert,
                display_name: value.display_name,
                verified_domains: current_domains,
                default_region: value.default_region,
                kind: value.kind,
            };
            MutationPlan {
                facts: vec![fact(&scope, "org", &record)?],
                notices: vec![("org", record.id.clone(), "upsert")],
                audit_action: "org.update",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "domain.verify" => {
            let value: DomainPayload = parse(&command.payload)?;
            let domain = value.domain.trim().to_ascii_lowercase();
            if domain.is_empty() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "domain is required" })),
                )
                    .into_response());
            }
            let mut record = org.org.clone().unwrap_or_default();
            record.id = ORG_ID.into();
            record.op = RecordOp::Upsert;
            if !record
                .verified_domains
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&domain))
            {
                record.verified_domains.push(domain.clone());
                record.verified_domains.sort();
                record.verified_domains.dedup();
            }
            MutationPlan {
                facts: vec![fact(&scope, "org", &record)?],
                notices: vec![("org", record.id.clone(), "upsert")],
                audit_action: "domain.verified",
                audit_target: domain,
                transient_result: None,
            }
        }
        "member.invite" => {
            let value: InvitePayload = parse(&command.payload)?;
            if !gaugedesk_app::org::is_valid_role(&value.role) || value.authority.trim().is_empty()
            {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "authority and a fixed role are required" })),
                )
                    .into_response());
            }
            let record = MembershipRecord {
                id: value.id.unwrap_or_else(|| value.authority.clone()),
                op: RecordOp::Upsert,
                org_id: ORG_ID.into(),
                authority: value.authority,
                email: value.email,
                role: value.role,
                status: MembershipStatus::Invited,
                managed_by_scim: false,
                team: value.team,
            };
            MutationPlan {
                facts: vec![fact(&scope, "membership", &record)?],
                notices: vec![("membership", record.id.clone(), "upsert")],
                audit_action: "member.invite",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "member.role.set" => {
            let value: MemberRolePayload = parse(&command.payload)?;
            if !gaugedesk_app::org::is_valid_role(&value.role) {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "unknown role" })),
                )
                    .into_response());
            }
            let Some(existing) = org.members.get(&value.id) else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "no such member" })),
                )
                    .into_response());
            };
            if !wb.team_scope_ok(bearer(headers), existing.team.as_deref()) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "outside your team scope" })),
                )
                    .into_response());
            }
            if existing.role == "owner"
                && existing.status == MembershipStatus::Active
                && value.role != "owner"
                && org.active_count_with_role("owner") <= 1
            {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "cannot demote the last owner" })),
                )
                    .into_response());
            }
            let mut record = existing.clone();
            record.op = RecordOp::Upsert;
            record.role = value.role;
            MutationPlan {
                facts: vec![fact(&scope, "membership", &record)?],
                notices: vec![("membership", record.id.clone(), "upsert")],
                audit_action: "member.role",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "member.deactivate" => {
            let value: MemberPayload = parse(&command.payload)?;
            let Some(existing) = org.members.get(&value.id) else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "no such member" })),
                )
                    .into_response());
            };
            if !wb.team_scope_ok(bearer(headers), existing.team.as_deref()) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "outside your team scope" })),
                )
                    .into_response());
            }
            if existing.role == "owner"
                && existing.status == MembershipStatus::Active
                && org.active_count_with_role("owner") <= 1
            {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "cannot deactivate the last owner" })),
                )
                    .into_response());
            }
            let mut record = existing.clone();
            record.op = RecordOp::Upsert;
            record.status = MembershipStatus::Deprovisioned;
            MutationPlan {
                facts: vec![fact(&scope, "membership", &record)?],
                notices: vec![("membership", record.id.clone(), "upsert")],
                audit_action: "member.deactivate",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "grant.add" | "grant.revoke" => {
            let value: GrantPayload = parse(&command.payload)?;
            if value.authority.trim().is_empty() || value.project_id.trim().is_empty() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "authority and project_id are required" })),
                )
                    .into_response());
            }
            let record = MemberGrantRecord {
                id: MemberGrantRecord::make_id(&value.authority, &value.project_id),
                op: if command.command_id == "grant.add" {
                    RecordOp::Upsert
                } else {
                    RecordOp::Tombstone
                },
                authority: value.authority,
                project_id: value.project_id,
            };
            let op = if command.command_id == "grant.add" {
                "upsert"
            } else {
                "tombstone"
            };
            MutationPlan {
                facts: vec![fact(&scope, "member_grant", &record)?],
                notices: vec![("member_grant", record.id.clone(), op)],
                audit_action: if command.command_id == "grant.add" {
                    "grant.add"
                } else {
                    "grant.revoke"
                },
                audit_target: record.id,
                transient_result: None,
            }
        }
        "sso.configure" => {
            let mut record: SsoConnectionRecord = parse(&command.payload)?;
            record.id = ORG_ID.into();
            record.op = RecordOp::Upsert;
            MutationPlan {
                facts: vec![fact(&scope, "sso", &record)?],
                notices: vec![("sso", record.id.clone(), "upsert")],
                audit_action: "sso.configure",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "scim-token.rotate" => {
            let mut bytes = [0_u8; 32];
            getrandom::getrandom(&mut bytes).map_err(internal)?;
            let token = hex::encode(bytes);
            let record = ScimTokenRecord {
                id: ORG_ID.into(),
                op: RecordOp::Upsert,
                token_sha256: sha256_hex(&token),
            };
            MutationPlan {
                facts: vec![fact(&scope, "scim_token", &record)?],
                notices: vec![("scim_token", record.id.clone(), "upsert")],
                audit_action: "scim.token.rotate",
                audit_target: record.id,
                transient_result: Some(json!({ "token": token })),
            }
        }
        "group-mapping.set" => {
            let value: crate::org_routes::GroupMappingBody = parse(&command.payload)?;
            if !gaugedesk_app::org::is_valid_role(&value.role) || value.group.trim().is_empty() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "group and a fixed role are required" })),
                )
                    .into_response());
            }
            let record = GroupMappingRecord {
                id: value.group.clone(),
                op: RecordOp::Upsert,
                group: value.group,
                role: value.role,
                team: value.team,
            };
            MutationPlan {
                facts: vec![fact(&scope, "group_mapping", &record)?],
                notices: vec![("group_mapping", record.id.clone(), "upsert")],
                audit_action: "group_mapping.update",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "policy.update" => {
            let value: PolicyPayload = parse(&command.payload)?;
            let resource = PolicyRecord {
                id: ORG_ID.into(),
                op: RecordOp::Upsert,
                policy: value.resource,
            };
            let mut security = value.security;
            security.id = ORG_ID.into();
            security.op = RecordOp::Upsert;
            let placement = PlacementPolicyRecord {
                id: ORG_ID.into(),
                op: RecordOp::Upsert,
                policy: value.placement,
            };
            let mut approval = value.archetype_approval;
            approval.id = ORG_ID.into();
            approval.op = RecordOp::Upsert;
            MutationPlan {
                facts: vec![
                    fact(&scope, "policy", &resource)?,
                    fact(&scope, "security", &security)?,
                    fact(&scope, "placement_policy", &placement)?,
                    fact(&scope, "archetype_approval", &approval)?,
                ],
                notices: vec![
                    ("policy", ORG_ID.into(), "upsert"),
                    ("security", ORG_ID.into(), "upsert"),
                    ("placement_policy", ORG_ID.into(), "upsert"),
                    ("archetype_approval", ORG_ID.into(), "upsert"),
                ],
                audit_action: "policy.update",
                audit_target: ORG_ID.into(),
                transient_result: None,
            }
        }
        "software-policy.update" => {
            let mut policy: gaugedesk_app::client_admission::SoftwarePolicy =
                parse(&command.payload)?;
            policy.minimum_version = policy.minimum_version.trim().to_owned();
            policy.allowed_channels = policy
                .allowed_channels
                .into_iter()
                .map(|channel| channel.trim().to_ascii_lowercase())
                .filter(|channel| !channel.is_empty())
                .collect();
            policy.allowed_channels.sort();
            policy.allowed_channels.dedup();
            if policy.grace_until_unix_ms == Some(0) {
                policy.grace_until_unix_ms = None;
            }
            if let Err(message) = policy.validate() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": message })),
                )
                    .into_response());
            }
            let record = SoftwarePolicyRecord {
                id: ORG_ID.into(),
                op: RecordOp::Upsert,
                policy,
            };
            MutationPlan {
                facts: vec![fact(&scope, "software_policy", &record)?],
                notices: vec![("software_policy", record.id.clone(), "upsert")],
                audit_action: "software_policy.update",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "billing.update" => {
            let mut record: BillingRecord = parse(&command.payload)?;
            record.id = ORG_ID.into();
            record.op = RecordOp::Upsert;
            MutationPlan {
                facts: vec![fact(&scope, "billing", &record)?],
                notices: vec![("billing", record.id.clone(), "upsert")],
                audit_action: "billing.update",
                audit_target: record.id,
                transient_result: None,
            }
        }
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unknown Administration command" })),
            )
                .into_response())
        }
    };
    Ok(plan)
}

fn proposed_change(
    session: &EnvironmentSession,
    envelope: &EnvironmentCommandEnvelope,
    key: &str,
) -> EnvironmentChangeRecord {
    let receipt = environment_receipt(session, envelope, key, "proposed");
    EnvironmentChangeRecord {
        id: environment_change_id(session, envelope, key),
        environment: ENVIRONMENT,
        scope: session.scope.clone(),
        actor: session.actor.clone(),
        document_id: envelope.document_id.clone(),
        command_id: envelope.command_id.clone(),
        base_revision: envelope.base_revision.clone(),
        payload: envelope.payload.clone(),
        client: envelope.client,
        status: EnvironmentChangeStatus::Proposed,
        reviewed_by: None,
        receipt_id: receipt.id,
    }
}

fn snapshot(envelope: &EnvironmentCommandEnvelope) -> String {
    serde_json::to_string(envelope).expect("command envelope serializes")
}

fn idempotency(headers: &HeaderMap) -> Result<String, Response> {
    gaugedesk_app::command_idempotency::caller_idempotency_key(headers)
}

/// Return a previously committed exact command result before re-evaluating its
/// old base revision. Authentication and current session identity have already
/// been rebuilt, but a successful identical retry must retain its first receipt
/// even when later commands advanced the document.
fn replayed_command_response(
    wb: &Workbench,
    headers: &HeaderMap,
    session: &EnvironmentSession,
    envelope: &EnvironmentCommandEnvelope,
    key: &str,
) -> Result<Option<Response>, Response> {
    let record = wb
        .store_ref()
        .command_for_key(&command_scope(headers), key)
        .map_err(internal)?;
    let Some(record) = record else {
        return Ok(None);
    };
    if record.snapshot_json != snapshot(envelope) {
        return Err(store_error(AdmitError::Rejected(
            gaugedesk_core::Rejection {
                reason: "idempotency key reused with different command",
            },
        )));
    }
    let id = environment_change_id(session, envelope, key);
    let change = fold_environment_changes(wb.store_ref(), &req_scope(headers))
        .map_err(internal)?
        .remove(&id)
        .ok_or_else(|| {
            internal(std::io::Error::other(
                "Environment command receipt is missing its durable change",
            ))
        })?;
    let status =
        command_policy(&envelope.command_id).map_or("applied", |policy| match policy.review {
            ReviewPolicy::Immediate => "applied",
            ReviewPolicy::Human => "proposed",
        });
    Ok(Some(
        (
            StatusCode::OK,
            Json(json!({
                "receipt": environment_receipt(session, envelope, key, status),
                "change": change,
            })),
        )
            .into_response(),
    ))
}

async fn submit_command(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationEnvironmentExtensionHandle>>,
    headers: HeaderMap,
    Json(envelope): Json<EnvironmentCommandEnvelope>,
) -> Response {
    let key = match idempotency(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let mut guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if envelope.session_id == session.id
        && envelope.environment == session.environment
        && envelope.scope == session.scope
    {
        match replayed_command_response(&guard, &headers, &session, &envelope, &key) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    let admission = match decide_environment_command(&session, &envelope) {
        Ok(value) => value,
        Err(error) => return reject_environment(error),
    };
    if contains_secret(&envelope.payload) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "secret-bearing fields are forbidden in Environment commands" })),
        )
            .into_response();
    }
    // Parse and validate the owning Environment's closed command before a
    // proposal becomes durable. Review re-runs this planner against fresh state.
    if let Err(response) = plan_command(&guard, &headers, &envelope, extension_ref(&extension)) {
        return response;
    }
    match admission.disposition {
        AdmissionDisposition::Propose => {
            let change = proposed_change(&session, &envelope, &key);
            let change_fact = match fact(&req_scope(&headers), ENVIRONMENT_CHANGE_KIND, &change) {
                Ok(fact) => fact,
                Err(response) => return response,
            };
            let audit_link = gaugedesk_app::audit::link(
                &session.actor,
                "environment.change.proposed",
                &change.id,
            );
            let store_scope = req_scope(&headers);
            let audit_scope = gaugedesk_app::audit::scope_for(&store_scope);
            let result = match guard.store_mut().admit_record_facts_chained(
                &command_scope(&headers),
                &key,
                &snapshot(&envelope),
                &[change_fact],
                Some(gaugedesk_app::audit::chained_in(&audit_scope, &audit_link)),
            ) {
                Ok(result) => result,
                Err(error) => return store_error(error),
            };
            if let Some(entry) =
                gaugedesk_app::audit::committed_entry(result.chained_payload.as_deref())
            {
                gaugedesk_app::audit::finish_committed_in(&mut guard, &store_scope, &entry);
            }
            (StatusCode::OK, Json(json!({ "receipt": environment_receipt(&session, &envelope, &key, "proposed"), "change": change }))).into_response()
        }
        AdmissionDisposition::Apply => {
            apply_command(
                &mut guard,
                &headers,
                &session,
                &envelope,
                &key,
                None,
                extension_ref(&extension),
            )
            .0
        }
    }
}

fn apply_command(
    wb: &mut Workbench,
    headers: &HeaderMap,
    session: &EnvironmentSession,
    envelope: &EnvironmentCommandEnvelope,
    key: &str,
    change: Option<EnvironmentChangeRecord>,
    extension: Option<&AdministrationEnvironmentExtensionHandle>,
) -> (Response, bool) {
    let plan = match plan_command(wb, headers, envelope, extension) {
        Ok(plan) => plan,
        Err(response) => return (response, false),
    };
    let operation_key = change
        .as_ref()
        .map(|change| change.id.as_str())
        .unwrap_or(key);
    let plan = if let Some(extension) = extension {
        match extension.apply(
            wb,
            &tenant_id(headers),
            &req_scope(headers),
            &session.actor,
            envelope,
            operation_key,
            plan,
        ) {
            Ok(plan) => plan,
            Err(error) => return (extension_error(error), false),
        }
    } else {
        plan
    };
    let mut applied_change = change.unwrap_or_else(|| proposed_change(session, envelope, key));
    applied_change.status = EnvironmentChangeStatus::Applied;
    applied_change.reviewed_by = Some(session.actor.clone());
    let mut facts = plan.facts.clone();
    let change_fact = match fact(
        &req_scope(headers),
        ENVIRONMENT_CHANGE_KIND,
        &applied_change,
    ) {
        Ok(fact) => fact,
        Err(response) => return (response, false),
    };
    facts.push(change_fact);
    let audit_link =
        gaugedesk_app::audit::link(&session.actor, plan.audit_action, &plan.audit_target);
    let store_scope = req_scope(headers);
    let audit_scope = gaugedesk_app::audit::scope_for(&store_scope);
    let result = match wb.store_mut().admit_record_facts_chained(
        &command_scope(headers),
        key,
        &snapshot(envelope),
        &facts,
        Some(gaugedesk_app::audit::chained_in(&audit_scope, &audit_link)),
    ) {
        Ok(result) => result,
        Err(error) => return (store_error(error), false),
    };
    if !result.replayed {
        for (kind, id, op) in &plan.notices {
            wb.notify_library_changed(kind, id, op);
        }
        if let Some(entry) =
            gaugedesk_app::audit::committed_entry(result.chained_payload.as_deref())
        {
            gaugedesk_app::audit::finish_committed_in(wb, &store_scope, &entry);
        }
    }
    let freshly_applied = !result.replayed;
    ((StatusCode::OK, Json(json!({
        "receipt": environment_receipt(session, envelope, key, "applied"),
        "change": applied_change,
        "result": if result.replayed { Value::Null } else { plan.transient_result.unwrap_or(Value::Null) },
    }))).into_response(), freshly_applied)
}

fn store_error(error: AdmitError) -> Response {
    match error {
        AdmitError::Rejected(rejection) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": rejection.reason, "rejected": rejection.reason })),
        )
            .into_response(),
        other => internal(other),
    }
}

#[derive(Deserialize)]
struct ChangeBody {
    session_id: String,
    environment: EnvironmentKind,
    scope: EnvironmentScope,
    document_id: String,
    base_revision: String,
    content: Value,
    client: EnvironmentClient,
}

async fn submit_change(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationEnvironmentExtensionHandle>>,
    headers: HeaderMap,
    Json(body): Json<ChangeBody>,
) -> Response {
    let (session, projected) = {
        let guard = wb.lock_unpoisoned();
        match build_session(&guard, &headers, extension_ref(&extension)) {
            Ok(value) => value,
            Err(response) => return response,
        }
    };
    if body.session_id != session.id
        || body.environment != ENVIRONMENT
        || body.scope != session.scope
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "environment session is stale or cross-scope" })),
        )
            .into_response();
    }
    let Some(document) = projected
        .iter()
        .find(|document| document.id == body.document_id)
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "document is not admitted" })),
        )
            .into_response();
    };
    let command_id = match document.id.as_str() {
        "administration.organization" => "organization.update",
        "administration.policy" => "policy.update",
        "administration.software-policy" => "software-policy.update",
        "administration.billing" => "billing.update",
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "document is read-only or has no closed edit parser" })),
            )
                .into_response()
        }
    };
    let envelope = EnvironmentCommandEnvelope {
        session_id: body.session_id,
        environment: body.environment,
        scope: body.scope,
        document_id: body.document_id,
        command_id: command_id.into(),
        base_revision: body.base_revision,
        payload: body.content,
        client: body.client,
    };
    submit_command(State(wb), extension, headers, Json(envelope)).await
}

async fn list_changes(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationEnvironmentExtensionHandle>>,
    Query(query): Query<SessionQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if query.session != session.id || query.scope != session.scope.id {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "environment session is stale or cross-scope" })),
        )
            .into_response();
    }
    let changes = match fold_environment_changes(guard.store_ref(), &req_scope(&headers)) {
        Ok(changes) => changes,
        Err(error) => return internal(error),
    };
    let values = changes
        .into_values()
        .filter(|change| change.environment == ENVIRONMENT && change.scope == session.scope)
        .collect::<Vec<_>>();
    (StatusCode::OK, Json(json!({ "changes": values }))).into_response()
}

#[derive(Deserialize)]
struct ReviewBody {
    session_id: String,
    environment: EnvironmentKind,
    scope: EnvironmentScope,
    decision: String,
    #[serde(default = "browser_client")]
    client: EnvironmentClient,
}
fn browser_client() -> EnvironmentClient {
    EnvironmentClient::Browser
}

async fn verify_domain_review_evidence(
    wb: &SharedWorkbench,
    headers: &HeaderMap,
    id: &str,
    body: &ReviewBody,
    extension: Option<&AdministrationEnvironmentExtensionHandle>,
) -> Result<(), Response> {
    if body.decision != "accept" {
        return Ok(());
    }
    let domain = {
        let guard = wb.lock_unpoisoned();
        let (session, _) = build_session(&guard, headers, extension)?;
        if body.session_id != session.id
            || body.environment != ENVIRONMENT
            || body.scope != session.scope
        {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "environment session is stale or cross-scope" })),
            )
                .into_response());
        }
        let changes =
            fold_environment_changes(guard.store_ref(), &req_scope(headers)).map_err(internal)?;
        let Some(change) = changes.get(id) else {
            return Ok(());
        };
        if change.status != EnvironmentChangeStatus::Proposed
            || change.command_id != "domain.verify"
        {
            return Ok(());
        }
        parse::<DomainPayload>(&change.payload)?.domain
    };
    let domain = domain.trim().to_ascii_lowercase();
    if crate::org_routes::domain_proof_matches(&domain).await {
        return Ok(());
    }
    Err((
        StatusCode::CONFLICT,
        Json(json!({
            "error": "DNS TXT proof is not present; the proposal remains open",
            "domain": domain,
            "expected": {
                "record_name": format!("_gaugewright-challenge.{domain}"),
                "record_type": "TXT",
                "value": crate::org_routes::expected_txt(&domain),
            },
        })),
    )
        .into_response())
}

async fn review_change(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationEnvironmentExtensionHandle>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ReviewBody>,
) -> Response {
    let key = match idempotency(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    if let Err(response) =
        verify_domain_review_evidence(&wb, &headers, &id, &body, extension_ref(&extension)).await
    {
        return response;
    }
    let mut guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if body.session_id != session.id
        || body.environment != ENVIRONMENT
        || body.scope != session.scope
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "environment session is stale or cross-scope" })),
        )
            .into_response();
    }
    let changes = match fold_environment_changes(guard.store_ref(), &req_scope(&headers)) {
        Ok(changes) => changes,
        Err(error) => return internal(error),
    };
    let Some(mut change) = changes.get(&id).cloned() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such Environment change" })),
        )
            .into_response();
    };
    let envelope = EnvironmentCommandEnvelope {
        session_id: session.id.clone(),
        environment: ENVIRONMENT,
        scope: session.scope.clone(),
        document_id: change.document_id.clone(),
        command_id: change.command_id.clone(),
        base_revision: change.base_revision.clone(),
        payload: change.payload.clone(),
        client: body.client,
    };
    if change.status != EnvironmentChangeStatus::Proposed {
        let expected_snapshot = if body.decision == "accept" {
            snapshot(&envelope)
        } else {
            serde_json::to_string(&json!({ "change": id, "decision": body.decision })).unwrap()
        };
        if let Ok(Some(record)) = guard
            .store_ref()
            .command_for_key(&command_scope(&headers), &key)
        {
            if record.status == "applied" && record.snapshot_json == expected_snapshot {
                let status = match change.status {
                    EnvironmentChangeStatus::Applied => "applied",
                    EnvironmentChangeStatus::Rejected => "rejected",
                    EnvironmentChangeStatus::Conflict => "conflict",
                    EnvironmentChangeStatus::Proposed => unreachable!(),
                };
                let code = if change.status == EnvironmentChangeStatus::Conflict {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::OK
                };
                return (
                    code,
                    Json(json!({ "receipt": environment_receipt(&session, &envelope, &key, status), "change": change })),
                )
                    .into_response();
            }
        }
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "Environment change is already terminal" })),
        )
            .into_response();
    }
    if body.decision == "reject" {
        change.status = EnvironmentChangeStatus::Rejected;
        change.reviewed_by = Some(session.actor.clone());
        let change_fact = match fact(&req_scope(&headers), ENVIRONMENT_CHANGE_KIND, &change) {
            Ok(fact) => fact,
            Err(response) => return response,
        };
        let audit_link =
            gaugedesk_app::audit::link(&session.actor, "environment.change.rejected", &id);
        let store_scope = req_scope(&headers);
        let audit_scope = gaugedesk_app::audit::scope_for(&store_scope);
        let result = match guard.store_mut().admit_record_facts_chained(
            &command_scope(&headers),
            &key,
            &serde_json::to_string(&json!({ "change": id, "decision": "reject" })).unwrap(),
            &[change_fact],
            Some(gaugedesk_app::audit::chained_in(&audit_scope, &audit_link)),
        ) {
            Ok(result) => result,
            Err(error) => return store_error(error),
        };
        if let Some(entry) =
            gaugedesk_app::audit::committed_entry(result.chained_payload.as_deref())
        {
            gaugedesk_app::audit::finish_committed_in(&mut guard, &store_scope, &entry);
        }
        return (StatusCode::OK, Json(json!({ "receipt": environment_receipt(&session, &envelope, &key, "rejected"), "change": change }))).into_response();
    }
    if body.decision != "accept" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "review decision must be accept or reject" })),
        )
            .into_response();
    }
    if let Err(error) = decide_reviewed_environment_command(&session, &envelope) {
        if matches!(
            error,
            gaugedesk_app::environment_contract::EnvironmentRejection::StaleBase
        ) {
            change.status = EnvironmentChangeStatus::Conflict;
            change.reviewed_by = Some(session.actor.clone());
            let conflict_fact = match fact(&req_scope(&headers), ENVIRONMENT_CHANGE_KIND, &change) {
                Ok(fact) => fact,
                Err(response) => return response,
            };
            let audit_link =
                gaugedesk_app::audit::link(&session.actor, "environment.change.conflict", &id);
            let store_scope = req_scope(&headers);
            let audit_scope = gaugedesk_app::audit::scope_for(&store_scope);
            let result = match guard.store_mut().admit_record_facts_chained(
                &command_scope(&headers),
                &key,
                &snapshot(&envelope),
                &[conflict_fact],
                Some(gaugedesk_app::audit::chained_in(&audit_scope, &audit_link)),
            ) {
                Ok(result) => result,
                Err(error) => return store_error(error),
            };
            if let Some(entry) =
                gaugedesk_app::audit::committed_entry(result.chained_payload.as_deref())
            {
                gaugedesk_app::audit::finish_committed_in(&mut guard, &store_scope, &entry);
            }
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "receipt": environment_receipt(&session, &envelope, &key, "conflict"),
                    "change": change,
                    "error": error.message(),
                    "rejection": error,
                })),
            )
                .into_response();
        }
        return reject_environment(error);
    }
    // The review intent gets its own idempotency key, while the applied change
    // retains the original proposal identity.
    let sso = if envelope.command_id == "sso.configure" {
        serde_json::from_value::<SsoConnectionRecord>(envelope.payload.clone()).ok()
    } else {
        None
    };
    let (response, freshly_applied) = apply_command(
        &mut guard,
        &headers,
        &session,
        &envelope,
        &key,
        Some(change),
        extension_ref(&extension),
    );
    drop(guard);
    if freshly_applied {
        if let Some(sso) = sso {
            let activation_wb = wb.clone();
            tokio::spawn(async move {
                let _ = crate::auth_oidc::activate_updated_idp(&activation_wb, sso).await;
            });
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use gaugedesk_app::identity::LoopbackIdentityProvider;
    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::ids::AuthorityId;
    use gaugedesk_store::Store;
    use gaugedesk_workspace::Instance;

    fn test_app_as(role: &str) -> (tempfile::TempDir, SharedWorkbench, Router) {
        let dir = tempfile::tempdir().unwrap();
        let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let idp = LoopbackIdentityProvider::new().enroll(
            "owner-token",
            AuthorityId::new("authority:owner"),
            AuthorityAttributes::default(),
        );
        let mut wb = Workbench::with_target(
            "environment-test",
            instance,
            Store::open_in_memory().unwrap(),
        )
        .with_identity_provider(Arc::new(idp));
        let owner = MembershipRecord {
            id: "owner".into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: "authority:owner".into(),
            email: "owner@example.test".into(),
            role: role.into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        };
        wb.store_mut()
            .append_record("org", "membership", &serde_json::to_string(&owner).unwrap())
            .unwrap();
        let shared = Arc::new(Mutex::new(wb));
        let app = routes().with_state(shared.clone());
        (dir, shared, app)
    }

    fn test_app() -> (tempfile::TempDir, SharedWorkbench, Router) {
        test_app_as("owner")
    }

    struct TestAdministrationExtension;

    impl AdministrationEnvironmentExtension for TestAdministrationExtension {
        fn project(
            &self,
            wb: &Workbench,
            _tenant_id: &str,
            store_scope: &str,
            _actor: &str,
            capabilities: &[Capability],
        ) -> Result<Vec<AdministrationExtensionDocument>, AdministrationExtensionError> {
            if !capabilities.contains(&Capability::ConfigureSecurity) {
                return Ok(Vec::new());
            }
            let rows = wb
                .store_ref()
                .records(store_scope, "test_backup")
                .map_err(|error| {
                    AdministrationExtensionError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("test projection failed: {error:?}"),
                    )
                })?;
            Ok(vec![AdministrationExtensionDocument {
                id: "administration.backups".into(),
                path: "backups.json".into(),
                schema: "gw://schemas/administration/backups/v1".into(),
                freshness: "live".into(),
                editable: false,
                content: json!({ "records": rows }),
                commands: vec![AdministrationExtensionCommand {
                    id: "backup.enable".into(),
                    capability: Capability::ConfigureSecurity,
                    review: ReviewPolicy::Human,
                }],
            }])
        }

        fn plan(
            &self,
            _wb: &Workbench,
            _tenant_id: &str,
            store_scope: &str,
            _actor: &str,
            command: &EnvironmentCommandEnvelope,
        ) -> Result<Option<AdministrationMutationPlan>, AdministrationExtensionError> {
            if command.command_id != "backup.enable" {
                return Ok(None);
            }
            Ok(Some(AdministrationMutationPlan {
                facts: vec![CommandRecordFact {
                    scope_id: store_scope.into(),
                    kind: "test_backup".into(),
                    payload: serde_json::to_string(&command.payload).unwrap(),
                }],
                notices: vec![("test_backup", "backup".into(), "upsert")],
                audit_action: "backup.enable",
                audit_target: "backup".into(),
                transient_result: None,
            }))
        }
    }

    async fn request(
        app: &Router,
        method: Method,
        uri: &str,
        body: Value,
        key: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", "Bearer owner-token")
            .header("content-type", "application/json");
        if let Some(key) = key {
            builder = builder.header("idempotency-key", key);
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    async fn open(app: &Router) -> Value {
        let (status, value) = request(
            app,
            Method::POST,
            "/environments/administration/sessions",
            json!({}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value["session"].clone()
    }

    #[tokio::test]
    async fn composition_extension_uses_the_same_session_review_and_receipt_path() {
        let (_dir, shared, _app) = test_app();
        let extension: AdministrationEnvironmentExtensionHandle =
            Arc::new(TestAdministrationExtension);
        let app = routes()
            .layer(Extension(extension))
            .with_state(shared.clone());
        let session = open(&app).await;
        let backups = session["documents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|document| document["id"] == "administration.backups")
            .unwrap();
        assert_eq!(backups["commands"], json!(["backup.enable"]));
        let envelope = json!({
            "session_id": session["id"], "environment": "administration", "scope": session["scope"],
            "document_id": "administration.backups", "command_id": "backup.enable",
            "base_revision": backups["revision"], "payload": { "schedule_days": 1 },
            "client": "cli",
        });
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/environments/administration/commands",
            envelope,
            Some("extension-proposal"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        assert_eq!(proposed["receipt"]["status"], "proposed");
        assert!(shared
            .lock()
            .unwrap()
            .store_ref()
            .records("org", "test_backup")
            .unwrap()
            .is_empty());
        let path = format!(
            "/environments/administration/changes/{}/review",
            proposed["change"]["id"].as_str().unwrap()
        );
        let review = json!({
            "session_id": session["id"], "environment": "administration", "scope": session["scope"],
            "decision": "accept", "client": "browser",
        });
        let (status, applied) =
            request(&app, Method::POST, &path, review, Some("extension-review")).await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        assert_eq!(applied["receipt"]["status"], "applied");
        assert_eq!(
            shared
                .lock()
                .unwrap()
                .store_ref()
                .records("org", "test_backup")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn inventory_is_unique_closed_and_carries_every_required_gate() {
        let ids = COMMANDS
            .iter()
            .map(|command| command.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), COMMANDS.len());
        let inventory = administration_route_inventory();
        assert_eq!(inventory.len(), COMMANDS.len());
        for command in COMMANDS {
            assert!(DOCUMENTS
                .iter()
                .any(|document| document.id == command.document));
            assert!(!command.method.is_empty());
            assert!(command.legacy_path.starts_with("/admin/"));
            assert_eq!(command.review, ReviewPolicy::Human);
        }
        for route in inventory {
            assert_eq!(
                route.authentication,
                "enterprise authenticated actor + admitted Environment session"
            );
            assert_eq!(
                route.scope_policy,
                "request tenant scope must exactly match session scope"
            );
            assert_eq!(route.submit_method, "POST");
            assert_eq!(route.submit_path, "/environments/administration/commands");
            assert_eq!(route.review_method, "POST");
            assert_eq!(
                route.review_path,
                "/environments/administration/changes/:id/review"
            );
            assert!(route.base_revision_required);
            assert!(route.idempotency_required);
            assert!(route.capability_rechecked_on_review);
            assert_eq!(route.review, "human");
        }
    }

    #[tokio::test]
    async fn retired_legacy_management_facades_are_unreachable() {
        let (_dir, shared, _environment_only) = test_app();
        // Compose the real enterprise route table around the same admitted Home.
        let app = crate::org_routes::routes().with_state(shared);

        let retired = [
            (Method::POST, "/admin/org"),
            (Method::POST, "/admin/domains/verify"),
            (Method::POST, "/admin/members"),
            (Method::POST, "/admin/members/member/role"),
            (Method::POST, "/admin/members/member/deactivate"),
            (Method::POST, "/admin/grants"),
            (Method::DELETE, "/admin/grants"),
            (Method::POST, "/admin/sso"),
            (Method::POST, "/admin/scim/token"),
            (Method::POST, "/admin/scim/group-mapping"),
            (Method::POST, "/admin/policy"),
            (Method::POST, "/admin/placement-policy"),
            (Method::POST, "/admin/security"),
            (Method::POST, "/admin/archetype-approval"),
            (Method::POST, "/admin/software-policy"),
            (Method::POST, "/admin/billing"),
            (Method::GET, "/admin/org"),
            (Method::GET, "/admin/members"),
            (Method::GET, "/admin/sessions"),
            (Method::GET, "/admin/audit/verify"),
            (Method::GET, "/admin/grants"),
            (Method::GET, "/admin/policy"),
            (Method::GET, "/admin/sso"),
            (Method::GET, "/admin/security"),
            (Method::GET, "/admin/archetype-approval"),
            (Method::GET, "/admin/billing"),
            (Method::POST, "/admin/domains/verify-token"),
            (Method::POST, "/admin/members/auto-join"),
        ];
        for (method, path) in retired {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .header("authorization", "Bearer owner-token")
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                matches!(
                    response.status(),
                    StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_FOUND
                ),
                "retired {method} {path} unexpectedly remains reachable: {}",
                response.status()
            );
        }
    }

    #[test]
    fn literal_edit_parser_is_closed_to_four_document_commands() {
        let editable = DOCUMENTS
            .iter()
            .filter(|document| {
                matches!(
                    document.id,
                    "administration.organization"
                        | "administration.policy"
                        | "administration.software-policy"
                        | "administration.billing"
                )
            })
            .count();
        assert_eq!(editable, 4);
        for id in [
            "organization.update",
            "policy.update",
            "software-policy.update",
            "billing.update",
        ] {
            assert!(command_policy(id).is_some());
        }
    }

    #[tokio::test]
    async fn billing_role_receives_only_overview_and_billing_authority() {
        let (_dir, _shared, app) = test_app_as("billing");
        let session = open(&app).await;
        let documents = session["documents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|document| document["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            documents,
            BTreeSet::from(["administration.billing", "administration.overview"])
        );
        let commands = session["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(commands, BTreeSet::from(["billing.update"]));
    }

    #[tokio::test]
    async fn proposal_validation_blocks_domain_self_assertion_and_accepts_group_mapping() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let organization = session["documents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|document| document["id"] == "administration.organization")
            .unwrap();
        let challenge_uri = format!(
            "/environments/administration/domain-verification?session={}&scope={}&domain=Example.TEST",
            session["id"].as_str().unwrap(),
            session["scope"]["id"].as_str().unwrap(),
        );
        let (status, challenge) =
            request(&app, Method::GET, &challenge_uri, Value::Null, None).await;
        assert_eq!(status, StatusCode::OK, "{challenge}");
        assert_eq!(challenge["domain"], "example.test");
        assert_eq!(challenge["record_type"], "TXT");
        assert_eq!(
            challenge["value"],
            crate::org_routes::expected_txt("example.test")
        );
        let invalid = json!({
            "session_id": session["id"], "environment": "administration", "scope": session["scope"],
            "document_id": "administration.organization", "command_id": "organization.update",
            "base_revision": organization["revision"], "payload": { "display_name": "Acme", "verified_domains": ["example.test"], "default_region": null, "kind": "client" },
            "client": "edit",
        });
        let (status, rejected) = request(
            &app,
            Method::POST,
            "/environments/administration/commands",
            invalid,
            Some("domain-self-assertion"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{rejected}");
        assert!(
            fold_environment_changes(shared.lock().unwrap().store_ref(), "org")
                .unwrap()
                .is_empty()
        );

        let identity = session["documents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|document| document["id"] == "administration.identity")
            .unwrap();
        let mapping = json!({
            "session_id": session["id"], "environment": "administration", "scope": session["scope"],
            "document_id": "administration.identity", "command_id": "group-mapping.set",
            "base_revision": identity["revision"], "payload": { "group": "engineering", "role": "member", "team": "product" },
            "client": "cli",
        });
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/environments/administration/commands",
            mapping,
            Some("group-mapping-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        assert_eq!(proposed["receipt"]["status"], "proposed");
    }

    #[tokio::test]
    async fn browser_edit_agent_and_cli_share_the_route_decision_and_receipt_contract() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let access = session["documents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|document| document["id"] == "administration.access")
            .unwrap();
        let mut normalized = Vec::new();
        for client in ["browser", "edit", "agent", "cli"] {
            let envelope = json!({
                "session_id": session["id"], "environment": "administration", "scope": session["scope"],
                "document_id": "administration.access", "command_id": "member.invite",
                "base_revision": access["revision"], "payload": { "authority": format!("{client}-user"), "role": "member" },
                "client": client,
            });
            let (status, proposed) = request(
                &app,
                Method::POST,
                "/environments/administration/commands",
                envelope,
                Some(&format!("{client}-proposal")),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{client}: {proposed}");
            normalized.push(json!({
                "environment": proposed["receipt"]["environment"],
                "scope": proposed["receipt"]["scope"],
                "document_id": proposed["receipt"]["document_id"],
                "command_id": proposed["receipt"]["command_id"],
                "base_revision": proposed["receipt"]["base_revision"],
                "status": proposed["receipt"]["status"],
            }));
        }
        assert!(normalized.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(
            Org::rebuild(shared.lock().unwrap().store_ref())
                .unwrap()
                .members
                .len(),
            1,
            "every client opens a proposal; none bypasses human review"
        );
    }

    #[tokio::test]
    async fn command_proposes_review_applies_and_replay_has_one_effect() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let organization = session["documents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|document| document["id"] == "administration.organization")
            .unwrap();
        let envelope = json!({
            "session_id": session["id"], "environment": "administration", "scope": session["scope"],
            "document_id": "administration.organization", "command_id": "organization.update",
            "base_revision": organization["revision"], "payload": { "display_name": "Acme", "verified_domains": [], "default_region": null, "kind": "client" },
            "client": "browser",
        });
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/environments/administration/commands",
            envelope.clone(),
            Some("proposal-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        assert_eq!(proposed["receipt"]["status"], "proposed");
        assert!(Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .org
            .is_none());

        let change_id = proposed["change"]["id"].as_str().unwrap();
        let review_uri = format!("/environments/administration/changes/{change_id}/review");
        let review = json!({ "session_id": session["id"], "environment": "administration", "scope": session["scope"], "decision": "accept", "client": "browser" });
        let (status, applied) = request(
            &app,
            Method::POST,
            &review_uri,
            review.clone(),
            Some("review-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        assert_eq!(applied["receipt"]["status"], "applied");
        assert_eq!(
            Org::rebuild(shared.lock().unwrap().store_ref())
                .unwrap()
                .org
                .unwrap()
                .display_name,
            "Acme"
        );

        let (status, replayed) =
            request(&app, Method::POST, &review_uri, review, Some("review-1")).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "successful retry must return its receipt: {replayed}"
        );
        assert_eq!(replayed["receipt"]["id"], applied["receipt"]["id"]);

        let (status, proposal_replay) = request(
            &app,
            Method::POST,
            "/environments/administration/commands",
            envelope,
            Some("proposal-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposal_replay}");
        assert_eq!(proposal_replay["receipt"]["id"], proposed["receipt"]["id"]);
        assert_eq!(proposal_replay["receipt"]["status"], "proposed");
        assert_eq!(proposal_replay["change"]["status"], "applied");
        assert_eq!(
            proposal_replay["change"]["receipt_id"],
            proposed["receipt"]["id"]
        );
        assert_eq!(
            shared
                .lock()
                .unwrap()
                .store_ref()
                .records("org", "org")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            gaugedesk_app::audit::list(shared.lock().unwrap().store_ref()).len(),
            2,
            "proposal and admitted effect each have one atomic audit row"
        );
    }

    #[tokio::test]
    async fn scim_rotation_returns_plaintext_once_and_persists_only_its_hash() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let identity = session["documents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|document| document["id"] == "administration.identity")
            .unwrap();
        let envelope = json!({
            "session_id": session["id"], "environment": "administration", "scope": session["scope"],
            "document_id": "administration.identity", "command_id": "scim-token.rotate",
            "base_revision": identity["revision"], "payload": {}, "client": "browser",
        });
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/environments/administration/commands",
            envelope,
            Some("scim-proposal-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        assert_eq!(proposed["receipt"]["status"], "proposed");
        assert!(Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .scim_token_sha256
            .is_none());

        let change_id = proposed["change"]["id"].as_str().unwrap();
        let review_uri = format!("/environments/administration/changes/{change_id}/review");
        let review = json!({ "session_id": session["id"], "environment": "administration", "scope": session["scope"], "decision": "accept", "client": "browser" });
        let (status, applied) = request(
            &app,
            Method::POST,
            &review_uri,
            review.clone(),
            Some("scim-review-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        let token = applied["result"]["token"]
            .as_str()
            .expect("accepted rotation returns the token once");
        assert_eq!(token.len(), 64);
        let rows = shared
            .lock()
            .unwrap()
            .store_ref()
            .records("org", "scim_token")
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].contains(token));
        let stored: ScimTokenRecord = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(stored.token_sha256, sha256_hex(token));

        let (status, replayed) = request(
            &app,
            Method::POST,
            &review_uri,
            review,
            Some("scim-review-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{replayed}");
        assert_eq!(replayed["receipt"]["id"], applied["receipt"]["id"]);
        assert!(replayed.get("result").is_none() || replayed["result"].is_null());
        assert_eq!(
            shared
                .lock()
                .unwrap()
                .store_ref()
                .records("org", "scim_token")
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn stale_concurrent_change_conflicts_and_revoked_session_fails_closed() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let base = session["documents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|document| document["id"] == "administration.organization")
            .unwrap()["revision"]
            .clone();
        let make = |name: &str| json!({ "session_id": session["id"], "environment": "administration", "scope": session["scope"], "document_id": "administration.organization", "command_id": "organization.update", "base_revision": base, "payload": { "display_name": name, "verified_domains": [], "kind": "client" }, "client": "cli" });
        let (_, first) = request(
            &app,
            Method::POST,
            "/environments/administration/commands",
            make("First"),
            Some("p-first"),
        )
        .await;
        let (_, second) = request(
            &app,
            Method::POST,
            "/environments/administration/commands",
            make("Second"),
            Some("p-second"),
        )
        .await;
        let first_uri = format!(
            "/environments/administration/changes/{}/review",
            first["change"]["id"].as_str().unwrap()
        );
        let review = json!({ "session_id": session["id"], "environment": "administration", "scope": session["scope"], "decision": "accept" });
        assert_eq!(
            request(&app, Method::POST, &first_uri, review, Some("r-first"))
                .await
                .0,
            StatusCode::OK
        );
        let fresh = open(&app).await;
        let second_uri = format!(
            "/environments/administration/changes/{}/review",
            second["change"]["id"].as_str().unwrap()
        );
        let review = json!({ "session_id": fresh["id"], "environment": "administration", "scope": fresh["scope"], "decision": "accept" });
        assert_eq!(
            request(&app, Method::POST, &second_uri, review, Some("r-second"))
                .await
                .0,
            StatusCode::CONFLICT
        );

        let mut owner = Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .members["owner"]
            .clone();
        owner.status = MembershipStatus::Deprovisioned;
        shared
            .lock()
            .unwrap()
            .store_mut()
            .append_record("org", "membership", &serde_json::to_string(&owner).unwrap())
            .unwrap();
        let uri = format!("/environments/administration/documents/administration.organization?session={}&scope=org", fresh["id"].as_str().unwrap());
        assert_eq!(
            request(&app, Method::GET, &uri, Value::Null, None).await.0,
            StatusCode::FORBIDDEN
        );
    }
}
