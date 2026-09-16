//! Administration adapter for the typed GaugeApp protocol (ADR 0161). The
//! registry below is the single page/action inventory used by discovery,
//! admission, typed page projection, and dispatch.

// Axum's concrete Response is the native error value throughout this route
// adapter; boxing it would add indirection to every handler and call site.
#![allow(clippy::result_large_err)]

#[path = "gaugeapp_external_review.rs"]
mod external_review;
pub use external_review::{
    stored_administration_approval, ApprovedAdministrationChange, ExternalReviewOutcome,
};

use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use gaugedesk_app::account_auth::{
    current_command_record_facts as account_auth_command_facts, decide_link_external_subject,
    normalize_email_contact, AccountAuth, ExternalSubjectKind, ExternalSubjectRecord,
};
use gaugedesk_app::gaugeapp_agent::{
    append_gaugeapp_agent_exchange_prepared_current, begin_gaugeapp_agent_live_turn,
    claim_gaugeapp_agent_turn, erase_gaugeapp_agent_transcript_current,
    gaugeapp_agent_live_subscription, gaugeapp_agent_page_commands, gaugeapp_agent_transcript,
    gaugeapp_agent_turn_was_stopped, gaugeapp_thread_id, migrate_legacy_gaugeapp_agent_transcript,
    replayed_gaugeapp_agent_turn, request_gaugeapp_agent_stop,
    run_gaugeapp_agent_turn_with_refresh_stop_and_events, GaugeAppAgentContext, GaugeAppAgentError,
    GaugeAppAgentLiveEvent, GaugeAppAgentLiveFrame, GaugeAppAgentMessage, GaugeAppAgentPage,
    GaugeAppAgentRejection,
};
use gaugedesk_app::gaugeapp_contract::{
    decide_gaugeapp_command, decide_reviewed_gaugeapp_command, fold_gaugeapp_changes,
    gaugeapp_change_id, gaugeapp_receipt, gaugeapp_session_id, AdmissionDisposition,
    GaugeAppChangeRecord, GaugeAppChangeStatus, GaugeAppClient, GaugeAppCommandEnvelope,
    GaugeAppCommandGrant, GaugeAppKind, GaugeAppPageAvailability, GaugeAppPageGrant,
    GaugeAppRejection, GaugeAppScope, GaugeAppSession, ReviewPolicy, GAUGEAPP_CHANGE_KIND,
};
use gaugedesk_app::model_provider_management::projection::{ModelProvidersPage, UnavailableReason};
use gaugedesk_app::org::{
    sha256_hex, ArchetypeApprovalPolicyRecord, BillingContactRecord, GroupMappingRecord,
    MemberGrantRecord, MembershipStatus, Org, OrganizationInvitationRecord,
    OrganizationInvitationStatus, OrganizationSessionRevocationRecord, PlacementPolicyRecord,
    PolicyRecord, RecordOp, ScimSyncStatus, ScimTokenRecord, SecurityPolicyRecord,
    SoftwarePolicyRecord, SsoAdmissionMode, SsoAdmissionRecord, SsoConnectionRecord,
    SsoCredentialRecord, BILLING_CONTACT_KIND, ORGANIZATION_INVITATION_KIND, ORG_ID,
    SSO_ADMISSION_KIND, SSO_CREDENTIAL_KIND,
};
use gaugedesk_app::{LockUnpoisoned, SharedWorkbench, Workbench};
use gaugedesk_core::abac::Policy;
use gaugedesk_core::rbac::Capability;
use gaugedesk_store::{AdmitError, CommandRecordFact};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, sync::Arc, time::Instant};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::org_routes::{bearer, req_scope};

const GAUGEAPP: GaugeAppKind = GaugeAppKind::Administration;
const ORGANIZATION_INVITATION_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const ORGANIZATION_INVITATION_BATCH_MAX: usize = 50;
const OWNER_SUBJECT_LINK_TTL_MS: u64 = 10 * 60 * 1_000;

#[derive(Clone, Copy)]
struct PagePolicy {
    id: &'static str,
    read_model: &'static str,
    version: u32,
    read: &'static [Capability],
}

#[derive(Clone, Copy)]
struct CommandPolicy {
    id: &'static str,
    page: &'static str,
    capability: Capability,
    review: ReviewPolicy,
}

#[derive(Clone, Debug)]
pub struct AdministrationExtensionCommand {
    pub id: String,
    pub capability: Capability,
    pub review: ReviewPolicy,
}

#[derive(Clone, Debug)]
pub struct AdministrationExtensionPage {
    pub id: String,
    pub read_model: String,
    pub version: u32,
    pub freshness: String,
    pub model: Value,
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
/// Administration pages and closed reducers without minting another route
/// family. The common adapter still owns authentication, exact scope, expected
/// resource basis, review, idempotency, durable receipt, and audit admission.
pub trait AdministrationGaugeAppExtension: Send + Sync {
    /// A hosted composition may narrow a built-in page when a separately
    /// authoritative entitlement is absent. Navigation and the role-derived
    /// capability are not substitutes for that standing.
    fn allow_base_page(
        &self,
        _wb: &Workbench,
        _tenant_id: &str,
        _store_scope: &str,
        _page_id: &str,
    ) -> Result<bool, AdministrationExtensionError> {
        Ok(true)
    }

    /// Apply the same entitlement fence to commands contributed by a retained
    /// built-in page (for example verified-domain controls on Organization).
    fn allow_base_command(
        &self,
        _wb: &Workbench,
        _tenant_id: &str,
        _store_scope: &str,
        _command_id: &str,
    ) -> Result<bool, AdministrationExtensionError> {
        Ok(true)
    }

    /// A separately authoritative effect needs a durable human-approval handoff
    /// and receipt recovery. Do not opt in an immediate/secret-bearing ceremony.
    fn requires_external_review(&self, _command_id: &str) -> bool {
        false
    }

    /// Query/resume the exact approved operation at its owning authority. Keep
    /// its original identity, payload, actor and expected basis: the owner must
    /// return that operation's receipt or admit that exact request atomically.
    /// Never re-plan against a newer page, allocate another operation, or treat
    /// a timeout/missing observation as proof of rejection. The caller's current
    /// capability is rechecked before this hook, including receipt recovery.
    /// The adapter runs this outside the Workbench lock, so the service may
    /// obtain fresh membership/approval evidence from the management authority.
    fn recover_external_review(
        &self,
        _tenant_id: &str,
        _store_scope: &str,
        _approved: &ApprovedAdministrationChange,
    ) -> Result<ExternalReviewOutcome, AdministrationExtensionError> {
        Ok(ExternalReviewOutcome::Pending)
    }

    fn apply_external_review(
        &self,
        _tenant_id: &str,
        _store_scope: &str,
        _approved: &ApprovedAdministrationChange,
        _plan: AdministrationMutationPlan,
    ) -> Result<ExternalReviewOutcome, AdministrationExtensionError> {
        Err(AdministrationExtensionError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "external review handoff is not configured",
        ))
    }

    fn project(
        &self,
        wb: &Workbench,
        tenant_id: &str,
        store_scope: &str,
        actor: &str,
        capabilities: &[Capability],
    ) -> Result<Vec<AdministrationExtensionPage>, AdministrationExtensionError>;

    fn plan(
        &self,
        wb: &Workbench,
        tenant_id: &str,
        store_scope: &str,
        actor: &str,
        command: &GaugeAppCommandEnvelope,
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
        _command: &GaugeAppCommandEnvelope,
        _operation_key: &str,
        plan: AdministrationMutationPlan,
    ) -> Result<AdministrationMutationPlan, AdministrationExtensionError> {
        Ok(plan)
    }
}

pub type AdministrationGaugeAppExtensionHandle = Arc<dyn AdministrationGaugeAppExtension>;

/// Machine-checkable inventory of every management mutation represented by
/// the Administration adapter. The legacy route is evidence for migration and
/// must disappear from browser clients; admission uses `command_id` only.
#[derive(Clone, Debug, serde::Serialize)]
pub struct GaugeAppRouteInventoryEntry {
    pub app: &'static str,
    pub command_id: &'static str,
    pub page_id: &'static str,
    pub authentication: &'static str,
    pub scope_policy: &'static str,
    pub capability: &'static str,
    pub expected_basis_required: bool,
    pub idempotency_required: bool,
    pub review: &'static str,
    pub submit_method: &'static str,
    pub submit_path: &'static str,
    pub review_method: &'static str,
    pub review_path: &'static str,
    pub capability_rechecked_on_review: bool,
}

const PAGES: &[PagePolicy] = &[
    PagePolicy {
        id: "organization",
        read_model: "OrganizationPageV1",
        version: 1,
        read: &[Capability::EditOrgSettings],
    },
    PagePolicy {
        id: "plans-services",
        read_model: "PlansServicesPageV1",
        version: 1,
        read: &[Capability::ManageBilling],
    },
    PagePolicy {
        id: "people",
        read_model: "PeoplePageV1",
        version: 1,
        read: &[Capability::ManageMembers],
    },
    PagePolicy {
        id: "sessions",
        read_model: "OrganizationSessionsPageV1",
        version: 1,
        read: &[Capability::ConfigureSecurity],
    },
    PagePolicy {
        id: "enterprise-identity",
        read_model: "EnterpriseIdentityPageV1",
        version: 1,
        read: &[Capability::ConfigureSso, Capability::ConfigureProvisioning],
    },
    PagePolicy {
        id: "projects",
        read_model: "AdministrationProjectsPageV1",
        version: 1,
        read: &[Capability::ManageMembers],
    },
    PagePolicy {
        id: "model-providers",
        read_model: "OrganizationModelProvidersPageV1",
        version: 1,
        read: &[Capability::ConfigureSecurity],
    },
    PagePolicy {
        id: "organization-policy",
        read_model: "OrganizationPolicyPageV1",
        version: 1,
        read: &[Capability::ConfigureSecurity],
    },
    PagePolicy {
        id: "project-hosts",
        read_model: "ProjectHostsPageV1",
        version: 1,
        read: &[Capability::ConfigureSecurity],
    },
    PagePolicy {
        id: "backups",
        read_model: "BackupsPageV1",
        version: 1,
        read: &[Capability::ConfigureSecurity],
    },
    PagePolicy {
        id: "software-policy",
        read_model: "SoftwarePolicyPageV1",
        version: 1,
        read: &[Capability::ConfigureSecurity],
    },
    PagePolicy {
        id: "billing",
        read_model: "TenantBillingPageV1",
        version: 1,
        read: &[Capability::ManageBilling],
    },
];

// Durable tenant changes always require human review. Read-only operational
// diagnostics may be immediate; a caller's desktop/web/agent label never
// changes either declaration.
const COMMANDS: &[CommandPolicy] = &[
    CommandPolicy {
        id: "organization.display-name.set",
        page: "organization",
        capability: Capability::EditOrgSettings,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "organization.ownership.transfer",
        page: "organization",
        capability: Capability::ManageOrgLifecycle,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "organization.delete",
        page: "organization",
        capability: Capability::ManageOrgLifecycle,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "organization.domain.add",
        page: "organization",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "organization.domain.verify",
        page: "organization",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "organization.domain.remove",
        page: "organization",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "people.invitation.create",
        page: "people",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "people.invitation.cancel",
        page: "people",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "people.invitation.resend",
        page: "people",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "people.role.change",
        page: "people",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "people.member.deactivate",
        page: "people",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "people.member.reactivate",
        page: "people",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "project-access.grant",
        page: "people",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "project-access.revoke",
        page: "people",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "organization-session.revoke",
        page: "sessions",
        capability: Capability::ConfigureSecurity,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "project.create",
        page: "projects",
        capability: Capability::ManageMembers,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "enterprise-identity.connection.set",
        page: "enterprise-identity",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "enterprise-identity.admission-mode.set",
        page: "enterprise-identity",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "enterprise-identity.owner-subject.link",
        page: "enterprise-identity",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "enterprise-identity.enforcement.enable",
        page: "enterprise-identity",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "enterprise-identity.enforcement.disable",
        page: "enterprise-identity",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "enterprise-identity.connection.validate",
        page: "enterprise-identity",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Immediate,
    },
    CommandPolicy {
        id: "enterprise-identity.test.begin",
        page: "enterprise-identity",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Immediate,
    },
    CommandPolicy {
        id: "enterprise-identity.connection.credential.set",
        page: "enterprise-identity",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Immediate,
    },
    CommandPolicy {
        id: "enterprise-identity.connection.credential.remove",
        page: "enterprise-identity",
        capability: Capability::ConfigureSso,
        review: ReviewPolicy::Immediate,
    },
    CommandPolicy {
        id: "enterprise-identity.scim-credential.issue",
        page: "enterprise-identity",
        capability: Capability::ConfigureProvisioning,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "enterprise-identity.scim-credential.rotate",
        page: "enterprise-identity",
        capability: Capability::ConfigureProvisioning,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "enterprise-identity.group-mapping.add",
        page: "enterprise-identity",
        capability: Capability::ConfigureProvisioning,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "enterprise-identity.group-mapping.edit",
        page: "enterprise-identity",
        capability: Capability::ConfigureProvisioning,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "enterprise-identity.group-mapping.remove",
        page: "enterprise-identity",
        capability: Capability::ConfigureProvisioning,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "organization-policy.set",
        page: "organization-policy",
        capability: Capability::ConfigureSecurity,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "software-policy.set",
        page: "software-policy",
        capability: Capability::ConfigureSecurity,
        review: ReviewPolicy::Human,
    },
    CommandPolicy {
        id: "billing.contact.set",
        page: "billing",
        capability: Capability::ManageBilling,
        review: ReviewPolicy::Human,
    },
];

pub fn administration_route_inventory() -> Vec<GaugeAppRouteInventoryEntry> {
    COMMANDS
        .iter()
        .map(|command| GaugeAppRouteInventoryEntry {
            app: "administration",
            command_id: command.id,
            page_id: command.page,
            authentication: "enterprise authenticated actor + admitted GaugeApp session",
            scope_policy: "request tenant scope must exactly match session scope",
            capability: command.capability.as_str(),
            expected_basis_required: true,
            idempotency_required: true,
            review: match command.review {
                ReviewPolicy::Immediate => "immediate",
                ReviewPolicy::Human => "human",
            },
            submit_method: "POST",
            submit_path: if matches!(
                command.id,
                "enterprise-identity.connection.credential.set"
                    | "enterprise-identity.connection.credential.remove"
            ) {
                "/gaugeapps/administration/enterprise-identity/credential"
            } else {
                "/gaugeapps/administration/commands"
            },
            review_method: "POST",
            review_path: "/gaugeapps/administration/proposals/:id/review",
            capability_rechecked_on_review: command.review == ReviewPolicy::Human,
        })
        .collect()
}

pub fn routes() -> Router<SharedWorkbench> {
    Router::new()
        .route("/gaugeapps/administration/sessions", post(open_session))
        .route("/gaugeapps/administration/pages/{id}", get(read_page))
        .route("/gaugeapps/administration/updates", get(read_updates))
        .route(
            "/gaugeapps/administration/agent/messages",
            get(agent_messages).post(agent_message),
        )
        .route("/gaugeapps/administration/agent/events", get(agent_events))
        .route("/gaugeapps/administration/agent/stop", post(agent_stop))
        .route("/gaugeapps/administration/agent/erase", post(agent_erase))
        .route(
            "/gaugeapps/administration/organization/domain-verification",
            get(domain_verification_challenge),
        )
        .route(
            "/gaugeapps/administration/enterprise-identity/credential",
            post(submit_sso_credential),
        )
        .route("/gaugeapps/administration/commands", post(submit_command))
        .route(
            "/gaugeapps/administration/proposals",
            get(list_changes).post(submit_proposal),
        )
        .route(
            "/gaugeapps/administration/proposals/{id}/review",
            post(review_change),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentMessageBody {
    session_id: String,
    generation: String,
    scope: GaugeAppScope,
    idempotency_key: String,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentStopBody {
    session_id: String,
    generation: String,
    scope: GaugeAppScope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEraseBody {
    session_id: String,
    generation: String,
    scope: GaugeAppScope,
    idempotency_key: String,
}

fn agent_error(error: GaugeAppAgentError) -> Response {
    // The reason reaches the client and, until now, nowhere else: the only
    // server-side record of a failed turn was the hosted request fault line,
    // which carries a status and no cause. Two production canary runs failed on
    // `status=502` with nothing in the log saying why, and the cause was in
    // hand the whole time.
    //
    // Only the variants an operator can act on are logged, and only their own
    // messages. `Provider` carries a timeout, a size cap, or a transport error;
    // `Credential` and `Store` describe configuration and persistence. The
    // model's own output is deliberately excluded: `InvalidOutput` and
    // `Rejected` carry generated content, which is the person's, not an
    // operational detail. `Busy`, `Interrupted` and `NoModelAccess` are ordinary
    // outcomes and stay quiet.
    match &error {
        GaugeAppAgentError::Provider(detail) => {
            eprintln!("[gaugewright] management agent turn failed: provider: {detail}");
        }
        GaugeAppAgentError::Credential(detail) => {
            eprintln!("[gaugewright] management agent turn failed: credential: {detail}");
        }
        GaugeAppAgentError::Store(detail) => {
            eprintln!("[gaugewright] management agent turn failed: store: {detail}");
        }
        GaugeAppAgentError::InvalidOutput(_) => {
            eprintln!("[gaugewright] management agent turn failed: invalid provider output");
        }
        GaugeAppAgentError::Rejected(_) => {
            eprintln!("[gaugewright] management agent turn failed: proposal rejected");
        }
        GaugeAppAgentError::Busy
        | GaugeAppAgentError::Interrupted
        | GaugeAppAgentError::NoModelAccess => {}
    }
    let status = match error {
        GaugeAppAgentError::Busy => StatusCode::CONFLICT,
        GaugeAppAgentError::Interrupted => StatusCode::from_u16(499).expect("valid status"),
        GaugeAppAgentError::NoModelAccess => StatusCode::CONFLICT,
        GaugeAppAgentError::Credential(_) => StatusCode::SERVICE_UNAVAILABLE,
        GaugeAppAgentError::Provider(_) => StatusCode::BAD_GATEWAY,
        GaugeAppAgentError::InvalidOutput(_) | GaugeAppAgentError::Rejected(_) => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        GaugeAppAgentError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": error.to_string() }))).into_response()
}

async fn agent_stop(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    headers: HeaderMap,
    Json(body): Json<AgentStopBody>,
) -> Response {
    // Keep the Store lock through both re-admission and stop intent. Final
    // transcript admission takes the same lock, so either Stop wins and the
    // final response is refused, or the completed turn wins and Stop truthfully
    // reports that nothing remains live.
    let guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if body.session_id != session.id
        || body.generation != session.generation
        || body.scope != session.scope
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "agent session is stale or cross-scope" })),
        )
            .into_response();
    }
    let stopped = request_gaugeapp_agent_stop(&gaugeapp_thread_id(&session));
    (StatusCode::OK, Json(json!({ "stopped": stopped }))).into_response()
}

async fn agent_erase(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    headers: HeaderMap,
    Json(body): Json<AgentEraseBody>,
) -> Response {
    let session = {
        let guard = wb.lock_unpoisoned();
        let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
            Ok(value) => value,
            Err(response) => return response,
        };
        if body.session_id != session.id
            || body.generation != session.generation
            || body.scope != session.scope
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "agent session is stale or cross-scope" })),
            )
                .into_response();
        }
        session
    };
    match erase_gaugeapp_agent_transcript_current(&wb, &session, &body.idempotency_key, &|guard| {
        let rejected = |_| GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionRevoked);
        let (current, _) =
            build_session(guard, &headers, extension_ref(&extension)).map_err(rejected)?;
        if current.id != session.id
            || current.generation != session.generation
            || current.app != session.app
            || current.scope != session.scope
            || current.actor != session.actor
        {
            return Err(GaugeAppAgentError::Rejected(
                GaugeAppAgentRejection::SessionMismatch,
            ));
        }
        Ok(())
    }) {
        Ok(receipt) => (StatusCode::OK, Json(json!({ "erasure": receipt }))).into_response(),
        Err(error) => agent_error(error),
    }
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
    format!("gaugeapp:administration:{}", req_scope(headers))
}

fn has_capability(capabilities: &[Capability], capability: Capability) -> bool {
    capabilities.contains(&capability)
}

fn personal_tenant(tenant_id: &str) -> bool {
    tenant_id.starts_with("personal:")
}

/// A Personal tenant is the same storage/auth primitive as an organization,
/// but it is not presented as a tiny organization. Its always-available
/// Administration surface is deliberately narrow. Backups are contributed by
/// the hosted composition only when its server-owned paid entitlement admits
/// them; the common adapter must not manufacture that commercial fact.
fn built_in_page_allowed(tenant_id: &str, page_id: &str) -> bool {
    !personal_tenant(tenant_id) || matches!(page_id, "project-hosts" | "billing")
}

fn contributed_page_allowed(tenant_id: &str, page_id: &str) -> bool {
    !personal_tenant(tenant_id) || matches!(page_id, "project-hosts" | "backups" | "billing")
}

fn can_read(capabilities: &[Capability], policy: PagePolicy) -> bool {
    policy
        .read
        .iter()
        .any(|capability| has_capability(capabilities, *capability))
}

fn resource_basis(model: &Value) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            serde_json::to_vec(model).expect("JSON serializes")
        ))
    )
}

/// Operational freshness changes whenever a client makes an admitted request;
/// it is evidence for a human, not the concurrency basis of a mutation. Sessions
/// therefore bind revocation to the exact live id set. People omits its embedded
/// member-session drill-through from the basis so merely viewing Administration
/// cannot stale an invitation or role proposal. Every other page keeps its complete
/// read model as the basis.
fn page_resource_basis(
    page: &AdministrationExtensionPage,
    tenant: &str,
) -> Result<String, &'static str> {
    if page.id == "model-providers" {
        let model: ModelProvidersPage = serde_json::from_value(page.model.clone())
            .map_err(|_| "invalid Model Providers projection")?;
        if model
            .organization()
            .is_some_and(|organization| organization != tenant)
        {
            return Err("Model Providers projection belongs to another organization");
        }
        if matches!(model, ModelProvidersPage::Unavailable { .. }) && !page.commands.is_empty() {
            return Err("unavailable Model Providers page declared commands");
        }
        return Ok(model.resource_basis());
    }
    if page.id == "project-hosts" {
        let mut stable = page.model.clone();
        if let Some(hosts) = stable.get_mut("homes").and_then(Value::as_array_mut) {
            for host in hosts {
                if let Some(object) = host.as_object_mut() {
                    // The registry declaration, lifecycle, capacity, and managed
                    // policy remain in the basis. Live target observations must
                    // not invalidate a pending management change. Handoff and
                    // retirement still recheck dependencies at their own authority.
                    for key in ["execution", "projects", "state", "repair_hint"] {
                        object.remove(key);
                    }
                }
            }
        }
        return Ok(resource_basis(&stable));
    }
    if page.id == "people" {
        let mut stable = page.model.clone();
        if let Some(object) = stable.as_object_mut() {
            object.remove("sessions");
        }
        return Ok(resource_basis(&stable));
    }
    if page.id != "sessions" {
        return Ok(resource_basis(&page.model));
    }
    let ids = page
        .model
        .get("sessions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|session| session.get("id").and_then(Value::as_str))
        .collect::<Vec<_>>();
    Ok(resource_basis(&json!({ "session_ids": ids })))
}

fn organization_session_rows(
    wb: &Workbench,
    store_scope: &str,
    request_bearer: Option<&str>,
    org: &Org,
) -> Result<Vec<Value>, AdmitError> {
    let current_id =
        request_bearer.and_then(|bearer| wb.organization_session_id_for(bearer, store_scope));
    wb.organization_session_roster_in(store_scope)?
        .into_iter()
        .map(|session| {
            let member = org.member_by_authority(&session.authority);
            let person_label = member
                .filter(|member| !member.email.trim().is_empty())
                .map_or_else(|| session.authority.clone(), |member| member.email.clone());
            let state = if session.software_status
                == gaugedesk_app::client_admission::ClientAdmissionStatus::Blocked
            {
                "recovery_only"
            } else {
                "active"
            };
            let client_label = session
                .client
                .platform
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "GaugeDesk client".into());
            let is_current = current_id.as_deref() == Some(session.id.as_str());
            Ok(json!({
                "id": session.id,
                "person": { "authority": session.authority, "label": person_label },
                "client_label": client_label,
                "client": session.client,
                "state": state,
                "software_status": session.software_status,
                "software_reason": session.software_reason,
                "first_seen_unix_ms": session.first_seen_unix_ms,
                "last_seen_unix_ms": session.last_seen_unix_ms,
                "age_ms": session.age_ms,
                "idle_ms": session.idle_ms,
                "current": is_current,
            }))
        })
        .collect()
}

fn public_sso(connection: Option<&SsoConnectionRecord>, client_secret_configured: bool) -> Value {
    connection.map_or(Value::Null, |connection| {
        json!({
            "id": connection.id,
            "revision": connection.current_revision(),
            "protocol": connection.protocol,
            "issuer": connection.issuer,
            "audiences": connection.audiences,
            "enforce_sso": connection.enforce_sso,
            "claim_mapping": connection.claim_mapping,
            "metadata_configured": !connection.metadata.is_empty(),
            "client_secret_configured": client_secret_configured,
        })
    })
}

fn public_sso_browser_test(org: &Org) -> Value {
    org.current_sso_browser_test().map_or(Value::Null, |test| {
        json!({
            "id": test.id,
            "connection_id": test.connection_id,
            "connection_revision": test.connection_revision,
            "protocol": test.protocol,
            "subject": test.subject,
            "mapped_roles": test.mapped_roles,
            "mapped_region": test.mapped_region,
            "mapped_tenant": test.mapped_tenant,
            "tested_at_ms": test.tested_at_ms,
        })
    })
}

fn scim_operating_state(org: &Org) -> Value {
    let last_sync_at_ms = org
        .scim_sync
        .iter()
        .filter(|record| record.status == ScimSyncStatus::Succeeded)
        .map(|record| record.observed_at_ms)
        .max();
    let mut latest_by_subject = std::collections::BTreeMap::new();
    for record in &org.scim_sync {
        latest_by_subject.insert(
            record
                .subject
                .clone()
                .unwrap_or_else(|| "missing-subject".to_owned()),
            record,
        );
    }
    let mut errors = latest_by_subject
        .into_values()
        .filter(|record| record.status == ScimSyncStatus::Failed)
        .collect::<Vec<_>>();
    errors.sort_by_key(|record| std::cmp::Reverse(record.observed_at_ms));
    json!({
        "last_sync_at_ms": last_sync_at_ms,
        "errors": errors.into_iter().take(5).map(|record| json!({
            "operation": record.operation,
            "subject": record.subject,
            "code": record.error,
            "observed_at_ms": record.observed_at_ms,
        })).collect::<Vec<_>>(),
    })
}

fn project_page(
    wb: &Workbench,
    store_scope: &str,
    policy: PagePolicy,
    request_bearer: Option<&str>,
    headers: &HeaderMap,
) -> Result<Value, AdmitError> {
    let org = Org::rebuild_in(wb.store_ref(), store_scope)?;
    let value = match policy.id {
        "organization" => org.org.as_ref().map_or(Value::Null, |record| {
            let owner = org
                .members
                .values()
                .find(|member| {
                    member.status == MembershipStatus::Active && member.role == "owner"
                })
                .map(|member| {
                    json!({
                        "id": member.id,
                        "authority": member.authority,
                        "email": member.email,
                        "label": if member.email.trim().is_empty() { &member.authority } else { &member.email },
                    })
                });
            json!({
                "display_name": record.display_name,
                "kind": record.kind,
                "owner": owner,
                "ownership_candidates": org.members.values().filter(|member| {
                    member.status == MembershipStatus::Active
                        && member.role != "owner"
                        && !member.managed_by_scim
                        && !member.authority.trim().is_empty()
                }).map(|member| json!({
                    "id": member.id,
                    "authority": member.authority,
                    "email": member.email,
                    "label": if member.email.trim().is_empty() { &member.authority } else { &member.email },
                    "role": member.role,
                })).collect::<Vec<_>>(),
                "domains": record
                    .verified_domains
                    .iter()
                    .map(|domain| json!({
                        "domain": domain,
                        "status": "verified",
                        "challenge": Value::Null,
                    }))
                    .chain(record.pending_domains.iter().map(|domain| json!({
                        "domain": domain,
                        "status": "pending",
                        // Derived on every read rather than stored with the
                        // claim. The token is a pure function of the domain, so
                        // a stored copy could only ever disagree with the proof
                        // check, and holding one grants nothing either way.
                        "challenge": {
                            "record_name": format!("_gaugewright-challenge.{domain}"),
                            "record_type": "TXT",
                            "value": crate::org_routes::expected_txt(domain),
                        },
                    })))
                    .collect::<Vec<_>>(),
            })
        }),
        "people" => {
            let now_ms = gaugedesk_app::account::session_now_ms();
            json!({
                "members": org.members.values().collect::<Vec<_>>(),
                "invitations": org.invitations.values().map(|invitation| json!({
                    "id": invitation.id,
                    "email": invitation.email,
                    "role": invitation.role,
                    "team": invitation.team,
                    "status": if invitation.status == OrganizationInvitationStatus::Pending
                        && invitation.expires_at_ms <= now_ms
                    {
                        "expired".to_owned()
                    } else {
                        serde_json::to_value(invitation.status)
                            .ok()
                            .and_then(|value| value.as_str().map(str::to_owned))
                            .unwrap_or_else(|| "unknown".to_owned())
                    },
                    "issued_at_ms": invitation.issued_at_ms,
                    "expires_at_ms": invitation.expires_at_ms,
                })).collect::<Vec<_>>(),
                "grants": org.grants.values().collect::<Vec<_>>(),
                "projects": gaugedesk_app::library_routes::administration_project_references_value(wb),
                "sessions": organization_session_rows(wb, store_scope, request_bearer, &org)?,
                // No outbound-mail provider is configured here. The server returns
                // addressed, one-time links only from create/resend so an admin can
                // deliver them without ever projecting the proof again.
                "invitation_delivery": "one-time-link",
            })
        }
        "enterprise-identity" => {
            let integration = crate::org_routes::enterprise_integration(headers);
            let scim_base_url = integration["scim"]["base_url"].clone();
            let account_auth = AccountAuth::rebuild(wb.store_ref())?;
            let actor = wb.actor(request_bearer);
            let current_owner = org.member_by_authority(&actor).is_some_and(|member| {
                member.status == MembershipStatus::Active && member.role == "owner"
            });
            let current_session_is_passkey = request_bearer
                .and_then(|token| wb.account_sessions().resolve_session(token))
                .is_some_and(|(account_id, method)| account_id == actor && method == "passkey");
            let readiness = org.sso_enforcement_readiness(&account_auth);
            json!({
                "verified_domains": org.org.as_ref().map(|record| &record.verified_domains).cloned().unwrap_or_default(),
                "sso": public_sso(org.sso.as_ref(), org.current_sso_credential().is_some()),
                "browser_test": public_sso_browser_test(&org),
                "admission_mode": org.sso_admission.as_ref().map(|record| record.mode),
                "current_owner": {
                    "is_owner": current_owner,
                    "passkey_session": current_session_is_passkey,
                    "subject_linked": current_owner
                        && org.corporate_subject_linked_for(&account_auth, &actor),
                },
                "enforcement": {
                    "required": org.sso_enforced(),
                    "ready": readiness.ready(),
                    "connection_configured": readiness.connection_configured,
                    "domain_verified": readiness.domain_verified,
                    "browser_test_current": readiness.browser_test_current,
                    "admission_configured": readiness.admission_configured,
                    "owner_subject_linked": readiness.owner_subject_linked,
                    "owner_recovery_ready": readiness.owner_recovery_ready,
                    "second_owner_present": readiness.second_owner_present,
                },
                "integration": integration,
                "scim": {
                    "credential_configured": org.scim_token_sha256.is_some(),
                    "base_url": scim_base_url,
                    "status": scim_operating_state(&org),
                },
                "group_mappings": org.group_mappings.values().collect::<Vec<_>>(),
            })
        }
        "organization-policy" => json!({
            "resource": org.policy(),
            "security": org.security,
            "placement": org.effective_placement_policy(),
            "archetype_approval": { "require_approval": org.effective_require_archetype_approval() },
        }),
        "software-policy" => json!(org.software_policy.unwrap_or_default()),
        "sessions" => json!({
            "sessions": organization_session_rows(wb, store_scope, request_bearer, &org)?,
        }),
        "project-hosts" => {
            json!({ "homes": [{
                "id": wb.home_id().as_str(), "home_id": wb.home_id().as_str(),
                "name": "This computer", "kind": "local", "endpoint": "", "lifecycle": "active",
                "state": "live", "repair_hint": Value::Null,
                "projects": Value::Null,
            }], "managed_enrollment": { "available": false,
                "reason": "Managed hosting is not configured on this service.", "region": Value::Null, "capacity": Value::Null } })
        }
        "projects" => {
            gaugedesk_app::library_routes::administration_projects_value(
                wb,
                &org,
                "This Project Host",
                "active",
                true,
            )
        }
        "model-providers" => json!(ModelProvidersPage::Unavailable {reason: UnavailableReason::NotConfigured}),
        "backups" => json!({ "backups": [], "recovery_recipients": [] }),
        "billing" | "plans-services" => {
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
            json!({
                "billing": org.billing,
                "billing_contact": org.billing_contact,
                "seats_used": org.seats_used(),
                "managed_usage": usage,
                "services": [
                    { "id": "commercial-operations", "status": "not-added", "accepted_at_ms": Value::Null, "removal_effective_at_ms": Value::Null },
                    { "id": "enterprise-controls", "status": "not-added", "accepted_at_ms": Value::Null, "removal_effective_at_ms": Value::Null },
                ],
            })
        }
        _ => Value::Null,
    };
    Ok(value)
}

fn extension_error(error: AdministrationExtensionError) -> Response {
    (error.status, Json(json!({ "error": error.message }))).into_response()
}

fn delete_organization_refusal(
    refusal: gaugedesk_app::tenancy::DeleteOrganizationRefusal,
) -> Response {
    use gaugedesk_app::tenancy::DeleteOrganizationRefusal as Refusal;
    let (status, message) = match refusal {
        Refusal::NoSuchOrganization => (
            StatusCode::NOT_FOUND,
            "this organization is no longer available".to_owned(),
        ),
        Refusal::Personal => (
            StatusCode::CONFLICT,
            "Personal is your account space and cannot be deleted".to_owned(),
        ),
        Refusal::NotAnOwner => (
            StatusCode::FORBIDDEN,
            "only the active owner can delete this organization".to_owned(),
        ),
        Refusal::OtherMembersRemain(count) => (
            StatusCode::CONFLICT,
            format!(
                "remove or deactivate the other {count} active {} before deleting this organization",
                if count == 1 { "member" } else { "members" },
            ),
        ),
        Refusal::FacilitiesRemain(count) => (
            StatusCode::CONFLICT,
            format!(
                "end the {count} active organization {} before deleting this organization",
                if count == 1 { "service" } else { "services" },
            ),
        ),
    };
    (status, Json(json!({ "error": message }))).into_response()
}

fn build_session(
    wb: &Workbench,
    headers: &HeaderMap,
    extension: Option<&AdministrationGaugeAppExtensionHandle>,
) -> Result<(GaugeAppSession, Vec<AdministrationExtensionPage>), Response> {
    let store_scope = req_scope(headers);
    let mut capabilities = wb
        .admin_capabilities(bearer(headers), &store_scope)
        .map_err(|(status, message)| (status, Json(json!({ "error": message }))).into_response())?;
    if capabilities.is_empty() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "no Administration capability in this tenant" })),
        )
            .into_response());
    }
    // Opening or using Administration is itself organization access. Record the
    // current client in the same exact-scope registry as ordinary project/data
    // traffic, while allowing a software-blocked client to reach its recovery
    // controls. Session lifetime, membership, and durable revocation still apply.
    let recovery_actor = wb.admit_sso_recovery(bearer(headers), &store_scope).ok();
    let recovery_only = recovery_actor.is_some();
    if recovery_only {
        capabilities.retain(|capability| *capability == Capability::ConfigureSso);
    }
    let actor = if let Some(actor) = recovery_actor {
        actor
    } else {
        wb.admit_data_request_with_client(
            bearer(headers),
            None,
            &store_scope,
            gaugedesk_app::client_admission::ClientBuild::from_headers(headers),
            false,
        )
        .map_err(|(status, message)| (status, Json(json!({ "error": message }))).into_response())?
    };
    let tenant = tenant_id(headers);
    let mut projected = Vec::new();
    for policy in PAGES.iter().copied().filter(|policy| {
        (!recovery_only || policy.id == "enterprise-identity")
            && can_read(&capabilities, *policy)
            && built_in_page_allowed(&tenant, policy.id)
    }) {
        if let Some(extension) = extension {
            if !extension
                .allow_base_page(wb, &tenant, &store_scope, policy.id)
                .map_err(extension_error)?
            {
                continue;
            }
        }
        let model =
            project_page(wb, &store_scope, policy, bearer(headers), headers).map_err(internal)?;
        let mut commands = Vec::new();
        for command in COMMANDS.iter().filter(|command| {
            command.page == policy.id
                && (!recovery_only || command.id == "enterprise-identity.enforcement.disable")
                && has_capability(&capabilities, command.capability)
                && (command.id != "organization.delete" || tenant != ORG_ID)
        }) {
            if let Some(extension) = extension {
                if !extension
                    .allow_base_command(wb, &tenant, &store_scope, command.id)
                    .map_err(extension_error)?
                {
                    continue;
                }
            }
            commands.push(AdministrationExtensionCommand {
                id: command.id.to_owned(),
                capability: command.capability,
                review: command.review,
            });
        }
        projected.push(AdministrationExtensionPage {
            id: policy.id.to_owned(),
            read_model: policy.read_model.to_owned(),
            version: policy.version,
            freshness: if policy.id == "project-hosts" {
                "target-live"
            } else {
                "live"
            }
            .to_owned(),
            model,
            commands,
        });
    }
    if let Some(extension) = extension {
        let contributed = extension
            .project(wb, &tenant, &store_scope, &actor, &capabilities)
            .map_err(extension_error)?;
        for page in contributed.into_iter().filter(|page| {
            (!recovery_only || page.id == "enterprise-identity")
                && contributed_page_allowed(&tenant, &page.id)
        }) {
            if let Some(index) = projected.iter().position(|current| {
                current.id == page.id
                    && current.read_model == page.read_model
                    && current.version == page.version
            }) {
                projected[index] = page;
                continue;
            }
            if projected.iter().any(|current| current.id == page.id) {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "Administration extension declared a duplicate page" })),
                )
                    .into_response());
            }
            projected.push(page);
        }
    }
    let page_grants = projected
        .iter()
        .map(|page| {
            Ok(GaugeAppPageGrant {
                id: page.id.clone(),
                read_model: page.read_model.clone(),
                version: page.version,
                resource_basis: page_resource_basis(page, &tenant).map_err(internal)?,
                freshness: page.freshness.clone(),
                availability: GaugeAppPageAvailability::Available,
                commands: page
                    .commands
                    .iter()
                    .map(|command| command.id.clone())
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>, Response>>()?;
    let mut command_grants: Vec<GaugeAppCommandGrant> = Vec::new();
    for page in &projected {
        for command in &page.commands {
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
                command_grants.push(GaugeAppCommandGrant {
                    id: command.id.clone(),
                    capability: command.capability.as_str().to_owned(),
                    review: command.review,
                });
            }
        }
    }
    let scope = GaugeAppScope {
        kind: "tenant".into(),
        id: tenant,
    };
    let capability_names = capabilities
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect::<Vec<_>>();
    // Session identity tracks authorization, not mutable projection content.
    // Each page carries its own exact resource basis; folding page hashes
    // into the session id would make the proposal's own audit row invalidate the
    // session before a human could review it.
    let epoch = resource_basis(&json!({ "actor": actor, "capabilities": capability_names }));
    let update_cursor = resource_basis(&json!(page_grants));
    let session = GaugeAppSession {
        id: gaugeapp_session_id(&actor, GAUGEAPP, &scope, &epoch),
        generation: epoch,
        app: GAUGEAPP,
        scope,
        actor,
        capabilities: capability_names,
        pages: page_grants,
        commands: command_grants,
        update_cursor,
    };
    Ok((session, projected))
}

fn internal(error: impl std::fmt::Debug) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": format!("GaugeApp page projection unavailable: {error:?}") })),
    )
        .into_response()
}

fn extension_ref(
    extension: &Option<Extension<AdministrationGaugeAppExtensionHandle>>,
) -> Option<&AdministrationGaugeAppExtensionHandle> {
    extension.as_ref().map(|Extension(extension)| extension)
}

#[derive(Deserialize)]
struct OpenBody {
    #[serde(default)]
    scope: Option<GaugeAppScope>,
}

async fn open_session(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
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
    generation: String,
    scope: String,
}

#[derive(Deserialize)]
struct AgentMessagesQuery {
    session: String,
    generation: String,
    scope: String,
    after: Option<String>,
}

#[derive(Deserialize)]
struct UpdatesQuery {
    session: String,
    generation: String,
    scope: String,
    after: String,
}

#[derive(Deserialize)]
struct DomainChallengeQuery {
    session: String,
    generation: String,
    scope: String,
    domain: String,
}

async fn domain_verification_challenge(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    Query(query): Query<DomainChallengeQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if query.session != session.id
        || query.generation != session.generation
        || query.scope != session.scope.id
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "GaugeApp session is stale or cross-scope" })),
        )
            .into_response();
    }
    if !session
        .commands
        .iter()
        .any(|command| command.id == "organization.domain.verify")
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

async fn read_page(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    Path(id): Path<String>,
    Query(query): Query<SessionQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let (session, projected) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if query.session != session.id
        || query.generation != session.generation
        || query.scope != session.scope.id
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "GaugeApp session is stale or cross-scope" })),
        )
            .into_response();
    }
    let Some(page) = projected.into_iter().find(|page| page.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "page is not admitted" })),
        )
            .into_response();
    };
    let grant = session
        .pages
        .iter()
        .find(|page| page.id == id)
        .expect("projected page has grant");
    (
        StatusCode::OK,
        Json(json!({ "page": {
            "app": session.app,
            "scope": session.scope,
            "id": page.id,
            "read_model": page.read_model,
            "version": page.version,
            "resource_basis": grant.resource_basis,
            "freshness": grant.freshness,
            "model": page.model,
    } })),
    )
        .into_response()
}

async fn read_updates(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    Query(query): Query<UpdatesQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if query.session != session.id
        || query.generation != session.generation
        || query.scope != session.scope.id
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "GaugeApp session is stale or cross-scope" })),
        )
            .into_response();
    }

    let invalidations = if query.after == session.update_cursor {
        Vec::new()
    } else {
        session
            .pages
            .iter()
            .map(|page| {
                json!({
                    "page_id": page.id,
                    "resource_basis": page.resource_basis,
                })
            })
            .collect()
    };
    (
        StatusCode::OK,
        Json(json!({
            "cursor": session.update_cursor,
            "invalidations": invalidations,
        })),
    )
        .into_response()
}

async fn agent_message(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    headers: HeaderMap,
    Json(body): Json<AgentMessageBody>,
) -> Response {
    if let Err(response) = idempotency(&headers, &body.idempotency_key) {
        return response;
    }
    let (context, turn_claim, turn_thread_id, live_turn) = {
        let mut guard = wb.lock_unpoisoned();
        let (session, projected) = match build_session(&guard, &headers, extension_ref(&extension))
        {
            Ok(value) => value,
            Err(response) => return response,
        };
        if body.session_id != session.id
            || body.generation != session.generation
            || body.scope != session.scope
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "agent session is stale or cross-scope" })),
            )
                .into_response();
        }
        if let Err(error) = migrate_legacy_gaugeapp_agent_transcript(&mut guard, &session) {
            return agent_error(error);
        }
        match replayed_gaugeapp_agent_turn(
            guard.store_ref(),
            &session,
            &body.idempotency_key,
            &body.message,
        ) {
            Ok(Some(turn)) => {
                let transcript = match gaugeapp_agent_transcript(guard.store_ref(), &session) {
                    Ok(transcript) => transcript,
                    Err(error) => {
                        return agent_error(GaugeAppAgentError::Store(format!("{error:?}")))
                    }
                };
                let payload = match agent_transcript_payload(&session, transcript, None) {
                    Ok(payload) => payload,
                    Err(response) => return response,
                };
                return (
                    StatusCode::OK,
                    Json(json!({ "turn": turn, "thread": payload })),
                )
                    .into_response();
            }
            Ok(None) => {}
            Err(error) => return agent_error(error),
        }
        let thread_id = gaugeapp_thread_id(&session);
        let Some(claim) = claim_gaugeapp_agent_turn(&thread_id) else {
            return agent_error(GaugeAppAgentError::Busy);
        };
        let live = match begin_gaugeapp_agent_live_turn(&session, &body.idempotency_key) {
            Ok(live) => live,
            Err(error) => return agent_error(error),
        };
        (agent_context(session, projected), claim, thread_id, live)
    };
    let transcript_session = context.session.clone();
    let transcript_idempotency_key = body.idempotency_key.clone();
    let transcript_user = body.message.clone();
    let runtime_wb = wb.clone();
    let runtime_headers = headers.clone();
    let runtime_extension = extension.clone();
    let refresh_wb = wb.clone();
    let runtime_thread_id = turn_thread_id.clone();
    let runtime_live_turn = live_turn.clone();
    match tokio::task::spawn_blocking(move || {
        let result = run_gaugeapp_agent_turn_with_refresh_stop_and_events(
            &runtime_wb,
            context,
            &body.message,
            move || {
                let guard = refresh_wb.lock_unpoisoned();
                let (session, projected) =
                    build_session(&guard, &runtime_headers, extension_ref(&runtime_extension))
                        .map_err(|_| {
                            GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionRevoked)
                        })?;
                Ok(agent_context(session, projected))
            },
            || gaugeapp_agent_turn_was_stopped(&runtime_thread_id),
            |event| runtime_live_turn.publish(event),
        );
        (turn_claim, result)
    })
    .await
    {
        Ok((_turn_claim, Ok(turn))) => match append_gaugeapp_agent_exchange_prepared_current(
            &wb,
            &transcript_session,
            &transcript_idempotency_key,
            &transcript_user,
            &turn,
            &|guard| {
                if gaugeapp_agent_turn_was_stopped(&turn_thread_id) {
                    return Err(GaugeAppAgentError::Interrupted);
                }
                let rejected =
                    |_| GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionRevoked);
                let (current, _) =
                    build_session(guard, &headers, extension_ref(&extension)).map_err(rejected)?;
                if current.id != transcript_session.id
                    || current.generation != transcript_session.generation
                    || current.app != transcript_session.app
                    || current.scope != transcript_session.scope
                    || current.actor != transcript_session.actor
                {
                    return Err(GaugeAppAgentError::Rejected(
                        GaugeAppAgentRejection::SessionMismatch,
                    ));
                }
                Ok(())
            },
            &|guard, envelope| {
                let rejected = |_| {
                    GaugeAppAgentError::InvalidOutput(format!(
                    "Cannot prepare {} with the current authority and values. Refresh its page and try again.", envelope.command_id))
                };
                let (current, _) =
                    build_session(guard, &headers, extension_ref(&extension)).map_err(rejected)?;
                decide_gaugeapp_command(&current, envelope).map_err(|error| {
                    GaugeAppAgentError::InvalidOutput(format!("Proposal refused: {error:?}"))
                })?;
                plan_command(guard, &headers, envelope, extension_ref(&extension))
                    .map_err(rejected)?;
                fact(
                    &req_scope(&headers),
                    GAUGEAPP_CHANGE_KIND,
                    proposed_change(&current, envelope),
                )
                .map_err(rejected)
            },
        ) {
            Ok(transcript) => {
                let _ = live_turn.publish(GaugeAppAgentLiveEvent::Settled);
                match agent_transcript_payload(&transcript_session, transcript, None) {
                    Ok(thread) => (
                        StatusCode::OK,
                        Json(json!({ "turn": turn, "thread": thread })),
                    )
                        .into_response(),
                    Err(response) => response,
                }
            }
            Err(error) => {
                let event = if matches!(&error, GaugeAppAgentError::Interrupted) {
                    GaugeAppAgentLiveEvent::Stopped
                } else {
                    GaugeAppAgentLiveEvent::Failed
                };
                let _ = live_turn.publish(event);
                agent_error(error)
            }
        },
        Ok((_turn_claim, Err(error))) => {
            let event = if matches!(&error, GaugeAppAgentError::Interrupted) {
                GaugeAppAgentLiveEvent::Stopped
            } else {
                GaugeAppAgentLiveEvent::Failed
            };
            let _ = live_turn.publish(event);
            agent_error(error)
        }
        Err(_) => {
            let _ = live_turn.publish(GaugeAppAgentLiveEvent::Failed);
            agent_error(GaugeAppAgentError::Provider("agent task failed".into()))
        }
    }
}

fn live_event(frame: GaugeAppAgentLiveFrame) -> Result<Event, Infallible> {
    Ok(Event::default()
        .data(serde_json::to_string(&frame).expect("GaugeApp live frame serializes")))
}

async fn agent_events(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    Query(query): Query<AgentMessagesQuery>,
    headers: HeaderMap,
) -> Response {
    let thread_id = {
        let guard = wb.lock_unpoisoned();
        let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
            Ok(value) => value,
            Err(response) => return response,
        };
        if query.session != session.id
            || query.generation != session.generation
            || query.scope != session.scope.id
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "agent session is stale or cross-scope" })),
            )
                .into_response();
        }
        gaugeapp_thread_id(&session)
    };
    let (retained, receiver) = gaugeapp_agent_live_subscription(&thread_id, query.after.as_deref());
    let retained = tokio_stream::iter(retained.into_iter().map(live_event));
    let broadcast_thread = thread_id.clone();
    // A lagged broadcast subscriber closes so the browser reconnects with its
    // last cursor and repairs from the retained server buffer.
    let current = BroadcastStream::new(receiver)
        .take_while(|message| message.is_ok())
        .filter_map(move |message| match message {
            Ok(frame) if frame.thread_id == broadcast_thread => Some(live_event(frame)),
            _ => None,
        });
    Sse::new(retained.chain(current))
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

fn agent_context(
    session: GaugeAppSession,
    projected: Vec<AdministrationExtensionPage>,
) -> GaugeAppAgentContext {
    let pages = projected
        .into_iter()
        .map(|page| {
            let grant = session
                .pages
                .iter()
                .find(|grant| grant.id == page.id)
                .expect("projected Administration page has a grant");
            GaugeAppAgentPage {
                id: grant.id.clone(),
                read_model: grant.read_model.clone(),
                version: grant.version,
                resource_basis: grant.resource_basis.clone(),
                model: page.model,
                commands: gaugeapp_agent_page_commands(&session, grant),
            }
        })
        .collect();
    GaugeAppAgentContext { session, pages }
}

async fn agent_messages(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    Query(query): Query<AgentMessagesQuery>,
    headers: HeaderMap,
) -> Response {
    let mut guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if query.session != session.id
        || query.generation != session.generation
        || query.scope != session.scope.id
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "agent session is stale or cross-scope" })),
        )
            .into_response();
    }
    if let Err(error) = migrate_legacy_gaugeapp_agent_transcript(&mut guard, &session) {
        return agent_error(error);
    }
    match gaugeapp_agent_transcript(guard.store_ref(), &session) {
        Ok(transcript) => {
            match agent_transcript_payload(&session, transcript, query.after.as_deref()) {
                Ok(thread) => (StatusCode::OK, Json(json!({ "thread": thread }))).into_response(),
                Err(response) => response,
            }
        }
        Err(error) => agent_error(GaugeAppAgentError::Store(format!("{error:?}"))),
    }
}

fn agent_transcript_payload(
    session: &GaugeAppSession,
    transcript: Vec<GaugeAppAgentMessage>,
    after: Option<&str>,
) -> Result<Value, Response> {
    let thread_id = gaugeapp_thread_id(session);
    let start_cursor = format!("{thread_id}:start");
    let start = match after {
        None => 0,
        Some(cursor) if cursor == start_cursor => 0,
        Some(cursor) => transcript
            .iter()
            .position(|message| message.id == cursor)
            .map(|index| index + 1)
            .ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "management conversation cursor is stale or belongs to another thread",
                        "thread_id": thread_id,
                        "restart_cursor": start_cursor,
                    })),
                )
                    .into_response()
            })?,
    };
    let cursor = transcript
        .last()
        .map(|message| message.id.clone())
        .unwrap_or_else(|| start_cursor.clone());
    Ok(json!({
        "id": thread_id,
        "cursor": cursor,
        "messages": transcript.into_iter().skip(start).collect::<Vec<_>>(),
    }))
}

fn command_policy(id: &str) -> Option<CommandPolicy> {
    COMMANDS.iter().copied().find(|command| command.id == id)
}

fn reject_gaugeapp(error: GaugeAppRejection) -> Response {
    let status = if matches!(error, GaugeAppRejection::StaleBasis) {
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
#[serde(deny_unknown_fields)]
struct OrganizationDisplayNamePayload {
    display_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SsoCredentialPayload {
    connection_revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SsoCredentialRequest {
    envelope: GaugeAppCommandEnvelope,
    #[serde(default)]
    secret: Option<String>,
}

#[derive(Deserialize)]
struct DomainPayload {
    domain: String,
}
#[derive(Deserialize)]
struct InvitePayload {
    emails: Vec<String>,
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
#[serde(deny_unknown_fields)]
struct OrganizationDeletePayload {
    confirmation: String,
}
#[derive(Deserialize)]
struct OrganizationSessionPayload {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectCreatePayload {
    name: String,
}
#[derive(Deserialize)]
struct GrantPayload {
    authority: String,
    project_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SsoAdmissionPayload {
    mode: SsoAdmissionMode,
}

#[derive(Deserialize)]
struct GroupMappingRemovePayload {
    group: String,
}
#[derive(Deserialize)]
struct PolicyPayload {
    resource: Policy,
    security: SecurityPolicyRecord,
    placement: gaugedesk_core::boundary_lifecycle::PlacementPolicy,
    archetype_approval: ArchetypeApprovalPolicyRecord,
}

/// The accepted Organization Policy page intentionally exposes only the fixed,
/// enforceable policy vocabulary in `admin-console.md`. Older records may carry
/// a rule from a previously exposed seam; the editor may preserve that rule but
/// cannot create, remove, or alter one through this command.
fn editable_organization_policy_rule(rule: &gaugedesk_core::abac::Rule) -> bool {
    use gaugedesk_core::abac::{Action, Condition, Constraint};
    match (&rule.when, &rule.require) {
        (Condition::Always, Constraint::RequireResourceRegionMatchesActor) => true,
        (Condition::ActorHasRole(role), Constraint::DenyAction(action)) => {
            matches!(role.as_str(), "owner" | "admin" | "member" | "viewer")
                && matches!(action, Action::Run | Action::Export)
        }
        _ => false,
    }
}

fn ensure_organization_policy_surface(
    current: &Org,
    submitted: &PolicyPayload,
) -> Result<(), Response> {
    let current_policy = current.policy();
    let current_preserved = current_policy
        .rules
        .iter()
        .filter(|rule| !editable_organization_policy_rule(rule))
        .collect::<Vec<_>>();
    let submitted_preserved = submitted
        .resource
        .rules
        .iter()
        .filter(|rule| !editable_organization_policy_rule(rule))
        .collect::<Vec<_>>();
    if current_preserved != submitted_preserved {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "Organization Policy accepts only fixed role export/run restrictions and matching-region policy"
            })),
        )
            .into_response());
    }
    let current_security = current.security.clone().unwrap_or_default();
    if submitted.security.require_mfa != current_security.require_mfa
        || submitted.security.residency_region != current_security.residency_region
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "MFA and default residency are not Organization Policy controls"
            })),
        )
            .into_response());
    }
    if submitted.placement.require_attested != current.effective_placement_policy().require_attested
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "deferred placement attestation is not an Organization Policy control"
            })),
        )
            .into_response());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BillingContactPayload {
    name: String,
    email: String,
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

/// A claimed domain, lowercased and checked for the shape a DNS challenge can
/// actually be published under.
///
/// The page sends whatever an administrator typed, so a pasted URL or an email
/// address arrives here routinely. Minting a challenge for one produces a
/// `_gaugewright-challenge.https://acme.com` record nobody can create, and the
/// claim then sits pending forever while the page insists the DNS is wrong.
fn claimed_domain(raw: &str) -> Result<String, Response> {
    let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "domain is required" })),
        )
            .into_response());
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let publishable = domain.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !publishable {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "domain is not a publishable DNS name",
                "domain": domain,
            })),
        )
            .into_response());
    }
    Ok(domain)
}

/// ADR 0149 §1: granting a **privileged** role (`owner`/`admin`) — as the target of an
/// invite or a role change — requires the owner-only `GrantPrivilegedRoles` capability,
/// over and above the `ManageMembers` the `member.*` command already carries. The
/// command adapter authorizes at capability granularity only (`decide_gaugeapp_command`
/// checks the command's single capability), so this **target-role** gate lives in the
/// planner, which re-runs on submit, apply, and review. Fail-closed: an admin — which
/// holds `ManageMembers` but not `GrantPrivilegedRoles` — cannot elevate anyone,
/// including itself, to `owner`/`admin`.
fn ensure_can_grant_privileged_role(
    wb: &Workbench,
    headers: &HeaderMap,
    target_role: &str,
) -> Result<(), Response> {
    if !gaugedesk_app::org::is_privileged_role(target_role) {
        return Ok(());
    }
    let capabilities = wb
        .admin_capabilities(bearer(headers), &req_scope(headers))
        .map_err(|(status, message)| (status, Json(json!({ "error": message }))).into_response())?;
    if capabilities.contains(&Capability::GrantPrivilegedRoles) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "granting the owner/admin role requires the owner-only GrantPrivilegedRoles capability"
            })),
        )
            .into_response())
    }
}

fn plan_command(
    wb: &Workbench,
    headers: &HeaderMap,
    command: &GaugeAppCommandEnvelope,
    extension: Option<&AdministrationGaugeAppExtensionHandle>,
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
            Json(json!({ "error": "secret-bearing fields are forbidden in GaugeApp commands" })),
        )
            .into_response());
    }
    let scope = req_scope(headers);
    let org = Org::rebuild_in(wb.store_ref(), &scope).map_err(internal)?;
    let plan = match command.command_id.as_str() {
        "project.create" => {
            let value: ProjectCreatePayload = parse(&command.payload)?;
            let name = value.name.trim();
            if name.is_empty() || name.chars().count() > 120 {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "project name must be between 1 and 120 characters" })),
                )
                    .into_response());
            }
            MutationPlan {
                // The exact Home owns project records and filesystem setup. The
                // plan stays pure; application below uses the durable change id
                // as an idempotent project identity before the Hub receipt lands.
                facts: Vec::new(),
                notices: Vec::new(),
                audit_action: "project.create",
                audit_target: name.to_owned(),
                transient_result: None,
            }
        }
        "organization.display-name.set" => {
            let value: OrganizationDisplayNamePayload = parse(&command.payload)?;
            let display_name = value.display_name.trim();
            if display_name.is_empty() || display_name.chars().count() > 120 {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "display name must be between 1 and 120 characters" })),
                )
                    .into_response());
            }
            let mut record = org.org.clone().unwrap_or_default();
            record.id = ORG_ID.into();
            record.op = RecordOp::Upsert;
            record.display_name = display_name.to_owned();
            MutationPlan {
                facts: vec![fact(&scope, "org", &record)?],
                notices: vec![("org", record.id.clone(), "upsert")],
                audit_action: "organization.display-name.set",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "organization.ownership.transfer" => {
            let value: MemberPayload = parse(&command.payload)?;
            let actor = wb.actor(bearer(headers));
            let current = org
                .member_by_authority(&actor)
                .filter(|member| {
                    member.status == MembershipStatus::Active && member.role == "owner"
                })
                .ok_or_else(|| {
                    (
                        StatusCode::FORBIDDEN,
                        Json(json!({ "error": "only the active owner may transfer ownership" })),
                    )
                        .into_response()
                })?;
            if org.active_count_with_role("owner") != 1 {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "ownership must be repaired to one active owner before it can be transferred"
                    })),
                )
                    .into_response());
            }
            let target = org.members.get(&value.id).ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "ownership recipient is not an organization member" })),
                )
                    .into_response()
            })?;
            if target.authority == actor {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "this account already owns the organization" })),
                )
                    .into_response());
            }
            if target.status != MembershipStatus::Active {
                return Err((
                    StatusCode::CONFLICT,
                    Json(
                        json!({ "error": "ownership can be transferred only to an active member" }),
                    ),
                )
                    .into_response());
            }
            if target.managed_by_scim {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "ownership cannot be transferred to an identity-provider-managed membership"
                    })),
                )
                    .into_response());
            }
            let mut prior_owner = current.clone();
            prior_owner.op = RecordOp::Upsert;
            prior_owner.role = "admin".into();
            let mut next_owner = target.clone();
            next_owner.op = RecordOp::Upsert;
            next_owner.role = "owner".into();
            next_owner.team = None;
            MutationPlan {
                facts: vec![
                    fact(&scope, "membership", &prior_owner)?,
                    fact(&scope, "membership", &next_owner)?,
                ],
                notices: vec![
                    ("membership", prior_owner.id.clone(), "upsert"),
                    ("membership", next_owner.id.clone(), "upsert"),
                ],
                audit_action: "organization.ownership.transfer",
                audit_target: next_owner.id,
                transient_result: None,
            }
        }
        "organization.delete" => {
            let value: OrganizationDeletePayload = parse(&command.payload)?;
            let organization_name = org
                .org
                .as_ref()
                .map(|record| record.display_name.trim())
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    (
                        StatusCode::CONFLICT,
                        Json(json!({ "error": "organization identity is unavailable" })),
                    )
                        .into_response()
                })?;
            if value.confirmation.trim() != organization_name {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({
                        "error": "enter the organization display name exactly to continue"
                    })),
                )
                    .into_response());
            }
            let tenant = tenant_id(headers);
            let actor = wb.actor(bearer(headers));
            let account_scope = wb.account_scope_for(bearer(headers));
            let deletion = gaugedesk_app::tenancy::plan_delete_organization_in(
                wb.store_ref(),
                &actor,
                &account_scope,
                &tenant,
            )
            .map_err(internal)?
            .map_err(delete_organization_refusal)?;
            MutationPlan {
                facts: deletion.facts,
                notices: Vec::new(),
                audit_action: "organization.delete",
                audit_target: tenant.clone(),
                transient_result: Some(json!({ "deleted_organization": tenant })),
            }
        }
        "organization.domain.add" => {
            let value: DomainPayload = parse(&command.payload)?;
            let domain = claimed_domain(&value.domain)?;
            let mut record = org.org.clone().unwrap_or_default();
            record.id = ORG_ID.into();
            record.op = RecordOp::Upsert;
            if record
                .verified_domains
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&domain))
            {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "domain is already verified",
                        "domain": domain,
                    })),
                )
                    .into_response());
            }
            if record
                .pending_domains
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&domain))
            {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "domain is already awaiting its DNS proof",
                        "domain": domain,
                    })),
                )
                    .into_response());
            }
            record.pending_domains.push(domain.clone());
            record.pending_domains.sort();
            record.pending_domains.dedup();
            MutationPlan {
                facts: vec![fact(&scope, "org", &record)?],
                notices: vec![("org", record.id.clone(), "upsert")],
                audit_action: "organization.domain.add",
                audit_target: domain,
                transient_result: None,
            }
        }
        "organization.domain.verify" => {
            let value: DomainPayload = parse(&command.payload)?;
            let domain = claimed_domain(&value.domain)?;
            let mut record = org.org.clone().unwrap_or_default();
            record.id = ORG_ID.into();
            record.op = RecordOp::Upsert;
            // Verification promotes a standing claim; it does not create one.
            // Accepting an unclaimed domain here would let the proof step be the
            // whole ceremony, which is how a domain nobody ever claimed becomes
            // verified in one reviewed call.
            let claimed = record
                .pending_domains
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&domain));
            let already_verified = record
                .verified_domains
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&domain));
            if !claimed && !already_verified {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "error": "domain has not been added",
                        "domain": domain,
                    })),
                )
                    .into_response());
            }
            record
                .pending_domains
                .retain(|existing| !existing.eq_ignore_ascii_case(&domain));
            if !already_verified {
                record.verified_domains.push(domain.clone());
                record.verified_domains.sort();
                record.verified_domains.dedup();
            }
            MutationPlan {
                facts: vec![fact(&scope, "org", &record)?],
                notices: vec![("org", record.id.clone(), "upsert")],
                audit_action: "organization.domain.verify",
                audit_target: domain,
                transient_result: None,
            }
        }
        "organization.domain.remove" => {
            let value: DomainPayload = parse(&command.payload)?;
            let domain = value.domain.trim().to_ascii_lowercase();
            if domain.is_empty() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "domain is required" })),
                )
                    .into_response());
            }
            let Some(mut record) = org.org.clone() else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "organization identity is unavailable" })),
                )
                    .into_response());
            };
            // Remove withdraws a claim at either stage. Restricting it to
            // verified domains would leave a mistyped pending claim with no way
            // off the page at all, since its DNS proof can never arrive.
            let before = record.verified_domains.len() + record.pending_domains.len();
            record
                .verified_domains
                .retain(|existing| !existing.eq_ignore_ascii_case(&domain));
            record
                .pending_domains
                .retain(|existing| !existing.eq_ignore_ascii_case(&domain));
            if record.verified_domains.len() + record.pending_domains.len() == before {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "domain is not present" })),
                )
                    .into_response());
            }
            record.id = ORG_ID.into();
            record.op = RecordOp::Upsert;
            MutationPlan {
                facts: vec![fact(&scope, "org", &record)?],
                notices: vec![("org", record.id.clone(), "upsert")],
                audit_action: "organization.domain.remove",
                audit_target: domain,
                transient_result: None,
            }
        }
        "people.invitation.create" => {
            let value: InvitePayload = parse(&command.payload)?;
            if !gaugedesk_app::org::is_valid_role(&value.role) {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "a fixed role is required" })),
                )
                    .into_response());
            }
            ensure_can_grant_privileged_role(wb, headers, &value.role)?;
            if value.role == "owner" {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "invite the person into a non-owner role, then use Transfer ownership after they accept"
                    })),
                )
                    .into_response());
            }
            if value.emails.is_empty() || value.emails.len() > ORGANIZATION_INVITATION_BATCH_MAX {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({
                        "error": format!(
                            "provide between 1 and {ORGANIZATION_INVITATION_BATCH_MAX} email addresses"
                        )
                    })),
                )
                    .into_response());
            }
            let mut emails = value
                .emails
                .iter()
                .map(|email| {
                    normalize_email_contact(email).ok_or_else(|| {
                        (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Json(json!({ "error": format!("invalid email address: {email}") })),
                        )
                            .into_response()
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            emails.sort();
            emails.dedup();
            for email in &emails {
                let already_member = org.members.values().any(|member| {
                    member.status != MembershipStatus::Deprovisioned
                        && member.email.eq_ignore_ascii_case(email)
                });
                let already_invited = org.invitations.values().any(|invitation| {
                    invitation.status == OrganizationInvitationStatus::Pending
                        && invitation.email.eq_ignore_ascii_case(email)
                });
                if already_member || already_invited {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(json!({
                            "error": format!("{email} is already a member or has a pending invitation")
                        })),
                    )
                        .into_response());
                }
            }
            let issued_at_ms = gaugedesk_app::account::session_now_ms();
            let expires_at_ms = issued_at_ms.saturating_add(ORGANIZATION_INVITATION_TTL_MS);
            let mut facts = Vec::with_capacity(emails.len());
            let mut notices = Vec::with_capacity(emails.len());
            let mut delivery_links = Vec::with_capacity(emails.len());
            for email in emails {
                let id = gaugedesk_app::library::gen_id("oinv");
                let proof = hex::encode(gaugedesk_app::session::random_bytes::<32>());
                let record = OrganizationInvitationRecord {
                    id: id.clone(),
                    op: RecordOp::Upsert,
                    org_id: ORG_ID.into(),
                    email: email.clone(),
                    role: value.role.clone(),
                    team: value.team.clone(),
                    proof_sha256: sha256_hex(&proof),
                    status: OrganizationInvitationStatus::Pending,
                    issued_at_ms,
                    expires_at_ms,
                    responded_by: None,
                    responded_at_ms: None,
                };
                facts.push(fact(&scope, ORGANIZATION_INVITATION_KIND, &record)?);
                notices.push((ORGANIZATION_INVITATION_KIND, id.clone(), "upsert"));
                delivery_links.push(json!({
                    "tenant_id": tenant_id(headers),
                    "invitation_id": id,
                    "email": email,
                    "proof": proof,
                    "expires_at_ms": expires_at_ms,
                }));
            }
            MutationPlan {
                facts,
                notices,
                audit_action: "people.invitation.create",
                audit_target: format!("{} recipients", delivery_links.len()),
                transient_result: Some(json!({
                    "delivery_kind": "organization-invitation",
                    "delivery_links": delivery_links,
                })),
            }
        }
        "people.invitation.cancel" => {
            let value: MemberPayload = parse(&command.payload)?;
            if let Some(existing) = org.invitations.get(&value.id) {
                if existing.status != OrganizationInvitationStatus::Pending {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(json!({ "error": "only a pending invitation can be cancelled" })),
                    )
                        .into_response());
                }
                let mut record = existing.clone();
                record.op = RecordOp::Upsert;
                record.status = OrganizationInvitationStatus::Cancelled;
                record.proof_sha256 = sha256_hex("");
                return Ok(MutationPlan {
                    facts: vec![fact(&scope, ORGANIZATION_INVITATION_KIND, &record)?],
                    notices: vec![(ORGANIZATION_INVITATION_KIND, record.id.clone(), "upsert")],
                    audit_action: "people.invitation.cancel",
                    audit_target: record.id,
                    transient_result: None,
                });
            }
            let Some(existing) = org.members.get(&value.id) else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "no such invitation" })),
                )
                    .into_response());
            };
            if existing.managed_by_scim {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "this membership is managed by SCIM" })),
                )
                    .into_response());
            }
            if existing.status != MembershipStatus::Invited {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "only a pending invitation can be cancelled" })),
                )
                    .into_response());
            }
            let mut record = existing.clone();
            record.op = RecordOp::Upsert;
            record.status = MembershipStatus::Deprovisioned;
            MutationPlan {
                facts: vec![fact(&scope, "membership", &record)?],
                notices: vec![("membership", record.id.clone(), "upsert")],
                audit_action: "people.invitation.cancel",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "people.invitation.resend" => {
            let value: MemberPayload = parse(&command.payload)?;
            let Some(existing) = org.invitations.get(&value.id) else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "no such invitation" })),
                )
                    .into_response());
            };
            if existing.status != OrganizationInvitationStatus::Pending {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "only a pending invitation can be resent" })),
                )
                    .into_response());
            }
            let proof = hex::encode(gaugedesk_app::session::random_bytes::<32>());
            let issued_at_ms = gaugedesk_app::account::session_now_ms();
            let expires_at_ms = issued_at_ms.saturating_add(ORGANIZATION_INVITATION_TTL_MS);
            let mut record = existing.clone();
            record.op = RecordOp::Upsert;
            record.proof_sha256 = sha256_hex(&proof);
            record.issued_at_ms = issued_at_ms;
            record.expires_at_ms = expires_at_ms;
            record.responded_by = None;
            record.responded_at_ms = None;
            MutationPlan {
                facts: vec![fact(&scope, ORGANIZATION_INVITATION_KIND, &record)?],
                notices: vec![(ORGANIZATION_INVITATION_KIND, record.id.clone(), "upsert")],
                audit_action: "people.invitation.resend",
                audit_target: record.id.clone(),
                transient_result: Some(json!({
                    "delivery_kind": "organization-invitation",
                    "delivery_links": [{
                        "tenant_id": tenant_id(headers),
                        "invitation_id": record.id,
                        "email": record.email,
                        "proof": proof,
                        "expires_at_ms": expires_at_ms,
                    }],
                })),
            }
        }
        "people.role.change" => {
            let value: MemberRolePayload = parse(&command.payload)?;
            if !gaugedesk_app::org::is_valid_role(&value.role) {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "unknown role" })),
                )
                    .into_response());
            }
            ensure_can_grant_privileged_role(wb, headers, &value.role)?;
            if value.role == "owner" {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "use Transfer ownership to assign the owner role" })),
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
            if existing.managed_by_scim {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "this membership is managed by SCIM" })),
                )
                    .into_response());
            }
            if !wb.team_scope_ok_in(bearer(headers), existing.team.as_deref(), &scope) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "outside your team scope" })),
                )
                    .into_response());
            }
            if existing.role == "owner" {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "use Transfer ownership to change the owner role" })),
                )
                    .into_response());
            }
            let mut record = existing.clone();
            record.op = RecordOp::Upsert;
            record.role = value.role;
            MutationPlan {
                facts: vec![fact(&scope, "membership", &record)?],
                notices: vec![("membership", record.id.clone(), "upsert")],
                audit_action: "people.role.change",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "people.member.deactivate" | "people.member.reactivate" => {
            let value: MemberPayload = parse(&command.payload)?;
            let Some(existing) = org.members.get(&value.id) else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "no such member" })),
                )
                    .into_response());
            };
            if existing.managed_by_scim {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "this membership is managed by SCIM" })),
                )
                    .into_response());
            }
            if !wb.team_scope_ok_in(bearer(headers), existing.team.as_deref(), &scope) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "outside your team scope" })),
                )
                    .into_response());
            }
            if command.command_id == "people.member.deactivate"
                && existing.role == "owner"
                && existing.status == MembershipStatus::Active
                && org.active_count_with_role("owner") <= 1
            {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "cannot deactivate the last owner" })),
                )
                    .into_response());
            }
            let target_status = if command.command_id == "people.member.deactivate" {
                MembershipStatus::Deprovisioned
            } else {
                MembershipStatus::Active
            };
            if target_status == MembershipStatus::Active && !org.seat_available_for(&existing.id) {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "purchased seat capacity is full" })),
                )
                    .into_response());
            }
            if existing.status == target_status {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "membership is already in the requested state" })),
                )
                    .into_response());
            }
            let mut record = existing.clone();
            record.op = RecordOp::Upsert;
            record.status = target_status;
            MutationPlan {
                facts: vec![fact(&scope, "membership", &record)?],
                notices: vec![("membership", record.id.clone(), "upsert")],
                audit_action: if command.command_id == "people.member.deactivate" {
                    "people.member.deactivate"
                } else {
                    "people.member.reactivate"
                },
                audit_target: record.id,
                transient_result: None,
            }
        }
        "project-access.grant" | "project-access.revoke" => {
            let value: GrantPayload = parse(&command.payload)?;
            if value.authority.trim().is_empty() || value.project_id.trim().is_empty() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "authority and project_id are required" })),
                )
                    .into_response());
            }
            let Some(member) = org.member_by_authority(&value.authority) else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "no such member" })),
                )
                    .into_response());
            };
            if member.status != MembershipStatus::Active {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "project access requires an active member" })),
                )
                    .into_response());
            }
            let record = MemberGrantRecord {
                id: MemberGrantRecord::make_id(&value.authority, &value.project_id),
                op: if command.command_id == "project-access.grant" {
                    RecordOp::Upsert
                } else {
                    RecordOp::Tombstone
                },
                authority: value.authority,
                project_id: value.project_id,
            };
            let op = if command.command_id == "project-access.grant" {
                "upsert"
            } else {
                "tombstone"
            };
            MutationPlan {
                facts: vec![fact(&scope, "member_grant", &record)?],
                notices: vec![("member_grant", record.id.clone(), op)],
                audit_action: if command.command_id == "project-access.grant" {
                    "project-access.grant"
                } else {
                    "project-access.revoke"
                },
                audit_target: record.id,
                transient_result: None,
            }
        }
        "organization-session.revoke" => {
            let value: OrganizationSessionPayload = parse(&command.payload)?;
            if value.id.trim().is_empty() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "session id is required" })),
                )
                    .into_response());
            }
            let target = wb
                .organization_session_roster_in(&scope)
                .map_err(internal)?
                .into_iter()
                .find(|session| session.id == value.id)
                .ok_or_else(|| {
                    (
                        StatusCode::NOT_FOUND,
                        Json(json!({ "error": "no such active organization session" })),
                    )
                        .into_response()
                })?;
            let record = OrganizationSessionRevocationRecord {
                id: target.id,
                op: RecordOp::Upsert,
            };
            MutationPlan {
                facts: vec![fact(&scope, "organization_session_revocation", &record)?],
                notices: vec![(
                    "organization_session_revocation",
                    record.id.clone(),
                    "upsert",
                )],
                audit_action: "organization-session.revoke",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "enterprise-identity.connection.set" => {
            let mut record: SsoConnectionRecord = parse(&command.payload)?;
            match record.protocol {
                gaugedesk_app::org::SsoProtocol::Oidc => {
                    record.issuer = record.issuer.trim().trim_end_matches('/').to_owned();
                    record.audiences = record
                        .audiences
                        .into_iter()
                        .map(|audience| audience.trim().to_owned())
                        .filter(|audience| !audience.is_empty())
                        .collect();
                    record.metadata.clear();
                    record.saml_sp_entity_id.clear();
                    record.saml_acs_url.clear();
                    if record.issuer.is_empty() || record.audiences.is_empty() {
                        return Err((
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Json(json!({ "error": "OIDC requires issuer and client id" })),
                        )
                            .into_response());
                    }
                }
                gaugedesk_app::org::SsoProtocol::Saml => {
                    let summary = crate::identity_saml::validate_idp_metadata(&record.metadata)
                        .map_err(|error| {
                            (
                                StatusCode::UNPROCESSABLE_ENTITY,
                                Json(json!({ "error": error.message(), "code": error.code() })),
                            )
                                .into_response()
                        })?;
                    record.issuer = summary.issuer;
                    record.audiences.clear();
                    let integration = crate::org_routes::enterprise_integration(headers);
                    record.saml_sp_entity_id = integration["saml"]["sp_entity_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                    record.saml_acs_url = integration["saml"]["acs_url"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                }
            }
            // Credential custody is a separate immediate write-only ceremony.
            // A reviewed claim-mapping edit may retain the credential, but a
            // new protocol, issuer, or client id is a different OAuth client
            // and retires the old secret rather than silently reassigning it.
            let retains_credential = org.sso.as_ref().is_some_and(|current| {
                current.protocol == record.protocol
                    && current.issuer == record.issuer
                    && current.audiences == record.audiences
            });
            record.credential_revision = org.sso.as_ref().and_then(|current| {
                retains_credential
                    .then(|| current.credential_revision.clone())
                    .flatten()
            });
            record.id = ORG_ID.into();
            record.op = RecordOp::Upsert;
            // Enforcement is a distinct accepted lifecycle with prerequisites.
            // Connection setup cannot smuggle it through the record field.
            record.enforce_sso = false;
            record.seal_revision();
            let mut facts = vec![fact(&scope, "sso", &record)?];
            let mut notices = vec![("sso", record.id.clone(), "upsert")];
            if !retains_credential {
                if let Some(current) = org.current_sso_credential() {
                    let retired = SsoCredentialRecord {
                        op: RecordOp::Tombstone,
                        sealed_secret: String::new(),
                        ..current.clone()
                    };
                    facts.push(fact(&scope, SSO_CREDENTIAL_KIND, &retired)?);
                    notices.push((SSO_CREDENTIAL_KIND, retired.id.clone(), "tombstone"));
                }
            }
            MutationPlan {
                facts,
                notices,
                audit_action: "enterprise-identity.connection.set",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "enterprise-identity.admission-mode.set" => {
            let value: SsoAdmissionPayload = parse(&command.payload)?;
            let record = SsoAdmissionRecord {
                id: ORG_ID.into(),
                op: RecordOp::Upsert,
                mode: value.mode,
            };
            MutationPlan {
                facts: vec![fact(&scope, SSO_ADMISSION_KIND, &record)?],
                notices: vec![(SSO_ADMISSION_KIND, record.id.clone(), "upsert")],
                audit_action: "enterprise-identity.admission-mode.set",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "enterprise-identity.owner-subject.link" => {
            let _: EmptyPayload = parse(&command.payload)?;
            let token = bearer(headers).ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "authenticate with a passkey before linking corporate sign-in" })),
                )
                    .into_response()
            })?;
            let (account_id, method) = wb
                .account_sessions()
                .resolve_session(token)
                .ok_or_else(|| {
                    (
                        StatusCode::CONFLICT,
                        Json(json!({ "error": "sign in to this GaugeDesk account with a passkey before linking corporate sign-in" })),
                    )
                        .into_response()
                })?;
            if method != "passkey" {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "this link requires a current independent passkey session" })),
                )
                    .into_response());
            }
            let owner = org.member_by_authority(&account_id).filter(|member| {
                member.status == MembershipStatus::Active && member.role == "owner"
            });
            if owner.is_none() {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "only an active organization owner may link the recovery subject" })),
                )
                    .into_response());
            }
            let connection = org.sso.as_ref().ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "configure corporate sign-in before linking it" })),
                )
                    .into_response()
            })?;
            let browser_test = org.current_sso_browser_test().ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "complete a browser sign-in test before linking it" })),
                )
                    .into_response()
            })?;
            let now_ms = gaugedesk_app::account::session_now_ms();
            if browser_test.initiated_by != account_id
                || browser_test.tested_at_ms > now_ms
                || now_ms.saturating_sub(browser_test.tested_at_ms) > OWNER_SUBJECT_LINK_TTL_MS
            {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "run a new sign-in test from this owner account, then link it within ten minutes" })),
                )
                    .into_response());
            }
            let account_auth = AccountAuth::rebuild(wb.store_ref()).map_err(internal)?;
            if org.corporate_subject_linked_for(&account_auth, &account_id) {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "this owner account already has a current corporate sign-in link" })),
                )
                    .into_response());
            }
            let kind = match connection.protocol {
                gaugedesk_app::org::SsoProtocol::Oidc => ExternalSubjectKind::EnterpriseOidc,
                gaugedesk_app::org::SsoProtocol::Saml => ExternalSubjectKind::EnterpriseSaml,
            };
            let record = ExternalSubjectRecord::new(
                &account_id,
                &org.enterprise_connection_key(&connection.id),
                &connection.issuer,
                &browser_test.subject,
                kind,
                now_ms,
            )
            .map_err(|error| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": format!("corporate subject cannot be linked: {error:?}") })),
                )
                    .into_response()
            })?;
            let decisions = decide_link_external_subject(&account_auth, record.clone()).map_err(|error| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": format!("corporate subject cannot be linked: {error:?}") })),
                )
                    .into_response()
            })?;
            MutationPlan {
                facts: account_auth_command_facts(wb.store_ref(), &decisions).map_err(internal)?,
                notices: vec![("account_auth_subject", record.id.clone(), "upsert")],
                audit_action: "enterprise-identity.owner-subject.link",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "enterprise-identity.enforcement.enable" | "enterprise-identity.enforcement.disable" => {
            let _: EmptyPayload = parse(&command.payload)?;
            let enable = command.command_id == "enterprise-identity.enforcement.enable";
            let mut record = org.sso.clone().ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "configure corporate sign-in before changing enforcement" })),
                )
                    .into_response()
            })?;
            if enable {
                let account_auth = AccountAuth::rebuild(wb.store_ref()).map_err(internal)?;
                let readiness = org.sso_enforcement_readiness(&account_auth);
                if !readiness.ready() {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(json!({
                            "error": "corporate sign-in is not ready to be required",
                            "readiness": readiness,
                        })),
                    )
                        .into_response());
                }
            }
            record.op = RecordOp::Upsert;
            record.enforce_sso = enable;
            record.seal_revision();
            MutationPlan {
                facts: vec![fact(&scope, "sso", &record)?],
                notices: vec![("sso", record.id.clone(), "upsert")],
                audit_action: if enable {
                    "enterprise-identity.enforcement.enable"
                } else {
                    "enterprise-identity.enforcement.disable"
                },
                audit_target: record.id,
                transient_result: None,
            }
        }
        "enterprise-identity.connection.validate" => {
            let _: EmptyPayload = parse(&command.payload)?;
            let connection = org.sso.as_ref().ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "configure corporate sign-in before validating it" })),
                )
                    .into_response()
            })?;
            MutationPlan {
                facts: Vec::new(),
                notices: Vec::new(),
                audit_action: "enterprise-identity.connection.validate",
                audit_target: format!("{}:{}", connection.id, connection.current_revision()),
                transient_result: None,
            }
        }
        "enterprise-identity.test.begin" => {
            let _: EmptyPayload = parse(&command.payload)?;
            let connection = org.sso.as_ref().ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "configure corporate sign-in before testing it" })),
                )
                    .into_response()
            })?;
            MutationPlan {
                facts: Vec::new(),
                notices: Vec::new(),
                audit_action: "enterprise-identity.test.begin",
                audit_target: format!("{}:{}", connection.id, connection.current_revision()),
                transient_result: None,
            }
        }
        "enterprise-identity.scim-credential.issue"
        | "enterprise-identity.scim-credential.rotate" => {
            let issuing = command.command_id == "enterprise-identity.scim-credential.issue";
            if issuing == org.scim_token_sha256.is_some() {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": if issuing {
                            "a SCIM credential already exists; rotate it instead"
                        } else {
                            "no SCIM credential exists; issue one first"
                        }
                    })),
                )
                    .into_response());
            }
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
                audit_action: if issuing {
                    "enterprise-identity.scim-credential.issue"
                } else {
                    "enterprise-identity.scim-credential.rotate"
                },
                audit_target: record.id,
                transient_result: Some(json!({ "token": token })),
            }
        }
        "enterprise-identity.group-mapping.add" | "enterprise-identity.group-mapping.edit" => {
            let value: crate::org_routes::GroupMappingBody = parse(&command.payload)?;
            if !gaugedesk_app::org::is_valid_role(&value.role) || value.group.trim().is_empty() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "group and a fixed role are required" })),
                )
                    .into_response());
            }
            // ADR 0149 §1: SCIM may never confer a privileged role. Refuse a mapping
            // into `owner`/`admin` at the config boundary (fail-closed); `role_for_groups`
            // also drops any such mapping at read time as defense-in-depth.
            if gaugedesk_app::org::is_privileged_role(&value.role) {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({
                        "error": "cannot map a group into owner/admin; those roles are owner-granted only"
                    })),
                )
                    .into_response());
            }
            let exists = org.group_mappings.contains_key(&value.group);
            let adding = command.command_id == "enterprise-identity.group-mapping.add";
            if adding == exists {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": if adding { "group mapping already exists" } else { "group mapping does not exist" }
                    })),
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
                audit_action: if adding {
                    "enterprise-identity.group-mapping.add"
                } else {
                    "enterprise-identity.group-mapping.edit"
                },
                audit_target: record.id,
                transient_result: None,
            }
        }
        "enterprise-identity.group-mapping.remove" => {
            let value: GroupMappingRemovePayload = parse(&command.payload)?;
            let existing = org.group_mappings.get(&value.group).ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "group mapping does not exist" })),
                )
                    .into_response()
            })?;
            let mut record = existing.clone();
            record.op = RecordOp::Tombstone;
            MutationPlan {
                facts: vec![fact(&scope, "group_mapping", &record)?],
                notices: vec![("group_mapping", record.id.clone(), "tombstone")],
                audit_action: "enterprise-identity.group-mapping.remove",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "organization-policy.set" => {
            let value: PolicyPayload = parse(&command.payload)?;
            ensure_organization_policy_surface(&org, &value)?;
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
                audit_action: "organization-policy.set",
                audit_target: ORG_ID.into(),
                transient_result: None,
            }
        }
        "software-policy.set" => {
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
                audit_action: "software-policy.set",
                audit_target: record.id,
                transient_result: None,
            }
        }
        "billing.contact.set" => {
            let value: BillingContactPayload = parse(&command.payload)?;
            let name = value.name.trim();
            if name.is_empty() || name.chars().count() > 120 {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "billing contact name must be between 1 and 120 characters" })),
                )
                    .into_response());
            }
            let email = normalize_email_contact(&value.email)
                .filter(|email| email.len() <= 320)
                .ok_or_else(|| {
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({ "error": "valid billing contact email required" })),
                    )
                        .into_response()
                })?;
            let record = BillingContactRecord {
                id: "tenant-billing-contact".into(),
                op: RecordOp::Upsert,
                name: name.to_owned(),
                email,
            };
            MutationPlan {
                facts: vec![fact(&scope, BILLING_CONTACT_KIND, &record)?],
                notices: vec![(BILLING_CONTACT_KIND, record.id.clone(), "upsert")],
                audit_action: "billing.contact.set",
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
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
) -> GaugeAppChangeRecord {
    let receipt = gaugeapp_receipt(session, envelope, "proposed");
    GaugeAppChangeRecord {
        id: gaugeapp_change_id(session, envelope),
        app: GAUGEAPP,
        scope: session.scope.clone(),
        actor: session.actor.clone(),
        page_id: envelope.page_id.clone(),
        command_id: envelope.command_id.clone(),
        expected_basis: envelope.expected_basis.clone(),
        payload: envelope.payload.clone(),
        client: envelope.client,
        status: GaugeAppChangeStatus::Proposed,
        reviewed_by: None,
        receipt_id: receipt.id,
    }
}

fn snapshot(envelope: &GaugeAppCommandEnvelope) -> String {
    serde_json::to_string(envelope).expect("command envelope serializes")
}

fn idempotency(headers: &HeaderMap, envelope_key: &str) -> Result<String, Response> {
    let header_key = gaugedesk_app::command_idempotency::caller_idempotency_key(headers)?;
    if header_key != envelope_key {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "command idempotency key must match the request header" })),
        )
            .into_response());
    }
    Ok(header_key)
}

/// Return a previously committed exact command result before re-evaluating its
/// old resource basis. Authentication and current session identity have already
/// been rebuilt, but a successful identical retry must retain its first receipt
/// even when later commands advanced the resource.
fn replayed_command_response(
    wb: &Workbench,
    headers: &HeaderMap,
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
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
    let id = gaugeapp_change_id(session, envelope);
    let change = fold_gaugeapp_changes(wb.store_ref(), &req_scope(headers))
        .map_err(internal)?
        .remove(&id)
        .ok_or_else(|| {
            internal(std::io::Error::other(
                "GaugeApp command receipt is missing its durable change",
            ))
        })?;
    let declaration = session
        .commands
        .iter()
        .find(|command| command.id == envelope.command_id)
        .ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "command is no longer available" })),
            )
                .into_response()
        })?;
    // This is the original submission receipt. Its current proposal may already
    // be applying/applied; extension commands must not fabricate an immediate
    // application just because their declaration lives outside the static map.
    let status = match declaration.review {
        ReviewPolicy::Immediate => "applied",
        ReviewPolicy::Human => "proposed",
    };
    Ok(Some(
        (
            StatusCode::OK,
            Json(json!({
                "receipt": gaugeapp_receipt(session, envelope, status),
                "proposal": change,
            })),
        )
            .into_response(),
    ))
}

async fn validate_sso_configuration(connection: SsoConnectionRecord) -> Value {
    let revision = connection.current_revision();
    let protocol = match connection.protocol {
        gaugedesk_app::org::SsoProtocol::Oidc => "oidc",
        gaugedesk_app::org::SsoProtocol::Saml => "saml",
    };
    let base = json!({
        "kind": "enterprise-identity-configuration-validation",
        "connection_id": connection.id,
        "connection_revision": revision,
        "protocol": protocol,
        "checked_at_ms": gaugedesk_app::account::session_now_ms(),
        "browser_test": "not-run",
    });
    let mut result = base.as_object().cloned().unwrap_or_default();
    match connection.protocol {
        gaugedesk_app::org::SsoProtocol::Oidc => {
            let built = tokio::task::spawn_blocking(move || {
                crate::auth_oidc::build_oidc_idp(Some(&connection))
            })
            .await;
            let (status, code) = match built {
                Ok(Some((_provider, true))) => ("ready", "oidc-discovery-ready"),
                Ok(Some((_provider, false))) => ("needs-attention", "oidc-discovery-unreachable"),
                Ok(None) => ("needs-attention", "oidc-configuration-incomplete"),
                Err(_) => ("needs-attention", "validation-task-failed"),
            };
            result.insert("status".into(), json!(status));
            result.insert("code".into(), json!(code));
        }
        gaugedesk_app::org::SsoProtocol::Saml => {
            match crate::identity_saml::validate_idp_metadata(&connection.metadata) {
                Ok(summary) => {
                    result.insert("status".into(), json!("ready"));
                    result.insert("code".into(), json!("saml-metadata-ready"));
                    result.insert(
                        "sign_in_services".into(),
                        json!(summary.sign_in_service_count),
                    );
                    result.insert(
                        "signing_certificates".into(),
                        json!(summary.signing_certificate_count),
                    );
                }
                Err(error) => {
                    result.insert("status".into(), json!("needs-attention"));
                    result.insert("code".into(), json!(error.code()));
                }
            }
        }
    }
    Value::Object(result)
}

async fn submit_sso_configuration_validation(
    wb: SharedWorkbench,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    headers: HeaderMap,
    envelope: GaugeAppCommandEnvelope,
    key: String,
) -> Response {
    let (connection, validated_revision) = {
        let guard = wb.lock_unpoisoned();
        let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
            Ok(value) => value,
            Err(response) => return response,
        };
        if envelope.session_id == session.id
            && envelope.generation == session.generation
            && envelope.app == session.app
            && envelope.scope == session.scope
        {
            match replayed_command_response(&guard, &headers, &session, &envelope, &key) {
                Ok(Some(response)) => return response,
                Ok(None) => {}
                Err(response) => return response,
            }
        }
        let admission = match decide_gaugeapp_command(&session, &envelope) {
            Ok(value) => value,
            Err(error) => return reject_gaugeapp(error),
        };
        if admission.disposition != AdmissionDisposition::Apply {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "configuration validation must be immediate" })),
            )
                .into_response();
        }
        if contains_secret(&envelope.payload) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    json!({ "error": "secret-bearing fields are forbidden in GaugeApp commands" }),
                ),
            )
                .into_response();
        }
        if let Err(response) = plan_command(&guard, &headers, &envelope, extension_ref(&extension))
        {
            return response;
        }
        let connection = match Org::rebuild_in(guard.store_ref(), &req_scope(&headers))
            .map_err(internal)
            .and_then(|org| {
                org.sso.ok_or_else(|| {
                    (
                        StatusCode::CONFLICT,
                        Json(
                            json!({ "error": "configure corporate sign-in before validating it" }),
                        ),
                    )
                        .into_response()
                })
            }) {
            Ok(connection) => connection,
            Err(response) => return response,
        };
        let revision = connection.current_revision();
        (connection, revision)
    };

    // Discovery is blocking network IO. The Workbench lock must not cross it;
    // authority and the exact connection revision are checked again before the
    // receipt is admitted.
    let result = validate_sso_configuration(connection).await;

    let mut guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if envelope.session_id == session.id
        && envelope.generation == session.generation
        && envelope.app == session.app
        && envelope.scope == session.scope
    {
        match replayed_command_response(&guard, &headers, &session, &envelope, &key) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    if let Err(error) = decide_gaugeapp_command(&session, &envelope) {
        return reject_gaugeapp(error);
    }
    let current_connection = match Org::rebuild_in(guard.store_ref(), &req_scope(&headers))
        .map_err(internal)
        .and_then(|org| {
            org.sso.ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "corporate sign-in changed during validation" })),
                )
                    .into_response()
            })
        }) {
        Ok(connection) => connection,
        Err(response) => return response,
    };
    if current_connection.current_revision() != validated_revision {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "corporate sign-in changed during validation; run validation again"
            })),
        )
            .into_response();
    }
    let mut plan = match plan_command(&guard, &headers, &envelope, extension_ref(&extension)) {
        Ok(plan) => plan,
        Err(response) => return response,
    };
    plan.transient_result = Some(result);
    finish_command(&mut guard, &headers, &session, &envelope, &key, None, plan).0
}

fn oidc_test_start_error(error: crate::auth_oidc::LoginError) -> Response {
    let (status, message) = match error {
        crate::auth_oidc::LoginError::NotConfigured => (
            StatusCode::CONFLICT,
            "the saved corporate sign-in connection is incomplete".to_owned(),
        ),
        crate::auth_oidc::LoginError::NoIssuer => (
            StatusCode::CONFLICT,
            "the saved OIDC connection has no issuer".to_owned(),
        ),
        crate::auth_oidc::LoginError::Discovery(message) => (
            StatusCode::BAD_GATEWAY,
            format!("OIDC discovery failed: {message}"),
        ),
        crate::auth_oidc::LoginError::Pkce(message) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("the browser test could not start: {message}"),
        ),
    };
    (status, Json(json!({ "error": message }))).into_response()
}

async fn submit_sso_browser_test_start(
    wb: SharedWorkbench,
    auth: Option<Extension<crate::auth_oidc::AuthShellState>>,
    saml_tests: Option<Extension<crate::identity_saml::SamlBrowserState>>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    headers: HeaderMap,
    envelope: GaugeAppCommandEnvelope,
    key: String,
) -> Response {
    let (connection, connection_revision, actor, store_scope, client_secret) = {
        let guard = wb.lock_unpoisoned();
        let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
            Ok(value) => value,
            Err(response) => return response,
        };
        if envelope.session_id == session.id
            && envelope.generation == session.generation
            && envelope.app == session.app
            && envelope.scope == session.scope
        {
            match replayed_command_response(&guard, &headers, &session, &envelope, &key) {
                Ok(Some(response)) => return response,
                Ok(None) => {}
                Err(response) => return response,
            }
        }
        let admission = match decide_gaugeapp_command(&session, &envelope) {
            Ok(value) => value,
            Err(error) => return reject_gaugeapp(error),
        };
        if admission.disposition != AdmissionDisposition::Apply {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "browser sign-in testing must be immediate" })),
            )
                .into_response();
        }
        if contains_secret(&envelope.payload) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    json!({ "error": "secret-bearing fields are forbidden in GaugeApp commands" }),
                ),
            )
                .into_response();
        }
        if let Err(response) = plan_command(&guard, &headers, &envelope, extension_ref(&extension))
        {
            return response;
        }
        let store_scope = req_scope(&headers);
        let org = match Org::rebuild_in(guard.store_ref(), &store_scope).map_err(internal) {
            Ok(org) => org,
            Err(response) => return response,
        };
        let Some(connection) = org.sso.clone() else {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "configure corporate sign-in before testing it" })),
            )
                .into_response();
        };
        let client_secret =
            match crate::auth_oidc::organization_oidc_client_secret(&guard, &org, &connection) {
                Ok(secret) => secret,
                Err(message) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({ "error": message })),
                    )
                        .into_response()
                }
            };
        let revision = connection.current_revision();
        (
            connection,
            revision,
            session.actor,
            store_scope,
            client_secret,
        )
    };

    // Re-establish the exact actor, tenant, capability epoch, and command
    // session before disclosing whether this deployment can run a browser
    // sign-in test. The GaugeApp session is correlation, not authority.
    let Some(Extension(auth)) = auth else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "corporate sign-in testing is unavailable" })),
        )
            .into_response();
    };
    let integration = crate::org_routes::enterprise_integration(&headers);
    let redirect_uri = integration["oidc"]["redirect_uri"]
        .as_str()
        .unwrap_or_default()
        .to_owned();

    let oidc_started = if connection.protocol == gaugedesk_app::org::SsoProtocol::Oidc {
        let scope =
            gaugedesk_env::var("OIDC_SCOPE").unwrap_or_else(|| "openid profile email".to_owned());
        let mapping = crate::auth_oidc::claim_mapping_for(&connection);
        let oidc_connection = connection.clone();
        let started = tokio::task::spawn_blocking(move || {
            let http = gaugedesk_app::net_http::HttpClient::new();
            crate::auth_oidc::start_login(&oidc_connection, &redirect_uri, &scope, mapping, &http)
        })
        .await;
        Some(match started {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => return oidc_test_start_error(error),
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "the browser-test start task failed" })),
                )
                    .into_response()
            }
        })
    } else {
        None
    };

    let mut guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if envelope.session_id == session.id
        && envelope.generation == session.generation
        && envelope.app == session.app
        && envelope.scope == session.scope
    {
        match replayed_command_response(&guard, &headers, &session, &envelope, &key) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    if let Err(error) = decide_gaugeapp_command(&session, &envelope) {
        return reject_gaugeapp(error);
    }
    let current = match Org::rebuild_in(guard.store_ref(), &store_scope)
        .map_err(internal)
        .and_then(|org| {
            org.sso.ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "corporate sign-in changed while the test started" })),
                )
                    .into_response()
            })
        }) {
        Ok(connection) => connection,
        Err(response) => return response,
    };
    if current.id != connection.id
        || current.protocol != connection.protocol
        || current.current_revision() != connection_revision
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "corporate sign-in changed while the test started; start again"
            })),
        )
            .into_response();
    }
    let context = crate::auth_oidc::PendingEnterpriseConnectionTest {
        id: gaugedesk_app::library::gen_id("ssotest"),
        store_scope: store_scope.clone(),
        actor: actor.clone(),
        connection_id: current.id.clone(),
        connection_revision: connection_revision.clone(),
    };
    let (protocol, authorize_url) = match current.protocol {
        gaugedesk_app::org::SsoProtocol::Oidc => {
            let (authorize_url, state, mut pending) =
                oidc_started.expect("the OIDC branch always prepares its authorize request");
            pending.client_secret = client_secret;
            pending.purpose =
                crate::auth_oidc::PendingAuthPurpose::EnterpriseConnectionTest(context);
            auth.pending_auth_mut()
                .begin(state, pending, Instant::now());
            ("oidc", authorize_url)
        }
        gaugedesk_app::org::SsoProtocol::Saml => {
            let Some(Extension(saml_tests)) = saml_tests else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "SAML browser testing is unavailable" })),
                )
                    .into_response();
            };
            let base = integration["base_url"].as_str().unwrap_or_default();
            let sp = integration["saml"]["sp_entity_id"]
                .as_str()
                .unwrap_or_default();
            let acs = integration["saml"]["acs_url"].as_str().unwrap_or_default();
            let launch = match saml_tests.begin_test(&current, context, base, sp, acs) {
                Ok(launch) => launch,
                Err(crate::identity_saml::SamlBrowserError::Metadata(error)) => {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({ "error": error.message(), "code": error.code() })),
                    )
                        .into_response()
                }
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "the SAML browser test could not start" })),
                    )
                        .into_response()
                }
            };
            ("saml", launch.launch_url)
        }
    };
    let mut plan = match plan_command(&guard, &headers, &envelope, extension_ref(&extension)) {
        Ok(plan) => plan,
        Err(response) => return response,
    };
    plan.transient_result = Some(json!({
        "kind": "enterprise-identity-browser-test-launch",
        "protocol": protocol,
        "connection_revision": connection_revision,
        "authorize_url": authorize_url,
    }));
    finish_command(&mut guard, &headers, &session, &envelope, &key, None, plan).0
}

/// Write-only custody boundary for an organization OIDC client secret.
///
/// The secret is deliberately outside the GaugeApp command envelope: the
/// envelope is retained in the idempotency receipt, proposal/change history,
/// and audit linkage, while this field is sealed before any durable append.
async fn submit_sso_credential(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    headers: HeaderMap,
    Json(body): Json<SsoCredentialRequest>,
) -> Response {
    let envelope = body.envelope;
    let key = match idempotency(&headers, &envelope.idempotency_key) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let setting = envelope.command_id == "enterprise-identity.connection.credential.set";
    let removing = envelope.command_id == "enterprise-identity.connection.credential.remove";
    if !setting && !removing {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "the credential route accepts only connection credential changes" })),
        )
            .into_response();
    }
    if contains_secret(&envelope.payload) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "the credential must not appear in the GaugeApp command envelope" })),
        )
            .into_response();
    }
    let requested: SsoCredentialPayload = match parse(&envelope.payload) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let secret =
        match (setting, body.secret) {
            (true, Some(secret)) if !secret.is_empty() && secret.len() <= 65_536 => Some(secret),
            (true, _) => return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "a non-empty client secret of at most 64 KiB is required" })),
            )
                .into_response(),
            (false, None) => None,
            (false, Some(_)) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "remove credential does not accept secret material" })),
                )
                    .into_response()
            }
        };

    let mut guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if envelope.session_id == session.id
        && envelope.generation == session.generation
        && envelope.app == session.app
        && envelope.scope == session.scope
    {
        match replayed_command_response(&guard, &headers, &session, &envelope, &key) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    let admission = match decide_gaugeapp_command(&session, &envelope) {
        Ok(value) => value,
        Err(error) => return reject_gaugeapp(error),
    };
    if admission.disposition != AdmissionDisposition::Apply {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "credential custody must be immediate" })),
        )
            .into_response();
    }

    let scope = req_scope(&headers);
    let org = match Org::rebuild_in(guard.store_ref(), &scope) {
        Ok(org) => org,
        Err(error) => return internal(error),
    };
    let mut connection =
        match org.sso.clone() {
            Some(connection) => connection,
            None => return (
                StatusCode::CONFLICT,
                Json(
                    json!({ "error": "configure corporate sign-in before adding a client secret" }),
                ),
            )
                .into_response(),
        };
    if connection.protocol != gaugedesk_app::org::SsoProtocol::Oidc {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "the current SAML binding uses IdP metadata and does not accept an SP signing secret" })),
        )
            .into_response();
    }
    if requested.connection_revision != connection.current_revision() {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "corporate sign-in changed; reload before changing its credential" })),
        )
            .into_response();
    }

    let (credential, configured) = if let Some(secret) = secret {
        let mut random = [0_u8; 32];
        if let Err(error) = getrandom::getrandom(&mut random) {
            return internal(error);
        }
        let credential_revision = hex::encode(random);
        connection.credential_revision = Some(credential_revision.clone());
        connection.seal_revision();
        let binding = connection
            .credential_binding()
            .expect("the new credential revision creates a binding");
        let Some(sealed_secret) = guard.seal_organization_secret(&scope, &binding, &secret) else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "organization credential encryption is unavailable" })),
            )
                .into_response();
        };
        (
            SsoCredentialRecord {
                id: ORG_ID.into(),
                op: RecordOp::Upsert,
                connection_id: connection.id.clone(),
                protocol: connection.protocol,
                credential_revision,
                sealed_secret,
            },
            true,
        )
    } else {
        if connection.credential_revision.is_none() || org.current_sso_credential().is_none() {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "this connection has no client secret to remove" })),
            )
                .into_response();
        }
        let current = org
            .current_sso_credential()
            .expect("checked current credential")
            .clone();
        connection.credential_revision = None;
        connection.seal_revision();
        (
            SsoCredentialRecord {
                op: RecordOp::Tombstone,
                sealed_secret: String::new(),
                ..current
            },
            false,
        )
    };
    let new_revision = connection.current_revision();
    let plan = MutationPlan {
        facts: match (
            fact(&scope, SSO_CREDENTIAL_KIND, &credential),
            fact(&scope, "sso", &connection),
        ) {
            (Ok(credential), Ok(connection)) => vec![credential, connection],
            (Err(response), _) | (_, Err(response)) => return response,
        },
        notices: vec![("sso", connection.id.clone(), "upsert")],
        audit_action: if configured {
            "enterprise-identity.connection.credential.set"
        } else {
            "enterprise-identity.connection.credential.remove"
        },
        audit_target: connection.id.clone(),
        transient_result: Some(json!({
            "kind": "enterprise-identity-credential",
            "connection_revision": new_revision,
            "client_secret_configured": configured,
        })),
    };
    finish_command(&mut guard, &headers, &session, &envelope, &key, None, plan).0
}

async fn submit_command(
    State(wb): State<SharedWorkbench>,
    auth: Option<Extension<crate::auth_oidc::AuthShellState>>,
    saml_tests: Option<Extension<crate::identity_saml::SamlBrowserState>>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    headers: HeaderMap,
    Json(envelope): Json<GaugeAppCommandEnvelope>,
) -> Response {
    let key = match idempotency(&headers, &envelope.idempotency_key) {
        Ok(key) => key,
        Err(response) => return response,
    };
    if envelope.command_id == "enterprise-identity.connection.validate" {
        return submit_sso_configuration_validation(wb, extension, headers, envelope, key).await;
    }
    if envelope.command_id == "enterprise-identity.test.begin" {
        return submit_sso_browser_test_start(
            wb, auth, saml_tests, extension, headers, envelope, key,
        )
        .await;
    }
    if matches!(
        envelope.command_id.as_str(),
        "enterprise-identity.connection.credential.set"
            | "enterprise-identity.connection.credential.remove"
    ) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "submit connection credentials through the write-only credential route" })),
        )
            .into_response();
    }
    let mut guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if envelope.session_id == session.id
        && envelope.generation == session.generation
        && envelope.app == session.app
        && envelope.scope == session.scope
    {
        match replayed_command_response(&guard, &headers, &session, &envelope, &key) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    let admission = match decide_gaugeapp_command(&session, &envelope) {
        Ok(value) => value,
        Err(error) => return reject_gaugeapp(error),
    };
    if extension_ref(&extension)
        .is_some_and(|extension| extension.requires_external_review(&envelope.command_id))
        && admission.command.review != ReviewPolicy::Human
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "external authority changes require human review" })),
        )
            .into_response();
    }
    if contains_secret(&envelope.payload) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "secret-bearing fields are forbidden in GaugeApp commands" })),
        )
            .into_response();
    }
    // Parse and validate the owning GaugeApp's closed command before a
    // proposal becomes durable. Review re-runs this planner against fresh state.
    if let Err(response) = plan_command(&guard, &headers, &envelope, extension_ref(&extension)) {
        return response;
    }
    match admission.disposition {
        AdmissionDisposition::Propose => {
            let change = proposed_change(&session, &envelope);
            let change_fact = match fact(&req_scope(&headers), GAUGEAPP_CHANGE_KIND, &change) {
                Ok(fact) => fact,
                Err(response) => return response,
            };
            let audit_link = gaugedesk_app::audit::link(
                &session.actor,
                "gaugeapp.proposal.proposed",
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
            (StatusCode::OK, Json(json!({ "receipt": gaugeapp_receipt(&session, &envelope, "proposed"), "proposal": change }))).into_response()
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
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
    key: &str,
    change: Option<GaugeAppChangeRecord>,
    extension: Option<&AdministrationGaugeAppExtensionHandle>,
) -> (Response, bool) {
    let plan = match plan_command(wb, headers, envelope, extension) {
        Ok(plan) => plan,
        Err(response) => return (response, false),
    };
    if extension.is_some_and(|extension| extension.requires_external_review(&envelope.command_id)) {
        return (
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "external review requires the durable handoff path" })),
            )
                .into_response(),
            false,
        );
    }
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
    } else if envelope.command_id == "project.create" {
        let value: ProjectCreatePayload = match parse(&envelope.payload) {
            Ok(value) => value,
            Err(response) => return (response, false),
        };
        let digest = sha256_hex(operation_key);
        let project_id = format!("proj-{}", &digest[..24]);
        match gaugedesk_app::library_routes::create_named_project(wb, &project_id, &value.name) {
            Ok(result) => AdministrationMutationPlan {
                transient_result: Some(json!({ "project": result })),
                audit_target: project_id,
                ..plan
            },
            Err(message) => {
                return (
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": message })),
                    )
                        .into_response(),
                    false,
                )
            }
        }
    } else {
        plan
    };
    finish_command(wb, headers, session, envelope, key, change, plan)
}

fn finish_command(
    wb: &mut Workbench,
    headers: &HeaderMap,
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
    key: &str,
    change: Option<GaugeAppChangeRecord>,
    plan: MutationPlan,
) -> (Response, bool) {
    finish_command_in(
        wb,
        headers,
        session,
        envelope,
        key,
        change,
        plan,
        &command_scope(headers),
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_command_in(
    wb: &mut Workbench,
    headers: &HeaderMap,
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
    key: &str,
    change: Option<GaugeAppChangeRecord>,
    plan: MutationPlan,
    receipt_scope: &str,
) -> (Response, bool) {
    let mut applied_change = change.unwrap_or_else(|| proposed_change(session, envelope));
    applied_change.status = GaugeAppChangeStatus::Applied;
    applied_change.reviewed_by = Some(session.actor.clone());
    let mut facts = plan.facts.clone();
    let change_fact = match fact(&req_scope(headers), GAUGEAPP_CHANGE_KIND, &applied_change) {
        Ok(fact) => fact,
        Err(response) => return (response, false),
    };
    facts.push(change_fact);
    let audit_link =
        gaugedesk_app::audit::link(&session.actor, plan.audit_action, &plan.audit_target);
    let store_scope = req_scope(headers);
    let audit_scope = gaugedesk_app::audit::scope_for(&store_scope);
    let result = match wb.store_mut().admit_record_facts_chained(
        receipt_scope,
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
    if envelope.command_id == "organization.delete" {
        // Each person's Administration/Commercial transcript has its own key,
        // outside the parent tenant scope. A retry repeats this scan before the
        // parent key is destroyed, so an interrupted erasure never silently
        // strands readable child content.
        if let Err(error) =
            gaugedesk_app::gaugeapp_agent::crypto_erase_gaugeapp_agent_threads_for_tenant(
                wb,
                &session.scope.id,
            )
        {
            return (store_error(error), false);
        }
        // The command tombstoned every live organization authority in the
        // transaction above. Destroying the parent key completes organization
        // erasure and is idempotent on retries and unencrypted local profiles.
        let _ = wb.crypto_erase_content(&store_scope);
    }
    let freshly_applied = !result.replayed;
    ((StatusCode::OK, Json(json!({
        "receipt": gaugeapp_receipt(session, envelope, "applied"),
        "proposal": applied_change,
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

async fn submit_proposal(
    State(wb): State<SharedWorkbench>,
    auth: Option<Extension<crate::auth_oidc::AuthShellState>>,
    saml_tests: Option<Extension<crate::identity_saml::SamlBrowserState>>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    headers: HeaderMap,
    Json(envelope): Json<GaugeAppCommandEnvelope>,
) -> Response {
    if envelope.client != GaugeAppClient::Agent {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "proposal preparation is reserved for the GaugeApp agent" })),
        )
            .into_response();
    }
    submit_command(
        State(wb),
        auth,
        saml_tests,
        extension,
        headers,
        Json(envelope),
    )
    .await
}

async fn list_changes(
    State(wb): State<SharedWorkbench>,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    Query(query): Query<SessionQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if query.session != session.id
        || query.generation != session.generation
        || query.scope != session.scope.id
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "GaugeApp session is stale or cross-scope" })),
        )
            .into_response();
    }
    let changes = match fold_gaugeapp_changes(guard.store_ref(), &req_scope(&headers)) {
        Ok(changes) => changes,
        Err(error) => return internal(error),
    };
    let recovery_only = guard
        .admit_sso_recovery(bearer(&headers), &req_scope(&headers))
        .is_ok();
    let values = changes
        .into_values()
        .filter(|change| {
            change.app == GAUGEAPP
                && change.scope == session.scope
                && (!recovery_only
                    || change.command_id == "enterprise-identity.enforcement.disable")
        })
        .collect::<Vec<_>>();
    (StatusCode::OK, Json(json!({ "proposals": values }))).into_response()
}

#[derive(Deserialize)]
struct ReviewBody {
    session_id: String,
    generation: String,
    app: GaugeAppKind,
    scope: GaugeAppScope,
    decision: String,
    #[serde(default = "web_client")]
    client: GaugeAppClient,
    #[serde(default)]
    authorization_proof: Option<String>,
}
fn web_client() -> GaugeAppClient {
    GaugeAppClient::Web
}

async fn verify_domain_review_evidence(
    wb: &SharedWorkbench,
    headers: &HeaderMap,
    id: &str,
    body: &ReviewBody,
    extension: Option<&AdministrationGaugeAppExtensionHandle>,
) -> Result<(), Response> {
    if body.decision != "accept" {
        return Ok(());
    }
    let domain = {
        let guard = wb.lock_unpoisoned();
        let (session, _) = build_session(&guard, headers, extension)?;
        if body.session_id != session.id
            || body.generation != session.generation
            || body.app != GAUGEAPP
            || body.scope != session.scope
        {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "GaugeApp session is stale or cross-scope" })),
            )
                .into_response());
        }
        let changes =
            fold_gaugeapp_changes(guard.store_ref(), &req_scope(headers)).map_err(internal)?;
        let Some(change) = changes.get(id) else {
            return Ok(());
        };
        if change.status != GaugeAppChangeStatus::Proposed
            || change.command_id != "organization.domain.verify"
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
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    auth: Option<Extension<gaugedesk_app::auth_oidc::AuthShellState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ReviewBody>,
) -> Response {
    let key = match gaugedesk_app::command_idempotency::caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    if let Err(response) =
        verify_domain_review_evidence(&wb, &headers, &id, &body, extension_ref(&extension)).await
    {
        return response;
    }
    match prepare_review(wb.clone(), extension, auth, id, headers.clone(), body, key) {
        Ok(response) => response,
        Err(job) => external_review::execute(wb, headers, job).await,
    }
}

// Keep the state guard in this synchronous phase; no network await can carry it.
fn prepare_review(
    wb: SharedWorkbench,
    extension: Option<Extension<AdministrationGaugeAppExtensionHandle>>,
    auth: Option<Extension<gaugedesk_app::auth_oidc::AuthShellState>>,
    id: String,
    headers: HeaderMap,
    body: ReviewBody,
    key: String,
) -> Result<Response, external_review::ReviewJob> {
    if body.client == GaugeAppClient::Agent {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "management reviews require a human client" })),
        )
            .into_response());
    }
    let mut guard = wb.lock_unpoisoned();
    let (session, _) = match build_session(&guard, &headers, extension_ref(&extension)) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    if body.session_id != session.id
        || body.generation != session.generation
        || body.app != GAUGEAPP
        || body.scope != session.scope
    {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "GaugeApp session is stale or cross-scope" })),
        )
            .into_response());
    }
    let changes = match fold_gaugeapp_changes(guard.store_ref(), &req_scope(&headers)) {
        Ok(changes) => changes,
        Err(error) => return Ok(internal(error)),
    };
    let Some(mut change) = changes.get(&id).cloned() else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such GaugeApp proposal" })),
        )
            .into_response());
    };
    let envelope = GaugeAppCommandEnvelope {
        session_id: session.id.clone(),
        generation: session.generation.clone(),
        app: GAUGEAPP,
        scope: session.scope.clone(),
        page_id: change.page_id.clone(),
        command_id: change.command_id.clone(),
        expected_basis: change.expected_basis.clone(),
        idempotency_key: key.clone(),
        payload: change.payload.clone(),
        client: body.client,
    };
    if let Some(recovery) = external_review::recover_if_approved(
        &mut guard,
        &headers,
        &session,
        &change,
        &body,
        extension_ref(&extension),
    ) {
        drop(guard);
        return match recovery {
            Ok(job) => Err(job),
            Err(response) => Ok(response),
        };
    }
    let external = extension_ref(&extension)
        .is_some_and(|extension| extension.requires_external_review(&change.command_id));
    let claim_key = external_review::claim_key(&change.id);
    let claim_snapshot = serde_json::to_string(&json!({ "proposal": id, "decision": body.decision, "actor": session.actor, "command": envelope })).expect("review metadata serializes");
    let terminal_claim = external.then_some(gaugedesk_store::RecordCommandClaim {
        key: &claim_key,
        snapshot: &claim_snapshot,
    });
    if external
        && (change.app != session.app
            || change.scope != session.scope
            || !session.commands.iter().any(|command| {
                command.id == change.command_id
                    && session.capabilities.contains(&command.capability)
            }))
    {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "current capability is required to review this change" })),
        )
            .into_response());
    }
    if change.status != GaugeAppChangeStatus::Proposed {
        let expected_snapshot = if body.decision == "accept" {
            snapshot(&envelope)
        } else {
            serde_json::to_string(&json!({ "proposal": id, "decision": body.decision })).unwrap()
        };
        if let Ok(Some(record)) = guard
            .store_ref()
            .command_for_key(&command_scope(&headers), &key)
        {
            if record.status == "applied" && record.snapshot_json == expected_snapshot {
                let status = match change.status {
                    GaugeAppChangeStatus::Applied => "applied",
                    GaugeAppChangeStatus::Rejected => "rejected",
                    GaugeAppChangeStatus::Conflict => "conflict",
                    GaugeAppChangeStatus::Proposed | GaugeAppChangeStatus::Applying => {
                        unreachable!()
                    }
                };
                let code = if change.status == GaugeAppChangeStatus::Conflict {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::OK
                };
                return Ok((
                    code,
                    Json(json!({ "receipt": gaugeapp_receipt(&session, &envelope, status), "proposal": change })),
                )
                    .into_response());
            }
        }
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({ "error": "GaugeApp proposal is already terminal" })),
        )
            .into_response());
    }
    if body.decision == "reject" {
        change.status = GaugeAppChangeStatus::Rejected;
        change.reviewed_by = Some(session.actor.clone());
        let change_fact = match fact(&req_scope(&headers), GAUGEAPP_CHANGE_KIND, &change) {
            Ok(fact) => fact,
            Err(response) => return Ok(response),
        };
        let audit_link =
            gaugedesk_app::audit::link(&session.actor, "gaugeapp.proposal.rejected", &id);
        let store_scope = req_scope(&headers);
        let audit_scope = gaugedesk_app::audit::scope_for(&store_scope);
        let result = match guard.store_mut().admit_record_facts_with_claims(
            &command_scope(&headers),
            &key,
            &serde_json::to_string(&json!({ "proposal": id, "decision": "reject" })).unwrap(),
            &[change_fact],
            Some(gaugedesk_app::audit::chained_in(&audit_scope, &audit_link)),
            terminal_claim.as_slice(),
        ) {
            Ok(result) => result,
            Err(error) => return Ok(store_error(error)),
        };
        if let Some(entry) =
            gaugedesk_app::audit::committed_entry(result.chained_payload.as_deref())
        {
            gaugedesk_app::audit::finish_committed_in(&mut guard, &store_scope, &entry);
        }
        return Ok((StatusCode::OK, Json(json!({ "receipt": gaugeapp_receipt(&session, &envelope, "rejected"), "proposal": change }))).into_response());
    }
    if body.decision != "accept" {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "review decision must be accept or reject" })),
        )
            .into_response());
    }
    let local_project_receipt_recovery = if !external && envelope.command_id == "project.create" {
        serde_json::from_value::<ProjectCreatePayload>(envelope.payload.clone())
            .ok()
            .is_some_and(|payload| {
                let digest = sha256_hex(&change.id);
                gaugedesk_app::library_routes::named_project_matches(
                    &guard,
                    &format!("proj-{}", &digest[..24]),
                    &payload.name,
                )
            })
    } else {
        false
    };
    if let Err(error) = decide_reviewed_gaugeapp_command(&session, &envelope) {
        if matches!(error, GaugeAppRejection::StaleBasis) && local_project_receipt_recovery {
            // The exact deterministic Home operation already committed, but
            // the command receipt did not. Resume the same operation below;
            // every other stale proposal still conflicts normally.
        } else if matches!(error, GaugeAppRejection::StaleBasis) {
            change.status = GaugeAppChangeStatus::Conflict;
            change.reviewed_by = Some(session.actor.clone());
            let conflict_fact = match fact(&req_scope(&headers), GAUGEAPP_CHANGE_KIND, &change) {
                Ok(fact) => fact,
                Err(response) => return Ok(response),
            };
            let audit_link =
                gaugedesk_app::audit::link(&session.actor, "gaugeapp.proposal.conflict", &id);
            let store_scope = req_scope(&headers);
            let audit_scope = gaugedesk_app::audit::scope_for(&store_scope);
            let result = match guard.store_mut().admit_record_facts_with_claims(
                &command_scope(&headers),
                &key,
                &snapshot(&envelope),
                &[conflict_fact],
                Some(gaugedesk_app::audit::chained_in(&audit_scope, &audit_link)),
                terminal_claim.as_slice(),
            ) {
                Ok(result) => result,
                Err(error) => return Ok(store_error(error)),
            };
            if let Some(entry) =
                gaugedesk_app::audit::committed_entry(result.chained_payload.as_deref())
            {
                gaugedesk_app::audit::finish_committed_in(&mut guard, &store_scope, &entry);
            }
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "receipt": gaugeapp_receipt(&session, &envelope, "conflict"),
                    "proposal": change,
                    "error": error.message(),
                    "rejection": error,
                })),
            )
                .into_response());
        }
        return Ok(reject_gaugeapp(error));
    }
    if requires_fresh_authorization(&envelope.command_id) {
        let Some(runtime) = auth.and_then(|Extension(auth)| auth.account_auth()) else {
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "fresh account authorization is unavailable" })),
            )
                .into_response());
        };
        let proof = body.authorization_proof.as_deref().unwrap_or_default();
        if !runtime.consume_authorization_proof(
            proof,
            &session.actor,
            &envelope.command_id,
            gaugedesk_app::account::session_now_ms() / 1_000,
        ) {
            return Ok((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "confirm this operation with a current account passkey"
                })),
            )
                .into_response());
        }
    }
    // The review intent gets its own idempotency key, while the applied change
    // retains the original proposal identity.
    if let Some(extension) = extension_ref(&extension)
        .filter(|extension| extension.requires_external_review(&envelope.command_id))
    {
        let plan = match plan_command(&guard, &headers, &envelope, Some(extension)) {
            Ok(plan) => plan,
            Err(response) => return Ok(response),
        };
        let prepared = external_review::begin(
            &mut guard, &headers, &session, &envelope, &key, &change, extension, plan,
        );
        drop(guard);
        return match prepared {
            Ok(job) => Err(job),
            Err(response) => Ok(response),
        };
    }
    let sso = if envelope.command_id == "enterprise-identity.connection.set" {
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
    Ok(response)
}

fn requires_fresh_authorization(command_id: &str) -> bool {
    matches!(
        command_id,
        "organization.ownership.transfer"
            | "organization.delete"
            | "enterprise-identity.owner-subject.link"
            | "enterprise-identity.enforcement.enable"
            | "enterprise-identity.enforcement.disable"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;

    /// A failed turn must leave a server-side record of *why*, and must not
    /// turn the model's own output into one.
    ///
    /// Two production canary runs failed with `status=502` and nothing in the
    /// log saying why. The cause was already in hand — `Provider` carries it —
    /// and was only ever sent to the client. This pins both halves: the
    /// operational variants map to statuses an operator can act on, and the
    /// variants carrying generated content are logged without it.
    #[test]
    fn a_failed_turn_reports_an_operational_cause_and_never_the_generated_content() {
        let generated = "the person's own words and the model's reply";

        // Operational causes: the detail is the service's own and is loggable.
        for (error, expected) in [
            (
                GaugeAppAgentError::Provider("provider response timed out".into()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                GaugeAppAgentError::Credential("no admitted credential".into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                GaugeAppAgentError::Store("transcript append failed".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            assert_eq!(agent_error(error).status(), expected);
        }

        // Generated content: still classified, still refused, never widened
        // into an operational status that would read as a service fault.
        assert_eq!(
            agent_error(GaugeAppAgentError::InvalidOutput(generated.into())).status(),
            StatusCode::UNPROCESSABLE_ENTITY,
        );

        // Ordinary outcomes are not faults at all.
        assert_eq!(
            agent_error(GaugeAppAgentError::Interrupted)
                .status()
                .as_u16(),
            499,
        );
        assert_eq!(
            agent_error(GaugeAppAgentError::Busy).status(),
            StatusCode::CONFLICT,
        );
        assert_eq!(
            agent_error(GaugeAppAgentError::NoModelAccess).status(),
            StatusCode::CONFLICT,
        );
    }
    use tower::ServiceExt;

    use gaugedesk_app::account_auth::{
        append_facts as append_account_auth_facts, AccountAuthFact, ExternalSubjectKind,
        ExternalSubjectRecord, RecoveryBatchRecord, RecoveryBatchStatus, RecoveryCodeRecord,
        WebAuthnMethodRecord,
    };
    use gaugedesk_app::identity::LoopbackIdentityProvider;
    use gaugedesk_app::org::{
        MembershipRecord, OrgRecord, SsoBrowserTestRecord, ORG_SCOPE, SSO_BROWSER_TEST_KIND,
    };
    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::ids::AuthorityId;
    use gaugedesk_store::Store;
    use gaugedesk_workspace::Instance;

    fn test_app_as_in(role: &str, tenant_id: &str) -> (tempfile::TempDir, SharedWorkbench, Router) {
        let dir = tempfile::tempdir().unwrap();
        let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let idp = LoopbackIdentityProvider::new()
            .enroll(
                "owner-token",
                AuthorityId::new("authority:owner"),
                AuthorityAttributes::default(),
            )
            .enroll(
                "owner-token-new",
                AuthorityId::new("authority:owner"),
                AuthorityAttributes::default(),
            )
            .enroll(
                "outsider-token",
                AuthorityId::new("authority:outsider"),
                AuthorityAttributes::default(),
            );
        let vault = Arc::new(gaugedesk_app::content_vault::ContentVault::new(
            dir.path().join("content-keys"),
            Box::new(gaugedesk_app::at_rest::LoopbackKeyWrap::new([17_u8; 32])),
        ));
        let mut wb = Workbench::with_target(
            "environment-test",
            instance,
            Store::open_in_memory().unwrap().with_codec(vault.clone()),
        )
        .with_identity_provider(Arc::new(idp))
        .with_content_vault(vault);
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
            .append_record(
                &gaugedesk_app::org::tenant_scope(tenant_id),
                "membership",
                &serde_json::to_string(&owner).unwrap(),
            )
            .unwrap();
        let shared = Arc::new(Mutex::new(wb));
        let app = routes().with_state(shared.clone());
        (dir, shared, app)
    }

    fn test_app_as(role: &str) -> (tempfile::TempDir, SharedWorkbench, Router) {
        test_app_as_in(role, ORG_ID)
    }

    fn test_app() -> (tempfile::TempDir, SharedWorkbench, Router) {
        test_app_as("owner")
    }

    fn persistent_test_app(
        root: &std::path::Path,
        seed_membership: bool,
    ) -> (SharedWorkbench, Router) {
        let shared = gaugedesk_app::open_workbench(root).unwrap();
        let idp = LoopbackIdentityProvider::new().enroll(
            "owner-token",
            AuthorityId::new("authority:owner"),
            AuthorityAttributes::default(),
        );
        {
            let mut guard = shared.lock_unpoisoned();
            guard.set_identity_provider(Some(Arc::new(idp)));
            if seed_membership {
                let owner = MembershipRecord {
                    id: "owner".into(),
                    op: RecordOp::Upsert,
                    org_id: ORG_ID.into(),
                    authority: "authority:owner".into(),
                    email: "owner@example.test".into(),
                    role: "owner".into(),
                    status: MembershipStatus::Active,
                    managed_by_scim: false,
                    team: None,
                };
                guard
                    .store_mut()
                    .append_record(
                        &gaugedesk_app::org::tenant_scope(ORG_ID),
                        "membership",
                        &serde_json::to_string(&owner).unwrap(),
                    )
                    .unwrap();
            }
        }
        let app = routes().with_state(shared.clone());
        (shared, app)
    }

    struct NoopEmailSender;

    impl gaugedesk_app::account_auth_ceremony::EmailChallengeSender for NoopEmailSender {
        fn send_verification(
            &self,
            _email: &str,
            _code: &str,
            _expires_in: u64,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    fn test_app_with_account_authorization_in(
        tenant_id: &str,
    ) -> (
        tempfile::TempDir,
        SharedWorkbench,
        Router,
        Arc<gaugedesk_app::account_auth_ceremony::AccountAuthRuntime>,
    ) {
        let (dir, shared, _app) = test_app_as_in("owner", tenant_id);
        let config = gaugedesk_app::account_auth_ceremony::AccountAuthConfig::new(
            "localhost",
            "GaugeDesk test",
            "http://localhost",
        )
        .unwrap();
        let runtime = Arc::new(
            gaugedesk_app::account_auth_ceremony::AccountAuthRuntime::new(
                config,
                Arc::new(NoopEmailSender),
            )
            .unwrap(),
        );
        let auth =
            gaugedesk_app::auth_oidc::AuthShellState::default().with_account_auth(runtime.clone());
        let app = routes().layer(Extension(auth)).with_state(shared.clone());
        (dir, shared, app, runtime)
    }

    fn test_app_with_account_authorization() -> (
        tempfile::TempDir,
        SharedWorkbench,
        Router,
        Arc<gaugedesk_app::account_auth_ceremony::AccountAuthRuntime>,
    ) {
        test_app_with_account_authorization_in(ORG_ID)
    }

    include!("gaugeapp_external_review_tests.rs");

    struct TestAdministrationExtension;

    struct TestModelProviderExtension(Arc<Mutex<Value>>);
    impl AdministrationGaugeAppExtension for TestModelProviderExtension {
        fn project(
            &self,
            _wb: &Workbench,
            _tenant_id: &str,
            _store_scope: &str,
            _actor: &str,
            capabilities: &[Capability],
        ) -> Result<Vec<AdministrationExtensionPage>, AdministrationExtensionError> {
            if !capabilities.contains(&Capability::ConfigureSecurity) {
                return Ok(Vec::new());
            }
            Ok(vec![AdministrationExtensionPage {
                id: "model-providers".into(),
                read_model: "OrganizationModelProvidersPageV1".into(),
                version: 1,
                freshness: "authority-live".into(),
                model: self.0.lock().unwrap().clone(),
                commands: Vec::new(),
            }])
        }
        fn plan(
            &self,
            _wb: &Workbench,
            _tenant_id: &str,
            _store_scope: &str,
            _actor: &str,
            _command: &GaugeAppCommandEnvelope,
        ) -> Result<Option<AdministrationMutationPlan>, AdministrationExtensionError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn model_provider_http_response_checks_scope_and_schema_before_disclosure() {
        let (_dir, shared, _app) = test_app();
        let mut fixture: Value = serde_json::from_str(include_str!(
            "../../../crates/app/src/model_provider_management/projection/page.fixture.json"
        ))
        .unwrap();
        fixture["binding"]["organization"] = json!(ORG_ID);
        let model = Arc::new(Mutex::new(fixture.clone()));
        let extension: AdministrationGaugeAppExtensionHandle =
            Arc::new(TestModelProviderExtension(model.clone()));
        let app = routes().layer(Extension(extension)).with_state(shared);
        let session = open(&app).await;
        let uri = format!(
            "/gaugeapps/administration/pages/model-providers?session={}&generation={}&scope={}",
            session["id"].as_str().unwrap(),
            session["generation"].as_str().unwrap(),
            session["scope"]["id"].as_str().unwrap()
        );
        let (status, response) = request(&app, Method::GET, &uri, Value::Null, None).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["page"]["model"], fixture);
        for foreign in [true, false] {
            let mut changed = fixture.clone();
            if foreign {
                changed["binding"]["organization"] =
                    json!("must-not-disclose-foreign-organization");
            } else {
                changed["connections"][0]["secret"] = json!("must-not-disclose-custody-value");
            }
            *model.lock().unwrap() = changed;
            let (status, response) = request(&app, Method::GET, &uri, Value::Null, None).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(!response.to_string().contains("must-not-disclose"));
            assert!(!response.to_string().contains("Team provider"));
        }
    }

    impl AdministrationGaugeAppExtension for TestAdministrationExtension {
        fn project(
            &self,
            wb: &Workbench,
            _tenant_id: &str,
            store_scope: &str,
            _actor: &str,
            capabilities: &[Capability],
        ) -> Result<Vec<AdministrationExtensionPage>, AdministrationExtensionError> {
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
            Ok(vec![AdministrationExtensionPage {
                id: "backups".into(),
                read_model: "BackupsPageV1".into(),
                version: 1,
                freshness: "live".into(),
                model: json!({ "records": rows }),
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
            command: &GaugeAppCommandEnvelope,
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
        request_in_tenant(app, method, uri, body, key, None).await
    }

    async fn request_in_tenant(
        app: &Router,
        method: Method,
        uri: &str,
        body: Value,
        key: Option<&str>,
        tenant_id: Option<&str>,
    ) -> (StatusCode, Value) {
        request_with_bearer(app, method, uri, body, key, tenant_id, "owner-token").await
    }

    async fn request_with_bearer(
        app: &Router,
        method: Method,
        uri: &str,
        body: Value,
        key: Option<&str>,
        tenant_id: Option<&str>,
        bearer: &str,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .header("x-gaugedesk-client-version", "0.4.5")
            .header("x-gaugedesk-client-protocol", "7")
            .header("x-gaugedesk-client-channel", "stable")
            .header("x-gaugedesk-client-platform", "GaugeDesk desktop");
        if let Some(tenant_id) = tenant_id {
            builder = builder.header("x-gaugewright-tenant", tenant_id);
        }
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

    async fn open_with_bearer(app: &Router, bearer: &str) -> Value {
        let (status, body) = request_with_bearer(
            app,
            Method::POST,
            "/gaugeapps/administration/sessions",
            json!({}),
            None,
            None,
            bearer,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["session"].clone()
    }

    async fn open(app: &Router) -> Value {
        open_in_tenant(app, None).await
    }

    #[tokio::test]
    async fn every_administration_command_rechecks_tenant_membership_and_role() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;

        let request_for = |command: &CommandPolicy, key: &str| {
            let basis = session["pages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|page| page["id"] == command.page)
                .unwrap()["resource_basis"]
                .clone();
            let payload = if matches!(
                command.id,
                "enterprise-identity.connection.credential.set"
                    | "enterprise-identity.connection.credential.remove"
            ) {
                json!({ "connection_revision": "revision:not-examined" })
            } else {
                json!({})
            };
            let envelope = json!({
                "session_id": session["id"],
                "generation": session["generation"],
                "app": session["app"],
                "scope": session["scope"],
                "page_id": command.page,
                "command_id": command.id,
                "expected_basis": basis,
                "idempotency_key": key,
                // Admission must fail before ordinary command payload parsing.
                "payload": payload,
                "client": "web",
            });
            if command.id == "enterprise-identity.connection.credential.set" {
                (
                    "/gaugeapps/administration/enterprise-identity/credential",
                    json!({ "envelope": envelope, "secret": "must-not-be-read" }),
                )
            } else if command.id == "enterprise-identity.connection.credential.remove" {
                (
                    "/gaugeapps/administration/enterprise-identity/credential",
                    json!({ "envelope": envelope }),
                )
            } else {
                ("/gaugeapps/administration/commands", envelope)
            }
        };

        for (index, command) in COMMANDS.iter().enumerate() {
            let key = format!("administration-cross-tenant-{index}");
            let (path, body) = request_for(command, &key);
            let (status, response) = request_with_bearer(
                &app,
                Method::POST,
                path,
                body,
                Some(&key),
                Some("organization:foreign"),
                "owner-token",
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{} crossed tenant scope: {response}",
                command.id
            );

            let key = format!("administration-non-member-{index}");
            let (path, body) = request_for(command, &key);
            let (status, response) = request_with_bearer(
                &app,
                Method::POST,
                path,
                body,
                Some(&key),
                None,
                "outsider-token",
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{} admitted a non-member: {response}",
                command.id
            );
        }

        // The session is only correlation. A live role change must withdraw
        // every Administration command without waiting for the client to
        // reopen its App or refresh its cached menu.
        let demoted = MembershipRecord {
            id: "owner".into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: "authority:owner".into(),
            email: "owner@example.test".into(),
            role: "member".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        };
        shared
            .lock_unpoisoned()
            .store_mut()
            .append_record(
                &gaugedesk_app::org::tenant_scope(ORG_ID),
                "membership",
                &serde_json::to_string(&demoted).unwrap(),
            )
            .unwrap();

        for (index, command) in COMMANDS.iter().enumerate() {
            let key = format!("administration-demoted-role-{index}");
            let (path, body) = request_for(command, &key);
            let (status, response) = request_with_bearer(
                &app,
                Method::POST,
                path,
                body,
                Some(&key),
                None,
                "owner-token",
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{} survived role revocation: {response}",
                command.id
            );
        }
    }

    async fn open_in_tenant(app: &Router, tenant_id: Option<&str>) -> Value {
        let (status, value) = request_in_tenant(
            app,
            Method::POST,
            "/gaugeapps/administration/sessions",
            json!({}),
            None,
            tenant_id,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value["session"].clone()
    }

    async fn read_page_json(app: &Router, session: &Value, page_id: &str) -> Value {
        let (status, value) = request(
            app,
            Method::GET,
            &format!(
                "/gaugeapps/administration/pages/{page_id}?session={}&generation={}&scope={}",
                session["id"].as_str().unwrap(),
                session["generation"].as_str().unwrap(),
                session["scope"]["id"].as_str().unwrap(),
            ),
            Value::Null,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value
    }

    async fn apply_reviewed(
        app: &Router,
        session: &Value,
        page_id: &str,
        command_id: &str,
        payload: Value,
        key: &str,
    ) -> Value {
        apply_reviewed_with_proof(app, session, page_id, command_id, payload, key, None).await
    }

    async fn apply_reviewed_with_proof(
        app: &Router,
        session: &Value,
        page_id: &str,
        command_id: &str,
        payload: Value,
        key: &str,
        authorization_proof: Option<&str>,
    ) -> Value {
        let page = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == page_id)
            .unwrap();
        let envelope = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "page_id": page_id, "command_id": command_id,
            "expected_basis": page["resource_basis"], "idempotency_key": format!("{key}-proposal"),
            "payload": payload, "client": "web",
        });
        let (status, proposed) = request(
            app,
            Method::POST,
            "/gaugeapps/administration/commands",
            envelope,
            Some(&format!("{key}-proposal")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        let review_uri = format!(
            "/gaugeapps/administration/proposals/{}/review",
            proposed["proposal"]["id"].as_str().unwrap()
        );
        let mut review = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "decision": "accept", "client": "web",
        });
        if let Some(proof) = authorization_proof {
            review["authorization_proof"] = json!(proof);
        }
        let (status, applied) = request(
            app,
            Method::POST,
            &review_uri,
            review,
            Some(&format!("{key}-review")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        applied
    }

    #[tokio::test]
    async fn personal_tenant_discovers_only_its_real_administration_shape() {
        let tenant_id = "personal:owner";
        let (_dir, _shared, app) = test_app_as_in("owner", tenant_id);
        let session = open_in_tenant(&app, Some(tenant_id)).await;
        let page_ids = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|page| page["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(page_ids, vec!["project-hosts", "billing"]);
        let command_ids = session["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(command_ids
            .iter()
            .all(|id| id.starts_with("machine.") || id.starts_with("billing.")));
    }

    #[tokio::test]
    async fn composition_extension_uses_the_same_session_review_and_receipt_path() {
        let (_dir, shared, _app) = test_app();
        let extension: AdministrationGaugeAppExtensionHandle =
            Arc::new(TestAdministrationExtension);
        let app = routes()
            .layer(Extension(extension))
            .with_state(shared.clone());
        let session = open(&app).await;
        let backups = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "backups")
            .unwrap();
        assert_eq!(backups["commands"], json!(["backup.enable"]));
        let envelope = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "page_id": "backups", "command_id": "backup.enable",
            "expected_basis": backups["resource_basis"], "idempotency_key": "extension-proposal",
            "payload": { "schedule_days": 1 }, "client": "web",
        });
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
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
            "/gaugeapps/administration/proposals/{}/review",
            proposed["proposal"]["id"].as_str().unwrap()
        );
        let review = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "decision": "accept", "client": "web",
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
        let contract: Value = serde_json::from_str(include_str!(
            "../../../contracts/gaugeapps-page-actions.json"
        ))
        .unwrap();
        let accepted = contract["gaugeApps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|app| app["id"] == "administration")
            .unwrap()["pages"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|page| page["actions"].as_array().unwrap())
            .map(|action| action["operation"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        for id in &ids {
            assert!(
                accepted.contains(id),
                "Administration advertises unaccepted command {id}"
            );
        }
        let inventory = administration_route_inventory();
        assert_eq!(inventory.len(), COMMANDS.len());
        for command in COMMANDS {
            assert!(PAGES.iter().any(|page| page.id == command.page));
            assert_eq!(
                command.review == ReviewPolicy::Immediate,
                matches!(
                    command.id,
                    "enterprise-identity.connection.validate"
                        | "enterprise-identity.test.begin"
                        | "enterprise-identity.connection.credential.set"
                        | "enterprise-identity.connection.credential.remove"
                )
            );
        }
        for route in inventory {
            assert_eq!(
                route.authentication,
                "enterprise authenticated actor + admitted GaugeApp session"
            );
            assert_eq!(
                route.scope_policy,
                "request tenant scope must exactly match session scope"
            );
            assert_eq!(route.submit_method, "POST");
            if matches!(
                route.command_id,
                "enterprise-identity.connection.credential.set"
                    | "enterprise-identity.connection.credential.remove"
            ) {
                assert_eq!(
                    route.submit_path,
                    "/gaugeapps/administration/enterprise-identity/credential"
                );
            } else {
                assert_eq!(route.submit_path, "/gaugeapps/administration/commands");
            }
            assert_eq!(route.review_method, "POST");
            assert_eq!(
                route.review_path,
                "/gaugeapps/administration/proposals/:id/review"
            );
            assert!(route.expected_basis_required);
            assert!(route.idempotency_required);
            assert_eq!(
                route.capability_rechecked_on_review,
                route.review == "human"
            );
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
    fn administration_exposes_exactly_the_twelve_accepted_pages() {
        assert_eq!(PAGES.len(), 12);
        let ids = PAGES.iter().map(|page| page.id).collect::<BTreeSet<_>>();
        assert!(!ids.contains("overview"));
        assert!(!ids.contains("audit"));
        assert_eq!(ids.len(), PAGES.len());
    }

    #[tokio::test]
    async fn organization_policy_uses_the_accepted_fixed_controls_and_round_trips() {
        let (_dir, _shared, app) = test_app();
        let session = open(&app).await;
        let policy = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization-policy")
            .unwrap();
        assert_eq!(policy["commands"], json!(["organization-policy.set"]));
        assert!(!session["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|command| command["id"] == "policy.update"));

        let payload = json!({
            "resource": { "rules": [
                { "when": { "ClassificationIs": "pii" }, "require": "RequireAttestedCeiling" },
                { "when": { "ClassificationIs": "pii" }, "require": "RequireResourceRegionMatchesActor" },
                { "when": { "ActorHasRole": "viewer" }, "require": { "DenyAction": "export" } },
                { "when": "Always", "require": "RequireResourceRegionMatchesActor" }
            ] },
            "security": {
                "require_mfa": false,
                "session_lifetime_secs": 28_800,
                "idle_timeout_secs": 1_800,
                "residency_region": null,
                "audit_retention_min_days": 730,
                "allow_auto_upgrade": true
            },
            "placement": { "require_attested": false, "allowed_operators": ["local", "neutral"] },
            "archetype_approval": { "require_approval": true }
        });
        let envelope = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "page_id": "organization-policy", "command_id": "organization-policy.set",
            "expected_basis": policy["resource_basis"], "idempotency_key": "policy-fixed-controls-1",
            "payload": payload, "client": "web"
        });
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            envelope,
            Some("policy-fixed-controls-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        assert_eq!(proposed["receipt"]["status"], "proposed");
        let id = proposed["proposal"]["id"].as_str().unwrap();
        let (status, applied) = request(
            &app,
            Method::POST,
            &format!("/gaugeapps/administration/proposals/{id}/review"),
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "decision": "accept", "client": "web"
            }),
            Some("policy-fixed-controls-review-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        assert_eq!(applied["receipt"]["status"], "applied");

        let uri = format!(
            "/gaugeapps/administration/pages/organization-policy?session={}&generation={}&scope={}",
            session["id"].as_str().unwrap(),
            session["generation"].as_str().unwrap(),
            session["scope"]["id"].as_str().unwrap(),
        );
        let (status, page) = request(&app, Method::GET, &uri, Value::Null, None).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(
            page["page"]["model"]["security"]["session_lifetime_secs"],
            28_800
        );
        assert_eq!(
            page["page"]["model"]["security"]["idle_timeout_secs"],
            1_800
        );
        assert_eq!(
            page["page"]["model"]["security"]["audit_retention_min_days"],
            730
        );
        assert_eq!(
            page["page"]["model"]["security"]["allow_auto_upgrade"],
            true
        );
        assert_eq!(
            page["page"]["model"]["placement"]["allowed_operators"],
            json!(["local", "neutral"])
        );
        assert_eq!(
            page["page"]["model"]["archetype_approval"]["require_approval"],
            true
        );
    }

    #[tokio::test]
    async fn organization_policy_cannot_mint_deferred_attestation_controls() {
        let (_dir, _shared, app) = test_app();
        let session = open(&app).await;
        let policy = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization-policy")
            .unwrap();
        let (status, rejected) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "organization-policy", "command_id": "organization-policy.set",
                "expected_basis": policy["resource_basis"], "idempotency_key": "policy-attestation-refused",
                "payload": {
                    "resource": { "rules": [
                        { "when": { "ClassificationIs": "pii" }, "require": "RequireAttestedCeiling" },
                        { "when": { "ClassificationIs": "pii" }, "require": "RequireResourceRegionMatchesActor" }
                    ] },
                    "security": {
                        "require_mfa": false, "session_lifetime_secs": 0,
                        "idle_timeout_secs": 0, "residency_region": null,
                        "audit_retention_min_days": 365, "allow_auto_upgrade": false
                    },
                    "placement": { "require_attested": true, "allowed_operators": [] },
                    "archetype_approval": { "require_approval": false }
                },
                "client": "web"
            }),
            Some("policy-attestation-refused"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{rejected}");
        assert!(
            rejected["error"]
                .as_str()
                .unwrap()
                .contains("deferred placement attestation"),
            "{rejected}"
        );
    }

    #[tokio::test]
    async fn every_page_carries_its_admitted_app_and_exact_scope() {
        let (_dir, _shared, app) = test_app();
        let session = open(&app).await;
        let pages = session["pages"].as_array().unwrap();
        assert_eq!(pages.len(), 12);
        for grant in pages {
            let uri = format!(
                "/gaugeapps/administration/pages/{}?session={}&generation={}&scope={}",
                grant["id"].as_str().unwrap(),
                session["id"].as_str().unwrap(),
                session["generation"].as_str().unwrap(),
                session["scope"]["id"].as_str().unwrap(),
            );
            let (status, response) = request(&app, Method::GET, &uri, Value::Null, None).await;
            assert_eq!(status, StatusCode::OK, "{response}");
            assert_eq!(response["page"]["app"], session["app"]);
            assert_eq!(response["page"]["scope"], session["scope"]);
            assert_eq!(response["page"]["id"], grant["id"]);
            assert_eq!(response["page"]["read_model"], grant["read_model"]);
            assert_eq!(response["page"]["version"], grant["version"]);
        }
    }

    #[tokio::test]
    async fn update_cursor_resumes_without_copying_page_state_to_the_client() {
        let (_dir, _shared, app) = test_app();
        let session = open(&app).await;
        let current_uri = format!(
            "/gaugeapps/administration/updates?session={}&generation={}&scope={}&after={}",
            session["id"].as_str().unwrap(),
            session["generation"].as_str().unwrap(),
            session["scope"]["id"].as_str().unwrap(),
            session["update_cursor"].as_str().unwrap(),
        );
        let (status, current) = request(&app, Method::GET, &current_uri, Value::Null, None).await;
        assert_eq!(status, StatusCode::OK, "{current}");
        assert_eq!(current["cursor"], session["update_cursor"]);
        assert_eq!(current["invalidations"], json!([]));

        let stale_uri = format!(
            "/gaugeapps/administration/updates?session={}&generation={}&scope={}&after=older-cursor",
            session["id"].as_str().unwrap(),
            session["generation"].as_str().unwrap(),
            session["scope"]["id"].as_str().unwrap(),
        );
        let (status, stale) = request(&app, Method::GET, &stale_uri, Value::Null, None).await;
        assert_eq!(status, StatusCode::OK, "{stale}");
        let invalidations = stale["invalidations"].as_array().unwrap();
        assert_eq!(
            invalidations.len(),
            session["pages"].as_array().unwrap().len()
        );
        assert!(invalidations
            .iter()
            .all(|entry| { entry["page_id"].is_string() && entry["resource_basis"].is_string() }));
    }

    #[tokio::test]
    async fn management_event_stream_reauthenticates_and_replays_from_its_cursor() {
        let (_dir, _shared, app) = test_app();
        let session = open(&app).await;
        let typed: GaugeAppSession = serde_json::from_value(session.clone()).unwrap();
        let live = begin_gaugeapp_agent_live_turn(&typed, "stream-turn-1").unwrap();
        live.publish(GaugeAppAgentLiveEvent::Text {
            delta: "Working".into(),
        })
        .unwrap();
        let (frames, _) = gaugeapp_agent_live_subscription(&gaugeapp_thread_id(&typed), None);
        let uri = format!(
            "/gaugeapps/administration/agent/events?session={}&generation={}&scope={}&after={}",
            session["id"].as_str().unwrap(),
            session["generation"].as_str().unwrap(),
            session["scope"]["id"].as_str().unwrap(),
            frames[0].cursor,
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .header("authorization", "Bearer owner-token")
                    .header("x-gaugedesk-client-version", "0.4.5")
                    .header("x-gaugedesk-client-protocol", "7")
                    .header("x-gaugedesk-client-channel", "stable")
                    .header("x-gaugedesk-client-platform", "GaugeDesk desktop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/event-stream"
        );
        let mut body = response.into_body();
        let frame = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let data = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
        assert!(data.contains("\"type\":\"text\""), "{data}");
        assert!(data.contains("Working"), "{data}");
        assert!(!data.contains("\"type\":\"started\""), "{data}");
    }

    #[test]
    fn management_thread_cursor_resumes_and_refuses_an_unknown_position() {
        let session = GaugeAppSession {
            id: "authorization-session".into(),
            generation: "generation-1".into(),
            app: GaugeAppKind::Administration,
            scope: GaugeAppScope {
                kind: "tenant".into(),
                id: "tenant-a".into(),
            },
            actor: "authority:owner".into(),
            capabilities: Vec::new(),
            pages: Vec::new(),
            commands: Vec::new(),
            update_cursor: "page-cursor".into(),
        };
        let thread_id = gaugeapp_thread_id(&session);
        let messages = vec![GaugeAppAgentMessage {
            id: "message-1".into(),
            thread_id: thread_id.clone(),
            app: GaugeAppKind::Administration,
            scope: session.scope.clone(),
            actor: session.actor.clone(),
            sequence: 0,
            role: gaugedesk_app::gaugeapp_agent::GaugeAppAgentMessageRole::User,
            text: "Explain this page.".into(),
            proposals: Vec::new(),
        }];

        let complete = agent_transcript_payload(&session, messages.clone(), None).unwrap();
        assert_eq!(complete["id"], thread_id);
        assert_eq!(complete["cursor"], "message-1");
        assert_eq!(complete["messages"].as_array().unwrap().len(), 1);

        let resumed =
            agent_transcript_payload(&session, messages.clone(), Some("message-1")).unwrap();
        assert_eq!(resumed["cursor"], "message-1");
        assert!(resumed["messages"].as_array().unwrap().is_empty());

        let stale =
            agent_transcript_payload(&session, messages, Some("other-thread-message")).unwrap_err();
        assert_eq!(stale.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn desktop_management_transcript_resumes_after_workbench_process_restart() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("desktop-state");
        let (shared, app) = persistent_test_app(&state, true);
        let session = open(&app).await;
        let typed: GaugeAppSession = serde_json::from_value(session.clone()).unwrap();
        let transcript = gaugedesk_app::gaugeapp_agent::append_gaugeapp_agent_exchange(
            &shared,
            &typed,
            "desktop-restart-turn",
            "What changed in this organization?",
            &gaugedesk_app::gaugeapp_agent::GaugeAppAgentTurn {
                message: "The admitted organization history is still available.".into(),
                proposals: Vec::new(),
            },
        )
        .unwrap();
        let resume_after = transcript[0].id.clone();
        let thread_id = gaugeapp_thread_id(&typed);

        drop(app);
        drop(shared);

        let (_reopened, app) = persistent_test_app(&state, false);
        let session = open(&app).await;
        let reopened: GaugeAppSession = serde_json::from_value(session.clone()).unwrap();
        assert_eq!(gaugeapp_thread_id(&reopened), thread_id);
        let uri = format!(
            "/gaugeapps/administration/agent/messages?session={}&generation={}&scope={}&after={}",
            session["id"].as_str().unwrap(),
            session["generation"].as_str().unwrap(),
            session["scope"]["id"].as_str().unwrap(),
            resume_after,
        );
        let (status, resumed) = request(&app, Method::GET, &uri, Value::Null, None).await;
        assert_eq!(status, StatusCode::OK, "{resumed}");
        assert_eq!(resumed["thread"]["id"], thread_id);
        assert_eq!(resumed["thread"]["messages"].as_array().unwrap().len(), 1);
        assert_eq!(
            resumed["thread"]["messages"][0]["text"],
            "The admitted organization history is still available."
        );
    }

    #[tokio::test]
    async fn stop_reauthenticates_the_exact_management_session_and_scope() {
        let tenant_id = "org-stop-test";
        let (_dir, _shared, app) = test_app_as_in("owner", tenant_id);
        let session = open_in_tenant(&app, Some(tenant_id)).await;
        let typed: GaugeAppSession = serde_json::from_value(session.clone()).unwrap();
        let thread_id = gaugeapp_thread_id(&typed);
        let claim = claim_gaugeapp_agent_turn(&thread_id).unwrap();

        let (status, refused) = request_in_tenant(
            &app,
            Method::POST,
            "/gaugeapps/administration/agent/stop",
            json!({
                "session_id": session["id"],
                "generation": "stale-generation",
                "scope": session["scope"],
            }),
            None,
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");
        assert!(!gaugeapp_agent_turn_was_stopped(&thread_id));

        let (status, stopped) = request_in_tenant(
            &app,
            Method::POST,
            "/gaugeapps/administration/agent/stop",
            json!({
                "session_id": session["id"],
                "generation": session["generation"],
                "scope": session["scope"],
            }),
            None,
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{stopped}");
        assert_eq!(stopped["stopped"], true);
        assert!(gaugeapp_agent_turn_was_stopped(&thread_id));

        drop(claim);
        let (status, nothing_running) = request_in_tenant(
            &app,
            Method::POST,
            "/gaugeapps/administration/agent/stop",
            json!({
                "session_id": session["id"],
                "generation": session["generation"],
                "scope": session["scope"],
            }),
            None,
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{nothing_running}");
        assert_eq!(nothing_running["stopped"], false);
    }

    #[tokio::test]
    async fn transcript_erasure_reauthenticates_and_replays_its_exact_request() {
        let tenant_id = "org-erasure-test";
        let (_dir, shared, app) = test_app_as_in("owner", tenant_id);
        let session = open_in_tenant(&app, Some(tenant_id)).await;
        let typed: GaugeAppSession = serde_json::from_value(session.clone()).unwrap();
        gaugedesk_app::gaugeapp_agent::append_gaugeapp_agent_exchange(
            &shared,
            &typed,
            "message-before-erase",
            "What is retained?",
            &gaugedesk_app::gaugeapp_agent::GaugeAppAgentTurn {
                message: "This admitted reply is retained.".into(),
                proposals: Vec::new(),
            },
        )
        .unwrap();

        let (status, refused) = request_in_tenant(
            &app,
            Method::POST,
            "/gaugeapps/administration/agent/erase",
            json!({
                "session_id": session["id"],
                "generation": "stale-generation",
                "scope": session["scope"],
                "idempotency_key": "erase-1",
            }),
            None,
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");
        assert_eq!(
            gaugeapp_agent_transcript(shared.lock_unpoisoned().store_ref(), &typed)
                .unwrap()
                .len(),
            2,
        );

        let body = json!({
            "session_id": session["id"],
            "generation": session["generation"],
            "scope": session["scope"],
            "idempotency_key": "erase-1",
        });
        let (status, erased) = request_in_tenant(
            &app,
            Method::POST,
            "/gaugeapps/administration/agent/erase",
            body.clone(),
            None,
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{erased}");
        assert_eq!(erased["erasure"]["generation"], 1);
        assert!(
            gaugeapp_agent_transcript(shared.lock_unpoisoned().store_ref(), &typed)
                .unwrap()
                .is_empty()
        );

        let (status, replayed) = request_in_tenant(
            &app,
            Method::POST,
            "/gaugeapps/administration/agent/erase",
            body,
            None,
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{replayed}");
        assert_eq!(replayed["erasure"], erased["erasure"]);
    }

    #[tokio::test]
    async fn billing_role_receives_only_plan_and_billing_authority() {
        let (_dir, _shared, app) = test_app_as("billing");
        let session = open(&app).await;
        let pages = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|page| page["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(pages, BTreeSet::from(["billing", "plans-services"]));
        let commands = session["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(commands, BTreeSet::from(["billing.contact.set"]));
    }

    #[tokio::test]
    async fn proposal_validation_blocks_domain_self_assertion_and_accepts_group_mapping() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let organization = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization")
            .unwrap();
        let challenge_uri = format!(
            "/gaugeapps/administration/organization/domain-verification?session={}&generation={}&scope={}&domain=Example.TEST",
            session["id"].as_str().unwrap(),
            session["generation"].as_str().unwrap(),
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
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "page_id": "organization", "command_id": "organization.display-name.set",
            "expected_basis": organization["resource_basis"], "idempotency_key": "domain-self-assertion",
            "payload": { "display_name": "Acme", "verified_domains": ["example.test"] },
            "client": "web",
        });
        let (status, rejected) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            invalid,
            Some("domain-self-assertion"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{rejected}");
        assert!(
            fold_gaugeapp_changes(shared.lock().unwrap().store_ref(), "org")
                .unwrap()
                .is_empty()
        );

        let identity = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "enterprise-identity")
            .unwrap();
        let mapping = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "page_id": "enterprise-identity", "command_id": "enterprise-identity.group-mapping.add",
            "expected_basis": identity["resource_basis"], "idempotency_key": "group-mapping-1",
            "payload": { "group": "engineering", "role": "member", "team": "product" },
            "client": "desktop",
        });
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            mapping,
            Some("group-mapping-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        assert_eq!(proposed["receipt"]["status"], "proposed");
    }

    #[tokio::test]
    async fn enterprise_identity_connection_and_group_mappings_use_canonical_lifecycles() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let identity = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "enterprise-identity")
            .unwrap();
        assert_eq!(identity["read_model"], "EnterpriseIdentityPageV1");
        let commands = identity["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            commands,
            BTreeSet::from([
                "enterprise-identity.admission-mode.set",
                "enterprise-identity.connection.set",
                "enterprise-identity.connection.credential.set",
                "enterprise-identity.connection.credential.remove",
                "enterprise-identity.test.begin",
                "enterprise-identity.connection.validate",
                "enterprise-identity.enforcement.enable",
                "enterprise-identity.enforcement.disable",
                "enterprise-identity.group-mapping.add",
                "enterprise-identity.group-mapping.edit",
                "enterprise-identity.group-mapping.remove",
                "enterprise-identity.owner-subject.link",
                "enterprise-identity.scim-credential.issue",
                "enterprise-identity.scim-credential.rotate",
            ])
        );

        apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.connection.set",
            json!({
                "protocol": "oidc", "issuer": "https://idp.example.invalid",
                "audiences": ["gaugedesk"], "metadata": "", "enforce_sso": true,
                "claim_mapping": { "subject_claim": "sub", "roles_claim": "groups" }
            }),
            "identity-connection",
        )
        .await;
        let sso = Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .sso
            .unwrap();
        assert_eq!(sso.issuer, "https://idp.example.invalid");
        assert!(
            !sso.enforce_sso,
            "connection setup cannot bypass enforcement prerequisites"
        );

        let session = open(&app).await;
        apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.group-mapping.add",
            json!({ "group": "engineering", "role": "member", "team": "product" }),
            "mapping-add",
        )
        .await;
        let session = open(&app).await;
        apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.group-mapping.edit",
            json!({ "group": "engineering", "role": "viewer", "team": null }),
            "mapping-edit",
        )
        .await;
        assert_eq!(
            Org::rebuild(shared.lock().unwrap().store_ref())
                .unwrap()
                .group_mappings["engineering"]
                .role,
            "viewer"
        );
        let session = open(&app).await;
        apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.group-mapping.remove",
            json!({ "group": "engineering" }),
            "mapping-remove",
        )
        .await;
        assert!(Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .group_mappings
            .is_empty());
    }

    #[tokio::test]
    async fn oidc_client_secret_is_write_only_revisioned_and_removable() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.connection.set",
            json!({
                "protocol": "oidc", "issuer": "https://idp.example.invalid",
                "audiences": ["gaugedesk"], "metadata": "", "enforce_sso": false,
                "claim_mapping": { "subject_claim": "sub", "roles_claim": null }
            }),
            "credential-connection",
        )
        .await;

        let session = open(&app).await;
        let page = read_page_json(&app, &session, "enterprise-identity").await;
        let original_revision = page["page"]["model"]["sso"]["revision"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            page["page"]["model"]["sso"]["client_secret_configured"],
            false
        );
        let envelope = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "page_id": "enterprise-identity",
            "command_id": "enterprise-identity.connection.credential.set",
            "expected_basis": page["page"]["resource_basis"],
            "idempotency_key": "oidc-secret-set", "client": "web",
            "payload": { "connection_revision": original_revision },
        });
        let body = json!({ "envelope": envelope, "secret": "confidential-client-value" });
        let (status, response) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/enterprise-identity/credential",
            body.clone(),
            Some("oidc-secret-set"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["receipt"]["status"], "applied");
        assert_eq!(response["result"]["client_secret_configured"], true);
        assert!(!response.to_string().contains("confidential-client-value"));

        let org = Org::rebuild(shared.lock().unwrap().store_ref()).unwrap();
        let connection = org.sso.as_ref().unwrap();
        assert_ne!(connection.current_revision(), original_revision);
        assert!(org.current_sso_credential().is_some());
        let opened = gaugedesk_app::auth_oidc::organization_oidc_client_secret(
            &shared.lock().unwrap(),
            &org,
            connection,
        )
        .unwrap()
        .unwrap();
        assert_eq!(opened.expose(), "confidential-client-value");
        let durable = shared
            .lock()
            .unwrap()
            .store_ref()
            .records(ORG_SCOPE, SSO_CREDENTIAL_KIND)
            .unwrap();
        assert_eq!(durable.len(), 1);
        assert!(!durable[0].contains("confidential-client-value"));

        let (status, replay) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/enterprise-identity/credential",
            body,
            Some("oidc-secret-set"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert!(!replay.to_string().contains("confidential-client-value"));
        assert_eq!(
            shared
                .lock()
                .unwrap()
                .store_ref()
                .records(ORG_SCOPE, SSO_CREDENTIAL_KIND)
                .unwrap()
                .len(),
            1,
            "an exact retry must not rotate the credential"
        );

        let session = open(&app).await;
        let page = read_page_json(&app, &session, "enterprise-identity").await;
        let configured_revision = page["page"]["model"]["sso"]["revision"].as_str().unwrap();
        assert_eq!(
            page["page"]["model"]["sso"]["client_secret_configured"],
            true
        );
        let remove = json!({
            "envelope": {
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "enterprise-identity",
                "command_id": "enterprise-identity.connection.credential.remove",
                "expected_basis": page["page"]["resource_basis"],
                "idempotency_key": "oidc-secret-remove", "client": "web",
                "payload": { "connection_revision": configured_revision },
            }
        });
        let (status, response) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/enterprise-identity/credential",
            remove,
            Some("oidc-secret-remove"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let org = Org::rebuild(shared.lock().unwrap().store_ref()).unwrap();
        assert!(org.sso.as_ref().unwrap().credential_revision.is_none());
        assert!(org.sso_credential.is_none());
    }

    fn install_enforcement_readiness(shared: &SharedWorkbench) {
        let mut guard = shared.lock().unwrap();
        let connection = Org::rebuild(guard.store_ref()).unwrap().sso.unwrap();
        let organization = OrgRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            display_name: "Example".into(),
            verified_domains: vec!["example.test".into()],
            ..Default::default()
        };
        let browser_test = SsoBrowserTestRecord {
            id: "browser-test-current".into(),
            connection_id: connection.id.clone(),
            connection_revision: connection.current_revision(),
            protocol: connection.protocol,
            subject: "owner-at-idp".into(),
            mapped_roles: Vec::new(),
            mapped_region: None,
            mapped_tenant: None,
            initiated_by: "authority:owner".into(),
            tested_at_ms: gaugedesk_app::account::session_now_ms(),
        };
        guard
            .store_mut()
            .append_records_atomically(&[
                (
                    ORG_SCOPE,
                    "org",
                    serde_json::to_string(&organization).unwrap().as_str(),
                ),
                (
                    ORG_SCOPE,
                    SSO_BROWSER_TEST_KIND,
                    serde_json::to_string(&browser_test).unwrap().as_str(),
                ),
            ])
            .unwrap();
        let subject = ExternalSubjectRecord::new(
            "authority:owner",
            &format!("{ORG_SCOPE}:{}", connection.id),
            &connection.issuer,
            &browser_test.subject,
            ExternalSubjectKind::EnterpriseOidc,
            1,
        )
        .unwrap();
        let credential = WebAuthnMethodRecord::new(
            "authority:owner",
            "owner-passkey",
            "public verifier",
            "Security key",
            1,
        )
        .unwrap();
        let recovery = RecoveryCodeRecord::prepare(
            "authority:owner",
            "owner-recovery",
            "salt",
            "one-use-code",
        )
        .unwrap();
        append_account_auth_facts(
            guard.store_mut(),
            &[
                AccountAuthFact::ExternalSubject(subject),
                AccountAuthFact::WebAuthn(credential),
                AccountAuthFact::RecoveryBatch(RecoveryBatchRecord {
                    id: "owner-recovery".into(),
                    op: RecordOp::Upsert,
                    account_id: "authority:owner".into(),
                    created_at: 1,
                    status: RecoveryBatchStatus::Active,
                }),
                AccountAuthFact::RecoveryCode(recovery),
            ],
        )
        .unwrap();
    }

    #[tokio::test]
    async fn enforcement_is_server_admitted_and_break_glass_can_only_disable_it() {
        let (_dir, shared, app, authorization) = test_app_with_account_authorization();
        let session = open(&app).await;
        apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.connection.set",
            json!({
                "protocol": "oidc", "issuer": "https://idp.example.test",
                "audiences": ["gaugedesk"], "metadata": "", "enforce_sso": false,
                "claim_mapping": { "subject_claim": "sub" }
            }),
            "enforcement-connection",
        )
        .await;
        let session = open(&app).await;
        apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.admission-mode.set",
            json!({ "mode": "invited-only" }),
            "enforcement-admission",
        )
        .await;

        let session = open(&app).await;
        let identity = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "enterprise-identity")
            .unwrap();
        let (status, refused) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "enterprise-identity",
                "command_id": "enterprise-identity.enforcement.enable",
                "expected_basis": identity["resource_basis"],
                "idempotency_key": "enforcement-incomplete",
                "payload": {}, "client": "web"
            }),
            Some("enforcement-incomplete"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        assert!(!Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .sso_enforced());

        install_enforcement_readiness(&shared);
        let before_revision = Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .sso
            .unwrap()
            .current_revision();
        let session = open(&app).await;
        let enable_proof = authorization
            .issue_authorization_proof_after_verification(
                "authority:owner",
                "enterprise-identity.enforcement.enable",
                gaugedesk_app::account::session_now_ms() / 1_000,
            )
            .unwrap();
        apply_reviewed_with_proof(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.enforcement.enable",
            json!({}),
            "enforcement-ready",
            Some(&enable_proof),
        )
        .await;
        let enforced = Org::rebuild(shared.lock().unwrap().store_ref()).unwrap();
        assert!(enforced.sso_enforced());
        assert_eq!(
            enforced.sso.unwrap().current_revision(),
            before_revision,
            "enforcement policy must not invalidate browser-test evidence"
        );

        let passkey = shared
            .lock()
            .unwrap()
            .mint_account_session("authority:owner", "passkey", 3600)
            .unwrap();
        let recovery = open_with_bearer(&app, &passkey).await;
        assert_eq!(
            recovery["pages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|page| page["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["enterprise-identity"]
        );
        assert_eq!(
            recovery["commands"]
                .as_array()
                .unwrap()
                .iter()
                .map(|command| command["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["enterprise-identity.enforcement.disable"]
        );
        let page = &recovery["pages"][0];
        let (status, proposed) = request_with_bearer(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": recovery["id"], "generation": recovery["generation"],
                "app": "administration", "scope": recovery["scope"],
                "page_id": "enterprise-identity",
                "command_id": "enterprise-identity.enforcement.disable",
                "expected_basis": page["resource_basis"],
                "idempotency_key": "recovery-disable",
                "payload": {}, "client": "web"
            }),
            Some("recovery-disable"),
            None,
            &passkey,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        let proposal_id = proposed["proposal"]["id"].as_str().unwrap();
        let disable_proof = authorization
            .issue_authorization_proof_after_verification(
                "authority:owner",
                "enterprise-identity.enforcement.disable",
                gaugedesk_app::account::session_now_ms() / 1_000,
            )
            .unwrap();
        let (status, applied) = request_with_bearer(
            &app,
            Method::POST,
            &format!("/gaugeapps/administration/proposals/{proposal_id}/review"),
            json!({
                "session_id": recovery["id"], "generation": recovery["generation"],
                "app": "administration", "scope": recovery["scope"],
                "decision": "accept", "client": "web",
                "authorization_proof": disable_proof
            }),
            Some("recovery-disable-review"),
            None,
            &passkey,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        assert!(!Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .sso_enforced());
        assert!(
            gaugedesk_app::audit::list(shared.lock().unwrap().store_ref())
                .iter()
                .any(
                    |entry| entry.action == "enterprise-identity.enforcement.disable"
                        && entry.actor == "authority:owner"
                )
        );
    }

    #[tokio::test]
    async fn owner_subject_link_binds_a_recent_test_to_a_fresh_passkey_confirmation() {
        let (_dir, shared, app, authorization) = test_app_with_account_authorization();
        let session = open(&app).await;
        apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.connection.set",
            json!({
                "protocol": "oidc", "issuer": "https://idp.example.test",
                "audiences": ["gaugedesk"], "metadata": "", "enforce_sso": false,
                "claim_mapping": { "subject_claim": "sub" }
            }),
            "owner-link-connection",
        )
        .await;
        {
            let mut guard = shared.lock().unwrap();
            let connection = Org::rebuild(guard.store_ref()).unwrap().sso.unwrap();
            let evidence = SsoBrowserTestRecord {
                id: "owner-link-test".into(),
                connection_id: connection.id.clone(),
                connection_revision: connection.current_revision(),
                protocol: connection.protocol,
                subject: "corporate-owner".into(),
                mapped_roles: Vec::new(),
                mapped_region: None,
                mapped_tenant: None,
                initiated_by: "authority:owner".into(),
                tested_at_ms: gaugedesk_app::account::session_now_ms(),
            };
            guard
                .store_mut()
                .append_record(
                    ORG_SCOPE,
                    SSO_BROWSER_TEST_KIND,
                    &serde_json::to_string(&evidence).unwrap(),
                )
                .unwrap();
        }
        let passkey = shared
            .lock()
            .unwrap()
            .mint_account_session("authority:owner", "passkey", 3600)
            .unwrap();
        let session = open_with_bearer(&app, &passkey).await;
        let page = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "enterprise-identity")
            .unwrap();
        let (status, proposed) = request_with_bearer(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "enterprise-identity",
                "command_id": "enterprise-identity.owner-subject.link",
                "expected_basis": page["resource_basis"],
                "idempotency_key": "owner-link",
                "payload": {}, "client": "web"
            }),
            Some("owner-link"),
            None,
            &passkey,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        let review_uri = format!(
            "/gaugeapps/administration/proposals/{}/review",
            proposed["proposal"]["id"].as_str().unwrap()
        );
        let review = |proof: Option<&str>| {
            let mut value = json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "decision": "accept", "client": "web"
            });
            if let Some(proof) = proof {
                value["authorization_proof"] = json!(proof);
            }
            value
        };
        let (status, no_proof) = request_with_bearer(
            &app,
            Method::POST,
            &review_uri,
            review(None),
            Some("owner-link-no-proof"),
            None,
            &passkey,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{no_proof}");

        let proof = authorization
            .issue_authorization_proof_after_verification(
                "authority:owner",
                "enterprise-identity.owner-subject.link",
                gaugedesk_app::account::session_now_ms() / 1_000,
            )
            .unwrap();
        let (status, applied) = request_with_bearer(
            &app,
            Method::POST,
            &review_uri,
            review(Some(&proof)),
            Some("owner-link-review"),
            None,
            &passkey,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        let auth = AccountAuth::rebuild(shared.lock().unwrap().store_ref()).unwrap();
        let org = Org::rebuild(shared.lock().unwrap().store_ref()).unwrap();
        assert!(org.corporate_subject_linked_for(&auth, "authority:owner"));
        assert_eq!(auth.external_subjects.len(), 1);
    }

    #[tokio::test]
    async fn enterprise_identity_validation_is_immediate_revision_bound_evidence() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let metadata = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso" /></IDPSSODescriptor></EntityDescriptor>"#;
        apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.connection.set",
            json!({
                "protocol": "saml", "issuer": "caller-supplied-value-is-ignored",
                "audiences": ["caller-supplied-value-is-ignored"], "metadata": metadata,
                "enforce_sso": true, "claim_mapping": { "subject_claim": "NameID" }
            }),
            "saml-connection",
        )
        .await;
        let stored = Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .sso
            .unwrap();
        assert_eq!(stored.issuer, "https://idp.example.test");
        assert!(stored.audiences.is_empty());
        assert_eq!(stored.revision, stored.computed_revision());

        let session = open(&app).await;
        let identity = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "enterprise-identity")
            .unwrap();
        let (status, page_response) = request(
            &app,
            Method::GET,
            &format!(
                "/gaugeapps/administration/pages/enterprise-identity?session={}&generation={}&scope={}",
                session["id"].as_str().unwrap(),
                session["generation"].as_str().unwrap(),
                session["scope"]["id"].as_str().unwrap(),
            ),
            Value::Null,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page_response}");
        let revision = page_response["page"]["model"]["sso"]["revision"]
            .as_str()
            .unwrap()
            .to_owned();
        let envelope = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "page_id": "enterprise-identity",
            "command_id": "enterprise-identity.connection.validate",
            "expected_basis": identity["resource_basis"],
            "idempotency_key": "validate-saml-connection", "payload": {}, "client": "web",
        });
        let (status, response) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            envelope,
            Some("validate-saml-connection"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["receipt"]["status"], "applied");
        assert_eq!(response["result"]["status"], "ready");
        assert_eq!(response["result"]["code"], "saml-metadata-ready");
        assert_eq!(response["result"]["connection_revision"], revision);
        assert_eq!(response["result"]["browser_test"], "not-run");
        assert_eq!(response["result"]["sign_in_services"], 1);
        assert_eq!(response["result"]["signing_certificates"], 1);
    }

    #[tokio::test]
    async fn saml_browser_test_command_launches_the_server_held_acs_ceremony() {
        let (_dir, shared, _plain_app) = test_app();
        let auth = crate::org_routes::auth_shell_state();
        let saml_tests = crate::identity_saml::SamlBrowserState::default();
        let app = Router::new()
            .merge(
                routes()
                    .layer(Extension(auth.clone()))
                    .layer(Extension(saml_tests.clone())),
            )
            .merge(
                crate::identity_saml::browser_routes()
                    .layer(Extension(auth.clone()))
                    .layer(Extension(saml_tests)),
            )
            .with_state(shared);
        let metadata = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></IDPSSODescriptor></EntityDescriptor>"#;
        let session = open(&app).await;
        apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.connection.set",
            json!({
                "protocol": "saml", "issuer": "ignored", "audiences": [],
                "metadata": metadata, "enforce_sso": false,
                "claim_mapping": { "subject_claim": null, "roles_claim": "groups" }
            }),
            "saml-browser-connection",
        )
        .await;
        let session = open(&app).await;
        let identity = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "enterprise-identity")
            .unwrap();
        let envelope = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "page_id": "enterprise-identity",
            "command_id": "enterprise-identity.test.begin",
            "expected_basis": identity["resource_basis"],
            "idempotency_key": "saml-browser-test-start", "payload": {}, "client": "web",
        });
        let (status, response) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            envelope,
            Some("saml-browser-test-start"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(
            response["result"]["kind"],
            "enterprise-identity-browser-test-launch"
        );
        assert_eq!(response["result"]["protocol"], "saml");
        let launch = response["result"]["authorize_url"].as_str().unwrap();
        assert!(
            launch.starts_with("http://localhost:7878/auth/enterprise-identity/saml/launch?state=")
        );

        let path = launch.strip_prefix("http://localhost:7878").unwrap();
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[axum::http::header::LOCATION]
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://idp.example.test/sso?SAMLRequest="));
        assert!(location.contains("&RelayState="));
    }

    #[tokio::test]
    async fn display_name_command_preserves_the_rest_of_organization_identity() {
        let (_dir, shared, app) = test_app();
        let original = OrgRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            display_name: "Expert LLC".into(),
            verified_domains: vec!["example.test".into()],
            pending_domains: Vec::new(),
            default_region: Some("eu".into()),
            kind: gaugedesk_app::org::OrgKind::Consultant,
        };
        shared
            .lock()
            .unwrap()
            .store_mut()
            .append_record("org", "org", &serde_json::to_string(&original).unwrap())
            .unwrap();
        let session = open(&app).await;
        let organization = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization")
            .unwrap();
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "organization", "command_id": "organization.display-name.set",
                "expected_basis": organization["resource_basis"],
                "idempotency_key": "display-name-1",
                "payload": { "display_name": "Expert Group" }, "client": "web",
            }),
            Some("display-name-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        let proposal_id = proposed["proposal"]["id"].as_str().unwrap();
        let (status, applied) = request(
            &app,
            Method::POST,
            &format!("/gaugeapps/administration/proposals/{proposal_id}/review"),
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "decision": "accept", "client": "web",
            }),
            Some("display-name-review-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        let record = Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .org
            .unwrap();
        assert_eq!(record.display_name, "Expert Group");
        assert_eq!(record.verified_domains, vec!["example.test"]);
        assert_eq!(record.default_region.as_deref(), Some("eu"));
        assert_eq!(record.kind, gaugedesk_app::org::OrgKind::Consultant);
    }

    #[tokio::test]
    async fn ownership_transfer_is_the_only_way_to_change_the_owner_role() {
        let (_dir, shared, app, authorization) = test_app_with_account_authorization();
        let organization = OrgRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            display_name: "Acme".into(),
            ..Default::default()
        };
        let successor = MembershipRecord {
            id: "successor".into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: "authority:successor".into(),
            email: "successor@example.test".into(),
            role: "member".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: Some("product".into()),
        };
        {
            let mut guard = shared.lock().unwrap();
            guard
                .store_mut()
                .append_record("org", "org", &serde_json::to_string(&organization).unwrap())
                .unwrap();
            guard
                .store_mut()
                .append_record(
                    "org",
                    "membership",
                    &serde_json::to_string(&successor).unwrap(),
                )
                .unwrap();
        }

        let session = open(&app).await;
        let organization_page = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization")
            .unwrap();
        assert!(organization_page["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|command| command == "organization.ownership.transfer"));
        let people_page = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "people")
            .unwrap();
        let (status, rejected) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "people", "command_id": "people.role.change",
                "expected_basis": people_page["resource_basis"],
                "idempotency_key": "role-cannot-mint-owner",
                "payload": { "id": "successor", "role": "owner" }, "client": "web",
            }),
            Some("role-cannot-mint-owner"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{rejected}");
        assert!(rejected["error"]
            .as_str()
            .unwrap()
            .contains("Transfer ownership"));

        let proof = authorization
            .issue_authorization_proof_after_verification(
                "authority:owner",
                "organization.ownership.transfer",
                gaugedesk_app::account::session_now_ms() / 1_000,
            )
            .unwrap();
        apply_reviewed_with_proof(
            &app,
            &session,
            "organization",
            "organization.ownership.transfer",
            json!({ "id": "successor" }),
            "ownership-transfer",
            Some(&proof),
        )
        .await;

        let org = Org::rebuild(shared.lock().unwrap().store_ref()).unwrap();
        assert_eq!(org.members["owner"].role, "admin");
        assert_eq!(org.members["successor"].role, "owner");
        assert_eq!(org.members["successor"].team, None);
        assert_eq!(org.active_count_with_role("owner"), 1);

        let old_owner_session = open(&app).await;
        let organization_page = old_owner_session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization")
            .unwrap();
        assert!(!organization_page["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|command| command == "organization.ownership.transfer"));
    }

    #[tokio::test]
    async fn organization_delete_requires_exact_name_fresh_authorization_and_no_dependencies() {
        let tenant_id = "organization:delete-me";
        let (_dir, shared, app, authorization) = test_app_with_account_authorization_in(tenant_id);
        let scope = gaugedesk_app::org::tenant_scope(tenant_id);
        let account_scope = {
            let mut guard = shared.lock().unwrap();
            let account_scope = guard.account_scope_for(Some("owner-token"));
            let organization = OrgRecord {
                id: ORG_ID.into(),
                op: RecordOp::Upsert,
                display_name: "Delete Me LLC".into(),
                ..Default::default()
            };
            let tenant = gaugedesk_app::tenancy::TenantRef {
                id: tenant_id.into(),
                op: RecordOp::Upsert,
                display_name: "Delete Me LLC".into(),
                role: "owner".into(),
                personal: false,
            };
            let organization_json = serde_json::to_string(&organization).unwrap();
            let tenant_json = serde_json::to_string(&tenant).unwrap();
            guard
                .store_mut()
                .append_records_atomically(&[
                    (scope.as_str(), "org", organization_json.as_str()),
                    (
                        account_scope.as_str(),
                        gaugedesk_app::tenancy::TENANT_REF_KIND,
                        tenant_json.as_str(),
                    ),
                ])
                .unwrap();
            account_scope
        };
        let session = open_in_tenant(&app, Some(tenant_id)).await;
        let page = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization")
            .unwrap();
        assert!(page["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|command| command == "organization.delete"));

        let command = |confirmation: &str, key: &str| {
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "organization", "command_id": "organization.delete",
                "expected_basis": page["resource_basis"], "idempotency_key": key,
                "payload": { "confirmation": confirmation }, "client": "web",
            })
        };
        let (status, wrong_name) = request_in_tenant(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            command("Delete me llc", "delete-wrong-name"),
            Some("delete-wrong-name"),
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{wrong_name}");

        let (status, proposed) = request_in_tenant(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            command("Delete Me LLC", "delete-proposal"),
            Some("delete-proposal"),
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        let review_uri = format!(
            "/gaugeapps/administration/proposals/{}/review",
            proposed["proposal"]["id"].as_str().unwrap()
        );
        let review = |proof: Option<&str>| {
            let mut value = json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "decision": "accept", "client": "web",
            });
            if let Some(proof) = proof {
                value["authorization_proof"] = json!(proof);
            }
            value
        };
        let (status, no_proof) = request_in_tenant(
            &app,
            Method::POST,
            &review_uri,
            review(None),
            Some("delete-review-no-proof"),
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{no_proof}");

        let wrong_operation = authorization
            .issue_authorization_proof_after_verification(
                "authority:owner",
                "organization.ownership.transfer",
                gaugedesk_app::account::session_now_ms() / 1_000,
            )
            .unwrap();
        let (status, wrong_proof) = request_in_tenant(
            &app,
            Method::POST,
            &review_uri,
            review(Some(&wrong_operation)),
            Some("delete-review-wrong-proof"),
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{wrong_proof}");

        let proof = authorization
            .issue_authorization_proof_after_verification(
                "authority:owner",
                "organization.delete",
                gaugedesk_app::account::session_now_ms() / 1_000,
            )
            .unwrap();
        let (status, applied) = request_in_tenant(
            &app,
            Method::POST,
            &review_uri,
            review(Some(&proof)),
            Some("delete-review"),
            Some(tenant_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        assert_eq!(applied["result"]["deleted_organization"], tenant_id);

        let guard = shared.lock().unwrap();
        assert!(
            !gaugedesk_app::tenancy::Tenancy::rebuild_in(guard.store_ref(), &account_scope,)
                .unwrap()
                .tenants
                .contains_key(tenant_id)
        );
        let deleted = Org::rebuild_in(guard.store_ref(), &scope).unwrap();
        assert!(deleted.org.is_none());
        assert!(
            deleted.members.is_empty(),
            "organization erasure destroys the content key after the tombstones commit"
        );
    }

    #[tokio::test]
    async fn verified_domain_removal_is_reviewed_and_preserves_organization_identity() {
        let (_dir, shared, app) = test_app();
        let original = OrgRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            display_name: "Acme".into(),
            verified_domains: vec!["acme.example".into(), "keep.example".into()],
            pending_domains: Vec::new(),
            default_region: Some("us".into()),
            kind: gaugedesk_app::org::OrgKind::Client,
        };
        shared
            .lock()
            .unwrap()
            .store_mut()
            .append_record("org", "org", &serde_json::to_string(&original).unwrap())
            .unwrap();
        let session = open(&app).await;
        let organization = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization")
            .unwrap();
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "organization", "command_id": "organization.domain.remove",
                "expected_basis": organization["resource_basis"],
                "idempotency_key": "domain-remove-1",
                "payload": { "domain": "ACME.example" }, "client": "web",
            }),
            Some("domain-remove-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        assert_eq!(
            Org::rebuild(shared.lock().unwrap().store_ref())
                .unwrap()
                .org
                .unwrap()
                .verified_domains,
            vec!["acme.example", "keep.example"],
            "a proposal is not authority"
        );

        let proposal_id = proposed["proposal"]["id"].as_str().unwrap();
        let (status, applied) = request(
            &app,
            Method::POST,
            &format!("/gaugeapps/administration/proposals/{proposal_id}/review"),
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "decision": "accept", "client": "web",
            }),
            Some("domain-remove-review-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        let record = Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .org
            .unwrap();
        assert_eq!(record.display_name, "Acme");
        assert_eq!(record.verified_domains, vec!["keep.example"]);
        assert_eq!(record.default_region.as_deref(), Some("us"));
    }

    async fn organization_page(app: &Router) -> Value {
        let session = open(app).await;
        let (status, response) = request(
            app,
            Method::GET,
            &format!(
                "/gaugeapps/administration/pages/organization?session={}&generation={}&scope={}",
                session["id"].as_str().unwrap(),
                session["generation"].as_str().unwrap(),
                session["scope"]["id"].as_str().unwrap(),
            ),
            Value::Null,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response["page"].clone()
    }

    /// Propose `command_id` against the current organization basis and return
    /// the status with the body, so a refusal can be read at the point it is
    /// made rather than after a review that never happens.
    async fn propose_organization(
        app: &Router,
        command_id: &str,
        payload: Value,
        key: &str,
    ) -> (StatusCode, Value) {
        let session = open(app).await;
        let organization = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization")
            .unwrap()
            .clone();
        request(
            app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "organization", "command_id": command_id,
                "expected_basis": organization["resource_basis"],
                "idempotency_key": key,
                "payload": payload, "client": "web",
            }),
            Some(key),
        )
        .await
    }

    async fn accept_organization_proposal(app: &Router, proposal_id: &str, key: &str) -> Value {
        let session = open(app).await;
        let (status, applied) = request(
            app,
            Method::POST,
            &format!("/gaugeapps/administration/proposals/{proposal_id}/review"),
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "decision": "accept", "client": "web",
            }),
            Some(key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        applied
    }

    #[tokio::test]
    async fn adding_a_domain_records_a_pending_claim_and_publishes_its_challenge() {
        let (_dir, shared, app) = test_app();
        let (status, proposed) = propose_organization(
            &app,
            "organization.domain.add",
            json!({ "domain": "Acme.Example." }),
            "domain-add-1",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        assert!(
            Org::rebuild(shared.lock().unwrap().store_ref())
                .unwrap()
                .org
                .is_none_or(|record| record.pending_domains.is_empty()),
            "a proposal is not authority"
        );

        accept_organization_proposal(
            &app,
            proposed["proposal"]["id"].as_str().unwrap(),
            "domain-add-review-1",
        )
        .await;
        let record = Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .org
            .unwrap();
        assert_eq!(record.pending_domains, vec!["acme.example"]);
        assert!(
            record.verified_domains.is_empty(),
            "adding a domain must not verify it"
        );

        let domains = organization_page(&app).await["model"]["domains"].clone();
        assert_eq!(domains.as_array().unwrap().len(), 1);
        assert_eq!(domains[0]["domain"], "acme.example");
        assert_eq!(domains[0]["status"], "pending");
        assert_eq!(
            domains[0]["challenge"]["record_name"],
            "_gaugewright-challenge.acme.example"
        );
        assert_eq!(domains[0]["challenge"]["record_type"], "TXT");
        assert_eq!(
            domains[0]["challenge"]["value"].as_str().unwrap(),
            crate::org_routes::expected_txt("acme.example"),
            "the page must publish the exact value the proof check compares against"
        );
    }

    #[tokio::test]
    async fn verification_promotes_only_a_domain_that_was_actually_claimed() {
        let (_dir, _shared, app) = test_app();
        let (status, proposed) = propose_organization(
            &app,
            "organization.domain.add",
            json!({ "domain": "acme.example" }),
            "claim-1",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        accept_organization_proposal(
            &app,
            proposed["proposal"]["id"].as_str().unwrap(),
            "claim-review-1",
        )
        .await;

        // The claim exists, so verification may be proposed. Accepting it still
        // requires the published TXT record, which is a separate gate.
        let (status, ok) = propose_organization(
            &app,
            "organization.domain.verify",
            json!({ "domain": "ACME.example" }),
            "verify-1",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{ok}");

        // Without a claim there is nothing to promote. Allowing this would make
        // the proof step the entire ceremony for a domain nobody ever added.
        let (status, refused) = propose_organization(
            &app,
            "organization.domain.verify",
            json!({ "domain": "other.example" }),
            "verify-2",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");

        let (status, duplicate) = propose_organization(
            &app,
            "organization.domain.add",
            json!({ "domain": "acme.example" }),
            "claim-2",
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{duplicate}");

        for bad in [
            "localhost",
            "https://acme.example",
            "admin@acme.example",
            "acme..example",
            "-acme.example",
        ] {
            let (status, refused) = propose_organization(
                &app,
                "organization.domain.add",
                json!({ "domain": bad }),
                &format!("bad-{bad}"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{bad} is not a publishable DNS name: {refused}"
            );
        }
    }

    #[tokio::test]
    async fn removing_a_pending_claim_withdraws_it_and_leaves_verified_domains() {
        let (_dir, shared, app) = test_app();
        let original = OrgRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            display_name: "Acme".into(),
            verified_domains: vec!["keep.example".into()],
            pending_domains: vec!["mistyped.example".into()],
            default_region: None,
            kind: gaugedesk_app::org::OrgKind::Client,
        };
        shared
            .lock()
            .unwrap()
            .store_mut()
            .append_record("org", "org", &serde_json::to_string(&original).unwrap())
            .unwrap();

        let (status, proposed) = propose_organization(
            &app,
            "organization.domain.remove",
            json!({ "domain": "mistyped.example" }),
            "withdraw-1",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        accept_organization_proposal(
            &app,
            proposed["proposal"]["id"].as_str().unwrap(),
            "withdraw-review-1",
        )
        .await;

        let record = Org::rebuild(shared.lock().unwrap().store_ref())
            .unwrap()
            .org
            .unwrap();
        assert!(record.pending_domains.is_empty());
        assert_eq!(record.verified_domains, vec!["keep.example"]);

        let (status, refused) = propose_organization(
            &app,
            "organization.domain.remove",
            json!({ "domain": "mistyped.example" }),
            "withdraw-2",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");
    }

    #[tokio::test]
    async fn billing_contact_round_trips_independently_of_plan_state() {
        let (_dir, shared, app) = test_app();
        assert_eq!(
            billing_page(&app).await["model"]["billing_contact"],
            Value::Null
        );

        let session = open(&app).await;
        let base = billing_page(&app).await["resource_basis"].clone();
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "billing", "command_id": "billing.contact.set",
                "expected_basis": base, "idempotency_key": "billing-contact",
                "payload": {
                    "name": "  Ada Lovelace  ",
                    "email": "  BILLING@Example.TEST  "
                },
                "client": "web",
            }),
            Some("billing-contact"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        accept(&app, &session, &proposed, "billing-contact-review").await;

        let page = billing_page(&app).await;
        assert_eq!(page["model"]["billing_contact"]["name"], "Ada Lovelace");
        assert_eq!(
            page["model"]["billing_contact"]["email"],
            "billing@example.test"
        );

        assert_eq!(
            Org::rebuild(shared.lock().unwrap().store_ref())
                .unwrap()
                .billing_contact
                .unwrap()
                .email,
            "billing@example.test"
        );
    }

    async fn billing_page(app: &Router) -> Value {
        let session = open(app).await;
        let (status, response) = request(
            app,
            Method::GET,
            &format!(
                "/gaugeapps/administration/pages/billing?session={}&generation={}&scope={}",
                session["id"].as_str().unwrap(),
                session["generation"].as_str().unwrap(),
                session["scope"]["id"].as_str().unwrap(),
            ),
            Value::Null,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response["page"].clone()
    }

    async fn accept(app: &Router, session: &Value, proposed: &Value, key: &str) -> Value {
        assert_eq!(proposed["receipt"]["status"], "proposed");
        let (status, applied) = request(
            app,
            Method::POST,
            &format!(
                "/gaugeapps/administration/proposals/{}/review",
                proposed["proposal"]["id"].as_str().unwrap()
            ),
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "decision": "accept", "client": "web",
            }),
            Some(&format!("{key}-review")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        assert_eq!(applied["receipt"]["status"], "applied");
        applied
    }

    async fn people_page(app: &Router, session: &Value) -> Value {
        let (status, response) = request(
            app,
            Method::GET,
            &format!(
                "/gaugeapps/administration/pages/people?session={}&generation={}&scope={}",
                session["id"].as_str().unwrap(),
                session["generation"].as_str().unwrap(),
                session["scope"]["id"].as_str().unwrap(),
            ),
            Value::Null,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response["page"].clone()
    }

    async fn sessions_page(app: &Router, session: &Value) -> Value {
        let (status, response) = request(
            app,
            Method::GET,
            &format!(
                "/gaugeapps/administration/pages/sessions?session={}&generation={}&scope={}",
                session["id"].as_str().unwrap(),
                session["generation"].as_str().unwrap(),
                session["scope"]["id"].as_str().unwrap(),
            ),
            Value::Null,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response["page"].clone()
    }

    async fn apply_people(
        app: &Router,
        session: &Value,
        command_id: &str,
        payload: Value,
        key: &str,
    ) -> Value {
        let base = people_page(app, session).await["resource_basis"].clone();
        let (status, proposed) = request(
            app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "people", "command_id": command_id,
                "expected_basis": base, "idempotency_key": key,
                "payload": payload, "client": "web",
            }),
            Some(key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        accept(app, session, &proposed, key).await
    }

    #[test]
    fn people_command_basis_excludes_operational_session_freshness() {
        let mut page = AdministrationExtensionPage {
            id: "people".into(),
            read_model: "PeoplePageV1".into(),
            version: 1,
            freshness: "live".into(),
            model: json!({
                "members": [{ "id": "owner", "role": "owner" }],
                "grants": [],
                "projects": [],
                "sessions": [{ "id": "session:one", "idle_ms": 1 }],
            }),
            commands: Vec::new(),
        };
        let first = page_resource_basis(&page, "tenant");
        page.model["sessions"][0]["idle_ms"] = json!(90_000);
        assert_eq!(page_resource_basis(&page, "tenant"), first);
        page.model["members"][0]["role"] = json!("admin");
        assert_ne!(page_resource_basis(&page, "tenant"), first);
    }

    #[test]
    fn model_providers_use_authority_revision_and_refuse_cross_org_or_malformed_pages() {
        let model: Value = serde_json::from_str(include_str!(
            "../../../crates/app/src/model_provider_management/projection/page.fixture.json"
        ))
        .unwrap();
        let mut page = AdministrationExtensionPage {
            id: "model-providers".into(),
            read_model: "OrganizationModelProvidersPageV1".into(),
            version: 1,
            freshness: "live".into(),
            model,
            commands: Vec::new(),
        };
        let basis = page_resource_basis(&page, "example-organization").unwrap();
        page.model["as_of"] = json!("1234");
        page.model["grants"][0]["usage"]["reserved"]["tokens"] = json!("25");
        assert_eq!(
            page_resource_basis(&page, "example-organization").unwrap(),
            basis
        );
        page.model["management_revision"] = json!("6");
        assert_ne!(
            page_resource_basis(&page, "example-organization").unwrap(),
            basis
        );
        assert!(page_resource_basis(&page, "another-organization").is_err());
        page.model["connections"][0]["secret"] = json!("must-not-expose");
        assert_eq!(
            page_resource_basis(&page, "example-organization"),
            Err("invalid Model Providers projection")
        );
        page.model = json!(ModelProvidersPage::Unavailable {
            reason: UnavailableReason::AuthorityUnavailable
        });
        assert!(page_resource_basis(&page, "example-organization").is_ok());
        page.commands.push(AdministrationExtensionCommand {
            id: "organization-provider.rename".into(),
            capability: Capability::ConfigureSecurity,
            review: ReviewPolicy::Human,
        });
        assert!(page_resource_basis(&page, "example-organization").is_err());
    }

    #[test]
    fn project_host_basis_preserves_declarations_not_live_observations() {
        let page = AdministrationExtensionPage {
            id: "project-hosts".into(),
            read_model: "ProjectHostsPageV1".into(),
            version: 1,
            freshness: "registry-live; inventory target-admitted".into(),
            model: json!({ "homes": [{
                "id": "host:one", "home_id": "home:one", "name": "Research",
                "kind": "cloud", "endpoint": "https://example.test",
                "lifecycle": "active", "state": "partial", "repair_hint": null,
                "managed_policy": { "isolated_workspace_enabled": false, "max_attempt_nanos_usd": 0 },
                "projects": [], "execution": { "usage": { "wall_millis": 1 } },
            }] }),
            commands: Vec::new(),
        };
        let basis = page_resource_basis(&page, "tenant");
        let mut observed = page.clone();
        observed.model["homes"][0]["execution"] =
            json!({ "freshness": "unavailable", "usage": null });
        observed.model["homes"][0]["state"] = json!("indeterminate");
        observed.model["homes"][0]["repair_hint"] = json!("Reconnect");
        observed.model["homes"][0]["projects"] =
            json!([{ "id": "project:one", "name": "Research" }]);
        assert_eq!(page_resource_basis(&observed, "tenant"), basis);
        for (field, value) in [
            ("name", json!("Renamed")),
            ("home_id", json!("home:two")),
            ("endpoint", json!("https://other.example.test")),
            ("lifecycle", json!("suspended")),
            (
                "managed_policy",
                json!({ "isolated_workspace_enabled": true, "max_attempt_nanos_usd": 10 }),
            ),
        ] {
            let mut changed = page.clone();
            changed.model["homes"][0][field] = value;
            assert_ne!(page_resource_basis(&changed, "tenant"), basis, "{field}");
        }
        let mut removed = page;
        removed.model["homes"] = json!([]);
        assert_ne!(page_resource_basis(&removed, "tenant"), basis);
    }

    #[tokio::test]
    async fn people_page_runs_the_canonical_membership_and_project_access_lifecycle() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let page = people_page(&app, &session).await;
        assert_eq!(page["model"]["invitation_delivery"], "one-time-link");
        let member_sessions = page["model"]["sessions"].as_array().unwrap();
        assert_eq!(member_sessions.len(), 1);
        assert_eq!(member_sessions[0]["person"]["authority"], "authority:owner");
        assert_eq!(member_sessions[0]["client_label"], "GaugeDesk desktop");
        let session_page = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["id"] == "people")
            .unwrap();
        assert_eq!(
            session_page["commands"],
            json!([
                "people.invitation.create",
                "people.invitation.cancel",
                "people.invitation.resend",
                "people.role.change",
                "people.member.deactivate",
                "people.member.reactivate",
                "project-access.grant",
                "project-access.revoke",
            ])
        );

        let created = apply_people(
            &app,
            &session,
            "people.invitation.create",
            json!({
                "emails": [" MEMBER@example.test ", "second@example.test"],
                "role": "member"
            }),
            "invite-member",
        )
        .await;
        assert_eq!(
            created["result"]["delivery_kind"],
            "organization-invitation"
        );
        let links = created["result"]["delivery_links"].as_array().unwrap();
        assert_eq!(links.len(), 2);
        let first_id = links[0]["invitation_id"].as_str().unwrap().to_owned();
        let first_proof = links[0]["proof"].as_str().unwrap().to_owned();
        let second_id = links[1]["invitation_id"].as_str().unwrap().to_owned();
        {
            let guard = shared.lock().unwrap();
            let org = Org::rebuild(guard.store_ref()).unwrap();
            assert_eq!(org.invitations.len(), 2);
            assert!(org.invitations[&first_id]
                .accepts_proof(&first_proof, gaugedesk_app::account::session_now_ms()));
            let stored = guard
                .store_ref()
                .records(ORG_SCOPE, ORGANIZATION_INVITATION_KIND)
                .unwrap()
                .join("\n");
            assert!(!stored.contains(&first_proof));
        }
        let resent = apply_people(
            &app,
            &session,
            "people.invitation.resend",
            json!({ "id": first_id }),
            "resend-member",
        )
        .await;
        let next_proof = resent["result"]["delivery_links"][0]["proof"]
            .as_str()
            .unwrap();
        assert_ne!(next_proof, first_proof);
        {
            let guard = shared.lock().unwrap();
            let org = Org::rebuild(guard.store_ref()).unwrap();
            let invitation = &org.invitations[&first_id];
            assert!(
                !invitation.accepts_proof(&first_proof, gaugedesk_app::account::session_now_ms())
            );
            assert!(invitation.accepts_proof(next_proof, gaugedesk_app::account::session_now_ms()));
        }
        apply_people(
            &app,
            &session,
            "people.invitation.cancel",
            json!({ "id": second_id }),
            "cancel-member-invitation",
        )
        .await;

        let member = MembershipRecord {
            id: "person:member".into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: "person:member".into(),
            email: "member@example.test".into(),
            role: "member".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        };
        shared
            .lock()
            .unwrap()
            .store_mut()
            .append_record(
                ORG_SCOPE,
                "membership",
                &serde_json::to_string(&member).unwrap(),
            )
            .unwrap();
        apply_people(
            &app,
            &session,
            "people.role.change",
            json!({ "id": "person:member", "role": "viewer" }),
            "change-member-role",
        )
        .await;
        apply_people(
            &app,
            &session,
            "people.member.deactivate",
            json!({ "id": "person:member" }),
            "initial-deactivate-member",
        )
        .await;
        apply_people(
            &app,
            &session,
            "people.member.reactivate",
            json!({ "id": "person:member" }),
            "reactivate-member",
        )
        .await;
        apply_people(
            &app,
            &session,
            "project-access.grant",
            json!({ "authority": "person:member", "project_id": "project:one" }),
            "grant-member-project",
        )
        .await;
        apply_people(
            &app,
            &session,
            "project-access.revoke",
            json!({ "authority": "person:member", "project_id": "project:one" }),
            "revoke-member-project",
        )
        .await;
        apply_people(
            &app,
            &session,
            "people.member.deactivate",
            json!({ "id": "person:member" }),
            "deactivate-member",
        )
        .await;

        let org = Org::rebuild(shared.lock().unwrap().store_ref()).unwrap();
        let member = org.members.get("person:member").unwrap();
        assert_eq!(member.role, "viewer");
        assert_eq!(member.status, MembershipStatus::Deprovisioned);
        assert!(org.grants.is_empty());
    }

    #[tokio::test]
    async fn sessions_page_inspects_and_durably_revokes_only_the_organization_session() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let page = sessions_page(&app, &session).await;
        let rows = page["model"]["sessions"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["person"]["authority"], "authority:owner");
        assert_eq!(rows[0]["client_label"], "GaugeDesk desktop");
        assert_eq!(rows[0]["client"]["version"], "0.4.5");
        assert_eq!(rows[0]["client"]["protocol"], 7);
        assert_eq!(rows[0]["state"], "active");
        assert_eq!(rows[0]["current"], true);
        assert!(rows[0]["id"]
            .as_str()
            .unwrap()
            .starts_with("organization-session:"));
        let grant = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["id"] == "sessions")
            .unwrap();
        assert_eq!(grant["commands"], json!(["organization-session.revoke"]));

        let key = "revoke-organization-session";
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "sessions", "command_id": "organization-session.revoke",
                "expected_basis": page["resource_basis"], "idempotency_key": key,
                "payload": { "id": rows[0]["id"] }, "client": "web",
            }),
            Some(key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        accept(&app, &session, &proposed, key).await;

        let guard = shared.lock().unwrap();
        let org = Org::rebuild(guard.store_ref()).unwrap();
        assert!(org
            .session_revocations
            .contains_key(rows[0]["id"].as_str().unwrap()));
        assert!(guard
            .organization_session_roster_in(gaugedesk_app::org::ORG_SCOPE)
            .unwrap()
            .is_empty());
        assert_eq!(
            guard
                .admin_capabilities(Some("owner-token"), gaugedesk_app::org::ORG_SCOPE)
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert!(!guard
            .admin_capabilities(Some("owner-token-new"), gaugedesk_app::org::ORG_SCOPE,)
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn desktop_web_and_agent_share_the_admission_and_receipt_contract() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let people = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "people")
            .unwrap();
        let mut normalized = Vec::new();
        for client in ["desktop", "web", "agent"] {
            let key = format!("{client}-proposal");
            let envelope = json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "people", "command_id": "people.invitation.create",
                "expected_basis": people["resource_basis"], "idempotency_key": key,
                "payload": { "emails": [format!("{client}@example.test")], "role": "member" }, "client": client,
            });
            let (status, proposed) = request(
                &app,
                Method::POST,
                if client == "agent" {
                    "/gaugeapps/administration/proposals"
                } else {
                    "/gaugeapps/administration/commands"
                },
                envelope,
                Some(&key),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{client}: {proposed}");
            normalized.push(json!({
                "app": proposed["receipt"]["app"],
                "scope": proposed["receipt"]["scope"],
                "page_id": proposed["receipt"]["page_id"],
                "command_id": proposed["receipt"]["command_id"],
                "expected_basis": proposed["receipt"]["expected_basis"],
                "status": proposed["receipt"]["status"],
            }));
        }
        assert!(normalized.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(
            Org::rebuild(shared.lock().unwrap().store_ref())
                .unwrap()
                .invitations
                .len(),
            0,
            "every client opens a proposal; none bypasses human review"
        );
    }

    #[tokio::test]
    async fn command_proposes_review_applies_and_replay_has_one_effect() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let organization = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization")
            .unwrap();
        let envelope = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "page_id": "organization", "command_id": "organization.display-name.set",
            "expected_basis": organization["resource_basis"], "idempotency_key": "proposal-1",
            "payload": { "display_name": "Acme" },
            "client": "web",
        });
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
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

        let change_id = proposed["proposal"]["id"].as_str().unwrap();
        let review_uri = format!("/gaugeapps/administration/proposals/{change_id}/review");
        let review = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "decision": "accept", "client": "web"
        });
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
            "/gaugeapps/administration/commands",
            envelope,
            Some("proposal-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{proposal_replay}");
        assert_eq!(proposal_replay["receipt"]["id"], proposed["receipt"]["id"]);
        assert_eq!(proposal_replay["receipt"]["status"], "proposed");
        assert_eq!(proposal_replay["proposal"]["status"], "applied");
        assert_eq!(
            proposal_replay["proposal"]["receipt_id"],
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
    async fn projects_page_is_summary_only_and_reviewed_creation_resumes_one_home_project() {
        let dir = tempfile::tempdir().unwrap();
        let shared = gaugedesk_app::open_workbench(dir.path()).unwrap();
        {
            let idp = LoopbackIdentityProvider::new().enroll(
                "owner-token",
                AuthorityId::new("authority:owner"),
                AuthorityAttributes::default(),
            );
            let mut guard = shared.lock().unwrap();
            guard.set_identity_provider(Some(Arc::new(idp)));
            guard
                .store_mut()
                .append_record(
                    ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&MembershipRecord {
                        id: "owner".into(),
                        op: RecordOp::Upsert,
                        org_id: ORG_ID.into(),
                        authority: "authority:owner".into(),
                        email: "owner@example.test".into(),
                        role: "owner".into(),
                        status: MembershipStatus::Active,
                        managed_by_scim: false,
                        team: None,
                    })
                    .unwrap(),
                )
                .unwrap();
        }
        let app = routes().with_state(shared.clone());
        let session = open(&app).await;
        let project_grant = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "projects")
            .unwrap();
        assert_eq!(project_grant["commands"], json!(["project.create"]));

        let uri = format!(
            "/gaugeapps/administration/pages/projects?session={}&generation={}&scope={}",
            session["id"].as_str().unwrap(),
            session["generation"].as_str().unwrap(),
            session["scope"]["id"].as_str().unwrap(),
        );
        let (status, before) = request(&app, Method::GET, &uri, Value::Null, None).await;
        assert_eq!(status, StatusCode::OK, "{before}");
        assert_eq!(before["page"]["model"]["state"], "live");
        assert_eq!(before["page"]["model"]["can_create"], true);
        let personal = &before["page"]["model"]["projects"][0];
        assert!(personal.get("placements").is_none(), "{personal}");
        assert!(personal.get("targets").is_none(), "{personal}");
        assert!(personal.get("authority").is_some(), "{personal}");

        let applied = apply_reviewed(
            &app,
            &session,
            "projects",
            "project.create",
            json!({ "name": "Research" }),
            "project-create",
        )
        .await;
        assert_eq!(applied["receipt"]["status"], "applied");
        let project_id = applied["result"]["project"]["id"]
            .as_str()
            .expect("created project id")
            .to_owned();

        let mut guard = shared.lock().unwrap();
        let initial = gaugedesk_app::library_routes::workspace_value(&guard);
        assert_eq!(
            initial["projects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|project| project["id"] == project_id)
                .count(),
            1
        );
        let resumed = gaugedesk_app::library_routes::create_named_project(
            &mut guard,
            &project_id,
            "Research",
        )
        .unwrap();
        assert_eq!(resumed["id"], project_id);
        let after = gaugedesk_app::library_routes::workspace_value(&guard);
        let project = after["projects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|project| project["id"] == project_id)
            .unwrap();
        assert_eq!(project["name"], "Research");
        assert_eq!(project["targets"].as_array().unwrap().len(), 1);
        assert_eq!(
            project["placements"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|placement| placement["is_default"] == true)
                .count(),
            1,
            "resume must not add another built-in placement"
        );
    }

    #[tokio::test]
    async fn scim_issue_returns_plaintext_once_and_persists_only_its_hash() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let identity = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "enterprise-identity")
            .unwrap();
        let envelope = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "page_id": "enterprise-identity", "command_id": "enterprise-identity.scim-credential.issue",
            "expected_basis": identity["resource_basis"], "idempotency_key": "scim-proposal-1",
            "payload": {}, "client": "web",
        });
        let (status, proposed) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
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

        let change_id = proposed["proposal"]["id"].as_str().unwrap();
        let review_uri = format!("/gaugeapps/administration/proposals/{change_id}/review");
        let review = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"],
            "decision": "accept", "client": "web"
        });
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
            .expect("accepted issuance returns the token once")
            .to_owned();
        assert_eq!(token.len(), 64);
        let rows = shared
            .lock()
            .unwrap()
            .store_ref()
            .records("org", "scim_token")
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].contains(&token));
        let stored: ScimTokenRecord = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(stored.token_sha256, sha256_hex(&token));

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

        let session = open(&app).await;
        let rotated = apply_reviewed(
            &app,
            &session,
            "enterprise-identity",
            "enterprise-identity.scim-credential.rotate",
            json!({}),
            "scim-rotate",
        )
        .await;
        let replacement = rotated["result"]["token"]
            .as_str()
            .expect("accepted rotation returns its replacement once");
        assert_ne!(replacement, token);
        let org = Org::rebuild(shared.lock().unwrap().store_ref()).unwrap();
        assert!(!org.scim_token_valid(&token));
        assert!(org.scim_token_valid(replacement));
        assert_eq!(
            shared
                .lock()
                .unwrap()
                .store_ref()
                .records("org", "scim_token")
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn stale_concurrent_change_conflicts_and_revoked_session_fails_closed() {
        let (_dir, shared, app) = test_app();
        let session = open(&app).await;
        let base = session["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|page| page["id"] == "organization")
            .unwrap()["resource_basis"]
            .clone();
        let make = |name: &str, key: &str| {
            json!({
                "session_id": session["id"], "generation": session["generation"],
                "app": "administration", "scope": session["scope"],
                "page_id": "organization", "command_id": "organization.display-name.set",
                "expected_basis": base, "idempotency_key": key,
                "payload": { "display_name": name },
                "client": "desktop"
            })
        };
        let (_, first) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            make("First", "p-first"),
            Some("p-first"),
        )
        .await;
        let (_, second) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            make("Second", "p-second"),
            Some("p-second"),
        )
        .await;
        let first_uri = format!(
            "/gaugeapps/administration/proposals/{}/review",
            first["proposal"]["id"].as_str().unwrap()
        );
        let review = json!({
            "session_id": session["id"], "generation": session["generation"],
            "app": "administration", "scope": session["scope"], "decision": "accept"
        });
        assert_eq!(
            request(&app, Method::POST, &first_uri, review, Some("r-first"))
                .await
                .0,
            StatusCode::OK
        );
        let fresh = open(&app).await;
        let second_uri = format!(
            "/gaugeapps/administration/proposals/{}/review",
            second["proposal"]["id"].as_str().unwrap()
        );
        let review = json!({
            "session_id": fresh["id"], "generation": fresh["generation"],
            "app": "administration", "scope": fresh["scope"], "decision": "accept"
        });
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
        let uri = format!(
            "/gaugeapps/administration/pages/organization?session={}&generation={}&scope=org",
            fresh["id"].as_str().unwrap(),
            fresh["generation"].as_str().unwrap(),
        );
        assert_eq!(
            request(&app, Method::GET, &uri, Value::Null, None).await.0,
            StatusCode::FORBIDDEN
        );
    }
}
