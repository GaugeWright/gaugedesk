//! Ordinary person-to-project Home invitations (`HOME-4`, ADR 0084).
//!
//! This is deliberately not peer federation. A Home owner creates an opaque,
//! authority-bound capability for one project. The invited person authenticates
//! with their free account directly to that Home; acceptance atomically activates
//! the Home-local member and project grant, then mints the replaceable Home
//! admission used by ordinary work routes. The Hub receives only the resulting
//! opaque `{project, home_id, endpoint}` route from the browser.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use gaugedesk_core::rbac::Capability;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::account::RecordOp;
use crate::org::{
    is_valid_role, MemberGrantRecord, MembershipRecord, MembershipStatus, Org, ORG_ID, ORG_SCOPE,
};
use crate::{library, net_http, LockUnpoisoned, SharedWorkbench};

const INVITATION_KIND: &str = "home_invitation";
const INVITATION_VERSION: u32 = 1;
const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Said when the inviting Home has no endpoint and is reached only through the
/// relay. desk's `RELAY_ONLY_INVITATION` says the same before asking, so a
/// client that checks first and one that does not read alike.
const RELAY_ONLY_REFUSAL: &str = "this project is on a computer that others reach only \
    through the relay, which does not yet admit invited people; move the project to a \
    hosted Home to share it";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InvitationStatus {
    Pending,
    Accepted,
    /// Withdrawn by whoever may invite to its project; it admits no one.
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HomeInvitationRecord {
    id: String,
    #[serde(default)]
    op: RecordOp,
    invited_authority: String,
    project: String,
    home_id: String,
    endpoint: String,
    role: String,
    expires_at: u64,
    token_sha256: String,
    status: InvitationStatus,
    /// An email invitation's normalized address (DR-0332). Its
    /// `invited_authority` is empty until an account holding the address as a
    /// verified email accepts it, and is that account afterwards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invited_email: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InvitationEnvelope {
    version: u32,
    invitation: String,
    invited_authority: String,
    project: String,
    home_id: String,
    endpoint: String,
    secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invited_email: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateInvitationBody {
    #[serde(default)]
    authority: String,
    /// An address instead of an account (DR-0332). Exactly one of the two is
    /// named.
    #[serde(default)]
    email: Option<String>,
    project: String,
    #[serde(default = "member_role")]
    role: String,
    endpoint: String,
    #[serde(default)]
    expires_in_secs: Option<u64>,
}

fn member_role() -> String {
    "member".to_owned()
}

#[derive(Deserialize)]
pub struct AcceptInvitationBody {
    invite: String,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn token_hash(secret: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());
    hex::encode(digest.as_ref())
}

fn encode_envelope(envelope: &InvitationEnvelope) -> Result<String, serde_json::Error> {
    serde_json::to_vec(envelope).map(hex::encode)
}

fn decode_envelope(encoded: &str) -> Option<InvitationEnvelope> {
    let bytes = hex::decode(encoded).ok()?;
    let envelope: InvitationEnvelope = serde_json::from_slice(&bytes).ok()?;
    (envelope.version == INVITATION_VERSION).then_some(envelope)
}

pub(crate) fn invitation_url(encoded: &str) -> String {
    let console = gaugedesk_env::var("CONSOLE_URL")
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| "https://desk.gaugewright.com".to_owned());
    format!("{}/invite?d={encoded}", console.trim_end_matches('/'))
}

fn latest_invitation(store: &gaugedesk_store::Store, id: &str) -> Option<HomeInvitationRecord> {
    store
        .records(ORG_SCOPE, INVITATION_KIND)
        .ok()?
        .into_iter()
        .filter_map(|payload| serde_json::from_str::<HomeInvitationRecord>(&payload).ok())
        .rfind(|record| record.id == id)
}

fn json_error(status: StatusCode, message: &'static str) -> axum::response::Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Refuse anyone who may not invite to `project` on this Home, which is also
/// who may see, cancel and send again its pending invitations.
fn inviter_refusal(
    wb: &crate::Workbench,
    headers: &HeaderMap,
    project: &str,
) -> Option<axum::response::Response> {
    // On a desktop the project's owner invites into it; a role in the
    // computer's directory is not needed (DR-0268 §1, DR-0328 §4).
    let owner_invites = wb.desktop_account_mode()
        && net_http::bearer(headers).is_some()
        && wb.owns_project(project)
        && wb.project_owner_refusal(headers, project).is_none()
        && wb.pairing_actor(headers).is_some_and(|actor| {
            wb.project_owner(project) == Some(crate::project_owner::ProjectOwner::Account(actor))
        });
    if !owner_invites {
        if let Err((status, message)) =
            wb.authorize(net_http::bearer(headers), Some(Capability::ManageMembers))
        {
            return Some(json_error(status, message));
        }
    }
    if !wb.owns_project(project) {
        return Some(json_error(
            StatusCode::NOT_FOUND,
            "project is not on this Home",
        ));
    }
    wb.project_owner_refusal(headers, project)
}

/// For an email invitation, the organization whose policy decides it, or
/// `None` for a project an account owns, which is always open (DR-0332). The
/// Personal project is never shared.
fn email_invitation_owner(
    wb: &crate::Workbench,
    project: &str,
    by_email: bool,
) -> Result<Option<String>, (StatusCode, &'static str)> {
    if !by_email {
        return Ok(None);
    }
    let Some(record) = wb.library.projects.get(project) else {
        return Err((StatusCode::NOT_FOUND, "project is not on this Home"));
    };
    if record.is_default {
        return Err((StatusCode::FORBIDDEN, "Personal cannot be shared"));
    }
    Ok(wb
        .project_organization(record)
        .filter(|organization| organization.starts_with("organization:"))
        .map(str::to_owned))
}

/// Refuse an email invitation to `organization`'s project unless the
/// organization lets anyone be invited, asked of the account authority now
/// with the inviter's own sign-in. Not being able to ask is a refusal.
async fn organization_sharing_refusal(
    shared: &SharedWorkbench,
    headers: &HeaderMap,
    organization: &str,
    hub: Option<String>,
) -> Option<axum::response::Response> {
    let bearer = net_http::bearer(headers)
        .map(str::to_owned)
        .or_else(|| crate::account_signin::hub_session_token(shared));
    let (Some(hub), Some(bearer)) = (hub, bearer) else {
        return Some(json_error(
            StatusCode::CONFLICT,
            "sign in to the account service to invite by email",
        ));
    };
    let organization = organization.to_owned();
    let asked = tokio::task::spawn_blocking(move || {
        crate::account_signin::organization_project_sharing_at(&hub, &bearer, &organization)
    })
    .await;
    match asked {
        Ok(Ok(crate::org::ProjectSharing::Anyone)) => None,
        Ok(Ok(crate::org::ProjectSharing::Members)) => Some(json_error(
            StatusCode::FORBIDDEN,
            "this organization shares its projects only with its members; an owner can change that in Organization Policy",
        )),
        Ok(Err(_)) | Err(_) => Some(json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "could not confirm the organization's sharing policy; try again",
        )),
    }
}

/// Owner/admin: mint and durably hash an authority-bound invitation. Membership
/// and project access remain unchanged until acceptance commits all three facts.
/// No content, project name, or provider credential leaves the Home.
pub async fn post_invitation(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<CreateInvitationBody>,
) -> axum::response::Response {
    create_invitation(wb, headers, body, crate::account_signin::hub_base()).await
}

async fn create_invitation(
    shared: SharedWorkbench,
    headers: HeaderMap,
    body: CreateInvitationBody,
    hub: Option<String>,
) -> axum::response::Response {
    let email = match body.email.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(raw) => match crate::account_auth::normalize_email_contact(raw) {
            Some(email) => Some(email),
            None => {
                return json_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "a valid email address is required",
                )
            }
        },
    };
    if body.authority.trim().is_empty() == email.is_none() {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invite either an account or an email address",
        );
    }
    // A Home with no endpoint of its own is reached only through the relay,
    // and the relay admits only accounts signed in on its computer (DR-0328
    // §6), not a project's invited members (DR-0332, WS-587). An invitation
    // minted here could never be accepted, so say why instead of sending a
    // link that fails for the person it is for.
    if body.endpoint.trim().is_empty() {
        return json_error(StatusCode::CONFLICT, RELAY_ONLY_REFUSAL);
    }
    if body.project.trim().is_empty()
        || !crate::account_routes::secure_home_endpoint(&body.endpoint)
        || !is_valid_role(&body.role)
        || matches!(
            body.role.as_str(),
            "owner" | "admin" | "auditor" | "billing"
        )
    {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "valid invite fields required",
        );
    }
    let ttl = body.expires_in_secs.unwrap_or(DEFAULT_TTL_SECS);
    if ttl == 0 || ttl > MAX_TTL_SECS {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid invitation lifetime",
        );
    }

    let authority = body.authority.trim().to_owned();
    let organization = {
        let wb = shared.lock_unpoisoned();
        if let Some(refusal) = inviter_refusal(&wb, &headers, &body.project) {
            return refusal;
        }
        match email_invitation_owner(&wb, &body.project, email.is_some()) {
            Ok(organization) => organization,
            Err((status, message)) => return json_error(status, message),
        }
    };
    if let Some(organization) = organization {
        if let Some(refusal) =
            organization_sharing_refusal(&shared, &headers, &organization, hub).await
        {
            return refusal;
        }
    }
    let mut wb = shared.lock_unpoisoned();
    if !wb.owns_project(&body.project) {
        return json_error(StatusCode::NOT_FOUND, "project is not on this Home");
    }

    let id = library::gen_id("hinv");
    let secret = hex::encode(crate::session::random_bytes::<32>());
    let endpoint = body.endpoint.trim_end_matches('/').to_owned();
    let home_id = wb.home_id().as_str().to_owned();
    let record = HomeInvitationRecord {
        id: id.clone(),
        op: RecordOp::Upsert,
        invited_authority: authority.clone(),
        project: body.project.clone(),
        home_id: home_id.clone(),
        endpoint: endpoint.clone(),
        role: body.role.clone(),
        expires_at: now_secs().saturating_add(ttl),
        token_sha256: token_hash(&secret),
        status: InvitationStatus::Pending,
        invited_email: email.clone(),
    };
    let record_json = serde_json::to_string(&record).expect("invitation serializes");
    if let Err(error) =
        wb.store_mut()
            .append_records_atomically(&[(ORG_SCOPE, INVITATION_KIND, &record_json)])
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("could not persist invitation: {error:?}") })),
        )
            .into_response();
    }
    let envelope = InvitationEnvelope {
        version: INVITATION_VERSION,
        invitation: id,
        invited_authority: authority,
        project: body.project,
        home_id,
        endpoint,
        secret,
        invited_email: email,
    };
    let encoded = match encode_envelope(&envelope) {
        Ok(encoded) => encoded,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "could not encode invite"),
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "invite": encoded,
            "url": invitation_url(&encoded),
            "home_id": envelope.home_id,
            "project": envelope.project,
            "endpoint": envelope.endpoint,
            "expires_at": record.expires_at,
        })),
    )
        .into_response()
}

/// Invitee: authenticate ordinary account identity, validate the exact
/// authority-bound capability, atomically activate membership+grant+invite, and
/// mint a replaceable Home session. Repeating a completed acceptance is
/// idempotent and mints a fresh session so a lost HTTP response is recoverable.
/// An email invitation is bound to the accepting account first, once the
/// account authority confirms that account holds the address (DR-0332).
pub async fn post_accept_invitation(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<AcceptInvitationBody>,
) -> axum::response::Response {
    accept_invitation(wb, headers, body, crate::account_signin::hub_base()).await
}

/// The capability matches the record and this Home, and the invitation is
/// addressed to `actor` or, for an email invitation still pending, to whoever
/// holds its address.
fn invitation_matches(
    wb: &crate::Workbench,
    envelope: &InvitationEnvelope,
    record: &HomeInvitationRecord,
    actor: &str,
) -> bool {
    // Comparing fixed-size SHA-256 digests leaks no useful prefix of the random
    // capability (the digest is not itself accepted and has 256-bit preimage work).
    let hash_matches = token_hash(&envelope.secret) == record.token_sha256;
    let addressed = match &record.invited_email {
        None => record.invited_authority == actor && envelope.invited_authority == actor,
        Some(email) => {
            envelope.invited_email.as_deref() == Some(email.as_str())
                && (record.status == InvitationStatus::Pending || record.invited_authority == actor)
        }
    };
    hash_matches
        && addressed
        && envelope.project == record.project
        && envelope.home_id == record.home_id
        && envelope.endpoint == record.endpoint
        && envelope.home_id == wb.home_id().as_str()
}

/// A link that was cancelled, or replaced by sending the invitation again,
/// says so to whoever holds it rather than reading as someone else's.
fn withdrawn_refusal(
    envelope: &InvitationEnvelope,
    record: &HomeInvitationRecord,
) -> Option<axum::response::Response> {
    if record.status == InvitationStatus::Cancelled {
        return Some(json_error(
            StatusCode::GONE,
            "this invitation was cancelled",
        ));
    }
    if record.status == InvitationStatus::Pending
        && token_hash(&envelope.secret) != record.token_sha256
    {
        return Some(json_error(
            StatusCode::GONE,
            "this invitation link was replaced by a newer one",
        ));
    }
    None
}

async fn accept_invitation(
    shared: SharedWorkbench,
    headers: HeaderMap,
    body: AcceptInvitationBody,
    hub: Option<String>,
) -> axum::response::Response {
    let Some(envelope) = decode_envelope(&body.invite) else {
        return json_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid Home invitation");
    };
    let (actor, email_to_confirm) = {
        let wb = shared.lock_unpoisoned();
        let actor = match wb.authenticate_identity(net_http::bearer(&headers)) {
            Ok(actor) => actor,
            Err((status, message)) => return json_error(status, message),
        };
        let Some(record) = latest_invitation(wb.store_ref(), &envelope.invitation) else {
            return json_error(StatusCode::NOT_FOUND, "invitation is unknown");
        };
        if let Some(refusal) = withdrawn_refusal(&envelope, &record) {
            return refusal;
        }
        if !invitation_matches(&wb, &envelope, &record, actor.as_str()) {
            return json_error(
                StatusCode::FORBIDDEN,
                "invitation does not match this identity and Home",
            );
        }
        let pending = record.status == InvitationStatus::Pending;
        if pending && record.expires_at <= now_secs() {
            return json_error(StatusCode::GONE, "invitation has expired");
        }
        (actor, record.invited_email.filter(|_| pending))
    };
    if let Some(email) = email_to_confirm {
        if let Some(refusal) = email_refusal(&headers, actor.as_str(), &email, hub).await {
            return refusal;
        }
    }

    let mut wb = shared.lock_unpoisoned();
    // Read again: another account may have taken an email invitation while
    // the account authority was asked.
    let Some(record) = latest_invitation(wb.store_ref(), &envelope.invitation) else {
        return json_error(StatusCode::NOT_FOUND, "invitation is unknown");
    };
    if let Some(refusal) = withdrawn_refusal(&envelope, &record) {
        return refusal;
    }
    if !invitation_matches(&wb, &envelope, &record, actor.as_str()) {
        return json_error(
            StatusCode::FORBIDDEN,
            "invitation does not match this identity and Home",
        );
    }
    if record.status == InvitationStatus::Pending && record.expires_at <= now_secs() {
        return json_error(StatusCode::GONE, "invitation has expired");
    }
    if record.status == InvitationStatus::Pending {
        let mut accepted = record.clone();
        accepted.status = InvitationStatus::Accepted;
        accepted.invited_authority = actor.as_str().to_owned();
        let org = match Org::rebuild(wb.store_ref()) {
            Ok(org) => org,
            Err(_) => {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "directory unavailable")
            }
        };
        // A project invitation must never demote an existing active owner/admin.
        // New people receive the invitation's narrow role; existing active people
        // retain their directory identity and gain only the explicit project grant.
        let member = org
            .member_by_authority(actor.as_str())
            .filter(|member| member.status == MembershipStatus::Active)
            .cloned()
            .unwrap_or_else(|| MembershipRecord {
                id: actor.as_str().to_owned(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.to_owned(),
                authority: actor.as_str().to_owned(),
                email: record.invited_email.clone().unwrap_or_default(),
                role: record.role.clone(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            });
        let grant = MemberGrantRecord {
            id: MemberGrantRecord::make_id(actor.as_str(), &record.project),
            op: RecordOp::Upsert,
            authority: actor.as_str().to_owned(),
            project_id: record.project.clone(),
        };
        let accepted_json = serde_json::to_string(&accepted).expect("invitation serializes");
        let member_json = serde_json::to_string(&member).expect("membership serializes");
        let grant_json = serde_json::to_string(&grant).expect("grant serializes");
        if let Err(error) = wb.store_mut().append_records_atomically(&[
            (ORG_SCOPE, INVITATION_KIND, &accepted_json),
            (ORG_SCOPE, "membership", &member_json),
            (ORG_SCOPE, "member_grant", &grant_json),
        ]) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("could not accept invitation: {error:?}") })),
            )
                .into_response();
        }
        if let Err(error) = wb.ensure_shipped_tutorials() {
            tracing::warn!(%error, "new member's Tutorials project was not reconciled");
        }
    }
    let home = wb.home_id().clone();
    let admission = wb.home_admissions.open(home.clone(), actor);
    (
        StatusCode::OK,
        Json(json!({
            "home_id": home.as_str(),
            "project": record.project,
            "endpoint": record.endpoint,
            "admission": admission.encode(),
        })),
    )
        .into_response()
}

/// Refuse to bind an email invitation unless the account authority says the
/// account presenting this bearer is `actor` and holds `email` verified.
async fn email_refusal(
    headers: &HeaderMap,
    actor: &str,
    email: &str,
    hub: Option<String>,
) -> Option<axum::response::Response> {
    let (Some(hub), Some(bearer)) = (hub, net_http::bearer(headers).map(str::to_owned)) else {
        return Some(json_error(
            StatusCode::UNAUTHORIZED,
            "sign in with your GaugeWright account to accept this invitation",
        ));
    };
    let email = email.to_owned();
    let standing = tokio::task::spawn_blocking(move || {
        crate::account_identity::hub_email_standing(&hub, &bearer, &email)
    })
    .await;
    use crate::account_identity::EmailStanding;
    match standing {
        Ok(Ok(EmailStanding::Holds { account })) if account == actor => None,
        Ok(Ok(EmailStanding::Holds { .. } | EmailStanding::DoesNotHold { .. })) => {
            Some(json_error(
                StatusCode::FORBIDDEN,
                "this invitation is for an email address your account has not verified",
            ))
        }
        Ok(Ok(EmailStanding::Unrecognised)) => Some(json_error(
            StatusCode::UNAUTHORIZED,
            "sign in with your GaugeWright account to accept this invitation",
        )),
        Ok(Err(_)) | Err(_) => Some(json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "could not confirm your email address; try again",
        )),
    }
}

/// Every invitation's current record, latest per id.
fn current_invitations(store: &gaugedesk_store::Store) -> Vec<HomeInvitationRecord> {
    let mut latest = std::collections::BTreeMap::new();
    for record in store
        .records(ORG_SCOPE, INVITATION_KIND)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|payload| serde_json::from_str::<HomeInvitationRecord>(&payload).ok())
    {
        latest.insert(record.id.clone(), record);
    }
    latest.into_values().collect()
}

/// `GET /home/projects/{project}/invitations` — the project's invitations
/// still waiting to be accepted (DR-0332). It names whom each is for, never
/// its link: the Home keeps only a hash of that.
pub async fn get_project_invitations(
    State(wb): State<SharedWorkbench>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    let wb = wb.lock_unpoisoned();
    if let Some(refusal) = inviter_refusal(&wb, &headers, &project) {
        return refusal;
    }
    let now = now_secs();
    let mut pending: Vec<_> = current_invitations(wb.store_ref())
        .into_iter()
        .filter(|record| {
            record.project == project
                && record.status == InvitationStatus::Pending
                && record.expires_at > now
        })
        .collect();
    pending.sort_by_key(|record| record.expires_at);
    let invitations: Vec<_> = pending
        .iter()
        .map(|record| {
            json!({
                "id": record.id,
                "authority": record.invited_authority,
                "email": record.invited_email,
                "role": record.role,
                "expires_at": record.expires_at,
            })
        })
        .collect();
    Json(json!({ "invitations": invitations })).into_response()
}

/// The pending invitation `id`, once its inviter is allowed to manage it.
fn pending_for_inviter(
    wb: &crate::Workbench,
    headers: &HeaderMap,
    id: &str,
) -> Result<HomeInvitationRecord, Box<axum::response::Response>> {
    // A caller who may not see the project learns nothing about the id.
    let record = latest_invitation(wb.store_ref(), id)
        .ok_or_else(|| Box::new(json_error(StatusCode::NOT_FOUND, "invitation is unknown")))?;
    if let Some(refusal) = inviter_refusal(wb, headers, &record.project) {
        return Err(Box::new(refusal));
    }
    if record.status != InvitationStatus::Pending {
        return Err(Box::new(json_error(
            StatusCode::CONFLICT,
            "this invitation is no longer pending",
        )));
    }
    Ok(record)
}

fn persist_invitation(
    wb: &mut crate::Workbench,
    record: &HomeInvitationRecord,
) -> Option<axum::response::Response> {
    let record_json = serde_json::to_string(record).expect("invitation serializes");
    let error = wb
        .store_mut()
        .append_records_atomically(&[(ORG_SCOPE, INVITATION_KIND, &record_json)])
        .err()?;
    Some(
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("could not persist invitation: {error:?}") })),
        )
            .into_response(),
    )
}

/// `POST /home/invitations/{id}/cancel` — withdraw a pending invitation. Its
/// link then admits no one.
pub async fn post_cancel_invitation(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    let mut wb = wb.lock_unpoisoned();
    let mut record = match pending_for_inviter(&wb, &headers, &id) {
        Ok(record) => record,
        Err(refusal) => return *refusal,
    };
    record.status = InvitationStatus::Cancelled;
    persist_invitation(&mut wb, &record).unwrap_or_else(|| StatusCode::NO_CONTENT.into_response())
}

/// `POST /home/invitations/{id}/resend` — a fresh link for the same person,
/// project and role, with a fresh lifetime. The Home keeps only one hash, so
/// the earlier link stops working.
pub async fn post_resend_invitation(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    let mut wb = wb.lock_unpoisoned();
    let mut record = match pending_for_inviter(&wb, &headers, &id) {
        Ok(record) => record,
        Err(refusal) => return *refusal,
    };
    let secret = hex::encode(crate::session::random_bytes::<32>());
    record.token_sha256 = token_hash(&secret);
    record.expires_at = now_secs().saturating_add(DEFAULT_TTL_SECS);
    if let Some(refusal) = persist_invitation(&mut wb, &record) {
        return refusal;
    }
    let envelope = InvitationEnvelope {
        version: INVITATION_VERSION,
        invitation: record.id.clone(),
        invited_authority: record.invited_authority.clone(),
        project: record.project.clone(),
        home_id: record.home_id.clone(),
        endpoint: record.endpoint.clone(),
        secret,
        invited_email: record.invited_email.clone(),
    };
    let Ok(encoded) = encode_envelope(&envelope) else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "could not encode invite");
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "invite": encoded,
            "url": invitation_url(&encoded),
            "home_id": envelope.home_id,
            "project": envelope.project,
            "endpoint": envelope.endpoint,
            "expires_at": record.expires_at,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::ids::AuthorityId;

    use crate::home_admission::HOME_ADMISSION_HEADER;
    use crate::identity::LoopbackIdentityProvider;
    use crate::{home_routes, local_routes, open_workbench};

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        admission: Option<&str>,
        body: Option<&str>,
    ) -> (StatusCode, String) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        if let Some(admission) = admission {
            request = request.header(HOME_ADMISSION_HEADER, admission);
        }
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let response = app
            .clone()
            .oneshot(
                request
                    .body(body.map_or_else(Body::empty, |value| Body::from(value.to_owned())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[test]
    fn invitation_envelope_round_trips_and_rejects_garbage() {
        let envelope = InvitationEnvelope {
            version: INVITATION_VERSION,
            invitation: "hinv-1".to_owned(),
            invited_authority: "alice".to_owned(),
            project: "proj-1".to_owned(),
            home_id: "home:owner".to_owned(),
            endpoint: "https://home.example".to_owned(),
            secret: "redacted-capability".to_owned(),
            invited_email: None,
        };
        let encoded = encode_envelope(&envelope).unwrap();
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded.invitation, envelope.invitation);
        assert_eq!(decoded.home_id, envelope.home_id);
        assert!(decode_envelope("not-an-invite").is_none());
    }

    const OPEN_ORG: &str = "organization:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CLOSED_ORG: &str = "organization:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A Home with an owner, two other accounts, a project the owner owns and
    /// one project for each of an open and a members-only organization.
    fn email_fixture() -> (tempfile::TempDir, SharedWorkbench) {
        let dir = tempfile::tempdir().unwrap();
        let wb = open_workbench(dir.path()).unwrap();
        {
            let mut guard = wb.lock_unpoisoned();
            guard.set_identity_provider(Some(Arc::new(
                LoopbackIdentityProvider::new()
                    .enroll(
                        "owner-login",
                        AuthorityId::new("owner"),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        "invitee-login",
                        AuthorityId::new("invitee"),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        "other-login",
                        AuthorityId::new("other"),
                        AuthorityAttributes::default(),
                    ),
            )));
            let owner = MembershipRecord {
                id: "owner".to_owned(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.to_owned(),
                authority: "owner".to_owned(),
                email: "owner@example.test".to_owned(),
                role: "owner".to_owned(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            };
            guard
                .store_mut()
                .append_record(
                    ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&owner).unwrap(),
                )
                .unwrap();
            let mut mine = std::collections::BTreeMap::new();
            crate::project_owner::record_owner(&mut mine, "owner");
            crate::library_routes::create_named_project_with_extra(
                &mut guard,
                "proj-mine",
                "Mine",
                mine,
            )
            .unwrap();
            for (id, organization) in [("proj-open", OPEN_ORG), ("proj-closed", CLOSED_ORG)] {
                crate::library_routes::create_named_project_with_extra(
                    &mut guard,
                    id,
                    id,
                    std::collections::BTreeMap::from([(
                        "organization".to_owned(),
                        serde_json::Value::String(organization.to_owned()),
                    )]),
                )
                .unwrap();
            }
        }
        (dir, wb)
    }

    /// An account authority on loopback: `invitee` holds the invited address,
    /// `other` holds none, and the two organizations answer their policies.
    async fn stub_account_authority() -> (String, tokio::task::JoinHandle<()>) {
        use axum::extract::Path;
        use axum::routing::get;
        let app = Router::new()
            .route(
                "/account/identity",
                get(|headers: HeaderMap| async move {
                    let account = match net_http::bearer(&headers) {
                        Some("invitee-login") => "invitee",
                        Some("other-login") => "other",
                        _ => return StatusCode::UNAUTHORIZED.into_response(),
                    };
                    let asked = headers
                        .get(crate::account_identity::VERIFIED_EMAIL_HEADER)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default();
                    Json(json!({
                        "account": account,
                        "holds_email": account == "invitee" && asked == "invitee@example.test",
                    }))
                    .into_response()
                }),
            )
            .route(
                "/account/tenants/{tenant}/project-share-candidates",
                get(
                    |Path(tenant): Path<String>, headers: HeaderMap| async move {
                        assert_eq!(headers["x-gaugewright-tenant"], tenant.as_str());
                        assert_eq!(headers["authorization"], "Bearer owner-login");
                        let sharing = if tenant == OPEN_ORG {
                            "anyone"
                        } else {
                            "members"
                        };
                        Json(json!({ "candidates": [], "sharing": sharing }))
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hub = format!("http://{}", listener.local_addr().unwrap());
        let service = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (hub, service)
    }

    fn signed_in(login: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {login}").parse().unwrap());
        headers
    }

    async fn invite(
        wb: &SharedWorkbench,
        body: serde_json::Value,
        hub: Option<String>,
    ) -> (StatusCode, serde_json::Value) {
        let body: CreateInvitationBody = serde_json::from_value(body).unwrap();
        let response = create_invitation(wb.clone(), signed_in("owner-login"), body, hub).await;
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn accept(
        wb: &SharedWorkbench,
        login: &str,
        invite: &str,
        hub: Option<String>,
    ) -> (StatusCode, serde_json::Value) {
        let body = AcceptInvitationBody {
            invite: invite.to_owned(),
        };
        let response = accept_invitation(wb.clone(), signed_in(login), body, hub).await;
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    fn by_email(project: &str) -> serde_json::Value {
        json!({
            "email": " Invitee@Example.test ",
            "project": project,
            "role": "member",
            "endpoint": "https://owner-home.example",
        })
    }

    async fn body_of(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn pending(wb: &SharedWorkbench, login: &str) -> (StatusCode, serde_json::Value) {
        body_of(
            get_project_invitations(
                State(wb.clone()),
                Path("proj-mine".to_owned()),
                signed_in(login),
            )
            .await,
        )
        .await
    }

    #[tokio::test]
    async fn pending_invitations_are_listed_cancelled_and_sent_again() {
        let (_dir, wb) = email_fixture();
        let (_, by_account) = invite(
            &wb,
            json!({ "authority": "invitee", "project": "proj-mine",
                    "endpoint": "https://owner-home.example" }),
            None,
        )
        .await;
        let (_, by_address) = invite(&wb, by_email("proj-mine"), None).await;
        let first_link = by_account["invite"].as_str().unwrap().to_owned();
        let account_id = decode_envelope(&first_link).unwrap().invitation;
        let address_id = decode_envelope(by_address["invite"].as_str().unwrap())
            .unwrap()
            .invitation;

        let (status, listed) = pending(&wb, "owner-login").await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        let rows = listed["invitations"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|row| row["email"] == "invitee@example.test" && row["authority"] == ""));
        assert!(
            !listed.to_string().contains("secret") && !listed.to_string().contains("invite?d=")
        );
        let (refused, _) = pending(&wb, "other-login").await;
        assert_eq!(refused, StatusCode::FORBIDDEN);

        // Sending again replaces the link: the old one is refused, the new
        // one admits.
        let (status, resent) = body_of(
            post_resend_invitation(
                State(wb.clone()),
                Path(account_id.clone()),
                signed_in("owner-login"),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{resent}");
        let (replaced, body) = accept(&wb, "invitee-login", &first_link, None).await;
        assert_eq!(replaced, StatusCode::GONE, "{body}");
        assert!(body["error"].as_str().unwrap().contains("replaced"));
        let (accepted, body) = accept(
            &wb,
            "invitee-login",
            resent["invite"].as_str().unwrap(),
            None,
        )
        .await;
        assert_eq!(accepted, StatusCode::OK, "{body}");

        // Cancelling withdraws it; it cannot be cancelled or sent again twice.
        let cancel = |login: &'static str| {
            post_cancel_invitation(
                State(wb.clone()),
                Path(address_id.clone()),
                signed_in(login),
            )
        };
        assert_eq!(cancel("other-login").await.status(), StatusCode::FORBIDDEN);
        assert_eq!(cancel("owner-login").await.status(), StatusCode::NO_CONTENT);
        assert_eq!(cancel("owner-login").await.status(), StatusCode::CONFLICT);
        let (cancelled, body) = accept(
            &wb,
            "invitee-login",
            by_address["invite"].as_str().unwrap(),
            None,
        )
        .await;
        assert_eq!(cancelled, StatusCode::GONE, "{body}");
        let resend_accepted = post_resend_invitation(
            State(wb.clone()),
            Path(account_id),
            signed_in("owner-login"),
        )
        .await;
        assert_eq!(resend_accepted.status(), StatusCode::CONFLICT);

        let (_, listed) = pending(&wb, "owner-login").await;
        assert_eq!(listed["invitations"], json!([]));
    }

    #[tokio::test]
    async fn an_email_invitation_binds_the_account_that_holds_the_address() {
        let (_dir, wb) = email_fixture();
        let (hub, service) = stub_account_authority().await;
        let (status, created) = invite(&wb, by_email("proj-mine"), Some(hub.clone())).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let encoded = created["invite"].as_str().unwrap().to_owned();

        let (refused, body) = accept(&wb, "other-login", &encoded, Some(hub.clone())).await;
        assert_eq!(refused, StatusCode::FORBIDDEN, "{body}");
        let (unreachable, _) = accept(&wb, "invitee-login", &encoded, None).await;
        assert_eq!(unreachable, StatusCode::UNAUTHORIZED);

        let (accepted, body) = accept(&wb, "invitee-login", &encoded, Some(hub.clone())).await;
        assert_eq!(accepted, StatusCode::OK, "{body}");
        {
            let guard = wb.lock_unpoisoned();
            let org = Org::rebuild(guard.store_ref()).unwrap();
            assert!(org.can_access_project("invitee", "proj-mine"));
            assert!(!org.can_access_project("other", "proj-mine"));
            let member = org.member_by_authority("invitee").unwrap();
            assert_eq!(member.email, "invitee@example.test");
            let record = latest_invitation(
                guard.store_ref(),
                &decode_envelope(&encoded).unwrap().invitation,
            )
            .unwrap();
            assert_eq!(record.invited_authority, "invitee");
        }

        // Taken: nobody else can use it, and its holder may repeat it.
        let (taken, _) = accept(&wb, "other-login", &encoded, Some(hub.clone())).await;
        assert_eq!(taken, StatusCode::FORBIDDEN);
        let (again, body) = accept(&wb, "invitee-login", &encoded, Some(hub)).await;
        assert_eq!(again, StatusCode::OK, "{body}");
        service.abort();
    }

    #[tokio::test]
    async fn an_organization_project_takes_email_invitations_only_when_it_allows() {
        let (_dir, wb) = email_fixture();
        let (hub, service) = stub_account_authority().await;
        let (open, body) = invite(&wb, by_email("proj-open"), Some(hub.clone())).await;
        assert_eq!(open, StatusCode::CREATED, "{body}");
        let (closed, body) = invite(&wb, by_email("proj-closed"), Some(hub)).await;
        assert_eq!(closed, StatusCode::FORBIDDEN, "{body}");
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("Organization Policy"));
        service.abort();

        let (unconfigured, _) = invite(&wb, by_email("proj-open"), None).await;
        assert_eq!(unconfigured, StatusCode::CONFLICT);
        let (unreachable, _) = invite(
            &wb,
            by_email("proj-open"),
            Some("http://127.0.0.1:9".into()),
        )
        .await;
        assert_eq!(unreachable, StatusCode::SERVICE_UNAVAILABLE);
        // A member chosen from the roster needs no policy and no Hub.
        let (addressed, body) = invite(
            &wb,
            json!({
                "authority": "invitee",
                "project": "proj-closed",
                "endpoint": "https://owner-home.example",
            }),
            None,
        )
        .await;
        assert_eq!(addressed, StatusCode::CREATED, "{body}");
    }

    #[tokio::test]
    async fn an_email_invitation_names_one_valid_address_and_never_personal() {
        let (_dir, wb) = email_fixture();
        let endpoint = "https://owner-home.example";
        for (body, expected) in [
            (by_email(crate::DEFAULT_PROJECT), StatusCode::FORBIDDEN),
            (
                json!({ "authority": "invitee", "email": "invitee@example.test",
                        "project": "proj-mine", "endpoint": endpoint }),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                json!({ "project": "proj-mine", "endpoint": endpoint }),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                json!({ "email": "not an address", "project": "proj-mine", "endpoint": endpoint }),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let (status, response) = invite(&wb, body.clone(), None).await;
            assert_eq!(status, expected, "{body} -> {response}");
        }
    }

    /// A desktop Home reached only through its relay sends an empty endpoint.
    /// The relay does not yet admit invited members (WS-587), so the Home says
    /// so plainly and mints nothing, rather than a link that cannot be accepted
    /// or the generic field refusal it used to give.
    #[tokio::test]
    async fn a_relay_only_home_refuses_to_mint_an_invitation_it_cannot_honour() {
        let (_dir, wb) = email_fixture();
        for body in [
            json!({ "email": "invitee@example.test", "project": "proj-mine", "endpoint": "" }),
            json!({ "authority": "invitee", "project": "proj-mine", "endpoint": "  " }),
        ] {
            let (status, response) = invite(&wb, body.clone(), None).await;
            assert_eq!(status, StatusCode::CONFLICT, "{body} -> {response}");
            assert_eq!(response["error"], RELAY_ONLY_REFUSAL, "{body}");
        }
        assert!(
            current_invitations(wb.lock_unpoisoned().store_ref()).is_empty(),
            "a refused invitation leaves no record behind"
        );
        // An endpoint that is present but not secure is still a malformed field.
        let (status, _) = invite(
            &wb,
            json!({ "authority": "invitee", "project": "proj-mine",
                    "endpoint": "http://owner-home.example" }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn free_account_accepts_on_owner_home_revokes_and_resumes_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let wb = open_workbench(dir.path()).unwrap();
        let owner = AuthorityId::new("owner");
        let invitee = AuthorityId::new("invitee");
        let owner_admission = {
            let mut guard = wb.lock_unpoisoned();
            guard.set_identity_provider(Some(Arc::new(
                LoopbackIdentityProvider::new()
                    .enroll("owner-login", owner.clone(), AuthorityAttributes::default())
                    .enroll(
                        "invitee-login",
                        invitee.clone(),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        "wrong-login",
                        AuthorityId::new("wrong"),
                        AuthorityAttributes::default(),
                    ),
            )));
            let owner_member = MembershipRecord {
                id: owner.as_str().to_owned(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.to_owned(),
                authority: owner.as_str().to_owned(),
                email: "owner@example.test".to_owned(),
                role: "owner".to_owned(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            };
            guard
                .store_mut()
                .append_record(
                    ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&owner_member).unwrap(),
                )
                .unwrap();
            let home = guard.home_id().clone();
            guard.home_admissions.open(home, owner.clone()).encode()
        };
        let auth_wb = wb.clone();
        let app = local_routes::routes(false)
            .merge(home_routes::routes())
            .route_layer(middleware::from_fn_with_state(
                auth_wb,
                home_routes::require_home_admission,
            ))
            .with_state(wb.clone());

        let create_body = json!({
            "authority": invitee.as_str(),
            "project": crate::DEFAULT_PROJECT,
            "role": "member",
            "endpoint": "https://owner-home.example",
        })
        .to_string();
        let (status, created) = call(
            &app,
            "POST",
            "/home/invitations",
            Some("owner-login"),
            Some(&owner_admission),
            Some(&create_body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let created: serde_json::Value = serde_json::from_str(&created).unwrap();
        let encoded = created["invite"].as_str().unwrap();
        let envelope = decode_envelope(encoded).unwrap();
        let stored = wb
            .lock_unpoisoned()
            .store_ref()
            .records(ORG_SCOPE, INVITATION_KIND)
            .unwrap();
        assert!(!stored.join("").contains(&envelope.secret));
        let staged_org = Org::rebuild(wb.lock_unpoisoned().store_ref()).unwrap();
        assert!(staged_org.role_of(invitee.as_str()).is_none());
        assert!(!staged_org.can_access_project(invitee.as_str(), crate::DEFAULT_PROJECT));

        let accept_body = json!({ "invite": encoded }).to_string();
        let (wrong, _) = call(
            &app,
            "POST",
            "/home/invitations/accept",
            Some("wrong-login"),
            None,
            Some(&accept_body),
        )
        .await;
        assert_eq!(wrong, StatusCode::FORBIDDEN);

        let (accepted, body) = call(
            &app,
            "POST",
            "/home/invitations/accept",
            Some("invitee-login"),
            None,
            Some(&accept_body),
        )
        .await;
        assert_eq!(accepted, StatusCode::OK, "{body}");
        let accepted: serde_json::Value = serde_json::from_str(&body).unwrap();
        let first_admission = accepted["admission"].as_str().unwrap().to_owned();
        {
            let guard = wb.lock_unpoisoned();
            let org = Org::rebuild(guard.store_ref()).unwrap();
            assert_eq!(org.role_of(invitee.as_str()).unwrap().as_str(), "member");
            assert!(org.can_access_project(invitee.as_str(), crate::DEFAULT_PROJECT));
            assert!(guard
                .admit_data_request(Some("invitee-login"), Some(crate::DEFAULT_PROJECT))
                .is_ok());
            assert!(guard
                .admit_data_request(Some("invitee-login"), Some("proj-not-granted"))
                .is_err());
        }

        let (home_ok, _) = call(
            &app,
            "GET",
            "/workspace",
            Some("invitee-login"),
            Some(&first_admission),
            None,
        )
        .await;
        assert_eq!(home_ok, StatusCode::OK);
        let (revoked, _) = call(
            &app,
            "DELETE",
            "/home/admissions",
            Some("invitee-login"),
            Some(&first_admission),
            None,
        )
        .await;
        assert_eq!(revoked, StatusCode::NO_CONTENT);
        let (old, _) = call(
            &app,
            "GET",
            "/workspace",
            Some("invitee-login"),
            Some(&first_admission),
            None,
        )
        .await;
        assert_eq!(old, StatusCode::FORBIDDEN);

        drop(app);
        drop(wb);
        let reopened = open_workbench(dir.path()).unwrap();
        reopened
            .lock_unpoisoned()
            .set_identity_provider(Some(Arc::new(LoopbackIdentityProvider::new().enroll(
                "invitee-login",
                invitee,
                AuthorityAttributes::default(),
            ))));
        let reopened_app = home_routes::routes().with_state(reopened.clone());
        let (resumed, body) = call(
            &reopened_app,
            "POST",
            "/home/admissions",
            Some("invitee-login"),
            None,
            None,
        )
        .await;
        assert_eq!(resumed, StatusCode::CREATED, "{body}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_ne!(body["admission"].as_str().unwrap(), first_admission);
        assert!(reopened
            .lock_unpoisoned()
            .admit_data_request(Some("invitee-login"), Some(crate::DEFAULT_PROJECT))
            .is_ok());
    }
}
