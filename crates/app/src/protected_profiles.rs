//! Protected-commercial Agent placement adapter.
//!
//! The public app owns the interoperable signed contract and ephemeral consumer.
//! A configured commercial service owns entitlement, KMS custody, metering, and
//! audit. Absence of a record is the ordinary open `licensed` profile.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use gaugedesk_core::protected_profile::{
    artifact_digest, issue_authorization_bytes, release_authorization_bytes, sha256_hex,
    IssueAuthorization, ProtectedProfileArtifact, ReleaseAuthorization, SignedIssueAuthorization,
    SignedReleaseAuthorization, PROTECTED_PROFILE_VERSION,
};
use serde::{Deserialize, Serialize};

use crate::library::{RecordOp, LIBRARY_SCOPE};
use crate::{net_http, LockUnpoisoned, SharedWorkbench, Workbench};

const RECORD_KIND: &str = "placement_distribution";
const EXPORT_FORMAT: &str = "gaugedesk-protected-agent-bundle.v1";
const DEFAULT_SERVICE_ORIGIN: &str = "https://auth.gaugewright.com";
const MAX_LEASE_SECONDS: u64 = 31 * 86_400;
const MATERIALIZATION_PREFIX: &str = "gaugedesk-protected-";
const STALE_MATERIALIZATION_AGE: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

// Production peer demand is co-located with the native consumer so the route
// composition gate can prove these non-browser calls still have an exact Cloud
// provider. The paths are templates; the implementation below binds them to a
// selected HTTPS service origin and exact license ids.
// gaugedesk-peer-demand: GET /protected-profiles/issuer
// gaugedesk-peer-demand: POST /protected-profiles/issue
// gaugedesk-peer-demand: POST /protected-profiles/licenses/:license/renew
// gaugedesk-peer-demand: POST /protected-profiles/unwrap
// gaugedesk-peer-demand: POST /protected-profiles/licenses/:license/revoke
// gaugedesk-peer-demand: GET /protected-profiles/licenses/:license/audit

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistributionProfile {
    #[default]
    Licensed,
    ProtectedCommercial,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtectedRelease {
    pub signed_issue: SignedIssueAuthorization,
    pub artifact: ProtectedProfileArtifact,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementDistributionRecord {
    pub placement_id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub profile: DistributionProfile,
    #[serde(default)]
    pub owner_authority: String,
    #[serde(default)]
    pub recipient_authority: String,
    /// Human label selected by the owner. Authority remains the security key;
    /// this is display-only and may never substitute for it.
    #[serde(default)]
    pub recipient_display_name: String,
    #[serde(default = "default_service_origin")]
    pub service_origin: String,
    #[serde(default)]
    pub lease_seconds: u64,
    #[serde(default)]
    pub max_runs: u64,
    #[serde(default)]
    pub release: Option<ProtectedRelease>,
    #[serde(default)]
    pub revoked: bool,
}

fn default_service_origin() -> String {
    DEFAULT_SERVICE_ORIGIN.to_owned()
}

#[derive(Debug, Deserialize)]
pub struct PutDistributionRequest {
    pub profile: DistributionProfile,
    #[serde(default)]
    pub recipient_authority: String,
    #[serde(default)]
    pub recipient_display_name: String,
    #[serde(default)]
    pub lease_seconds: u64,
    #[serde(default)]
    pub max_runs: u64,
    #[serde(default)]
    pub service_origin: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DistributionStatus {
    pub placement_id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub revision: String,
    pub profile: DistributionProfile,
    pub owner_authority: String,
    pub owner_root_pubkey: Option<String>,
    pub recipient_authority: String,
    pub recipient_display_name: String,
    pub recipient_root_pubkey: Option<String>,
    pub service_origin: String,
    pub lease_seconds: u64,
    pub max_runs: u64,
    pub state: &'static str,
    pub license_id: Option<String>,
    pub attribution_id: Option<String>,
    pub expires_at: Option<u64>,
    pub plaintext_sha256: Option<String>,
    pub artifact_sha256: Option<String>,
    pub protection_blob_sha256: Option<String>,
    pub issuer_authority: Option<String>,
    pub can_manage: bool,
}

/// Secret-free contract copied into an engagement invitation so the recipient
/// can consent before any project content moves. `release_digest` is the frozen
/// package reference until a protected artifact exists, then the signed artifact
/// digest. Neither form contains Agent body bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistributionOfferSummary {
    pub placement_id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub revision: String,
    pub release_digest: String,
    pub profile: DistributionProfile,
    pub owner_authority: String,
    pub recipient_authority: String,
    pub recipient_display_name: String,
    pub lease_seconds: u64,
    pub max_runs: u64,
    pub expires_at: Option<u64>,
}

pub(crate) fn project_distribution_offers(
    wb: &Workbench,
    project: &str,
) -> Vec<DistributionOfferSummary> {
    let mut offers = wb
        .library
        .instances
        .values()
        .filter(|instance| instance.project_id.as_deref() == Some(project))
        .filter_map(|instance| {
            let agent = wb.library.agents.get(&instance.agent_id)?;
            let version = agent.versions.get(&instance.version)?;
            let record = distribution_for(wb.store_ref(), &instance.id);
            let release = record.as_ref().and_then(|record| record.release.as_ref());
            let claims = release.map(|release| &release.artifact.claims);
            Some(DistributionOfferSummary {
                placement_id: instance.id.clone(),
                agent_id: agent.id.clone(),
                agent_name: agent.name.clone(),
                revision: instance.version.to_string(),
                release_digest: release
                    .map(|release| artifact_digest(&release.artifact))
                    .unwrap_or_else(|| version.package_ref.clone()),
                profile: record
                    .as_ref()
                    .map(|record| record.profile.clone())
                    .unwrap_or_default(),
                owner_authority: record
                    .as_ref()
                    .map(|record| record.owner_authority.clone())
                    .filter(|authority| !authority.is_empty())
                    .unwrap_or_else(|| wb.federation_authority().as_str().to_owned()),
                recipient_authority: record
                    .as_ref()
                    .map(|record| record.recipient_authority.clone())
                    .unwrap_or_default(),
                recipient_display_name: record
                    .as_ref()
                    .map(|record| record.recipient_display_name.clone())
                    .unwrap_or_default(),
                lease_seconds: record
                    .as_ref()
                    .map(|record| record.lease_seconds)
                    .unwrap_or(0),
                max_runs: record.as_ref().map(|record| record.max_runs).unwrap_or(0),
                expires_at: claims.map(|claims| claims.expires_at),
            })
        })
        .collect::<Vec<_>>();
    offers.sort_by(|left, right| left.agent_name.cmp(&right.agent_name));
    offers
}

fn distribution_status(wb: &Workbench, record: &PlacementDistributionRecord) -> DistributionStatus {
    let instance = wb.library.instances.get(&record.placement_id);
    let agent = instance.and_then(|instance| wb.library.agents.get(&instance.agent_id));
    let claims = record
        .release
        .as_ref()
        .map(|release| &release.artifact.claims);
    DistributionStatus {
        placement_id: record.placement_id.clone(),
        agent_id: instance
            .map(|instance| instance.agent_id.clone())
            .unwrap_or_default(),
        agent_name: agent
            .map(|agent| agent.name.clone())
            .unwrap_or_else(|| "Agent".to_owned()),
        revision: claims
            .map(|claims| claims.revision.clone())
            .or_else(|| instance.map(|instance| instance.version.to_string()))
            .unwrap_or_default(),
        profile: record.profile.clone(),
        owner_authority: if record.owner_authority.is_empty() {
            wb.federation_authority().as_str().to_owned()
        } else {
            record.owner_authority.clone()
        },
        owner_root_pubkey: claims.map(|claims| claims.owner_root_pubkey.clone()),
        recipient_authority: record.recipient_authority.clone(),
        recipient_display_name: record.recipient_display_name.clone(),
        recipient_root_pubkey: claims.map(|claims| claims.recipient_root_pubkey.clone()),
        service_origin: record.service_origin.clone(),
        lease_seconds: record.lease_seconds,
        max_runs: record.max_runs,
        state: match (&record.profile, &record.release) {
            (DistributionProfile::Licensed, _) => "licensed",
            (DistributionProfile::ProtectedCommercial, None) => "awaiting_issue",
            (DistributionProfile::ProtectedCommercial, Some(_)) if record.revoked => "revoked",
            (DistributionProfile::ProtectedCommercial, Some(_))
                if claims.is_some_and(|claims| claims.expires_at <= now_secs()) =>
            {
                "expired"
            }
            (DistributionProfile::ProtectedCommercial, Some(_)) => "issued",
        },
        license_id: claims.map(|claims| claims.license_id.clone()),
        attribution_id: claims.map(|claims| claims.attribution_id.clone()),
        expires_at: claims.map(|claims| claims.expires_at),
        plaintext_sha256: claims.map(|claims| claims.plaintext_sha256.clone()),
        artifact_sha256: record
            .release
            .as_ref()
            .map(|release| artifact_digest(&release.artifact)),
        protection_blob_sha256: claims.map(|claims| claims.protection_blob_sha256.clone()),
        issuer_authority: claims.map(|claims| claims.issuer_authority.clone()),
        can_manage: operator_may_manage(wb, &record.placement_id),
    }
}

pub fn distribution_for(
    store: &gaugedesk_store::Store,
    placement: &str,
) -> Option<PlacementDistributionRecord> {
    store
        .records(LIBRARY_SCOPE, RECORD_KIND)
        .ok()?
        .into_iter()
        .filter_map(|row| serde_json::from_str::<PlacementDistributionRecord>(&row).ok())
        .rfind(|record| record.placement_id == placement)
        .filter(|record| record.op != RecordOp::Tombstone)
}

fn write_distribution(
    wb: &mut Workbench,
    record: &PlacementDistributionRecord,
) -> Result<(), String> {
    let payload = serde_json::to_string(record).map_err(|error| error.to_string())?;
    wb.store_mut()
        .append_record(LIBRARY_SCOPE, RECORD_KIND, &payload)
        .map(|_| ())
        .map_err(|error| format!("store placement distribution: {error:?}"))
}

fn operator_may_manage(wb: &Workbench, placement: &str) -> bool {
    let Some(project) = wb
        .library
        .instances
        .get(placement)
        .and_then(|instance| instance.project_id.as_deref())
    else {
        return false;
    };
    crate::federation::distribution_operator_authorized(
        wb.store_ref(),
        project,
        wb.federation_authority().as_str(),
    )
}

pub async fn get_distribution(
    State(wb): State<SharedWorkbench>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let guard = wb.lock_unpoisoned();
    if !guard.library.instances.contains_key(&id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no such placement" })),
        )
            .into_response();
    }
    let status =
        distribution_for(guard.store_ref(), &id).unwrap_or_else(|| PlacementDistributionRecord {
            placement_id: id,
            op: RecordOp::Upsert,
            profile: DistributionProfile::Licensed,
            owner_authority: String::new(),
            recipient_authority: String::new(),
            recipient_display_name: String::new(),
            service_origin: default_service_origin(),
            lease_seconds: 0,
            max_runs: 0,
            release: None,
            revoked: false,
        });
    let status = distribution_status(&guard, &status);
    (StatusCode::OK, Json(serde_json::to_value(status).unwrap())).into_response()
}

pub async fn put_distribution(
    State(wb): State<SharedWorkbench>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<PutDistributionRequest>,
) -> impl IntoResponse {
    let owner_authority = headers
        .get("x-gaugewright-tenant")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_owned();
    let service_origin = request
        .service_origin
        .unwrap_or_else(default_service_origin)
        .trim_end_matches('/')
        .to_owned();
    if request.profile == DistributionProfile::ProtectedCommercial
        && (owner_authority.is_empty()
            || request.recipient_authority.trim().is_empty()
            || request.lease_seconds == 0
            || request.lease_seconds > MAX_LEASE_SECONDS
            || !valid_origin(&service_origin))
    {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
            "error": "protected commercial distribution requires exact owner and recipient tenants, an HTTPS service origin, and a lease of at most 31 days"
        }))).into_response();
    }
    let mut guard = wb.lock_unpoisoned();
    let Some(instance) = guard.library.instances.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no such placement" })),
        )
            .into_response();
    };
    if instance.project_id.is_none() {
        return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "distribution profiles apply to project placements, not authoring targets" }))).into_response();
    }
    if !operator_may_manage(&guard, &id) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "only the active Agent operator may change distribution" }))).into_response();
    }
    let record = PlacementDistributionRecord {
        placement_id: id,
        op: RecordOp::Upsert,
        profile: request.profile,
        owner_authority,
        recipient_authority: request.recipient_authority.trim().to_owned(),
        recipient_display_name: request.recipient_display_name.trim().to_owned(),
        service_origin,
        lease_seconds: request.lease_seconds,
        max_runs: request.max_runs,
        release: None,
        revoked: false,
    };
    match write_distribution(&mut guard, &record) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::to_value(distribution_status(&guard, &record)).unwrap()),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
    }
}

fn forwarded_session(headers: &HeaderMap) -> Vec<(String, String)> {
    net_http::bearer(headers)
        .map(|token| vec![("Authorization".to_owned(), format!("Bearer {token}"))])
        .unwrap_or_default()
}

pub async fn renew_distribution(
    State(wb): State<SharedWorkbench>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let mut guard = wb.lock_unpoisoned();
    if !operator_may_manage(&guard, &id) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "only the active Agent operator may renew distribution" }))).into_response();
    }
    let Some(record) = distribution_for(guard.store_ref(), &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "placement has no protected release" })),
        )
            .into_response();
    };
    let Some(release) = record.release.as_ref() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "protected placement has not been issued" })),
        )
            .into_response();
    };
    let peer_root = release.artifact.claims.recipient_root_pubkey.clone();
    let license = release.artifact.claims.license_id.clone();
    match issue_placement_release(&mut guard, &id, &peer_root, record, Some(&license)) {
        Ok(record) => (
            StatusCode::OK,
            Json(serde_json::to_value(distribution_status(&guard, &record)).unwrap()),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
    }
}

pub async fn revoke_distribution(
    State(wb): State<SharedWorkbench>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut guard = wb.lock_unpoisoned();
    if !operator_may_manage(&guard, &id) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "only the active Agent operator may revoke distribution" }))).into_response();
    }
    let Some(mut record) = distribution_for(guard.store_ref(), &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "placement has no protected release" })),
        )
            .into_response();
    };
    let Some(release) = record.release.as_ref() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "protected placement has not been issued" })),
        )
            .into_response();
    };
    let license = release.artifact.claims.license_id.clone();
    let response = net_http::HttpClient::new().post_json_headers(
        &format!(
            "{}/protected-profiles/licenses/{license}/revoke",
            record.service_origin
        ),
        &forwarded_session(&headers),
        "{}",
    );
    match response {
        Ok((status, _)) if (200..300).contains(&status) => {
            record.revoked = true;
            match write_distribution(&mut guard, &record) {
                Ok(()) => (
                    StatusCode::OK,
                    Json(serde_json::to_value(distribution_status(&guard, &record)).unwrap()),
                )
                    .into_response(),
                Err(error) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": error })),
                )
                    .into_response(),
            }
        }
        Ok((status, _)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(serde_json::json!({ "error": "protected-profile service refused revocation" })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
    }
}

pub async fn get_distribution_audit(
    State(wb): State<SharedWorkbench>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let guard = wb.lock_unpoisoned();
    if !operator_may_manage(&guard, &id) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "only the active Agent operator may read commercial audit" }))).into_response();
    }
    let Some(record) = distribution_for(guard.store_ref(), &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "placement has no protected release" })),
        )
            .into_response();
    };
    let Some(release) = record.release.as_ref() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "protected placement has not been issued" })),
        )
            .into_response();
    };
    let license = &release.artifact.claims.license_id;
    match net_http::HttpClient::new().get_string_headers(
        &format!(
            "{}/protected-profiles/licenses/{license}/audit",
            record.service_origin
        ),
        &forwarded_session(&headers),
    ) {
        Ok((status, body)) if (200..300).contains(&status) => match serde_json::from_str::<
            serde_json::Value,
        >(&body)
        {
            Ok(value) => (StatusCode::OK, Json(value)).into_response(),
            Err(_) => (
                StatusCode::BAD_GATEWAY,
                Json(
                    serde_json::json!({ "error": "protected-profile audit response is malformed" }),
                ),
            )
                .into_response(),
        },
        Ok((status, _)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(serde_json::json!({ "error": "protected-profile service refused audit access" })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
    }
}

fn valid_origin(origin: &str) -> bool {
    origin.starts_with("https://")
        && !origin[8..].is_empty()
        && !origin[8..].contains('/')
        && !origin.contains('?')
        && !origin.contains('#')
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PackageFile {
    path: String,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProtectedAgentBundle {
    version: u8,
    config: String,
    package_ref: String,
    package: Vec<PackageFile>,
    discipline: Vec<PackageFile>,
}

fn collect_files(root: &Path) -> Result<Vec<PackageFile>, String> {
    fn walk(root: &Path, directory: &Path, out: &mut Vec<PackageFile>) -> Result<(), String> {
        for entry in std::fs::read_dir(directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            let path = entry.path();
            if kind.is_symlink() {
                return Err("protected package cannot contain symbolic links".to_owned());
            }
            if kind.is_dir() {
                walk(root, &path, out)?;
            } else if kind.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|error| error.to_string())?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(PackageFile {
                    path: relative,
                    bytes: std::fs::read(&path).map_err(|error| error.to_string())?,
                });
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn bundle_for_placement(wb: &Workbench, placement: &str) -> Result<Vec<u8>, String> {
    let instance = wb
        .library
        .instances
        .get(placement)
        .ok_or_else(|| "protected placement is unavailable".to_owned())?;
    let agent = wb
        .library
        .agents
        .get(&instance.agent_id)
        .ok_or_else(|| "protected Agent is unavailable".to_owned())?;
    let target = wb
        .library
        .authoring_target_for(&agent.id)
        .ok_or_else(|| "protected Agent authoring target is unavailable".to_owned())?;
    let version = agent
        .versions
        .get(&instance.version)
        .ok_or_else(|| "protected Agent version is unavailable".to_owned())?;
    let package_root = crate::library_state::published_package_root(
        &wb.targets_dir(),
        &target.id,
        instance.version,
    );
    let discipline_root = crate::library_state::published_discipline_root(
        &wb.targets_dir(),
        &target.id,
        instance.version,
    );
    serde_json::to_vec(&ProtectedAgentBundle {
        version: 1,
        config: agent.config.clone(),
        package_ref: version.package_ref.clone(),
        package: collect_files(&package_root)?,
        discipline: collect_files(&discipline_root)?,
    })
    .map_err(|error| error.to_string())
}

#[derive(Deserialize)]
struct IssuerDocument {
    version: u8,
    authority: String,
    public_key: String,
    service_origin: String,
}

#[derive(Serialize)]
struct IssueRequest<'a> {
    signed_authorization: &'a SignedIssueAuthorization,
    package: &'a [u8],
}

fn issue_placement_release(
    wb: &mut Workbench,
    placement: &str,
    peer_root: &str,
    mut record: PlacementDistributionRecord,
    renew_license: Option<&str>,
) -> Result<PlacementDistributionRecord, String> {
    let instance = wb
        .library
        .instances
        .get(placement)
        .ok_or_else(|| "protected placement is unavailable".to_owned())?;
    let agent_id = instance.agent_id.clone();
    let version = instance.version;
    let package = bundle_for_placement(wb, placement)?;
    let issuer_body = net_http::HttpClient::new().get_string(&format!(
        "{}/protected-profiles/issuer",
        record.service_origin
    ))?;
    let issuer: IssuerDocument = serde_json::from_str(&issuer_body)
        .map_err(|error| format!("protected issuer document is malformed: {error}"))?;
    if issuer.version != PROTECTED_PROFILE_VERSION
        || issuer.service_origin != record.service_origin
        || issuer.public_key.is_empty()
    {
        return Err("protected issuer identity does not match the selected service".to_owned());
    }
    let now = now_secs();
    let authorization = IssueAuthorization {
        version: PROTECTED_PROFILE_VERSION,
        request_id: crate::library::gen_id(if renew_license.is_some() {
            "protected-renew"
        } else {
            "protected-issue"
        }),
        profile_id: placement.to_owned(),
        agent_id,
        revision: version.to_string(),
        owner_authority: record.owner_authority.clone(),
        owner_root_pubkey: wb.governance_public_key().as_str().to_owned(),
        issuer_authority: issuer.authority,
        issuer_pubkey: issuer.public_key,
        service_origin: issuer.service_origin,
        recipient_authority: record.recipient_authority.clone(),
        recipient_root_pubkey: peer_root.to_owned(),
        plaintext_sha256: sha256_hex(&package),
        export_format: EXPORT_FORMAT.to_owned(),
        authorized_at: now,
        authorization_expires_at: now + 300,
        lease_expires_at: now + record.lease_seconds,
        max_runs: record.max_runs,
    };
    let signed_issue = SignedIssueAuthorization {
        owner_signature: wb.sign_governance_payload(&issue_authorization_bytes(&authorization)),
        authorization,
    };
    let body = serde_json::to_string(&IssueRequest {
        signed_authorization: &signed_issue,
        package: &package,
    })
    .map_err(|error| error.to_string())?;
    let path = renew_license
        .map(|license| format!("/protected-profiles/licenses/{license}/renew"))
        .unwrap_or_else(|| "/protected-profiles/issue".to_owned());
    let (status, response) = net_http::HttpClient::new().post_json_headers(
        &format!("{}{}", record.service_origin, path),
        &[],
        &body,
    )?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "protected issuer refused placement {placement}: HTTP {status}"
        ));
    }
    let artifact: ProtectedProfileArtifact = serde_json::from_str(&response)
        .map_err(|error| format!("protected issuer returned a malformed artifact: {error}"))?;
    record.release = Some(ProtectedRelease {
        signed_issue,
        artifact,
    });
    record.revoked = false;
    write_distribution(wb, &record)?;
    Ok(record)
}

/// Resolve every explicitly protected placement before a handoff snapshot is
/// collected. Licensed placements do nothing. The exact paired peer root is
/// bound by the owner's governance signature and the issuer artifact.
pub(crate) fn prepare_project_relocation(
    wb: &mut Workbench,
    project: &str,
    peer_root: &str,
) -> Result<(), String> {
    let project_instances = wb
        .library
        .instances
        .values()
        .filter(|instance| instance.project_id.as_deref() == Some(project))
        .collect::<Vec<_>>();
    for agent in project_instances.iter().map(|instance| &instance.agent_id) {
        let profiles = project_instances
            .iter()
            .filter(|instance| instance.agent_id == *agent)
            .map(|instance| {
                distribution_for(wb.store_ref(), &instance.id)
                    .map(|record| record.profile)
                    .unwrap_or_default()
            })
            .collect::<std::collections::BTreeSet<_>>();
        if profiles.len() > 1 {
            return Err(format!(
                "Agent {agent} has mixed licensed and protected placements in this project; choose one explicit profile before relocation"
            ));
        }
    }
    let placements = wb
        .library
        .instances
        .values()
        .filter(|instance| instance.project_id.as_deref() == Some(project))
        .filter_map(|instance| {
            distribution_for(wb.store_ref(), &instance.id)
                .filter(|record| record.profile == DistributionProfile::ProtectedCommercial)
                .map(|record| {
                    (
                        instance.id.clone(),
                        instance.agent_id.clone(),
                        instance.version,
                        record,
                    )
                })
        })
        .collect::<Vec<_>>();
    for (placement, _agent_id, _version, record) in placements {
        if record.release.as_ref().is_some_and(|release| {
            release.artifact.claims.recipient_root_pubkey == peer_root
                && release.artifact.claims.recipient_authority == record.recipient_authority
                && release.artifact.claims.expires_at > now_secs()
        }) {
            continue;
        }
        issue_placement_release(wb, &placement, peer_root, record, None)?;
    }
    Ok(())
}

pub(crate) struct PreparedProtectedPackage {
    _directory: tempfile::TempDir,
    pub package_root: PathBuf,
    pub package_ref: String,
    pub config: String,
}

/// Best-effort startup cleanup for plaintext left by a process crash. Live
/// materializations are younger than the conservative age bound and remain
/// owned by their `TempDir` guard; only directories carrying our exact prefix
/// are candidates.
pub(crate) fn scavenge_stale_materializations() {
    scavenge_stale_materializations_in(&std::env::temp_dir(), std::time::SystemTime::now());
}

fn scavenge_stale_materializations_in(parent: &Path, now: std::time::SystemTime) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(MATERIALIZATION_PREFIX) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if now.duration_since(modified).unwrap_or_default() >= STALE_MATERIALIZATION_AGE {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

fn safe_destination(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("protected package contains an unsafe path".to_owned());
    }
    Ok(root.join(path))
}

fn materialize_files(root: &Path, files: &[PackageFile]) -> Result<(), String> {
    for file in files {
        let destination = safe_destination(root, &file.path)?;
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        std::fs::write(destination, &file.bytes).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[derive(Serialize)]
struct UnwrapRequest<'a> {
    artifact: &'a ProtectedProfileArtifact,
    signed_authorization: &'a SignedReleaseAuthorization,
}

#[derive(Deserialize)]
struct UnwrapResponse {
    package: Vec<u8>,
}

pub(crate) fn prepare_chat_package(
    wb: &Workbench,
    chat_id: &str,
) -> Result<Option<PreparedProtectedPackage>, String> {
    let Some(chat) = wb.library.chats.get(chat_id) else {
        return Ok(None);
    };
    let Some(record) = distribution_for(wb.store_ref(), &chat.instance_id) else {
        return Ok(None);
    };
    if record.profile == DistributionProfile::Licensed {
        return Ok(None);
    }
    let release = record
        .release
        .ok_or_else(|| "protected placement has not been issued for this Home".to_owned())?;
    if release.artifact.claims.recipient_root_pubkey != wb.governance_public_key().as_str() {
        return Err("protected placement is bound to another Home root".to_owned());
    }
    let now = now_secs();
    let authorization = ReleaseAuthorization {
        version: PROTECTED_PROFILE_VERSION,
        request_id: crate::library::gen_id("protected-release"),
        license_id: release.artifact.claims.license_id.clone(),
        artifact_sha256: artifact_digest(&release.artifact),
        recipient_root_pubkey: wb.governance_public_key().as_str().to_owned(),
        issued_at: now,
        expires_at: now + 120,
        nonce: crate::library::gen_id("nonce"),
    };
    let signed_authorization = SignedReleaseAuthorization {
        recipient_signature: wb
            .sign_governance_payload(&release_authorization_bytes(&authorization)),
        authorization,
    };
    let body = serde_json::to_string(&UnwrapRequest {
        artifact: &release.artifact,
        signed_authorization: &signed_authorization,
    })
    .map_err(|error| error.to_string())?;
    let (status, response) = net_http::HttpClient::new().post_json_headers(
        &format!("{}/protected-profiles/unwrap", record.service_origin),
        &[],
        &body,
    )?;
    if !(200..300).contains(&status) {
        return Err(format!("protected release was refused: HTTP {status}"));
    }
    let response: UnwrapResponse = serde_json::from_str(&response)
        .map_err(|error| format!("protected release response is malformed: {error}"))?;
    let bundle: ProtectedAgentBundle = serde_json::from_slice(&response.package)
        .map_err(|error| format!("protected Agent package is malformed: {error}"))?;
    if bundle.version != 1 || bundle.package_ref.is_empty() {
        return Err("protected Agent package version is unsupported".to_owned());
    }
    let directory = tempfile::Builder::new()
        .prefix(MATERIALIZATION_PREFIX)
        .tempdir()
        .map_err(|error| error.to_string())?;
    let package_root = directory.path().join("package");
    let discipline_root = directory.path().join("discipline");
    materialize_files(&package_root, &bundle.package)?;
    materialize_files(&discipline_root, &bundle.discipline)?;
    let engagement = wb
        .engagements
        .get(chat_id)
        .ok_or_else(|| "protected chat target candidate is unavailable".to_owned())?;
    let mount = engagement
        .path()
        .join(gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT)
        .join("discipline");
    if mount.exists() {
        std::fs::remove_dir_all(&mount).map_err(|error| error.to_string())?;
    }
    materialize_files(&mount, &bundle.discipline)?;
    Ok(Some(PreparedProtectedPackage {
        _directory: directory,
        package_root,
        package_ref: bundle.package_ref,
        config: bundle.config,
    }))
}

pub(crate) fn distribution_records_for_placements(
    store: &gaugedesk_store::Store,
    placements: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    let mut latest = BTreeMap::new();
    for payload in store
        .records(LIBRARY_SCOPE, RECORD_KIND)
        .unwrap_or_default()
    {
        if let Ok(record) = serde_json::from_str::<PlacementDistributionRecord>(&payload) {
            if placements.contains(&record.placement_id) {
                latest.insert(record.placement_id, payload);
            }
        }
    }
    latest.into_values().collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_record_is_licensed_and_paths_fail_closed() {
        let store = gaugedesk_store::Store::open_in_memory().unwrap();
        assert!(distribution_for(&store, "placement").is_none());
        assert!(safe_destination(Path::new("/tmp/root"), "agent.toml").is_ok());
        assert!(safe_destination(Path::new("/tmp/root"), "../secret").is_err());
        assert!(safe_destination(Path::new("/tmp/root"), "/etc/passwd").is_err());
    }

    #[test]
    fn startup_scavenging_only_removes_old_protected_directories() {
        use std::time::{Duration, SystemTime};

        let parent = tempfile::tempdir().unwrap();
        let old = parent.path().join(format!("{MATERIALIZATION_PREFIX}old"));
        let recent = parent
            .path()
            .join(format!("{MATERIALIZATION_PREFIX}recent"));
        let unrelated = parent.path().join("unrelated-old");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&recent).unwrap();
        std::fs::create_dir_all(&unrelated).unwrap();
        scavenge_stale_materializations_in(parent.path(), SystemTime::UNIX_EPOCH);

        assert!(old.exists());
        assert!(recent.exists());
        assert!(unrelated.exists());

        let future = SystemTime::now() + STALE_MATERIALIZATION_AGE + Duration::from_secs(1);
        scavenge_stale_materializations_in(parent.path(), future);

        assert!(!old.exists());
        assert!(!recent.exists());
        assert!(unrelated.exists());
    }
}
