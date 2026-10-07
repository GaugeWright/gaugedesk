//! Hosted data routes under the office-controlled healthcare profile
//! (`specs/experience/office-healthcare.md`, GaugeWright DR-0186, DR-0395, WS-426).
//!
//! An organization enrolled in the office profile keeps patient work on
//! office-controlled systems. The hosted service still signs its staff in, but
//! every hosted route that could carry work, content-derived metadata, or
//! PHI-bearing free text is refused for it — on the server, so a stale or
//! modified client cannot restore the route by sending the request anyway.
//!
//! This module is the inventory and the decision, in one place:
//!
//! - [`INVENTORY`] names every hosted route family the specification lists,
//!   its disposition under the profile, and where (or whether) it is enforced
//!   today. A test refuses a family that is missing or listed twice.
//! - The organization's enrollment is the one binding record the office
//!   profile already defines ([`crate::office_profile`], DR-0371), read here
//!   from the organization's directory scope with that module's fold. It is
//!   one-way: a tombstone or a later record cannot take an organization back
//!   out of the profile, because a project that has held PHI cannot silently
//!   leave it.
//! - [`refusal`] classifies a request path and answers whether it must be
//!   refused. The Hub's enterprise admission layer calls it for every
//!   authenticated request, so the routes it names are refused whichever
//!   router mounted them.
//!
//! A client flag, a resource `regulated` label, or a person's analytics
//! preference cannot create or remove the profile; only the enrollment record
//! in the organization's own directory scope does.

use std::borrow::Cow;

use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use gaugedesk_store::{AdmitError, Store};

pub use crate::office_profile::{OfficeProfileRecord, OFFICE_PROFILE_KIND};

use crate::office_profile::fold_office_profile;
use crate::org::{tenant_scope, RecordOp, ORG_ID};

/// One family of hosted routes named by the office profile's specification.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum HostedRouteFamily {
    /// Hosted account sign-in: workforce identity, authentication, membership
    /// and entitlement facts.
    AccountSignIn,
    /// Essential software update delivery.
    SoftwareUpdate,
    /// Ordinary product analytics events.
    ProductAnalytics,
    /// Hosted dictation (speech transcription).
    Dictation,
    /// The public relay transport between a client and a Home.
    PublicRelay,
    /// The public directory transport.
    DirectoryTransport,
    /// Published or previewed public Panels.
    PanelPublication,
    /// A GaugeWright-hosted Home.
    HostedHome,
    /// Hosted backup of a Home.
    HostedBackup,
    /// Managed inference brokered by the hosted service.
    ManagedInference,
    /// Organization model-provider credentials custodied by the hosted service.
    CredentialBroker,
    /// Crash report upload.
    CrashReport,
    /// Remote diagnostic upload.
    DiagnosticUpload,
    /// Support upload carrying a user's free text or attachments.
    SupportUpload,
}

impl HostedRouteFamily {
    /// Every family, in inventory order.
    pub const ALL: [HostedRouteFamily; 14] = [
        HostedRouteFamily::AccountSignIn,
        HostedRouteFamily::SoftwareUpdate,
        HostedRouteFamily::ProductAnalytics,
        HostedRouteFamily::Dictation,
        HostedRouteFamily::PublicRelay,
        HostedRouteFamily::DirectoryTransport,
        HostedRouteFamily::PanelPublication,
        HostedRouteFamily::HostedHome,
        HostedRouteFamily::HostedBackup,
        HostedRouteFamily::ManagedInference,
        HostedRouteFamily::CredentialBroker,
        HostedRouteFamily::CrashReport,
        HostedRouteFamily::DiagnosticUpload,
        HostedRouteFamily::SupportUpload,
    ];

    /// Stable machine name, as carried in a refusal body.
    pub fn as_str(self) -> &'static str {
        match self {
            HostedRouteFamily::AccountSignIn => "account-sign-in",
            HostedRouteFamily::SoftwareUpdate => "software-update",
            HostedRouteFamily::ProductAnalytics => "product-analytics",
            HostedRouteFamily::Dictation => "dictation",
            HostedRouteFamily::PublicRelay => "public-relay",
            HostedRouteFamily::DirectoryTransport => "directory-transport",
            HostedRouteFamily::PanelPublication => "panel-publication",
            HostedRouteFamily::HostedHome => "hosted-home",
            HostedRouteFamily::HostedBackup => "hosted-backup",
            HostedRouteFamily::ManagedInference => "managed-inference",
            HostedRouteFamily::CredentialBroker => "credential-broker",
            HostedRouteFamily::CrashReport => "crash-report",
            HostedRouteFamily::DiagnosticUpload => "diagnostic-upload",
            HostedRouteFamily::SupportUpload => "support-upload",
        }
    }

    /// What a person reads when the route is refused.
    pub fn label(self) -> &'static str {
        match self {
            HostedRouteFamily::AccountSignIn => "Hosted sign-in",
            HostedRouteFamily::SoftwareUpdate => "Software updates",
            HostedRouteFamily::ProductAnalytics => "Product analytics",
            HostedRouteFamily::Dictation => "Hosted dictation",
            HostedRouteFamily::PublicRelay => "The public relay",
            HostedRouteFamily::DirectoryTransport => "The public directory transport",
            HostedRouteFamily::PanelPublication => "Public Panels",
            HostedRouteFamily::HostedHome => "A hosted Home",
            HostedRouteFamily::HostedBackup => "Hosted backup",
            HostedRouteFamily::ManagedInference => "Managed inference",
            HostedRouteFamily::CredentialBroker => "Hosted model-provider credentials",
            HostedRouteFamily::CrashReport => "Crash report upload",
            HostedRouteFamily::DiagnosticUpload => "Remote diagnostics",
            HostedRouteFamily::SupportUpload => "Support upload",
        }
    }

    /// The family's disposition under the office profile.
    pub fn disposition(self) -> Disposition {
        match self {
            HostedRouteFamily::AccountSignIn | HostedRouteFamily::SoftwareUpdate => {
                Disposition::Conditional
            }
            _ => Disposition::Refused,
        }
    }
}

/// How the office profile treats a hosted route family.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    /// Available only once its requests and logs are shown to carry no PHI or
    /// content-derived metadata. Never refused by [`refusal`].
    Conditional,
    /// Refused for an enrolled organization, client-side and server-side.
    Refused,
}

/// Where a family's refusal is enforced today.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "detail")]
pub enum Enforcement {
    /// Refused by [`refusal`] in the Hub's enterprise admission layer for the
    /// listed path shapes.
    HubAdmission(&'static [&'static str]),
    /// The hosted route exists and is not yet refused here; the detail says
    /// what remains.
    Open(&'static str),
    /// No hosted route of this family exists in the released product.
    NoHostedRoute,
    /// The family is conditional; it is never refused here.
    NotRefused,
}

/// One inventory line: a family, its disposition, and its enforcement.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct InventoryEntry {
    pub family: HostedRouteFamily,
    pub disposition: Disposition,
    pub enforcement: Enforcement,
}

const fn entry(family: HostedRouteFamily, enforcement: Enforcement) -> InventoryEntry {
    // `disposition()` is not const; the inventory test checks every line
    // against it so the two cannot drift.
    let disposition = match family {
        HostedRouteFamily::AccountSignIn | HostedRouteFamily::SoftwareUpdate => {
            Disposition::Conditional
        }
        _ => Disposition::Refused,
    };
    InventoryEntry {
        family,
        disposition,
        enforcement,
    }
}

/// The hosted route inventory under the office profile.
pub const INVENTORY: &[InventoryEntry] = &[
    entry(HostedRouteFamily::AccountSignIn, Enforcement::NotRefused),
    entry(HostedRouteFamily::SoftwareUpdate, Enforcement::NotRefused),
    entry(
        HostedRouteFamily::ProductAnalytics,
        Enforcement::HubAdmission(&["POST /product-analytics/events"]),
    ),
    entry(
        HostedRouteFamily::Dictation,
        // The Panel machine route (`/internal/dictation/transcribe`) sits
        // outside the admission layer and is still open; see WS-426.
        Enforcement::HubAdmission(&["/account/dictation/*"]),
    ),
    entry(
        HostedRouteFamily::PublicRelay,
        Enforcement::Open(
            "the relay authenticates machine sessions in gaugewright-directory, which does not yet read the enrollment",
        ),
    ),
    entry(
        HostedRouteFamily::DirectoryTransport,
        Enforcement::Open(
            "the directory transport is served by gaugewright-directory, which does not yet read the enrollment",
        ),
    ),
    entry(
        HostedRouteFamily::PanelPublication,
        Enforcement::Open(
            "publication starts from the Home's local /public-deployments routes; the Home does not yet know its organization's enrollment",
        ),
    ),
    entry(
        HostedRouteFamily::HostedHome,
        Enforcement::HubAdmission(&["/account/tenants/{tenant}/cloud-home*"]),
    ),
    entry(
        HostedRouteFamily::HostedBackup,
        Enforcement::HubAdmission(&["/account/tenants/{tenant}/backups*"]),
    ),
    entry(
        HostedRouteFamily::ManagedInference,
        Enforcement::HubAdmission(&[
            "/projects/{project}/organization-model-options",
            "/projects/{project}/organization-model-invocations",
        ]),
    ),
    entry(
        HostedRouteFamily::CredentialBroker,
        Enforcement::HubAdmission(&["/gaugeapps/administration/model-providers/*"]),
    ),
    entry(HostedRouteFamily::CrashReport, Enforcement::NoHostedRoute),
    entry(HostedRouteFamily::DiagnosticUpload, Enforcement::NoHostedRoute),
    entry(HostedRouteFamily::SupportUpload, Enforcement::NoHostedRoute),
];

/// The tenant a request path names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathTenant<'a> {
    /// The tenant id, percent-decoded exactly as the router's `Path` extractor
    /// decodes it for the handler. A client addresses a generated tenant such
    /// as `organization:<hex>` as `organization%3A<hex>`, so the raw segment is
    /// never the id the enrollment is stored under.
    Named(Cow<'a, str>),
    /// The segment does not decode to UTF-8. The router would not serve it,
    /// and the refusal fails closed rather than guess which tenant it means.
    Undecodable,
}

/// What a classified request is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedRequest<'a> {
    pub family: HostedRouteFamily,
    /// The tenant the path itself names, when it names one.
    pub tenant: Option<PathTenant<'a>>,
}

/// Percent-decode one path segment the way `percent_encoding::percent_decode`
/// does, which is what the router's `Path` extractor applies: `%XX` with two
/// hex digits becomes that byte, anything else — a lone `%`, a `+` — stays as
/// it is. `None` when the bytes are not UTF-8.
fn decode_segment(segment: &str) -> Option<Cow<'_, str>> {
    if !segment.contains('%') {
        return Some(Cow::Borrowed(segment));
    }
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok().map(Cow::Owned)
}

/// Classify a hosted request path into the family the Hub refuses for an
/// enrolled organization. `None` means the path belongs to no refused family
/// enforced here; it is not a statement that the path is safe.
pub fn classify<'a>(method: &Method, path: &'a str) -> Option<HostedRequest<'a>> {
    if let Some(rest) = path.strip_prefix("/account/tenants/") {
        let (tenant, tail) = rest.split_once('/')?;
        if tenant.is_empty() {
            return None;
        }
        let family = if tail == "backups" || tail.starts_with("backups/") {
            HostedRouteFamily::HostedBackup
        } else if tail == "cloud-home" || tail.starts_with("cloud-home/") {
            HostedRouteFamily::HostedHome
        } else {
            return None;
        };
        let tenant = match decode_segment(tenant) {
            Some(tenant) => PathTenant::Named(tenant),
            None => PathTenant::Undecodable,
        };
        return Some(HostedRequest {
            family,
            tenant: Some(tenant),
        });
    }
    let family = if path == "/account/dictation" || path.starts_with("/account/dictation/") {
        HostedRouteFamily::Dictation
    } else if path == "/product-analytics/events" && method == Method::POST {
        HostedRouteFamily::ProductAnalytics
    } else if path.starts_with("/gaugeapps/administration/model-providers/") {
        HostedRouteFamily::CredentialBroker
    } else if path.starts_with("/projects/")
        && (path.ends_with("/organization-model-options")
            || path.ends_with("/organization-model-invocations"))
    {
        HostedRouteFamily::ManagedInference
    } else {
        return None;
    };
    Some(HostedRequest {
        family,
        tenant: None,
    })
}

/// Whether the organization whose directory lives at `scope` is enrolled.
///
/// One-way: any enrollment ever recorded keeps the organization enrolled. A
/// tombstone or later record does not restore a refused route.
pub fn scope_enrolled(store: &Store, scope: &str) -> Result<bool, AdmitError> {
    Ok(enrollment(store, scope)?.is_some())
}

/// Whether tenant `tenant` is enrolled.
pub fn tenant_enrolled(store: &Store, tenant: &str) -> Result<bool, AdmitError> {
    scope_enrolled(store, &tenant_scope(tenant))
}

/// The first enrollment of the organization at `scope`, if any.
pub fn enrollment(store: &Store, scope: &str) -> Result<Option<OfficeProfileRecord>, AdmitError> {
    let rows = store.records(scope, OFFICE_PROFILE_KIND)?;
    Ok(fold_office_profile(rows)?)
}

/// Enroll tenant `tenant` in the office profile, bound to the Project Host
/// `home_id` that keeps its work. Idempotent: an enrolled organization keeps
/// its first enrollment and nothing is appended.
///
/// The record is the binding [`crate::office_profile`] defines, so a Home and
/// the Hub read one shape of one kind. This is the onboarding operator's
/// action. There is deliberately no counterpart that leaves the profile.
pub fn enroll(
    store: &mut Store,
    tenant: &str,
    home_id: &str,
    enrolled_by: &str,
    now_ms: u64,
) -> Result<OfficeProfileRecord, AdmitError> {
    let scope = tenant_scope(tenant);
    if let Some(existing) = enrollment(store, &scope)? {
        return Ok(existing);
    }
    let record = OfficeProfileRecord {
        id: ORG_ID.to_owned(),
        op: RecordOp::Upsert,
        organization: tenant.to_owned(),
        home_id: home_id.to_owned(),
        enrolled_by: enrolled_by.to_owned(),
        enrolled_at_ms: now_ms,
    };
    store.append_record(
        &scope,
        OFFICE_PROFILE_KIND,
        &serde_json::to_string(&record)?,
    )?;
    Ok(record)
}

/// Whether any tenant in the person's tenant index (their account `scope`) is
/// enrolled.
pub fn person_in_enrolled_tenant(store: &Store, account_scope: &str) -> Result<bool, AdmitError> {
    let tenancy = crate::tenancy::Tenancy::rebuild_in(store, account_scope)?;
    for tenant in tenancy.tenants.keys() {
        if tenant_enrolled(store, tenant)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A refused hosted request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfficeProfileRefusal {
    pub family: HostedRouteFamily,
}

impl IntoResponse for OfficeProfileRefusal {
    fn into_response(self) -> Response {
        (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!(
                    "{} is not available: this organization keeps its work on office-controlled systems.",
                    self.family.label()
                ),
                "refusal": "office-profile",
                "route_family": self.family.as_str(),
            })),
        )
            .into_response()
    }
}

/// Decide whether an authenticated request must be refused under the office
/// profile.
///
/// - A path that names a tenant is refused when that tenant is enrolled.
/// - Any other refused family is refused when the request's organization
///   (`request_scope`, from the tenant header) is enrolled, or when the
///   person (`account_scope`) belongs to any enrolled organization. A person-
///   level route such as dictation carries no organization of its own, and a
///   client cannot be trusted to name the organization its payload is for.
///
/// A store error refuses: the profile fails closed.
pub fn refusal(
    store: &Store,
    method: &Method,
    path: &str,
    request_scope: &str,
    account_scope: Option<&str>,
) -> Option<OfficeProfileRefusal> {
    let request = classify(method, path)?;
    if request.family.disposition() != Disposition::Refused {
        return None;
    }
    let refused = OfficeProfileRefusal {
        family: request.family,
    };
    let enrolled = match request.tenant {
        Some(PathTenant::Named(tenant)) => tenant_enrolled(store, &tenant),
        Some(PathTenant::Undecodable) => Ok(true),
        None => scope_enrolled(store, request_scope).and_then(|enrolled| {
            if enrolled {
                return Ok(true);
            }
            match account_scope {
                Some(scope) => person_in_enrolled_tenant(store, scope),
                None => Ok(false),
            }
        }),
    };
    match enrolled {
        Ok(false) => None,
        Ok(true) | Err(_) => Some(refused),
    }
}

#[cfg(test)]
#[path = "office_hosted_routes_tests.rs"]
mod tests;
