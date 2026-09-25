//! SAML SSO adapter (M3 `ID-2`) — a real [`IdentityProvider`](gaugedesk_app::identity::IdentityProvider)
//! that authenticates a **SAML Response** by delegating the signature/XML-dsig
//! verification to a co-resident **sidecar** process, then maps the verified subject
//! + attributes onto an [`AuthorityId`] + [`AuthorityAttributes`].
//!
//! ## Why a sidecar
//!
//! SAML SP verification requires XML canonicalization (C14N) + XML-dsig — the most
//! attack-prone code in SSO (signature-wrapping / XSW) and the one piece with no
//! vetted, OpenSSL-free, pure-Rust library. Rather than hand-roll dangerous crypto or
//! pull libxml2/OpenSSL into the Rust binary, the verification runs in a small
//! **bun/node sidecar** built on a maintained SAML library, behind a narrow
//! subprocess seam.
//! The Rust core stays memory-safe and OpenSSL-free; correctness of the XSW-prone path
//! lives in a maintained library.
//!
//! ## Trust boundary (fail-closed, `INV-20`)
//!
//! The sidecar is co-resident (loopback IPC, same host trust) and is given
//! the IdP's **public** signing certificate + the expected audience; it returns a
//! `{subject, attributes}` verdict or a rejection. **Anything** that is not an
//! explicit success — a non-zero exit, malformed output, `ok:false`, an empty subject,
//! a spawn failure — yields **no** authority. The Rust side never parses XML.
//!
//! The wire contract is one JSON request on the child's stdin and one JSON response on
//! its stdout (spawn-per-verify; SAML auth is login-frequency, not per-request).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Extension, Form, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine as _;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use gaugedesk_core::abac::{AuthorityAttributes, Region, Role, Tenant};
use gaugedesk_core::ids::AuthorityId;

use gaugedesk_app::identity::IdentityProvider;
use gaugedesk_app::{LockUnpoisoned, SharedWorkbench};

const SAML_METADATA_LIMIT_BYTES: usize = 512 * 1024;
const SAML_METADATA_DEPTH_LIMIT: usize = 64;
const SAML2_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const SAML_HTTP_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

/// The non-secret facts a structurally valid IdP metadata document provides.
/// Assertion verification still happens only during the browser ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlMetadataSummary {
    pub issuer: String,
    pub sign_in_service_count: usize,
    pub signing_certificate_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SamlMetadataError {
    Empty,
    TooLarge,
    DoctypeForbidden,
    TooDeep,
    Malformed,
    MissingEntityId,
    MissingIdpDescriptor,
    AmbiguousIdp,
    MissingSignInService,
    MissingSigningCertificate,
}

impl SamlMetadataError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Empty => "metadata-empty",
            Self::TooLarge => "metadata-too-large",
            Self::DoctypeForbidden => "metadata-doctype-forbidden",
            Self::TooDeep => "metadata-too-deep",
            Self::Malformed => "metadata-malformed",
            Self::MissingEntityId => "metadata-missing-entity-id",
            Self::MissingIdpDescriptor => "metadata-missing-idp",
            Self::AmbiguousIdp => "metadata-ambiguous-idp",
            Self::MissingSignInService => "metadata-missing-sign-in-service",
            Self::MissingSigningCertificate => "metadata-missing-signing-certificate",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Empty => "SAML requires an IdP metadata document",
            Self::TooLarge => "SAML metadata must be no larger than 512 KiB",
            Self::DoctypeForbidden => "SAML metadata must not contain a document type",
            Self::TooDeep => "SAML metadata is nested too deeply",
            Self::Malformed => "SAML metadata is not well-formed XML",
            Self::MissingEntityId => "SAML metadata must identify the IdP entity",
            Self::MissingIdpDescriptor => "SAML metadata has no SAML 2.0 IdP descriptor",
            Self::AmbiguousIdp => "SAML metadata describes more than one IdP entity",
            Self::MissingSignInService => {
                "SAML metadata has no HTTP-Redirect or HTTP-POST sign-in service"
            }
            Self::MissingSigningCertificate => {
                "SAML metadata has no signing certificate for assertion verification"
            }
        }
    }
}

fn xml_attribute(
    element: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    name: &[u8],
) -> Result<Option<String>, SamlMetadataError> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|_| SamlMetadataError::Malformed)?;
        if attribute.key.local_name().as_ref() == name {
            return attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|_| SamlMetadataError::Malformed);
        }
    }
    Ok(None)
}

fn sign_in_service(
    element: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
) -> Result<Option<SamlSignInService>, SamlMetadataError> {
    let binding = xml_attribute(element, reader, b"Binding")?;
    let location = xml_attribute(element, reader, b"Location")?;
    let binding = match binding.as_deref() {
        Some(SAML_HTTP_POST) => SamlSignInBinding::Post,
        Some(SAML_HTTP_REDIRECT) => SamlSignInBinding::Redirect,
        _ => return Ok(None),
    };
    let Some(location) =
        location.filter(|value| value.starts_with("https://") || value.starts_with("http://"))
    else {
        return Ok(None);
    };
    Ok(Some(SamlSignInService { binding, location }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SamlSignInBinding {
    Post,
    Redirect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlSignInService {
    pub binding: SamlSignInBinding,
    pub location: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedSamlMetadata {
    issuer: String,
    sign_in_services: Vec<SamlSignInService>,
    signing_certificates_pem: Vec<String>,
}

/// Exact non-secret material required to start and verify a SAML browser test.
/// It is derived server-side from the saved metadata and never projected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlBrowserConfiguration {
    pub issuer: String,
    pub sign_in_service: SamlSignInService,
    pub signing_certificate_pem: String,
}

/// Parse the bounded metadata input without resolving DTDs or external
/// entities. It accepts exactly one SAML 2.0 IdP authority with a usable web
/// sign-in binding and signing certificate. This validates configuration
/// shape; it does not claim a successful user sign-in.
fn parse_idp_metadata(metadata: &str) -> Result<ParsedSamlMetadata, SamlMetadataError> {
    let metadata = metadata.trim();
    if metadata.is_empty() {
        return Err(SamlMetadataError::Empty);
    }
    if metadata.len() > SAML_METADATA_LIMIT_BYTES {
        return Err(SamlMetadataError::TooLarge);
    }

    let mut reader = Reader::from_str(metadata);
    reader.config_mut().trim_text(true);
    let mut depth = 0_usize;
    let mut entities: Vec<(usize, Option<String>)> = Vec::new();
    let mut idp_depth: Option<usize> = None;
    let mut signing_key_depth: Option<usize> = None;
    let mut certificate_depth: Option<usize> = None;
    let mut certificate_text = String::new();
    let mut issuers = BTreeSet::new();
    let mut sign_in_services = Vec::new();
    let mut signing_certificates_pem = Vec::new();

    loop {
        let event = reader
            .read_event()
            .map_err(|_| SamlMetadataError::Malformed)?;
        match event {
            Event::Start(element) => {
                depth += 1;
                if depth > SAML_METADATA_DEPTH_LIMIT {
                    return Err(SamlMetadataError::TooDeep);
                }
                match element.local_name().as_ref() {
                    b"EntityDescriptor" => {
                        let id = xml_attribute(&element, &reader, b"entityID")?
                            .map(|value| value.trim().to_owned())
                            .filter(|value| !value.is_empty());
                        entities.push((depth, id));
                    }
                    b"IDPSSODescriptor" => {
                        let protocols =
                            xml_attribute(&element, &reader, b"protocolSupportEnumeration")?
                                .unwrap_or_default();
                        if protocols
                            .split_ascii_whitespace()
                            .any(|value| value == SAML2_PROTOCOL)
                        {
                            let issuer = entities
                                .last()
                                .and_then(|(_, issuer)| issuer.clone())
                                .ok_or(SamlMetadataError::MissingEntityId)?;
                            issuers.insert(issuer);
                            idp_depth = Some(depth);
                        }
                    }
                    b"KeyDescriptor" if idp_depth.is_some() => {
                        let usage = xml_attribute(&element, &reader, b"use")?;
                        if usage.as_deref().is_none_or(|value| value == "signing") {
                            signing_key_depth = Some(depth);
                        }
                    }
                    b"X509Certificate" if signing_key_depth.is_some() => {
                        certificate_depth = Some(depth);
                        certificate_text.clear();
                    }
                    b"SingleSignOnService" if idp_depth.is_some() => {
                        if let Some(service) = sign_in_service(&element, &reader)? {
                            sign_in_services.push(service);
                        }
                    }
                    _ => {}
                }
            }
            Event::Empty(element)
                if element.local_name().as_ref() == b"SingleSignOnService"
                    && idp_depth.is_some() =>
            {
                if let Some(service) = sign_in_service(&element, &reader)? {
                    sign_in_services.push(service);
                }
            }
            Event::Text(text) if certificate_depth.is_some() => {
                certificate_text.push_str(
                    text.decode()
                        .map_err(|_| SamlMetadataError::Malformed)?
                        .trim(),
                );
            }
            Event::CData(text) if certificate_depth.is_some() => {
                certificate_text.push_str(
                    text.decode()
                        .map_err(|_| SamlMetadataError::Malformed)?
                        .trim(),
                );
            }
            Event::End(element) => {
                if certificate_depth == Some(depth)
                    && element.local_name().as_ref() == b"X509Certificate"
                {
                    let compact = certificate_text
                        .chars()
                        .filter(|value| !value.is_ascii_whitespace())
                        .collect::<String>();
                    if compact.len() >= 64 {
                        signing_certificates_pem.push(format!(
                            "-----BEGIN CERTIFICATE-----\n{compact}\n-----END CERTIFICATE-----"
                        ));
                    }
                    certificate_depth = None;
                    certificate_text.clear();
                }
                if signing_key_depth == Some(depth)
                    && element.local_name().as_ref() == b"KeyDescriptor"
                {
                    signing_key_depth = None;
                }
                if idp_depth == Some(depth) && element.local_name().as_ref() == b"IDPSSODescriptor"
                {
                    idp_depth = None;
                }
                if element.local_name().as_ref() == b"EntityDescriptor"
                    && entities
                        .last()
                        .is_some_and(|(entity_depth, _)| *entity_depth == depth)
                {
                    entities.pop();
                }
                depth = depth.checked_sub(1).ok_or(SamlMetadataError::Malformed)?;
            }
            Event::DocType(_) => return Err(SamlMetadataError::DoctypeForbidden),
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 {
        return Err(SamlMetadataError::Malformed);
    }
    let issuer = match issuers.len() {
        0 => return Err(SamlMetadataError::MissingIdpDescriptor),
        1 => issuers.into_iter().next().expect("one issuer exists"),
        _ => return Err(SamlMetadataError::AmbiguousIdp),
    };
    if sign_in_services.is_empty() {
        return Err(SamlMetadataError::MissingSignInService);
    }
    if signing_certificates_pem.is_empty() {
        return Err(SamlMetadataError::MissingSigningCertificate);
    }
    Ok(ParsedSamlMetadata {
        issuer,
        sign_in_services,
        signing_certificates_pem,
    })
}

pub fn validate_idp_metadata(metadata: &str) -> Result<SamlMetadataSummary, SamlMetadataError> {
    let parsed = parse_idp_metadata(metadata)?;
    Ok(SamlMetadataSummary {
        issuer: parsed.issuer,
        sign_in_service_count: parsed.sign_in_services.len(),
        signing_certificate_count: parsed.signing_certificates_pem.len(),
    })
}

pub fn saml_browser_configuration(
    metadata: &str,
) -> Result<SamlBrowserConfiguration, SamlMetadataError> {
    let parsed = parse_idp_metadata(metadata)?;
    // Prefer Redirect when both are advertised so the popup can proceed
    // directly. POST remains supported for IdPs that expose only that binding.
    let sign_in_service = parsed
        .sign_in_services
        .iter()
        .find(|service| service.binding == SamlSignInBinding::Redirect)
        .cloned()
        .unwrap_or_else(|| parsed.sign_in_services[0].clone());
    Ok(SamlBrowserConfiguration {
        issuer: parsed.issuer,
        sign_in_service,
        signing_certificate_pem: parsed.signing_certificates_pem[0].clone(),
    })
}

/// Resolve the verify-sidecar command (an explicit env-override seam,
/// SELFHOST). A packaged bundle vendors the sidecar (e.g. a bun-compiled binary) and
/// points here via `GAUGEDESK_SAML_SIDECAR`; the dev build falls back to running the
/// script on `node` under the repo's `ee/sidecar/saml-verify/verify.mjs`. `None` when
/// neither is resolvable (the SAML provider is then simply not configured).
pub fn saml_command_from(env: Option<String>, cwd: Option<&Path>) -> Option<Vec<String>> {
    if let Some(bin) = env.filter(|s| !s.trim().is_empty()) {
        return Some(vec![bin]);
    }
    cwd.map(|c| {
        vec![
            "node".to_string(),
            c.join("ee/sidecar/saml-verify/verify.mjs")
                .display()
                .to_string(),
        ]
    })
}

/// Which SAML **attribute names** carry the claims the ABAC evaluator reads. Unset
/// (`None`) ⇒ that attribute is not mapped (fail-closed — no role is safer than a
/// wrongly-mapped one). IdP-specific (Entra emits `http://schemas.../groups`, etc.).
#[derive(Clone, Debug, Default)]
pub struct SamlClaimMapping {
    pub email_attribute: Option<String>,
    pub roles_attribute: Option<String>,
    pub region_attribute: Option<String>,
    pub tenant_attribute: Option<String>,
}

/// Verified, replay-consumed SAML identity used by either the isolated test or
/// ordinary account-login purpose. `verified_email` comes from one explicitly
/// configured signed attribute, or from an email-shaped signed NameID.
pub struct VerifiedSamlIdentity {
    pub authority: AuthorityId,
    pub verified_email: Option<String>,
    pub attributes: AuthorityAttributes,
}

/// The request handed to the verify sidecar on stdin.
#[derive(Serialize)]
struct VerifyRequest<'a> {
    /// The base64-encoded (or raw XML) SAML Response from the IdP POST binding.
    saml_response: &'a str,
    /// The IdP's signing certificate (PEM) — the trust anchor the sidecar checks the
    /// assertion's XML signature against.
    idp_cert: &'a str,
    /// The SP entity id the assertion's `AudienceRestriction` must contain.
    audience: &'a str,
    /// Exact SP-initiated browser ceremony bounds. They are absent for the
    /// provider-neutral verifier seam, and all present for a real browser test.
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    callback_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idp_issuer: Option<&'a str>,
}

#[derive(Clone, Debug)]
struct BrowserResponseBinding {
    request_id: String,
    callback_url: String,
    idp_issuer: String,
}

/// The sidecar's verdict on stdout. `ok:false` (or any non-success) is a rejection.
#[derive(Deserialize, Default)]
struct VerifyResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    subject: String,
    /// Verified attribute statements: name → values.
    #[serde(default)]
    attributes: BTreeMap<String, Vec<String>>,
    /// The assertion's unique `@ID` — the replay key. A verified SAML assertion must
    /// carry one; an empty id is treated fail-closed (we cannot enforce single-use).
    #[serde(default)]
    assertion_id: String,
    /// The assertion's `NotOnOrAfter` as epoch milliseconds (the tighter of
    /// SubjectConfirmationData / Conditions). Bounds how long the replay entry is kept.
    #[serde(default)]
    not_on_or_after: Option<i64>,
}

/// How long a consumed assertion id is remembered when the sidecar reports no expiry
/// (defensive; a valid assertion normally carries a `NotOnOrAfter`). Comfortably covers
/// a typical assertion validity window.
const DEFAULT_REPLAY_RETENTION_MS: i64 = 10 * 60 * 1000;

fn now_epoch_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A SAML `IdentityProvider` backed by the verify sidecar.
pub struct SamlSidecarIdentityProvider {
    /// The verifier command: program + args (request on stdin, verdict on stdout).
    /// Production: the vendored bun sidecar (resolved via `GAUGEDESK_SAML_SIDECAR`);
    /// dev: `["node", "ee/sidecar/saml-verify/verify.mjs"]`.
    command: Vec<String>,
    idp_cert_pem: String,
    audience: String,
    mapping: SamlClaimMapping,
    browser_response: Option<BrowserResponseBinding>,
    /// Attributes materialized at the last successful [`authenticate`], per authority
    /// (the seam splits authenticate from claims; the SAML attributes live in the
    /// just-verified assertion). Interior-mutable behind the `&self` trait methods.
    ///
    /// [`authenticate`]: IdentityProvider::authenticate
    cache: Mutex<BTreeMap<AuthorityId, AuthorityAttributes>>,
    /// One-time-use cache of consumed assertion ids → their expiry (epoch ms). A
    /// signed assertion is otherwise replayable within its validity window; this makes
    /// each one single-use (the Web-Browser-SSO requirement node-saml does not itself
    /// enforce). Interior-mutable behind the `&self` trait methods.
    replay: Mutex<BTreeMap<String, i64>>,
}

impl SamlSidecarIdentityProvider {
    pub fn new(
        command: Vec<String>,
        idp_cert_pem: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            command,
            idp_cert_pem: idp_cert_pem.into(),
            audience: audience.into(),
            mapping: SamlClaimMapping::default(),
            browser_response: None,
            cache: Mutex::new(BTreeMap::new()),
            replay: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record a one-time assertion id, pruning entries that have expired by `now_ms`.
    /// Returns `false` if the id was already consumed and is still within its validity
    /// window — a replay, rejected fail-closed. `now_ms`/`expiry_ms` are parameters so
    /// the policy is deterministically testable without the wall clock.
    fn record_assertion(&self, id: &str, expiry_ms: i64, now_ms: i64) -> bool {
        let mut replay = self.replay.lock().expect("saml replay cache poisoned");
        replay.retain(|_, exp| *exp > now_ms);
        if replay.contains_key(id) {
            return false;
        }
        // Keep the entry at least until the assertion's expiry; never insert an
        // already-expired entry that an immediate replay could slip past.
        let keep_until = expiry_ms.max(now_ms + 1);
        replay.insert(id.to_string(), keep_until);
        true
    }

    pub fn with_mapping(mut self, mapping: SamlClaimMapping) -> Self {
        self.mapping = mapping;
        self
    }

    fn with_browser_response_binding(
        mut self,
        request_id: impl Into<String>,
        callback_url: impl Into<String>,
        idp_issuer: impl Into<String>,
    ) -> Self {
        self.browser_response = Some(BrowserResponseBinding {
            request_id: request_id.into(),
            callback_url: callback_url.into(),
            idp_issuer: idp_issuer.into(),
        });
        self
    }

    /// Run the verify sidecar once: write the request to stdin, read the JSON verdict
    /// from stdout. `None` on any spawn/IO/parse failure or non-zero exit (fail-closed).
    fn verify(&self, saml_response: &str) -> Option<VerifyResponse> {
        let (program, args) = self.command.split_first()?;
        let request = serde_json::to_string(&VerifyRequest {
            saml_response,
            idp_cert: &self.idp_cert_pem,
            audience: &self.audience,
            request_id: self
                .browser_response
                .as_ref()
                .map(|binding| binding.request_id.as_str()),
            callback_url: self
                .browser_response
                .as_ref()
                .map(|binding| binding.callback_url.as_str()),
            idp_issuer: self
                .browser_response
                .as_ref()
                .map(|binding| binding.idp_issuer.as_str()),
        })
        .ok()?;

        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        if let Some(mut stdin) = child.stdin.take() {
            // Best-effort: a child that ignores stdin still gets the request in the
            // pipe buffer; dropping the handle at end of block closes it.
            let _ = stdin.write_all(request.as_bytes());
        }
        let output = child.wait_with_output().ok()?;
        if !output.status.success() {
            return None;
        }
        serde_json::from_slice(&output.stdout).ok()
    }

    /// Map a verified attribute set onto authority attributes per [`SamlClaimMapping`].
    /// Only ever *adds* attributes the assertion carries.
    fn map_attributes(&self, attrs: &BTreeMap<String, Vec<String>>) -> AuthorityAttributes {
        let mut out = AuthorityAttributes::default();
        if let Some(name) = &self.mapping.roles_attribute {
            if let Some(values) = attrs.get(name) {
                out.roles = values.iter().map(|v| Role::new(v.as_str())).collect();
            }
        }
        if let Some(name) = &self.mapping.region_attribute {
            out.region = attrs.get(name).and_then(|v| v.first()).map(Region::new);
        }
        if let Some(name) = &self.mapping.tenant_attribute {
            out.affiliation = attrs.get(name).and_then(|v| v.first()).map(Tenant::new);
        }
        out
    }

    fn verified_email(
        &self,
        subject: &str,
        attrs: &BTreeMap<String, Vec<String>>,
    ) -> Option<String> {
        let candidate = self
            .mapping
            .email_attribute
            .as_ref()
            .and_then(|name| attrs.get(name))
            .and_then(|values| values.first())
            .map(String::as_str)
            .unwrap_or(subject);
        gaugedesk_app::account_auth::normalize_email_contact(candidate)
    }

    /// Verify and consume one signed assertion, retaining only the mapped,
    /// non-secret identity facts needed by the selected server-held purpose.
    pub fn authenticate_with_profile(&self, credential: &str) -> Option<VerifiedSamlIdentity> {
        let verdict = self.verify(credential)?;
        if !verdict.ok || verdict.subject.is_empty() || verdict.assertion_id.is_empty() {
            return None;
        }
        let now_ms = now_epoch_ms();
        let expiry_ms = verdict
            .not_on_or_after
            .unwrap_or(now_ms + DEFAULT_REPLAY_RETENTION_MS);
        if !self.record_assertion(&verdict.assertion_id, expiry_ms, now_ms) {
            return None;
        }
        let authority = AuthorityId::new(verdict.subject.as_str());
        let attributes = self.map_attributes(&verdict.attributes);
        let verified_email = self.verified_email(&verdict.subject, &verdict.attributes);
        self.cache
            .lock()
            .expect("saml cache mutex poisoned")
            .insert(authority.clone(), attributes.clone());
        Some(VerifiedSamlIdentity {
            authority,
            verified_email,
            attributes,
        })
    }
}

impl IdentityProvider for SamlSidecarIdentityProvider {
    fn authenticate(&self, credential: &str) -> Option<AuthorityId> {
        self.authenticate_with_profile(credential)
            .map(|identity| identity.authority)
    }

    fn claims(&self, authority: &AuthorityId) -> AuthorityAttributes {
        self.cache
            .lock()
            .expect("saml cache mutex poisoned")
            .get(authority)
            .cloned()
            .unwrap_or_default()
    }
}

const SAML_BROWSER_TTL: Duration = Duration::from_secs(10 * 60);
const SAML_BROWSER_MAX: usize = 128;
const SAML_RESPONSE_LIMIT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
struct PendingSamlBrowser {
    purpose: PendingSamlPurpose,
    sign_in_service: SamlSignInService,
    authn_request: String,
    request_id: String,
    signing_certificate_pem: String,
    audience: String,
    acs_url: String,
    idp_issuer: String,
    mapping: SamlClaimMapping,
    expires_at: Instant,
}

#[derive(Clone)]
enum PendingSamlPurpose {
    ConnectionTest(gaugedesk_app::auth_oidc::PendingEnterpriseConnectionTest),
    Login {
        context: gaugedesk_app::auth_oidc::PendingEnterpriseLogin,
        native_return: Option<String>,
        native_handoff_challenge: Option<String>,
    },
}

/// Process-local single-use state joining an authenticated Administration
/// command to the public SAML launch and ACS legs. The random RelayState is the
/// only browser-carried selector; actor, tenant, connection revision, trust
/// anchor, request, and mapping remain server-held.
#[derive(Clone, Default)]
pub struct SamlBrowserState {
    pending: Arc<Mutex<BTreeMap<String, PendingSamlBrowser>>>,
}

impl SamlBrowserState {
    fn prune_and_bound(pending: &mut BTreeMap<String, PendingSamlBrowser>, now: Instant) {
        pending.retain(|_, entry| entry.expires_at > now);
        while pending.len() >= SAML_BROWSER_MAX {
            let oldest = pending
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(state, _)| state.clone());
            match oldest {
                Some(state) => {
                    pending.remove(&state);
                }
                None => break,
            }
        }
    }

    pub fn begin_test(
        &self,
        connection: &gaugedesk_app::org::SsoConnectionRecord,
        context: gaugedesk_app::auth_oidc::PendingEnterpriseConnectionTest,
        public_base: &str,
        sp_entity_id: &str,
        acs_url: &str,
    ) -> Result<SamlBrowserLaunch, SamlBrowserError> {
        self.begin(
            connection,
            PendingSamlPurpose::ConnectionTest(context),
            public_base,
            sp_entity_id,
            acs_url,
        )
    }

    fn begin(
        &self,
        connection: &gaugedesk_app::org::SsoConnectionRecord,
        purpose: PendingSamlPurpose,
        public_base: &str,
        sp_entity_id: &str,
        acs_url: &str,
    ) -> Result<SamlBrowserLaunch, SamlBrowserError> {
        if connection.protocol != gaugedesk_app::org::SsoProtocol::Saml {
            return Err(SamlBrowserError::NotSaml);
        }
        // New connection revisions bind the service-provider identity as well
        // as the IdP metadata. A deployment-origin change therefore cannot
        // reuse old browser-test evidence or send an assertion to an unreviewed
        // ACS. Empty values retain read compatibility for pre-revision records.
        if (!connection.saml_sp_entity_id.is_empty()
            && connection.saml_sp_entity_id != sp_entity_id)
            || (!connection.saml_acs_url.is_empty() && connection.saml_acs_url != acs_url)
        {
            return Err(SamlBrowserError::Request);
        }
        let configuration =
            saml_browser_configuration(&connection.metadata).map_err(SamlBrowserError::Metadata)?;
        let state = hex::encode(gaugedesk_app::session::random_bytes::<24>());
        let request_id = format!(
            "_{}",
            hex::encode(gaugedesk_app::session::random_bytes::<20>())
        );
        let issued_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| SamlBrowserError::Request)?;
        let request = authn_request(
            &request_id,
            &issued_at,
            &configuration.sign_in_service.location,
            sp_entity_id,
            acs_url,
        );
        let mapping = SamlClaimMapping {
            email_attribute: connection.claim_mapping.email_claim.clone(),
            roles_attribute: connection.claim_mapping.roles_claim.clone(),
            region_attribute: connection.claim_mapping.region_claim.clone(),
            tenant_attribute: connection.claim_mapping.tenant_claim.clone(),
        };
        let now = Instant::now();
        let entry = PendingSamlBrowser {
            purpose,
            sign_in_service: configuration.sign_in_service,
            authn_request: request,
            request_id,
            signing_certificate_pem: configuration.signing_certificate_pem,
            audience: sp_entity_id.to_owned(),
            acs_url: acs_url.to_owned(),
            idp_issuer: configuration.issuer,
            mapping,
            expires_at: now + SAML_BROWSER_TTL,
        };
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        Self::prune_and_bound(&mut pending, now);
        pending.insert(state.clone(), entry);
        Ok(SamlBrowserLaunch {
            launch_url: format!(
                "{}/auth/enterprise-identity/saml/launch?state={state}",
                public_base.trim_end_matches('/')
            ),
        })
    }

    pub fn begin_login(
        &self,
        request: gaugedesk_app::auth_oidc::EnterpriseSamlStartRequest,
        sp_entity_id: &str,
        acs_url: &str,
    ) -> Result<SamlBrowserLaunch, SamlBrowserError> {
        let gaugedesk_app::auth_oidc::EnterpriseSamlStartRequest {
            connection,
            login_context,
            public_base,
            native_return,
            native_handoff_challenge,
        } = request;
        self.begin(
            &connection,
            PendingSamlPurpose::Login {
                context: login_context,
                native_return,
                native_handoff_challenge,
            },
            &public_base,
            sp_entity_id,
            acs_url,
        )
    }

    fn get(&self, state: &str, now: Instant) -> Option<PendingSamlBrowser> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        pending.retain(|_, entry| entry.expires_at > now);
        pending.get(state).cloned()
    }

    fn take(&self, state: &str, now: Instant) -> Option<PendingSamlBrowser> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = pending.remove(state)?;
        (entry.expires_at > now).then_some(entry)
    }
}

pub struct SamlBrowserLaunch {
    pub launch_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SamlBrowserError {
    NotSaml,
    Metadata(SamlMetadataError),
    Request,
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn html_escape(value: &str) -> String {
    xml_escape(value)
}

fn authn_request(
    id: &str,
    issue_instant: &str,
    destination: &str,
    issuer: &str,
    acs_url: &str,
) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="{}"><saml:Issuer>{}</saml:Issuer><samlp:NameIDPolicy AllowCreate="true"/></samlp:AuthnRequest>"#,
        xml_escape(id),
        xml_escape(issue_instant),
        xml_escape(destination),
        xml_escape(acs_url),
        SAML_HTTP_POST,
        xml_escape(issuer),
    )
}

fn redirect_binding_url(
    service_url: &str,
    request: &str,
    relay_state: &str,
) -> Result<String, SamlBrowserError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(request.as_bytes())
        .map_err(|_| SamlBrowserError::Request)?;
    let compressed = encoder.finish().map_err(|_| SamlBrowserError::Request)?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(compressed);
    let separator = if service_url.contains('?') { '&' } else { '?' };
    Ok(format!(
        "{service_url}{separator}SAMLRequest={}&RelayState={}",
        urlencoding::encode(&encoded),
        urlencoding::encode(relay_state),
    ))
}

fn post_binding_page(service_url: &str, request: &str, relay_state: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(request.as_bytes());
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Continue corporate sign-in</title></head><body><main><h1>Continue corporate sign-in</h1><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"SAMLRequest\" value=\"{}\"><input type=\"hidden\" name=\"RelayState\" value=\"{}\"><button type=\"submit\">Continue to identity provider</button></form></main></body></html>",
        html_escape(service_url),
        html_escape(&encoded),
        html_escape(relay_state),
    )
}

fn completed_page() -> &'static str {
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in test complete</title></head><body><main><h1>Sign-in test complete</h1><p>The verified result is now available in GaugeDesk. You can close this window.</p></main></body></html>"
}

#[derive(Deserialize)]
struct SamlLaunchQuery {
    state: String,
}

#[derive(Deserialize)]
struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: String,
}

pub fn browser_routes() -> Router<SharedWorkbench> {
    Router::new()
        .route(
            "/auth/enterprise-identity/saml/launch",
            get(launch_saml_browser_test),
        )
        .route("/auth/saml/acs", post(complete_saml_browser_test))
        .layer(axum::middleware::from_fn(
            gaugedesk_app::auth_error_page::render_browser_errors,
        ))
}

async fn launch_saml_browser_test(
    Extension(state): Extension<SamlBrowserState>,
    Query(query): Query<SamlLaunchQuery>,
) -> Response {
    let Some(pending) = state.get(&query.state, Instant::now()) else {
        return (StatusCode::BAD_REQUEST, "unknown or expired sign-in").into_response();
    };
    match pending.sign_in_service.binding {
        SamlSignInBinding::Redirect => match redirect_binding_url(
            &pending.sign_in_service.location,
            &pending.authn_request,
            &query.state,
        ) {
            Ok(url) => Redirect::to(&url).into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not build SAML request",
            )
                .into_response(),
        },
        SamlSignInBinding::Post => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            post_binding_page(
                &pending.sign_in_service.location,
                &pending.authn_request,
                &query.state,
            ),
        )
            .into_response(),
    }
}

async fn complete_saml_browser_test(
    State(workbench): State<SharedWorkbench>,
    Extension(state): Extension<SamlBrowserState>,
    Extension(auth): Extension<gaugedesk_app::auth_oidc::AuthShellState>,
    Form(form): Form<SamlAcsForm>,
) -> Response {
    if form.saml_response.len() > SAML_RESPONSE_LIMIT_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "SAML response is too large").into_response();
    }
    let Some(pending) = state.take(&form.relay_state, Instant::now()) else {
        return (StatusCode::BAD_REQUEST, "unknown or expired sign-in").into_response();
    };
    let command = saml_command_from(
        gaugedesk_env::var("SAML_SIDECAR"),
        std::env::current_dir().ok().as_deref(),
    );
    let Some(command) = command else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "SAML verification is unavailable on this server",
        )
            .into_response();
    };
    let response = form.saml_response;
    let verified = tokio::task::spawn_blocking(move || {
        let provider = SamlSidecarIdentityProvider::new(
            command,
            pending.signing_certificate_pem,
            pending.audience,
        )
        .with_mapping(pending.mapping)
        .with_browser_response_binding(
            pending.request_id,
            pending.acs_url,
            pending.idp_issuer,
        );
        let identity = provider.authenticate_with_profile(&response)?;
        Some((pending.purpose, identity))
    })
    .await;
    let (purpose, identity) = match verified {
        Ok(Some(result)) => result,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, "the SAML response did not verify").into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "SAML verification failed unexpectedly",
            )
                .into_response()
        }
    };
    match purpose {
        PendingSamlPurpose::ConnectionTest(context) => {
            let recorded = crate::org_routes::record_enterprise_connection_test(
                &mut workbench.lock_unpoisoned(),
                &context,
                gaugedesk_app::org::SsoProtocol::Saml,
                &identity.authority,
                &identity.attributes,
            );
            if recorded.is_err() {
                return (
                    StatusCode::CONFLICT,
                    "this corporate sign-in test is no longer current; return to GaugeDesk and start again",
                )
                    .into_response();
            }
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                completed_page(),
            )
                .into_response()
        }
        PendingSamlPurpose::Login {
            context,
            native_return,
            native_handoff_challenge,
        } => {
            let corporate_identity = gaugedesk_app::auth_oidc::VerifiedEnterpriseIdentity {
                authority: identity.authority,
                verified_email: identity.verified_email,
            };
            let resolution = {
                let mut guard = workbench.lock_unpoisoned();
                auth.resolve_enterprise_login(&mut guard, &context, &corporate_identity)
            };
            let resolution = match resolution {
                Ok(resolution) => resolution,
                Err(gaugedesk_app::auth_oidc::LoginFoldRefusal::NotAdmitted) => {
                    return (
                        StatusCode::FORBIDDEN,
                        "this corporate account is not admitted to the organization",
                    )
                        .into_response()
                }
                Err(gaugedesk_app::auth_oidc::LoginFoldRefusal::StaleConnection) => {
                    return (
                        StatusCode::CONFLICT,
                        "corporate sign-in changed while you were signing in; start again",
                    )
                        .into_response()
                }
                Err(gaugedesk_app::auth_oidc::LoginFoldRefusal::Unavailable) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "corporate account admission is unavailable",
                    )
                        .into_response()
                }
            };
            let account_label = corporate_identity
                .verified_email
                .clone()
                .unwrap_or_else(|| resolution.account_id.clone());
            let session_ceiling = gaugedesk_app::account::session_now_ms()
                .saturating_add(gaugedesk_app::account::SESSION_ABSOLUTE_LIFETIME_MS);
            auth.deliver_enterprise_login(
                &workbench,
                gaugedesk_app::auth_oidc::EnterpriseLoginDelivery {
                    login_context: context,
                    resolution,
                    display_label: account_label,
                    // SAML has no refresh grant: the verified assertion opens a
                    // bounded GaugeDesk session and is never used as its bearer.
                    provider_expires_at_ms: session_ceiling,
                    refresh_token: None,
                    native_return,
                    native_handoff_challenge,
                },
            )
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const CERT: &str = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
    const METADATA: &str = r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso" />
  </IDPSSODescriptor>
</EntityDescriptor>"#;

    #[test]
    fn idp_metadata_validation_extracts_one_usable_authority() {
        let summary = validate_idp_metadata(METADATA).unwrap();
        assert_eq!(summary.issuer, "https://idp.example.test");
        assert_eq!(summary.sign_in_service_count, 1);
        assert_eq!(summary.signing_certificate_count, 1);
    }

    #[test]
    fn browser_configuration_retains_the_server_selected_endpoint_and_trust_anchor() {
        let configuration = saml_browser_configuration(METADATA).unwrap();
        assert_eq!(configuration.issuer, "https://idp.example.test");
        assert_eq!(
            configuration.sign_in_service,
            SamlSignInService {
                binding: SamlSignInBinding::Redirect,
                location: "https://idp.example.test/sso".into(),
            }
        );
        assert!(configuration
            .signing_certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----\nAAAA"));
        assert!(configuration
            .signing_certificate_pem
            .ends_with("\n-----END CERTIFICATE-----"));
    }

    #[test]
    fn browser_test_state_is_bounded_single_use_server_context() {
        let mut connection = gaugedesk_app::org::SsoConnectionRecord {
            id: gaugedesk_app::org::ORG_ID.into(),
            protocol: gaugedesk_app::org::SsoProtocol::Saml,
            metadata: METADATA.into(),
            ..Default::default()
        };
        connection.seal_revision();
        let context = gaugedesk_app::auth_oidc::PendingEnterpriseConnectionTest {
            id: "ssotest-1".into(),
            store_scope: gaugedesk_app::org::ORG_SCOPE.into(),
            actor: "authority:owner".into(),
            connection_id: connection.id.clone(),
            connection_revision: connection.current_revision(),
        };
        let state = SamlBrowserState::default();
        let launch = state
            .begin_test(
                &connection,
                context.clone(),
                "https://desk.example.test",
                "https://desk.example.test/saml/metadata",
                "https://desk.example.test/auth/saml/acs",
            )
            .unwrap();
        let relay = launch.launch_url.split("state=").nth(1).unwrap();
        let entry = state.get(relay, Instant::now()).unwrap();
        assert!(matches!(
            entry.purpose,
            PendingSamlPurpose::ConnectionTest(ref actual) if actual == &context
        ));
        assert!(entry.authn_request.contains("<samlp:AuthnRequest"));
        assert!(entry
            .authn_request
            .contains("https://desk.example.test/auth/saml/acs"));
        assert!(state.take(relay, Instant::now()).is_some());
        assert!(state.take(relay, Instant::now()).is_none());
    }

    #[test]
    fn a_revision_bound_to_another_service_provider_origin_cannot_start() {
        let mut connection = gaugedesk_app::org::SsoConnectionRecord {
            id: gaugedesk_app::org::ORG_ID.into(),
            protocol: gaugedesk_app::org::SsoProtocol::Saml,
            metadata: METADATA.into(),
            saml_sp_entity_id: "https://old.example.test/saml/metadata".into(),
            saml_acs_url: "https://old.example.test/auth/saml/acs".into(),
            ..Default::default()
        };
        connection.seal_revision();
        let context = gaugedesk_app::auth_oidc::PendingEnterpriseConnectionTest {
            id: "ssotest-origin-change".into(),
            store_scope: gaugedesk_app::org::ORG_SCOPE.into(),
            actor: "authority:owner".into(),
            connection_id: connection.id.clone(),
            connection_revision: connection.current_revision(),
        };
        assert!(matches!(
            SamlBrowserState::default().begin_test(
                &connection,
                context,
                "https://new.example.test",
                "https://new.example.test/saml/metadata",
                "https://new.example.test/auth/saml/acs",
            ),
            Err(SamlBrowserError::Request)
        ));
    }

    #[test]
    fn ordinary_login_state_pins_tenant_revision_and_native_handoff_server_side() {
        let mut connection = gaugedesk_app::org::SsoConnectionRecord {
            id: gaugedesk_app::org::ORG_ID.into(),
            protocol: gaugedesk_app::org::SsoProtocol::Saml,
            metadata: METADATA.into(),
            ..Default::default()
        };
        connection.claim_mapping.email_claim = Some("mail".into());
        connection.seal_revision();
        let context = gaugedesk_app::auth_oidc::PendingEnterpriseLogin {
            store_scope: "org::organization:acme".into(),
            connection_id: connection.id.clone(),
            connection_revision: connection.current_revision(),
            protocol: connection.protocol,
        };
        let state = SamlBrowserState::default();
        let launch = state
            .begin_login(
                gaugedesk_app::auth_oidc::EnterpriseSamlStartRequest {
                    connection,
                    login_context: context.clone(),
                    public_base: "https://desk.example.test".into(),
                    native_return: Some("gaugewright://auth/callback".into()),
                    native_handoff_challenge: Some("challenge".into()),
                },
                "https://desk.example.test/saml/metadata",
                "https://desk.example.test/auth/saml/acs",
            )
            .unwrap();
        let relay = launch.launch_url.split("state=").nth(1).unwrap();
        let entry = state.take(relay, Instant::now()).unwrap();
        assert_eq!(entry.mapping.email_attribute.as_deref(), Some("mail"));
        assert!(matches!(
            entry.purpose,
            PendingSamlPurpose::Login {
                context: ref actual,
                native_return: Some(ref return_to),
                native_handoff_challenge: Some(ref challenge),
            } if actual == &context
                && return_to == "gaugewright://auth/callback"
                && challenge == "challenge"
        ));
        assert!(state.take(relay, Instant::now()).is_none());
    }

    #[test]
    fn redirect_binding_deflates_the_request_and_carries_only_relay_state() {
        let url = redirect_binding_url(
            "https://idp.example.test/sso",
            "<samlp:AuthnRequest ID=\"_one\"/>",
            "state-123",
        )
        .unwrap();
        assert!(url.starts_with("https://idp.example.test/sso?SAMLRequest="));
        assert!(url.contains("&RelayState=state-123"));
        assert!(!url.contains("AuthnRequest"), "the request is encoded");
    }

    #[test]
    fn idp_metadata_validation_rejects_dtd_ambiguity_and_missing_trust() {
        assert_eq!(
            validate_idp_metadata("<!DOCTYPE foo><EntityDescriptor />"),
            Err(SamlMetadataError::DoctypeForbidden)
        );
        assert_eq!(
            validate_idp_metadata(&format!(
                "<EntitiesDescriptor>{METADATA}{}</EntitiesDescriptor>",
                METADATA.replace("idp.example.test", "other.example.test")
            )),
            Err(SamlMetadataError::AmbiguousIdp)
        );
        assert_eq!(
            validate_idp_metadata(&METADATA.replace(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "short"
            )),
            Err(SamlMetadataError::MissingSigningCertificate)
        );
    }

    /// A mock sidecar: a shell command that ignores stdin and prints `stdout_json`.
    fn provider_with_stdout(stdout_json: &str) -> SamlSidecarIdentityProvider {
        SamlSidecarIdentityProvider::new(
            vec![
                "sh".into(),
                "-c".into(),
                format!("cat >/dev/null; printf '%s' '{stdout_json}'"),
            ],
            CERT,
            "sp-entity-id",
        )
        .with_mapping(SamlClaimMapping {
            email_attribute: None,
            roles_attribute: Some("roles".into()),
            region_attribute: Some("region".into()),
            tenant_attribute: Some("org".into()),
        })
    }

    #[test]
    fn verified_assertion_authenticates_and_maps_attributes() {
        let idp = provider_with_stdout(
            r#"{"ok":true,"subject":"alice@acme.com","assertion_id":"_a1","not_on_or_after":4102444799000,"attributes":{"roles":["admin","member"],"region":["eu"],"org":["acme"]}}"#,
        );
        let authority = idp
            .authenticate("<base64 saml response>")
            .expect("authenticates");
        assert_eq!(authority, AuthorityId::new("alice@acme.com"));
        let attrs = idp.claims(&authority);
        assert!(attrs.roles.contains(&Role::admin()));
        assert!(attrs.roles.contains(&Role::member()));
        assert_eq!(attrs.region, Some(Region::new("eu")));
        assert_eq!(attrs.affiliation, Some(Tenant::new("acme")));
    }

    #[test]
    fn signed_email_attribute_supports_an_opaque_name_id() {
        let idp = SamlSidecarIdentityProvider::new(
            vec![
                "sh".into(),
                "-c".into(),
                r#"cat >/dev/null; printf '%s' '{"ok":true,"subject":"opaque-7","assertion_id":"_email","not_on_or_after":4102444799000,"attributes":{"mail":[" Alice@Acme.Example "]}}'"#.into(),
            ],
            CERT,
            "sp-entity-id",
        )
        .with_mapping(SamlClaimMapping {
            email_attribute: Some("mail".into()),
            ..Default::default()
        });
        let identity = idp
            .authenticate_with_profile("<base64 saml response>")
            .unwrap();
        assert_eq!(identity.authority.as_str(), "opaque-7");
        assert_eq!(
            identity.verified_email.as_deref(),
            Some("alice@acme.example")
        );
    }

    #[test]
    fn email_shaped_name_id_is_the_closed_default() {
        let idp = provider_with_stdout(
            r#"{"ok":true,"subject":"Alice@Acme.Example","assertion_id":"_name-email","not_on_or_after":4102444799000}"#,
        );
        let identity = idp
            .authenticate_with_profile("<base64 saml response>")
            .unwrap();
        assert_eq!(
            identity.verified_email.as_deref(),
            Some("alice@acme.example")
        );
    }

    #[test]
    fn a_replayed_assertion_is_rejected() {
        // The same signed assertion (same id) presented twice: first consumes, second
        // is a replay and must be refused (fail-closed).
        let idp = provider_with_stdout(
            r#"{"ok":true,"subject":"alice@acme.com","assertion_id":"_a1","not_on_or_after":4102444799000,"attributes":{}}"#,
        );
        assert_eq!(
            idp.authenticate("<resp>"),
            Some(AuthorityId::new("alice@acme.com"))
        );
        assert_eq!(idp.authenticate("<resp>"), None, "replay must be rejected");
    }

    #[test]
    fn a_verified_assertion_without_an_id_is_rejected() {
        // No assertion id ⇒ single-use cannot be enforced ⇒ fail-closed.
        let idp = provider_with_stdout(r#"{"ok":true,"subject":"alice@acme.com","attributes":{}}"#);
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn replay_cache_is_single_use_per_id_and_prunes_expired() {
        let idp = SamlSidecarIdentityProvider::new(vec!["true".into()], CERT, "sp");
        let now = 1_000_000;
        let far = now + 60_000;
        // First sight of an id within its window: accepted + recorded.
        assert!(idp.record_assertion("_a", far, now));
        // Second sight within the window: a replay.
        assert!(!idp.record_assertion("_a", far, now));
        // A different id is independent.
        assert!(idp.record_assertion("_b", far, now));
        // Once past its expiry the entry is pruned, so memory does not grow without
        // bound (a genuinely expired assertion is already rejected upstream by node-saml).
        assert!(idp.record_assertion("_a", now + 120_000, now + 90_000));
    }

    #[test]
    fn rejection_yields_no_authority() {
        let idp = provider_with_stdout(r#"{"ok":false,"error":"signature did not verify"}"#);
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn empty_subject_is_rejected() {
        let idp = provider_with_stdout(r#"{"ok":true,"subject":"","attributes":{}}"#);
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn sidecar_crash_is_fail_closed() {
        let idp = SamlSidecarIdentityProvider::new(
            vec!["sh".into(), "-c".into(), "exit 1".into()],
            CERT,
            "sp",
        );
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn garbage_output_is_fail_closed() {
        let idp = provider_with_stdout("not json at all");
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn missing_sidecar_binary_is_fail_closed() {
        let idp = SamlSidecarIdentityProvider::new(
            vec!["gaugewright-no-such-sidecar-binary-xyz".into()],
            CERT,
            "sp",
        );
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn unknown_authority_gets_default_claims() {
        let idp = provider_with_stdout(r#"{"ok":true,"subject":"x","attributes":{}}"#);
        assert_eq!(
            idp.claims(&AuthorityId::new("ghost")),
            AuthorityAttributes::default()
        );
    }

    #[test]
    fn command_resolves_from_env_then_cwd() {
        // A vendored binary wins.
        assert_eq!(
            saml_command_from(Some("/opt/gw/saml-verify".into()), None),
            Some(vec!["/opt/gw/saml-verify".to_string()])
        );
        // Else the dev fallback runs the script on node, under cwd.
        assert_eq!(
            saml_command_from(None, Some(Path::new("/repo"))),
            Some(vec![
                "node".to_string(),
                "/repo/ee/sidecar/saml-verify/verify.mjs".to_string()
            ])
        );
        // Blank env is ignored; nothing resolvable ⇒ None.
        assert_eq!(saml_command_from(Some("  ".into()), None), None);
        assert_eq!(saml_command_from(None, None), None);
    }
}
