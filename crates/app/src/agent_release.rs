//! GaugeDesk-side construction of immutable public [`AgentRelease`] artifacts.
//!
//! This module is intentionally a one-way export. It reads the selected,
//! already-published archetype bytes and returns a signed, self-contained
//! release. It does not create a hosted session, retain a Home callback, or
//! publish a mutable placement reference.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use gaugedesk_core::agent_release::{
    AgentRelease, CapabilityManifest, CollectionPolicy, HostPolicyClosure, PackageClosure,
    PanelManifest, PersonaClosure, ProviderPolicy, ReleaseFile, RetentionPolicy,
    RuntimeCompatibility, SignedAgentRelease, AGENT_RELEASE_MEDIA_TYPE, AGENT_RELEASE_SCHEMA,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use whipplescript_store::skill_frontmatter::parse_skill_frontmatter;

use crate::app_support::LockUnpoisoned;
use crate::key_store::FileKeyStore;
use crate::library::{
    Admission, ArchetypeVersionRecord, DeploymentAudience, DeploymentAudienceOidc,
    DeploymentBindingStatus, DeploymentOperationalConfig, InstanceKind, InstanceRecord,
    PlacementKind, PublicDeploymentBindingRecord, RecordOp, LIBRARY_RECORD_SCHEMA,
};
use crate::library_state::{published_discipline_root, published_package_root};
use crate::Workbench;

pub const PUBLIC_SESSION_HOST_PROTOCOL: &str = "gaugewright.public-session.v1";
pub const WHIPPLESCRIPT_DO_RUNTIME_ABI: &str = "whipplescript-do.v1";
pub const DIRECT_PROVIDER_STREAM: &str = "direct_provider_stream";
pub const HIBERNATABLE_WEBSOCKET: &str = "hibernatable_websocket";
pub const PUBLISHER_PROTOCOL: &str = "gaugewright.publisher.v1";
const PUBLIC_PUBLISHER_KEY_SUFFIX: &str = "::public-publisher";
const DEFAULT_PUBLIC_TURN_RESERVE_CENTS: u64 = 5;

fn reservation_cents_for_spend_guards(
    max_spend_cents: Option<u64>,
    max_session_spend_cents: Option<u64>,
    max_turn_spend_cents: Option<u64>,
) -> u64 {
    [
        max_spend_cents,
        max_session_spend_cents,
        max_turn_spend_cents,
    ]
    .into_iter()
    .flatten()
    .min()
    .map(|tightest_guard| tightest_guard.min(DEFAULT_PUBLIC_TURN_RESERVE_CENTS))
    .unwrap_or(0)
}

fn preview_release_spec(
    profile: &crate::library::PanelPublicProfile,
    published_at_unix_ms: u64,
) -> ReleasePublishSpec {
    ReleasePublishSpec {
        published_at_unix_ms,
        public_abilities: profile.public_abilities.clone(),
        panels: profile.panels.clone(),
        audience_inputs: profile.audience_inputs.clone(),
        provider: profile.provider.clone(),
        retention: profile.retention.clone(),
        initial_workspace: profile.initial_workspace.clone(),
        collection: profile.collection.clone(),
    }
}

fn discipline_media_type(path: &str) -> &'static str {
    if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".md") {
        "text/markdown"
    } else {
        "application/octet-stream"
    }
}

/// Deletes only the two generated version directories named by a disposable
/// draft snapshot. The authoring draft and every real numeric version are
/// outside these exact paths.
struct PreviewSnapshot {
    roots: Vec<std::path::PathBuf>,
}

impl Drop for PreviewSnapshot {
    fn drop(&mut self) {
        for root in &self.roots {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

/// Turn one immutable discipline bundle into the two release channels the
/// public runtime understands. A standards-compliant top-level `SKILL.md`
/// makes the bundle an Agent Skill: its instructions and relative resources
/// are seeded under `.agents/skills/<name>/` for metadata-first discovery and
/// on-demand reads. Explicit `workspace/` assets remain ordinary session files;
/// bundles without a skill retain the legacy always-on instruction treatment.
fn release_discipline_files(
    files: Vec<(String, String)>,
) -> io::Result<(Vec<ReleaseFile>, Vec<ReleaseFile>)> {
    let skill_name = files
        .iter()
        .find(|(path, _)| path == "SKILL.md")
        .map(|(_, body)| {
            parse_skill_frontmatter(body)
                .map(|frontmatter| frontmatter.name)
                .map_err(invalid)
        })
        .transpose()?;
    let mut workspace = Vec::new();
    let mut instructions = Vec::new();
    for (path, body) in files {
        let media_type = discipline_media_type(&path);
        if path.starts_with("workspace/") {
            workspace.push(ReleaseFile::new(path, media_type, body.into_bytes()));
        } else if let Some(name) = &skill_name {
            if path == crate::discipline::DISCIPLINE_MANIFEST {
                instructions.push(ReleaseFile::new(
                    format!("discipline/{path}"),
                    media_type,
                    body.into_bytes(),
                ));
            } else {
                workspace.push(ReleaseFile::new(
                    format!("workspace/.agents/skills/{name}/{path}"),
                    media_type,
                    body.into_bytes(),
                ));
            }
        } else {
            instructions.push(ReleaseFile::new(
                format!("discipline/{path}"),
                media_type,
                body.into_bytes(),
            ));
        }
    }
    Ok((workspace, instructions))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublisherAuthorization {
    pub authority: String,
    pub public_key: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
}

impl PublisherAuthorization {
    pub fn apply(&self, request: ureq::Request) -> ureq::Request {
        request
            .set("x-gw-publisher-authority", &self.authority)
            .set("x-gw-publisher-key", &self.public_key)
            .set("x-gw-publisher-timestamp", &self.timestamp)
            .set("x-gw-publisher-nonce", &self.nonce)
            .set("x-gw-publisher-signature", &self.signature)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasePublishSpec {
    pub published_at_unix_ms: u64,
    pub public_abilities: BTreeSet<String>,
    pub panels: PanelManifest,
    pub audience_inputs: BTreeSet<String>,
    pub provider: ProviderPolicy,
    pub retention: RetentionPolicy,
    /// Exact selected initial session content. Paths are release-relative and
    /// validated by the core; no target/Home path is serialized.
    pub initial_workspace: Vec<ReleaseFile>,
    /// What a session may return. Absent means it returns nothing.
    pub collection: Option<CollectionPolicy>,
}

pub type PublishAudience = DeploymentAudience;
pub type PublishAudienceOidc = DeploymentAudienceOidc;

/// Product-facing funding choice. The managed variant names the authenticated
/// tenant, never a forgeable funding reference; the reference is derived from
/// the Hub-signed claims after minting. Legacy request fields remain readable
/// below for old automation during the migration window.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeploymentFundingSelection {
    Managed {
        tenant_id: String,
        #[serde(default)]
        entitlement: Option<crate::managed_entitlement::Entitlement>,
    },
    Byok {
        credential_ref: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishDeploymentRequest {
    pub placement_id: String,
    pub deployment_id: String,
    pub edge_origin: String,
    pub allowed_origins: Vec<String>,
    /// Optional aggregate, per-session, and per-turn monetary guards. The
    /// legacy reservation field is accepted as a per-turn guard so an older
    /// publisher keeps its exact behavior across ADR 0121.
    #[serde(default)]
    pub max_spend_cents: Option<u64>,
    #[serde(default)]
    pub max_session_spend_cents: Option<u64>,
    #[serde(default)]
    pub max_turn_spend_cents: Option<u64>,
    pub per_visitor_turn_limit: u64,
    pub max_concurrent_sessions: u64,
    #[serde(default)]
    pub funding: Option<DeploymentFundingSelection>,
    #[serde(default)]
    pub funding_ref: String,
    #[serde(default)]
    pub credential_ref: String,
    /// The authenticated account/tenant selected to fund managed inference.
    /// This is used only by the desktop route to acquire a fresh entitlement
    /// from the Hub; it is never written into the hosted deployment config.
    #[serde(default)]
    pub managed_tenant_id: Option<String>,
    /// A fresh Hub-signed entitlement bound to this Workbench's public
    /// publisher key. Hosted compositions mint it in the authenticated browser
    /// plane; the desktop route may acquire it from its sealed Hub session.
    #[serde(default)]
    pub funding_entitlement: Option<crate::managed_entitlement::Entitlement>,
    /// Audience admission for the public deployment. Anonymous remains the
    /// compatibility default, while an explicit OIDC tuple is carried into the
    /// signed publisher request consumed by the edge.
    #[serde(default)]
    pub audience: PublishAudience,
    #[serde(default)]
    pub white_label: bool,
    /// Operative lease for this deployment, within the frozen version ceiling.
    #[serde(default = "default_idle_ttl_seconds")]
    pub retention_idle_ttl_seconds: u64,
    #[serde(default = "default_absolute_ttl_seconds")]
    pub retention_absolute_ttl_seconds: u64,
    /// End every live session as part of this publication (DR-0090).
    ///
    /// Defaults to false, because a visitor's conversation surviving a change
    /// to the deployment hosting it is a property owed to them rather than a
    /// convenience. Set it when the release being replaced was wrong in a way
    /// that should not go on being served, or when the edge refuses a release
    /// that narrows what a live session may do.
    #[serde(default)]
    pub end_sessions: bool,
}

fn default_idle_ttl_seconds() -> u64 {
    86_400
}

fn default_absolute_ttl_seconds() -> u64 {
    2_592_000
}

#[derive(Clone, Debug, Serialize)]
pub struct PublishDeploymentOutcome {
    pub binding_id: String,
    pub project_id: String,
    pub placement_id: String,
    pub deployment_id: String,
    pub release_id: String,
    pub edge_origin: String,
    pub deployment_url: String,
    pub embed_html: String,
    pub deployment: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartPanelPreviewRequest {
    pub agent_id: String,
    /// Present for a project-scoped preview. The placement's pinned version and
    /// frozen profile win; the mutable Library draft is not consulted.
    #[serde(default)]
    pub placement_id: Option<String>,
    pub edge_origin: String,
    pub allowed_origin: String,
    #[serde(default)]
    pub funding: Option<DeploymentFundingSelection>,
    #[serde(default)]
    pub funding_ref: String,
    #[serde(default)]
    pub credential_ref: String,
    #[serde(default)]
    pub managed_tenant_id: Option<String>,
    #[serde(default)]
    pub funding_entitlement: Option<crate::managed_entitlement::Entitlement>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PanelPreviewOutcome {
    pub preview_id: String,
    pub deployment_id: String,
    pub release_id: String,
    pub edge_origin: String,
    pub deployment_url: String,
    pub panels: BTreeSet<String>,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ActivePanelPreview {
    pub edge_origin: String,
    pub deployment_id: String,
    pub expires_at_unix_ms: u64,
}

const PUBLIC_EMBED_LOADER_URL: &str = "https://embed.gaugewright.com/embed.js";

fn customer_embed_html(
    edge_origin: &str,
    deployment_id: &str,
    panel_ceiling: &BTreeSet<String>,
) -> String {
    let panels = ["chat", "viewer", "files", "chats"]
        .into_iter()
        .filter(|panel| panel_ceiling.contains(&format!("gw-{panel}")))
        .collect::<Vec<_>>();
    let children = panels
        .iter()
        .map(|panel| format!("  <gw-{panel}></gw-{panel}>"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "<script type=\"module\" src=\"{PUBLIC_EMBED_LOADER_URL}\"></script>\n\
<gw-session host=\"{edge_origin}/d/{deployment_id}\" panels=\"{}\">\n\
{children}\n\
</gw-session>",
        panels.join(",")
    )
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectDeploymentRequest {
    pub deployment_id: String,
    pub edge_origin: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportLegacyDeploymentRequest {
    pub placement_id: String,
    pub deployment_id: String,
    pub edge_origin: String,
}

#[derive(Debug, Deserialize)]
struct HostedOperationalConfig {
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default)]
    audience: DeploymentAudience,
    funding_ref: String,
    credential_class: String,
    #[serde(default)]
    credential_ref: String,
    #[serde(default)]
    max_spend_cents: Option<u64>,
    #[serde(default)]
    max_session_spend_cents: Option<u64>,
    #[serde(default)]
    max_turn_spend_cents: Option<u64>,
    per_visitor_turn_limit: u64,
    max_concurrent_sessions: u64,
    #[serde(default)]
    white_label: bool,
    retention: HostedRetentionConfig,
}

#[derive(Debug, Deserialize)]
struct HostedRetentionConfig {
    idle_ttl_seconds: u64,
    absolute_ttl_seconds: u64,
}

fn operational_from_hosted_config(
    hosted_config: serde_json::Value,
    expected_credential_class: &str,
) -> io::Result<DeploymentOperationalConfig> {
    let hosted: HostedOperationalConfig = serde_json::from_value(hosted_config)
        .map_err(|error| invalid(format!("hosted operational config is incomplete: {error}")))?;
    if hosted.credential_class != expected_credential_class {
        return Err(invalid(
            "hosted provider posture does not match the selected Panel-agent version",
        ));
    }
    Ok(DeploymentOperationalConfig {
        allowed_origins: hosted.allowed_origins,
        audience: hosted.audience,
        funding_ref: hosted.funding_ref,
        credential_class: hosted.credential_class,
        credential_ref: hosted.credential_ref,
        max_spend_cents: hosted.max_spend_cents,
        max_session_spend_cents: hosted.max_session_spend_cents,
        max_turn_spend_cents: hosted.max_turn_spend_cents,
        per_visitor_turn_limit: hosted.per_visitor_turn_limit,
        max_concurrent_sessions: hosted.max_concurrent_sessions,
        white_label: hosted.white_label,
        retention_idle_ttl_seconds: hosted.retention.idle_ttl_seconds,
        retention_absolute_ttl_seconds: hosted.retention.absolute_ttl_seconds,
    })
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlDeploymentRequest {
    pub deployment_id: String,
    pub edge_origin: String,
    pub command: String,
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasePublicSessionRequest {
    pub deployment_id: String,
    pub edge_origin: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainCollectionsRequest {
    pub deployment_id: String,
    pub edge_origin: String,
    /// Only artifacts deposited after this instant are returned.
    #[serde(default)]
    pub after_unix_ms: Option<u64>,
}

/// Drain a deployment's collections all the way into a project's quarantine in
/// one operation (ADR 0110).
///
/// Deliberately one call rather than four the caller sequences: the ordering is
/// load-bearing. Acknowledgement drops the hosted payload, so it may only happen
/// after the plaintext is durably held here — a caller that drained, crashed,
/// and acknowledged on restart would have destroyed what it never kept.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectIntoProjectRequest {
    /// Local project-owned deployment authority. Project, edge, hosted id,
    /// recipient, schema and admission scope are resolved from this record.
    pub binding_id: String,
    #[serde(default)]
    pub after_unix_ms: Option<u64>,
}

/// One artifact the drain could not accept, and why. Refusals are reported, not
/// swallowed, and are never acknowledged — the hosted copy stays until someone
/// understands what went wrong.
#[derive(Clone, Debug, Serialize)]
pub struct CollectionRefusal {
    pub session_id: String,
    pub revision: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CollectIntoProjectOutcome {
    pub deployment_id: String,
    pub project_id: String,
    /// How many artifacts the deposit store still held when we drained.
    pub waiting: u64,
    /// Item ids newly landed in quarantine, awaiting the gate.
    pub landed: Vec<String>,
    /// Artifact ids we already held; their disposition was left alone.
    pub already_held: Vec<String>,
    pub refused: Vec<CollectionRefusal>,
    /// How many sealed payloads the deposit store dropped at our word.
    pub acknowledged: u64,
    /// How many it kept despite the acknowledgement. The collections bucket
    /// carries a seven-day minimum-age deletion lock (DR-0054 Phase D), so a
    /// drain acknowledged minutes after the deposit cannot release the hosted
    /// copy — the acknowledgement still stands and the entry is still drained.
    /// Reported rather than dropped: a caller that only saw `acknowledged`
    /// could not tell custody transferred from nothing having happened.
    pub retained: u64,
    /// The attention count after this drain: items awaiting the gate.
    pub pending_attention: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeCollectionsRequest {
    pub deployment_id: String,
    pub edge_origin: String,
    /// Sessions whose sealed payload may now be dropped. The custody index and
    /// its audit metadata remain.
    pub acknowledge: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPublicCredentialsRequest {
    pub edge_origin: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionPublicCredentialRequest {
    pub edge_origin: String,
    pub provider: String,
    pub credential_class: String,
    pub api_key: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokePublicCredentialRequest {
    pub edge_origin: String,
    pub credential_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageManifestPaths {
    schema: String,
    source: String,
    workflow: String,
    agent: String,
    system_prompt: String,
    capabilities: Vec<String>,
    agent_abilities: Vec<String>,
    max_steps: usize,
}

/// Everything a publisher round trip needs, owned.
///
/// Checked out under a brief workbench lock and used entirely outside it
/// ([ADR 0115](../../../specs/decisions/0115-serialization-is-per-scope-not-per-process.md)
/// §5). A publisher request is a network round trip to the edge; signing it
/// from `&Workbench` forced the caller to hold the global lock for that whole
/// trip, which froze every reader and every other chat behind it.
///
/// One credential signs many requests. That is not just a convenience: a drain
/// signs a `GET` and then an acknowledging `POST` whose body depends on the
/// first response, so a single precomputed authorization could never have
/// covered both.
pub struct PublisherCredential {
    authority: String,
    signing_key: gaugedesk_core::signature::SigningKey,
}

impl PublisherCredential {
    /// Sign one exact hosted publisher command. Each call stamps its own
    /// timestamp and nonce, so a credential is reusable but a signature is not.
    pub fn authorize(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> io::Result<PublisherAuthorization> {
        if !path_and_query.starts_with('/') || path_and_query.contains('#') {
            return Err(invalid("publisher request target is invalid"));
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis()
            .to_string();
        let mut nonce_bytes = [0_u8; 24];
        // p256 0.14 brings a second `getrandom` major into the graph, and the
        // `std::error::Error` impl no longer applies to the one this resolves
        // to, so `io::Error::other` cannot take it directly. `Display` is
        // implemented by every version, so converting through it is stable
        // whichever major wins resolution.
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let nonce = hex::encode(nonce_bytes);
        Ok(sign_publisher_command(
            &self.authority,
            &self.signing_key,
            method,
            path_and_query,
            body,
            &timestamp,
            &nonce,
        ))
    }
}

impl Workbench {
    /// Check out this account's publisher credential so a round trip can run
    /// without holding the workbench.
    pub fn publisher_credential(&self) -> io::Result<PublisherCredential> {
        Ok(PublisherCredential {
            authority: format!("gaugedesk:{}", self.authority().as_str()),
            signing_key: self.public_publisher_signing_key()?,
        })
    }

    /// The public half the Hub binds a managed-inference entitlement to.
    /// Returning it is safe: every publisher command already presents this key
    /// to the edge, while the private half never leaves the key-store boundary.
    pub fn public_publisher_key(&self) -> io::Result<String> {
        Ok(self
            .public_publisher_signing_key()?
            .public_key()
            .as_str()
            .to_owned())
    }

    fn public_publisher_signing_key(&self) -> io::Result<gaugedesk_core::signature::SigningKey> {
        let authority = gaugedesk_core::ids::AuthorityId::new(format!(
            "{}{PUBLIC_PUBLISHER_KEY_SUFFIX}",
            self.authority().as_str(),
        ));
        FileKeyStore::new(self.root_path().join("keys")).random_signing_key(&authority)
    }

    /// Sign one exact hosted publisher command with this account's isolated
    /// public-publishing root.
    ///
    /// `path_and_query` is the request target beginning with `/`; callers send
    /// the exact same bytes and path after this returns. The private key remains
    /// inside the local key-store boundary.
    pub fn authorize_publisher_command(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> io::Result<PublisherAuthorization> {
        self.publisher_credential()?
            .authorize(method, path_and_query, body)
    }

    /// Build and sign the complete release for one using placement.
    ///
    /// The result can be uploaded after this method returns and remains
    /// sufficient when this Workbench and its Home are offline.
    pub fn build_agent_release(
        &self,
        instance_id: &str,
        spec: ReleasePublishSpec,
    ) -> io::Result<SignedAgentRelease> {
        let instance = self
            .library
            .instances
            .get(instance_id)
            .ok_or_else(|| not_found("deployment placement does not exist"))?;
        let agent = self
            .library
            .agents
            .get(&instance.agent_id)
            .ok_or_else(|| not_found("deployment archetype does not exist"))?;
        let version = agent
            .versions
            .get(&instance.version)
            .ok_or_else(|| invalid("deployment archetype version is not published"))?;
        let target = self
            .library
            .authoring_target_for(&agent.id)
            .ok_or_else(|| not_found("archetype authoring target does not exist"))?;

        let package_root =
            published_package_root(&self.targets_dir(), &target.id, instance.version);
        let package =
            gaugedesk_whip_runtime::AuthoredAgentPackage::load(&package_root).map_err(invalid)?;
        if package.version_ref() != version.package_ref {
            return Err(invalid(
                "published package bytes do not match the selected version",
            ));
        }
        let manifest: PackageManifestPaths =
            serde_json::from_str(package.manifest_document()).map_err(invalid)?;
        if manifest.schema != "whipplescript.agent_package.v0"
            || manifest.workflow.trim().is_empty()
            || manifest.agent.trim().is_empty()
            || manifest.max_steps == 0
        {
            return Err(invalid("published package manifest is incomplete"));
        }
        let manifest_capabilities: BTreeSet<String> =
            manifest.capabilities.iter().cloned().collect();
        let package_capabilities: BTreeSet<String> =
            package.capabilities().iter().cloned().collect();
        if manifest_capabilities != package_capabilities {
            return Err(invalid(
                "published package manifest capability registry is inconsistent",
            ));
        }
        let manifest_abilities: BTreeSet<String> =
            manifest.agent_abilities.iter().cloned().collect();
        let package_abilities: BTreeSet<String> =
            package.agent_abilities().iter().cloned().collect();
        if manifest_abilities != package_abilities {
            return Err(invalid(
                "published package manifest agent abilities are inconsistent",
            ));
        }

        let discipline = crate::discipline::load(
            &published_discipline_root(&self.targets_dir(), &target.id, instance.version),
            package.capabilities().iter().cloned(),
        )
        .map_err(invalid)?;
        if discipline.reference != version.discipline_ref {
            return Err(invalid(
                "published discipline bytes do not match the selected version",
            ));
        }

        let package_prefix = "package";
        let package_manifest_path = format!("{package_prefix}/package.json");
        let package_source_path = format!("{package_prefix}/{}", manifest.source);
        let package_persona_path = format!("{package_prefix}/{}", manifest.system_prompt);
        let package_files = vec![
            ReleaseFile::new(
                package_manifest_path.clone(),
                "application/json",
                package.manifest_document().as_bytes().to_vec(),
            ),
            ReleaseFile::new(
                package_source_path,
                "text/x-whipplescript",
                package.source_document().as_bytes().to_vec(),
            ),
            ReleaseFile::new(
                package_persona_path,
                "text/markdown",
                package.system_prompt_document().as_bytes().to_vec(),
            ),
        ];
        if !spec.public_abilities.is_subset(&package_abilities) {
            return Err(invalid(
                "public ability ceiling exceeds the package agent abilities",
            ));
        }
        let required = spec.public_abilities.clone();
        let signing_key = self.public_publisher_signing_key()?;
        let policy_principal = gaugedesk_whip_runtime::ResourcePolicy {
            reader: BTreeSet::from(["audience".to_owned()]),
            writer: BTreeSet::from(["audience".to_owned()]),
            principal: true,
            internal: false,
        };
        let host_policy = gaugedesk_whip_runtime::HostGovernancePolicy {
            resources: BTreeMap::from([
                (
                    "file:public-session:workspace".to_owned(),
                    gaugedesk_whip_runtime::ResourcePolicy {
                        principal: false,
                        ..policy_principal.clone()
                    },
                ),
                (
                    "memory:public-session:turn-images".to_owned(),
                    gaugedesk_whip_runtime::ResourcePolicy {
                        principal: false,
                        ..policy_principal.clone()
                    },
                ),
                (
                    "command:public-session:workspace".to_owned(),
                    policy_principal.clone(),
                ),
                (
                    "provider:public-session".to_owned(),
                    policy_principal.clone(),
                ),
                ("placement:public-do".to_owned(), policy_principal),
            ]),
            bindings: BTreeMap::from([
                (
                    "project".to_owned(),
                    "file:public-session:workspace".to_owned(),
                ),
                (
                    "turn_images".to_owned(),
                    "memory:public-session:turn-images".to_owned(),
                ),
                (
                    "command".to_owned(),
                    "command:public-session:workspace".to_owned(),
                ),
                ("model".to_owned(), "provider:public-session".to_owned()),
                ("owned".to_owned(), "provider:public-session".to_owned()),
                ("public-do".to_owned(), "placement:public-do".to_owned()),
            ]),
            parties: BTreeMap::from([("audience".to_owned(), "audience".to_owned())]),
            // WhippleScript validates the authored package against the complete
            // package registry carried by the governance epoch. The release's
            // `CapabilityManifest` below is the narrower Panel-agent ability
            // set offered to the public model. Conflating the two made a
            // chat-only Panel profile unable to run any ordinary authored
            // package whose registry also contained workspace abilities.
            capabilities: package_capabilities.clone(),
            provider_bindings: BTreeMap::from([(
                "model".to_owned(),
                gaugedesk_whip_runtime::ProviderBindingPolicy {
                    provider: spec.provider.provider.clone(),
                    model: spec.provider.model.clone(),
                    base_url: spec.provider.base_url.clone(),
                    // WhippleScript custody admits only `credential:<name>`
                    // here, so the class travels in its canonical spelling.
                    // The public session runtime must present exactly this
                    // string when it resolves the binding, while the closure's
                    // `credential_class` below stays the raw class the edge
                    // compares against the deployment config. The runtime
                    // derives one from the other with the same rule;
                    // `envelope_names_the_canonical_class_ref` pins this side.
                    credential_ref: crate::account::canonical_credential_class_ref(
                        &spec.provider.credential_class,
                    ),
                    wire: Some(provider_wire(&spec.provider)?.to_owned()),
                },
            )]),
            placements: BTreeMap::from([(
                "public-do".to_owned(),
                gaugedesk_whip_runtime::WhipplePlacementPolicy {
                    kind: "do".to_owned(),
                    provider_bindings: BTreeSet::from(["model".to_owned()]),
                    command_network: false,
                },
            )]),
            ..gaugedesk_whip_runtime::HostGovernancePolicy::default()
        };
        const HOST_POLICY_EPOCH: u64 = 1;
        let signed_host_policy = gaugedesk_whip_runtime::sign_hosted_policy_envelope(
            &host_policy.to_json().map_err(invalid)?,
            self.authority(),
            &signing_key,
            HOST_POLICY_EPOCH,
        )
        .map_err(invalid)?;
        // Discipline assets under `workspace/` fork into each session's private
        // workspace; everything else is persona instruction. The public host
        // strips the prefix when it seeds, so the release carries it verbatim.
        let (workspace_assets, instructions) = release_discipline_files(discipline.files)?;
        let mut initial_workspace = spec.initial_workspace;
        initial_workspace.extend(workspace_assets);

        let release = AgentRelease {
            schema: AGENT_RELEASE_SCHEMA.to_owned(),
            published_at_unix_ms: spec.published_at_unix_ms,
            source_revision: format!(
                "gaugedesk:archetype:{}:version:{}:{}",
                agent.id, instance.version, version.discipline_ref
            ),
            runtime: RuntimeCompatibility {
                host_protocol: PUBLIC_SESSION_HOST_PROTOCOL.to_owned(),
                runtime_abi: WHIPPLESCRIPT_DO_RUNTIME_ABI.to_owned(),
                required_host_capabilities: BTreeSet::from([
                    DIRECT_PROVIDER_STREAM.to_owned(),
                    HIBERNATABLE_WEBSOCKET.to_owned(),
                ]),
            },
            host_policy: HostPolicyClosure {
                epoch: HOST_POLICY_EPOCH,
                signed_envelope: signed_host_policy,
                expected_signer: self.authority().as_str().to_owned(),
                signer_public_key_hex: signing_key.public_key().as_str().to_owned(),
                provider_binding_ref: "model".to_owned(),
                credential_class: spec.provider.credential_class.clone(),
                placement_ref: "public-do".to_owned(),
            },
            package: PackageClosure {
                version_ref: package.version_ref().to_owned(),
                entrypoint: package_manifest_path,
                files: package_files,
            },
            persona: PersonaClosure {
                system_prompt: package.system_prompt_document().to_owned(),
                instructions,
            },
            initial_workspace,
            capabilities: CapabilityManifest {
                required: required.clone(),
                ceiling: required,
            },
            panels: spec.panels,
            audience_inputs: spec.audience_inputs,
            provider: spec.provider,
            retention: spec.retention,
            collection: spec.collection,
        };

        release
            .sign(
                format!("gaugedesk:{}", self.authority().as_str()),
                &signing_key,
            )
            .map_err(invalid)
    }

    /// Construct the exact public release exercised by Preview without
    /// publishing an Agent version or creating a project/chat record.
    ///
    /// A project preview uses the placement's real pinned version. A Library
    /// preview copies the current draft package and discipline into a generated
    /// high-numbered version directory solely long enough for the ordinary
    /// release builder to validate and sign it. The generated directories and
    /// the in-memory instance/version entries are removed before this method
    /// returns; no append-only store fact is written.
    pub fn build_panel_preview_release(
        &mut self,
        agent_id: &str,
        placement_id: Option<&str>,
        published_at_unix_ms: u64,
    ) -> io::Result<(SignedAgentRelease, crate::library::PanelPublicProfile)> {
        let agent = self
            .library
            .agents
            .get(agent_id)
            .filter(|agent| agent.agent_kind == crate::library::AgentKind::Panel)
            .cloned()
            .ok_or_else(|| invalid("preview requires a Panel agent"))?;
        if let Some(placement_id) = placement_id {
            let placement = self
                .library
                .instances
                .get(placement_id)
                .filter(|placement| {
                    placement.kind == InstanceKind::Using
                        && placement.placement_kind == PlacementKind::Panel
                        && placement.agent_id == agent.id
                })
                .ok_or_else(|| invalid("project preview requires this Panel-agent placement"))?;
            let profile = agent
                .versions
                .get(&placement.version)
                .and_then(|version| version.panel_profile.clone())
                .ok_or_else(|| invalid("project preview placement has no frozen public profile"))?;
            let release = self.build_agent_release(
                placement_id,
                preview_release_spec(&profile, published_at_unix_ms),
            )?;
            return Ok((release, profile));
        }

        let profile = agent
            .panel_profile
            .clone()
            .ok_or_else(|| invalid("Panel-agent draft has no public profile"))?;
        let target_id = self
            .library
            .authoring_target_for(&agent.id)
            .map(|target| target.id.clone())
            .ok_or_else(|| not_found("Panel-agent authoring target does not exist"))?;
        let repo = self.targets_dir().join(&target_id).join("repo");
        let draft_package_root = repo.join(gaugedesk_boundary::definition::DRAFT_ROOT);
        let draft_package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(&draft_package_root)
            .map_err(invalid)?;
        let draft_discipline = crate::discipline::load(
            &repo.join(crate::discipline::DISCIPLINE_DRAFT_ROOT),
            draft_package.capabilities().iter().cloned(),
        )
        .map_err(invalid)?;

        let mut preview_version = u64::MAX;
        while agent.versions.contains_key(&preview_version)
            || published_package_root(&self.targets_dir(), &target_id, preview_version).exists()
            || published_discipline_root(&self.targets_dir(), &target_id, preview_version).exists()
        {
            preview_version = preview_version
                .checked_sub(1)
                .ok_or_else(|| invalid("no disposable preview version is available"))?;
        }
        let package_root = published_package_root(&self.targets_dir(), &target_id, preview_version);
        let discipline_root =
            published_discipline_root(&self.targets_dir(), &target_id, preview_version);
        std::fs::create_dir_all(&package_root)?;
        std::fs::create_dir_all(&discipline_root)?;
        let _snapshot = PreviewSnapshot {
            roots: vec![package_root.clone(), discipline_root.clone()],
        };
        for file in [
            gaugedesk_boundary::definition::MANIFEST_FILE,
            gaugedesk_boundary::definition::SOURCE_FILE,
            gaugedesk_boundary::definition::PERSONA_FILE,
        ] {
            std::fs::copy(draft_package_root.join(file), package_root.join(file))?;
        }
        for (path, body) in &draft_discipline.files {
            let destination = discipline_root.join(path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(destination, body)?;
        }

        let preview_instance_id = crate::library::gen_id("panel-preview-instance");
        let version = ArchetypeVersionRecord {
            package_ref: draft_package.version_ref().to_owned(),
            discipline_ref: draft_discipline.reference,
            panel_profile: Some(profile.clone()),
        };
        self.library
            .agents
            .get_mut(&agent.id)
            .expect("agent was resolved above")
            .versions
            .insert(preview_version, version);
        self.library.instances.insert(
            preview_instance_id.clone(),
            InstanceRecord {
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: preview_instance_id.clone(),
                op: RecordOp::Upsert,
                kind: InstanceKind::Using,
                placement_kind: PlacementKind::Panel,
                agent_id: agent.id.clone(),
                project_id: None,
                version: preview_version,
                admission: Admission::Active,
                collection_recipient: None,
            },
        );
        let release = self.build_agent_release(
            &preview_instance_id,
            preview_release_spec(&profile, published_at_unix_ms),
        );
        self.library.instances.remove(&preview_instance_id);
        if let Some(agent) = self.library.agents.get_mut(&agent.id) {
            agent.versions.remove(&preview_version);
        }
        release.map(|release| (release, profile))
    }

    /// Publish a bounded, expiring public deployment used only by the Preview
    /// surface. It deliberately creates no local deployment binding: there is
    /// no project and therefore no production Inbox or custody destination.
    pub fn start_panel_preview(
        &mut self,
        request: StartPanelPreviewRequest,
    ) -> io::Result<PanelPreviewOutcome> {
        let edge = normalized_edge(&request.edge_origin)?;
        if !request.allowed_origin.starts_with("https://")
            || request.allowed_origin.contains('?')
            || request.allowed_origin.contains('#')
            || request.allowed_origin.trim_end_matches('/') != request.allowed_origin
        {
            return Err(invalid("preview origin must be one exact HTTPS origin"));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let (release, profile) = self.build_panel_preview_release(
            &request.agent_id,
            request.placement_id.as_deref(),
            now.as_millis().try_into().map_err(io::Error::other)?,
        )?;
        let managed = crate::managed_inference::is_managed_funding_ref(&request.funding_ref);
        if request.funding_ref.trim().is_empty() {
            return Err(invalid("preview funding is required"));
        }
        if managed {
            if !request.credential_ref.trim().is_empty() {
                return Err(invalid(
                    "managed preview funding may not name an owner credential",
                ));
            }
            request
                .managed_tenant_id
                .as_deref()
                .filter(|tenant| !tenant.trim().is_empty())
                .ok_or_else(|| invalid("managed preview requires an authenticated tenant"))?;
            let entitlement = request
                .funding_entitlement
                .as_ref()
                .ok_or_else(|| invalid("managed preview requires a Hub entitlement"))?;
            if entitlement.claims.authority != self.public_publisher_key()? {
                return Err(invalid(
                    "managed preview entitlement is not bound to this publisher",
                ));
            }
            if entitlement.claims.exp <= now.as_secs() {
                return Err(invalid("managed preview entitlement has expired"));
            }
            if profile.provider.provider != crate::managed_inference::METERED_GATEWAY_PROVIDER {
                return Err(invalid(
                    "managed preview requires a Panel-agent draft authored for the metered gateway",
                ));
            }
            if let Some(reason) = crate::managed_inference::metered_pairing_error(
                &profile.provider.base_url,
                &profile.provider.model,
            ) {
                return Err(invalid(reason));
            }
        } else {
            if request.credential_ref.trim().is_empty() {
                return Err(invalid("BYOK preview requires an exact owner credential"));
            }
            if request.funding_entitlement.is_some() || request.managed_tenant_id.is_some() {
                return Err(invalid(
                    "BYOK preview may not carry managed funding authority",
                ));
            }
        }

        const PREVIEW_LIFETIME_MS: u64 = 60 * 60 * 1_000;
        const PREVIEW_TOTAL_CENTS: u64 = 100;
        const PREVIEW_SESSION_CENTS: u64 = 50;
        const PREVIEW_TURN_CENTS: u64 = 10;
        let expires_at_unix_ms = u64::try_from(now.as_millis())
            .map_err(io::Error::other)?
            .saturating_add(PREVIEW_LIFETIME_MS);
        let preview_id = crate::library::gen_id("panel-preview");
        let deployment_id = preview_id.clone();
        let release_bytes = release.canonical_bytes().map_err(io::Error::other)?;
        send_publisher_request(
            self,
            &edge,
            "PUT",
            &format!("/v1/releases/{}", release.release_id()),
            &release_bytes,
            AGENT_RELEASE_MEDIA_TYPE,
        )?;
        let idle = profile.retention.idle_ttl_seconds.clamp(1, 3_600);
        let absolute = profile.retention.absolute_ttl_seconds.min(3_600).max(idle);
        let mut config = serde_json::json!({
            "deployment_id": deployment_id,
            "enabled": true,
            "allowed_origins": [request.allowed_origin],
            "panel_ceiling": profile.panels.components.clone(),
            "max_spend_cents": PREVIEW_TOTAL_CENTS,
            "max_session_spend_cents": PREVIEW_SESSION_CENTS,
            "max_turn_spend_cents": PREVIEW_TURN_CENTS,
            "reserve_cents_per_turn": DEFAULT_PUBLIC_TURN_RESERVE_CENTS,
            "per_visitor_turn_limit": 20,
            "max_concurrent_sessions": 1,
            "funding_ref": request.funding_ref,
            "credential_class": profile.provider.credential_class.clone(),
            "credential_ref": request.credential_ref,
            "audience": { "anonymous_allowed": true },
            "pricing": crate::deployment_pricing::pricing_block(),
            "retention": {
                "idle_ttl_seconds": idle,
                "absolute_ttl_seconds": absolute,
                "transcript_retained": profile.retention.transcript_retained,
                "workspace_retained": profile.retention.workspace_retained,
            },
            "white_label": false,
            "preview_expires_at_unix_ms": expires_at_unix_ms,
        });
        if let Some(entitlement) = &request.funding_entitlement {
            config["funding_entitlement"] =
                serde_json::Value::String(serde_json::to_string(entitlement).map_err(invalid)?);
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "config": config,
            "initial_release_id": release.release_id(),
        }))
        .map_err(invalid)?;
        send_publisher_request(
            self,
            &edge,
            "PUT",
            &format!("/v1/deployments/{deployment_id}"),
            &body,
            "application/json",
        )?;
        self.panel_previews.insert(
            preview_id.clone(),
            ActivePanelPreview {
                edge_origin: edge.clone(),
                deployment_id: deployment_id.clone(),
                expires_at_unix_ms,
            },
        );
        Ok(PanelPreviewOutcome {
            preview_id,
            deployment_id: deployment_id.clone(),
            release_id: release.release_id(),
            edge_origin: edge.clone(),
            deployment_url: format!("{edge}/d/{deployment_id}"),
            panels: profile.panels.components,
            expires_at_unix_ms,
        })
    }

    /// Revoke an in-memory preview handle. A failed edge mutation keeps the
    /// handle so the caller can retry; an already-expired preview is forgotten.
    pub fn stop_panel_preview(&mut self, preview_id: &str) -> io::Result<()> {
        let preview = self
            .panel_previews
            .get(preview_id)
            .cloned()
            .ok_or_else(|| not_found("panel preview does not exist"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis() as u64;
        if now >= preview.expires_at_unix_ms {
            self.panel_previews.remove(preview_id);
            return Ok(());
        }
        let path = format!("/v1/deployments/{}", preview.deployment_id);
        let inspection = send_publisher_request(
            self,
            &preview.edge_origin,
            "GET",
            &path,
            &[],
            "application/json",
        )?;
        let inspection: serde_json::Value = serde_json::from_str(&inspection).map_err(invalid)?;
        let revision = inspection
            .pointer("/deployment/activation_revision")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| invalid("preview inspection omitted its revision"))?;
        let body = serde_json::to_vec(&serde_json::json!({
            "command": "revoke",
            "expected_revision": revision,
        }))
        .map_err(invalid)?;
        send_publisher_request(
            self,
            &preview.edge_origin,
            "POST",
            &format!("{path}/control"),
            &body,
            "application/json",
        )?;
        self.panel_previews.remove(preview_id);
        Ok(())
    }

    /// Build, upload, and atomically create one public edge deployment.
    ///
    /// The account root key never leaves the Workbench key store. Every edge
    /// mutation receives a fresh detached signature over its exact request.
    pub fn publish_agent_deployment(
        &mut self,
        request: PublishDeploymentRequest,
    ) -> io::Result<PublishDeploymentOutcome> {
        validate_deployment_id(&request.deployment_id)?;
        let edge = normalized_edge(&request.edge_origin)?;
        let placement = self
            .library
            .instances
            .get(&request.placement_id)
            .filter(|instance| {
                instance.kind == crate::library::InstanceKind::Using
                    && instance.placement_kind == PlacementKind::Panel
            })
            .cloned()
            .ok_or_else(|| invalid("deployment requires a Panel-agent project placement"))?;
        let project_id = placement
            .project_id
            .clone()
            .filter(|project| !project.is_empty())
            .ok_or_else(|| invalid("panel placement has no owning project"))?;
        let agent = self
            .library
            .agents
            .get(&placement.agent_id)
            .ok_or_else(|| not_found("panel agent does not exist"))?;
        let profile = agent
            .versions
            .get(&placement.version)
            .and_then(|version| version.panel_profile.clone())
            .ok_or_else(|| invalid("panel placement has no frozen public profile"))?;
        let recipient = placement.collection_recipient.clone();
        if profile.collection.is_some() && recipient.is_none() {
            return Err(invalid(
                "collecting panel placement has no exact project recipient",
            ));
        }
        if request.allowed_origins.is_empty()
            || request.allowed_origins.iter().any(|origin| {
                !origin.starts_with("https://")
                    || origin.contains('?')
                    || origin.contains('#')
                    || origin.trim_end_matches('/') != origin
            })
        {
            return Err(invalid(
                "allowed origins must be exact HTTPS origins without paths or trailing slashes",
            ));
        }
        if let Some(recipient) = &recipient {
            if recipient.recipient_ref.trim().is_empty()
                || recipient.recipient_public_keys.is_empty()
                || recipient.recipient_public_keys.iter().any(|key| {
                    key.len() < 2
                        || key.len() % 2 != 0
                        || !key.chars().all(|c| c.is_ascii_hexdigit())
                })
            {
                return Err(invalid(
                    "collection requires an exact project recipient and hex public keys",
                ));
            }
        }
        if request.retention_idle_ttl_seconds == 0
            || request.retention_absolute_ttl_seconds < request.retention_idle_ttl_seconds
            || request.retention_idle_ttl_seconds > profile.retention.idle_ttl_seconds
            || request.retention_absolute_ttl_seconds > profile.retention.absolute_ttl_seconds
        {
            return Err(invalid(
                "deployment retention must be positive, ordered, and within the release ceiling",
            ));
        }
        let max_turn_spend_cents = request.max_turn_spend_cents;
        if [
            request.max_spend_cents,
            request.max_session_spend_cents,
            max_turn_spend_cents,
        ]
        .into_iter()
        .flatten()
        .any(|cap| cap == 0)
            || request.per_visitor_turn_limit == 0
            || request.max_concurrent_sessions == 0
            || request.funding_ref.trim().is_empty()
        {
            return Err(invalid(
                "deployment funding, credential, or quota is invalid",
            ));
        }
        let operational = DeploymentOperationalConfig {
            allowed_origins: request.allowed_origins.clone(),
            audience: request.audience.clone(),
            funding_ref: request.funding_ref.clone(),
            credential_class: profile.provider.credential_class.clone(),
            credential_ref: request.credential_ref.clone(),
            max_spend_cents: request.max_spend_cents,
            max_session_spend_cents: request.max_session_spend_cents,
            max_turn_spend_cents,
            per_visitor_turn_limit: request.per_visitor_turn_limit,
            max_concurrent_sessions: request.max_concurrent_sessions,
            white_label: request.white_label,
            retention_idle_ttl_seconds: request.retention_idle_ttl_seconds,
            retention_absolute_ttl_seconds: request.retention_absolute_ttl_seconds,
        };
        let existing = self
            .library
            .public_deployments
            .values()
            .find(|binding| {
                binding.hosted_deployment_id == request.deployment_id && binding.edge_origin == edge
            })
            .cloned();
        if existing
            .as_ref()
            .is_some_and(|binding| binding.placement_id != placement.id)
        {
            return Err(invalid(
                "hosted deployment is already bound to a different Panel placement",
            ));
        }
        let reuses_admitted_operational = existing.as_ref().is_some_and(|binding| {
            binding.status == DeploymentBindingStatus::Active && binding.operational == operational
        });
        // A managed plan funds the turn from GaugeWright's metered rail and the
        // owner is billed from usage, so there is no customer credential to name
        // (ADR 0085 §1, `FUND-1`). BYOK still requires one — an empty reference
        // there is a deployment with nothing to pay with.
        //
        // Naming both is refused rather than disambiguated: the ambiguity is
        // about *who pays*, and resolving it quietly downstream is how a turn
        // gets billed to the wrong party.
        let managed = crate::managed_inference::is_managed_funding_ref(&request.funding_ref);
        if managed && !request.credential_ref.trim().is_empty() {
            return Err(invalid(
                "managed funding may not also name an owner credential",
            ));
        }
        if !managed && request.credential_ref.trim().is_empty() {
            return Err(invalid(
                "BYOK funding requires the owner credential reference",
            ));
        }
        if managed && !(reuses_admitted_operational && request.funding_entitlement.is_none()) {
            let _tenant = request
                .managed_tenant_id
                .as_deref()
                .filter(|tenant| !tenant.trim().is_empty())
                .ok_or_else(|| invalid("managed funding requires an authenticated tenant"))?;
            let entitlement = request
                .funding_entitlement
                .as_ref()
                .ok_or_else(|| invalid("managed funding requires a Hub entitlement"))?;
            let publisher_key = self.public_publisher_signing_key()?.public_key();
            if entitlement.claims.authority != publisher_key.as_str() {
                return Err(invalid(
                    "managed funding entitlement is not bound to this publisher",
                ));
            }
            if entitlement.claims.exp
                <= SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(io::Error::other)?
                    .as_secs()
            {
                return Err(invalid("managed funding entitlement has expired"));
            }
        } else if request.funding_entitlement.is_some()
            || request
                .managed_tenant_id
                .as_deref()
                .is_some_and(|tenant| !tenant.trim().is_empty())
        {
            return Err(invalid(
                "BYOK funding may not carry a managed funding entitlement",
            ));
        }
        // A model and the surface it is admitted against are chosen together
        // here, so this is where they are compared. Publishing an impossible
        // pairing used to succeed and fail later, in front of a visitor, with
        // the reason recorded two systems away.
        if managed {
            if profile.provider.provider != crate::managed_inference::METERED_GATEWAY_PROVIDER {
                return Err(invalid(
                    "managed funding requires a Panel-agent version authored for the metered gateway",
                ));
            }
            if let Some(reason) = crate::managed_inference::metered_pairing_error(
                &profile.provider.base_url,
                &profile.provider.model,
            ) {
                return Err(invalid(reason));
            }
        }

        let path = format!("/v1/deployments/{}", request.deployment_id);
        let inspected =
            send_publisher_response(self, &edge, "GET", &path, &[], "application/json")?;
        if existing.is_none() && inspected.0 == 200 {
            return Err(invalid(
                "legacy hosted deployment requires import and project confirmation before update",
            ));
        }
        if !matches!(inspected.0, 200 | 404) {
            return Err(io::Error::other(format!(
                "edge publisher rejected deployment inspection ({}): {}",
                inspected.0, inspected.1
            )));
        }

        let published_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis()
            .try_into()
            .map_err(io::Error::other)?;
        let release = self.build_agent_release(
            &request.placement_id,
            ReleasePublishSpec {
                published_at_unix_ms,
                public_abilities: profile.public_abilities.clone(),
                panels: profile.panels.clone(),
                audience_inputs: profile.audience_inputs.clone(),
                provider: profile.provider.clone(),
                retention: profile.retention.clone(),
                initial_workspace: profile.initial_workspace.clone(),
                collection: profile.collection.clone(),
            },
        )?;

        let binding_id = existing
            .as_ref()
            .map(|binding| binding.id.clone())
            .unwrap_or_else(|| crate::library::gen_id("public-deployment"));
        let pending_binding = PublicDeploymentBindingRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: binding_id.clone(),
            op: RecordOp::Upsert,
            project_id: project_id.clone(),
            placement_id: placement.id.clone(),
            hosted_deployment_id: request.deployment_id.clone(),
            edge_origin: edge.clone(),
            active_release_id: existing
                .as_ref()
                .and_then(|binding| binding.active_release_id.clone()),
            operational: operational.clone(),
            status: DeploymentBindingStatus::PendingPublish,
        };
        // An update already has durable active custody. Keep that exact active
        // snapshot visible until the hosted mutation succeeds; overwriting it
        // with `pending_publish` made a rejected update look like the serving
        // release had disappeared. A never-active binding is still recorded
        // before its first network mutation, as ADR 0143 requires.
        if !existing
            .as_ref()
            .is_some_and(|binding| binding.status == DeploymentBindingStatus::Active)
        {
            self.write_public_deployment_record(pending_binding.clone())?;
        }
        let release_bytes = release.canonical_bytes().map_err(io::Error::other)?;
        send_publisher_request(
            self,
            &edge,
            "PUT",
            &format!("/v1/releases/{}", release.release_id()),
            &release_bytes,
            AGENT_RELEASE_MEDIA_TYPE,
        )?;

        // The reservation is an accounting hold, not a per-turn product cap.
        // Bound the small default estimate by the tightest configured guard;
        // an unguarded deployment reserves zero.
        let reserve_cents_per_turn = reservation_cents_for_spend_guards(
            request.max_spend_cents,
            request.max_session_spend_cents,
            max_turn_spend_cents,
        );
        let mut config = serde_json::json!({
            "deployment_id": request.deployment_id.clone(),
            "enabled": true,
            "allowed_origins": request.allowed_origins.clone(),
            "panel_ceiling": profile.panels.components.clone(),
            "max_spend_cents": request.max_spend_cents,
            "max_session_spend_cents": request.max_session_spend_cents,
            "max_turn_spend_cents": max_turn_spend_cents,
            "reserve_cents_per_turn": reserve_cents_per_turn,
            "per_visitor_turn_limit": request.per_visitor_turn_limit,
            "max_concurrent_sessions": request.max_concurrent_sessions,
            "funding_ref": request.funding_ref.clone(),
            "credential_class": profile.provider.credential_class.clone(),
            "credential_ref": request.credential_ref.clone(),
            "audience": request.audience.clone(),
            // Upstream cost plus GaugeWright's margin for fronting the metered
            // rail (ADR 0085 §6, `FUND-1`). Stored in the deployment record, so
            // a published deployment keeps the card it was published under and a
            // later rate change never reprices work already sold.
            "pricing": crate::deployment_pricing::pricing_block(),
            "retention": {
                "idle_ttl_seconds": request.retention_idle_ttl_seconds,
                "absolute_ttl_seconds": request.retention_absolute_ttl_seconds,
                "transcript_retained": profile.retention.transcript_retained,
                "workspace_retained": profile.retention.workspace_retained
            },
            "white_label": request.white_label
        });
        if let Some(entitlement) = &request.funding_entitlement {
            config["funding_entitlement"] =
                serde_json::Value::String(serde_json::to_string(entitlement).map_err(invalid)?);
        }
        if let (Some(collection), Some(recipient)) = (&profile.collection, &recipient) {
            // The release carries the class; the deployment names the exact
            // recipient reference and the edge proves the class before a
            // session is admitted (ADR 0109 §7/§8).
            config["collection"] = serde_json::json!({
                "schema_ref": collection.schema_ref.clone(),
                "recipient_class": collection.recipient_class.clone(),
                "recipient_ref": recipient.recipient_ref.clone(),
                "recipient_public_keys": recipient.recipient_public_keys.clone(),
                "max_artifact_bytes": collection.max_artifact_bytes,
            });
        }
        let response = match inspected {
            (404, _) => {
                let body = serde_json::to_vec(&serde_json::json!({
                    "config": config,
                    "initial_release_id": release.release_id(),
                }))
                .map_err(invalid)?;
                send_publisher_request(self, &edge, "PUT", &path, &body, "application/json")?
            }
            (200, current) => {
                let current: serde_json::Value = serde_json::from_str(&current).map_err(invalid)?;
                // Pricing and retention are host-owned deployment snapshots. A GaugeDesk
                // release update must not replace them with publisher defaults merely
                // because the public configuration was edited.
                for field in ["pricing", "retention"] {
                    if let Some(value) = current.pointer(&format!("/deployment/config/{field}")) {
                        config[field] = value.clone();
                    }
                }
                let active = current
                    .pointer("/deployment/active_release_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| invalid("deployment inspection omitted its active release"))?;
                if reuses_admitted_operational
                    || current.pointer("/deployment/config") == Some(&config)
                {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "expected_release_id": active,
                        "release_id": release.release_id(),
                        "end_sessions": request.end_sessions,
                    }))
                    .map_err(invalid)?;
                    send_publisher_request(
                        self,
                        &edge,
                        "POST",
                        &format!("{path}/activate"),
                        &body,
                        "application/json",
                    )?
                } else {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "config": config,
                        "initial_release_id": release.release_id(),
                        "hard_cutover": true,
                        "expected_release_id": active,
                        "end_sessions": request.end_sessions,
                    }))
                    .map_err(invalid)?;
                    send_publisher_request(self, &edge, "PUT", &path, &body, "application/json")?
                }
            }
            (status, detail) => {
                return Err(io::Error::other(format!(
                    "edge publisher rejected deployment inspection ({status}): {detail}"
                )))
            }
        };
        let deployment: serde_json::Value = serde_json::from_str(&response).map_err(invalid)?;
        let deployment_url = format!("{edge}/d/{}", request.deployment_id);
        let embed_html =
            customer_embed_html(&edge, &request.deployment_id, &profile.panels.components);
        self.write_public_deployment_record(PublicDeploymentBindingRecord {
            active_release_id: Some(release.release_id().to_owned()),
            status: DeploymentBindingStatus::Active,
            ..pending_binding
        })?;
        Ok(PublishDeploymentOutcome {
            binding_id,
            project_id,
            placement_id: placement.id,
            deployment_id: request.deployment_id.clone(),
            release_id: release.release_id().to_owned(),
            edge_origin: edge,
            deployment_url,
            embed_html,
            deployment,
        })
    }

    pub fn inspect_public_deployment(
        &self,
        request: InspectDeploymentRequest,
    ) -> io::Result<serde_json::Value> {
        validate_deployment_id(&request.deployment_id)?;
        let edge = normalized_edge(&request.edge_origin)?;
        let response = send_publisher_request(
            self,
            &edge,
            "GET",
            &format!("/v1/deployments/{}", request.deployment_id),
            &[],
            "application/json",
        )?;
        serde_json::from_str(&response).map_err(invalid)
    }

    /// Confirm the owner-selected project and Panel placement for a hosted
    /// deployment created before local bindings existed. Hosted identity and
    /// active release remain unchanged; this only records the missing local
    /// ownership after verifying the hosted functional surface against the
    /// placement's pinned version.
    pub fn import_legacy_public_deployment(
        &mut self,
        request: ImportLegacyDeploymentRequest,
    ) -> io::Result<serde_json::Value> {
        validate_deployment_id(&request.deployment_id)?;
        let edge = normalized_edge(&request.edge_origin)?;
        let placement = self
            .library
            .instances
            .get(&request.placement_id)
            .filter(|placement| {
                placement.kind == crate::library::InstanceKind::Using
                    && placement.placement_kind == PlacementKind::Panel
            })
            .cloned()
            .ok_or_else(|| invalid("legacy import requires a Panel-agent placement"))?;
        let project_id = placement
            .project_id
            .clone()
            .ok_or_else(|| invalid("panel placement has no owning project"))?;
        let profile = self
            .library
            .agents
            .get(&placement.agent_id)
            .and_then(|agent| agent.versions.get(&placement.version))
            .and_then(|version| version.panel_profile.clone())
            .ok_or_else(|| invalid("panel placement has no frozen public profile"))?;
        if self.library.public_deployments.values().any(|binding| {
            binding.hosted_deployment_id == request.deployment_id && binding.edge_origin == edge
        }) {
            return Err(invalid("hosted deployment already has a local binding"));
        }
        let path = format!("/v1/deployments/{}", request.deployment_id);
        let response = send_publisher_request(self, &edge, "GET", &path, &[], "application/json")?;
        let hosted: serde_json::Value = serde_json::from_str(&response).map_err(invalid)?;
        let active_release_id = hosted
            .pointer("/deployment/active_release_id")
            .and_then(serde_json::Value::as_str)
            .filter(|release| !release.is_empty())
            .ok_or_else(|| invalid("hosted deployment inspection omitted its active release"))?
            .to_owned();
        let hosted_release = send_publisher_request(
            self,
            &edge,
            "GET",
            &format!("/v1/releases/{active_release_id}"),
            &[],
            "application/json",
        )?;
        let hosted_release: serde_json::Value =
            serde_json::from_str(&hosted_release).map_err(invalid)?;
        if hosted_release
            .get("release_id")
            .and_then(serde_json::Value::as_str)
            != Some(active_release_id.as_str())
        {
            return Err(invalid(
                "hosted active release could not be verified for legacy import",
            ));
        }
        let hosted_config = hosted
            .pointer("/deployment/config")
            .cloned()
            .ok_or_else(|| invalid("hosted deployment inspection omitted its config"))?;
        let hosted_panels = hosted_config
            .get("panel_ceiling")
            .and_then(serde_json::Value::as_array)
            .map(|panels| {
                panels
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            })
            .ok_or_else(|| invalid("hosted deployment inspection omitted its panel contract"))?;
        if hosted_panels != profile.panels.components {
            return Err(invalid(
                "hosted deployment panels do not match the selected Panel-agent version",
            ));
        }
        let binding_id = crate::library::gen_id("public-deployment");
        let operational =
            operational_from_hosted_config(hosted_config, &profile.provider.credential_class)?;
        self.write_public_deployment_record(PublicDeploymentBindingRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: binding_id.clone(),
            op: RecordOp::Upsert,
            project_id: project_id.clone(),
            placement_id: placement.id,
            hosted_deployment_id: request.deployment_id.clone(),
            edge_origin: edge,
            active_release_id: Some(active_release_id.clone()),
            operational,
            status: DeploymentBindingStatus::Active,
        })?;
        Ok(serde_json::json!({
            "binding_id": binding_id,
            "project_id": project_id,
            "deployment_id": request.deployment_id,
            "active_release_id": active_release_id,
        }))
    }

    /// Local custody for this account's collection recipient keys.
    ///
    /// Kept beside the signing keys and deliberately separate from backup
    /// recovery material: a backup recipient may not double as a collection
    /// recipient, which is also why the two seal under different KDF domains.
    pub fn collection_recipients(&self) -> crate::collection_recipient::CollectionRecipientStore {
        crate::collection_recipient::CollectionRecipientStore::new(
            self.root_path().join("keys").join("collection"),
        )
    }

    /// Load or create the recipient a collecting deployment seals to, returning
    /// only its publishable half. Republishing reuses the same recipient rather
    /// than orphaning artifacts sealed to a previous one.
    pub fn ensure_collection_recipient(
        &self,
        recipient_id: &str,
    ) -> io::Result<crate::collection_recipient::CollectionRecipient> {
        self.collection_recipients().ensure(recipient_id)
    }

    /// Open one drained artifact locally and re-validate it against this Home's
    /// own copy of the release schema.
    pub fn open_collection_artifact(
        &self,
        recipient_id: &str,
        sealed: &crate::collection_recipient::SealedCollection,
        admission_scope: &str,
        expected_schema_ref: &str,
    ) -> io::Result<crate::collection_recipient::IngestedCollection> {
        let seed = self.collection_recipients().open_seed(recipient_id)?;
        crate::collection_recipient::ingest_sealed_collection(
            sealed,
            &seed,
            admission_scope,
            expected_schema_ref,
        )
        .map_err(io::Error::other)
    }

    /// Drain sealed collections under this account's public-publishing root.
    ///
    /// The hosted side holds ciphertext it cannot read; unsealing happens here
    /// with tenant-held recipient material and is a separate, explicit act.
    pub fn drain_collections(
        &self,
        request: DrainCollectionsRequest,
    ) -> io::Result<serde_json::Value> {
        drain_collections_with(&self.publisher_credential()?, &request)
    }

    /// Local custody for quarantined payload.
    ///
    /// Rooted at the state root's `quarantine/`, a **sibling** of the targets
    /// directory every agent worktree lives under — never inside one. That
    /// placement is the invariant, so it is checked rather than trusted:
    /// [`Workbench::quarantine_isolation_violations`].
    pub fn quarantine_payloads(&self) -> crate::quarantine::QuarantineStore {
        crate::quarantine::QuarantineStore::new(self.root_path().join("quarantine"))
    }

    /// Every live chat worktree — the set of agent file store roots. Exposed so
    /// the boundary can be asserted against worktrees that actually exist
    /// rather than against the layout they are assumed to follow.
    pub fn engagement_worktrees(&self) -> Vec<std::path::PathBuf> {
        self.engagements
            .values()
            .map(|engagement| engagement.path().to_path_buf())
            .collect()
    }

    /// Read one quarantined item's payload for human review.
    ///
    /// The reviewer is a person looking at the content viewer, and a person
    /// reading untrusted text is not an agent under injection — that asymmetry
    /// is the whole reason review-by-hand needs no screening program. No agent
    /// path reaches this: it is a control-plane read, not a file store.
    pub fn read_quarantined_item(&self, project_id: &str, item_id: &str) -> io::Result<Vec<u8>> {
        self.quarantine_payloads().read(project_id, item_id)
    }

    /// Apply a human reviewer's decision to one quarantined item.
    ///
    /// **Deprecated as a decision path.** This once took the verdict straight
    /// from an HTTP route and moved bytes — a privileged runtime service reading
    /// quarantine and writing a workspace, which ADR 0110 §2 forbids in as many
    /// words. Its doc comment justified that with §3's "their approval *is* the
    /// endorsement", which governs *who holds the grant*, not *whether a program
    /// runs*.
    ///
    /// Use [`Workbench::review_through_gate`], which files the answer into the
    /// queue the gate is parked against and lets the gate rule. This remains
    /// only for callers that already hold a gate-produced verdict.
    pub fn review_quarantined_item(
        &mut self,
        project_id: &str,
        item_id: &str,
        _chat_id: &str,
        verdict: crate::gate::Verdict,
    ) -> io::Result<Option<String>> {
        self.apply_project_gate_verdict(project_id, item_id, verdict)
    }

    /// Move one item according to a verdict, and settle its quarantine record.
    ///
    /// The effector, and the only path that writes quarantined bytes into a
    /// workspace. It is verdict-agnostic on purpose: ADR 0117 §1 makes the
    /// project's gate the only *producer* of a verdict, and keeping production
    /// and effect separate is what lets the same code serve a screener's ruling
    /// and a person's without either one becoming a special case.
    pub fn apply_gate_verdict(
        &mut self,
        project_id: &str,
        item_id: &str,
        _chat_id: &str,
        verdict: crate::gate::Verdict,
    ) -> io::Result<Option<String>> {
        self.apply_project_gate_verdict(project_id, item_id, verdict)
    }

    /// Apply a project gate's verdict to the project-owned inbound area. A
    /// work chat may be created later to act on approved material, but it is
    /// neither the owner nor a prerequisite of this custody transition.
    pub fn apply_project_gate_verdict(
        &mut self,
        project_id: &str,
        item_id: &str,
        verdict: crate::gate::Verdict,
    ) -> io::Result<Option<String>> {
        if !self.library.projects.contains_key(project_id) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no such project"));
        }
        let worktree = self
            .targets_dir()
            .join(crate::library_state::managed_project_target_id(project_id))
            .join("repo");
        if !worktree.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "project inbound target is unavailable",
            ));
        }
        let payloads = self.quarantine_payloads();
        let landed = crate::gate::apply_verdict(
            &mut self.store,
            &payloads,
            project_id,
            item_id,
            &worktree,
            verdict,
        )?;
        self.notify_library_changed("quarantine", project_id, "upsert");
        Ok(landed)
    }

    /// Every agent file store root that can reach quarantine. Empty is the
    /// invariant holding (ADR 0110 §1).
    ///
    /// Checks the live chat worktrees *and* the targets directory all future
    /// worktrees are created under, so a violation is caught whether it already
    /// exists or is about to.
    pub fn quarantine_isolation_violations(&self) -> Vec<std::path::PathBuf> {
        let quarantine = self.root_path().join("quarantine");
        let mut roots = self.engagement_worktrees();
        roots.push(self.root_path().join("targets"));
        crate::quarantine::isolation_violations(&quarantine, roots.iter().map(|r| r.as_path()))
    }

    /// Acknowledge drained collections so their sealed payload becomes
    /// deletable. Never call this before the artifacts are durably held here.
    pub fn acknowledge_collections(
        &self,
        request: AcknowledgeCollectionsRequest,
    ) -> io::Result<serde_json::Value> {
        acknowledge_collections_with(&self.publisher_credential()?, &request)
    }

    pub fn control_public_deployment(
        &self,
        request: ControlDeploymentRequest,
    ) -> io::Result<serde_json::Value> {
        validate_deployment_id(&request.deployment_id)?;
        if !matches!(request.command.as_str(), "pause" | "resume" | "revoke") {
            return Err(invalid("deployment control command is invalid"));
        }
        let edge = normalized_edge(&request.edge_origin)?;
        let body = serde_json::to_vec(&serde_json::json!({
            "command": request.command,
            "expected_revision": request.expected_revision,
        }))
        .map_err(invalid)?;
        let response = send_publisher_request(
            self,
            &edge,
            "POST",
            &format!("/v1/deployments/{}/control", request.deployment_id),
            &body,
            "application/json",
        )?;
        serde_json::from_str(&response).map_err(invalid)
    }

    pub fn erase_public_session(
        &self,
        request: ErasePublicSessionRequest,
    ) -> io::Result<serde_json::Value> {
        validate_deployment_id(&request.deployment_id)?;
        if !request.session_id.starts_with("sess_")
            || request.session_id.len() != 37
            || !request.session_id[5..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("public session id is invalid"));
        }
        let edge = normalized_edge(&request.edge_origin)?;
        let response = send_publisher_request(
            self,
            &edge,
            "DELETE",
            &format!(
                "/v1/deployments/{}/sessions/{}",
                request.deployment_id, request.session_id
            ),
            &[],
            "application/json",
        )?;
        serde_json::from_str(&response).map_err(invalid)
    }

    /// List only non-secret metadata for credentials owned by this account.
    pub fn list_public_credentials(
        &self,
        request: ListPublicCredentialsRequest,
    ) -> io::Result<serde_json::Value> {
        let edge = normalized_edge(&request.edge_origin)?;
        let response = send_publisher_request(
            self,
            &edge,
            "GET",
            "/v1/public-credentials",
            &[],
            "application/json",
        )?;
        serde_json::from_str(&response).map_err(invalid)
    }

    /// Send a provider key directly to the account-owned edge registry.
    ///
    /// GaugeDesk does not persist the request or the response. The edge returns
    /// metadata and an opaque reference only.
    pub fn provision_public_credential(
        &self,
        request: ProvisionPublicCredentialRequest,
    ) -> io::Result<serde_json::Value> {
        let edge = normalized_edge(&request.edge_origin)?;
        if !matches!(request.provider.as_str(), "openai" | "anthropic" | "xai")
            || request.credential_class.is_empty()
            || request.api_key.trim().len() < 8
            || request.label.len() > 128
        {
            return Err(invalid("public credential is invalid"));
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "provider": request.provider,
            "credential_class": request.credential_class,
            "api_key": request.api_key,
            "label": request.label,
        }))
        .map_err(invalid)?;
        let response = send_publisher_request(
            self,
            &edge,
            "POST",
            "/v1/public-credentials",
            &body,
            "application/json",
        )?;
        serde_json::from_str(&response).map_err(invalid)
    }

    pub fn revoke_public_credential(
        &self,
        request: RevokePublicCredentialRequest,
    ) -> io::Result<serde_json::Value> {
        let edge = normalized_edge(&request.edge_origin)?;
        if !request.credential_ref.starts_with("credential:public:") {
            return Err(invalid("public credential reference is invalid"));
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "credential_ref": request.credential_ref,
        }))
        .map_err(invalid)?;
        let response = send_publisher_request(
            self,
            &edge,
            "DELETE",
            "/v1/public-credentials",
            &body,
            "application/json",
        )?;
        serde_json::from_str(&response).map_err(invalid)
    }
}

/// Resolve the request dialect from the exact provider surface frozen into a
/// release. Managed inference is one provider identity with three different
/// wire protocols, so provider name alone is deliberately insufficient there.
fn provider_wire(provider: &ProviderPolicy) -> io::Result<&'static str> {
    if provider.provider != crate::managed_inference::METERED_GATEWAY_PROVIDER {
        return gaugedesk_whip_runtime::provider_model_wire_name(&provider.provider);
    }

    let route = crate::managed_inference::metered_route(&provider.model);
    if route.base_url.trim_end_matches('/') != provider.base_url.trim_end_matches('/')
        || route.model != provider.model
    {
        return Err(invalid(format!(
            "managed Panel provider must use model `{}` on `{}`",
            route.model, route.base_url
        )));
    }
    Ok(route.wire)
}

fn drain_collections_with(
    credential: &PublisherCredential,
    request: &DrainCollectionsRequest,
) -> io::Result<serde_json::Value> {
    validate_deployment_id(&request.deployment_id)?;
    let edge = normalized_edge(&request.edge_origin)?;
    let query = request
        .after_unix_ms
        .map(|after| format!("?after={after}"))
        .unwrap_or_default();
    let response = send_publisher_request_with(
        credential,
        &edge,
        "GET",
        &format!(
            "/v1/deployments/{}/collections{query}",
            request.deployment_id
        ),
        &[],
        "application/json",
    )?;
    serde_json::from_str(&response).map_err(invalid)
}

fn acknowledge_collections_with(
    credential: &PublisherCredential,
    request: &AcknowledgeCollectionsRequest,
) -> io::Result<serde_json::Value> {
    validate_deployment_id(&request.deployment_id)?;
    let edge = normalized_edge(&request.edge_origin)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "acknowledge": request.acknowledge,
    }))
    .map_err(invalid)?;
    let response = send_publisher_request_with(
        credential,
        &edge,
        "POST",
        &format!("/v1/deployments/{}/collections", request.deployment_id),
        &body,
        "application/json",
    )?;
    serde_json::from_str(&response).map_err(invalid)
}

/// The whole drain: pull sealed artifacts, open them here, hold the payload in
/// quarantine, index it as awaiting the gate, and only then release the hosted
/// copies.
///
/// Nothing is attached to a chat and nothing is minted as a resource: a drained
/// artifact waits in quarantine until the project's gate passes it into the
/// workspace (ADR 0110).
///
/// **This runs holding no workbench lock, and that is load-bearing rather than
/// an optimization** (ADR 0115 §5). The drain is a network round trip to the
/// edge followed by one ECDH-and-AES open per artifact; under the global lock a
/// survey with a few hundred responses froze every read and every other chat for
/// its whole duration. The three phases below are the same shape a turn uses:
/// check out owned resources under a brief lock, run holding none of the
/// workbench, then take it again only to publish the change.
///
/// The ordering inside phase two is still load-bearing and unchanged: drain →
/// open → hold → record → acknowledge, with a refusal keeping its hosted copy,
/// because acknowledging a payload that is not durably held here loses it.
pub fn collect_into_project(
    workbench: &crate::workbench_state::SharedWorkbench,
    request: CollectIntoProjectRequest,
) -> io::Result<CollectIntoProjectOutcome> {
    // Phase one: check out. Every value here is owned, so nothing below borrows
    // the workbench.
    let (credential, seed, mut store, payloads, binding, schema_ref) = {
        let guard = workbench.lock_unpoisoned();
        let binding = guard
            .library
            .public_deployments
            .get(&request.binding_id)
            .filter(|binding| binding.status == DeploymentBindingStatus::Active)
            .cloned()
            .ok_or_else(|| not_found("no active public deployment binding"))?;
        let placement = guard
            .library
            .instances
            .get(&binding.placement_id)
            .filter(|placement| {
                placement.placement_kind == PlacementKind::Panel
                    && placement.project_id.as_deref() == Some(binding.project_id.as_str())
            })
            .ok_or_else(|| {
                invalid("deployment binding no longer resolves to its Panel placement")
            })?;
        let agent = guard
            .library
            .agents
            .get(&placement.agent_id)
            .ok_or_else(|| invalid("deployment binding's Panel agent is unavailable"))?;
        let schema_ref = agent
            .versions
            .get(&placement.version)
            .and_then(|version| version.panel_profile.as_ref())
            .and_then(|profile| profile.collection.as_ref())
            .map(|collection| collection.schema_ref.clone())
            .ok_or_else(|| invalid("deployment's frozen version does not permit collection"))?;
        let recipient_id = placement
            .collection_recipient
            .as_ref()
            .map(|recipient| recipient.recipient_ref.clone())
            .ok_or_else(|| invalid("deployment's Panel placement has no collection recipient"))?;
        let store = guard
            .store_ref()
            .sibling()
            .map_err(|error| io::Error::other(format!("open a drain store connection: {error}")))?;
        (
            guard.publisher_credential()?,
            guard.collection_recipients().open_seed(&recipient_id)?,
            store,
            guard.quarantine_payloads(),
            binding,
            schema_ref,
        )
    };

    // Phase two: the network round trip and the crypto, holding nothing.
    let drained = drain_collections_with(
        &credential,
        &DrainCollectionsRequest {
            deployment_id: binding.hosted_deployment_id.clone(),
            edge_origin: binding.edge_origin.clone(),
            after_unix_ms: request.after_unix_ms,
        },
    )?;
    let waiting = drained
        .get("waiting")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let artifacts = drained
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis() as u64;

    let mut landed = Vec::new();
    let mut already_held = Vec::new();
    let mut refused = Vec::new();
    let mut acknowledge = Vec::new();

    for entry in artifacts {
        let session_id = entry
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let revision = entry
            .get("revision")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        let mut refuse = |reason: String| {
            refused.push(CollectionRefusal {
                session_id: session_id.clone(),
                revision,
                reason,
            });
        };

        let Some(sealed_value) = entry.get("sealed").filter(|value| !value.is_null()) else {
            // The index entry outlived its object. Say so; do not acknowledge
            // a payload we never received.
            refuse("the deposit store returned no sealed payload".to_owned());
            continue;
        };
        let sealed: crate::collection_recipient::SealedCollection =
            match serde_json::from_value(sealed_value.clone()) {
                Ok(sealed) => sealed,
                Err(error) => {
                    refuse(format!("sealed artifact is not well formed: {error}"));
                    continue;
                }
            };
        let ingested = match crate::collection_recipient::ingest_sealed_collection(
            &sealed,
            &seed,
            &binding.hosted_deployment_id,
            &schema_ref,
        ) {
            Ok(ingested) => ingested,
            Err(error) => {
                refuse(error.to_string());
                continue;
            }
        };

        let artifact_id = crate::quarantine::item_id(&ingested.session_id, ingested.revision);
        // Custody before disposition: an index entry pointing at bytes we do
        // not hold is worse than no entry at all.
        if let Err(error) = payloads.put(&binding.project_id, &artifact_id, &ingested.plaintext) {
            refuse(format!("collected plaintext could not be held: {error}"));
            continue;
        }
        let item = crate::quarantine::QuarantinedItem {
            item_id: artifact_id.clone(),
            source: format!("collection:{}", binding.hosted_deployment_id),
            deployment_binding_id: Some(binding.id.clone()),
            deployment_id: Some(binding.hosted_deployment_id.clone()),
            public_session_id: Some(ingested.session_id.clone()),
            source_id: ingested.session_id.clone(),
            release_id: ingested.release_id.clone(),
            revision: ingested.revision,
            schema_ref: sealed.envelope.schema_ref.clone(),
            byte_len: ingested.plaintext.len() as u64,
            produced_at_unix_ms: entry
                .get("deposited_at_unix_ms")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(sealed.envelope.produced_at_unix_ms),
            arrived_at_unix_ms: now,
            status: crate::quarantine::ItemStatus::Pending,
        };
        match crate::quarantine::record(&mut store, &binding.project_id, &item) {
            Ok(true) => landed.push(artifact_id),
            Ok(false) => already_held.push(artifact_id),
            Err(error) => {
                refuse(format!(
                    "collected artifact could not be recorded: {error:?}"
                ));
                continue;
            }
        }
        acknowledge.push(ingested.session_id);
    }

    // Only what is durably held here. A refusal keeps its hosted copy.
    let released = if acknowledge.is_empty() {
        serde_json::json!({ "acknowledged": 0, "retained": 0 })
    } else {
        acknowledge_collections_with(
            &credential,
            &AcknowledgeCollectionsRequest {
                deployment_id: binding.hosted_deployment_id.clone(),
                edge_origin: binding.edge_origin.clone(),
                acknowledge,
            },
        )?
    };
    let acknowledged = released
        .get("acknowledged")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let retained = released
        .get("retained")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();

    let pending_attention = crate::quarantine::pending_count(&store, &binding.project_id)
        .map_err(|error| io::Error::other(format!("{error:?}")))?;

    // Phase three: publish the change. The projection is stale until this runs,
    // which INV-5 permits — a projection is never authority.
    workbench
        .lock_unpoisoned()
        .notify_library_changed("quarantine", &binding.project_id, "upsert");

    Ok(CollectIntoProjectOutcome {
        deployment_id: binding.hosted_deployment_id,
        project_id: binding.project_id,
        waiting,
        landed,
        already_held,
        refused,
        acknowledged,
        retained,
        pending_attention,
    })
}

pub fn send_publisher_request(
    workbench: &Workbench,
    edge: &str,
    method: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
) -> io::Result<String> {
    send_publisher_request_with(
        &workbench.publisher_credential()?,
        edge,
        method,
        path,
        body,
        content_type,
    )
}

/// The same request against a checked-out credential, so it can be sent without
/// holding the workbench (ADR 0115 §5).
pub fn send_publisher_request_with(
    credential: &PublisherCredential,
    edge: &str,
    method: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
) -> io::Result<String> {
    let (status, response) =
        send_publisher_response_with(credential, edge, method, path, body, content_type)?;
    if (200..300).contains(&status) {
        Ok(response)
    } else {
        // The status the edge actually gave, recorded where it is still known.
        //
        // Everything downstream loses it. This message inlines the edge's
        // response body, so the `502` it becomes carries a payload large enough
        // that Cloudflare — in front of this Home — judges the reply invalid or
        // incomplete and substitutes its own error page. The canary then reports
        // Cloudflare's sentence, which names no origin and no status, and the
        // first failure in the chain is unrecoverable from any log.
        //
        // Status and method only: a path here carries a deployment id, and this
        // is a diagnostic rather than an audit trail.
        tracing::warn!(status, method, "edge publisher rejected a command");
        Err(io::Error::other(EdgeRejection {
            status,
            detail: bounded_upstream(&response),
        }))
    }
}

fn send_publisher_response(
    workbench: &Workbench,
    edge: &str,
    method: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
) -> io::Result<(u16, String)> {
    send_publisher_response_with(
        &workbench.publisher_credential()?,
        edge,
        method,
        path,
        body,
        content_type,
    )
}

fn send_publisher_response_with(
    credential: &PublisherCredential,
    edge: &str,
    method: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
) -> io::Result<(u16, String)> {
    let authorization = credential.authorize(method, path, body)?;
    let request = authorization
        .apply(ureq::request(
            method,
            &format!("{}{path}", normalized_edge(edge)?),
        ))
        .set("content-type", content_type);
    let result = if body.is_empty() {
        request.call()
    } else {
        request.send_bytes(body)
    };
    match result {
        Ok(response) => {
            let status = response.status();
            Ok((status, response.into_string().map_err(io::Error::other)?))
        }
        Err(ureq::Error::Status(status, response)) => {
            let detail = response
                .into_string()
                .unwrap_or_else(|_| "hosted publisher command failed".to_owned());
            Ok((status, detail))
        }
        Err(error) => Err(io::Error::other(error)),
    }
}

/// The upstream's explanation, bounded to a diagnostic.
///
/// This string is inlined into an error that becomes a `502` response body. An
/// edge behind Cloudflare answers a rejection with a full HTML error page, so
/// inlining it whole made the Home's reply large enough to be worth nobody's
/// time to read and — with Cloudflare in front of this Home — large enough to
/// be judged invalid or incomplete and replaced by Cloudflare's own error page.
/// The reply that named the failing origin was therefore the reply most likely
/// to be discarded before anyone saw it.
///
/// Whitespace is collapsed before the bound because a character bound is not a
/// line bound: 400 characters of pretty-printed HTML is still 400 log lines.
fn bounded_upstream(response: &str) -> String {
    const LIMIT: usize = 300;
    let flattened = response.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.is_empty() {
        return "(no response body)".to_owned();
    }
    match flattened.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}… (truncated)", &flattened[..cut]),
        None => flattened,
    }
}

/// A refusal from the publisher edge, carrying the status the edge gave.
///
/// The status used to survive only inside a formatted message, so every caller
/// downstream saw `ErrorKind::Other` and could not tell a request the edge
/// declined from an edge that was down. `/public-deployments/collect` therefore
/// answered `502` to a `422`, the canary retried it as a transient gateway
/// failure, and Cloudflare's substituted page called it an overloaded origin —
/// three layers describing an outage that never happened.
#[derive(Debug)]
pub struct EdgeRejection {
    pub status: u16,
    pub detail: String,
}

impl std::fmt::Display for EdgeRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "edge publisher rejected command ({}): {}",
            self.status, self.detail
        )
    }
}

impl std::error::Error for EdgeRejection {}

/// The status an edge refusal should be reported as.
///
/// A client error upstream is this request's fault and stays a client error: a
/// caller that retries `502` must not be told to retry something the edge will
/// decline identically every time. Anything else the edge says is a genuine
/// gateway condition.
pub fn edge_rejection_status(status: u16) -> u16 {
    if (400..500).contains(&status) {
        status
    } else {
        502
    }
}

pub fn normalized_edge(value: &str) -> io::Result<String> {
    let edge = value.trim().trim_end_matches('/');
    if (!edge.starts_with("https://")
        && !edge.starts_with("http://127.0.0.1:")
        && !edge.starts_with("http://localhost:"))
        || edge.contains('?')
        || edge.contains('#')
    {
        return Err(invalid("edge origin must be HTTPS (or loopback for tests)"));
    }
    Ok(edge.to_owned())
}

pub fn validate_deployment_id(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(invalid("deployment id is invalid"));
    }
    Ok(())
}

fn sign_publisher_command(
    authority: &str,
    signing_key: &gaugedesk_core::signature::SigningKey,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    timestamp: &str,
    nonce: &str,
) -> PublisherAuthorization {
    let canonical = [
        PUBLISHER_PROTOCOL,
        &method.to_ascii_uppercase(),
        path_and_query,
        &hex::encode(Sha256::digest(body)),
        timestamp,
        nonce,
        authority,
    ]
    .join("\n");
    PublisherAuthorization {
        authority: authority.to_owned(),
        public_key: signing_key.public_key().as_str().to_owned(),
        timestamp: timestamp.to_owned(),
        nonce: nonce.to_owned(),
        signature: hex::encode(signing_key.sign(canonical.as_bytes()).as_bytes()),
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn not_found(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, message)
}

#[cfg(test)]
mod publisher_tests {
    use super::*;
    use gaugedesk_core::signature::{verify_signature, Signature, SigningKey};

    #[test]
    fn library_preview_signs_the_draft_without_publishing_or_placing_it() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let mut guard = workbench.lock_unpoisoned();
        guard
            .seed_panel_placement(
                "inst-preview-source",
                crate::library::PanelPublicProfile::default(),
            )
            .unwrap();
        let agent_id = "inst-preview-source-agent";
        let versions_before = guard.library.agents[agent_id].versions.clone();
        let instances_before = guard.library.instances.len();
        let records_before = guard
            .store_ref()
            .records(crate::library::LIBRARY_SCOPE, "agent")
            .unwrap()
            .len();

        let (release, profile) = guard
            .build_panel_preview_release(agent_id, None, 1_800_000_000_000)
            .expect("the mutable draft can be exercised as a signed public release");

        assert_eq!(profile, crate::library::PanelPublicProfile::default());
        assert_eq!(release.payload.panels.components, profile.panels.components);
        assert_eq!(guard.library.agents[agent_id].versions, versions_before);
        assert_eq!(guard.library.instances.len(), instances_before);
        assert_eq!(
            guard
                .store_ref()
                .records(crate::library::LIBRARY_SCOPE, "agent")
                .unwrap()
                .len(),
            records_before,
            "preview appends no Library fact",
        );
        assert!(
            !guard
                .library
                .instances
                .keys()
                .any(|id| id.starts_with("panel-preview-instance-")),
            "the transient instance is gone before the preview is returned",
        );
    }

    /// The public session runtime resolves the provider binding by presenting a
    /// credential id and requiring the signed envelope's binding to carry the
    /// same string (`VerifiedEnvelope::resolve_provider_binding`). The closure
    /// carries the raw class, which the edge compares against the deployment
    /// config; the envelope carries the canonical `credential:` form, which is
    /// the only spelling WhippleScript custody admits. The runtime bridges the
    /// two by deriving the canonical form from the class with this exact rule,
    /// so the rule is pinned here as a literal — a release whose halves the
    /// runtime cannot reconcile passes every validator and refuses its first
    /// turn with "provider binding has no exact realization in the verified
    /// policy epoch", which is what every Panel release built after
    /// 2026-08-27 did until the runtime learned the derivation.
    #[test]
    fn envelope_names_the_canonical_class_ref() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let mut guard = workbench.lock_unpoisoned();
        // The managed metered-gateway profile every production Panel runs on,
        // so the literal pinned below is the one the runtime meets in practice.
        let route = crate::managed_inference::metered_route("gpt-5.6-terra");
        let profile = crate::library::PanelPublicProfile {
            provider: ProviderPolicy {
                provider: crate::managed_inference::METERED_GATEWAY_PROVIDER.to_owned(),
                model: route.model,
                base_url: route.base_url,
                credential_class: "managed-openai".to_owned(),
                max_input_tokens: None,
                max_output_tokens: None,
            },
            ..crate::library::PanelPublicProfile::default()
        };
        guard
            .seed_panel_placement("inst-envelope-agreement", profile)
            .unwrap();

        let (release, _) = guard
            .build_panel_preview_release("inst-envelope-agreement-agent", None, 1_800_000_000_000)
            .unwrap();

        let host_policy = &release.payload.host_policy;
        // A signed envelope is the policy content itself with an `attestation`
        // block added (`SignedEnvelope::to_json`), so the bindings sit at the
        // top level — which is also where the runtime reads them.
        let policy: serde_json::Value = serde_json::from_str(&host_policy.signed_envelope).unwrap();
        assert!(policy["attestation"]["signature"].is_string());
        let binding = &policy["provider_bindings"][host_policy.provider_binding_ref.as_str()];
        assert_eq!(host_policy.credential_class, "managed-openai");
        assert_eq!(
            binding["credential_ref"].as_str(),
            Some("credential:gaugedesk/class/6d616e616765642d6f70656e6169"),
            "the runtime derives this literal from the closure's class; \
             change both sides together (whipplescript worker `credentialIdForHostPolicy`)",
        );
        assert_eq!(
            binding["credential_ref"].as_str(),
            Some(
                crate::account::canonical_credential_class_ref(&host_policy.credential_class)
                    .as_str()
            ),
        );
        assert!(
            policy["placements"][host_policy.placement_ref.as_str()]["provider_bindings"]
                .as_array()
                .is_some_and(|bindings| {
                    bindings
                        .iter()
                        .any(|b| b.as_str() == Some(host_policy.provider_binding_ref.as_str()))
                }),
            "the closure's placement must list the closure's binding",
        );
    }

    #[test]
    fn project_preview_uses_the_placement_profile_not_the_later_library_draft() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let mut guard = workbench.lock_unpoisoned();
        guard
            .seed_panel_placement(
                "inst-preview-pinned",
                crate::library::PanelPublicProfile::default(),
            )
            .unwrap();
        let agent_id = "inst-preview-pinned-agent";
        let mut changed = guard.panel_profile(agent_id).unwrap();
        changed.panels.components.insert("gw-viewer".to_owned());
        guard.set_panel_profile(agent_id, changed).unwrap();

        let (release, tested) = guard
            .build_panel_preview_release(agent_id, Some("inst-preview-pinned"), 1_800_000_000_000)
            .unwrap();

        assert_eq!(
            tested.panels.components,
            BTreeSet::from(["gw-chat".to_owned()])
        );
        assert_eq!(release.payload.panels.components, tested.panels.components);
        assert!(
            guard
                .panel_profile(agent_id)
                .unwrap()
                .panels
                .components
                .contains("gw-viewer"),
            "the mutable draft really did diverge from the pinned placement",
        );
    }

    #[test]
    fn managed_panel_provider_uses_the_wire_declared_by_its_exact_surface() {
        let route = crate::managed_inference::metered_route("gpt-5.6-terra");
        let provider = ProviderPolicy {
            provider: crate::managed_inference::METERED_GATEWAY_PROVIDER.to_owned(),
            model: route.model,
            base_url: route.base_url,
            credential_class: "managed-openai".to_owned(),
            max_input_tokens: None,
            max_output_tokens: None,
        };

        assert_eq!(
            provider_wire(&provider).unwrap(),
            crate::managed_inference::WIRE_OPENAI_RESPONSES,
        );
    }

    #[test]
    fn managed_panel_provider_refuses_a_surface_other_than_the_metered_route() {
        let provider = ProviderPolicy {
            provider: crate::managed_inference::METERED_GATEWAY_PROVIDER.to_owned(),
            model: "gpt-5.6-terra".to_owned(),
            base_url: "https://gateway.example/compat".to_owned(),
            credential_class: "managed-openai".to_owned(),
            max_input_tokens: None,
            max_output_tokens: None,
        };

        let error = provider_wire(&provider).expect_err("the exact metered route is required");
        assert!(error
            .to_string()
            .contains("managed Panel provider must use"));
        assert!(error.to_string().contains("/openai"));
    }

    /// A conversation is kept unless the publisher asks for it to end.
    ///
    /// The default is the whole decision (DR-0090): a request written before
    /// this field existed, or by a caller with no opinion, must not destroy a
    /// stranger's conversation. Flip this default and every republish quietly
    /// becomes a cutover again — which is what it was, when the choice was
    /// made by comparing configurations instead of being stated.
    #[test]
    fn a_publication_that_says_nothing_about_sessions_keeps_them() {
        let request: PublishDeploymentRequest = serde_json::from_str(
            r#"{
                "placement_id": "inst-1",
                "deployment_id": "panel",
                "edge_origin": "https://panels.example",
                "allowed_origins": ["https://example.com"],
                "per_visitor_turn_limit": 20,
                "max_concurrent_sessions": 5,
                "funding_ref": "gaugedesk:managed-plan:v1:61:62",
                "credential_ref": ""
            }"#,
        )
        .expect("a request without the instruction is still a request");
        assert!(
            !request.end_sessions,
            "a publication that says nothing about sessions must keep them",
        );
    }

    /// The edge reads this exact key on both the activation and the
    /// configuration endpoint, and nothing at compile time relates the two
    /// spellings — the same seam the managed-funding prefix test holds in
    /// managed_inference. A drift here is quiet in the worst direction: the
    /// edge would read an absent instruction as false and keep sessions the
    /// publisher believed it had ended.
    #[test]
    fn the_instruction_travels_under_the_name_the_edge_reads() {
        let body = serde_json::json!({ "end_sessions": true });
        assert_eq!(
            body.as_object()
                .and_then(|map| map.keys().next())
                .map(String::as_str),
            Some("end_sessions"),
        );
    }

    #[test]
    fn reservation_is_an_internal_estimate_not_a_turn_limit() {
        assert_eq!(reservation_cents_for_spend_guards(None, None, None), 0);
        assert_eq!(
            reservation_cents_for_spend_guards(Some(1_000), None, None),
            DEFAULT_PUBLIC_TURN_RESERVE_CENTS,
        );
        assert_eq!(reservation_cents_for_spend_guards(None, None, Some(2)), 2);
    }

    #[test]
    fn publisher_signature_binds_every_request_field() {
        let key = SigningKey::from_seed(&[7; 32]).unwrap();
        let authorization = sign_publisher_command(
            "gaugedesk:alice",
            &key,
            "put",
            "/v1/deployments/theory-a",
            br#"{"enabled":true}"#,
            "1800000000000",
            "0123456789abcdef0123456789abcdef",
        );
        let canonical = [
            PUBLISHER_PROTOCOL,
            "PUT",
            "/v1/deployments/theory-a",
            &hex::encode(Sha256::digest(br#"{"enabled":true}"#)),
            "1800000000000",
            "0123456789abcdef0123456789abcdef",
            "gaugedesk:alice",
        ]
        .join("\n");
        assert_eq!(
            verify_signature(
                canonical.as_bytes(),
                &Signature::new(hex::decode(&authorization.signature).unwrap()),
                &key.public_key(),
            ),
            Ok(true),
        );
        assert_ne!(
            sign_publisher_command(
                "gaugedesk:alice",
                &key,
                "POST",
                "/v1/deployments/theory-a",
                br#"{"enabled":true}"#,
                "1800000000000",
                "0123456789abcdef0123456789abcdef",
            )
            .signature,
            authorization.signature,
        );
    }

    #[test]
    fn publisher_audience_defaults_to_anonymous_and_preserves_explicit_oidc() {
        let defaulted: PublishAudience = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(defaulted, PublishAudience::default());

        let configured: PublishAudience = serde_json::from_value(serde_json::json!({
            "anonymous_allowed": false,
            "oidc": {
                "issuer": "https://identity.example",
                "audience": "deployment-audience"
            }
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_value(configured).unwrap(),
            serde_json::json!({
                "anonymous_allowed": false,
                "oidc": {
                    "issuer": "https://identity.example",
                    "audience": "deployment-audience"
                }
            }),
        );
    }

    #[test]
    fn legacy_import_copies_the_hosted_operational_record_instead_of_form_defaults() {
        let operational = operational_from_hosted_config(
            serde_json::json!({
                "deployment_id": "existing",
                "enabled": true,
                "allowed_origins": ["https://customer.example"],
                "panel_ceiling": ["gw-chat"],
                "max_spend_cents": 900,
                "max_session_spend_cents": 90,
                "max_turn_spend_cents": 9,
                "reserve_cents_per_turn": 5,
                "per_visitor_turn_limit": 12,
                "max_concurrent_sessions": 3,
                "funding_ref": "funding:existing",
                "credential_class": "openai-api-key",
                "credential_ref": "credential:existing",
                "audience": { "anonymous_allowed": false, "oidc": {
                    "issuer": "https://identity.example", "audience": "customers"
                }},
                "pricing": {},
                "retention": {
                    "idle_ttl_seconds": 3_600,
                    "absolute_ttl_seconds": 86_400,
                    "transcript_retained": true,
                    "workspace_retained": false
                },
                "white_label": true
            }),
            "openai-api-key",
        )
        .unwrap();

        assert_eq!(operational.allowed_origins, ["https://customer.example"]);
        assert_eq!(operational.funding_ref, "funding:existing");
        assert_eq!(operational.credential_ref, "credential:existing");
        assert_eq!(operational.max_turn_spend_cents, Some(9));
        assert_eq!(operational.per_visitor_turn_limit, 12);
        assert_eq!(operational.max_concurrent_sessions, 3);
        assert!(operational.white_label);
        assert_eq!(operational.retention_idle_ttl_seconds, 3_600);
        assert_eq!(operational.retention_absolute_ttl_seconds, 86_400);
    }

    #[test]
    fn customer_embed_html_uses_stable_urls_and_renders_selected_panels() {
        let html = customer_embed_html(
            "https://panels.gaugewright.com",
            "theo",
            &BTreeSet::from(["gw-chat".to_owned(), "gw-files".to_owned()]),
        );

        assert_eq!(
            html,
            concat!(
                "<script type=\"module\" src=\"https://embed.gaugewright.com/embed.js\"></script>\n",
                "<gw-session host=\"https://panels.gaugewright.com/d/theo\" panels=\"chat,files\">\n",
                "  <gw-chat></gw-chat>\n",
                "  <gw-files></gw-files>\n",
                "</gw-session>"
            )
        );
        assert!(!html.contains("?v="));
        assert!(!html.contains("sha256:"));
    }

    #[test]
    fn agent_skill_bundle_is_seeded_for_progressive_disclosure() {
        let (workspace, instructions) = release_discipline_files(vec![
            (
                "discipline.json".to_owned(),
                r#"{"schema":"gaugedesk.discipline.v1"}"#.to_owned(),
            ),
            (
                "SKILL.md".to_owned(),
                "---\nname: theory-a\ndescription: Explain Theory A.\n---\n# Theory A\n".to_owned(),
            ),
            (
                "references/core.md".to_owned(),
                "# Core reference\n".to_owned(),
            ),
            (
                "workspace/brief.md".to_owned(),
                "# Client brief\n".to_owned(),
            ),
        ])
        .unwrap();

        let paths = workspace
            .iter()
            .map(|file| file.path.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            paths,
            BTreeSet::from([
                "workspace/.agents/skills/theory-a/SKILL.md",
                "workspace/.agents/skills/theory-a/references/core.md",
                "workspace/brief.md",
            ])
        );
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].path, "discipline/discipline.json");
    }

    /// The rejection body is a diagnostic, not a payload.
    ///
    /// An edge behind Cloudflare answers with a full HTML error page. Inlined
    /// whole, that made the Home's `502` large enough for Cloudflare to judge
    /// the reply invalid or incomplete and substitute its own error page — so
    /// the canary reported Cloudflare's sentence, which names neither the
    /// origin nor its status, and the first failure in the chain was lost.
    #[test]
    fn an_upstream_rejection_is_bounded_to_a_diagnostic() {
        assert_eq!(
            bounded_upstream("collection not ready"),
            "collection not ready"
        );
        assert_eq!(bounded_upstream(""), "(no response body)");
        assert_eq!(bounded_upstream("   \n\t "), "(no response body)");

        // A character bound is not a line bound.
        assert_eq!(bounded_upstream("a\n\nb   c"), "a b c");

        // The shape that caused this: a large HTML page.
        let page = format!("<html>{}</html>", "x".repeat(5_000));
        let bounded = bounded_upstream(&page);
        assert!(bounded.len() < 340, "still {} bytes", bounded.len());
        assert!(bounded.ends_with("… (truncated)"));
        // Enough survives to name the upstream.
        assert!(bounded.starts_with("<html>"));

        // Multibyte text must not be cut mid-character.
        let wide = bounded_upstream(&"é".repeat(5_000));
        assert!(wide.ends_with("… (truncated)"));
    }

    /// A client error upstream stays a client error.
    ///
    /// The edge answered `422` to a drain issued before its artifact was ready.
    /// Reported as `502`, that told the canary a gateway had failed, so it
    /// retried — and the shape of the reply then let Cloudflare replace it with
    /// "the origin is overloaded or misconfigured". Three layers describing an
    /// outage that never happened, from one wrong mapping.
    #[test]
    fn an_edge_client_error_is_not_reported_as_a_gateway_failure() {
        assert_eq!(
            edge_rejection_status(422),
            422,
            "the exact refusal survives"
        );
        assert_eq!(edge_rejection_status(400), 400);
        assert_eq!(edge_rejection_status(404), 404);
        assert_eq!(edge_rejection_status(409), 409);
        assert_eq!(edge_rejection_status(499), 499);

        // Anything the edge says that is not a client error is a genuine
        // gateway condition, including its own 5xx.
        assert_eq!(edge_rejection_status(500), 502);
        assert_eq!(edge_rejection_status(502), 502);
        assert_eq!(edge_rejection_status(503), 502);
        assert_eq!(edge_rejection_status(302), 502);
        assert_eq!(edge_rejection_status(200), 502);
    }

    /// The status has to travel on the error, not inside its message. Every
    /// caller downstream sees `ErrorKind::Other`, so a formatted string was
    /// indistinguishable from an edge that was simply down.
    #[test]
    fn an_edge_rejection_carries_its_status_to_the_caller() {
        let error = std::io::Error::other(EdgeRejection {
            status: 422,
            detail: "collection not ready".to_owned(),
        });
        let carried = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<EdgeRejection>())
            .expect("the rejection must survive as itself, not as prose");
        assert_eq!(carried.status, 422);
        // And still reads as the sentence operators had before.
        assert!(error
            .to_string()
            .contains("edge publisher rejected command (422)"));
        assert!(error.to_string().contains("collection not ready"));
    }

    /// A refused release is still an acknowledgement, and the caller has to be
    /// able to tell it from nothing happening.
    ///
    /// The collections bucket carries a seven-day minimum-age deletion lock, so
    /// a drain acknowledged seconds after the deposit always leaves the hosted
    /// copy in place. Reporting only `acknowledged` made that indistinguishable
    /// from an acknowledge that never ran — which is exactly what a canary saw:
    /// `acknowledged 0`, with nothing to say the custody transfer had happened.
    #[test]
    fn a_retained_payload_is_reported_beside_the_released_count() {
        let released = serde_json::json!({ "acknowledged": 0, "retained": 2 });
        assert_eq!(
            released.get("retained").and_then(serde_json::Value::as_u64),
            Some(2),
        );
        // The shape the edge answers when nothing is locked.
        let clean = serde_json::json!({ "acknowledged": 3, "retained": 0 });
        assert_eq!(
            clean
                .get("acknowledged")
                .and_then(serde_json::Value::as_u64),
            Some(3),
        );
        // And an older edge that predates the field reads as zero rather than
        // failing the drain.
        let legacy = serde_json::json!({ "acknowledged": 1 });
        assert_eq!(
            legacy
                .get("retained")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default(),
            0,
        );
    }
}
