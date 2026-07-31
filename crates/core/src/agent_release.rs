//! Immutable, self-contained publication artifact for public edge sessions.
//!
//! An [`AgentRelease`] is the complete non-secret input required to create a
//! public session runtime. It deliberately contains bytes rather than Home
//! paths or mutable package references. [`SignedAgentRelease`] binds those
//! bytes to the publishing authority and the content-addressed release id.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ids::PublicKey;
use crate::signature::{verify_signature, Signature, SigningKey};

pub const AGENT_RELEASE_SCHEMA: &str = "gaugedesk.agent_release.v1";
pub const AGENT_RELEASE_MEDIA_TYPE: &str = "application/vnd.gaugedesk.agent-release+cbor;v=1";
pub const AGENT_RELEASE_SIGNATURE_ALGORITHM: &str = "p256-sha256";
pub const AGENT_RELEASE_HASH_ALGORITHM: &str = "sha256";

/// Complete immutable payload. Secret provider credentials, mutable account
/// state, audience identities and deployment policy do not belong here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRelease {
    pub schema: String,
    pub published_at_unix_ms: u64,
    pub source_revision: String,
    pub runtime: RuntimeCompatibility,
    pub host_policy: HostPolicyClosure,
    pub package: PackageClosure,
    pub persona: PersonaClosure,
    pub initial_workspace: Vec<ReleaseFile>,
    pub capabilities: CapabilityManifest,
    pub panels: PanelManifest,
    pub provider: ProviderPolicy,
    pub retention: RetentionPolicy,
    /// What, if anything, a session may return to the deployment owner. Absent
    /// means a session emits nothing. Declared by the author and enforced by the
    /// host; it is deliberately not reachable from the agent's ability set, so
    /// an induced agent can neither widen nor suppress it (ADR 0109 §5).
    #[serde(default)]
    pub collection: Option<CollectionPolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionPolicy {
    /// Release-relative workspace paths eligible to leave the session. A
    /// trailing `/*` matches one path segment; a bare `**` is refused.
    pub exportable_paths: Vec<String>,
    /// Declared independently of the workspace: a filled structured document
    /// and a raw record of everything a visitor typed differ in disclosure.
    pub transcript_eligible: bool,
    /// Schema identity both the session and the receiving Home validate against.
    pub schema_ref: String,
    /// Non-secret recipient class. The deployment names the exact recipient
    /// reference and must prove it belongs to this class before admission.
    pub recipient_class: String,
    pub max_artifact_bytes: u64,
}

/// Hard ceiling on a declared artifact, independent of the author's own bound.
pub const MAX_COLLECTION_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPolicyClosure {
    pub epoch: u64,
    pub signed_envelope: String,
    pub expected_signer: String,
    pub signer_public_key_hex: String,
    pub provider_binding_ref: String,
    /// Author-approved non-secret credential class. The deployment-selected
    /// exact hosted credential reference is deliberately not release content.
    pub credential_class: String,
    pub placement_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCompatibility {
    /// Exact public-session host protocol, not a semver range.
    pub host_protocol: String,
    /// Exact runtime build ABI understood by the published package.
    pub runtime_abi: String,
    /// Features the Session DO must truthfully implement before activation.
    pub required_host_capabilities: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageClosure {
    pub version_ref: String,
    pub entrypoint: String,
    /// Every authored package and locked dependency file needed at runtime.
    pub files: Vec<ReleaseFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaClosure {
    pub system_prompt: String,
    pub instructions: Vec<ReleaseFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFile {
    /// Normalized release-relative path using `/`.
    pub path: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

impl ReleaseFile {
    pub fn new(
        path: impl Into<String>,
        media_type: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        let bytes = bytes.into();
        Self {
            path: path.into(),
            media_type: media_type.into(),
            sha256: sha256_hex(&bytes),
            bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    /// Capabilities requested by the authored program.
    pub required: BTreeSet<String>,
    /// Maximum capability ceiling the deployment may grant to a session.
    pub ceiling: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanelManifest {
    /// Custom-element names exported by the shared GaugeDesk workbench UI.
    pub components: BTreeSet<String>,
    pub default_component: String,
    pub attribution: AttributionPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionPolicy {
    GaugeWright,
    WhiteLabelEligible,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPolicy {
    /// Stable hosted-provider adapter id.
    pub provider: String,
    pub model: String,
    pub base_url: String,
    /// Names a deployment-time credential class; never a credential or secret.
    pub credential_class: String,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub idle_ttl_seconds: u64,
    pub absolute_ttl_seconds: u64,
    pub transcript_retained: bool,
    pub workspace_retained: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAgentRelease {
    pub media_type: String,
    pub payload_sha256: String,
    pub signer_key_id: String,
    pub signer_public_key: PublicKey,
    pub signature_algorithm: String,
    pub signature: Signature,
    pub payload: AgentRelease,
}

/// Capabilities and exact protocols implemented by the deployed Session DO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicDoRuntimeSupport {
    pub host_protocol: String,
    pub runtime_abi: String,
    pub host_capabilities: BTreeSet<String>,
    pub providers: BTreeSet<String>,
    pub panel_components: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentReleaseError {
    Encoding,
    Invalid(&'static str),
    DigestMismatch,
    InvalidPublicKey,
    SignatureMismatch,
    UnsupportedHostProtocol,
    UnsupportedRuntimeAbi,
    UnsupportedHostCapability(String),
    UnsupportedProvider(String),
    UnsupportedPanel(String),
}

impl fmt::Display for AgentReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding => write!(f, "agent release could not be encoded"),
            Self::Invalid(reason) => write!(f, "invalid agent release: {reason}"),
            Self::DigestMismatch => write!(f, "agent release digest does not match its payload"),
            Self::InvalidPublicKey => write!(f, "agent release signer public key is invalid"),
            Self::SignatureMismatch => write!(f, "agent release signature does not verify"),
            Self::UnsupportedHostProtocol => {
                write!(f, "agent release host protocol is unsupported")
            }
            Self::UnsupportedRuntimeAbi => write!(f, "agent release runtime ABI is unsupported"),
            Self::UnsupportedHostCapability(capability) => {
                write!(f, "unsupported public host capability `{capability}`")
            }
            Self::UnsupportedProvider(provider) => {
                write!(f, "unsupported public provider `{provider}`")
            }
            Self::UnsupportedPanel(panel) => write!(f, "unsupported panel component `{panel}`"),
        }
    }
}

impl std::error::Error for AgentReleaseError {}

impl AgentRelease {
    /// Deterministic payload bytes used by hashing, signing and managed storage.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AgentReleaseError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes).map_err(|_| AgentReleaseError::Encoding)?;
        Ok(bytes)
    }

    pub fn content_hash(&self) -> Result<String, AgentReleaseError> {
        Ok(format!(
            "{}:{}",
            AGENT_RELEASE_HASH_ALGORITHM,
            sha256_hex(&self.canonical_bytes()?)
        ))
    }

    pub fn sign(
        self,
        signer_key_id: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Result<SignedAgentRelease, AgentReleaseError> {
        self.validate_shape()?;
        let payload_bytes = self.canonical_bytes()?;
        Ok(SignedAgentRelease {
            media_type: AGENT_RELEASE_MEDIA_TYPE.to_owned(),
            payload_sha256: sha256_hex(&payload_bytes),
            signer_key_id: signer_key_id.into(),
            signer_public_key: signing_key.public_key(),
            signature_algorithm: AGENT_RELEASE_SIGNATURE_ALGORITHM.to_owned(),
            signature: signing_key.sign(&payload_bytes),
            payload: self,
        })
    }

    fn validate_shape(&self) -> Result<(), AgentReleaseError> {
        if self.schema != AGENT_RELEASE_SCHEMA {
            return Err(AgentReleaseError::Invalid("unsupported schema"));
        }
        required_text(&self.source_revision, "source revision is required")?;
        required_text(&self.runtime.host_protocol, "host protocol is required")?;
        required_text(&self.runtime.runtime_abi, "runtime ABI is required")?;
        if self.host_policy.epoch == 0 {
            return Err(AgentReleaseError::Invalid("host policy epoch is invalid"));
        }
        required_text(
            &self.host_policy.signed_envelope,
            "signed host policy is required",
        )?;
        required_text(
            &self.host_policy.expected_signer,
            "host policy signer is required",
        )?;
        required_text(
            &self.host_policy.signer_public_key_hex,
            "host policy public key is required",
        )?;
        required_text(
            &self.host_policy.provider_binding_ref,
            "provider binding reference is required",
        )?;
        required_text(
            &self.host_policy.credential_class,
            "credential class is required",
        )?;
        required_text(
            &self.host_policy.placement_ref,
            "placement reference is required",
        )?;
        required_text(&self.package.version_ref, "package version is required")?;
        valid_release_path(&self.package.entrypoint)?;
        if self.package.files.is_empty() {
            return Err(AgentReleaseError::Invalid("package closure is empty"));
        }
        validate_files(&self.package.files)?;
        if !self
            .package
            .files
            .iter()
            .any(|file| file.path == self.package.entrypoint)
        {
            return Err(AgentReleaseError::Invalid(
                "package entrypoint is absent from the closure",
            ));
        }
        validate_files(&self.persona.instructions)?;
        validate_files(&self.initial_workspace)?;
        if !self
            .capabilities
            .required
            .is_subset(&self.capabilities.ceiling)
        {
            return Err(AgentReleaseError::Invalid(
                "required capability exceeds the release ceiling",
            ));
        }
        if let Some(collection) = &self.collection {
            if collection.exportable_paths.is_empty() && !collection.transcript_eligible {
                return Err(AgentReleaseError::Invalid(
                    "collection declares nothing eligible to leave the session",
                ));
            }
            for path in &collection.exportable_paths {
                let selector = path.strip_suffix("/*").unwrap_or(path);
                if selector.is_empty()
                    || selector.starts_with('/')
                    || selector.contains('\\')
                    || selector.contains("**")
                    || selector
                        .split('/')
                        .any(|part| part.is_empty() || part == "." || part == "..")
                {
                    return Err(AgentReleaseError::Invalid(
                        "collection exportable path is not a bounded relative selector",
                    ));
                }
            }
            required_text(&collection.schema_ref, "collection schema is required")?;
            required_text(
                &collection.recipient_class,
                "collection recipient class is required",
            )?;
            if collection.max_artifact_bytes == 0
                || collection.max_artifact_bytes > MAX_COLLECTION_ARTIFACT_BYTES
            {
                return Err(AgentReleaseError::Invalid(
                    "collection artifact bound is outside the permitted range",
                ));
            }
        }
        if self.panels.components.is_empty()
            || !self
                .panels
                .components
                .contains(&self.panels.default_component)
        {
            return Err(AgentReleaseError::Invalid(
                "default panel is not in the panel manifest",
            ));
        }
        for panel in &self.panels.components {
            required_text(panel, "panel component is empty")?;
        }
        required_text(&self.provider.provider, "provider is required")?;
        required_text(&self.provider.model, "provider model is required")?;
        required_text(&self.provider.base_url, "provider base URL is required")?;
        required_text(
            &self.provider.credential_class,
            "provider credential class is required",
        )?;
        if self.provider.max_input_tokens == 0 || self.provider.max_output_tokens == 0 {
            return Err(AgentReleaseError::Invalid(
                "provider token ceilings must be non-zero",
            ));
        }
        if self.retention.idle_ttl_seconds == 0
            || self.retention.absolute_ttl_seconds < self.retention.idle_ttl_seconds
        {
            return Err(AgentReleaseError::Invalid(
                "retention TTLs are inconsistent",
            ));
        }
        Ok(())
    }
}

impl SignedAgentRelease {
    /// Deterministic complete envelope bytes uploaded to managed release
    /// storage. The payload hash remains the release id; this encoding carries
    /// the signature and signer required for offline verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AgentReleaseError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes).map_err(|_| AgentReleaseError::Encoding)?;
        Ok(bytes)
    }

    pub fn release_id(&self) -> String {
        format!("{}:{}", AGENT_RELEASE_HASH_ALGORITHM, self.payload_sha256)
    }

    pub fn verify(&self, support: &PublicDoRuntimeSupport) -> Result<(), AgentReleaseError> {
        if self.media_type != AGENT_RELEASE_MEDIA_TYPE
            || self.signature_algorithm != AGENT_RELEASE_SIGNATURE_ALGORITHM
            || self.signer_key_id.trim().is_empty()
        {
            return Err(AgentReleaseError::Invalid(
                "signed envelope metadata is invalid",
            ));
        }
        self.payload.validate_shape()?;
        let payload_bytes = self.payload.canonical_bytes()?;
        if sha256_hex(&payload_bytes) != self.payload_sha256 {
            return Err(AgentReleaseError::DigestMismatch);
        }
        match verify_signature(&payload_bytes, &self.signature, &self.signer_public_key) {
            Ok(true) => {}
            Ok(false) => return Err(AgentReleaseError::SignatureMismatch),
            Err(_) => return Err(AgentReleaseError::InvalidPublicKey),
        }
        if self.payload.runtime.host_protocol != support.host_protocol {
            return Err(AgentReleaseError::UnsupportedHostProtocol);
        }
        if self.payload.runtime.runtime_abi != support.runtime_abi {
            return Err(AgentReleaseError::UnsupportedRuntimeAbi);
        }
        if let Some(capability) = self
            .payload
            .runtime
            .required_host_capabilities
            .difference(&support.host_capabilities)
            .next()
        {
            return Err(AgentReleaseError::UnsupportedHostCapability(
                capability.clone(),
            ));
        }
        if !support.providers.contains(&self.payload.provider.provider) {
            return Err(AgentReleaseError::UnsupportedProvider(
                self.payload.provider.provider.clone(),
            ));
        }
        if let Some(panel) = self
            .payload
            .panels
            .components
            .difference(&support.panel_components)
            .next()
        {
            return Err(AgentReleaseError::UnsupportedPanel(panel.clone()));
        }
        Ok(())
    }
}

fn validate_files(files: &[ReleaseFile]) -> Result<(), AgentReleaseError> {
    let mut paths = BTreeSet::new();
    for file in files {
        valid_release_path(&file.path)?;
        required_text(&file.media_type, "file media type is required")?;
        if !paths.insert(file.path.as_str()) {
            return Err(AgentReleaseError::Invalid(
                "release closure contains a duplicate path",
            ));
        }
        if sha256_hex(&file.bytes) != file.sha256 {
            return Err(AgentReleaseError::Invalid(
                "release file digest does not match its bytes",
            ));
        }
    }
    Ok(())
}

fn valid_release_path(path: &str) -> Result<(), AgentReleaseError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with("./")
        || path.contains('\\')
        || path.split('/').any(|part| part.is_empty() || part == "..")
    {
        return Err(AgentReleaseError::Invalid("release file path is unsafe"));
    }
    Ok(())
}

fn required_text(value: &str, reason: &'static str) -> Result<(), AgentReleaseError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(AgentReleaseError::Invalid(reason))
    } else {
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release() -> AgentRelease {
        AgentRelease {
            schema: AGENT_RELEASE_SCHEMA.to_owned(),
            published_at_unix_ms: 1_800_000_000_000,
            source_revision: "agent-version:7".to_owned(),
            runtime: RuntimeCompatibility {
                host_protocol: "gaugewright.public-session.v1".to_owned(),
                runtime_abi: "whipplescript-do.v1".to_owned(),
                required_host_capabilities: BTreeSet::from([
                    "direct_provider_stream".to_owned(),
                    "hibernatable_websocket".to_owned(),
                ]),
            },
            host_policy: HostPolicyClosure {
                epoch: 1,
                signed_envelope: "signed-policy".to_owned(),
                expected_signer: "gaugedesk:test".to_owned(),
                signer_public_key_hex: "02abc".to_owned(),
                provider_binding_ref: "model".to_owned(),
                credential_class: "managed-openai".to_owned(),
                placement_ref: "public-do".to_owned(),
            },
            package: PackageClosure {
                version_ref: "whip:package:7".to_owned(),
                entrypoint: "agent/package.json".to_owned(),
                files: vec![
                    ReleaseFile::new(
                        "agent/package.json",
                        "application/json",
                        br#"{"entrypoint":"main.whip"}"#.to_vec(),
                    ),
                    ReleaseFile::new(
                        "agent/main.whip",
                        "text/x-whipplescript",
                        b"workflow Published {}".to_vec(),
                    ),
                    ReleaseFile::new(
                        "deps/std.lock",
                        "application/json",
                        br#"{"std":"sha256:abc"}"#.to_vec(),
                    ),
                ],
            },
            persona: PersonaClosure {
                system_prompt: "You are the published agent.".to_owned(),
                instructions: vec![ReleaseFile::new(
                    "persona/AGENTS.md",
                    "text/markdown",
                    b"Be exact.".to_vec(),
                )],
            },
            initial_workspace: vec![ReleaseFile::new(
                "workspace/README.md",
                "text/markdown",
                b"# Session workspace".to_vec(),
            )],
            capabilities: CapabilityManifest {
                required: BTreeSet::from(["workspace.read".to_owned()]),
                ceiling: BTreeSet::from([
                    "workspace.read".to_owned(),
                    "workspace.write".to_owned(),
                ]),
            },
            panels: PanelManifest {
                components: BTreeSet::from([
                    "gw-chat-panel".to_owned(),
                    "gw-viewer-panel".to_owned(),
                ]),
                default_component: "gw-chat-panel".to_owned(),
                attribution: AttributionPolicy::GaugeWright,
            },
            provider: ProviderPolicy {
                provider: "openai".to_owned(),
                model: "gpt-5.1".to_owned(),
                base_url: "https://api.openai.com".to_owned(),
                credential_class: "managed-openai".to_owned(),
                max_input_tokens: 100_000,
                max_output_tokens: 8_000,
            },
            retention: RetentionPolicy {
                idle_ttl_seconds: 86_400,
                absolute_ttl_seconds: 2_592_000,
                transcript_retained: true,
                workspace_retained: true,
            },
            // Most releases collect nothing; the declaring case has its own
            // shape tests below.
            collection: None,
        }
    }

    fn support() -> PublicDoRuntimeSupport {
        PublicDoRuntimeSupport {
            host_protocol: "gaugewright.public-session.v1".to_owned(),
            runtime_abi: "whipplescript-do.v1".to_owned(),
            host_capabilities: BTreeSet::from([
                "direct_provider_stream".to_owned(),
                "hibernatable_websocket".to_owned(),
            ]),
            providers: BTreeSet::from(["openai".to_owned()]),
            panel_components: BTreeSet::from([
                "gw-chat-panel".to_owned(),
                "gw-viewer-panel".to_owned(),
                "gw-files-panel".to_owned(),
            ]),
        }
    }

    #[test]
    fn canonical_release_hash_is_stable_and_content_addressed() {
        let first = release();
        let second = release();
        assert_eq!(
            first.canonical_bytes().unwrap(),
            second.canonical_bytes().unwrap()
        );
        assert_eq!(
            first.content_hash().unwrap(),
            second.content_hash().unwrap()
        );
        assert!(first.content_hash().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn signed_complete_release_verifies_for_exact_public_runtime() {
        let key = SigningKey::from_seed(&[21; 32]).unwrap();
        let signed = release().sign("publisher:test", &key).unwrap();
        assert_eq!(signed.release_id(), signed.payload.content_hash().unwrap());
        assert_eq!(signed.verify(&support()), Ok(()));
    }

    #[test]
    fn tampered_payload_and_file_bytes_fail_closed() {
        let key = SigningKey::from_seed(&[21; 32]).unwrap();
        let mut signed = release().sign("publisher:test", &key).unwrap();
        signed.payload.persona.system_prompt.push_str(" tampered");
        assert_eq!(
            signed.verify(&support()),
            Err(AgentReleaseError::DigestMismatch)
        );

        let mut bad_file = release();
        bad_file.package.files[0].bytes.push(b'!');
        assert!(matches!(
            bad_file.sign("publisher:test", &key),
            Err(AgentReleaseError::Invalid(
                "release file digest does not match its bytes"
            ))
        ));
    }

    #[test]
    fn unsupported_do_feature_provider_and_panel_are_rejected() {
        let key = SigningKey::from_seed(&[21; 32]).unwrap();
        let signed = release().sign("publisher:test", &key).unwrap();

        let mut missing_feature = support();
        missing_feature
            .host_capabilities
            .remove("hibernatable_websocket");
        assert_eq!(
            signed.verify(&missing_feature),
            Err(AgentReleaseError::UnsupportedHostCapability(
                "hibernatable_websocket".to_owned()
            ))
        );

        let mut missing_provider = support();
        missing_provider.providers.clear();
        assert_eq!(
            signed.verify(&missing_provider),
            Err(AgentReleaseError::UnsupportedProvider("openai".to_owned()))
        );

        let mut missing_panel = support();
        missing_panel.panel_components.remove("gw-viewer-panel");
        assert_eq!(
            signed.verify(&missing_panel),
            Err(AgentReleaseError::UnsupportedPanel(
                "gw-viewer-panel".to_owned()
            ))
        );
    }

    #[test]
    fn release_is_self_contained_after_source_paths_disappear() {
        let key = SigningKey::from_seed(&[21; 32]).unwrap();
        let signed = release().sign("publisher:test", &key).unwrap();
        let bytes = signed.payload.canonical_bytes().unwrap();
        let restored: AgentRelease = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(restored, signed.payload);
        assert!(restored
            .package
            .files
            .iter()
            .any(|file| file.path == "deps/std.lock" && !file.bytes.is_empty()));
        assert!(restored
            .initial_workspace
            .iter()
            .any(|file| file.path == "workspace/README.md"));
    }
}
