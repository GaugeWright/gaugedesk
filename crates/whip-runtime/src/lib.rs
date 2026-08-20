//! GaugeDesk's side of the permanent WhippleScript runtime boundary.
//!
//! This crate deliberately depends on WhippleScript's published trust-boundary
//! types. GaugeDesk may produce product policy, but it must never reimplement the
//! envelope parser, attestation check, or IFC algebra it asks WhippleScript to
//! enforce (ADR 0080 / SUB-1).

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use gaugedesk_core::ids::{AuthorityId, PublicKey};
use gaugedesk_core::signature::{verify_signature, Signature, SigningKey};
use gaugedesk_harness::sandbox::Network;
use gaugedesk_harness::{
    ContextWindowReading, CredentialCapability, CredentialProbe, EgressGate, Harness,
    HarnessContinuitySpec, HarnessFactory, HarnessSpec, ImageContent, Observation, OutputFieldFlow,
    RuntimePosition, ToolInfo, TurnOutcome,
};
pub use whipplescript::gov::{
    external_signing_bytes, external_signing_bytes_v2, ExternalAttestation,
    GovernanceAttestationVerifier, SignedEnvelope,
};
pub use whipplescript::host_policy::{
    HostGovernancePolicy, PlacementPolicy as WhipplePlacementPolicy, ProviderBindingPolicy,
    ResourcePolicy,
};
pub use whipplescript::host_protocol::{
    CredentialRef, EventPosition, ForkInstanceCommand, ForkedInstance, LabeledRuntimeEvent,
    OpenInstanceCommand, OpenedInstance, PolicyEpochRef, ProtocolError, ProviderBindingRef,
    ResourceRef, RuntimeEvidencePointer, StartTurnCommand, TurnInput, TurnReceipt, TurnStatus,
    HOST_PROTOCOL,
};
pub use whipplescript::host_runtime::{
    native_workspace_tool_specs, native_workspace_tool_specs_with_capabilities,
    native_workspace_tool_specs_with_command, AuthoredAgentPackage, CertifiedOutputFieldFlow,
    GovernedHostRuntime, HostCancellationHandle, HostRuntimeError, LabeledTurnOutput,
    ModelProvider, NativeWorkspaceResolver, PackageResolver, ProjectedToolCall, ResolvedImage,
    ResolvedPackage, ResolvedProviderBinding, ResourceResolver, SecretResolver, ToolCall,
    TurnExecution,
};
/// WhippleScript's information-flow surface, re-exported so a host can parse and
/// check the governance envelopes it ships rather than trusting their text.
pub use whipplescript::ifc;

/// One compiled WhippleScript program, with its diagnostics flattened to
/// messages so callers do not need the parser's diagnostic type.
pub struct CompiledWhipProgram {
    pub ir: Option<whipplescript_parser::IrProgram>,
    pub diagnostics: Vec<String>,
}

/// Compile a governed program so it can be admitted before it runs.
///
/// A host that executes a WhippleScript program it did not write — a project's
/// own gate, for instance — must be able to refuse it, and refusing requires
/// compiling it here rather than trusting that it compiled somewhere else.
pub fn compile_whip_program(source: &str) -> CompiledWhipProgram {
    let compiled = whipplescript_parser::compile_program(source);
    CompiledWhipProgram {
        ir: compiled.ir,
        diagnostics: compiled
            .diagnostics
            .into_iter()
            .map(|diagnostic| diagnostic.message)
            .collect(),
    }
}
use whipplescript::ifc::VerifiedEnvelope;

pub mod gate_runner;
/// The sans-I/O HTTP types a gate host implements its transport against.
pub mod sansio_types {
    pub use whipplescript_kernel::sansio::{HttpRequest, HttpResponse, TransportError};
}
mod hosted;
pub use hosted::{DoHostConfig, DoHostRequest, DoHostResponse, DoHostTransport};

pub const GAUGEDESK_ATTESTATION_ALGORITHM: &str = "p256-sha256";

/// The capability that admits asking, declared by GaugeWright's package manifest
/// (ADR 0113 §1). Held here rather than beside the question record because the
/// *gate* lives here: this crate turns an ability ceiling into admitted turn
/// resources, and app re-exports these so the manifest, the gate, and the record
/// cannot drift onto three different strings.
pub const QUESTION_ASK_CAPABILITY: &str = "question.ask";

/// The turn resource admitted when the ceiling carries [`QUESTION_ASK_CAPABILITY`].
/// `execute_tool` refuses `ask` without it, exactly as `bash` refuses without
/// `command`.
pub const QUESTION_RESOURCE: &str = "question";

/// The pinned GaugeDesk governance root WhippleScript calls to verify an
/// externally signed policy envelope. Both the responsible authority identity
/// and its exact P-256 public key are bound; substituting either fails closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceRootVerifier {
    expected_signer: AuthorityId,
    expected_key: PublicKey,
}

impl GovernanceRootVerifier {
    pub fn new(expected_signer: AuthorityId, expected_key: PublicKey) -> Self {
        Self {
            expected_signer,
            expected_key,
        }
    }

    pub fn expected_signer(&self) -> &AuthorityId {
        &self.expected_signer
    }

    pub fn expected_key(&self) -> &PublicKey {
        &self.expected_key
    }
}

impl GovernanceAttestationVerifier for GovernanceRootVerifier {
    fn verify(
        &self,
        signing_bytes: &[u8],
        attestation: &ExternalAttestation,
    ) -> Result<(), String> {
        if attestation.algorithm != GAUGEDESK_ATTESTATION_ALGORITHM {
            return Err("unsupported GaugeDesk governance signature algorithm".to_owned());
        }
        if attestation.key_id != self.expected_key.as_str() {
            return Err("governance attestation key does not match the pinned root".to_owned());
        }
        let bytes = hex::decode(&attestation.signature)
            .map_err(|_| "governance signature is not valid hex".to_owned())?;
        let signature = Signature::new(bytes);
        match verify_signature(signing_bytes, &signature, &self.expected_key) {
            Ok(true) => Ok(()),
            Ok(false) => Err("governance signature does not verify".to_owned()),
            Err(error) => Err(format!("invalid governance root: {}", error.reason)),
        }
    }
}

/// Compile and sign a WhippleScript governance envelope with GaugeDesk's
/// existing P-256 governance root. No environment variable or WhippleScript
/// admin mode participates; the matching [`GovernanceRootVerifier`] is the only
/// production verification path.
pub fn sign_policy_envelope(
    config_text: &str,
    signer: &AuthorityId,
    key: &SigningKey,
) -> Result<String, String> {
    let public_key = key.public_key();
    let signing_bytes = external_signing_bytes(
        config_text,
        signer.as_str(),
        GAUGEDESK_ATTESTATION_ALGORITHM,
        public_key.as_str(),
    )?;
    let signature = key.sign(&signing_bytes);
    SignedEnvelope::from_external_signature(
        config_text,
        signer.as_str(),
        GAUGEDESK_ATTESTATION_ALGORITHM,
        public_key.as_str(),
        &hex::encode(signature.as_bytes()),
    )
    .map(|envelope| envelope.to_json())
}

/// Compile and sign a hosted WhippleScript governance envelope whose signature
/// also binds the immutable policy epoch and the authority it speaks for.
/// Hosted placements require this `:v2` form; the single-envelope local path
/// continues to use [`sign_policy_envelope`].
pub fn sign_hosted_policy_envelope(
    config_text: &str,
    signer: &AuthorityId,
    key: &SigningKey,
    epoch: u64,
) -> Result<String, String> {
    if epoch == 0 {
        return Err("hosted governance policy epoch must be non-zero".to_owned());
    }
    let public_key = key.public_key();
    let signing_bytes = external_signing_bytes_v2(
        config_text,
        signer.as_str(),
        GAUGEDESK_ATTESTATION_ALGORITHM,
        public_key.as_str(),
        epoch,
        signer.as_str(),
    )?;
    let signature = key.sign(&signing_bytes);
    SignedEnvelope::from_external_signature_v2(
        config_text,
        signer.as_str(),
        GAUGEDESK_ATTESTATION_ALGORITHM,
        public_key.as_str(),
        &hex::encode(signature.as_bytes()),
        epoch,
        signer.as_str(),
    )
    .map(|envelope| envelope.to_json())
}

// The immediately preceding GaugeDesk-generated package. It remains resolvable
// only so an existing long-lived thread can make WhippleScript's explicit,
// position-preserving jump into its authored archetype package.
const GAUGEDESK_CHAT_PACKAGE: &str = r#"
file store project {
  root "."
  allow read ["**"]
  allow write ["**"]
}

workflow GaugeDeskChat {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
  }

  rule converse
    when started
  => {
    tell assistant
      with access to project {
        read ["**"]
        write ["**"]
      }
      with access to command {
        run
      }
      with access to human {
        ask
      }
      "GaugeDesk host turn"
  }
}
"#;

// The immediately preceding immutable package. GaugeDesk keeps this resolver
// only to migrate an existing chat thread through WhippleScript's explicit
// cross-version fork; it is never selected for a new foreground turn.
const GAUGEDESK_CHAT_PACKAGE_COMMAND_V1: &str = r#"
file store project {
  root "."
  allow read ["**"]
  allow write ["**"]
}

workflow GaugeDeskChat {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
  }

  rule converse
    when started
  => {
    tell assistant
      with access to project {
        read ["**"]
        write ["**"]
      }
      with access to command {
        run
      }
      "GaugeDesk host turn"
  }
}
"#;

const GAUGEDESK_EDITOR_MANIFEST: &str = r#"{
  "schema": "whipplescript.agent_package.v0",
  "source": "editor.whip",
  "workflow": "GaugeDeskEditor",
  "agent": "editor",
  "system_prompt": "editor.md",
  "capabilities": ["workspace.read", "workspace.write", "command.run"],
  "agent_abilities": ["workspace.read", "workspace.write", "command.run"],
  "max_steps": 32
}"#;

const GAUGEDESK_EDITOR_SOURCE: &str = r#"
file store project {
  root "."
  allow read ["**"]
  allow write ["**"]
}

workflow GaugeDeskEditor {
  agent editor {
    provider owned
    profile "repo-writer"
    capacity 1
    capabilities ["workspace.read", "workspace.write", "command.run"]
  }

  rule edit
    when started
  => {
    tell editor requires ["workspace.read", "workspace.write", "command.run"]
      with access to project {
        read ["**"]
        write ["**"]
      }
      with access to command {
        run
      }
      "Edit the selected GaugeDesk method package."
  }
}
"#;

pub fn editor_package_capabilities() -> io::Result<BTreeSet<String>> {
    AuthoredAgentPackage::from_documents(
        GAUGEDESK_EDITOR_MANIFEST,
        GAUGEDESK_EDITOR_SOURCE,
        "GaugeDesk editor capability projection",
    )
    .map(|package| package.capabilities().iter().cloned().collect())
    .map_err(invalid_data)
}

/// Transitional implementation of GaugeDesk's neutral harness seam over the
/// permanent WhippleScript host protocol. GaugeDesk supplies its governance
/// root and state directory; package admission, IFC, transcript continuity,
/// tool execution, and the labeled output projection remain WhippleScript-owned.
#[derive(Clone)]
pub struct WhipHarnessFactory {
    pub(crate) authority: AuthorityId,
    signing_key: SigningKey,
    runtime_root: PathBuf,
    hosted: Option<DoHostConfig>,
}

impl WhipHarnessFactory {
    pub fn new(
        authority: AuthorityId,
        signing_key: SigningKey,
        runtime_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            authority,
            signing_key,
            runtime_root: runtime_root.into(),
            hosted: None,
        }
    }

    pub fn with_do_host(mut self, config: DoHostConfig) -> Self {
        self.hosted = Some(config);
        self
    }

    fn runtime_for_chat(
        &self,
        chat_id: &str,
        epoch: u64,
        signed_policy: &str,
    ) -> io::Result<GovernedHostRuntime> {
        let verifier =
            GovernanceRootVerifier::new(self.authority.clone(), self.signing_key.public_key());
        std::fs::create_dir_all(&self.runtime_root)?;
        GovernedHostRuntime::open_with_verifier(
            self.runtime_root
                .join(format!("{}.sqlite", hex::encode(chat_id.as_bytes()))),
            epoch,
            signed_policy,
            &verifier,
        )
        .map_err(invalid_data)
    }

    pub(crate) fn package_for(
        mode: gaugedesk_harness::ChatMode,
        package_root: Option<&Path>,
        package_version_ref: Option<&str>,
        prompt_override: Option<&str>,
    ) -> io::Result<AuthoredAgentPackage> {
        match mode {
            gaugedesk_harness::ChatMode::Use => {
                if prompt_override.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a work chat cannot override its pinned package persona",
                    ));
                }
                let root = package_root.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a work chat has no selected WhippleScript package root",
                    )
                })?;
                let expected = package_version_ref.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a work chat has no pinned WhippleScript package reference",
                    )
                })?;
                let package = AuthoredAgentPackage::load(root).map_err(invalid_data)?;
                if package.version_ref() != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "selected package bytes do not match the placement's pinned reference",
                    ));
                }
                Ok(package)
            }
            gaugedesk_harness::ChatMode::Edit => AuthoredAgentPackage::from_documents(
                GAUGEDESK_EDITOR_MANIFEST,
                GAUGEDESK_EDITOR_SOURCE,
                prompt_override.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "an edit chat requires the GaugeDesk editor persona",
                    )
                })?,
            )
            .map_err(invalid_data),
        }
    }

    fn previous_package_for(
        worktree: &Path,
        mode: gaugedesk_harness::ChatMode,
        prompt_override: Option<&str>,
        roster: &[(String, String)],
    ) -> io::Result<StaticPackage> {
        let system_prompt = legacy_method_prompt(worktree, prompt_override)?;
        Ok(StaticPackage {
            version_ref: package_version_ref(mode, &system_prompt, "human-v1"),
            system_prompt,
            writable: true,
            can_ask: true,
            roster: roster.to_vec(),
        })
    }

    fn open_request(
        chat_id: &str,
        package_version_ref: &str,
        policy: PolicyEpochRef,
    ) -> OpenInstanceCommand {
        OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: format!("gaugedesk:{chat_id}:{package_version_ref}"),
            package_version_ref: package_version_ref.to_owned(),
            policy,
        }
    }

    fn create_harness(&self, spec: &HarnessSpec) -> io::Result<WhipHarness> {
        let provider = ProviderConfig::from_spec(spec)?;
        let package = Self::package_for(
            spec.mode,
            spec.package_root.as_deref(),
            spec.package_version_ref.as_deref(),
            spec.system_prompt.as_deref(),
        )?;
        let previous = Self::previous_package_for(
            &spec.worktree,
            spec.mode,
            spec.system_prompt.as_deref(),
            &spec.roster,
        )?;
        let packages = StaticPackages {
            current: package.clone(),
            previous,
        };
        let epoch = spec.policy_epoch.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WhippleScript policy epoch is required",
            )
        })?;
        let signed_policy = spec.signed_policy_envelope.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WhippleScript signed policy envelope is required",
            )
        })?;
        let mut runtime = self.runtime_for_chat(&spec.chat_id, epoch, signed_policy)?;
        let mut source_runtime = self.runtime_for_chat(&spec.chat_id, epoch, signed_policy)?;
        let source_open = Self::open_request(
            &spec.chat_id,
            packages.previous.version_ref.as_str(),
            source_runtime.policy_ref().clone(),
        );
        let source = source_runtime
            .open_instance(&source_open, &packages)
            .map_err(invalid_data)?;
        let source_position = source_runtime
            .current_position(&source.instance_ref)
            .map_err(invalid_data)?;
        let open = Self::open_request(
            &spec.chat_id,
            package.version_ref(),
            runtime.policy_ref().clone(),
        );
        let upgrade = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: format!(
                "gaugedesk:package-upgrade:{}:{}:{}",
                spec.chat_id,
                packages.previous.version_ref,
                package.version_ref()
            ),
            source: source_position,
            target_request_id: open.request_id,
            package_version_ref: package.version_ref().to_owned(),
            policy: open.policy.clone(),
        };
        let instance = runtime
            .fork_instance_from(&source_runtime, &upgrade, &packages)
            .map(|fork| fork.target)
            .map_err(invalid_data)?;

        let read_only = spec
            .sandbox
            .read_only_roots
            .iter()
            .map(|path| {
                path.strip_prefix(&spec.worktree)
                    .map(Path::to_path_buf)
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "WhippleScript read-only root is outside the workspace capability",
                        )
                    })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let workspace = NativeWorkspaceResolver::new(&spec.worktree)
            .and_then(|resolver| resolver.read_only(read_only))
            .map_err(invalid_data)?;

        Ok(WhipHarness {
            runtime,
            instance_ref: instance.instance_ref,
            policy: open.policy,
            package,
            provider,
            workspace,
            chat_id: spec.chat_id.clone(),
            provider_binding_ref: spec.provider_binding_ref.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "provider binding ref is required",
                )
            })?,
            credential_ref: spec.credential_ref.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "credential ref is required")
            })?,
            placement_ceiling_ref: spec.placement_ceiling_ref.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "placement ceiling ref is required",
                )
            })?,
            respondent_ref: self.authority.as_str().to_owned(),
            turn_sequence: 0,
            next_command_id: None,
            cancellation: Arc::new(Mutex::new(None)),
            cancel_requested: Arc::new(AtomicBool::new(false)),
            pursuing_cancel: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl HarnessFactory for WhipHarnessFactory {
    fn kind(&self) -> &'static str {
        if self.hosted.is_some() {
            "whip-do"
        } else {
            "whip"
        }
    }

    fn create(&self, spec: &HarnessSpec) -> io::Result<Box<dyn Harness>> {
        if let Some(config) = &self.hosted {
            return hosted::create_harness(self, config, spec);
        }
        self.create_harness(spec)
            .map(|harness| Box::new(harness) as Box<dyn Harness>)
    }

    fn reuse_across_turns(&self) -> bool {
        self.hosted
            .as_ref()
            .map(DoHostConfig::reuse_across_turns)
            .unwrap_or(true)
    }

    fn clone_continuity(
        &self,
        source: &HarnessContinuitySpec,
        target: &HarnessContinuitySpec,
    ) -> io::Result<()> {
        if let Some(config) = &self.hosted {
            return hosted::clone_continuity(config, source, target);
        }
        if source.policy_epoch.is_none() && source.signed_policy_envelope.is_none() {
            return Ok(());
        }
        if source.mode != target.mode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WhippleScript continuity fork cannot change chat mode",
            ));
        }
        let source_package = Self::package_for(
            source.mode,
            source.package_root.as_deref(),
            source.package_version_ref.as_deref(),
            source.system_prompt.as_deref(),
        )?;
        let target_package = Self::package_for(
            target.mode,
            target.package_root.as_deref(),
            target.package_version_ref.as_deref(),
            target.system_prompt.as_deref(),
        )?;
        if source_package.version_ref() != target_package.version_ref() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WhippleScript continuity fork requires the same package identity",
            ));
        }

        let epoch = source.policy_epoch.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WhippleScript source policy epoch is required for continuity",
            )
        })?;
        let signed_policy = source.signed_policy_envelope.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WhippleScript source signed policy is required for continuity",
            )
        })?;
        let mut source_runtime = self.runtime_for_chat(&source.chat_id, epoch, signed_policy)?;
        let source_open = Self::open_request(
            &source.chat_id,
            source_package.version_ref(),
            source_runtime.policy_ref().clone(),
        );
        let source_instance = source_runtime
            .open_instance(&source_open, &source_package)
            .map_err(invalid_data)?;
        let source_position = match &source.source_position {
            Some(position) => {
                if position.instance_ref != source_instance.instance_ref {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "WhippleScript continuity position belongs to a different source instance",
                    ));
                }
                EventPosition {
                    instance_ref: position.instance_ref.clone(),
                    sequence: position.sequence,
                }
            }
            None => source_runtime
                .current_position(&source_instance.instance_ref)
                .map_err(invalid_data)?,
        };

        let mut target_runtime = self.runtime_for_chat(&target.chat_id, epoch, signed_policy)?;
        let target_open = Self::open_request(
            &target.chat_id,
            target_package.version_ref(),
            target_runtime.policy_ref().clone(),
        );
        let command = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: format!(
                "gaugedesk:fork:{}:{}:{}",
                source.chat_id, target.chat_id, source_position.sequence
            ),
            source: source_position,
            target_request_id: target_open.request_id,
            package_version_ref: target_package.version_ref().to_owned(),
            policy: target_open.policy,
        };
        target_runtime
            .fork_instance_from(&source_runtime, &command, &target_package)
            .map(|_| ())
            .map_err(invalid_data)
    }

    fn credential_status(
        &self,
        provider: &str,
        capability: Option<&dyn CredentialCapability>,
    ) -> CredentialProbe {
        if self.hosted.is_some() {
            return CredentialProbe::Ready;
        }
        match capability {
            Some(capability) if !capability.credential_ref().is_empty() => CredentialProbe::Ready,
            _ if provider == "openai-codex" => CredentialProbe::Missing(
                "No GaugeDesk-owned Codex OAuth credential is linked. Open Account settings and connect ChatGPT."
                    .to_owned(),
            ),
            _ => CredentialProbe::Missing(format!(
                "WhippleScript has no admitted credential capability for provider `{provider}`"
            )),
        }
    }
}

struct WhipHarness {
    runtime: GovernedHostRuntime,
    instance_ref: String,
    policy: PolicyEpochRef,
    package: AuthoredAgentPackage,
    provider: ProviderConfig,
    workspace: NativeWorkspaceResolver,
    chat_id: String,
    provider_binding_ref: String,
    credential_ref: String,
    placement_ceiling_ref: String,
    respondent_ref: String,
    turn_sequence: u64,
    next_command_id: Option<String>,
    cancellation: Arc<Mutex<Option<HostCancellationHandle>>>,
    /// That a cancellation has been asked for, held separately from the handle
    /// that performs it. The handle exists only from `install_cancellation` to
    /// the end of the turn, and the store refuses a request for an effect that
    /// is not yet `running`, so a Stop can arrive at two moments where the
    /// request cannot yet be made. Recording the *intent* lets those moments
    /// resolve themselves instead of dropping the Stop.
    cancel_requested: Arc<AtomicBool>,
    /// Whether a deferred pursuit is already running, so pressing Stop twice
    /// does not start a second one.
    pursuing_cancel: Arc<AtomicBool>,
}

impl Harness for WhipHarness {
    fn bind_authenticated_actor(&mut self, actor_ref: &str) {
        if !actor_ref.trim().is_empty() {
            self.respondent_ref = actor_ref.to_owned();
        }
    }

    fn bind_runtime_command_id(&mut self, command_id: Option<&str>) {
        self.next_command_id = command_id.map(str::to_owned);
    }

    fn run_turn(
        &mut self,
        _legacy_gate: &dyn EgressGate,
        prompt: &str,
        images: &[ImageContent],
        sink: &mut dyn FnMut(&Observation),
    ) -> io::Result<TurnOutcome> {
        let runtime_start_position = self
            .runtime
            .current_position(&self.instance_ref)
            .map_err(invalid_data)?;
        self.turn_sequence += 1;
        let admitted_command_id = self.next_command_id.take();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let resources = TurnResources {
            workspace: &self.workspace,
            images,
            asked: std::cell::RefCell::new(Vec::new()),
            live: std::cell::RefCell::new(sink),
            streamed: std::cell::Cell::new(false),
        };
        // ADR 0111: a question settles the turn. There is no suspended epoch to
        // resume into, because WhippleScript 0.2.2 removed the host-facing
        // suspension contract — a parked turn now surfaces as
        // `HostRuntimeError::Incomplete` rather than a resumable state. Every
        // turn is an ordinary turn; an agent that needs a person files a task
        // and the answer arrives as the next turn's context.
        let command = self.new_turn_command(prompt, images, nonce, admitted_command_id);
        self.install_cancellation(&command);
        let execution = self
            .runtime
            .run_turn(&command, &self.package, &self.provider, &resources)
            .map_err(turn_failure);
        self.clear_cancellation();
        let execution = execution?;
        let evidence_pointers = execution.evidence_pointers();
        // The runtime's settled context reading (its own compaction-trigger
        // number), taken before the execution moves into the projection. The
        // provider/model ride along so the reading is measured against the
        // window of the model that actually produced it.
        let context_tokens = execution
            .usage
            .as_ref()
            .map(|usage| usage.last_input_tokens)
            .filter(|tokens| *tokens > 0);
        let streamed = resources.streamed.get();
        let sink = resources.live.into_inner();
        let mut outcome =
            project_turn_execution(execution, evidence_pointers, &command, sink, !streamed)?;
        outcome.context_reading = context_tokens.map(|last_input_tokens| ContextWindowReading {
            provider: provider_wire_name(self.provider.provider).to_owned(),
            model: self.provider.model.clone(),
            last_input_tokens,
        });
        outcome.asked_questions = resources.asked.into_inner();
        outcome.runtime_start_position = Some(RuntimePosition {
            instance_ref: runtime_start_position.instance_ref,
            sequence: runtime_start_position.sequence,
        });
        if outcome.runtime_terminal_position.is_none() {
            let suspended_position = self
                .runtime
                .current_position(&self.instance_ref)
                .map_err(invalid_data)?;
            outcome.runtime_terminal_position = Some(RuntimePosition {
                instance_ref: suspended_position.instance_ref,
                sequence: suspended_position.sequence,
            });
        }
        // DR-0036 §2 → ADR 0082 §5: attach the turn's certified dynamic
        // guarantee outcomes so the settle-time advancement policy can match
        // them by name. Best-effort by design — a runtime/report predating
        // DR-0036 yields nothing and consumers fall back to host-local truth.
        // Unconditional since ADR 0111: every turn now reaches a terminal, so
        // there is no suspended case without a receipt.
        if let Ok(Some(report)) = self.runtime.turn_guarantee_report(&command) {
            outcome.guarantee_outcomes = gaugedesk_harness::GuaranteeOutcome::from_report(&report);
        }
        Ok(outcome)
    }

    fn interrupt_handle(&self) -> Option<gaugedesk_harness::InterruptHandle> {
        let cancellation = Arc::clone(&self.cancellation);
        let requested = Arc::clone(&self.cancel_requested);
        let pursuing = Arc::clone(&self.pursuing_cancel);
        Some(Arc::new(move || {
            // The intent is recorded before the attempt, and never cleared by a
            // failed attempt: `install_cancellation` reads it, so a Stop that
            // beat the turn's cancellation surface into existence is performed
            // the moment that surface appears rather than lost.
            requested.store(true, Ordering::SeqCst);
            pursue_cancellation(&cancellation, &pursuing);
        }))
    }
}

impl WhipHarness {
    fn new_turn_command(
        &self,
        prompt: &str,
        images: &[ImageContent],
        nonce: u128,
        admitted_command_id: Option<String>,
    ) -> StartTurnCommand {
        let command_id = admitted_command_id.unwrap_or_else(|| {
            format!("gaugedesk:{}:{}:{nonce}", self.chat_id, self.turn_sequence)
        });
        let has = |name: &str| {
            self.package
                .agent_abilities()
                .iter()
                .any(|capability| capability == name)
        };
        let mut resources = Vec::new();
        if has("workspace.read") || has("workspace.write") {
            resources.push(ResourceRef {
                handle: "project".to_owned(),
                kind: "file_store".to_owned(),
                selector: None,
            });
        }
        if has("command.run") {
            resources.push(ResourceRef {
                handle: "command".to_owned(),
                kind: "command".to_owned(),
                selector: None,
            });
        }
        // ADR 0113: asking is a governed ability. An archetype whose ceiling
        // omits `question.ask` admits no question resource, and the tool refuses
        // without it — the same gate that makes `bash` require `command`.
        if has(QUESTION_ASK_CAPABILITY) {
            resources.push(ResourceRef {
                handle: QUESTION_RESOURCE.to_owned(),
                kind: QUESTION_RESOURCE.to_owned(),
                selector: None,
            });
        }
        StartTurnCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: command_id.clone(),
            run_ref: format!("gaugedesk:run:{command_id}"),
            instance_ref: self.instance_ref.clone(),
            package_version_ref: self.package.version_ref().to_owned(),
            policy: self.policy.clone(),
            actor_ref: self.respondent_ref.clone(),
            input: TurnInput {
                text: prompt.to_owned(),
                images: images
                    .iter()
                    .enumerate()
                    .map(|(index, _)| ResourceRef {
                        handle: "turn_images".to_owned(),
                        kind: "image".to_owned(),
                        selector: Some(index.to_string()),
                    })
                    .collect(),
            },
            resources,
            provider_binding: ProviderBindingRef {
                binding_id: self.provider_binding_ref.clone(),
                credential: CredentialRef {
                    credential_id: self.credential_ref.clone(),
                },
            },
            placement_ceiling_ref: self.placement_ceiling_ref.clone(),
        }
    }

    fn install_cancellation(&self, command: &StartTurnCommand) {
        *self
            .cancellation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(
            self.runtime
                .cancellation_handle(&command.instance_ref, &command.command_id),
        );
        // A Stop that landed during the turn's assembly found no handle here and
        // returned having done nothing. It set the flag; this performs it.
        if self.cancel_requested.load(Ordering::SeqCst) {
            pursue_cancellation(&self.cancellation, &self.pursuing_cancel);
        }
    }

    fn clear_cancellation(&self) {
        self.cancellation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        // A harness is reused across turns; one turn's Stop must not cancel the
        // next. Dropping the handle is also what retires any pursuit still
        // waiting on it.
        self.cancel_requested.store(false, Ordering::SeqCst);
    }
}

/// How long a pursuit keeps asking. The effect became `running` within 38ms of
/// the handle appearing in every measurement; this is slack, not an expectation.
const CANCELLATION_PURSUIT: Duration = Duration::from_secs(10);

/// The interval between attempts. Each is one small `IMMEDIATE` transaction on
/// an independent connection.
const CANCELLATION_RETRY: Duration = Duration::from_millis(20);

/// Ask the runtime to cancel the running effect, and keep asking until it can
/// accept.
///
/// One attempt is not enough. The store refuses a cancellation request for an
/// effect that is not `running` — the kernel creates that row *after* the handle
/// is installed — so a Stop arriving in between is answered
/// `"effect does not exist"`. That error used to be discarded, which is what
/// made a Stop report success while the turn ran on to completion.
///
/// The pursuit is bounded by the turn itself: it gives up as soon as the handle
/// is cleared, which `clear_cancellation` does when the turn ends.
fn pursue_cancellation(
    cancellation: &Arc<Mutex<Option<HostCancellationHandle>>>,
    pursuing: &Arc<AtomicBool>,
) {
    let Some(handle) = current_cancellation(cancellation) else {
        // Not installed yet. `install_cancellation` reads the intent flag and
        // calls this again, so there is nothing to pursue here.
        return;
    };
    if handle.request().is_ok() {
        return;
    }
    // Refused: the effect is not `running` yet. Not an error to report — the
    // kernel simply has not created the row. A turn that is never cancelled
    // despite this pursuit is caught by the engine, which can see the turn's
    // outcome and says so there.
    // Already being pursued: a second Stop press joins the first rather than
    // racing it.
    if pursuing.swap(true, Ordering::SeqCst) {
        return;
    }
    let cancellation = Arc::clone(cancellation);
    let pursuing = Arc::clone(pursuing);
    std::thread::spawn(move || {
        let deadline = Instant::now() + CANCELLATION_PURSUIT;
        loop {
            std::thread::sleep(CANCELLATION_RETRY);
            let Some(handle) = current_cancellation(&cancellation) else {
                // The turn ended under us. Whether it ended because an earlier
                // attempt landed or for its own reasons, there is nothing left
                // to cancel.
                break;
            };
            if handle.request().is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        pursuing.store(false, Ordering::SeqCst);
    });
}

fn current_cancellation(
    cancellation: &Mutex<Option<HostCancellationHandle>>,
) -> Option<HostCancellationHandle> {
    cancellation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn project_turn_execution(
    execution: TurnExecution,
    evidence_pointers: Vec<RuntimeEvidencePointer>,
    command: &StartTurnCommand,
    sink: &mut dyn FnMut(&Observation),
    sink_final_text: bool,
) -> io::Result<TurnOutcome> {
    let mut outcome = TurnOutcome {
        runtime_evidence_pointers: evidence_pointers
            .into_iter()
            .map(|pointer| serde_json::to_string(&pointer).map_err(invalid_data))
            .collect::<io::Result<Vec<_>>>()?,
        ..TurnOutcome::default()
    };
    let receipt = execution
        .receipt
        .ok_or_else(|| invalid_data("WhippleScript returned no terminal receipt"))?;
    receipt.validate_for(command).map_err(invalid_data)?;
    outcome.runtime_terminal_position = Some(RuntimePosition {
        instance_ref: receipt.terminal_position.instance_ref.clone(),
        sequence: receipt.terminal_position.sequence,
    });
    if let Some(output) = execution.output {
        outcome.output_flow_signature = output
            .flow_signature
            .iter()
            .map(|flow| OutputFieldFlow {
                field: flow.field.clone(),
                read_handles: flow
                    .reads
                    .iter()
                    .map(|resource| resource.handle.clone())
                    .collect(),
            })
            .collect();
        outcome.assistant_text = output.assistant_text;
        for call in output.tool_calls {
            let target = tool_target(&call);
            let observation = Observation {
                kind: "tool_result",
                detail: format!("{} {}", call.name, target.as_deref().unwrap_or(""))
                    .trim()
                    .to_owned(),
                tool: Some(ToolInfo {
                    name: call.name.clone(),
                    call_id: call.call_id,
                    target,
                    args: call.arguments.to_string(),
                    ok: call.ok,
                    result: call.result,
                }),
            };
            sink(&observation);
            outcome.mediated_tool_calls.push(call.name);
            outcome.observations.push(observation);
        }
        // When deltas already streamed through `observe_text_delta`, the live
        // tier has this text; sinking it again would double it on the open
        // line. The durable record still carries it either way.
        if sink_final_text && !outcome.assistant_text.is_empty() {
            sink(&Observation {
                kind: "text",
                detail: outcome.assistant_text.clone(),
                tool: None,
            });
        }
    }
    if receipt.status != TurnStatus::Completed {
        outcome.error = Some(format!("WhippleScript turn ended {:?}", receipt.status));
    }
    Ok(outcome)
}

#[derive(Clone)]
struct StaticPackage {
    version_ref: String,
    system_prompt: String,
    writable: bool,
    /// Whether this package's ceiling admits `question.ask` (ADR 0113).
    can_ask: bool,
    /// Who this agent may name, as `(authority, who they are)` (`GATE-3f`).
    /// Rendered into the `ask` tool's `to` field so the choice is offered rather
    /// than guessed. Empty leaves `to` a free string the host still resolves.
    roster: Vec<(String, String)>,
}

#[derive(Clone)]
struct StaticPackages {
    current: AuthoredAgentPackage,
    previous: StaticPackage,
}

// Historical OS-command realization retained outside the compiled surface for
// one release so downstream patches remain reviewable. `bash` is implemented
// solely by WhippleScript's shared Bashkit-backed virtual shell.
#[cfg(any())]
mod retired_os_command_executor {
    use super::*;

    const COMMAND_OUTPUT_LIMIT: usize = 1_000_000;

    /// GaugeDesk realizes an already-admitted WhippleScript command inside the
    /// product's OS boundary. It deliberately does not parse or reinterpret command
    /// authority: WhippleScript owns the simple-command grammar, allow policy,
    /// timeout ceiling, and output projection.
    struct GaugeDeskCommandExecutor {
        sandbox: gaugedesk_harness::sandbox::SandboxPolicy,
    }

    impl CommandExecutor for GaugeDeskCommandExecutor {
        fn execute(&self, admitted: &AdmittedCommand) -> Result<CommandExecutionOutput, String> {
            let policy = command_sandbox_policy(&self.sandbox, admitted);

            let args = vec!["-c".to_owned(), admitted.command.clone()];
            let mut command = gaugedesk_harness::sandbox::wrap_strict(
                &policy,
                "/bin/sh",
                &args,
                Some(&admitted.workspace_root),
            )
            .map_err(|error| format!("cannot realize governed command: {error}"))?;
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt as _;
                command.process_group(0);
            }
            let mut child = command
                .spawn()
                .map_err(|error| format!("cannot spawn governed command: {error}"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| "governed command stdout was not captured".to_owned())?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| "governed command stderr was not captured".to_owned())?;
            let output_bytes = Arc::new(AtomicUsize::new(0));
            let readers_done = Arc::new(AtomicUsize::new(0));
            let stdout_reader =
                spawn_bounded_reader(stdout, Arc::clone(&output_bytes), Arc::clone(&readers_done));
            let stderr_reader =
                spawn_bounded_reader(stderr, Arc::clone(&output_bytes), Arc::clone(&readers_done));
            let started = Instant::now();
            let status = loop {
                match child
                    .try_wait()
                    .map_err(|error| format!("cannot observe governed command: {error}"))?
                {
                    Some(status) => break status,
                    None if output_bytes.load(Ordering::Relaxed) > COMMAND_OUTPUT_LIMIT => {
                        kill_governed_command(&mut child);
                        let _ = child.wait();
                        let _ = stdout_reader.join();
                        let _ = stderr_reader.join();
                        return Err(format!(
                            "governed command exceeded the {} byte output limit",
                            COMMAND_OUTPUT_LIMIT
                        ));
                    }
                    None if started.elapsed() >= admitted.timeout => {
                        kill_governed_command(&mut child);
                        let _ = child.wait();
                        let _ = stdout_reader.join();
                        let _ = stderr_reader.join();
                        return Err(format!(
                            "governed command exceeded its {} second timeout",
                            admitted.timeout.as_secs()
                        ));
                    }
                    None => thread::sleep(Duration::from_millis(10)),
                }
            };
            // A simple command may itself fork. The admitted invocation ends with
            // its foreground process; do not let any descendant retain workspace
            // authority or keep captured pipes alive past that boundary.
            let drain_deadline = Instant::now() + Duration::from_secs(1);
            while readers_done.load(Ordering::Relaxed) < 2 && Instant::now() < drain_deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if readers_done.load(Ordering::Relaxed) < 2 {
                kill_governed_command(&mut child);
            }
            let stdout = stdout_reader
                .join()
                .map_err(|_| "governed command stdout reader panicked".to_owned())??;
            let stderr = stderr_reader
                .join()
                .map_err(|_| "governed command stderr reader panicked".to_owned())??;
            if output_bytes.load(Ordering::Relaxed) > COMMAND_OUTPUT_LIMIT {
                return Err(format!(
                    "governed command exceeded the {} byte output limit",
                    COMMAND_OUTPUT_LIMIT
                ));
            }
            Ok(CommandExecutionOutput {
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
                exit_code: status.code(),
            })
        }
    }

    fn kill_governed_command(child: &mut std::process::Child) {
        #[cfg(unix)]
        {
            // SAFETY: the child was placed in a fresh process group whose id is its
            // pid immediately before spawn. A negative pid targets only that group.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }
    }

    fn command_sandbox_policy(
        base: &gaugedesk_harness::sandbox::SandboxPolicy,
        admitted: &AdmittedCommand,
    ) -> gaugedesk_harness::sandbox::SandboxPolicy {
        let mut policy = base.clone();
        policy.writable_roots = vec![admitted.workspace_root.clone()];
        policy.read_only_roots = admitted.read_only_paths.clone();

        // The filtered provider route belongs to WhippleScript's in-process
        // provider connection, not arbitrary repository commands. Commands get no
        // network under that posture; only GaugeDesk's explicit unfiltered project
        // opt-in carries through as network authority.
        if policy.network == Network::Filtered {
            policy.network = Network::Deny;
        }
        policy
    }

    fn spawn_bounded_reader<R>(
        mut reader: R,
        output_bytes: Arc<AtomicUsize>,
        readers_done: Arc<AtomicUsize>,
    ) -> thread::JoinHandle<Result<Vec<u8>, String>>
    where
        R: Read + Send + 'static,
    {
        thread::spawn(move || {
            let result = (|| {
                let mut captured = Vec::new();
                let mut buffer = [0_u8; 8192];
                loop {
                    let read = reader.read(&mut buffer).map_err(|error| {
                        format!("cannot capture governed command output: {error}")
                    })?;
                    if read == 0 {
                        break;
                    }
                    let previous = output_bytes.fetch_add(read, Ordering::Relaxed);
                    let remaining = COMMAND_OUTPUT_LIMIT.saturating_sub(previous);
                    captured.extend_from_slice(&buffer[..read.min(remaining)]);
                }
                Ok(captured)
            })();
            readers_done.fetch_add(1, Ordering::Relaxed);
            result
        })
    }
}

impl PackageResolver for StaticPackage {
    fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
        if version_ref != self.version_ref {
            return Err("package version ref does not match the GaugeDesk chat package".to_owned());
        }
        ResolvedPackage::compile(
            self.version_ref.clone(),
            if self.can_ask {
                GAUGEDESK_CHAT_PACKAGE
            } else {
                GAUGEDESK_CHAT_PACKAGE_COMMAND_V1
            },
            Some("GaugeDeskChat"),
            "assistant",
            self.system_prompt.clone(),
            question_tool_specs(
                native_workspace_tool_specs_with_capabilities(self.writable, true),
                self.can_ask,
                &self.roster,
            ),
            32,
        )
    }
}

impl PackageResolver for StaticPackages {
    fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
        if version_ref == self.current.version_ref() {
            self.current.resolve_package(version_ref)
        } else if version_ref == self.previous.version_ref {
            self.previous.resolve_package(version_ref)
        } else {
            Err("package version ref is outside the GaugeDesk migration set".to_owned())
        }
    }
}

/// The provider's config-vocabulary name, the inverse of the `ProviderConfig`
/// parse below — the same strings `.agent-config.json` carries, so a persisted
/// reading names its provider in the one vocabulary the product speaks.
fn provider_wire_name(provider: ModelProvider) -> &'static str {
    match provider {
        ModelProvider::OpenAi => "openai",
        ModelProvider::OpenAiCompat => "openai-generic",
        ModelProvider::Anthropic => "anthropic",
        ModelProvider::Codex => "openai-codex",
        // Not yet reachable from `.agent-config.json` (the xai rollout has not
        // landed here); named ahead so the reading is right when it does.
        ModelProvider::Xai => "xai",
    }
}

struct ProviderConfig {
    provider: ModelProvider,
    model: String,
    base_url: String,
    codex_session_id: Option<String>,
    credential_ref: String,
    credential_capability: Arc<dyn CredentialCapability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProviderDescriptor {
    pub provider_name: String,
    pub model: String,
    pub base_url: String,
    pub endpoint_host: String,
    pub credential_env: &'static str,
}

/// Whether `host` is a loopback address the TLS policy admits over plain `http`
/// (ADR 0083): a local model server (Ollama / LM Studio / a dev vLLM) has no
/// network to encrypt over, so cleartext is acceptable there and there only.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Derive the egress host the sandbox must admit from an `openai-generic`
/// endpoint base URL, enforcing the ADR 0083 TLS policy: `https` for any host,
/// `http` **only** for a loopback host. Pure and total — the single home for the
/// endpoint URL rule, called both at link time (validation) and at descriptor
/// derivation (defense in depth). Returns the bare lowercase host (no scheme,
/// port, or path) so it matches the exact-host egress allowlist (ADR 0079).
pub fn openai_generic_endpoint_host(base_url: &str) -> io::Result<String> {
    let invalid = |msg: &str| io::Error::new(io::ErrorKind::InvalidInput, msg.to_owned());
    let base_url = base_url.trim();
    let (scheme, rest) = base_url
        .split_once("://")
        .ok_or_else(|| invalid("openai-generic endpoint must be an absolute http(s) URL"))?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(invalid("openai-generic endpoint must use http or https"));
    }
    // authority = up to the first path/query/fragment delimiter.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@') // drop any userinfo
        .next()
        .unwrap_or("");
    // host[:port], with IPv6 hosts in brackets.
    let host = if let Some(after) = authority.strip_prefix('[') {
        after
            .split_once(']')
            .map(|(h, _)| h)
            .ok_or_else(|| invalid("openai-generic endpoint has a malformed IPv6 host"))?
    } else {
        authority.split(':').next().unwrap_or("")
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty() {
        return Err(invalid("openai-generic endpoint has no host"));
    }
    if scheme == "http" && !is_loopback_host(&host) {
        return Err(invalid(
            "openai-generic endpoint must use https for a non-loopback host (ADR 0083)",
        ));
    }
    Ok(host)
}

/// Resolve a provider's endpoint descriptor. `base_url` is honored only for the
/// endpoint-configurable `openai-generic` provider (ADR 0083), where it is
/// required and its host is derived under the TLS policy; the fixed-host
/// providers ignore it.
pub fn native_provider_descriptor(
    provider_name: &str,
    model: Option<&str>,
    base_url: Option<&str>,
) -> io::Result<NativeProviderDescriptor> {
    if provider_name == "openai-generic" {
        let base_url = base_url
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "openai-generic provider requires a linked endpoint base URL",
                )
            })?;
        let endpoint_host = openai_generic_endpoint_host(base_url)?;
        let model = model.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "openai-generic provider requires an explicit model",
            )
        })?;
        return Ok(NativeProviderDescriptor {
            provider_name: provider_name.to_owned(),
            model: model.to_owned(),
            base_url: base_url.trim().to_owned(),
            endpoint_host,
            // The key rides the CredentialCapability path, not the env resolver.
            credential_env: "OPENAI_API_KEY",
        });
    }
    let (base_url, endpoint_host, credential_env, default_model) = match provider_name {
        "openai" => (
            "https://api.openai.com",
            "api.openai.com",
            "OPENAI_API_KEY",
            None,
        ),
        "anthropic" => (
            "https://api.anthropic.com",
            "api.anthropic.com",
            "ANTHROPIC_API_KEY",
            None,
        ),
        "openai-codex" => (
            "https://chatgpt.com",
            "chatgpt.com",
            "GAUGEDESK_CODEX_ACCESS_TOKEN",
            Some("gpt-5.5"),
        ),
        // xAI's Grok API: a fixed-host OpenAI-compatible endpoint. The wire is
        // the Chat Completions client (ADR 0083 §4), whose builder appends only
        // `/chat/completions`, so the base URL must carry the `/v1` segment —
        // unlike the rows above, whose clients append the full `/v1/...` path.
        "xai" => ("https://api.x.ai/v1", "api.x.ai", "XAI_API_KEY", None),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("WhippleScript native provider `{provider_name}` is not supported"),
            ));
        }
    };
    let model = model.or(default_model).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "WhippleScript native API-key providers require an explicit model",
        )
    })?;
    Ok(NativeProviderDescriptor {
        provider_name: provider_name.to_owned(),
        model: model.to_owned(),
        base_url: base_url.to_owned(),
        endpoint_host: endpoint_host.to_owned(),
        credential_env,
    })
}

impl ProviderConfig {
    fn from_spec(spec: &HarnessSpec) -> io::Result<Self> {
        let provider_name = spec.provider.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WhippleScript provider is required",
            )
        })?;
        let descriptor = native_provider_descriptor(
            provider_name,
            spec.model.as_deref(),
            spec.base_url.as_deref(),
        )?;
        let provider = match provider_name {
            "openai" => ModelProvider::OpenAi,
            // openai-generic targets a configured OpenAI-**compatible** endpoint over
            // the Chat Completions API (ADR 0083), a distinct wire client from the
            // Responses-API `OpenAi` provider.
            "openai-generic" => ModelProvider::OpenAiCompat,
            // xai is a fixed-host endpoint on the same Chat Completions wire.
            "xai" => ModelProvider::OpenAiCompat,
            "anthropic" => ModelProvider::Anthropic,
            "openai-codex" => ModelProvider::Codex,
            _ => unreachable!("validated by native_provider_descriptor"),
        };
        if spec.sandbox.network == Network::Deny {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "GaugeDesk project policy denies provider network egress",
            ));
        }
        if !spec
            .sandbox
            .allowed_hosts
            .iter()
            .any(|host| host == &descriptor.endpoint_host)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "GaugeDesk project policy does not admit provider endpoint `{}`",
                    descriptor.endpoint_host
                ),
            ));
        }
        let credential_ref = spec.credential_ref.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "credential ref is required")
        })?;
        let credential_capability = spec.credential_capability.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "GaugeDesk supplied no credential capability",
            )
        })?;
        if credential_capability.credential_ref() != credential_ref {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential capability does not match the policy reference",
            ));
        }
        Ok(Self {
            provider,
            model: descriptor.model,
            base_url: descriptor.base_url,
            codex_session_id: (provider == ModelProvider::Codex)
                .then(|| format!("gaugedesk-{}", hex::encode(spec.chat_id.as_bytes()))),
            credential_ref,
            credential_capability,
        })
    }
}

impl SecretResolver for ProviderConfig {
    fn resolve_provider(
        &self,
        binding: &ProviderBindingRef,
        placement_ceiling_ref: &str,
    ) -> Result<ResolvedProviderBinding, String> {
        if binding.binding_id != "model"
            || binding.credential.credential_id != self.credential_ref
            || placement_ceiling_ref != "local"
        {
            return Err(
                "provider binding does not match the admitted GaugeDesk placement".to_owned(),
            );
        }
        let material = self
            .credential_capability
            .resolve(&binding.credential.credential_id)
            .map_err(|error| format!("credential capability refused resolution: {error}"))?;
        if self.provider == ModelProvider::Codex {
            let account_id = material
                .account_id()
                .filter(|account_id| !account_id.is_empty())
                .ok_or_else(|| "GaugeDesk Codex capability has no account id".to_owned())?;
            return Ok(ResolvedProviderBinding::new_codex(
                material.secret().to_owned(),
                account_id.to_owned(),
                self.codex_session_id.clone().unwrap_or_default(),
                self.model.clone(),
                self.base_url.clone(),
                8_192,
                Duration::from_secs(120),
            ));
        }
        Ok(ResolvedProviderBinding::new(
            self.provider,
            material.secret().to_owned(),
            self.model.clone(),
            self.base_url.clone(),
            8_192,
            Duration::from_secs(120),
        ))
    }
}

struct TurnResources<'a> {
    workspace: &'a NativeWorkspaceResolver,
    images: &'a [ImageContent],
    /// Questions asked during this turn. Interior mutability because
    /// `execute_tool` takes `&self`; the engine drains these once the turn
    /// settles, since it holds the store across the run (ADR 0113).
    asked: std::cell::RefCell<Vec<gaugedesk_harness::AskedQuestion>>,
    /// The engine's observation sink, held for the duration of the blocking
    /// `run_turn` call so WhippleScript's `observe_text_delta` can project
    /// answer text live — the native counterpart of the DO harness's stream
    /// relay. Interior mutability for the same reason as `asked`; the sink is
    /// taken back out once the runtime returns.
    live: std::cell::RefCell<&'a mut dyn FnMut(&Observation)>,
    /// Whether any answer delta streamed, so the settled projection does not
    /// sink the full text a second time (mirrors the hosted `streamed_text`).
    streamed: std::cell::Cell<bool>,
}

impl ResourceResolver for TurnResources<'_> {
    fn resolve_image(&self, image: &ResourceRef) -> Result<ResolvedImage, String> {
        if image.handle != "turn_images" || image.kind != "image" {
            return Err("image ref is outside the admitted turn-image capability".to_owned());
        }
        let index = image
            .selector
            .as_deref()
            .ok_or_else(|| "turn image ref has no selector".to_owned())?
            .parse::<usize>()
            .map_err(|_| "turn image selector is invalid".to_owned())?;
        let image = self
            .images
            .get(index)
            .ok_or_else(|| "turn image selector is out of range".to_owned())?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&image.data)
            .map_err(|_| "turn image is not valid base64".to_owned())?;
        Ok(ResolvedImage {
            media_type: image.mime_type.clone(),
            bytes,
        })
    }

    fn execute_tool(
        &self,
        admitted_resources: &[ResourceRef],
        call: &ToolCall,
    ) -> Result<String, String> {
        if call.name == "ask" {
            if !admitted_resources
                .iter()
                .any(|resource| resource.kind == QUESTION_RESOURCE)
            {
                return Err("turn has no admitted question capability".to_owned());
            }
            let arguments = &call.arguments;
            // The tool's argument name, which coincides with the resource handle but
            // is a different thing — do not fold them onto one constant.
            let question = arguments
                .get("question")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .trim()
                .to_owned();
            if question.is_empty() {
                return Err("`ask` requires a question".to_owned());
            }
            let choices = arguments
                .get("choices")
                .and_then(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let to = arguments
                .get("to")
                .and_then(|value| value.as_str())
                .map(str::to_owned);
            let blocking = arguments
                .get("blocking")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            self.asked
                .borrow_mut()
                .push(gaugedesk_harness::AskedQuestion {
                    question,
                    choices,
                    to,
                    blocking,
                });
            // The answer arrives in a later turn (ADR 0111): the turn settles,
            // it does not park waiting for one.
            return Ok(serde_json::json!({
                "asked": true,
                "note": "the answer will arrive as context in a later turn; this turn should settle"
            })
            .to_string());
        }
        self.workspace.execute_tool(admitted_resources, call)
    }

    /// WhippleScript projects each answer-text delta here while the turn
    /// streams (its "Live Turn Observation" contract). Relay it to the
    /// engine's observation sink as the same operational `text` event the
    /// hosted harness emits — never durable, replaced by the settled record.
    fn observe_text_delta(&self, delta: &str) {
        if delta.is_empty() {
            return;
        }
        self.streamed.set(true);
        let observation = Observation {
            kind: "text",
            detail: delta.to_owned(),
            tool: None,
        };
        (self.live.borrow_mut())(&observation);
    }
}

/// Append GaugeDesk's `ask` tool when the ability ceiling admits it (ADR 0113).
///
/// The workspace tools are WhippleScript's and their schemas are not ours to
/// change; this is a GaugeWright ability layered beside them, gated by the same
/// ceiling that admits the `question` resource `execute_tool` checks for.
fn question_tool_specs(
    mut tools: Vec<whipplescript_kernel::harness_loop::ToolSpec>,
    can_ask: bool,
    roster: &[(String, String)],
) -> Vec<whipplescript_kernel::harness_loop::ToolSpec> {
    if !can_ask {
        return tools;
    }
    // The roster on the tool itself (`GATE-3f`). Removing `askHuman` moved the
    // choice of *who* to the agent, and until now the only way for it to find out
    // who exists was to guess and read the refusal. A model should not have to
    // fail to discover a fact the host already knows.
    //
    // `enum` rather than a described free string: this is a closed set the host
    // resolves, so constraining it turns "asked a person who does not exist" from
    // a runtime refusal into something the call cannot express. The refusal path
    // stays — a roster can change between this schema being built and the call
    // arriving — but it is no longer the primary discovery mechanism.
    let mut to_schema = serde_json::json!({
        "type": "string",
        "description": if roster.is_empty() {
            "Who to ask. Omit for the chat's owner.".to_owned()
        } else {
            format!(
                "Who to ask, as one of the listed authorities. Omit for the chat's owner. \
                 People: {}",
                roster
                    .iter()
                    .map(|(authority, who)| format!("{authority} = {who}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        },
    });
    if !roster.is_empty() {
        to_schema["enum"] = serde_json::Value::Array(
            roster
                .iter()
                .map(|(authority, _)| serde_json::Value::String(authority.clone()))
                .collect(),
        );
    }
    tools.push(whipplescript_kernel::harness_loop::ToolSpec {
        name: "ask".to_owned(),
        description:
            "Ask a person a question. The turn settles; the answer arrives in a later turn."
                .to_owned(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "question": { "type": "string", "minLength": 1, "maxLength": 10000 },
                "choices": { "type": "array", "maxItems": 20, "items": {
                    "type": "string", "minLength": 1, "maxLength": 256
                }},
                "to": to_schema,
                "blocking": { "type": "boolean" }
            },
            "required": ["question"],
            "additionalProperties": false
        }),
    });
    tools
}

fn legacy_method_prompt(worktree: &Path, prompt_override: Option<&str>) -> io::Result<String> {
    if let Some(prompt) = prompt_override {
        return Ok(prompt.to_owned());
    }
    for relative in [
        ".whipple/legacy-persona.md",
        ".whipple/versions/1/persona.md",
    ] {
        match std::fs::read_to_string(worktree.join(relative)) {
            Ok(text) if !text.trim().is_empty() => return Ok(text),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok("Work inside the admitted GaugeDesk project workspace.".to_owned())
}

fn package_version_ref(
    mode: gaugedesk_harness::ChatMode,
    system_prompt: &str,
    revision: &str,
) -> String {
    let material = format!("{revision}\0{mode:?}\0{system_prompt}");
    format!("gaugedesk:chat-package:{}", stable_text_hash(&material))
}

fn stable_text_hash(text: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn tool_target(call: &ProjectedToolCall) -> Option<String> {
    ["path", "command", "url", "query"]
        .into_iter()
        .find_map(|key| call.arguments.get(key).and_then(|value| value.as_str()))
        .map(str::to_owned)
}

fn invalid_data(error: impl fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

/// Classify a turn failure while the runtime's own error type is still in hand.
///
/// `HostRuntimeError` distinguishes the runtime **refusing** a turn from the
/// runtime **failing** at one, but the harness seam is `io::Result`, so the
/// variant is gone one frame later. `io::ErrorKind` is the carrier that
/// survives: a refusal becomes `PermissionDenied` and everything else keeps
/// `InvalidData`. `EngineError::is_policy_denial` reads it back at the route,
/// which is what keeps a refusal out of the 5xx range.
///
/// Only the two deliberate-decision variants qualify. `Incomplete`,
/// `UngovernedHandle` and `UnknownInstance` are the runtime or its host being
/// wrong, not the policy speaking, and stay where they were.
fn turn_failure(error: whipplescript::host_runtime::HostRuntimeError) -> io::Error {
    use whipplescript::host_runtime::HostRuntimeError as E;
    let kind = match error {
        E::Ifc(_) | E::PolicyRejected(_) => io::ErrorKind::PermissionDenied,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error.to_string())
}

/// A monotonically increasing GaugeDesk policy epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PolicyEpoch(u64);

impl PolicyEpoch {
    /// Epoch zero is reserved for "no admitted policy" and cannot identify a run.
    pub fn new(value: u64) -> Result<Self, PolicyAdmissionError> {
        if value == 0 {
            Err(PolicyAdmissionError::InvalidEpoch)
        } else {
            Ok(Self(value))
        }
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

/// A policy epoch only after WhippleScript has verified its signed envelope.
///
/// The verified envelope stays opaque. Callers may retain the stable identity
/// for commands and receipts, and may ask WhippleScript whether it governs a
/// resource, but cannot inspect or reinterpret WhippleScript's security model.
pub struct AdmittedPolicyEpoch {
    epoch: PolicyEpoch,
    policy_ref: PolicyEpochRef,
    envelope: VerifiedEnvelope,
}

impl AdmittedPolicyEpoch {
    /// Cross the production trust boundary. Unsigned, malformed, and tampered
    /// envelopes fail closed; the epoch is never admitted without an attestation.
    pub fn verify(epoch: PolicyEpoch, signed_envelope: &str) -> Result<Self, PolicyAdmissionError> {
        let envelope = VerifiedEnvelope::verify_signed_text(signed_envelope)
            .map_err(PolicyAdmissionError::EnvelopeRejected)?;
        let policy_ref = PolicyEpochRef::from_verified(epoch.get(), &envelope)
            .map_err(PolicyAdmissionError::Protocol)?;
        Ok(Self {
            epoch,
            policy_ref,
            envelope,
        })
    }

    /// Production embedding trust boundary: require a cryptographic GaugeDesk
    /// root attestation, then retain the exact WhippleScript policy identity.
    pub fn verify_with(
        epoch: PolicyEpoch,
        signed_envelope: &str,
        verifier: &GovernanceRootVerifier,
    ) -> Result<Self, PolicyAdmissionError> {
        let envelope = VerifiedEnvelope::verify_signed_text_with(signed_envelope, verifier)
            .map_err(PolicyAdmissionError::EnvelopeRejected)?;
        let policy_ref = PolicyEpochRef::from_verified(epoch.get(), &envelope)
            .map_err(PolicyAdmissionError::Protocol)?;
        Ok(Self {
            epoch,
            policy_ref,
            envelope,
        })
    }

    pub fn epoch(&self) -> PolicyEpoch {
        self.epoch
    }

    /// The canonical WhippleScript envelope hash to place on runtime commands and
    /// require back on evidence receipts.
    pub fn envelope_hash(&self) -> &str {
        &self.policy_ref.envelope_hash
    }

    /// The governance signer WhippleScript verified.
    pub fn signer(&self) -> &str {
        &self.policy_ref.signer
    }

    /// The cryptographic governance root bound to this epoch. `None` exists only
    /// for the legacy CLI hash-attestation path.
    pub fn key_id(&self) -> Option<&str> {
        self.policy_ref.key_id.as_deref()
    }

    /// The WhippleScript-owned identity placed unchanged on commands, events, and
    /// receipts. GaugeDesk does not define a parallel wire representation.
    pub fn protocol_ref(&self) -> &PolicyEpochRef {
        &self.policy_ref
    }

    /// Delegate resource-coverage questions to WhippleScript's verified model.
    pub fn governs(&self, resource: &str) -> bool {
        self.envelope.governs(resource)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyAdmissionError {
    InvalidEpoch,
    EnvelopeRejected(String),
    Protocol(ProtocolError),
}

impl fmt::Display for PolicyAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEpoch => formatter.write_str("policy epoch must be greater than zero"),
            Self::EnvelopeRejected(message) => {
                write!(
                    formatter,
                    "WhippleScript governance envelope rejected: {message}"
                )
            }
            Self::Protocol(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PolicyAdmissionError {}

#[cfg(test)]
mod tests {
    /// The native answer-delta relay: WhippleScript's `observe_text_delta`
    /// lands in the engine's observation sink as the same operational `text`
    /// event the hosted harness emits, and marks the turn streamed so the
    /// settled projection does not sink the full text a second time.
    #[test]
    fn answer_deltas_relay_to_the_observation_sink_as_text_events() {
        use whipplescript::host_runtime::{NativeWorkspaceResolver, ResourceResolver};
        let root = std::env::temp_dir().join(format!("whip-delta-relay-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("workspace root");
        let workspace = NativeWorkspaceResolver::new(&root).expect("workspace resolver");
        let mut seen: Vec<gaugedesk_harness::Observation> = Vec::new();
        {
            let mut sink = |observation: &gaugedesk_harness::Observation| {
                seen.push(observation.clone());
            };
            let resources = super::TurnResources {
                workspace: &workspace,
                images: &[],
                asked: std::cell::RefCell::new(Vec::new()),
                live: std::cell::RefCell::new(&mut sink),
                streamed: std::cell::Cell::new(false),
            };
            resources.observe_text_delta("Gauge");
            resources.observe_text_delta("");
            resources.observe_text_delta("Wright");
            assert!(
                resources.streamed.get(),
                "a non-empty delta marks the turn streamed"
            );
        }
        assert_eq!(seen.len(), 2, "empty deltas are not relayed");
        assert!(seen.iter().all(|o| o.kind == "text"));
        assert_eq!(
            seen.iter().map(|o| o.detail.as_str()).collect::<String>(),
            "GaugeWright"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `GATE-3f`: the roster reaches the agent on the tool, not by trial and error.
    ///
    /// Before this, an agent's only way to learn who exists was to name someone,
    /// be refused, and read the roster out of the error. A model should not have
    /// to fail to discover a fact the host already knows.
    #[test]
    fn the_ask_tool_offers_the_roster_as_a_closed_choice() {
        let roster = vec![
            ("auth:alex".to_owned(), "alex@example.com".to_owned()),
            ("auth:owner".to_owned(), "auth:owner".to_owned()),
        ];
        let specs = super::question_tool_specs(Vec::new(), true, &roster);
        let ask = specs
            .iter()
            .find(|spec| spec.name == "ask")
            .expect("the ask tool");
        let to = &ask.input_schema["properties"]["to"];
        assert_eq!(
            to["enum"],
            serde_json::json!(["auth:alex", "auth:owner"]),
            "the choice is closed over the roster's authorities",
        );
        // ...and says which opaque authority is which person, or the model would
        // be choosing between indistinguishable identifiers.
        let described = to["description"].as_str().expect("described");
        assert!(
            described.contains("auth:alex = alex@example.com"),
            "{described}"
        );
    }

    /// An empty roster must not produce `enum: []`, which is unsatisfiable — a
    /// deployment with no directory has to leave `to` free for the host to
    /// resolve, not forbid every value.
    #[test]
    fn an_empty_roster_leaves_the_recipient_free_rather_than_impossible() {
        let specs = super::question_tool_specs(Vec::new(), true, &[]);
        let ask = specs
            .iter()
            .find(|spec| spec.name == "ask")
            .expect("the ask tool");
        let to = &ask.input_schema["properties"]["to"];
        assert!(to.get("enum").is_none(), "no impossible enum: {to}");
        assert_eq!(to["type"], "string");
    }

    /// A package whose ceiling does not admit `question.ask` gets no tool at all,
    /// roster or otherwise — the roster is a convenience on an admitted ability,
    /// never a way to acquire one.
    #[test]
    fn a_package_that_cannot_ask_gets_no_ask_tool() {
        let roster = vec![("auth:alex".to_owned(), "alex@example.com".to_owned())];
        let specs = super::question_tool_specs(Vec::new(), false, &roster);
        assert!(specs.iter().all(|spec| spec.name != "ask"));
    }

    use super::*;
    use std::sync::{Mutex, OnceLock};

    #[derive(Debug)]
    struct TestCredentialCapability {
        credential_ref: String,
    }

    impl CredentialCapability for TestCredentialCapability {
        fn credential_ref(&self) -> &str {
            &self.credential_ref
        }

        fn resolve(
            &self,
            credential_ref: &str,
        ) -> io::Result<gaugedesk_harness::CredentialMaterial> {
            if credential_ref != self.credential_ref {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "wrong ref"));
            }
            Ok(gaugedesk_harness::CredentialMaterial::new("test-key", None))
        }
    }

    fn test_credential_capability() -> Arc<dyn CredentialCapability> {
        Arc::new(TestCredentialCapability {
            credential_ref: "gaugedesk:credential:account:openai".to_owned(),
        })
    }

    fn signed_envelope() -> String {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("governance test env lock");
        std::env::set_var("WHIPPLESCRIPT_GOV_ADMIN", "test");
        let result = SignedEnvelope::sign(
            "grant file_store project -> file:/workspace readable by Operator from Operator\n",
            "gaugedesk-admin",
        )
        .expect("test governance agent signs")
        .to_json();
        std::env::remove_var("WHIPPLESCRIPT_GOV_ADMIN");
        drop(guard);
        result
    }

    fn signed_harness_policy() -> String {
        let principal = ResourcePolicy {
            principal: true,
            ..ResourcePolicy::default()
        };
        let ordinary = ResourcePolicy::default();
        let policy = HostGovernancePolicy {
            resources: std::collections::BTreeMap::from([
                ("file:workspace:chat-1".to_owned(), ordinary.clone()),
                ("memory:turn-images:chat-1".to_owned(), ordinary),
                ("command:workspace:chat-1".to_owned(), principal.clone()),
                ("provider:openai".to_owned(), principal.clone()),
                ("provider:owned".to_owned(), principal.clone()),
                ("placement:local".to_owned(), principal),
            ]),
            bindings: std::collections::BTreeMap::from([
                ("project".to_owned(), "file:workspace:chat-1".to_owned()),
                (
                    "turn_images".to_owned(),
                    "memory:turn-images:chat-1".to_owned(),
                ),
                ("command".to_owned(), "command:workspace:chat-1".to_owned()),
                ("model".to_owned(), "provider:openai".to_owned()),
                ("owned".to_owned(), "provider:owned".to_owned()),
                ("local".to_owned(), "placement:local".to_owned()),
            ]),
            capabilities: BTreeSet::from([
                "workspace.read".to_owned(),
                "workspace.write".to_owned(),
                "command.run".to_owned(),
            ]),
            provider_bindings: std::collections::BTreeMap::from([(
                "model".to_owned(),
                ProviderBindingPolicy {
                    provider: "openai".to_owned(),
                    model: "gpt-test".to_owned(),
                    base_url: "https://api.openai.com".to_owned(),
                    credential_ref: "gaugedesk:credential:account:openai".to_owned(),
                },
            )]),
            placements: std::collections::BTreeMap::from([(
                "local".to_owned(),
                WhipplePlacementPolicy {
                    kind: "local".to_owned(),
                    provider_bindings: BTreeSet::from(["model".to_owned()]),
                    command_network: false,
                },
            )]),
            ..HostGovernancePolicy::default()
        };
        let authority = AuthorityId::new("authority:owner");
        let key = SigningKey::from_seed(&[7u8; 32]).expect("key");
        sign_policy_envelope(&policy.to_json().expect("policy"), &authority, &key)
            .expect("signed harness policy")
    }

    #[test]
    fn admits_only_a_signed_whipplescript_envelope_and_keeps_its_identity() {
        let signed = signed_envelope();
        let admitted = AdmittedPolicyEpoch::verify(PolicyEpoch::new(7).expect("epoch"), &signed)
            .expect("signed envelope admits");
        assert_eq!(admitted.epoch().get(), 7);
        assert_eq!(admitted.signer(), "gaugedesk-admin");
        assert_eq!(admitted.envelope_hash().len(), 64);
        assert_eq!(admitted.protocol_ref().epoch, 7);
        assert!(admitted.governs("project"));
    }

    #[test]
    fn openai_generic_endpoint_host_derives_and_enforces_tls_policy() {
        // https remote: host derived, lowercased, port/path stripped.
        assert_eq!(
            openai_generic_endpoint_host("https://API.OpenRouter.ai/v1").unwrap(),
            "api.openrouter.ai"
        );
        assert_eq!(
            openai_generic_endpoint_host("https://gw.example.com:8443/v1/").unwrap(),
            "gw.example.com"
        );
        // http allowed for loopback only (ADR 0083 — local model servers).
        assert_eq!(
            openai_generic_endpoint_host("http://localhost:11434/v1").unwrap(),
            "localhost"
        );
        assert_eq!(
            openai_generic_endpoint_host("http://127.0.0.1:1234").unwrap(),
            "127.0.0.1"
        );
        assert_eq!(
            openai_generic_endpoint_host("http://[::1]:8000/v1").unwrap(),
            "::1"
        );
        // http to a remote host is refused (cleartext to a TCB endpoint).
        assert!(openai_generic_endpoint_host("http://api.example.com/v1").is_err());
        // Non-http(s) scheme, missing host, and non-URL input all fail closed.
        assert!(openai_generic_endpoint_host("ftp://api.example.com").is_err());
        assert!(openai_generic_endpoint_host("https:///v1").is_err());
        assert!(openai_generic_endpoint_host("api.example.com").is_err());
    }

    #[test]
    fn openai_generic_descriptor_requires_endpoint_and_model_and_maps_to_openai() {
        // Endpoint + model present: descriptor carries the exact host + full base_url.
        let desc = native_provider_descriptor(
            "openai-generic",
            Some("llama-3.3-70b"),
            Some("https://api.together.xyz/v1"),
        )
        .expect("openai-generic descriptor");
        assert_eq!(desc.endpoint_host, "api.together.xyz");
        assert_eq!(desc.base_url, "https://api.together.xyz/v1");
        assert_eq!(desc.model, "llama-3.3-70b");
        // Missing endpoint and missing model both fail closed.
        assert!(native_provider_descriptor("openai-generic", Some("m"), None).is_err());
        assert!(native_provider_descriptor(
            "openai-generic",
            None,
            Some("https://api.together.xyz")
        )
        .is_err());
        // A bad (remote http) endpoint is refused at descriptor derivation too.
        assert!(native_provider_descriptor(
            "openai-generic",
            Some("m"),
            Some("http://api.together.xyz")
        )
        .is_err());
    }

    #[test]
    fn xai_descriptor_carries_the_v1_base_and_requires_an_explicit_model() {
        // Fixed host, but on the Chat Completions wire: the client appends only
        // `/chat/completions`, so the base URL MUST already carry `/v1` or every
        // turn 404s (the openai-generic lesson, live-confirmed 2026-07-19).
        let desc =
            native_provider_descriptor("xai", Some("grok-4.6"), None).expect("xai descriptor");
        assert_eq!(desc.base_url, "https://api.x.ai/v1");
        assert_eq!(desc.endpoint_host, "api.x.ai");
        assert_eq!(desc.model, "grok-4.6");
        // Like the other fixed-host API-key providers, the model is not defaulted.
        assert!(native_provider_descriptor("xai", None, None).is_err());
        // base_url is ignored for fixed-host providers rather than honored.
        let pinned =
            native_provider_descriptor("xai", Some("grok-4.6"), Some("https://evil.example"))
                .expect("xai descriptor ignores base_url");
        assert_eq!(pinned.base_url, "https://api.x.ai/v1");
    }

    #[test]
    fn unsigned_tampered_and_zero_epoch_inputs_fail_closed() {
        assert_eq!(PolicyEpoch::new(0), Err(PolicyAdmissionError::InvalidEpoch));
        let epoch = PolicyEpoch::new(1).expect("epoch");
        assert!(AdmittedPolicyEpoch::verify(
            epoch,
            "grant file_store project -> file:/workspace public\n"
        )
        .is_err());

        let signed = signed_envelope();
        let tampered = signed.replace("file:/workspace", "file:/elsewhere");
        assert_ne!(tampered, signed);
        assert!(AdmittedPolicyEpoch::verify(epoch, &tampered).is_err());
    }

    #[test]
    fn gaugedesk_uses_whipplescripts_policy_bound_command_and_receipt_types() {
        let admitted =
            AdmittedPolicyEpoch::verify(PolicyEpoch::new(9).expect("epoch"), &signed_envelope())
                .expect("policy");
        let command = StartTurnCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: "turn-command-9".to_owned(),
            run_ref: "gaugedesk:run:9".to_owned(),
            instance_ref: "whip:instance:9".to_owned(),
            package_version_ref: "whip:package-version:9".to_owned(),
            policy: admitted.protocol_ref().clone(),
            actor_ref: "authority:owner".to_owned(),
            input: TurnInput {
                text: "inspect the project".to_owned(),
                images: Vec::new(),
            },
            resources: vec![ResourceRef {
                handle: "gaugedesk:resource:project".to_owned(),
                kind: "file_store".to_owned(),
                selector: None,
            }],
            provider_binding: ProviderBindingRef {
                binding_id: "gaugedesk:provider:primary".to_owned(),
                credential: CredentialRef {
                    credential_id: "gaugedesk:credential:account:openai".to_owned(),
                },
            },
            placement_ceiling_ref: "gaugedesk:placement:local".to_owned(),
        };
        command.validate().expect("command");

        let receipt = TurnReceipt {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: command.command_id.clone(),
            run_ref: command.run_ref.clone(),
            instance_ref: command.instance_ref.clone(),
            policy: command.policy.clone(),
            terminal_position: EventPosition {
                instance_ref: command.instance_ref.clone(),
                sequence: 1,
            },
            status: TurnStatus::Completed,
            output_handle: Some("whip:output:9".to_owned()),
            usage_ref: "whip:evidence:usage:9".to_owned(),
            guarantee_report_ref: "whip:evidence:guarantee:9".to_owned(),
            workspace_cut_ref: None,
        };
        receipt.validate_for(&command).expect("receipt");
    }

    #[test]
    fn gaugedesk_root_signs_and_whipplescript_verifies_without_admin_env() {
        let authority = AuthorityId::new("authority:owner");
        let key = SigningKey::from_seed(&[7u8; 32]).expect("root key");
        let config = "grant file_store project -> file:/workspace readable by Operator\n";
        let signed = sign_policy_envelope(config, &authority, &key).expect("signed");
        let verifier = GovernanceRootVerifier::new(authority.clone(), key.public_key());
        let admitted = AdmittedPolicyEpoch::verify_with(
            PolicyEpoch::new(11).expect("epoch"),
            &signed,
            &verifier,
        )
        .expect("cryptographic policy admission");

        assert_eq!(admitted.signer(), authority.as_str());
        assert_eq!(admitted.key_id(), Some(key.public_key().as_str()));
        assert_eq!(
            admitted.protocol_ref().key_id,
            Some(key.public_key().to_string())
        );
        assert!(admitted.governs("project"));

        let other = SigningKey::from_seed(&[8u8; 32]).expect("other key");
        let wrong_root = GovernanceRootVerifier::new(authority, other.public_key());
        assert!(AdmittedPolicyEpoch::verify_with(
            PolicyEpoch::new(11).expect("epoch"),
            &signed,
            &wrong_root,
        )
        .is_err());
    }

    #[test]
    fn whip_harness_reopens_the_same_instance_and_owns_workspace_tools() {
        let root = tempfile::tempdir().expect("runtime root");
        let worktree = tempfile::tempdir().expect("worktree");
        let package_root = worktree.path().join(".whipple/versions/1");
        std::fs::create_dir_all(&package_root).expect("method dir");
        std::fs::write(
            package_root.join("package.json"),
            r#"{
  "schema":"whipplescript.agent_package.v0",
  "source":"method.whip",
  "workflow":"Method",
  "agent":"assistant",
  "system_prompt":"persona.md",
  "capabilities":["workspace.read","workspace.write","command.run"],
  "agent_abilities":["workspace.read","workspace.write","command.run"],
  "max_steps":32
}"#,
        )
        .expect("manifest");
        std::fs::write(
            package_root.join("method.whip"),
            r#"
file store project { root "." allow read ["**"] allow write ["**"] }
workflow Method {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
    capabilities ["workspace.read", "workspace.write", "command.run"]
  }
  rule converse when started => {
    tell assistant requires ["workspace.read", "workspace.write", "command.run"]
      with access to project { read ["**"] write ["**"] }
      with access to command { run }
      "Run."
  }
}
"#,
        )
        .expect("source");
        std::fs::write(package_root.join("persona.md"), "Use the project method.").expect("method");
        let package_ref = AuthoredAgentPackage::load(&package_root)
            .expect("package")
            .version_ref()
            .to_owned();
        let spec = HarnessSpec {
            chat_id: "chat-1".to_owned(),
            worktree: worktree.path().to_path_buf(),
            mode: gaugedesk_harness::ChatMode::Use,
            package_root: Some(package_root.clone()),
            package_version_ref: Some(package_ref.clone()),
            policy_epoch: Some(1),
            signed_policy_envelope: Some(signed_harness_policy()),
            provider_binding_ref: Some("model".to_owned()),
            credential_ref: Some("gaugedesk:credential:account:openai".to_owned()),
            placement_ceiling_ref: Some("local".to_owned()),
            runtime_placement_id: Some("placement-test".to_owned()),
            provider: Some("openai".to_owned()),
            model: Some("gpt-test".to_owned()),
            base_url: None,
            thinking: None,
            system_prompt: None,
            credential_capability: Some(test_credential_capability()),
            credentials: vec![("OPENAI_API_KEY".to_owned(), "test-key".to_owned())],
            sandbox: gaugedesk_harness::sandbox::SandboxPolicy::new(vec![worktree
                .path()
                .to_path_buf()])
            .read_only(vec![worktree.path().join(".whipple")])
            .filter_egress(vec!["api.openai.com".to_owned()]),
            roster: Vec::new(),
        };
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            SigningKey::from_seed(&[7u8; 32]).expect("key"),
            root.path(),
        );
        let first = factory.create_harness(&spec).expect("first harness");
        assert_eq!(first.package.version_ref(), package_ref);
        assert!(!first
            .package
            .agent_abilities()
            .iter()
            .any(|capability| capability == "human.ask"));
        assert!(!first
            .new_turn_command("question", &[], 1, None)
            .resources
            .iter()
            .any(|resource| resource.kind == "human"));
        assert_eq!(
            first
                .new_turn_command("question", &[], 2, Some("home-command:stable".to_owned()))
                .command_id,
            "home-command:stable"
        );
        assert!(native_workspace_tool_specs(true)
            .iter()
            .any(|tool| tool.name == "write"));
        assert!(native_workspace_tool_specs_with_command(true, true)
            .iter()
            .any(|tool| tool.name == "bash"));
        assert!(first.interrupt_handle().is_some());
        let instance = first.instance_ref.clone();
        drop(first);
        let reopened = factory.create_harness(&spec).expect("reopened harness");
        assert_eq!(reopened.instance_ref, instance);
        let exact_source_position = reopened
            .runtime
            .current_position(&reopened.instance_ref)
            .expect("source position");

        let respondent = AuthorityId::new("authority:authenticated-member");
        let mut attributed = factory.create_harness(&spec).expect("attributed harness");
        attributed.bind_authenticated_actor(respondent.as_str());
        assert_eq!(attributed.respondent_ref, respondent.as_str());

        let target_worktree = tempfile::tempdir().expect("target worktree");
        let target_package_root = target_worktree.path().join(".whipple/versions/1");
        std::fs::create_dir_all(&target_package_root).expect("target package parent");
        for file in ["package.json", "method.whip", "persona.md"] {
            std::fs::copy(package_root.join(file), target_package_root.join(file))
                .expect("target package file");
        }
        let source_continuity = HarnessContinuitySpec {
            chat_id: spec.chat_id.clone(),
            runtime_placement_id: spec.runtime_placement_id.clone(),
            worktree: spec.worktree.clone(),
            mode: spec.mode,
            package_root: Some(package_root),
            package_version_ref: Some(package_ref.clone()),
            system_prompt: None,
            policy_epoch: spec.policy_epoch,
            signed_policy_envelope: spec.signed_policy_envelope.clone(),
            source_position: Some(RuntimePosition {
                instance_ref: exact_source_position.instance_ref,
                sequence: exact_source_position.sequence,
            }),
        };
        let target_continuity = HarnessContinuitySpec {
            chat_id: "chat-2".to_owned(),
            runtime_placement_id: spec.runtime_placement_id.clone(),
            worktree: target_worktree.path().to_path_buf(),
            mode: spec.mode,
            package_root: Some(target_package_root),
            package_version_ref: Some(package_ref),
            system_prompt: None,
            policy_epoch: spec.policy_epoch,
            signed_policy_envelope: spec.signed_policy_envelope.clone(),
            source_position: None,
        };
        factory
            .clone_continuity(&source_continuity, &target_continuity)
            .expect("governed fork");
        factory
            .clone_continuity(&source_continuity, &target_continuity)
            .expect("governed fork replay");
        let target_spec = HarnessSpec {
            chat_id: target_continuity.chat_id.clone(),
            worktree: target_continuity.worktree.clone(),
            sandbox: gaugedesk_harness::sandbox::SandboxPolicy::new(vec![target_continuity
                .worktree
                .clone()])
            .read_only(vec![target_continuity.worktree.join(".whipple")])
            .filter_egress(vec!["api.openai.com".to_owned()]),
            ..spec.clone()
        };
        let forked = factory
            .create_harness(&target_spec)
            .expect("forked harness reopens");
        assert_ne!(forked.instance_ref, instance);
        assert!(
            forked
                .runtime
                .current_position(&forked.instance_ref)
                .expect("fork position")
                .sequence
                >= 3
        );

        let mut isolated = spec.clone();
        isolated.sandbox.network = Network::Deny;
        let error = ProviderConfig::from_spec(&isolated)
            .err()
            .expect("isolation must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let mut wrong_endpoint = spec;
        wrong_endpoint.sandbox.allowed_hosts = vec!["example.com".to_owned()];
        let error = ProviderConfig::from_spec(&wrong_endpoint)
            .err()
            .expect("provider endpoint must be explicitly admitted");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn whip_factory_requires_gaugedesk_owned_codex_material() {
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            SigningKey::from_seed(&[7u8; 32]).expect("key"),
            ".",
        );
        assert!(matches!(
            factory.credential_status("openai-codex", None),
            CredentialProbe::Missing(reason) if reason.contains("GaugeDesk-owned")
        ));
        assert_eq!(
            factory.credential_status("openai-codex", Some(test_credential_capability().as_ref())),
            CredentialProbe::Ready
        );
    }
}

#[cfg(test)]
mod turn_failure_tests {
    use super::turn_failure;
    use crate::HostRuntimeError;
    use std::io;

    /// An information-flow denial is the policy speaking. It is carried out of
    /// the runtime as `PermissionDenied` so the route can answer `403` rather
    /// than reporting a refusal as a broken gateway.
    #[test]
    fn an_ifc_denial_is_carried_as_permission_denied() {
        let error = HostRuntimeError::Ifc(vec![
            "denied read in rule `converse`: the agent acts-for `authority:abc`".to_string(),
        ]);
        let carried = turn_failure(error);
        assert_eq!(carried.kind(), io::ErrorKind::PermissionDenied);
        assert!(carried.to_string().contains("denied read in rule"));
    }

    /// A rejected package is the same kind of decision and travels the same way.
    #[test]
    fn a_policy_rejection_is_carried_as_permission_denied() {
        let carried = turn_failure(HostRuntimeError::PolicyRejected("no such rule".into()));
        assert_eq!(carried.kind(), io::ErrorKind::PermissionDenied);
    }

    /// The runtime or its host being wrong is not a refusal. These keep
    /// `InvalidData`, so they keep answering `502` — the reclassification is
    /// deliberately narrow.
    #[test]
    fn runtime_faults_are_not_reclassified() {
        for error in [
            HostRuntimeError::UnknownInstance("inst-gone".into()),
            HostRuntimeError::UngovernedHandle("handle".into()),
            HostRuntimeError::Incomplete("turn".into()),
            HostRuntimeError::Resolver("no package".into()),
        ] {
            assert_eq!(
                turn_failure(error).kind(),
                io::ErrorKind::InvalidData,
                "only a deliberate policy decision may be reclassified",
            );
        }
    }

    /// The message survives the classification unchanged — the point is to add
    /// a machine-readable kind, never to replace the runtime's explanation.
    #[test]
    fn the_runtime_explanation_survives() {
        let error = HostRuntimeError::Ifc(vec!["outside `project`'s readers".to_string()]);
        let expected = error.to_string();
        assert_eq!(turn_failure(error).to_string(), expected);
    }
}
