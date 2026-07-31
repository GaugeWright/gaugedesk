use std::path::{Path, PathBuf};
use std::sync::Mutex;

use gaugewright_store::Store;

use crate::boundary_keeper::LoopbackKeyReleaseService;
use crate::workbench_state::Workbench;

/// How the attested-boundary accept route verifies a presented quote before
/// releasing sealed keys (C-3 hardening). The [`LoopbackVerifier`]'s "signature"
/// check is only *report bytes non-empty*, so on a live key-release route it
/// must not stand in for a real TEE verifier.
///
/// [`LoopbackVerifier`]: crate::attestation_verifier::LoopbackVerifier
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttestationMode {
    /// A real TEE verifier is required. Until one is wired, the attested-accept
    /// route refuses rather than release sealed keys against the loopback stand-in.
    #[default]
    RealRequired,
    /// Explicit loopback/dev mode: the in-process loopback verifier is used.
    Loopback,
}

/// Lock a mutex, recovering from poisoning (RF-A4). Durable product truth is
/// the store's atomic transactions and the in-memory `Workbench` is rebuildable
/// projection state, so the data behind a poisoned lock is safe to reuse.
pub trait LockUnpoisoned<T> {
    fn lock_unpoisoned(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> LockUnpoisoned<T> for Mutex<T> {
    fn lock_unpoisoned(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The stable id of the seeded default archetype's repo.
pub const DEFAULT_INSTANCE: &str = "inst-default";
/// The stable id of the seeded Default archetype (ADR 0035).
pub const DEFAULT_AGENT: &str = "agent-default";
pub const SOFTWARE_ENGINEER_AGENT: &str = "agent-software-engineer";
pub const OFFICE_WORKER_AGENT: &str = "agent-office-worker";
/// The hidden default "Personal" project (ADR 0036).
pub const DEFAULT_PROJECT: &str = "proj-default";
/// The default archetype placement on the default "Personal" project.
pub const DEFAULT_PLACEMENT: &str = "inst-placement-default";

pub struct BuiltinArchetype {
    pub id: &'static str,
    pub name: &'static str,
    system: &'static str,
    instructions: &'static str,
    pub official_skills: bool,
}

/// Starter method definitions for the built-in library archetypes.
pub(crate) const DEFAULT_AGENT_SYSTEM_MD: &str = "\
You are a general-purpose assistant. Work carefully and directly on the task.
";

pub(crate) const SOFTWARE_ENGINEER_SYSTEM_MD: &str = "\
You are a software engineer. Understand the codebase, make focused changes, and verify them.
";

pub(crate) const OFFICE_WORKER_SYSTEM_MD: &str = "\
You are an office worker. For document work, read the applicable guide in .gaugedesk-runtime/discipline/official-skills/.
";

pub(crate) const DEFAULT_AGENT_AGENTS_MD: &str = "\
# Agent conventions

Use the workspace's own files and conventions. Your definition is read-only in
a work chat; edit it only in an edit chat.
";

const BUILTIN_ARCHETYPES: [BuiltinArchetype; 3] = [
    BuiltinArchetype {
        id: DEFAULT_AGENT,
        name: "Default",
        system: DEFAULT_AGENT_SYSTEM_MD,
        instructions: DEFAULT_AGENT_AGENTS_MD,
        official_skills: false,
    },
    BuiltinArchetype {
        id: SOFTWARE_ENGINEER_AGENT,
        name: "Software engineer",
        system: SOFTWARE_ENGINEER_SYSTEM_MD,
        instructions: DEFAULT_AGENT_AGENTS_MD,
        official_skills: false,
    },
    BuiltinArchetype {
        id: OFFICE_WORKER_AGENT,
        name: "Office worker",
        system: OFFICE_WORKER_SYSTEM_MD,
        instructions: DEFAULT_AGENT_AGENTS_MD,
        official_skills: true,
    },
];

pub(crate) fn builtin_archetypes() -> &'static [BuiltinArchetype] {
    &BUILTIN_ARCHETYPES
}

pub(crate) fn builtin_agent_definition(
    archetype: &BuiltinArchetype,
) -> gaugewright_boundary::definition::AgentDefinition {
    gaugewright_boundary::definition::AgentDefinition {
        system: archetype.system.into(),
        instructions: archetype.instructions.into(),
        config: None,
    }
}

/// The seeded default agent as the neutral definition (ADR 0029/0035): the one
/// constructor both seeding paths materialize via
/// [`AgentDefinition::seed_files`](gaugewright_boundary::definition::AgentDefinition::seed_files).
pub(crate) fn default_agent_definition() -> gaugewright_boundary::definition::AgentDefinition {
    builtin_agent_definition(&BUILTIN_ARCHETYPES[0])
}

/// The single local user authority — the owner of context opened in the
/// single-user collapse. Multi-user identity is the G1/M2 deferral.
pub const LOCAL_AUTHORITY: &str = "local-user";

/// Whether the cross-authority **federation** surface is enabled (`GAUGEWRIGHT_FEDERATION=1`).
/// **PARKED off by default (ADR 0065):** the single-authority initial product needs no relay, so
/// the federation subsystem is not opened and its routes are not mounted unless an operator
/// explicitly opts in. The cross-authority machinery reactivates with D-ATTEST / a real
/// multi-party push; until then it is dormant and unreachable in the product.
pub(crate) fn federation_enabled() -> bool {
    std::env::var("GAUGEWRIGHT_FEDERATION").as_deref() == Ok("1")
}

/// Whether the **attested-specific operator surface** is enabled (`GAUGEWRIGHT_ATTESTATION=1`).
/// **PARKED off by default (ADR 0065):** the measurement registry + attested-run entitlement
/// routes are mounted only on opt-in. The attested accept path stays fail-closed
/// (`RealRequired`) regardless; this gate removes the operator surface from the initial product.
pub(crate) fn attestation_enabled() -> bool {
    std::env::var("GAUGEWRIGHT_ATTESTATION").as_deref() == Ok("1")
}

/// The attestation verifier mode for a real served deployment. It fails closed
/// by default; the loopback stand-in is used only when explicitly requested.
pub(crate) fn attestation_mode_from_env() -> AttestationMode {
    if std::env::var("GAUGEWRIGHT_ATTESTATION_VERIFIER").as_deref() == Ok("loopback") {
        eprintln!(
            "[gaugewright] WARNING: attested-boundary acceptance is using the LOOPBACK quote \
             verifier (GAUGEWRIGHT_ATTESTATION_VERIFIER=loopback). Its signature check is only \
             \"report bytes non-empty\" — a forged quote for a registered measurement would \
             verify and unseal keys. Use only for the loopback/dev shape, never with real \
             measurements/sealed keys."
        );
        AttestationMode::Loopback
    } else {
        AttestationMode::RealRequired
    }
}

pub(crate) fn io<E: std::fmt::Debug>(e: E) -> std::io::Error {
    std::io::Error::other(format!("{e:?}"))
}

pub(crate) fn prepare_workbench_root(root: &Path) -> std::io::Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(root)?;
    let root = root.canonicalize()?;
    let targets_dir = root.join("targets");
    std::fs::create_dir_all(&targets_dir)?;
    Ok((root, targets_dir))
}

impl Workbench {
    /// Immutable package identity and declared WhippleScript effects for a
    /// work chat. Managed execution uses this before acknowledging a command so
    /// the selected profile and its outer grant cannot drift from the package
    /// the shared engine later opens.
    pub fn runtime_package_descriptor_for_chat(
        &self,
        chat_id: &str,
    ) -> std::io::Result<Option<RuntimePackageDescriptor>> {
        let Some((version, expected_ref)) = self.package_selection_for_chat(chat_id) else {
            return Ok(None);
        };
        let root = self
            .package_root_for_chat(chat_id, version)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "selected WhippleScript package is unavailable",
                )
            })?;
        let package = gaugewright_whip_runtime::AuthoredAgentPackage::load(&root)
            .map_err(std::io::Error::other)?;
        if package.version_ref() != expected_ref {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "selected WhippleScript package bytes do not match their pinned reference",
            ));
        }
        Ok(Some(RuntimePackageDescriptor {
            package_ref: expected_ref,
            capabilities: package.capabilities().to_vec(),
        }))
    }

    pub fn whip_harness_factory(
        &self,
    ) -> std::io::Result<gaugewright_whip_runtime::WhipHarnessFactory> {
        let signing_key =
            gaugewright_core::signature::SigningKey::from_seed(&self.governance_seed())
                .map_err(|error| std::io::Error::other(error.reason))?;
        let factory = gaugewright_whip_runtime::WhipHarnessFactory::new(
            self.authority().clone(),
            signing_key,
            self.root_path().join("whip-runtimes"),
        );
        match std::env::var("GAUGEWRIGHT_DO_HOST_URL") {
            Ok(url) if !url.trim().is_empty() => {
                let token = std::env::var("GAUGEWRIGHT_DO_HOST_TOKEN").map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "GAUGEWRIGHT_DO_HOST_TOKEN is required with GAUGEWRIGHT_DO_HOST_URL",
                    )
                })?;
                let tenant = std::env::var("GAUGEWRIGHT_DO_TENANT").map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "GAUGEWRIGHT_DO_TENANT is required with GAUGEWRIGHT_DO_HOST_URL",
                    )
                })?;
                Ok(
                    factory.with_do_host(gaugewright_whip_runtime::DoHostConfig::new(
                        url, token, tenant,
                    )?),
                )
            }
            _ => Ok(factory),
        }
    }

    /// Set how attested acceptance verifies quotes (C-3). Production reads
    /// `GAUGEWRIGHT_ATTESTATION_VERIFIER` (see `open_workbench`); the loopback/e2e shape
    /// sets [`AttestationMode::Loopback`] explicitly. Builder-style.
    pub fn with_attestation_mode(mut self, mode: AttestationMode) -> Self {
        self.attestation_mode = mode;
        self
    }

    /// How this workbench verifies attested-boundary quotes (C-3).
    pub fn attestation_mode(&self) -> AttestationMode {
        self.attestation_mode
    }

    /// Enable the **attested-specific operator surface** (the measurement registry + attested-run
    /// entitlement/metering routes). PARKED off by default (ADR 0065); startup sets this from
    /// `GAUGEWRIGHT_ATTESTATION=1`, the attested e2e suites set it explicitly. Builder-style.
    /// Does **not** affect the shared `/boundaries/*` lifecycle.
    pub fn with_attestation_enabled(mut self, on: bool) -> Self {
        self.attestation_enabled = on;
        self
    }

    /// Whether the attested-specific operator routes are mounted (`ENTSEC`/ADR 0065 gate).
    pub fn is_attestation_enabled(&self) -> bool {
        self.attestation_enabled
    }

    /// Whether cross-authority federation routes are mounted.
    pub fn is_federation_enabled(&self) -> bool {
        self.federation.is_some()
    }

    /// This instance's state root, used by open local/federation routes for
    /// file-backed key stores and workspace-local artifacts.
    pub fn root_path(&self) -> std::path::PathBuf {
        self.root.clone()
    }

    pub(crate) fn apply_startup_root(&mut self, root: PathBuf) {
        self.root = root;
    }

    pub(crate) fn restore_startup_local_projections(&mut self) {
        self.restore_workstream_homing();
        self.restore_measurements();
    }

    /// The underlying event store, mutable. Route owners and integration tests
    /// use this narrow seam to drive lifecycle scopes through the durable log.
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// The underlying event store, read-only, for projections that only fold log
    /// state without taking ownership of Workbench internals.
    pub fn store_ref(&self) -> &Store {
        &self.store
    }

    /// Borrow the mutable store alongside the sealed-key release service for
    /// attested boundary acceptance, where the reducer write and key release
    /// decision must stay in one operation.
    pub(crate) fn store_mut_and_sealed_keys(&mut self) -> (&mut Store, &LoopbackKeyReleaseService) {
        (&mut self.store, &self.sealed_keys)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePackageDescriptor {
    pub package_ref: String,
    pub capabilities: Vec<String>,
}
