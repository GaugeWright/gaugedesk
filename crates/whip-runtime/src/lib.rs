//! GaugeDesk's side of the permanent WhippleScript runtime boundary.
//!
//! This crate deliberately depends on WhippleScript's published trust-boundary
//! types. GaugeDesk may produce product policy, but it must never reimplement the
//! envelope parser, attestation check, or IFC algebra it asks WhippleScript to
//! enforce (ADR 0080 / SUB-1).

use std::collections::{BTreeMap, BTreeSet};

pub mod home_import;
pub mod host_actions;
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use gaugedesk_core::ids::{AuthorityId, ModelAttemptId, PublicKey};
use gaugedesk_core::model_connection::AuthorityBinding;
use gaugedesk_core::signature::{verify_signature, Signature, SigningKey};
use gaugedesk_harness::sandbox::Network;
use gaugedesk_harness::{
    ContextWindowReading, CredentialCapability, CredentialProbe, EgressGate, Harness,
    HarnessContinuitySpec, HarnessFactory, HarnessSpec, ImageContent, ModelContextHandle,
    Observation, OutputFieldFlow, RuntimePosition, RuntimeTurnPreparation, TargetRenamer,
    TaskFiler, ToolInfo, TurnOutcome,
};

use whipplescript_store::payload_protection::PayloadProtection;

type TargetRenamerSlot = Arc<Mutex<Option<Arc<dyn TargetRenamer>>>>;
pub use whipplescript::gov::{
    canonicalize, external_signing_bytes, external_signing_bytes_v2, ExternalAttestation,
    GovernanceAttestationVerifier, SignedEnvelope,
};
pub use whipplescript::host_policy::{
    HostGovernancePolicy, PlacementPolicy as WhipplePlacementPolicy, ProviderBindingPolicy,
    ResourcePolicy,
};
pub use whipplescript::host_protocol::{
    AdoptionCut, CredentialRef, EventPosition, ForkInstanceCommand, ForkedInstance,
    LabeledRuntimeEvent, OpenInstanceCommand, OpenedInstance, PolicyEpochRef, ProtocolError,
    ProviderBindingRef, ResourceRef, RuntimeEvidencePointer, StartTurnCommand, TurnInput,
    TurnReceipt, TurnStatus, HOST_PROTOCOL,
};
pub use whipplescript::host_runtime::{
    native_workspace_tool_specs, native_workspace_tool_specs_with_capabilities,
    native_workspace_tool_specs_with_command, AuthoredAgentPackage, CertifiedOutputFieldFlow,
    GovernedHostRuntime, HostCancellationHandle, HostRuntimeError, LabeledTurnOutput,
    ModelProvider, NativeProviderTransport, NativeWorkspaceResolver, PackageResolver,
    ProjectedToolCall, RecordedWorkspaceWitness, ResolvedImage, ResolvedPackage,
    ResolvedProviderBinding, ResourceResolver, SecretResolver, ToolCall, TurnContentSegment,
    TurnExecution, TurnWitness,
};
/// WhippleScript's information-flow surface, re-exported so a host can parse and
/// check the governance envelopes it ships rather than trusting their text.
pub use whipplescript::ifc;
use whipplescript_kernel::sansio::{
    InitialModelProvenance, ModelContentProvenance, ModelRequestProvenance,
};

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

/// The native workspace a turn's tools run in: the chat's worktree with its
/// read-only roots, each target presented under its name (DR-0248), and a
/// rename of a target's folder admitted by the Home's renamer bound for the
/// running turn.
fn workspace_resolver(
    worktree: &Path,
    sandbox_read_only: &[PathBuf],
    targets: &[gaugedesk_harness::WorkspaceTargetBinding],
    renamer: &TargetRenamerSlot,
) -> io::Result<NativeWorkspaceResolver> {
    let mut read_only = sandbox_read_only.to_vec();
    read_only.extend(
        targets
            .iter()
            .filter(|target| !target.writable)
            .map(|target| PathBuf::from(&target.root)),
    );
    if !targets.is_empty() {
        read_only.push(PathBuf::from(TARGET_MANIFEST_SELECTOR));
    }
    let renamer = Arc::clone(renamer);
    Ok(NativeWorkspaceResolver::new(worktree)
        .and_then(|resolver| resolver.read_only(read_only))
        .map_err(invalid_data)?
        .with_root_rename_admission(move |rename| {
            let bound = renamer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            match bound {
                Some(renamer) => renamer.rename_target(&rename.selector, &rename.from, &rename.to),
                None => Err(format!(
                    "renaming `{}` is not available in this conversation",
                    rename.from
                )),
            }
        }))
}

pub(crate) fn validate_workspace_targets(
    targets: &[gaugedesk_harness::WorkspaceTargetBinding],
) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    let mut handles = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut names = BTreeSet::new();
    for target in targets {
        if target.target_id.is_empty()
            || !ids.insert(target.target_id.as_str())
            || !handles.insert(target.resource_handle.as_str())
            || !roots.insert(target.root.as_str())
            || (!target.name.is_empty() && !names.insert(target.name.as_str()))
        {
            return Err("workspace target declaration has an empty or duplicate identity".into());
        }
        let mut components = target.root.split('/');
        if components.next() != Some("targets")
            || !components.next().is_some_and(|root| root.starts_with("t-"))
            || components.next().is_some()
            || !target.resource_handle.starts_with("target:")
        {
            return Err("workspace target declaration has a non-canonical root or handle".into());
        }
        if !target.readable || (target.output && !target.writable) {
            return Err("workspace target declaration has impossible I/O capabilities".into());
        }
    }
    Ok(())
}

pub(crate) fn workspace_resource_refs(
    targets: &[gaugedesk_harness::WorkspaceTargetBinding],
) -> Vec<ResourceRef> {
    if targets.is_empty() {
        vec![ResourceRef {
            handle: "project".to_owned(),
            kind: "file_store".to_owned(),
            selector: None,
            writable: None,
            presented_as: None,
        }]
    } else {
        let mut resources = targets
            .iter()
            .map(|target| ResourceRef {
                handle: target.resource_handle.clone(),
                kind: "file_store".to_owned(),
                selector: Some(target.root.clone()),
                writable: Some(target.writable),
                // DR-0248: the agent sees the target as a folder named after
                // it; the selector stays the stable-ID partition.
                presented_as: (!target.name.is_empty()).then(|| target.name.clone()),
            })
            .collect::<Vec<_>>();
        resources.push(ResourceRef {
            handle: TARGET_MANIFEST_RESOURCE.to_owned(),
            kind: "file_store".to_owned(),
            selector: Some(TARGET_MANIFEST_SELECTOR.to_owned()),
            writable: Some(false),
            presented_as: None,
        });
        resources
    }
}
use whipplescript::ifc::VerifiedEnvelope;

/// The runtime database a chat's harness writes: one SQLite store per chat
/// under the factory's runtime root, named by the chat id.
///
/// One derivation, because two readers of it now exist. The harness opens it
/// to run turns, and the Instances view opens it to draw what those turns
/// did; a second spelling of this path would be a way to draw nothing while
/// the harness writes somewhere else.
pub fn chat_runtime_database(runtime_root: &Path, chat_id: &str) -> PathBuf {
    runtime_root.join(format!("{}.sqlite", hex::encode(chat_id.as_bytes())))
}

/// One instance, projected, with the program it belongs to.
#[derive(Clone, Debug)]
pub struct ProjectedInstance {
    /// The program version's `program_name`: the workflow's declared name for
    /// the inbound gate, the agent's name for a chat's package.
    pub program: String,
    /// `whipplescript.instance_view.v1`, as `whip view --json` prints it.
    pub view: serde_json::Value,
}

/// The coercion-config fingerprint of a kernel built by `RuntimeKernel::new`
/// with nothing else configured, which is every kernel this crate builds.
const KERNEL_COERCION_FINGERPRINT: &str = "fixture";

/// Every instance in a runtime store, projected.
///
/// Opens the store the harness or gate writes and reads it as a second
/// connection — SQLite in WAL mode admits a reader beside the writer — so a
/// running instance is drawn as it runs. The projection is WhippleScript's
/// own (`whipplescript::instance_view`), which is what keeps this and `whip
/// view` from disagreeing about the same instance. Observation never initializes
/// or migrates a store; unavailable storage remains an error for the caller.
pub fn instance_views(store_path: &Path) -> io::Result<Vec<ProjectedInstance>> {
    use whipplescript::instance_view;
    // The projection explains each coercion under the fingerprint its
    // admission keys were built with. Every kernel GaugeDesk constructs is
    // `RuntimeKernel::new(store)` with no fingerprint configured, so the value
    // to read back under is the constructor's own; the test below holds the
    // two together.
    // `StoreError` is not a `std::error::Error`, so it is carried by its text.
    let store_io = |error: whipplescript_store::StoreError| io::Error::other(format!("{error:?}"));
    let store = whipplescript_store::SqliteStore::open_read_only(store_path).map_err(store_io)?;
    let mut projected = Vec::new();
    for instance in store.list_instances().map_err(store_io)? {
        let program = store
            .get_program_version(&instance.version_id)
            .map_err(store_io)?
            .map(|version| version.program_name)
            .unwrap_or_default();
        if let Some(view) =
            instance_view::load(&store, &instance.instance_id, KERNEL_COERCION_FINGERPRINT)
                .map_err(store_io)?
        {
            projected.push(ProjectedInstance { program, view });
        }
    }
    Ok(projected)
}

/// One instance of an open runtime store, projected as [`instance_views`]
/// projects each: what a folder run's history row expands to. `None` when the
/// instance does not exist or cannot be read.
pub fn instance_view_in(
    store: &whipplescript_store::SqliteStore,
    instance_id: &str,
) -> Option<serde_json::Value> {
    whipplescript::instance_view::load(store, instance_id, KERNEL_COERCION_FINGERPRINT)
        .ok()
        .flatten()
}

/// The structure of a program from its source, with no instance.
///
/// `None` when the source does not compile: a Structure tab for a broken file
/// shows the diagnostics the editor already shows, not an empty graph.
pub fn program_structure(source: &str) -> Option<serde_json::Value> {
    let compiled = compile_whip_program(source);
    let ir = compiled.ir?;
    let snapshot = ir.to_snapshot();
    let ir_hash = whipplescript_store::stable_hash_hex(&snapshot);
    Some(whipplescript::instance_view::structure(&snapshot, &ir_hash))
}

/// The inputs a workflow declares, as a form can draw them (WHIP-3's Run
/// control). Each is `{name, type}`, where `type` is one of: a primitive
/// (`string`, `int`, `float`, `bool`), a `literal` with its `value`, an `enum`
/// with its `variants`, an `object` with its `fields` (a class resolved to its
/// fields), an `optional` wrapping another, or `json` — everything else, which
/// the form takes as a JSON value and the launch still validates. A pure
/// function of the source: it reads nothing and grants nothing. `None` when the
/// source does not compile.
pub fn workflow_inputs(source: &str) -> Option<serde_json::Value> {
    use whipplescript_parser::{IrPrimitiveType, IrSchema, IrType, IrWorkflowContractKind};
    let ir = compile_whip_program(source).ir?;
    fn describe(ty: &IrType, schemas: &[IrSchema], depth: usize) -> serde_json::Value {
        use serde_json::json;
        if depth > 8 {
            return json!({ "kind": "json" });
        }
        match ty {
            IrType::Primitive(IrPrimitiveType::String) => json!({ "kind": "string" }),
            IrType::Primitive(IrPrimitiveType::Int) => json!({ "kind": "int" }),
            IrType::Primitive(IrPrimitiveType::Float) => json!({ "kind": "float" }),
            IrType::Primitive(IrPrimitiveType::Bool) => json!({ "kind": "bool" }),
            IrType::LiteralString(value) => json!({ "kind": "literal", "value": value }),
            IrType::Optional(inner) => {
                json!({ "kind": "optional", "of": describe(inner, schemas, depth + 1) })
            }
            IrType::Object(fields) => object(fields, schemas, depth),
            IrType::Ref(name) => match schemas.iter().find(|schema| match schema {
                IrSchema::Class(class) => &class.name == name,
                IrSchema::Enum(en) => &en.name == name,
            }) {
                Some(IrSchema::Class(class)) => {
                    let mut value = object(&class.fields, schemas, depth);
                    value["name"] = json!(class.name);
                    value
                }
                Some(IrSchema::Enum(en)) => {
                    json!({ "kind": "enum", "name": en.name, "variants": en.variants })
                }
                None => json!({ "kind": "json" }),
            },
            _ => json!({ "kind": "json" }),
        }
    }
    fn object(
        fields: &[whipplescript_parser::IrClassField],
        schemas: &[IrSchema],
        depth: usize,
    ) -> serde_json::Value {
        // A field present only under a discriminant is beyond a plain form.
        if fields
            .iter()
            .any(|field| field.presence_condition.is_some())
        {
            return serde_json::json!({ "kind": "json" });
        }
        serde_json::json!({
            "kind": "object",
            "fields": fields
                .iter()
                .map(|field| serde_json::json!({
                    "name": field.name,
                    "type": describe(&field.ty, schemas, depth + 1),
                }))
                .collect::<Vec<_>>(),
        })
    }
    Some(serde_json::json!({
        "workflow": ir.workflow,
        "inputs": ir
            .workflow_contracts
            .iter()
            .filter(|contract| contract.kind == IrWorkflowContractKind::Input)
            .map(|contract| serde_json::json!({
                "name": contract.name,
                "type": describe(&contract.ty, &ir.schemas, 0),
            }))
            .collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod workflow_input_tests {
    use super::workflow_inputs;
    use serde_json::json;

    #[test]
    fn basics_asks_for_a_learner_with_an_authority() {
        let inputs = workflow_inputs(include_str!("../../app/src/tutorials/basics.whip")).unwrap();
        assert_eq!(
            inputs,
            json!({
                "workflow": "Basics",
                "inputs": [{
                    "name": "learner",
                    "type": {
                        "kind": "object",
                        "name": "Learner",
                        "fields": [{ "name": "authority", "type": { "kind": "string" } }],
                    },
                }],
            })
        );
    }

    #[test]
    fn primitives_enums_optionals_and_the_rest() {
        let source = r#"workflow Shapes(n: int, ok: bool, mood: Mood, note: string?, tags: string[], box: Box) -> bool
enum Mood {
  Calm
  Busy
}
class Box {
  size int
}
rule go
  when Box as b
=> { complete result true }
"#;
        let inputs = workflow_inputs(source)
            .unwrap_or_else(|| panic!("{:?}", super::compile_whip_program(source).diagnostics));
        let kinds: Vec<_> = inputs["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| {
                (
                    input["name"].as_str().unwrap().to_owned(),
                    input["type"].clone(),
                )
            })
            .collect();
        assert_eq!(kinds[0], ("n".into(), json!({ "kind": "int" })));
        assert_eq!(kinds[1], ("ok".into(), json!({ "kind": "bool" })));
        assert_eq!(kinds[2].1["kind"], "enum");
        assert_eq!(kinds[2].1["variants"], json!(["Calm", "Busy"]));
        assert_eq!(
            kinds[3].1,
            json!({ "kind": "optional", "of": { "kind": "string" } })
        );
        assert_eq!(kinds[4].1, json!({ "kind": "json" }));
    }

    #[test]
    fn a_source_that_does_not_compile_describes_nothing() {
        assert_eq!(workflow_inputs("workflow ("), None);
    }
}

#[cfg(test)]
mod instance_view_tests {
    use super::*;

    #[test]
    fn the_projection_reads_under_the_fingerprint_the_kernels_are_built_with() {
        let store = whipplescript_store::SqliteStore::open_in_memory().expect("store opens");
        let kernel = whipplescript_kernel::RuntimeKernel::new(store);
        assert_eq!(
            kernel.coercion_config_fingerprint(),
            KERNEL_COERCION_FINGERPRINT,
            "a projection under another fingerprint would explain every coercion as stale"
        );
    }

    #[test]
    fn a_chat_s_runtime_database_is_named_by_its_id_in_one_place() {
        // The harness writes here and the Instances view reads here. A second
        // spelling would draw nothing while turns are recorded somewhere else.
        let root = Path::new("/r");
        assert_eq!(
            chat_runtime_database(root, "chat_1"),
            root.join(format!("{}.sqlite", hex::encode("chat_1".as_bytes())))
        );
    }

    #[test]
    fn a_program_has_a_structure_before_anything_runs_it() {
        let structure = program_structure(
            "workflow Demo\n\nrule work\n  when started\n  then\n    log \"hi\"\n",
        );
        // Whether this particular source lowers is the parser's business; what
        // this asserts is the contract: a compiling program yields the view's
        // `structure` member with `available: true`, and a broken one yields
        // nothing rather than an empty graph.
        if let Some(structure) = structure {
            assert_eq!(structure["available"], true);
            assert_eq!(structure["program_version_id"], "");
        }
        assert!(program_structure("this is not a program").is_none());
    }

    #[test]
    fn the_structure_names_each_effect_the_way_its_author_wrote_it() {
        // The cross-repository contract the Structure figure is drawn from
        // (whipplescript DR-0109). Asserted on THIS side of the pin because the
        // figure degrades quietly without it: the mapper falls back to the kind,
        // so a pin that went backwards would draw `agent.tell` where the verb
        // belongs and nothing would fail.
        let structure = program_structure(
            "workflow Demo\n\
             \n\
             agent writer {\n  \
             provider fixture\n  \
             profile \"scribe\"\n  \
             capacity 1\n\
             }\n\
             \n\
             rule work\n  \
             when started\n  \
             when writer is available\n\
             => {\n  \
             then note <- tell writer \"\"\"markdown\n  \
             say something\n  \
             \"\"\"\n\
             }\n",
        )
        .expect("the program compiles");

        let effect = &structure["rules"][0]["effects"][0];
        // The verb the author typed, not the kind the compiler assigned...
        assert_eq!(effect["verb"], "tell");
        assert_eq!(effect["kind"], "agent.tell");
        // ...and their own name, not the `then` sugar's synthetic handle.
        assert_eq!(effect["label"], "note");
        assert_eq!(effect["node"], "__then_note");
        // Every rule answers about its record sources, which is what tells a
        // `table` declaration's lowered rule from behaviour someone wrote.
        assert!(structure["rules"][0]["records"].is_array());
    }

    #[test]
    fn observing_an_unavailable_runtime_does_not_initialize_storage() {
        let dir = tempfile::tempdir().unwrap();
        for path in [
            dir.path().join("missing.sqlite"),
            dir.path().join("absent/runtime.sqlite"),
        ] {
            assert!(instance_views(&path).is_err());
            assert!(!path.exists());
        }
        assert!(!dir.path().join("absent").exists());
    }

    #[cfg(unix)]
    #[test]
    fn runtime_projection_preserves_existing_database_bytes_and_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.sqlite");
        drop(whipplescript_store::SqliteStore::open(&path).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(instance_views(&path).unwrap().is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn an_empty_runtime_store_has_no_instances_and_is_not_an_error() {
        // The ordinary state of a project nothing has run in.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("runtime.sqlite");
        drop(whipplescript_store::SqliteStore::open(&path).expect("open"));
        assert!(instance_views(&path).expect("read").is_empty());
    }
}

mod editor_skill;
pub mod gate_runner;
pub mod whip_stats;
/// The sans-I/O HTTP types a gate host implements its transport against.
pub mod sansio_types {
    pub use whipplescript_kernel::sansio::{HttpRequest, HttpResponse, TransportError};
}

/// One turn-scoped path from a project Home to the organization-owned final
/// fetch authority. The account session authenticates the actor to Hub; it is
/// never sent to the provider authority or serialized into runtime state.
/// Provider credentials are not fields of this value and never enter Desk.
// gaugedesk-peer-demand: POST /projects/:p/organization-model-invocations
// gaugedesk-peer-demand: POST /v1/model-providers/private-fetch
#[derive(Clone)]
pub struct OrganizationModelBrokerConfig {
    hub_origin: String,
    account_session: Arc<str>,
    organization: String,
    project: String,
    chat: String,
    binding: AuthorityBinding,
}

impl fmt::Debug for OrganizationModelBrokerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrganizationModelBrokerConfig")
            .field("hub_origin", &self.hub_origin)
            .field("account_session", &"[REDACTED]")
            .field("organization", &self.organization)
            .field("project", &self.project)
            .field("chat", &self.chat)
            .field("binding", &self.binding)
            .finish()
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrganizationModelPrepareReply {
    v: u8,
    binding: AuthorityBinding,
    attempt: ModelAttemptId,
    fetch_url: String,
    ticket: String,
    expires_at: u64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrganizationModelFetchReply {
    v: u8,
    attempt: ModelAttemptId,
    status: u16,
    body: serde_json::Value,
}

impl OrganizationModelBrokerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hub_origin: impl Into<String>,
        account_session: impl Into<String>,
        organization: impl Into<String>,
        project: impl Into<String>,
        chat: impl Into<String>,
        binding: AuthorityBinding,
    ) -> io::Result<Self> {
        let hub_origin = admitted_service_origin(&hub_origin.into())?.to_string();
        let account_session = account_session.into();
        let organization = organization.into();
        let project = project.into();
        let chat = chat.into();
        for (name, value, maximum) in [
            ("account session", account_session.as_str(), 16 * 1024),
            ("organization", organization.as_str(), 512),
            ("project", project.as_str(), 512),
            ("chat", chat.as_str(), 512),
        ] {
            if value.is_empty()
                || value.trim() != value
                || value.len() > maximum
                || value.chars().any(char::is_control)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("organization model {name} is invalid"),
                ));
            }
        }
        if binding.organization.as_str() != organization {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "organization model authority binding does not match the selected organization",
            ));
        }
        Ok(Self {
            hub_origin,
            account_session: Arc::from(account_session),
            organization,
            project,
            chat,
            binding,
        })
    }

    fn fetch(
        &self,
        request: &sansio_types::HttpRequest,
    ) -> Result<sansio_types::HttpResponse, sansio_types::TransportError> {
        self.fetch_with_timeout(request, Duration::from_secs(130))
    }

    /// The same admitted organization-model route for a bounded metadata
    /// request. Naming a chat must not hold up an otherwise completed turn for
    /// the full agent-turn deadline.
    pub fn fetch_for_title(
        &self,
        request: &sansio_types::HttpRequest,
    ) -> Result<sansio_types::HttpResponse, sansio_types::TransportError> {
        self.fetch_with_timeout(request, Duration::from_secs(20))
    }

    fn fetch_with_timeout(
        &self,
        request: &sansio_types::HttpRequest,
        timeout: Duration,
    ) -> Result<sansio_types::HttpResponse, sansio_types::TransportError> {
        // A provider body can be close to WhippleScript's 32 MiB response
        // limit before JSON string escaping. Leave room for the escaped body
        // and the small signed-attempt envelope without silently reducing the
        // runtime's admitted response size.
        const MAX_REPLY: u64 = 70 * 1024 * 1024;
        let request_digest = organization_model_request_digest(request)
            .map_err(|_| organization_transport("provider request could not be identified"))?;
        let mut prepare_url = admitted_service_origin(&self.hub_origin)
            .map_err(|_| organization_transport("Hub origin is unavailable"))?;
        {
            let mut segments = prepare_url
                .path_segments_mut()
                .map_err(|_| organization_transport("Hub origin is unavailable"))?;
            segments.pop_if_empty();
            segments.extend([
                "projects",
                self.project.as_str(),
                "organization-model-invocations",
            ]);
        }
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(timeout)
            .build();
        let prepared = post_json_value(
            &agent,
            prepare_url.as_str(),
            &[
                ("authorization", format!("Bearer {}", self.account_session)),
                ("x-gaugewright-tenant", self.organization.clone()),
            ],
            &serde_json::json!({
                "v": 1,
                "chat": self.chat,
                "request_digest": request_digest,
            }),
            128 * 1024,
        )?;
        let prepared: OrganizationModelPrepareReply = serde_json::from_value(prepared)
            .map_err(|_| organization_transport("Hub returned an incompatible invocation"))?;
        if prepared.v != 1
            || prepared.binding != self.binding
            || prepared.ticket.is_empty()
            || prepared.ticket.len() > 16 * 1024
            || prepared.expires_at <= unix_now()
        {
            return Err(organization_transport(
                "Hub returned an invalid organization model invocation",
            ));
        }
        let fetch_url = admitted_final_fetch(&prepared.fetch_url)
            .map_err(|_| organization_transport("final fetch authority is unavailable"))?;
        let fetched = post_json_value(
            &agent,
            fetch_url.as_str(),
            &[("authorization", format!("Bearer {}", prepared.ticket))],
            &serde_json::json!({
                "url": request.url,
                "headers": request.headers,
                "body": request.body,
            }),
            MAX_REPLY,
        )?;
        let fetched: OrganizationModelFetchReply = serde_json::from_value(fetched)
            .map_err(|_| organization_transport("final fetch returned an incompatible response"))?;
        if fetched.v != 1
            || fetched.attempt != prepared.attempt
            || !(100..=599).contains(&fetched.status)
        {
            return Err(organization_transport(
                "final fetch returned a different provider attempt",
            ));
        }
        Ok(sansio_types::HttpResponse {
            status: fetched.status,
            body: fetched.body,
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
}

fn organization_transport(message: &str) -> sansio_types::TransportError {
    sansio_types::TransportError::Transport(message.to_owned())
}

fn admitted_service_origin(value: &str) -> io::Result<url::Url> {
    let mut url = url::Url::parse(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid service origin"))?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host.ends_with(".localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service origin must be TLS or loopback and contain no credentials, query, or fragment",
        ));
    }
    url.set_query(None);
    Ok(url)
}

fn admitted_final_fetch(value: &str) -> io::Result<url::Url> {
    let url = admitted_service_origin(value)?;
    if url.path() != "/v1/model-providers/private-fetch" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "organization model final fetch path is invalid",
        ));
    }
    Ok(url)
}

fn post_json_value(
    agent: &ureq::Agent,
    url: &str,
    headers: &[(&str, String)],
    body: &serde_json::Value,
    maximum: u64,
) -> Result<serde_json::Value, sansio_types::TransportError> {
    let mut outgoing = agent.post(url).set("content-type", "application/json");
    for (name, value) in headers {
        outgoing = outgoing.set(name, value);
    }
    let response = match outgoing.send_json(body) {
        Ok(response) => response,
        Err(ureq::Error::Status(_, _)) => {
            return Err(organization_transport(
                "organization model authority refused the request",
            ))
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(
                if error.to_string().to_ascii_lowercase().contains("timeout") {
                    sansio_types::TransportError::Timeout
                } else {
                    organization_transport("organization model authority is unreachable")
                },
            )
        }
    };
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| organization_transport("organization model authority response failed"))?;
    if bytes.len() as u64 > maximum {
        return Err(organization_transport(
            "organization model authority response is too large",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| organization_transport("organization model authority response is malformed"))
}

struct OrganizationModelHostDriver<'a> {
    broker: &'a OrganizationModelBrokerConfig,
    capture: Arc<Mutex<NativeModelContext>>,
}

impl whipplescript_kernel::sansio::HostDriver for OrganizationModelHostDriver<'_> {
    fn fulfill(
        &self,
        request: &whipplescript_kernel::sansio::IoRequest,
    ) -> whipplescript_kernel::sansio::IoResult {
        let whipplescript_kernel::sansio::IoRequest::Http(request) = request;
        // Only a model request has this label. Other HTTP effects use the
        // same driver but are not provider calls. Capture the provider JSON
        // before the broker adds its credential; neither the broker envelope
        // nor transport headers enter the live view.
        if let Some(provenance) = request.model_provenance.as_ref() {
            self.capture
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .observe(&request.body, Some(provenance));
        }
        whipplescript_kernel::sansio::IoResult::Http(self.broker.fetch(request))
    }
}

/// The deliberately non-secret value placed in WhippleScript's provider-auth
/// header when an operated organization broker will perform final fetch. The
/// broker accepts exactly this marker, removes it, and injects the current
/// credential only after the organization attempt has been dispatched. It is
/// not a bearer credential and grants nothing by itself.
pub const ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER: &str =
    "gaugewright-organization-model-broker-v1";

/// The one operated no-cost provider endpoint and model used to prove the
/// deployed organization credential path. These are not compatibility hooks:
/// request admission matches both exact values and rejects every other
/// non-native endpoint. The serving process independently requires the closed
/// disposable credential shape and performs no outbound request.
pub const ORGANIZATION_MODEL_CANARY_ENDPOINT: &str =
    "https://models.gaugewright.com/_canary/openai/v1";
pub const ORGANIZATION_MODEL_CANARY_MODEL: &str = "gaugewright-canary-model-v1";
pub const ORGANIZATION_MODEL_CANARY_TOKEN_BOUND: u64 = 1_024;

/// Stable identity of the exact provider request WhippleScript constructed.
/// The project Home obtains a dispatch ticket for this digest without sending
/// prompt content to the account Hub; the final-fetch authority recomputes it
/// from the request body before it can reserve or dispatch allowance.
pub fn organization_model_request_digest(
    request: &sansio_types::HttpRequest,
) -> io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};

    // The same request crosses Cargo and Buck builds. A transitive
    // `serde_json/preserve_order` feature must not change its identity.
    fn sorted_json(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(object) => {
                let mut entries = object.iter().collect::<Vec<_>>();
                entries.sort_unstable_by_key(|(key, _)| *key);
                let mut sorted = serde_json::Map::new();
                for (key, value) in entries {
                    sorted.insert(key.clone(), sorted_json(value));
                }
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(sorted_json).collect())
            }
            other => other.clone(),
        }
    }

    let body = sorted_json(&request.body);
    let bytes = serde_json::to_vec(&(
        "gaugewright:whipplescript-provider-request:v1",
        &request.url,
        &request.headers,
        &body,
    ))
    .map_err(io::Error::other)?;
    if bytes.len() > 9 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "organization model request is too large to identify",
        ));
    }
    Ok(Sha256::digest(bytes).into())
}

/// Conservative token admission for one exact WhippleScript-built provider
/// request. The context window is the smallest provider-owned ceiling that
/// covers the complete request and response without estimating tokens from
/// member-controlled text. A trusted final-fetch adapter may reserve this
/// bound; a tighter future bound must remain a WhippleScript provider fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationModelRequestAdmission {
    pub token_bound: u64,
    pub request_digest: [u8; 32],
}

/// Validate the provider-facing part of a private organization model request.
///
/// WhippleScript still owns request construction. This function checks only
/// the axes the credential/spend authority must enforce before replacing the
/// non-secret auth marker: exact native provider endpoint, selected model,
/// closed headers, bounded JSON, and the provider's conservative context
/// ceiling. It intentionally supports only the native OpenAI Responses,
/// Anthropic Messages, and fixed-host xAI Chat Completions adapters plus the
/// exact operated synthetic canary.
pub fn admit_organization_model_request(
    binding: &gaugedesk_core::model_connection::ProviderBinding,
    model: &str,
    request: &sansio_types::HttpRequest,
) -> io::Result<OrganizationModelRequestAdmission> {
    use gaugedesk_core::model_connection::AuthenticationKind;
    use whipplescript_kernel::coerce_native::CoerceProvider;

    if binding.authentication != AuthenticationKind::ApiKey || model.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "organization model request has an unsupported authentication or model",
        ));
    }
    let (provider, expected_url, auth_header, auth_value, required_header) = match (
        binding.provider.as_str(),
        binding.endpoint.trim_end_matches('/'),
    ) {
        ("openai", "https://api.openai.com/v1") => (
            CoerceProvider::OpenAi,
            "https://api.openai.com/v1/responses",
            "authorization",
            format!("Bearer {ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER}"),
            None,
        ),
        ("openai", ORGANIZATION_MODEL_CANARY_ENDPOINT)
            if model == ORGANIZATION_MODEL_CANARY_MODEL =>
        {
            (
                CoerceProvider::OpenAi,
                "https://models.gaugewright.com/_canary/openai/v1/responses",
                "authorization",
                format!("Bearer {ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER}"),
                None,
            )
        }
        ("anthropic", "https://api.anthropic.com/v1") => (
            CoerceProvider::Anthropic,
            "https://api.anthropic.com/v1/messages",
            "x-api-key",
            ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER.to_owned(),
            Some(("anthropic-version", "2023-06-01")),
        ),
        ("xai", "https://api.x.ai/v1") => (
            CoerceProvider::Xai,
            "https://api.x.ai/v1/chat/completions",
            "authorization",
            format!("Bearer {ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER}"),
            None,
        ),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "organization model request uses an unsupported provider endpoint",
            ));
        }
    };
    if request.url != expected_url
        || request
            .body
            .get("model")
            .and_then(serde_json::Value::as_str)
            != Some(model)
        || !request.body.is_object()
        || serde_json::to_vec(&request.body)
            .map_err(io::Error::other)?
            .len()
            > 8 * 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "organization model request does not match its admitted provider and model",
        ));
    }
    let mut headers = std::collections::BTreeMap::<String, String>::new();
    for (name, value) in &request.headers {
        let name = name.to_ascii_lowercase();
        if name.is_empty()
            || name.len() > 100
            || value.len() > 1024
            || name.chars().any(char::is_control)
            || value.chars().any(char::is_control)
            || headers.insert(name, value.clone()).is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "organization model request has malformed or duplicate headers",
            ));
        }
    }
    let allowed = match provider {
        CoerceProvider::OpenAi | CoerceProvider::Xai => {
            ["authorization", "content-type", "idempotency-key", "accept"].as_slice()
        }
        CoerceProvider::Anthropic => [
            "x-api-key",
            "anthropic-version",
            "content-type",
            "idempotency-key",
            "accept",
        ]
        .as_slice(),
        _ => unreachable!("closed provider match"),
    };
    if headers.keys().any(|name| !allowed.contains(&name.as_str()))
        || headers.get(auth_header) != Some(&auth_value)
        || headers.get("content-type").map(String::as_str) != Some("application/json")
        || required_header
            .is_some_and(|(name, value)| headers.get(name).map(String::as_str) != Some(value))
        || headers
            .get("accept")
            .is_some_and(|value| value != "text/event-stream")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "organization model request headers are not the admitted WhippleScript shape",
        ));
    }
    let token_bound = if binding.endpoint.trim_end_matches('/')
        == ORGANIZATION_MODEL_CANARY_ENDPOINT
        && model == ORGANIZATION_MODEL_CANARY_MODEL
    {
        ORGANIZATION_MODEL_CANARY_TOKEN_BOUND
    } else {
        whipplescript_kernel::harness_model::model_context_window(provider.into(), model)
    };
    if token_bound == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "organization model request has no enforceable token bound",
        ));
    }
    Ok(OrganizationModelRequestAdmission {
        token_bound,
        request_digest: organization_model_request_digest(request)?,
    })
}

/// Read provider usage through the same WhippleScript response parser that
/// advances the model loop. Missing, malformed, or non-success usage is not
/// converted to zero; the caller must retain the conservative reservation as
/// an unknown outcome.
pub fn organization_model_response_tokens(
    binding: &gaugedesk_core::model_connection::ProviderBinding,
    model: &str,
    response: sansio_types::HttpResponse,
) -> io::Result<u64> {
    use whipplescript_kernel::{
        coerce_native::CoerceProvider, harness_loop::HttpModelClient,
        harness_model::MessagesApiClient,
    };

    let (provider, base_url) = match (
        binding.provider.as_str(),
        binding.endpoint.trim_end_matches('/'),
    ) {
        ("openai", "https://api.openai.com/v1") => {
            (CoerceProvider::OpenAi, "https://api.openai.com")
        }
        ("openai", ORGANIZATION_MODEL_CANARY_ENDPOINT)
            if model == ORGANIZATION_MODEL_CANARY_MODEL =>
        {
            (
                CoerceProvider::OpenAi,
                "https://models.gaugewright.com/_canary/openai",
            )
        }
        ("anthropic", "https://api.anthropic.com/v1") => {
            (CoerceProvider::Anthropic, "https://api.anthropic.com")
        }
        ("xai", "https://api.x.ai/v1") => (CoerceProvider::Xai, "https://api.x.ai/v1"),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "organization model response uses an unsupported provider endpoint",
            ));
        }
    };
    let client = MessagesApiClient::new(
        provider,
        ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER,
        model,
        base_url,
        None,
        None,
    );
    let reply = client
        .parse_response(Ok(response))
        .map_err(|_| io::Error::other("WhippleScript could not admit provider usage"))?;
    let input = reply
        .usage
        .get("input_tokens")
        .or_else(|| reply.usage.get("prompt_tokens"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| io::Error::other("provider response did not report input usage"))?;
    let output = reply
        .usage
        .get("output_tokens")
        .or_else(|| reply.usage.get("completion_tokens"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| io::Error::other("provider response did not report output usage"))?;
    input
        .checked_add(output)
        .ok_or_else(|| io::Error::other("provider usage overflowed"))
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
/// The tool an Agent calls to hand the person in its chat a file (DR-0314).
/// GaugeDesk's package builder declares it under `workspace.read`.
pub const OFFER_DOWNLOAD_TOOL: &str = "offer_download";

/// The turn resource admitted when the ceiling carries [`QUESTION_ASK_CAPABILITY`].
/// `execute_tool` refuses `ask` without it, exactly as `bash` refuses without
/// `command`.
pub const QUESTION_RESOURCE: &str = "question";
pub const TARGET_MANIFEST_RESOURCE: &str = "target_manifest";
pub const TARGET_MANIFEST_SELECTOR: &str = ".gaugedesk-runtime/target-set.json";

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
/// permanent WhippleScript host protocol. GaugeDesk supplies a trusted public
/// policy root, a separate actor identity and a state directory. The factory
/// holds no private governance key. Package admission, IFC, transcript continuity,
/// tool execution, and the labeled output projection remain WhippleScript-owned.
#[derive(Clone)]
pub struct WhipHarnessFactory {
    pub(crate) authority: AuthorityId,
    policy_root: GovernanceRootVerifier,
    runtime_root: PathBuf,
    hosted: Option<DoHostConfig>,
    organization_model_broker: Option<OrganizationModelBrokerConfig>,
    native_runtime_protection: Option<BTreeMap<String, PayloadProtection>>,
}

impl WhipHarnessFactory {
    /// The product composition selects this root independently of the incoming
    /// policy. Possessing its public key grants no signing or product standing.
    pub fn new(
        authority: AuthorityId,
        policy_root: GovernanceRootVerifier,
        runtime_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            authority,
            policy_root,
            runtime_root: runtime_root.into(),
            hosted: None,
            organization_model_broker: None,
            native_runtime_protection: None,
        }
    }

    /// Select exact existing native storage. This creates no key, store or access grant.
    /// Every selected chat must already have its protected original database.
    pub fn with_existing_native_runtime_protection(
        mut self,
        chat: &str,
        protection: PayloadProtection,
    ) -> io::Result<Self> {
        if chat.trim().is_empty() || self.hosted.is_some() {
            return Err(invalid_data(
                "protected native storage requires an exact native chat",
            ));
        }
        let bindings = self
            .native_runtime_protection
            .get_or_insert_with(BTreeMap::new);
        if bindings.contains_key(chat) {
            return Err(invalid_data(
                "native runtime protection is already selected for this chat",
            ));
        }
        bindings.insert(chat.into(), protection);
        Ok(self)
    }

    fn runtime_protection(&self, chat: &str) -> io::Result<Option<PayloadProtection>> {
        match &self.native_runtime_protection {
            None => Ok(None),
            Some(bindings) if self.hosted.is_none() => {
                bindings.get(chat).cloned().map(Some).ok_or_else(|| {
                    invalid_data("native runtime has no selected original protection")
                })
            }
            Some(_) => Err(invalid_data(
                "protected native runtime cannot use hosted execution",
            )),
        }
    }

    fn existing_catalogue_store(&self, chat: &str) -> io::Result<whipplescript_store::SqliteStore> {
        let path = chat_runtime_database(&self.runtime_root, chat);
        match self.runtime_protection(chat)? {
            Some(protection) => {
                whipplescript_store::SqliteStore::open_existing_protected(path, protection)
            }
            None => whipplescript_store::SqliteStore::open(path),
        }
        .map_err(|error| invalid_data(format!("{error:?}")))
    }

    pub fn with_do_host(mut self, config: DoHostConfig) -> Self {
        self.hosted = Some(config);
        self
    }

    /// Bind the public root selected by the product's verified policy epoch.
    /// This preserves the actor and execution transport. Callers must resolve
    /// the root independently of any incoming envelope's key declaration.
    pub fn with_policy_root(mut self, root: GovernanceRootVerifier) -> Self {
        self.policy_root = root;
        self
    }

    /// Route WhippleScript-built provider requests through one exact
    /// organization final-fetch authority for this turn factory. Hosted DO
    /// placements have their own Home callback and therefore reject this
    /// native transport attachment instead of serializing an account session
    /// into the remote runtime.
    pub fn with_organization_model_broker(
        mut self,
        config: OrganizationModelBrokerConfig,
    ) -> io::Result<Self> {
        if self.hosted.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hosted organization model final fetch must be composed at the Home broker",
            ));
        }
        self.organization_model_broker = Some(config);
        Ok(self)
    }

    fn runtime_for_chat(
        &self,
        chat_id: &str,
        epoch: u64,
        signed_policy: &str,
    ) -> io::Result<GovernedHostRuntime> {
        // The original policy issuer is independent of the actor/transport
        // identity. Verify the complete pinned root before touching its store.
        self.verify_policy(epoch, signed_policy)
            .map_err(invalid_data)?;
        let path = chat_runtime_database(&self.runtime_root, chat_id);
        match self.runtime_protection(chat_id)? {
            Some(protection) => GovernedHostRuntime::open_existing_protected_with_verifier(
                path,
                epoch,
                signed_policy,
                &self.policy_root,
                protection,
            ),
            None => {
                std::fs::create_dir_all(&self.runtime_root)?;
                GovernedHostRuntime::open_with_verifier(
                    path,
                    epoch,
                    signed_policy,
                    &self.policy_root,
                )
            }
        }
        .map_err(invalid_data)
    }

    /// Verify original policy meaning under this factory's independently
    /// selected public root. This grants no execution or current membership.
    pub fn verify_policy(
        &self,
        epoch: u64,
        signed_policy: &str,
    ) -> Result<AdmittedPolicyEpoch, PolicyAdmissionError> {
        AdmittedPolicyEpoch::verify_with(PolicyEpoch::new(epoch)?, signed_policy, &self.policy_root)
    }

    fn refresh_agent_skill_catalogue(&self, chat_id: &str, worktree: &Path) -> io::Result<()> {
        let store = self.existing_catalogue_store(chat_id)?;
        store
            .remove_unattached_skills_from_source("gaugedesk-agent")
            .map_err(|error| invalid_data(format!("{error:?}")))?;
        let root = worktree.join(".gaugedesk-runtime/agent/skills");
        if !root.exists() {
            return Ok(());
        }
        let mut entries = std::fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if !entry.file_type()?.is_dir() {
                return Err(invalid_data("an Agent skill is not a directory"));
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let source_path = format!(".gaugedesk-runtime/agent/skills/{name}/SKILL.md");
            let body = std::fs::read_to_string(worktree.join(&source_path))?;
            let frontmatter =
                whipplescript_store::skill_frontmatter::parse_skill_frontmatter(&body)
                    .map_err(invalid_data)?;
            if frontmatter.name != name {
                return Err(invalid_data(format!(
                    "Agent skill `{}` differs from its directory `{name}`",
                    frontmatter.name
                )));
            }
            let version = frontmatter
                .metadata
                .get("version")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("0.0.0");
            let metadata = serde_json::to_string(&frontmatter.metadata).map_err(invalid_data)?;
            store
                .register_skill(whipplescript_store::SkillRegistration {
                    skill_id: &format!("skill:{name}"),
                    name: &name,
                    version,
                    source: "gaugedesk-agent",
                    source_path: &source_path,
                    body: &body,
                    description: &frontmatter.description,
                    required_capabilities_json: "[]",
                    metadata_json: &metadata,
                })
                .map_err(|error| invalid_data(format!("{error:?}")))?;
        }
        Ok(())
    }

    /// An edit chat's catalogue holds exactly WhippleScript's authoring skill,
    /// mounted from the vendored copy. Nothing the Agent being edited declares
    /// is registered here: its skills are files the editor edits, not
    /// instructions the editor follows.
    fn refresh_editor_skill_catalogue(&self, chat_id: &str, worktree: &Path) -> io::Result<()> {
        let store = self.existing_catalogue_store(chat_id)?;
        editor_skill::mount(worktree)?;
        store
            .remove_unattached_skills_from_source(editor_skill::EDITOR_SKILL_SOURCE)
            .map_err(|error| invalid_data(format!("{error:?}")))?;
        let body = editor_skill::skill_body();
        let frontmatter = whipplescript_store::skill_frontmatter::parse_skill_frontmatter(body)
            .map_err(invalid_data)?;
        let version = frontmatter
            .metadata
            .get("version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("0.0.0");
        let metadata = serde_json::to_string(&frontmatter.metadata).map_err(invalid_data)?;
        store
            .register_skill(whipplescript_store::SkillRegistration {
                skill_id: &format!("skill:{}", frontmatter.name),
                name: &frontmatter.name,
                version,
                source: editor_skill::EDITOR_SKILL_SOURCE,
                source_path: &editor_skill::skill_location(),
                body,
                description: &frontmatter.description,
                required_capabilities_json: "[]",
                metadata_json: &metadata,
            })
            .map_err(|error| invalid_data(format!("{error:?}")))?;
        Ok(())
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

    /// Carry a chat's conversation into the package and policy it runs under now.
    ///
    /// A chat's thread lives on the instance its turns ran on. That instance
    /// is found by request ids that name the package and the policy epoch, so
    /// when either changes — an edit chat's persona, a placement's Agent
    /// version, a model switch, a tracker gained — they name a new instance.
    /// Seeding it from the legacy source, which never ran a turn, left the
    /// model with none of the chat's history while the transcript still
    /// showed it (WS-631, WS-660).
    ///
    /// So the chat's most recently active instance decides. On this package
    /// and policy it is reused. Otherwise its thread is adopted into the
    /// instance this package and policy open to, which does not ask for the
    /// older package to be reproducible. A thread recorded under an earlier
    /// epoch is read through a runtime opened under that epoch, so
    /// WhippleScript can re-admit what it read under the current one
    /// (WhippleScript DR-0293). A thread whose last turn never settled is
    /// carried up to the turn before it, and the chat says so.
    ///
    /// `Fresh` is a new chat, or one whose newest instance is the legacy
    /// source. A thread that exists and cannot be carried is an error that
    /// names why: the chat says so rather than starting again beneath a
    /// transcript that shows earlier turns (DR-0412).
    fn continue_recorded_thread(
        &self,
        spec: &HarnessSpec,
        runtime: &mut GovernedHostRuntime,
        source_runtime: &GovernedHostRuntime,
        open: &OpenInstanceCommand,
        packages: &StaticPackages,
    ) -> io::Result<Continuation> {
        let Some(recorded) = source_runtime
            .newest_recorded_instance()
            .map_err(invalid_data)?
        else {
            return Ok(Continuation::Fresh);
        };
        if recorded.package_version_ref == open.package_version_ref
            && recorded.policy == open.policy
        {
            let opened = runtime
                .open_instance(open, packages)
                .map_err(invalid_data)?;
            return Ok(if opened.instance_ref == recorded.instance_ref {
                Continuation::Carried {
                    instance: Box::new(opened),
                    cut: None,
                }
            } else {
                Continuation::Fresh
            });
        }
        if recorded.package_version_ref == packages.previous.version_ref {
            return Ok(Continuation::Fresh);
        }
        let earlier;
        let source = if &recorded.policy == source_runtime.policy_ref() {
            source_runtime
        } else {
            let (epoch, envelope) = spec
                .prior_policy_envelopes
                .iter()
                .find(|(epoch, _)| *epoch == recorded.policy.epoch)
                .ok_or_else(|| {
                    not_carried("the settings it was recorded under are no longer on record")
                })?;
            earlier = self
                .runtime_for_chat(&spec.chat_id, *epoch, envelope)
                .map_err(|error| not_carried(&error.to_string()))?;
            &earlier
        };
        let position = source
            .current_position(&recorded.instance_ref)
            .map_err(invalid_data)?;
        let adopt = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: format!(
                "gaugedesk:package-adopt:{}:{}:policy:{}:{}",
                recorded.instance_ref,
                open.package_version_ref,
                open.policy.epoch,
                open.policy.envelope_hash
            ),
            source: position,
            target_request_id: open.request_id.clone(),
            package_version_ref: open.package_version_ref.clone(),
            policy: open.policy.clone(),
        };
        let adopted = runtime
            .adopt_instance_from(source, &adopt, packages)
            .map_err(|error| not_carried(&error.to_string()))?;
        Ok(Continuation::Carried {
            instance: Box::new(adopted.target),
            cut: adopted.cut,
        })
    }

    fn open_request(
        chat_id: &str,
        package_version_ref: &str,
        policy: PolicyEpochRef,
    ) -> OpenInstanceCommand {
        OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            // A replayed open must name the same immutable policy. A later turn
            // can gain a tracker or change authority, which advances the epoch.
            request_id: format!(
                "gaugedesk:{chat_id}:{package_version_ref}:policy:{}:{}",
                policy.epoch, policy.envelope_hash
            ),
            package_version_ref: package_version_ref.to_owned(),
            policy,
        }
    }

    /// An office-bound turn reaches only its own pinned endpoint, so a hosted
    /// runtime (whose model calls leave this machine) and the organization
    /// model broker (a GaugeWright-routed shared-key path) both refuse it.
    fn refuse_office_routes(&self, spec: &HarnessSpec) -> io::Result<()> {
        if spec.office_inference.is_none() {
            return Ok(());
        }
        if self.hosted.is_some() {
            return Err(office_refusal("a hosted runtime is not office-operated"));
        }
        if self.organization_model_broker.is_some() {
            return Err(office_refusal(
                "the organization model broker is not office-operated",
            ));
        }
        Ok(())
    }

    fn create_harness(&self, spec: &HarnessSpec) -> io::Result<WhipHarness> {
        self.refuse_office_routes(spec)?;
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
        match spec.mode {
            gaugedesk_harness::ChatMode::Use => {
                self.refresh_agent_skill_catalogue(&spec.chat_id, &spec.worktree)?
            }
            gaugedesk_harness::ChatMode::Edit => {
                self.refresh_editor_skill_catalogue(&spec.chat_id, &spec.worktree)?
            }
        }
        let mut source_runtime = self.runtime_for_chat(&spec.chat_id, epoch, signed_policy)?;
        let open = Self::open_request(
            &spec.chat_id,
            package.version_ref(),
            runtime.policy_ref().clone(),
        );
        let continued =
            self.continue_recorded_thread(spec, &mut runtime, &source_runtime, &open, &packages)?;
        let (instance, cut) = match continued {
            Continuation::Carried { instance, cut } => (*instance, cut),
            Continuation::Fresh => {
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
                let upgrade = ForkInstanceCommand {
                    protocol: HOST_PROTOCOL.to_owned(),
                    request_id: format!(
                        "gaugedesk:package-upgrade:{}:{}:{}:policy:{}:{}",
                        spec.chat_id,
                        packages.previous.version_ref,
                        package.version_ref(),
                        open.policy.epoch,
                        open.policy.envelope_hash
                    ),
                    source: source_position,
                    target_request_id: open.request_id.clone(),
                    package_version_ref: package.version_ref().to_owned(),
                    policy: open.policy.clone(),
                };
                let instance = runtime
                    .fork_instance_from(&source_runtime, &upgrade, &packages)
                    .map(|fork| fork.target)
                    .map_err(invalid_data)?;
                (instance, None)
            }
        };

        validate_workspace_targets(&spec.workspace_targets).map_err(invalid_data)?;
        let sandbox_read_only = spec
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
        let target_renamer: TargetRenamerSlot = Arc::new(Mutex::new(None));
        let workspace = workspace_resolver(
            &spec.worktree,
            &sandbox_read_only,
            &spec.workspace_targets,
            &target_renamer,
        )?;

        Ok(WhipHarness {
            runtime,
            instance_ref: instance.instance_ref,
            policy: open.policy,
            package,
            provider,
            workspace,
            chat_id: spec.chat_id.clone(),
            mode: spec.mode,
            provider_binding_ref: spec.provider_binding_ref.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "provider binding ref is required",
                )
            })?,
            credential_ref: spec.credential_ref.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "credential ref is required")
            })?,
            workspace_targets: spec.workspace_targets.clone(),
            placement_ceiling_ref: spec.placement_ceiling_ref.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "placement ceiling ref is required",
                )
            })?,
            respondent_ref: self.authority.as_str().to_owned(),
            user_context_sources: Some(Vec::new()),
            turn_sequence: 0,
            next_command_id: None,
            prepared_runtime: None,
            task_filer: None,
            target_renamer,
            worktree: spec.worktree.clone(),
            sandbox_read_only,
            external_tool_handler: None,
            turn_access: None,
            payload_retention: None,
            cancellation: Arc::new(Mutex::new(None)),
            cancel_requested: Arc::new(AtomicBool::new(false)),
            pursuing_cancel: Arc::new(AtomicBool::new(false)),
            organization_model_broker: self.organization_model_broker.clone(),
            native_model_context: Arc::new(Mutex::new(NativeModelContext::default())),
            managed_call_meter: None,
            continuity_notice: cut.as_ref().map(unresolved_turn_notice),
        })
    }
}

/// How a chat's recorded conversation continues into the run being opened.
enum Continuation {
    /// The thread runs on this instance. `cut` is set when it was carried
    /// only up to the turn before one whose effect never settled.
    Carried {
        instance: Box<OpenedInstance>,
        cut: Option<AdoptionCut>,
    },
    /// Nothing to carry: a new chat, or one whose newest instance is the
    /// legacy source the package-upgrade fork seeds from.
    Fresh,
}

/// A chat whose thread exists and cannot be carried says why (DR-0412).
fn not_carried(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "this chat's earlier conversation could not be carried into its current settings \
             ({reason}); start a new chat to continue"
        ),
    )
}

/// What the chat shows when its conversation was cut before a turn whose
/// outcome is unknown (DR-0412 §3). Turns are serial, so what never settled
/// is the chat's previous turn.
fn unresolved_turn_notice(_cut: &AdoptionCut) -> String {
    "The previous turn did not finish, so what it did is unknown. The conversation \
     continues from before it, and the assistant has not seen that turn."
        .to_owned()
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
        self.runtime_protection(&spec.chat_id)?;
        self.refuse_office_routes(spec)?;
        if let Some(config) = &self.hosted {
            return hosted::create_harness(self, config, spec);
        }
        self.create_harness(spec)
            .map(|harness| Box::new(harness) as Box<dyn Harness>)
    }

    fn recorded_policy_epoch(&self, preparation: &RuntimeTurnPreparation) -> io::Result<u64> {
        let command: StartTurnCommand =
            serde_json::from_str(&preparation.command_json).map_err(invalid_data)?;
        command.validate().map_err(invalid_data)?;
        Ok(command.policy.epoch)
    }

    fn observe_recorded_runtime(
        &self,
        spec: &gaugedesk_harness::RecordedRuntimeSpec<'_>,
    ) -> io::Result<TurnOutcome> {
        if self.hosted.is_some() {
            return Err(invalid_data(
                "original runtime observation requires a native Home",
            ));
        }
        RecordedResources {
            access: &|| spec.access.check_current(),
        }
        .check_live_access()
        .map_err(invalid_data)?;
        // Pending product recovery still proves the exact submitted inputs.
        let command: StartTurnCommand =
            serde_json::from_str(&spec.preparation.command_json).map_err(invalid_data)?;
        command.validate().map_err(invalid_data)?;
        if spec.preparation.input_digest
            != gaugedesk_harness::runtime_input_digest(&command.input.text, spec.images)
        {
            return Err(invalid_data("original runtime preparation changed"));
        }
        self.observe_completed_product_runtime(&gaugedesk_harness::CompletedProductRuntimeSpec {
            chat_id: spec.chat_id,
            command_id: spec.command_id,
            policy_epoch: spec.policy_epoch,
            signed_policy_envelope: spec.signed_policy_envelope,
            preparation: spec.preparation,
            access: &|| spec.access.check_current(),
        })
    }

    fn observe_completed_product_runtime(
        &self,
        spec: &gaugedesk_harness::CompletedProductRuntimeSpec<'_>,
    ) -> io::Result<TurnOutcome> {
        if self.hosted.is_some() {
            return Err(invalid_data(
                "original runtime observation requires a native Home",
            ));
        }
        let access = RecordedResources {
            access: spec.access,
        };
        access.check_live_access().map_err(invalid_data)?;
        let command: StartTurnCommand =
            serde_json::from_str(&spec.preparation.command_json).map_err(invalid_data)?;
        command.validate().map_err(invalid_data)?;
        if command.command_id != spec.command_id
            || command.policy.epoch != spec.policy_epoch
            || command.instance_ref != spec.preparation.start_position.instance_ref
            || spec.preparation.input_digest.is_empty()
        {
            return Err(invalid_data("original runtime preparation changed"));
        }
        let path = chat_runtime_database(&self.runtime_root, spec.chat_id);
        let runtime = match self.runtime_protection(spec.chat_id)? {
            Some(protection) => whipplescript::host_runtime::RecordedHostRuntime::open_existing_protected_with_verifier(
                path,
                spec.policy_epoch,
                spec.signed_policy_envelope,
                &self.policy_root,
                &access,
                protection,
            ),
            None => whipplescript::host_runtime::RecordedHostRuntime::open_with_verifier(
                path,
                spec.policy_epoch,
                spec.signed_policy_envelope,
                &self.policy_root,
                &access,
            ),
        }
        .map_err(turn_failure)?;
        let start = whipplescript::host_protocol::PinnedPosition {
            instance_ref: spec.preparation.start_position.instance_ref.clone(),
            sequence: spec.preparation.start_position.sequence,
            head_digest: spec.preparation.start_head_digest.clone(),
        };
        let execution = runtime
            .recorded_turn_execution(&command, &start, &access)
            .map_err(turn_failure)?
            .ok_or_else(|| invalid_data("original saved runtime execution unavailable"))?;
        let recorded = runtime
            .turn_workspace_witness(&command, &start, &access)
            .map_err(turn_failure)?
            .ok_or_else(|| invalid_data("original saved runtime workspace witness unavailable"))?;
        if execution.receipt.as_ref() != Some(&recorded.receipt) {
            return Err(invalid_data("original runtime workspace receipt changed"));
        }
        let report = runtime
            .turn_guarantee_report(&command, &start, &access)
            .map_err(turn_failure)?
            .ok_or_else(|| invalid_data("original saved runtime guarantee report unavailable"))?;
        let context_tokens = execution
            .usage
            .as_ref()
            .map(|usage| usage.last_input_tokens)
            .filter(|tokens| *tokens > 0);
        let original_envelope = VerifiedEnvelope::verify_signed_text_with(
            spec.signed_policy_envelope,
            &self.policy_root,
        )
        .map_err(invalid_data)?;
        let binding = original_envelope
            .resolve_provider_binding(
                &command.provider_binding.binding_id,
                &command.provider_binding.credential.credential_id,
                &command.placement_ceiling_ref,
            )
            .ok_or_else(|| invalid_data("original runtime provider binding unavailable"))?;
        let context_reading = context_tokens.map(|last_input_tokens| ContextWindowReading {
            provider: binding.provider.clone(),
            model: binding.model.clone(),
            last_input_tokens,
        });
        let pointers = execution.evidence_pointers();
        let mut outcome =
            project_turn_execution(execution, pointers, &command, &mut |_| {}, false)?;
        outcome.context_reading = context_reading;
        outcome.runtime_start_position = Some(spec.preparation.start_position.clone());
        outcome.runtime_workspace_witness = Some(gaugedesk_harness::RuntimeWorkspaceWitness {
            receipt_json: serde_json::to_string(&recorded.receipt).map_err(invalid_data)?,
            writes: recorded
                .writes
                .into_iter()
                .map(|write| gaugedesk_harness::WorkspaceWriteWitness {
                    path: write.path,
                    kind: write.kind,
                    content_hash: write.content_hash,
                    bytes: write.bytes,
                })
                .collect(),
            reads: recorded.reads,
        });
        outcome.guarantee_outcomes = gaugedesk_harness::GuaranteeOutcome::from_report(&report);
        access.check_live_access().map_err(invalid_data)?;
        Ok(outcome)
    }

    fn reuse_across_turns(&self) -> bool {
        // The final-fetch path binds current actor session, organization,
        // project selection and broker admission. Reopen the persistent
        // runtime for each turn so none of those ephemeral inputs becomes a
        // cached authorization fact; the SQLite WhippleScript instance still
        // supplies transcript continuity.
        if self.organization_model_broker.is_some() || self.native_runtime_protection.is_some() {
            return false;
        }
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
        self.runtime_protection(&source.chat_id)?;
        self.runtime_protection(&target.chat_id)?;
        if let Some(config) = &self.hosted {
            return hosted::clone_continuity(self, config, source, target);
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

    fn discard_continuity(&self, target: &HarnessContinuitySpec) -> io::Result<()> {
        if let Some(config) = &self.hosted {
            return hosted::discard_continuity(self, config, target);
        }
        let database = self
            .runtime_root
            .join(format!("{}.sqlite", hex::encode(target.chat_id.as_bytes())));
        for path in [
            database.clone(),
            database.with_extension("sqlite-wal"),
            database.with_extension("sqlite-shm"),
        ] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
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
            _ if provider == "xai-grok" => CredentialProbe::Missing(
                "No GaugeDesk-owned Grok subscription is linked. Open Model access and connect xAI Grok."
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
    mode: gaugedesk_harness::ChatMode,
    provider_binding_ref: String,
    credential_ref: String,
    workspace_targets: Vec<gaugedesk_harness::WorkspaceTargetBinding>,
    placement_ceiling_ref: String,
    respondent_ref: String,
    user_context_sources: Option<Vec<String>>,
    turn_sequence: u64,
    next_command_id: Option<String>,
    prepared_runtime: Option<RuntimeTurnPreparation>,
    task_filer: Option<Arc<dyn TaskFiler>>,
    /// The Home's recorder of target-folder renames for the running turn
    /// (DR-0248). Shared with the workspace resolver's rename admission,
    /// which outlives any one turn's binding.
    target_renamer: TargetRenamerSlot,
    /// What the workspace resolver is rebuilt from when a turn's targets
    /// differ from the last turn's.
    worktree: PathBuf,
    sandbox_read_only: Vec<PathBuf>,
    external_tool_handler: Option<gaugedesk_harness::ExternalToolHandler>,
    turn_access: Option<Arc<dyn gaugedesk_harness::TurnAccess>>,
    payload_retention: Option<Arc<dyn gaugedesk_harness::WorkspacePayloadRetention>>,
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
    organization_model_broker: Option<OrganizationModelBrokerConfig>,
    native_model_context: Arc<Mutex<NativeModelContext>>,
    managed_call_meter: Option<Arc<dyn gaugedesk_harness::ManagedCallMeter>>,
    /// What the chat must show before this harness's first turn: that its
    /// conversation was carried past a turn whose outcome is unknown.
    continuity_notice: Option<String>,
}

const NATIVE_MODEL_CONTEXT_LIMIT: usize = 8 * 1024 * 1024;

/// Identity of one image still held by this chat's live, submitted turn. The
/// source handle carries no bytes and grants nothing on its own; the viewer
/// must find it in the current turn and recheck the chat's reader.
pub fn live_turn_image_source(chat_id: &str, image: &ImageContent) -> Option<String> {
    use sha2::{Digest, Sha256};

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&image.data)
        .ok()?;
    let mut digest = Sha256::new();
    digest.update(b"gaugedesk:live-turn-image:v1");
    digest.update((image.mime_type.len() as u64).to_be_bytes());
    digest.update(image.mime_type.as_bytes());
    digest.update(bytes);
    Some(format!(
        "turn-image:{chat_id}:{}",
        hex::encode(digest.finalize())
    ))
}

#[derive(Default)]
struct NativeModelContext {
    active: bool,
    calls: Vec<serde_json::Value>,
    bytes: usize,
    incomplete: bool,
}

impl NativeModelContext {
    fn observe(&mut self, body: &serde_json::Value, provenance: Option<&ModelRequestProvenance>) {
        if !self.active || self.incomplete {
            return;
        }
        let Ok(size) = serde_json::to_vec(body).map(|bytes| bytes.len()) else {
            self.incomplete = true;
            return;
        };
        if self.bytes.saturating_add(size) > NATIVE_MODEL_CONTEXT_LIMIT {
            self.incomplete = true;
            return;
        }
        self.bytes += size;
        let complete = provenance.is_some_and(|labels| {
            labels.messages.iter().all(|label| label.complete) && labels.tools.complete
        });
        self.calls.push(serde_json::json!({
            "ordinal": self.calls.len(),
            "body": body,
            "ordered_provenance": provenance,
            "provenance_complete": complete
        }));
    }
}

struct ActiveNativeModelContext(Arc<Mutex<NativeModelContext>>);

impl Drop for ActiveNativeModelContext {
    fn drop(&mut self) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = NativeModelContext::default();
    }
}

#[cfg(test)]
mod native_model_context_tests {
    use super::{ActiveNativeModelContext, NativeModelContext};
    use std::sync::{Arc, Mutex};
    use whipplescript_kernel::sansio::{ModelContentProvenance, ModelRequestProvenance};

    #[test]
    fn ordered_bodies_disappear_when_the_turn_ends() {
        let state = Arc::new(Mutex::new(NativeModelContext {
            active: true,
            ..NativeModelContext::default()
        }));
        {
            let _turn = ActiveNativeModelContext(Arc::clone(&state));
            let mut capture = state.lock().unwrap();
            capture.observe(&serde_json::json!({"messages": ["first"]}), None);
            let labels = ModelRequestProvenance {
                messages: vec![ModelContentProvenance {
                    source_handles: vec!["chat:one".to_owned()],
                    complete: true,
                }],
                tools: ModelContentProvenance {
                    source_handles: vec!["runtime".to_owned()],
                    complete: true,
                },
                wire: None,
            };
            capture.observe(
                &serde_json::json!({"messages": ["first", "tool result"]}),
                Some(&labels),
            );
            assert_eq!(capture.calls[0]["ordinal"], 0);
            assert_eq!(capture.calls[1]["ordinal"], 1);
            assert_eq!(capture.calls[1]["body"]["messages"][1], "tool result");
            assert_eq!(capture.calls[0]["provenance_complete"], false);
            assert_eq!(capture.calls[1]["provenance_complete"], true);
            assert_eq!(
                capture.calls[1]["ordered_provenance"]["messages"][0]["source_handles"][0],
                "chat:one"
            );
        }
        let capture = state.lock().unwrap();
        assert!(!capture.active);
        assert!(capture.calls.is_empty());
    }
}

impl Harness for WhipHarness {
    fn take_continuity_notice(&mut self) -> Option<String> {
        self.continuity_notice.take()
    }

    fn bind_authenticated_actor(&mut self, actor_ref: &str) {
        if !actor_ref.trim().is_empty() {
            self.respondent_ref = actor_ref.to_owned();
        }
    }

    fn bind_runtime_command_id(&mut self, command_id: Option<&str>) {
        self.next_command_id = command_id.map(str::to_owned);
    }

    fn prepare_runtime_turn(
        &mut self,
        prompt: &str,
        images: &[ImageContent],
    ) -> io::Result<RuntimeTurnPreparation> {
        let access = CurrentTurnAccess {
            inner: self.turn_access.clone(),
            ended: AtomicBool::new(false),
        };
        access.current()?;
        let command_id = self.next_command_id.clone().ok_or_else(|| {
            invalid_data("runtime preparation requires the original admitted command")
        })?;
        let command = self.new_turn_command(prompt, images, 0, Some(command_id));
        command.validate().map_err(invalid_data)?;
        let command_json = serde_json::to_string(&command).map_err(invalid_data)?;
        let prepared = if let Some(original) = &self.prepared_runtime {
            if original.command_json != command_json
                || original.workspace_targets != self.workspace_targets
                || original.input_digest != gaugedesk_harness::runtime_input_digest(prompt, images)
            {
                return Err(invalid_data("prepared runtime intent changed"));
            }
            original.clone()
        } else {
            let start = self
                .runtime
                .pinned_position(&self.instance_ref)
                .map_err(invalid_data)?;
            RuntimeTurnPreparation {
                input_digest: gaugedesk_harness::runtime_input_digest(prompt, images),
                command_json,
                start_position: RuntimePosition {
                    instance_ref: start.instance_ref,
                    sequence: start.sequence,
                },
                start_head_digest: start.head_digest,
                workspace_targets: self.workspace_targets.clone(),
            }
        };
        access.current()?;
        self.prepared_runtime = Some(prepared.clone());
        Ok(prepared)
    }

    fn bind_user_context_provenance(&mut self, sources: Option<&[String]>) {
        self.user_context_sources = sources.map(|handles| handles.to_vec());
    }

    fn bind_task_filer(&mut self, filer: Option<Arc<dyn TaskFiler>>) {
        self.task_filer = filer;
    }
    fn bind_workspace_targets(
        &mut self,
        targets: Vec<gaugedesk_harness::WorkspaceTargetBinding>,
    ) -> io::Result<()> {
        if targets == self.workspace_targets {
            return Ok(());
        }
        validate_workspace_targets(&targets).map_err(invalid_data)?;
        // A fresh resolver drops renames it admitted in an earlier turn: the
        // new bindings already carry the names the Home recorded (DR-0248),
        // and a later rename back must not be overridden by an old one.
        self.workspace = workspace_resolver(
            &self.worktree,
            &self.sandbox_read_only,
            &targets,
            &self.target_renamer,
        )?;
        self.workspace_targets = targets;
        Ok(())
    }
    fn bind_target_renamer(&mut self, renamer: Option<Arc<dyn TargetRenamer>>) {
        *self
            .target_renamer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = renamer;
    }
    fn bind_external_tool_handler(
        &mut self,
        handler: Option<gaugedesk_harness::ExternalToolHandler>,
    ) {
        self.external_tool_handler = handler;
    }

    fn bind_turn_access(
        &mut self,
        access: Option<Arc<dyn gaugedesk_harness::TurnAccess>>,
    ) -> io::Result<()> {
        self.turn_access = access;
        Ok(())
    }

    fn bind_workspace_payload_retention(
        &mut self,
        retention: Option<Arc<dyn gaugedesk_harness::WorkspacePayloadRetention>>,
    ) -> io::Result<()> {
        self.payload_retention = retention;
        Ok(())
    }

    fn bind_managed_call_meter(
        &mut self,
        meter: Option<Arc<dyn gaugedesk_harness::ManagedCallMeter>>,
    ) -> io::Result<()> {
        // The organization broker performs its own final fetch, outside the
        // native send this meter wraps; a meter there would hold nothing.
        if meter.is_some() && self.organization_model_broker.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "an organization-brokered turn cannot be credit funded",
            ));
        }
        self.managed_call_meter = meter;
        Ok(())
    }

    fn run_turn(
        &mut self,
        _legacy_gate: &dyn EgressGate,
        prompt: &str,
        images: &[ImageContent],
        sink: &mut dyn FnMut(&Observation),
    ) -> io::Result<TurnOutcome> {
        // Consume once: a reused harness cannot borrow this person's check for
        // another submission. The runtime latches refusal for this invocation.
        let turn_access = CurrentTurnAccess {
            inner: self.turn_access.take(),
            ended: AtomicBool::new(false),
        };
        let retention = self.payload_retention.take();
        let managed_call_meter = self.managed_call_meter.take();
        turn_access.current()?;
        if turn_access.inner.is_some() && retention.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "office workspace payload retention unavailable",
            ));
        }
        // Callback custody is limited to this invocation. Target rebinding and
        // harness reuse cannot retain a prior person's callback or witness.
        let retained_workspace = self.workspace_with_retention(retention)?;
        let mut guarded_sink = |observation: &Observation| {
            turn_access.observe(observation, sink);
        };
        self.turn_sequence += 1;
        let admitted_command_id = self.next_command_id.take();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let command = self.new_turn_command(prompt, images, nonce, admitted_command_id);
        let runtime_start_position = if let Some(prepared) = self.prepared_runtime.take() {
            let original: StartTurnCommand =
                serde_json::from_str(&prepared.command_json).map_err(invalid_data)?;
            if original != command
                || prepared.workspace_targets != self.workspace_targets
                || prepared.input_digest != gaugedesk_harness::runtime_input_digest(prompt, images)
            {
                return Err(invalid_data("prepared runtime intent changed"));
            }
            EventPosition {
                instance_ref: prepared.start_position.instance_ref,
                sequence: prepared.start_position.sequence,
            }
        } else {
            self.runtime
                .current_position(&self.instance_ref)
                .map_err(invalid_data)?
        };
        let resources = TurnResources {
            workspace: retained_workspace.as_ref().unwrap_or(&self.workspace),
            workspace_resources: &command.resources,
            chat_id: &self.chat_id,
            mode: self.mode,
            images,
            task_filer: self.task_filer.as_deref(),
            external_tool_handler: self.external_tool_handler.as_ref(),
            access: Some(&turn_access),
            command_id: command.command_id.clone(),
            live: std::cell::RefCell::new(&mut guarded_sink),
            streamed: std::cell::Cell::new(false),
            office_request_url: self.provider.office_request_url.clone(),
            managed_call_meter: managed_call_meter.as_deref(),
        };
        // ADR 0111: a question settles the turn. There is no suspended epoch to
        // resume into, because WhippleScript 0.2.2 removed the host-facing
        // suspension contract — a parked turn now surfaces as
        // `HostRuntimeError::Incomplete` rather than a resumable state. Every
        // turn is an ordinary turn; an agent that needs a person files a task
        // and the answer arrives as the next turn's context.
        self.install_cancellation(&command);
        let _native_context_guard = {
            let mut state = self
                .native_model_context
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *state = NativeModelContext {
                active: true,
                ..NativeModelContext::default()
            };
            ActiveNativeModelContext(Arc::clone(&self.native_model_context))
        };
        let package = ProjectTaskPackage {
            inner: &self.package,
            task_filing_admitted: self.task_filer.is_some(),
            recipients: self
                .task_filer
                .as_ref()
                .map_or_else(Vec::new, |filer| filer.assignable_recipients()),
        };
        let model_provenance = self.initial_model_provenance(&command, images);
        let execution = match &self.organization_model_broker {
            Some(broker) => self.runtime.run_turn_with_driver_and_provenance(
                &command,
                &package,
                &self.provider,
                &resources,
                &OrganizationModelHostDriver {
                    broker,
                    capture: Arc::clone(&self.native_model_context),
                },
                &model_provenance,
            ),
            None => {
                let capture = Arc::clone(&self.native_model_context);
                self.runtime
                    .run_turn_observing_model_requests_with_provenance(
                        &command,
                        &package,
                        &self.provider,
                        &resources,
                        &model_provenance,
                        &move |body, provenance| {
                            capture
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .observe(body, provenance);
                        },
                    )
            }
        }
        .map_err(turn_failure);
        self.clear_cancellation();
        let execution = execution?;
        turn_access.current()?;
        let evidence_pointers = execution.evidence_pointers();
        let workspace_witness = original_workspace_witness(
            &self.runtime,
            &command,
            &resources,
            execution.receipt.as_ref(),
        )?;
        // The runtime's settled context reading (its own compaction-trigger
        // number), taken before the execution moves into the projection. The
        // provider/model ride along so the reading is measured against the
        // window of the model that actually produced it.
        let context_tokens = execution
            .usage
            .as_ref()
            .map(|usage| usage.last_input_tokens)
            .filter(|tokens| *tokens > 0);
        // A credit-funded turn settles from the runtime's own meter: every
        // model call it made, summed. Only a metered turn publishes it, so a
        // personal-key turn is never mistaken for one to bill.
        let metered_usage = managed_call_meter
            .as_ref()
            .and(execution.usage.as_ref())
            .map(|usage| gaugedesk_harness::ModelUsage {
                usage_ref: usage.usage_ref.clone(),
                provider: provider_wire_name(self.provider.provider).to_owned(),
                model: self.provider.model.clone(),
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
            });
        let streamed = resources.streamed.get();
        let sink = resources.live.into_inner();
        let mut outcome =
            project_turn_execution(execution, evidence_pointers, &command, sink, !streamed)?;
        outcome.runtime_workspace_witness = workspace_witness;
        if metered_usage.is_some() {
            outcome.managed_usage = metered_usage;
        }
        if outcome.error.is_some() {
            if let Some(reason) = self
                .runtime
                .turn_failure_summary(&command)
                .map_err(invalid_data)?
            {
                outcome.error = Some(reason);
            }
        }
        outcome.context_reading = context_tokens.map(|last_input_tokens| ContextWindowReading {
            provider: provider_wire_name(self.provider.provider).to_owned(),
            model: self.provider.model.clone(),
            last_input_tokens,
        });
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
        turn_access.current()?;
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

    fn model_context_handle(&self) -> Option<ModelContextHandle> {
        let capture = Arc::clone(&self.native_model_context);
        Some(Arc::new(move || {
            let state = capture
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !state.active {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no live model context",
                ));
            }
            serde_json::to_string(&serde_json::json!({
                "calls": state.calls,
                "incomplete": state.incomplete
            }))
            .map_err(io::Error::other)
        }))
    }
}

fn registered_agent_skill_sources(
    skills: &[whipplescript_store::SkillView],
    chat_id: &str,
    mode: gaugedesk_harness::ChatMode,
) -> Option<Vec<String>> {
    if mode == gaugedesk_harness::ChatMode::Edit {
        // The editor's one skill is GaugeDesk-shipped runtime material, like
        // its persona, and only the exact vendored bytes count as that.
        let shipped = whipplescript_store::stable_hash_hex(editor_skill::skill_body());
        return skills
            .iter()
            .all(|skill| {
                skill.source == editor_skill::EDITOR_SKILL_SOURCE
                    && skill.source_path == editor_skill::skill_location()
                    && skill.content_hash == shipped
            })
            .then(|| vec!["runtime".to_owned(); skills.len().min(1)]);
    }
    let mut sources = Vec::with_capacity(skills.len());
    for skill in skills {
        let expected_path = format!(".gaugedesk-runtime/agent/skills/{}/SKILL.md", skill.name);
        if mode != gaugedesk_harness::ChatMode::Use
            || skill.source != "gaugedesk-agent"
            || skill.name.is_empty()
            || !skill
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            || skill.source_path != expected_path
            || skill.content_hash.len() != 32
            || !skill
                .content_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        sources.push(format!(
            "discipline-skill:{chat_id}:{}:{}",
            skill.content_hash, skill.name
        ));
    }
    Some(sources)
}

impl WhipHarness {
    fn workspace_with_retention(
        &self,
        retention: Option<Arc<dyn gaugedesk_harness::WorkspacePayloadRetention>>,
    ) -> io::Result<Option<NativeWorkspaceResolver>> {
        retention
            .map(|retention| {
                workspace_resolver(
                    &self.worktree,
                    &self.sandbox_read_only,
                    &self.workspace_targets,
                    &self.target_renamer,
                )
                .map(|workspace| {
                    workspace.with_payload_retention(move |file, body| {
                        retention.retain(
                            &gaugedesk_harness::PreparedWorkspaceFile {
                                path: file.path.clone(),
                                kind: file.kind.clone(),
                                sha256: file.content_hash.clone(),
                                bytes: file.bytes,
                            },
                            body,
                        )
                    })
                })
            })
            .transpose()
    }

    fn initial_model_provenance(
        &self,
        command: &StartTurnCommand,
        images: &[ImageContent],
    ) -> InitialModelProvenance {
        let chat = format!("chat:{}", self.chat_id);
        let package = if self.mode == gaugedesk_harness::ChatMode::Use {
            format!("package:{}", command.package_version_ref)
        } else {
            "runtime".to_owned()
        };
        let known = |handles: Vec<String>| ModelContentProvenance {
            source_handles: handles,
            complete: true,
        };
        // The runtime labels the actual skill catalogue after reading the
        // registry for this model request. A pre-turn store read cannot attest
        // the bytes that went into the provider-bound system prompt.
        let system = known(vec![package.clone(), chat.clone()]);
        let image_sources = images
            .iter()
            .map(|image| live_turn_image_source(&self.chat_id, image))
            .collect::<Option<Vec<_>>>();
        let images_known = command.input.images.len() == images.len() && image_sources.is_some();
        let mut user = known(vec![chat.clone()]);
        if let Some(sources) = &self.user_context_sources {
            user.source_handles.extend(sources.iter().cloned());
        }
        if let Some(sources) = image_sources {
            user.source_handles.extend(sources);
        }
        user.complete = self.user_context_sources.is_some() && images_known;
        InitialModelProvenance {
            system,
            user,
            world: known(vec![package.clone(), chat.clone()]),
            tools: known(vec![package, chat]),
            workspace_content: known(vec![format!("workspace:{}", self.chat_id)]),
        }
    }

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
            resources.extend(workspace_resource_refs(&self.workspace_targets));
        }
        if has("command.run") {
            resources.push(ResourceRef {
                handle: "command".to_owned(),
                kind: "command".to_owned(),
                selector: None,
                writable: None,
                presented_as: None,
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
                writable: None,
                presented_as: None,
            });
        }
        if has("tracker.file") && self.task_filer.is_some() {
            resources.push(ResourceRef {
                handle: "tasks".to_owned(),
                kind: "tracker".to_owned(),
                selector: None,
                // `writable` attenuates file_store writes only. The tracker
                // tool is admitted by this resource and the bound TaskFiler.
                writable: None,
                presented_as: None,
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
                        writable: None,
                        presented_as: None,
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

/// Query the original native receipt/witness, never a later resolver drain or
/// live worktree scan. The owner checks complete command identity and current
/// product access before and after the read, including on retained replay.
fn original_workspace_witness<R: ResourceResolver + ?Sized>(
    runtime: &GovernedHostRuntime,
    command: &StartTurnCommand,
    resources: &R,
    receipt: Option<&TurnReceipt>,
) -> io::Result<Option<gaugedesk_harness::RuntimeWorkspaceWitness>> {
    let Some(recorded) = runtime
        .turn_workspace_witness(command, resources)
        .map_err(turn_failure)?
    else {
        if receipt.is_some_and(|receipt| receipt.workspace_cut_ref.is_some()) {
            return Err(invalid_data(
                "original runtime workspace witness unavailable",
            ));
        }
        return Ok(None);
    };
    if Some(&recorded.receipt) != receipt {
        return Err(invalid_data("original runtime workspace receipt changed"));
    }
    Ok(Some(gaugedesk_harness::RuntimeWorkspaceWitness {
        receipt_json: serde_json::to_string(&recorded.receipt).map_err(invalid_data)?,
        writes: recorded
            .writes
            .into_iter()
            .map(|write| gaugedesk_harness::WorkspaceWriteWitness {
                path: write.path,
                kind: write.kind,
                content_hash: write.content_hash,
                bytes: write.bytes,
            })
            .collect(),
        reads: recorded.reads,
    }))
}

fn original_asked_question(
    arguments: &serde_json::Value,
) -> io::Result<gaugedesk_harness::AskedQuestion> {
    let question = arguments
        .get("question")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim()
        .to_owned();
    if question.is_empty() {
        return Err(invalid_data("`ask` requires a question"));
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
    Ok(gaugedesk_harness::AskedQuestion {
        question,
        choices,
        to,
        blocking,
    })
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
        // `assistant_text` stays the folded view (the closing reply) for the
        // TaskResult and the turn-boundary anchor. The durable transcript,
        // though, is built from the ordered `segments`: each assistant prose run
        // interleaved with the tool calls it introduced, so a reloaded turn
        // replays its narration in place rather than collapsing to that closing
        // line. (Before segments the durable record kept only the fold.)
        outcome.assistant_text = output.assistant_text;
        for segment in output.segments {
            match segment {
                TurnContentSegment::Prose(text) => {
                    if text.is_empty() {
                        continue;
                    }
                    // The prose already streamed live via `observe_text_delta`;
                    // re-sinking would double it on the open line. Only when
                    // nothing streamed (the fallback) do we sink, so the live
                    // view is not empty. Either way it is durable below.
                    if sink_final_text {
                        sink(&Observation {
                            kind: "text",
                            detail: text.clone(),
                            tool: None,
                        });
                    }
                    outcome.observations.push(Observation {
                        kind: "assistant",
                        detail: text,
                        tool: None,
                    });
                }
                TurnContentSegment::Tool(call) => {
                    if call.name == "ask" && call.ok == Some(true) {
                        outcome
                            .asked_questions
                            .push(original_asked_question(&call.arguments)?);
                    }
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
            }
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

/// Refine the native tracker tool with this turn's project recipients. The
/// authored package still decides whether `tracker.file` exists at all; this
/// host projection only tells the model who this Home currently permits.
struct ProjectTaskPackage<'a> {
    inner: &'a AuthoredAgentPackage,
    task_filing_admitted: bool,
    recipients: Vec<(String, String)>,
}

impl PackageResolver for ProjectTaskPackage<'_> {
    fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
        let mut package = self.inner.resolve_package(version_ref)?;
        if !self.task_filing_admitted {
            package.tools.retain(|tool| tool.name != "add_todo");
        }
        describe_task_recipients(&mut package.tools, &self.recipients);
        Ok(package)
    }
}

fn describe_task_recipients(
    tools: &mut [whipplescript_kernel::harness_loop::ToolSpec],
    recipients: &[(String, String)],
) {
    let Some(tool) = tools.iter_mut().find(|tool| tool.name == "add_todo") else {
        return;
    };
    let people = recipients
        .iter()
        .map(|(authority, display)| format!("{authority} = {display}"))
        .collect::<Vec<_>>()
        .join("; ");
    let mut assignee = serde_json::json!({
        "type": "string",
        "description": format!(
            "Assign to an eligible person by authority. Omit to leave the issue unassigned. Eligible people: {people}"
        )
    });
    if !recipients.is_empty() {
        assignee["enum"] = serde_json::json!(recipients
            .iter()
            .map(|(authority, _)| authority)
            .collect::<Vec<_>>());
    }
    tool.input_schema["properties"]["assigned_to"] = assignee;
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
        ModelProvider::XaiSubscription => "xai-grok",
    }
}

struct ProviderConfig {
    provider: ModelProvider,
    model: String,
    base_url: String,
    codex_session_id: Option<String>,
    credential_ref: String,
    credential_capability: Arc<dyn CredentialCapability>,
    /// The pinned transport of an office-approved inference endpoint (HIPAA-2).
    /// When present, every model request of the turn connects only through it.
    office_transport: Option<NativeProviderTransport>,
    /// The approved Chat Completions URL of that endpoint, fixed at admission.
    office_request_url: Option<String>,
}

/// The one provider an office-approved inference endpoint may be reached as:
/// an OpenAI-compatible endpoint the office itself operates. Every fixed-host
/// provider is a cloud provider, and so is never an office endpoint.
const OFFICE_INFERENCE_PROVIDER: &str = "openai-generic";

fn office_refusal(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("office inference endpoint refused: {reason}"),
    )
}

/// Admit an office-bound turn's provider selection against its approved
/// endpoint, and build the transport that alone may carry its requests.
///
/// Every difference refuses rather than falls back: another provider, a model
/// or base URL other than the approved one (a host or chat override), egress
/// to any host but the endpoint's own (a tool, shell or web path), and an
/// address set or TLS identity the pinned transport cannot honor.
fn office_transport(
    spec: &HarnessSpec,
    office: &gaugedesk_harness::OfficeInferenceEndpoint,
    descriptor: &NativeProviderDescriptor,
) -> io::Result<NativeProviderTransport> {
    if descriptor.provider_name != OFFICE_INFERENCE_PROVIDER {
        return Err(office_refusal(&format!(
            "provider `{}` is not the office-operated endpoint",
            descriptor.provider_name
        )));
    }
    if descriptor.base_url != office.base_url {
        return Err(office_refusal("the endpoint is not the approved base URL"));
    }
    if descriptor.model != office.model {
        return Err(office_refusal("the model is not the approved model"));
    }
    match spec.sandbox.network {
        Network::Allow => {
            return Err(office_refusal("unfiltered egress is not reviewed"));
        }
        Network::Deny | Network::Filtered => {}
    }
    if spec
        .sandbox
        .allowed_hosts
        .iter()
        .any(|host| host != &descriptor.endpoint_host)
    {
        return Err(office_refusal("egress to another host is not reviewed"));
    }
    let transport = match &office.tls {
        None => NativeProviderTransport::loopback_http(&office.base_url, office.addresses.clone()),
        Some(tls) => NativeProviderTransport::pinned_https(
            &office.base_url,
            office.addresses.clone(),
            tls.trust_roots_der.clone(),
            tls.certificate_sha256.clone(),
        ),
    };
    transport.map_err(|_| office_refusal("the approved address set or TLS identity is invalid"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProviderDescriptor {
    pub provider_name: String,
    pub model: String,
    pub base_url: String,
    pub endpoint_host: String,
    pub credential_env: &'static str,
    pub wire: &'static str,
}

/// The model request dialect GaugeDesk admits for a provider identity.
/// Provider identity and wire are separate policy facts: xAI's API key uses
/// Chat Completions, while a Grok subscription uses Responses.
pub fn provider_model_wire_name(provider_name: &str) -> io::Result<&'static str> {
    match provider_name {
        "anthropic" => Ok("anthropic-messages"),
        "openai" | "openai-codex" | "xai-grok" => Ok("openai-responses"),
        "openai-generic" | "xai" | "openrouter" => Ok("openai-chat-compat"),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("WhippleScript native provider `{provider_name}` has no declared wire"),
        )),
    }
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
            wire: provider_model_wire_name(provider_name)?,
        });
    }
    // A fixed-host provider with a shipped catalog defaults to the current
    // model of its line there, so a chat that pins nothing runs it (DR-0287).
    // Change one only alongside its catalog row in
    // `web/packages/workbench-ui/src/model-catalog.json`.
    let (base_url, endpoint_host, credential_env, default_model) = match provider_name {
        "openai" => (
            "https://api.openai.com",
            "api.openai.com",
            "OPENAI_API_KEY",
            Some("gpt-6.1-sol"),
        ),
        "anthropic" => (
            "https://api.anthropic.com",
            "api.anthropic.com",
            "ANTHROPIC_API_KEY",
            Some("claude-opus-5-5"),
        ),
        "openai-codex" => (
            "https://chatgpt.com",
            "chatgpt.com",
            "GAUGEDESK_CODEX_ACCESS_TOKEN",
            Some("gpt-6.1-sol"),
        ),
        // xAI's Grok API: a fixed-host OpenAI-compatible endpoint. The wire is
        // the Chat Completions client (ADR 0083 §4), whose builder appends only
        // `/chat/completions`, so the base URL must carry the `/v1` segment —
        // unlike the rows above, whose clients append the full `/v1/...` path.
        "xai" => (
            "https://api.x.ai/v1",
            "api.x.ai",
            "XAI_API_KEY",
            Some("grok-4.7"),
        ),
        // OpenRouter: a fixed-host aggregator on the same Chat Completions
        // wire, so its base URL carries `/v1` for the same reason xAI's does.
        // Its model ids are vendor-namespaced (`anthropic/claude-sonnet-4.5`)
        // and its catalog turns over weekly, so there is no default model and
        // no shipped catalog — the operator names the route (ADR 0148).
        "openrouter" => (
            "https://openrouter.ai/api/v1",
            "openrouter.ai",
            "OPENROUTER_API_KEY",
            None,
        ),
        "xai-grok" => (
            "https://cli-chat-proxy.grok.com",
            "cli-chat-proxy.grok.com",
            "GAUGEDESK_XAI_ACCESS_TOKEN",
            None,
        ),
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
            "this WhippleScript native provider requires an explicit model",
        )
    })?;
    Ok(NativeProviderDescriptor {
        provider_name: provider_name.to_owned(),
        model: model.to_owned(),
        base_url: base_url.to_owned(),
        endpoint_host: endpoint_host.to_owned(),
        credential_env,
        wire: provider_model_wire_name(provider_name)?,
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
            // openrouter is likewise fixed-host on that wire; the vendor behind
            // the route is the model id's business, not the client's.
            "openrouter" => ModelProvider::OpenAiCompat,
            "xai-grok" => ModelProvider::XaiSubscription,
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
        let office_transport = spec
            .office_inference
            .as_ref()
            .map(|office| office_transport(spec, office, &descriptor))
            .transpose()?;
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
        let office_request_url = office_transport.as_ref().map(|_| {
            format!(
                "{}/chat/completions",
                descriptor.base_url.trim_end_matches('/')
            )
        });
        Ok(Self {
            provider,
            model: descriptor.model,
            base_url: descriptor.base_url,
            codex_session_id: (provider == ModelProvider::Codex)
                .then(|| format!("gaugedesk-{}", hex::encode(spec.chat_id.as_bytes()))),
            credential_ref,
            credential_capability,
            office_request_url,
            office_transport,
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
                NATIVE_MODEL_OUTPUT_LIMIT,
                Duration::from_secs(120),
            ));
        }
        let binding = ResolvedProviderBinding::new(
            self.provider,
            material.secret().to_owned(),
            self.model.clone(),
            self.base_url.clone(),
            NATIVE_MODEL_OUTPUT_LIMIT,
            Duration::from_secs(120),
        );
        Ok(match &self.office_transport {
            Some(transport) => binding.with_admitted_transport(transport.clone()),
            None => binding,
        })
    }
}

/// Keep refusal terminal across owner execution and GaugeDesk's later projection.
struct CurrentTurnAccess {
    inner: Option<Arc<dyn gaugedesk_harness::TurnAccess>>,
    ended: AtomicBool,
}

impl gaugedesk_harness::TurnAccess for CurrentTurnAccess {
    fn check_current(&self) -> Result<(), String> {
        if self.ended.load(Ordering::Acquire)
            || self
                .inner
                .as_ref()
                .is_some_and(|access| access.check_current().is_err())
        {
            self.ended.store(true, Ordering::Release);
            return Err("original turn access ended".into());
        }
        Ok(())
    }
}
impl CurrentTurnAccess {
    fn current(&self) -> io::Result<()> {
        gaugedesk_harness::TurnAccess::check_current(self).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "original turn access ended",
            )
        })
    }
    fn observe(&self, observation: &Observation, sink: &mut dyn FnMut(&Observation)) {
        if self.current().is_ok() {
            sink(observation);
            let _ = self.current();
        }
    }
}

/// Only current original authority is available to the recorded owner. Any
/// accidental resource/effect request refuses rather than reaching a live tool.
struct RecordedResources<'a> {
    access: &'a dyn Fn() -> Result<(), String>,
}
impl ResourceResolver for RecordedResources<'_> {
    fn check_live_access(&self) -> Result<(), String> {
        (self.access)().map_err(|_| "original turn access ended".into())
    }
    fn resolve_image(&self, _: &ResourceRef) -> Result<ResolvedImage, String> {
        Err("saved runtime observation cannot resolve images".into())
    }
    fn execute_tool(&self, _: &[ResourceRef], _: &ToolCall) -> Result<String, String> {
        Err("saved runtime observation cannot execute tools".into())
    }
}

struct TurnResources<'a> {
    workspace: &'a NativeWorkspaceResolver,
    workspace_resources: &'a [ResourceRef],
    chat_id: &'a str,
    mode: gaugedesk_harness::ChatMode,
    images: &'a [ImageContent],
    task_filer: Option<&'a dyn TaskFiler>,
    external_tool_handler: Option<&'a gaugedesk_harness::ExternalToolHandler>,
    access: Option<&'a dyn gaugedesk_harness::TurnAccess>,
    command_id: String,
    /// The engine's observation sink, held for the duration of the blocking
    /// `run_turn` call so WhippleScript's `observe_text_delta` can project
    /// answer text live — the native counterpart of the DO harness's stream
    /// relay. Interior mutability for the same reason as `asked`; the sink is
    /// taken back out once the runtime returns.
    live: std::cell::RefCell<&'a mut dyn FnMut(&Observation)>,
    /// Whether any answer delta streamed, so the settled projection does not
    /// sink the full text a second time (mirrors the hosted `streamed_text`).
    streamed: std::cell::Cell<bool>,
    /// The one request URL an office-bound turn may send to, fixed when its
    /// binding was admitted (HIPAA-2). `None` for an ordinary turn.
    office_request_url: Option<String>,
    /// Holds credit before each provider call of a credit-funded turn
    /// (GaugeWright DR-0203). A refusal sends nothing for that call.
    managed_call_meter: Option<&'a dyn gaugedesk_harness::ManagedCallMeter>,
}

/// The most output tokens a native provider call asks for. Credit holds are
/// sized from it, so it is named once here rather than repeated at each
/// binding.
pub const NATIVE_MODEL_OUTPUT_LIMIT: u64 = 8_192;

/// Hold credit for one prepared call before the runtime may send it. With no
/// meter the send proceeds exactly as WhippleScript would have made it.
fn admit_metered_call(
    meter: Option<&dyn gaugedesk_harness::ManagedCallMeter>,
    request: &whipplescript::host_runtime::NativeProviderRequest<'_>,
    send: &mut dyn FnMut(Duration) -> Result<(), String>,
) -> Result<(), String> {
    if let Some(meter) = meter {
        meter.admit_call(&gaugedesk_harness::ManagedModelCall {
            command_id: &request.command.command_id,
            ordinal: request.ordinal,
            url: request.url,
            body: request.body,
            output_limit: NATIVE_MODEL_OUTPUT_LIMIT,
        })?;
    }
    send(request.configured_timeout)
}

impl ResourceResolver for TurnResources<'_> {
    fn take_turn_witness(&self) -> TurnWitness {
        // Only the actual workspace resolver can witness effects. Incomplete
        // owner evidence stays incomplete instead of becoming empty work.
        self.workspace.take_turn_witness()
    }

    fn take_workspace_reads(&self) -> Vec<whipplescript_kernel::whip_shell::ShellRead> {
        self.workspace.take_workspace_reads()
    }

    fn check_live_access(&self) -> Result<(), String> {
        self.access.map_or(Ok(()), |access| access.check_current())
    }

    /// An office-bound turn sends only on the admitted pinned transport, to
    /// the approved request URL. Anything else — an unpinned driver, a changed
    /// endpoint — is refused before a connection is made. A credit-funded call
    /// then holds its credit before it is sent.
    fn with_native_provider_request(
        &self,
        request: &whipplescript::host_runtime::NativeProviderRequest<'_>,
        send: &mut dyn FnMut(Duration) -> Result<(), String>,
    ) -> Result<(), String> {
        if let Some(approved) = &self.office_request_url {
            if !request.transport_pinned || request.url != approved {
                return Err(
                    "office inference endpoint refused: the request is not on its pinned transport"
                        .to_owned(),
                );
            }
        }
        // A credit-funded call holds its credit only once its endpoint is
        // admitted, so a refused office endpoint never holds anything.
        admit_metered_call(self.managed_call_meter, request, send)
    }

    fn model_visible_environment(&self) -> whipplescript_kernel::world_state::EnvironmentState {
        // The file tools use a virtual view: model paths begin at the target's
        // presented name, never at the host's materialized storage partition.
        let mut environment = self.workspace.model_visible_environment();
        environment.cwd = Some(".".to_owned());
        environment.workspace_roots = self
            .workspace_resources
            .iter()
            .filter(|resource| {
                resource.kind == "file_store" && resource.handle != TARGET_MANIFEST_RESOURCE
            })
            .map(|resource| {
                resource
                    .presented_as
                    .as_deref()
                    .or(resource.selector.as_deref())
                    .unwrap_or(".")
                    .to_owned()
            })
            .collect();
        environment
    }

    fn model_skill_catalogue_provenance(
        &self,
        skills: &[whipplescript_store::SkillView],
    ) -> ModelContentProvenance {
        match registered_agent_skill_sources(skills, self.chat_id, self.mode) {
            Some(source_handles) => ModelContentProvenance {
                source_handles,
                complete: true,
            },
            None => ModelContentProvenance::default(),
        }
    }

    fn model_output_provenance(
        &self,
        _admitted_resources: &[ResourceRef],
        call: &ToolCall,
    ) -> ModelContentProvenance {
        if call.name == "ask" {
            // Its returned acknowledgement is fixed runtime text. The
            // question arguments already inherit the model's input labels.
            ModelContentProvenance {
                source_handles: vec!["runtime".to_owned()],
                complete: true,
            }
        } else if matches!(call.name.as_str(), "read" | "grep" | "find" | "ls") {
            // The resolver witnessed the exact source set for this call.
            // A bounded directory search or listing carries its root and
            // every source behind its result. An incomplete witness falls
            // back to the coarse source, which cannot authorize a cut.
            if let Some(witness) = self.workspace.take_model_read_witness(&call.id) {
                ModelContentProvenance {
                    source_handles: vec![format!(
                        "workspace-file:{}:{}:{}",
                        self.chat_id, witness.content_hash, witness.path
                    )],
                    complete: true,
                }
            } else if let Some(scan) = self.workspace.take_model_scan_witness(&call.id) {
                let mut handles = vec![format!("workspace-dir:{}:{}", self.chat_id, scan.root)];
                handles.extend(scan.files.into_iter().map(|file| {
                    format!(
                        "workspace-file:{}:{}:{}",
                        self.chat_id, file.content_hash, file.path
                    )
                }));
                handles.extend(
                    scan.directories
                        .into_iter()
                        .map(|path| format!("workspace-dir:{}:{path}", self.chat_id)),
                );
                ModelContentProvenance {
                    source_handles: handles,
                    complete: true,
                }
            } else {
                ModelContentProvenance {
                    source_handles: vec![format!("workspace:{}", self.chat_id)],
                    complete: true,
                }
            }
        } else if matches!(call.name.as_str(), "write" | "edit" | "bash") {
            // These tools may combine several workspace sources. Keep the
            // coarse label until they can attest exact file cuts too.
            ModelContentProvenance {
                source_handles: vec![format!("workspace:{}", self.chat_id)],
                complete: true,
            }
        } else {
            ModelContentProvenance::default()
        }
    }

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
        if call.name == "add_todo" {
            if !admitted_resources.iter().any(|resource| {
                resource.handle == "tasks"
                    && resource.kind == "tracker"
                    && resource.writable.is_none()
            }) {
                return Err("turn has no admitted project task tracker".to_owned());
            }
            let content = call
                .arguments
                .get("content")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .trim();
            if content.is_empty() {
                return Err("`add_todo` requires task content".to_owned());
            }
            if call
                .arguments
                .get("status")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|status| status != "pending")
            {
                return Err("new tasks must start pending".to_owned());
            }
            let filer = self
                .task_filer
                .ok_or("project task filing is unavailable")?;
            let assigned_to = call
                .arguments
                .get("assigned_to")
                .map(|value| value.as_str().ok_or("task assignee must be a person id"))
                .transpose()?;
            let id = filer.file_task(&call.id, content, assigned_to)?;
            return Ok(serde_json::json!({"id": id}).to_string());
        }
        // DR-0314: the chat renders this call as a Download card, so the call
        // itself only proves the offer is real. The path must be a file under
        // `artifacts/`, and the turn must be able to read it: the check is the
        // workspace's own `read`, under the same admitted resources, so an
        // offer never reaches a file the agent could not have read. The
        // receipt carries no file content.
        if call.name == OFFER_DOWNLOAD_TOOL {
            let path = call
                .arguments
                .get("path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .trim();
            let Some(rest) = path.strip_prefix("artifacts/") else {
                return Err("`offer_download` offers only files under artifacts/".to_owned());
            };
            if rest.is_empty()
                || rest
                    .split('/')
                    .any(|segment| segment.is_empty() || segment.starts_with('.'))
            {
                return Err(format!("`{path}` is not a file path under artifacts/"));
            }
            self.workspace.execute_tool(
                admitted_resources,
                &ToolCall {
                    id: call.id.clone(),
                    name: "read".to_owned(),
                    arguments: serde_json::json!({ "path": path }),
                },
            )?;
            return Ok(serde_json::json!({
                "offered": path,
                "note": "The person sees a Download card for this file in the chat."
            })
            .to_string());
        }
        if call.name == "ask_choices" {
            if !admitted_resources
                .iter()
                .any(|resource| resource.kind == QUESTION_RESOURCE)
            {
                return Err("turn has no admitted question capability".to_owned());
            }
            let handler = self.external_tool_handler.as_ref().ok_or_else(|| {
                "this placement has no implementation for `ask_choices`".to_owned()
            })?;
            let call_key = format!("{}/{}", self.command_id, call.id);
            return handler(&call_key, &call.name, &call.arguments);
        }
        if call.name == "ask" {
            if !admitted_resources
                .iter()
                .any(|resource| resource.kind == QUESTION_RESOURCE)
            {
                return Err("turn has no admitted question capability".to_owned());
            }
            original_asked_question(&call.arguments).map_err(|error| error.to_string())?;
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
        if envelope
            .attestation()
            .and_then(|attestation| attestation.epoch)
            .is_some_and(|signed_epoch| signed_epoch != epoch.get())
        {
            return Err(PolicyAdmissionError::EnvelopeRejected(
                "requested policy epoch differs from its signed binding".to_owned(),
            ));
        }
        let policy_ref = PolicyEpochRef::from_verified(epoch.get(), &envelope)
            .map_err(PolicyAdmissionError::Protocol)?;
        if policy_ref.signer != verifier.expected_signer().as_str() {
            return Err(PolicyAdmissionError::EnvelopeRejected(
                "governance signer does not match the pinned root".to_owned(),
            ));
        }
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
    #[test]
    fn turn_observation_revocation_is_terminal_through_final_return() {
        struct MutableAccess(Arc<AtomicBool>);
        impl gaugedesk_harness::TurnAccess for MutableAccess {
            fn check_current(&self) -> Result<(), String> {
                if self.0.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    Err("private reason".into())
                }
            }
        }
        let standing = Arc::new(AtomicBool::new(true));
        let access = CurrentTurnAccess {
            inner: Some(Arc::new(MutableAccess(standing.clone()))),
            ended: AtomicBool::new(false),
        };
        let observation = Observation {
            kind: "text",
            detail: "synthetic clinical output".into(),
            tool: None,
        };
        let mut released = Vec::new();
        access.observe(&observation, &mut |observation| {
            released.push(observation.detail.clone());
            standing.store(false, Ordering::Release);
        });
        assert_eq!(released.len(), 1); // an already delivered delta cannot be recalled
        standing.store(true, Ordering::Release);
        access.observe(&observation, &mut |observation| {
            released.push(observation.detail.clone())
        });
        assert_eq!(released.len(), 1);
        assert_eq!(
            access.current().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            gaugedesk_harness::TurnAccess::check_current(&access).unwrap_err(),
            "original turn access ended"
        );
    }

    #[test]
    fn protected_factory_preserves_encrypted_turns_across_reopen_and_root_rebinding() {
        use ring::{
            aead,
            rand::{SecureRandom, SystemRandom},
        };
        use whipplescript_store::{payload_protection::PayloadCodec, StoreError, StoreResult};
        struct Codec(u8);
        impl Codec {
            fn key(&self) -> aead::LessSafeKey {
                aead::LessSafeKey::new(
                    aead::UnboundKey::new(&aead::AES_256_GCM, &[self.0; 32]).unwrap(),
                )
            }
        }
        impl PayloadCodec for Codec {
            fn seal(&self, aad: &[u8], plain: &[u8]) -> StoreResult<Vec<u8>> {
                let mut nonce = [0; 12];
                SystemRandom::new().fill(&mut nonce).unwrap();
                let mut body = plain.to_vec();
                self.key()
                    .seal_in_place_append_tag(
                        aead::Nonce::assume_unique_for_key(nonce),
                        aead::Aad::from(aad),
                        &mut body,
                    )
                    .map_err(|_| StoreError::fault("synthetic codec", "seal failed"))?;
                Ok([nonce.to_vec(), body].concat())
            }
            fn open(&self, aad: &[u8], sealed: &[u8]) -> StoreResult<Vec<u8>> {
                let nonce = sealed
                    .get(..12)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| StoreError::fault("synthetic codec", "short envelope"))?;
                let mut body = sealed[12..].to_vec();
                let plain = self
                    .key()
                    .open_in_place(
                        aead::Nonce::assume_unique_for_key(nonce),
                        aead::Aad::from(aad),
                        &mut body,
                    )
                    .map_err(|_| StoreError::fault("synthetic codec", "authentication failed"))?;
                Ok(plain.to_vec())
            }
            fn retain(&self, publish: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
                // This fixture's immutable key has no concurrent erasure operation.
                publish()
            }
        }
        let root = tempfile::tempdir().unwrap();
        let worktree = tempfile::tempdir().unwrap();
        let (origin, calls, server) = recording_provider(2);
        let spec = continuity_spec(
            worktree.path(),
            &origin,
            gaugedesk_harness::ChatMode::Edit,
            None,
            Some("SYNTHETIC PRIVATE PERSONA"),
        );
        let selected =
            |domain: &str, key| PayloadProtection::new(domain, Arc::new(Codec(key))).unwrap();
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            root.path(),
        )
        .with_existing_native_runtime_protection(
            &spec.chat_id,
            selected("synthetic-original-chat", 7),
        )
        .unwrap();
        let database = chat_runtime_database(root.path(), &spec.chat_id);
        let signed = spec.signed_policy_envelope.as_ref().unwrap();
        // Enrollment is an explicit owner operation, never a factory fallback.
        drop(
            GovernedHostRuntime::create_protected_with_verifier(
                &database,
                1,
                signed,
                &harness_policy_root(),
                selected("synthetic-original-chat", 7),
            )
            .unwrap(),
        );
        let mut harness = factory.create_harness(&spec).unwrap();
        harness.provider.base_url = origin.clone();
        harness.bind_runtime_command_id(Some("synthetic-original-command"));
        let preparation = harness
            .prepare_runtime_turn("SYNTHETIC PRIVATE FIRST REQUEST", &[])
            .unwrap();
        let original = harness
            .run_turn(
                &gaugedesk_harness::AllowAllGate,
                "SYNTHETIC PRIVATE FIRST REQUEST",
                &[],
                &mut |_| {},
            )
            .unwrap();
        assert!(original.error.is_none(), "{:?}", original.error);
        let first = harness.instance_ref.clone();
        drop(harness);
        let rebound = factory.clone().with_policy_root(harness_policy_root());
        let second = continuity_turn(&rebound, &spec, &origin, "SYNTHETIC PRIVATE SECOND REQUEST");
        assert_eq!(first, second);
        server.join().unwrap();
        assert!(calls.lock().unwrap()[1]
            .to_string()
            .contains("SYNTHETIC PRIVATE FIRST REQUEST"));
        for path in [database.clone(), database.with_extension("sqlite-wal")] {
            if let Ok(bytes) = std::fs::read(path) {
                for private in [
                    "SYNTHETIC PRIVATE FIRST REQUEST",
                    "SYNTHETIC PRIVATE SECOND REQUEST",
                    "SYNTHETIC PRIVATE PERSONA",
                ] {
                    assert!(!bytes
                        .windows(private.len())
                        .any(|window| window == private.as_bytes()));
                }
            }
        }
        let allowed = std::cell::Cell::new(true);
        let checks = std::cell::Cell::new(0usize);
        let current = || {
            checks.set(checks.get() + 1);
            if allowed.get() {
                Ok(())
            } else {
                Err("synthetic current read refused".into())
            }
        };
        let completed = gaugedesk_harness::CompletedProductRuntimeSpec {
            chat_id: &spec.chat_id,
            command_id: "synthetic-original-command",
            policy_epoch: 1,
            signed_policy_envelope: signed,
            preparation: &preparation,
            access: &current,
        };
        let observed = rebound
            .observe_completed_product_runtime(&completed)
            .unwrap();
        assert_eq!(observed.assistant_text, original.assistant_text);
        assert_eq!(
            observed.runtime_start_position,
            original.runtime_start_position
        );
        assert_eq!(
            observed.runtime_terminal_position,
            original.runtime_terminal_position
        );
        assert_eq!(
            observed.runtime_workspace_witness,
            original.runtime_workspace_witness
        );
        assert!(checks.get() > 0);
        struct Allowed;
        impl gaugedesk_harness::TurnAccess for Allowed {
            fn check_current(&self) -> Result<(), String> {
                Ok(())
            }
        }
        let wrong_images = [gaugedesk_harness::ImageContent {
            kind: gaugedesk_harness::ImageKind::Image,
            data: "AA==".into(),
            mime_type: "image/png".into(),
        }];
        let mut pending = gaugedesk_harness::RecordedRuntimeSpec {
            chat_id: &spec.chat_id,
            command_id: "synthetic-original-command",
            policy_epoch: 1,
            signed_policy_envelope: signed,
            preparation: &preparation,
            images: &wrong_images,
            access: &Allowed,
        };
        assert!(rebound.observe_recorded_runtime(&pending).is_err());
        pending.images = &[];
        let recovered = rebound.observe_recorded_runtime(&pending).unwrap();
        assert_eq!(
            recovered.runtime_workspace_witness,
            original.runtime_workspace_witness
        );
        let before = std::fs::read(&database).unwrap();
        allowed.set(false);
        assert!(rebound
            .observe_completed_product_runtime(&completed)
            .is_err());
        assert_eq!(std::fs::read(&database).unwrap(), before);
        // The synchronous caller's non-Send Cell proves no task capability is retained.
        // It supplies current authority; this primitive does not grant a product reader.

        let plain = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            root.path(),
        );
        assert!(plain.runtime_for_chat(&spec.chat_id, 1, signed).is_err());
        let wrong_domain = plain
            .clone()
            .with_existing_native_runtime_protection(
                &spec.chat_id,
                selected("synthetic-foreign-chat", 7),
            )
            .unwrap();
        assert!(wrong_domain
            .runtime_for_chat(&spec.chat_id, 1, signed)
            .is_err());
        let wrong_key = plain
            .with_existing_native_runtime_protection(
                &spec.chat_id,
                selected("synthetic-original-chat", 8),
            )
            .unwrap();
        assert!(wrong_key
            .runtime_for_chat(&spec.chat_id, 1, signed)
            .and_then(|runtime| runtime.newest_recorded_instance().map_err(invalid_data))
            .is_err());
        assert_eq!(std::fs::read(&database).unwrap(), before);
        assert!(rebound
            .runtime_for_chat(&spec.chat_id, 1, signed)
            .unwrap()
            .newest_recorded_instance()
            .unwrap()
            .is_some());
    }

    #[test]
    fn selected_native_protection_never_initializes_missing_or_unbound_storage() {
        use super::*;
        use whipplescript_store::payload_protection::PayloadCodec;
        struct UnreachableCodec;
        impl PayloadCodec for UnreachableCodec {
            fn seal(&self, _: &[u8], _: &[u8]) -> whipplescript_store::StoreResult<Vec<u8>> {
                panic!("missing storage must refuse before sealing")
            }
            fn open(&self, _: &[u8], _: &[u8]) -> whipplescript_store::StoreResult<Vec<u8>> {
                panic!("missing storage has no payload to open")
            }
            fn retain(
                &self,
                _: &mut dyn FnMut() -> whipplescript_store::StoreResult<()>,
            ) -> whipplescript_store::StoreResult<()> {
                panic!("missing storage must refuse before retaining")
            }
        }
        let root = tempfile::tempdir().unwrap();
        let runtime_root = root.path().join("missing-runtime");
        let protection =
            PayloadProtection::new("synthetic-missing-chat", Arc::new(UnreachableCodec)).unwrap();
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("transport:owner"),
            harness_policy_root(),
            &runtime_root,
        )
        .with_existing_native_runtime_protection("bound", protection.clone())
        .unwrap();
        assert!(factory
            .clone()
            .with_existing_native_runtime_protection("bound", protection.clone())
            .is_err());
        assert!(factory
            .clone()
            .with_existing_native_runtime_protection(" ", protection)
            .is_err());
        assert!(factory.runtime_protection("unbound").is_err());
        assert!(!gaugedesk_harness::HarnessFactory::reuse_across_turns(
            &factory
        ));
        let hosted = factory.clone().with_do_host(
            DoHostConfig::new(
                "https://synthetic.invalid",
                "synthetic-token",
                "synthetic-office",
            )
            .unwrap(),
        );
        assert!(hosted.runtime_protection("bound").is_err());
        assert!(hosted.existing_catalogue_store("bound").is_err());
        assert!(hosted
            .with_existing_native_runtime_protection(
                "second",
                PayloadProtection::new("synthetic-second", Arc::new(UnreachableCodec)).unwrap()
            )
            .is_err());
        let key = SigningKey::from_seed(&[7u8; 32]).unwrap();
        let signed = sign_hosted_policy_envelope(
            &harness_policy_at("https://api.openai.com"),
            &AuthorityId::new("authority:owner"),
            &key,
            1,
        )
        .unwrap();
        for chat in ["bound", "unbound"] {
            assert!(factory.runtime_for_chat(chat, 1, &signed).is_err());
            assert!(factory.existing_catalogue_store(chat).is_err());
        }
        assert!(
            !runtime_root.exists(),
            "selection cannot create or adopt storage"
        );
    }

    #[test]
    fn native_agent_skill_catalogue_tracks_the_mounted_version() {
        use super::*;
        let root = tempfile::tempdir().unwrap();
        let worktree = root.path().join("worktree");
        let skill = worktree.join(".gaugedesk-runtime/agent/skills/triage");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(
            skill.join("SKILL.md"),
            "---\nname: triage\ndescription: Inspect reports\n---\nRead the report.\n",
        )
        .unwrap();
        let runtime_root = root.path().join("runtime");
        std::fs::create_dir_all(&runtime_root).unwrap();
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            &runtime_root,
        );
        factory
            .refresh_agent_skill_catalogue("chat-one", &worktree)
            .unwrap();
        let store = whipplescript_store::SqliteStore::open(chat_runtime_database(
            &runtime_root,
            "chat-one",
        ))
        .unwrap();
        let registered = store.list_skills().unwrap();
        assert_eq!(registered.len(), 1);
        assert_eq!(registered[0].name, "triage");
        assert_eq!(registered[0].description, "Inspect reports");
        assert_eq!(
            registered_agent_skill_sources(
                &registered,
                "chat-one",
                gaugedesk_harness::ChatMode::Use,
            ),
            Some(vec![format!(
                "discipline-skill:chat-one:{}:triage",
                registered[0].content_hash
            )])
        );
        assert!(registered_agent_skill_sources(
            &registered,
            "chat-one",
            gaugedesk_harness::ChatMode::Edit,
        )
        .is_none());
        let workspace = NativeWorkspaceResolver::new(&worktree).unwrap();
        let mut sink = |_observation: &gaugedesk_harness::Observation| {};
        let resources = TurnResources {
            workspace: &workspace,
            workspace_resources: &[],
            chat_id: "chat-one",
            mode: gaugedesk_harness::ChatMode::Use,
            images: &[],
            task_filer: None,
            external_tool_handler: None,
            access: None,
            command_id: "test-turn".to_owned(),
            live: std::cell::RefCell::new(&mut sink),
            streamed: std::cell::Cell::new(false),
            office_request_url: None,
            managed_call_meter: None,
        };
        assert!(
            resources
                .model_skill_catalogue_provenance(&registered)
                .complete
        );
        store
            .register_skill(whipplescript_store::SkillRegistration {
                skill_id: "skill:external",
                name: "external",
                version: "1.0.0",
                source: "external",
                source_path: "external/SKILL.md",
                body: "unclassified skill",
                description: "unclassified",
                required_capabilities_json: "[]",
                metadata_json: "{}",
            })
            .unwrap();
        assert!(registered_agent_skill_sources(
            &store.list_skills().unwrap(),
            "chat-one",
            gaugedesk_harness::ChatMode::Use,
        )
        .is_none());
        assert!(
            !resources
                .model_skill_catalogue_provenance(&store.list_skills().unwrap())
                .complete
        );
        store
            .remove_unattached_skills_from_source("external")
            .unwrap();
        std::fs::remove_dir_all(skill).unwrap();
        factory
            .refresh_agent_skill_catalogue("chat-one", &worktree)
            .unwrap();
        assert!(store.list_skills().unwrap().is_empty());
    }

    #[test]
    fn edit_chat_catalogue_is_the_vendored_authoring_skill_alone() {
        use super::*;
        let root = tempfile::tempdir().unwrap();
        let worktree = root.path().join("worktree");
        // A skill of the Agent being edited is a file to edit, never one the
        // editor is offered.
        let agent_skill = worktree.join(".gaugedesk-runtime/agent/skills/triage");
        std::fs::create_dir_all(&agent_skill).unwrap();
        std::fs::write(
            agent_skill.join("SKILL.md"),
            "---\nname: triage\ndescription: Inspect reports\n---\nRead the report.\n",
        )
        .unwrap();
        let runtime_root = root.path().join("runtime");
        std::fs::create_dir_all(&runtime_root).unwrap();
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            &runtime_root,
        );
        factory
            .refresh_editor_skill_catalogue("chat-edit", &worktree)
            .unwrap();
        factory
            .refresh_editor_skill_catalogue("chat-edit", &worktree)
            .unwrap();
        let store = whipplescript_store::SqliteStore::open(chat_runtime_database(
            &runtime_root,
            "chat-edit",
        ))
        .unwrap();
        let registered = store.list_skills().unwrap();
        assert_eq!(registered.len(), 1);
        assert_eq!(registered[0].name, "whipplescript-author");
        assert_eq!(registered[0].source_path, editor_skill::skill_location());
        assert_eq!(
            std::fs::read_to_string(worktree.join(&registered[0].source_path)).unwrap(),
            editor_skill::skill_body()
        );
        assert_eq!(
            registered_agent_skill_sources(
                &registered,
                "chat-edit",
                gaugedesk_harness::ChatMode::Edit,
            ),
            Some(vec!["runtime".to_owned()])
        );
        assert!(registered_agent_skill_sources(
            &registered,
            "chat-edit",
            gaugedesk_harness::ChatMode::Use,
        )
        .is_none());

        // Bytes that are not the vendored skill are not runtime material.
        store
            .register_skill(whipplescript_store::SkillRegistration {
                skill_id: "skill:whipplescript-author",
                name: "whipplescript-author",
                version: "0.0.0",
                source: editor_skill::EDITOR_SKILL_SOURCE,
                source_path: &editor_skill::skill_location(),
                body: "---\nname: whipplescript-author\ndescription: altered\n---\n",
                description: "altered",
                required_capabilities_json: "[]",
                metadata_json: "{}",
            })
            .unwrap();
        assert!(registered_agent_skill_sources(
            &store.list_skills().unwrap(),
            "chat-edit",
            gaugedesk_harness::ChatMode::Edit,
        )
        .is_none());
    }

    #[test]
    fn offer_download_offers_only_a_readable_file_under_artifacts() {
        use whipplescript::host_runtime::{NativeWorkspaceResolver, ResourceResolver};
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("artifacts")).unwrap();
        std::fs::create_dir_all(root.path().join("outbox")).unwrap();
        std::fs::write(
            root.path().join("artifacts/readout.html"),
            "<h1>Readout</h1>",
        )
        .unwrap();
        std::fs::write(root.path().join("outbox/record.json"), "{}").unwrap();
        let workspace = NativeWorkspaceResolver::new(root.path()).unwrap();
        let mut sink = |_observation: &gaugedesk_harness::Observation| {};
        let resources = super::TurnResources {
            workspace: &workspace,
            workspace_resources: &[],
            chat_id: "test-chat",
            mode: gaugedesk_harness::ChatMode::Use,
            images: &[],
            task_filer: None,
            access: None,
            external_tool_handler: None,
            command_id: "test-turn".to_owned(),
            live: std::cell::RefCell::new(&mut sink),
            streamed: std::cell::Cell::new(false),
            office_request_url: None,
            managed_call_meter: None,
        };
        let project = super::ResourceRef {
            handle: "project".into(),
            kind: "file_store".into(),
            selector: None,
            writable: None,
            presented_as: None,
        };
        let offer = |path: &str| super::ToolCall {
            id: "call-1".into(),
            name: super::OFFER_DOWNLOAD_TOOL.into(),
            arguments: serde_json::json!({ "path": path }),
        };

        let receipt = resources
            .execute_tool(
                std::slice::from_ref(&project),
                &offer("artifacts/readout.html"),
            )
            .unwrap();
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["offered"], "artifacts/readout.html");
        assert!(
            !receipt.to_string().contains("<h1>"),
            "the receipt carries no file content"
        );

        // Only the person's folder, only a real file, only what the turn can read.
        for refused in [
            "outbox/record.json",
            "artifacts/../outbox/record.json",
            "artifacts/.hidden.html",
            "artifacts/",
            "artifacts/missing.html",
        ] {
            assert!(
                resources
                    .execute_tool(std::slice::from_ref(&project), &offer(refused))
                    .is_err(),
                "{refused} must not be offered"
            );
        }
        assert!(resources
            .execute_tool(&[], &offer("artifacts/readout.html"))
            .is_err());
    }

    #[test]
    fn add_todo_requires_an_admitted_tracker_and_returns_the_committed_id() {
        use whipplescript::host_runtime::{NativeWorkspaceResolver, ResourceResolver};
        struct Filed(std::sync::Mutex<Vec<(String, String, Option<String>)>>);
        impl gaugedesk_harness::TaskFiler for Filed {
            fn file_task(
                &self,
                call_id: &str,
                content: &str,
                assigned_to: Option<&str>,
            ) -> Result<String, String> {
                self.0.lock().unwrap().push((
                    call_id.into(),
                    content.into(),
                    assigned_to.map(str::to_owned),
                ));
                Ok("issue-123".into())
            }
        }
        let root = tempfile::tempdir().unwrap();
        let workspace = NativeWorkspaceResolver::new(root.path()).unwrap();
        let filer = Filed(std::sync::Mutex::new(Vec::new()));
        let mut sink = |_observation: &gaugedesk_harness::Observation| {};
        let resources = super::TurnResources {
            workspace: &workspace,
            workspace_resources: &[],
            chat_id: "test-chat",
            mode: gaugedesk_harness::ChatMode::Use,
            images: &[],
            task_filer: Some(&filer),
            external_tool_handler: None,
            access: None,
            command_id: "test-turn".to_owned(),
            live: std::cell::RefCell::new(&mut sink),
            streamed: std::cell::Cell::new(false),
            office_request_url: None,
            managed_call_meter: None,
        };
        let call = super::ToolCall {
            id: "call-1".into(),
            name: "add_todo".into(),
            arguments: serde_json::json!({"content":"Test task"}),
        };
        assert!(!resources.model_output_provenance(&[], &call).complete);
        assert_eq!(
            resources
                .model_output_provenance(
                    &[],
                    &super::ToolCall {
                        name: "read".into(),
                        ..call.clone()
                    }
                )
                .source_handles,
            vec!["workspace:test-chat".to_owned()]
        );
        assert!(resources.execute_tool(&[], &call).is_err());
        assert!(filer.0.lock().unwrap().is_empty());
        let admitted = super::ResourceRef {
            handle: "tasks".into(),
            kind: "tracker".into(),
            selector: None,
            writable: None,
            presented_as: None,
        };
        assert_eq!(
            resources.execute_tool(&[admitted], &call).unwrap(),
            serde_json::json!({"id":"issue-123"}).to_string()
        );
        assert_eq!(
            *filer.0.lock().unwrap(),
            vec![("call-1".into(), "Test task".into(), None)]
        );
        let assigned = super::ToolCall {
            id: "call-2".into(),
            name: "add_todo".into(),
            arguments: serde_json::json!({"content":"Colleague task", "assigned_to":"member-b"}),
        };
        assert_eq!(
            resources
                .execute_tool(
                    &[super::ResourceRef {
                        handle: "tasks".into(),
                        kind: "tracker".into(),
                        selector: None,
                        writable: None,
                        presented_as: None,
                    }],
                    &assigned
                )
                .unwrap(),
            serde_json::json!({"id":"issue-123"}).to_string()
        );
        assert_eq!(
            filer.0.lock().unwrap()[1],
            (
                "call-2".into(),
                "Colleague task".into(),
                Some("member-b".into())
            )
        );
        let invalid = super::ToolCall {
            id: "call-3".into(),
            name: "add_todo".into(),
            arguments: serde_json::json!({"content":"Invalid task", "assigned_to":42}),
        };
        assert!(resources
            .execute_tool(
                &[super::ResourceRef {
                    handle: "tasks".into(),
                    kind: "tracker".into(),
                    selector: None,
                    writable: None,
                    presented_as: None,
                }],
                &invalid
            )
            .is_err());
        assert_eq!(filer.0.lock().unwrap().len(), 2);
    }

    #[test]
    fn native_turn_adapter_preserves_exact_writes_and_shell_read_sources() {
        use sha2::{Digest, Sha256};
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("read.txt"), "synthetic source").unwrap();
        std::fs::write(
            root.path().join("unrelated.txt"),
            "unrelated unimported work",
        )
        .unwrap();
        let workspace = NativeWorkspaceResolver::new(root.path()).unwrap();
        let mut sink = |_observation: &Observation| {};
        let resources = TurnResources {
            workspace: &workspace,
            workspace_resources: &[],
            chat_id: "test-chat",
            mode: gaugedesk_harness::ChatMode::Use,
            images: &[],
            task_filer: None,
            external_tool_handler: None,
            access: None,
            command_id: "original-command".into(),
            live: std::cell::RefCell::new(&mut sink),
            streamed: std::cell::Cell::new(false),
            office_request_url: None,
            managed_call_meter: None,
        };
        let admitted = [
            ResourceRef {
                handle: "project".into(),
                kind: "file_store".into(),
                selector: None,
                writable: Some(true),
                presented_as: None,
            },
            ResourceRef {
                handle: "command".into(),
                kind: "command".into(),
                selector: None,
                writable: None,
                presented_as: None,
            },
        ];
        resources
            .execute_tool(
                &admitted,
                &ToolCall {
                    id: "write".into(),
                    name: "write".into(),
                    arguments: serde_json::json!({"path":"out.txt","content":"synthetic output"}),
                },
            )
            .unwrap();
        resources
            .execute_tool(
                &admitted,
                &ToolCall {
                    id: "read".into(),
                    name: "read".into(),
                    arguments: serde_json::json!({"path":"read.txt"}),
                },
            )
            .unwrap();
        resources
            .execute_tool(
                &admitted,
                &ToolCall {
                    id: "shell".into(),
                    name: "bash".into(),
                    arguments: serde_json::json!({"command":"cat read.txt"}),
                },
            )
            .unwrap();
        let shell = resources.take_workspace_reads();
        assert_eq!(shell.len(), 1);
        assert_eq!(shell[0].path, "read.txt");
        assert_eq!(
            shell[0].content_hash,
            whipplescript_store::stable_hash_bytes_hex(b"synthetic source")
        );
        assert_eq!(shell[0].bytes, 16);
        assert!(resources.take_workspace_reads().is_empty());
        let TurnWitness::Witnessed { writes, reads } = resources.take_turn_witness() else {
            panic!("the real native resolver must publish a complete witness");
        };
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].path, "out.txt");
        assert_eq!(writes[0].kind, "add");
        assert_eq!(
            writes[0].content_hash,
            hex::encode(Sha256::digest(b"synthetic output"))
        );
        assert_eq!(writes[0].bytes, 16);
        assert!(reads.iter().any(|path| path == "read.txt"));
        assert!(!reads.iter().any(|path| path.contains("unrelated")));
        assert!(
            matches!(resources.take_turn_witness(), TurnWitness::Witnessed { writes, reads } if writes.is_empty() && reads.is_empty())
        );
        assert_eq!(
            std::fs::read(root.path().join("unrelated.txt")).unwrap(),
            b"unrelated unimported work"
        );
    }

    #[test]
    fn native_read_and_search_use_exact_file_witnesses() {
        use whipplescript::host_runtime::{NativeWorkspaceResolver, ResourceResolver};

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("targets/t-one");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("first.txt"), "first\n").unwrap();
        std::fs::write(target.join("second.txt"), "second\n").unwrap();
        let workspace = NativeWorkspaceResolver::new(root.path()).unwrap();
        let mut sink = |_observation: &gaugedesk_harness::Observation| {};
        let resources = super::TurnResources {
            workspace: &workspace,
            workspace_resources: &[],
            chat_id: "test-chat",
            mode: gaugedesk_harness::ChatMode::Use,
            images: &[],
            task_filer: None,
            external_tool_handler: None,
            access: None,
            command_id: "test-turn".to_owned(),
            live: std::cell::RefCell::new(&mut sink),
            streamed: std::cell::Cell::new(false),
            office_request_url: None,
            managed_call_meter: None,
        };
        let admitted = [super::ResourceRef {
            handle: "target:t-one".into(),
            kind: "file_store".into(),
            selector: Some("targets/t-one".into()),
            writable: Some(false),
            presented_as: None,
        }];
        let read = |id: &str, path: &str| super::ToolCall {
            id: id.into(),
            name: "read".into(),
            arguments: serde_json::json!({"path": path}),
        };
        let first = read("one", "targets/t-one/first.txt");
        let second = read("two", "targets/t-one/second.txt");
        resources.execute_tool(&admitted, &first).unwrap();
        resources.execute_tool(&admitted, &second).unwrap();
        let first_source = resources.model_output_provenance(&admitted, &first);
        let second_source = resources.model_output_provenance(&admitted, &second);
        assert_eq!(
            first_source.source_handles,
            vec![format!(
                "workspace-file:test-chat:{}:targets/t-one/first.txt",
                whipplescript_store::stable_hash_bytes_hex(b"first\n")
            )]
        );
        assert_eq!(
            second_source.source_handles,
            vec![format!(
                "workspace-file:test-chat:{}:targets/t-one/second.txt",
                whipplescript_store::stable_hash_bytes_hex(b"second\n")
            )]
        );
        assert!(first_source.complete && second_source.complete);
        assert_eq!(
            resources
                .model_output_provenance(&admitted, &first)
                .source_handles,
            vec!["workspace:test-chat".to_owned()],
            "a witness is consumed only once"
        );
        let grep = |id: &str, path: &str| super::ToolCall {
            id: id.into(),
            name: "grep".into(),
            arguments: serde_json::json!({"path": path, "pattern": "first"}),
        };
        let single = grep("single", "targets/t-one/first.txt");
        let directory = grep("directory", "targets/t-one");
        resources.execute_tool(&admitted, &single).unwrap();
        resources.execute_tool(&admitted, &directory).unwrap();
        assert_eq!(
            resources
                .model_output_provenance(&admitted, &single)
                .source_handles,
            vec![format!(
                "workspace-file:test-chat:{}:targets/t-one/first.txt",
                whipplescript_store::stable_hash_bytes_hex(b"first\n")
            )]
        );
        let scan = resources.model_output_provenance(&admitted, &directory);
        assert_eq!(scan.source_handles.len(), 3);
        assert!(scan
            .source_handles
            .contains(&"workspace-dir:test-chat:targets/t-one".to_owned()));
        for (name, bytes) in [
            ("first.txt", &b"first\n"[..]),
            ("second.txt", &b"second\n"[..]),
        ] {
            assert!(scan.source_handles.contains(&format!(
                "workspace-file:test-chat:{}:targets/t-one/{name}",
                whipplescript_store::stable_hash_bytes_hex(bytes)
            )));
        }
        assert!(scan.complete);
        let find = super::ToolCall {
            id: "find-directory".into(),
            name: "find".into(),
            arguments: serde_json::json!({
                "path": "targets/t-one", "pattern": "*first*"
            }),
        };
        assert_eq!(
            resources.execute_tool(&admitted, &find).unwrap(),
            "targets/t-one/first.txt"
        );
        let found = resources.model_output_provenance(&admitted, &find);
        assert_eq!(found.source_handles.len(), 3);
        assert!(found.complete);
        assert!(found
            .source_handles
            .contains(&"workspace-dir:test-chat:targets/t-one".to_owned()));
        assert!(
            found.source_handles.contains(&format!(
                "workspace-file:test-chat:{}:targets/t-one/second.txt",
                whipplescript_store::stable_hash_bytes_hex(b"second\n")
            )),
            "a negative filename match contributes its source"
        );
        assert_eq!(
            resources
                .model_output_provenance(&admitted, &find)
                .source_handles,
            vec!["workspace:test-chat".to_owned()],
            "the exact find witness is consumed only once"
        );
        let single_find = super::ToolCall {
            id: "find-file".into(),
            name: "find".into(),
            arguments: serde_json::json!({
                "path": "targets/t-one/first.txt", "pattern": "*second*"
            }),
        };
        assert_eq!(resources.execute_tool(&admitted, &single_find).unwrap(), "");
        assert_eq!(
            resources
                .model_output_provenance(&admitted, &single_find)
                .source_handles,
            vec![format!(
                "workspace-file:test-chat:{}:targets/t-one/first.txt",
                whipplescript_store::stable_hash_bytes_hex(b"first\n")
            )]
        );
        std::fs::create_dir(target.join("child")).unwrap();
        std::fs::write(target.join("child/nested.txt"), "nested\n").unwrap();
        let ls = super::ToolCall {
            id: "list-directory".into(),
            name: "ls".into(),
            arguments: serde_json::json!({"path": "targets/t-one"}),
        };
        assert!(resources
            .execute_tool(&admitted, &ls)
            .unwrap()
            .contains("child/"));
        let listed = resources.model_output_provenance(&admitted, &ls);
        assert!(listed.complete);
        assert_eq!(listed.source_handles.len(), 4);
        assert!(listed
            .source_handles
            .contains(&"workspace-dir:test-chat:targets/t-one".to_owned()));
        assert!(listed
            .source_handles
            .contains(&"workspace-dir:test-chat:targets/t-one/child".to_owned()));
        assert!(listed.source_handles.contains(&format!(
            "workspace-file:test-chat:{}:targets/t-one/first.txt",
            whipplescript_store::stable_hash_bytes_hex(b"first\n")
        )));
        assert!(listed.source_handles.contains(&format!(
            "workspace-file:test-chat:{}:targets/t-one/second.txt",
            whipplescript_store::stable_hash_bytes_hex(b"second\n")
        )));
        assert_eq!(
            resources
                .model_output_provenance(&admitted, &ls)
                .source_handles,
            vec!["workspace:test-chat".to_owned()],
            "a listing witness is consumed only once"
        );
    }

    #[test]
    fn task_tool_offers_only_current_project_recipients() {
        let mut tools = vec![whipplescript_kernel::host_package::tracker_add_todo_spec()];
        super::describe_task_recipients(
            &mut tools,
            &[
                ("member-a".into(), "Alex".into()),
                ("member-b".into(), "Blair".into()),
            ],
        );
        let assigned = &tools[0].input_schema["properties"]["assigned_to"];
        assert_eq!(
            assigned["enum"],
            serde_json::json!(["member-a", "member-b"])
        );
        assert!(assigned["description"]
            .as_str()
            .unwrap()
            .contains("member-b = Blair"));
        assert_eq!(
            tools[0].input_schema["required"],
            serde_json::json!(["content"])
        );
    }

    #[test]
    fn sparse_target_resources_are_exact_and_never_include_project() {
        let targets = vec![
            gaugedesk_harness::WorkspaceTargetBinding {
                target_id: "target-a".to_owned(),
                resource_handle: "target:t-a".to_owned(),
                root: "targets/t-a".to_owned(),
                readable: true,
                writable: true,
                output: true,
                name: "api".to_owned(),
            },
            gaugedesk_harness::WorkspaceTargetBinding {
                target_id: "target-b".to_owned(),
                resource_handle: "target:t-b".to_owned(),
                root: "targets/t-b".to_owned(),
                readable: true,
                writable: false,
                output: false,
                name: "web".to_owned(),
            },
        ];
        super::validate_workspace_targets(&targets).expect("valid sparse targets");
        let resources = super::workspace_resource_refs(&targets);
        assert_eq!(resources.len(), 3);
        assert_eq!(resources[0].handle, "target:t-a");
        assert_eq!(resources[0].selector.as_deref(), Some("targets/t-a"));
        assert_eq!(resources[0].writable, Some(true));
        // DR-0248: the agent sees each target at its name.
        assert_eq!(resources[0].presented_as.as_deref(), Some("api"));
        assert_eq!(resources[1].presented_as.as_deref(), Some("web"));
        assert_eq!(resources[2].presented_as, None);
        assert_eq!(resources[1].handle, "target:t-b");
        assert_eq!(resources[1].selector.as_deref(), Some("targets/t-b"));
        assert_eq!(resources[1].writable, Some(false));
        assert_eq!(resources[2].handle, super::TARGET_MANIFEST_RESOURCE);
        assert_eq!(
            resources[2].selector.as_deref(),
            Some(super::TARGET_MANIFEST_SELECTOR)
        );
        assert_eq!(resources[2].writable, Some(false));
        assert!(resources
            .iter()
            .all(|resource| resource.handle != "project"));

        let duplicate = vec![targets[0].clone(), targets[0].clone()];
        assert!(super::validate_workspace_targets(&duplicate).is_err());
        let mut same_name = targets[1].clone();
        same_name.name = "api".to_owned();
        assert!(super::validate_workspace_targets(&[targets[0].clone(), same_name]).is_err());
        let mut impossible = targets[1].clone();
        impossible.output = true;
        assert!(super::validate_workspace_targets(&[impossible]).is_err());
    }

    /// WS-590: a first work chat must tell the model the same folder names
    /// that the governed file tools admit, without exposing storage partitions.
    #[test]
    fn first_chat_model_world_names_the_admitted_target_folders() {
        let root = tempfile::tempdir().unwrap();
        let workspace = NativeWorkspaceResolver::new(root.path()).unwrap();
        let admitted = workspace_resource_refs(&[gaugedesk_harness::WorkspaceTargetBinding {
            target_id: "target-personal".into(),
            resource_handle: "target:personal".into(),
            root: "targets/t-opaque-partition".into(),
            name: "Personal".into(),
            readable: true,
            writable: true,
            output: true,
        }]);
        let mut sink = |_: &Observation| {};
        let resources = TurnResources {
            workspace: &workspace,
            workspace_resources: &admitted,
            chat_id: "first-chat",
            mode: gaugedesk_harness::ChatMode::Use,
            images: &[],
            task_filer: None,
            access: None,
            external_tool_handler: None,
            command_id: "first-turn".into(),
            live: std::cell::RefCell::new(&mut sink),
            streamed: std::cell::Cell::new(false),
            office_request_url: None,
            managed_call_meter: None,
        };
        let environment = resources.model_visible_environment();
        assert_eq!(environment.cwd.as_deref(), Some("."));
        assert_eq!(environment.workspace_roots, vec!["Personal"]);
        std::fs::create_dir_all(root.path().join("targets/t-opaque-partition")).unwrap();
        let write = |path: &str| ToolCall {
            id: "write-poem".into(),
            name: "write".into(),
            arguments: serde_json::json!({"path":path,"content":"A first poem."}),
        };
        resources
            .execute_tool(&admitted, &write("Personal/poem.md"))
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("targets/t-opaque-partition/poem.md"))
                .unwrap(),
            "A first poem."
        );
        assert!(resources
            .execute_tool(&admitted, &write("poem.md"))
            .is_err());
        assert!(resources
            .execute_tool(&admitted, &write("../escape.md"))
            .is_err());
    }

    #[test]
    fn native_workspace_rejects_writes_below_a_read_only_target_root() {
        use whipplescript::host_runtime::{NativeWorkspaceResolver, ResourceResolver};

        let root = tempfile::tempdir().expect("workspace");
        let read_only = root.path().join("targets/t-read-only");
        let writable = root.path().join("targets/t-writable");
        std::fs::create_dir_all(&read_only).expect("read-only root");
        std::fs::create_dir_all(&writable).expect("writable root");
        std::fs::create_dir_all(root.path().join(".gaugedesk-runtime")).expect("manifest root");
        std::fs::write(root.path().join(super::TARGET_MANIFEST_SELECTOR), "{}").expect("manifest");
        let workspace = NativeWorkspaceResolver::new(root.path())
            .and_then(|resolver| {
                resolver.read_only([
                    std::path::PathBuf::from("targets/t-read-only"),
                    std::path::PathBuf::from(super::TARGET_MANIFEST_SELECTOR),
                ])
            })
            .expect("resolver");
        let resources = super::workspace_resource_refs(&[
            gaugedesk_harness::WorkspaceTargetBinding {
                target_id: "read-only".to_owned(),
                resource_handle: "target:t-read-only".to_owned(),
                root: "targets/t-read-only".to_owned(),
                readable: true,
                writable: false,
                output: false,
                name: String::new(),
            },
            gaugedesk_harness::WorkspaceTargetBinding {
                target_id: "writable".to_owned(),
                resource_handle: "target:t-writable".to_owned(),
                root: "targets/t-writable".to_owned(),
                readable: true,
                writable: true,
                output: true,
                name: String::new(),
            },
        ]);
        let write = |path: &str| super::ToolCall {
            id: format!("write-{path}"),
            name: "write".to_owned(),
            arguments: serde_json::json!({ "path": path, "content": "candidate" }),
        };
        assert!(workspace
            .execute_tool(&resources, &write("targets/t-read-only/note.txt"))
            .is_err());
        assert!(workspace
            .execute_tool(&resources, &write(super::TARGET_MANIFEST_SELECTOR))
            .is_err());
        workspace
            .execute_tool(&resources, &write("targets/t-writable/note.txt"))
            .expect("writable target");
        assert_eq!(
            std::fs::read_to_string(writable.join("note.txt")).expect("written candidate"),
            "candidate"
        );
    }

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
                workspace_resources: &[],
                chat_id: "test-chat",
                mode: gaugedesk_harness::ChatMode::Use,
                images: &[],
                task_filer: None,
                external_tool_handler: None,
                access: None,
                command_id: "test-turn".to_owned(),
                live: std::cell::RefCell::new(&mut sink),
                streamed: std::cell::Cell::new(false),
                office_request_url: None,
                managed_call_meter: None,
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

    #[test]
    fn organization_broker_admits_only_the_exact_whipplescript_request_and_usage() {
        use gaugedesk_core::model_connection::{AuthenticationKind, ProviderBinding};
        use whipplescript_kernel::{
            coerce_native::CoerceProvider,
            harness_loop::{ChatMessage, HttpModelClient},
            harness_model::MessagesApiClient,
        };

        let openai = ProviderBinding {
            provider: "openai".into(),
            endpoint: "https://api.openai.com/v1/".into(),
            authentication: AuthenticationKind::ApiKey,
        };
        let client = MessagesApiClient::new(
            CoerceProvider::OpenAi,
            ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER,
            "gpt-5-mini",
            "https://api.openai.com",
            None,
            None,
        );
        let request = client.build_request(
            &[ChatMessage::User {
                text: "hello".into(),
                images: Vec::new(),
            }],
            &[],
        );
        let admitted = admit_organization_model_request(&openai, "gpt-5-mini", &request).unwrap();
        // The pinned owner catalogue distinguishes input from completion limits.
        assert_eq!(admitted.token_bound, 272_000);
        assert_eq!(
            admitted.request_digest,
            organization_model_request_digest(&request).unwrap()
        );

        let mut wrong_model = request.clone();
        wrong_model.body["model"] = serde_json::json!("copied-model");
        assert!(admit_organization_model_request(&openai, "gpt-5-mini", &wrong_model).is_err());
        assert_ne!(
            organization_model_request_digest(&request).unwrap(),
            organization_model_request_digest(&wrong_model).unwrap()
        );
        let mut secret_bearing = request.clone();
        secret_bearing.headers[0].1 = "Bearer raw-provider-key".into();
        assert!(admit_organization_model_request(&openai, "gpt-5-mini", &secret_bearing).is_err());
        assert_eq!(
            organization_model_response_tokens(
                &openai,
                "gpt-5-mini",
                sansio_types::HttpResponse {
                    status: 200,
                    body: serde_json::json!({
                        "output_text": "hello",
                        "usage": {"input_tokens": 7, "output_tokens": 3}
                    }),
                },
            )
            .unwrap(),
            10
        );

        let xai = ProviderBinding {
            provider: "xai".into(),
            endpoint: "https://api.x.ai/v1/".into(),
            authentication: AuthenticationKind::ApiKey,
        };
        let client = MessagesApiClient::new(
            CoerceProvider::Xai,
            ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER,
            "grok-4.6",
            "https://api.x.ai/v1",
            None,
            None,
        );
        let request = client.build_request(
            &[ChatMessage::User {
                text: "hello".into(),
                images: Vec::new(),
            }],
            &[],
        );
        let admitted = admit_organization_model_request(&xai, "grok-4.6", &request).unwrap();
        assert_eq!(request.url, "https://api.x.ai/v1/chat/completions");
        assert_eq!(admitted.token_bound, 500_000);
        assert_eq!(
            organization_model_response_tokens(
                &xai,
                "grok-4.6",
                sansio_types::HttpResponse {
                    status: 200,
                    body: serde_json::json!({
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": "hello"},
                            "finish_reason": "stop"
                        }],
                        "usage": {"prompt_tokens": 11, "completion_tokens": 5, "total_tokens": 16}
                    }),
                },
            )
            .unwrap(),
            16
        );
        let mut wrong_xai_url = request;
        wrong_xai_url.url = "https://compatible.example/v1/chat/completions".into();
        assert!(admit_organization_model_request(&xai, "grok-4.6", &wrong_xai_url).is_err());

        let canary = ProviderBinding {
            provider: "openai".into(),
            endpoint: ORGANIZATION_MODEL_CANARY_ENDPOINT.into(),
            authentication: AuthenticationKind::ApiKey,
        };
        let canary_request = sansio_types::HttpRequest {
            url: format!("{ORGANIZATION_MODEL_CANARY_ENDPOINT}/responses"),
            headers: vec![
                (
                    "authorization".into(),
                    format!("Bearer {ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER}"),
                ),
                ("content-type".into(), "application/json".into()),
            ],
            body: serde_json::json!({
                "model": ORGANIZATION_MODEL_CANARY_MODEL,
                "input": "Return the bounded GaugeWright production canary response."
            }),
            model_provenance: None,
        };
        assert_eq!(
            admit_organization_model_request(
                &canary,
                ORGANIZATION_MODEL_CANARY_MODEL,
                &canary_request,
            )
            .unwrap()
            .token_bound,
            ORGANIZATION_MODEL_CANARY_TOKEN_BOUND
        );
        assert_eq!(
            hex::encode(organization_model_request_digest(&canary_request).unwrap()),
            "147b66dcaf03287b8f6fdea4ade836ec7fa59a6b2b7a1a82b3a6b92003527a85",
            "the production runner computes this cross-language request identity",
        );
        assert_eq!(
            organization_model_response_tokens(
                &canary,
                ORGANIZATION_MODEL_CANARY_MODEL,
                sansio_types::HttpResponse {
                    status: 200,
                    body: serde_json::json!({
                        "output_text": "synthetic response",
                        "usage": {"input_tokens": 7, "output_tokens": 3}
                    }),
                },
            )
            .unwrap(),
            10
        );
        let mut copied_canary = canary_request.clone();
        copied_canary.body["model"] = serde_json::json!("copied-model");
        assert!(admit_organization_model_request(
            &canary,
            ORGANIZATION_MODEL_CANARY_MODEL,
            &copied_canary,
        )
        .is_err());
        let copied_endpoint = ProviderBinding {
            endpoint: "https://models.gaugewright.com/_canary/openai/v2".into(),
            ..canary.clone()
        };
        assert!(admit_organization_model_request(
            &copied_endpoint,
            ORGANIZATION_MODEL_CANARY_MODEL,
            &canary_request,
        )
        .is_err());

        let anthropic = ProviderBinding {
            provider: "anthropic".into(),
            endpoint: "https://api.anthropic.com/v1".into(),
            authentication: AuthenticationKind::ApiKey,
        };
        let client = MessagesApiClient::new(
            CoerceProvider::Anthropic,
            ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER,
            "claude-sonnet-4-6",
            "https://api.anthropic.com",
            None,
            None,
        );
        let request = client.build_request(
            &[ChatMessage::User {
                text: "hello".into(),
                images: Vec::new(),
            }],
            &[],
        );
        assert_eq!(
            admit_organization_model_request(&anthropic, "claude-sonnet-4-6", &request)
                .unwrap()
                .token_bound,
            1_000_000
        );
        assert_eq!(
            organization_model_response_tokens(
                &anthropic,
                "claude-sonnet-4-6",
                sansio_types::HttpResponse {
                    status: 200,
                    body: serde_json::json!({
                        "content": [{"type": "text", "text": "hello"}],
                        "usage": {"input_tokens": 11, "output_tokens": 5}
                    }),
                },
            )
            .unwrap(),
            16
        );
        assert!(organization_model_response_tokens(
            &anthropic,
            "claude-sonnet-4-6",
            sansio_types::HttpResponse {
                status: 200,
                body: serde_json::json!({"content": []}),
            },
        )
        .is_err());
    }

    #[test]
    fn organization_request_digest_ignores_json_object_insertion_order() {
        let mut nested = serde_json::Map::new();
        nested.insert("b".into(), serde_json::json!(2));
        nested.insert("a".into(), serde_json::json!(1));
        let mut body = serde_json::Map::new();
        body.insert("z".into(), serde_json::Value::Object(nested));
        body.insert("a".into(), serde_json::json!(0));
        let request = |body| sansio_types::HttpRequest {
            url: "https://api.openai.com/v1/responses".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body,
            model_provenance: None,
        };
        let reversed = request(serde_json::Value::Object(body));
        let ordered = request(serde_json::json!({"a": 0, "z": {"a": 1, "b": 2}}));
        assert_eq!(
            organization_model_request_digest(&reversed).unwrap(),
            organization_model_request_digest(&ordered).unwrap(),
        );
    }

    #[test]
    fn organization_model_driver_sends_only_a_digest_to_hub_then_the_exact_request_to_fetch() {
        use gaugedesk_core::ids::ScopeId;
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use whipplescript_kernel::{
            coerce_native::CoerceProvider,
            harness_loop::{ChatMessage, HttpModelClient},
            harness_model::MessagesApiClient,
            sansio::{
                HostDriver as _, IoRequest, IoResult, ModelContentProvenance,
                ModelRequestProvenance,
            },
        };

        fn read_request(
            stream: &mut std::net::TcpStream,
        ) -> (String, Vec<(String, String)>, Vec<u8>) {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 4096];
            let header_end = loop {
                let count = stream.read(&mut chunk).unwrap();
                assert!(count > 0, "request ended before its headers");
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let header = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
            let mut lines = header.split("\r\n");
            let request_line = lines.next().unwrap().to_owned();
            let headers = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                .collect::<Vec<_>>();
            let content_length = headers
                .iter()
                .find(|(name, _)| name == "content-length")
                .and_then(|(_, value)| value.parse::<usize>().ok())
                .unwrap();
            while bytes.len() - header_end < content_length {
                let count = stream.read(&mut chunk).unwrap();
                assert!(count > 0, "request ended before its body");
                bytes.extend_from_slice(&chunk[..count]);
            }
            (
                request_line,
                headers,
                bytes[header_end..header_end + content_length].to_vec(),
            )
        }

        fn write_json(stream: &mut std::net::TcpStream, value: serde_json::Value) {
            let body = serde_json::to_vec(&value).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }

        let binding = AuthorityBinding {
            authority: AuthorityId::new("authority:model"),
            organization: ScopeId::new("organization:acme"),
            environment: "test".to_owned(),
        };
        let client = MessagesApiClient::new(
            CoerceProvider::OpenAi,
            ORGANIZATION_MODEL_BROKER_CREDENTIAL_PLACEHOLDER,
            "gpt-5-mini",
            "https://api.openai.com",
            None,
            None,
        );
        let mut request = client.build_request(
            &[ChatMessage::User {
                text: "private project prompt".to_owned(),
                images: Vec::new(),
            }],
            &[],
        );
        request.model_provenance = Some(ModelRequestProvenance {
            messages: vec![ModelContentProvenance {
                source_handles: vec!["chat:one".to_owned()],
                complete: true,
            }],
            tools: ModelContentProvenance {
                source_handles: vec!["runtime".to_owned()],
                complete: true,
            },
            wire: None,
        });
        let expected_request = request.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server_origin = origin.clone();
        let server_binding = binding.clone();
        let server = std::thread::spawn(move || {
            let (mut prepare, _) = listener.accept().unwrap();
            let (line, headers, body) = read_request(&mut prepare);
            assert_eq!(
                line,
                "POST /projects/project:one/organization-model-invocations HTTP/1.1"
            );
            assert!(headers.iter().any(|(name, value)| {
                name == "authorization" && value == "Bearer account-session"
            }));
            assert!(headers.iter().any(|(name, value)| {
                name == "x-gaugewright-tenant" && value == "organization:acme"
            }));
            let prepared: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(prepared.get("v"), Some(&serde_json::json!(1)));
            assert_eq!(prepared.get("chat"), Some(&serde_json::json!("chat:one")));
            assert!(prepared.get("prompt").is_none());
            assert_eq!(
                prepared.get("request_digest"),
                Some(
                    &serde_json::to_value(
                        organization_model_request_digest(&expected_request).unwrap()
                    )
                    .unwrap()
                )
            );
            write_json(
                &mut prepare,
                serde_json::json!({
                    "v": 1,
                    "binding": server_binding,
                    "attempt": "attempt:one",
                    "fetch_url": format!("{server_origin}/v1/model-providers/private-fetch"),
                    "ticket": "signed-ticket",
                    "expires_at": unix_now() + 30,
                }),
            );

            let (mut fetch, _) = listener.accept().unwrap();
            let (line, headers, body) = read_request(&mut fetch);
            assert_eq!(line, "POST /v1/model-providers/private-fetch HTTP/1.1");
            assert!(headers.iter().any(|(name, value)| {
                name == "authorization" && value == "Bearer signed-ticket"
            }));
            let fetched: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(fetched["url"], expected_request.url);
            assert_eq!(
                fetched["headers"],
                serde_json::json!(expected_request.headers)
            );
            assert_eq!(fetched["body"], expected_request.body);
            write_json(
                &mut fetch,
                serde_json::json!({
                    "v": 1,
                    "attempt": "attempt:one",
                    "status": 200,
                    "body": {
                        "output": [],
                        "output_text": "answer",
                        "usage": {"input_tokens": 7, "output_tokens": 3}
                    }
                }),
            );
        });

        let broker = OrganizationModelBrokerConfig::new(
            origin,
            "account-session",
            "organization:acme",
            "project:one",
            "chat:one",
            binding,
        )
        .unwrap();
        let capture = Arc::new(Mutex::new(NativeModelContext {
            active: true,
            ..NativeModelContext::default()
        }));
        let driver = OrganizationModelHostDriver {
            broker: &broker,
            capture: Arc::clone(&capture),
        };
        let expected_body = request.body.clone();
        let IoResult::Http(Ok(response)) = driver.fulfill(&IoRequest::Http(request)) else {
            panic!("broker response");
        };
        assert_eq!(response.status, 200);
        assert_eq!(response.body["output_text"], "answer");
        let snapshot = &capture.lock().unwrap().calls[0];
        assert_eq!(snapshot["body"], expected_body);
        assert_eq!(
            snapshot["ordered_provenance"]["messages"][0]["source_handles"][0],
            "chat:one"
        );
        assert_eq!(snapshot["provenance_complete"], true);
        assert!(snapshot["body"].get("headers").is_none());
        server.join().unwrap();
    }

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
            credential_ref: "credential:gaugedesk/account/616c696365/6f70656e6169/v1".to_owned(),
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
        signed_harness_policy_at("https://api.openai.com")
    }

    fn harness_policy_root() -> GovernanceRootVerifier {
        GovernanceRootVerifier::new(
            AuthorityId::new("authority:owner"),
            SigningKey::from_seed(&[7u8; 32]).expect("key").public_key(),
        )
    }

    fn signed_harness_policy_at(base_url: &str) -> String {
        let authority = AuthorityId::new("authority:owner");
        let key = SigningKey::from_seed(&[7u8; 32]).expect("key");
        sign_policy_envelope(&harness_policy_at(base_url), &authority, &key)
            .expect("signed harness policy")
    }

    pub(super) fn harness_policy_at(base_url: &str) -> String {
        harness_policy_for("openai", "gpt-test", base_url, "openai-responses")
    }

    fn harness_policy_for(provider: &str, model: &str, base_url: &str, wire: &str) -> String {
        let principal = ResourcePolicy {
            principal: true,
            ..ResourcePolicy::default()
        };
        let ordinary = ResourcePolicy::default();
        let policy = HostGovernancePolicy {
            resources: std::collections::BTreeMap::from([
                ("file:workspace:chat-1".to_owned(), ordinary.clone()),
                ("file:personal".to_owned(), ordinary.clone()),
                ("file:target-manifest".to_owned(), ordinary.clone()),
                ("memory:turn-images:chat-1".to_owned(), ordinary),
                ("tracker:tasks".to_owned(), ResourcePolicy::default()),
                ("command:workspace:chat-1".to_owned(), principal.clone()),
                ("provider:openai".to_owned(), principal.clone()),
                ("provider:owned".to_owned(), principal.clone()),
                ("placement:local".to_owned(), principal),
            ]),
            bindings: std::collections::BTreeMap::from([
                ("project".to_owned(), "file:workspace:chat-1".to_owned()),
                ("target:personal".to_owned(), "file:personal".to_owned()),
                (
                    TARGET_MANIFEST_RESOURCE.to_owned(),
                    "file:target-manifest".to_owned(),
                ),
                (
                    "turn_images".to_owned(),
                    "memory:turn-images:chat-1".to_owned(),
                ),
                ("command".to_owned(), "command:workspace:chat-1".to_owned()),
                ("tasks".to_owned(), "tracker:tasks".to_owned()),
                ("model".to_owned(), "provider:openai".to_owned()),
                ("owned".to_owned(), "provider:owned".to_owned()),
                ("local".to_owned(), "placement:local".to_owned()),
            ]),
            capabilities: BTreeSet::from([
                "workspace.read".to_owned(),
                "workspace.write".to_owned(),
                "command.run".to_owned(),
                "tracker.file".to_owned(),
            ]),
            provider_bindings: std::collections::BTreeMap::from([(
                "model".to_owned(),
                ProviderBindingPolicy {
                    provider: provider.to_owned(),
                    model: model.to_owned(),
                    base_url: base_url.to_owned(),
                    credential_ref: "credential:gaugedesk/account/616c696365/6f70656e6169/v1"
                        .to_owned(),
                    wire: Some(wire.to_owned()),
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
        policy.to_json().expect("policy")
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
    fn xai_descriptor_carries_the_v1_base_and_defaults_to_the_current_grok() {
        // Fixed host, but on the Chat Completions wire: the client appends only
        // `/chat/completions`, so the base URL MUST already carry `/v1` or every
        // turn 404s (the openai-generic lesson, live-confirmed 2026-07-19).
        let desc =
            native_provider_descriptor("xai", Some("grok-4.6"), None).expect("xai descriptor");
        assert_eq!(desc.base_url, "https://api.x.ai/v1");
        assert_eq!(desc.endpoint_host, "api.x.ai");
        assert_eq!(desc.model, "grok-4.6");
        // Like the other fixed-host providers with a shipped catalog, an
        // unpinned turn runs the current model of the line (DR-0287).
        assert_eq!(
            native_provider_descriptor("xai", None, None).unwrap().model,
            "grok-4.7"
        );
        // base_url is ignored for fixed-host providers rather than honored.
        let pinned =
            native_provider_descriptor("xai", Some("grok-4.6"), Some("https://evil.example"))
                .expect("xai descriptor ignores base_url");
        assert_eq!(pinned.base_url, "https://api.x.ai/v1");
    }

    #[test]
    fn openrouter_descriptor_is_fixed_host_compat_and_takes_a_namespaced_model() {
        // Same `/v1`-in-base convention as xAI: the Chat Completions client
        // appends only `/chat/completions`.
        let desc =
            native_provider_descriptor("openrouter", Some("anthropic/claude-sonnet-4.5"), None)
                .expect("openrouter descriptor");
        assert_eq!(desc.base_url, "https://openrouter.ai/api/v1");
        assert_eq!(desc.endpoint_host, "openrouter.ai");
        assert_eq!(desc.wire, "openai-chat-compat");
        // A vendor-namespaced route survives descriptor derivation intact — the
        // slash is part of the model id OpenRouter routes on, not a path.
        assert_eq!(desc.model, "anthropic/claude-sonnet-4.5");
        // No default model: OpenRouter's catalog turns over too fast to name one.
        assert!(native_provider_descriptor("openrouter", None, None).is_err());
        // Fixed host, so a carried base URL is ignored rather than honored.
        let pinned = native_provider_descriptor(
            "openrouter",
            Some("openai/gpt-5"),
            Some("https://evil.example"),
        )
        .expect("openrouter descriptor ignores base_url");
        assert_eq!(pinned.base_url, "https://openrouter.ai/api/v1");
    }

    #[test]
    fn xai_subscription_descriptor_is_fixed_host_responses() {
        let descriptor = native_provider_descriptor("xai-grok", Some("grok-code-fast-1"), None)
            .expect("xAI Grok subscription descriptor");
        assert_eq!(descriptor.base_url, "https://cli-chat-proxy.grok.com");
        assert_eq!(descriptor.endpoint_host, "cli-chat-proxy.grok.com");
        assert_eq!(descriptor.credential_env, "GAUGEDESK_XAI_ACCESS_TOKEN");
        assert_eq!(descriptor.wire, "openai-responses");
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

    /// A metered call is held before the runtime may send it, with the call's
    /// exact identity and the native output limit; a refusal sends nothing.
    #[test]
    fn a_metered_native_call_is_admitted_before_it_is_sent() {
        struct Recording(Mutex<Vec<(String, u64, u64)>>, bool);
        impl gaugedesk_harness::ManagedCallMeter for Recording {
            fn admit_call(
                &self,
                call: &gaugedesk_harness::ManagedModelCall<'_>,
            ) -> Result<(), String> {
                self.0.lock().unwrap().push((
                    call.command_id.to_owned(),
                    call.ordinal,
                    call.output_limit,
                ));
                if self.1 {
                    Ok(())
                } else {
                    Err("credits exhausted".to_owned())
                }
            }
        }
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
            resources: Vec::new(),
            provider_binding: ProviderBindingRef {
                binding_id: "gaugedesk:provider:primary".to_owned(),
                credential: CredentialRef {
                    credential_id: "credential:gaugedesk/account/616c696365/6f70656e6169/v1"
                        .to_owned(),
                },
            },
            placement_ceiling_ref: "gaugedesk:placement:local".to_owned(),
        };
        let body = serde_json::json!({ "model": "m" });
        let request = whipplescript::host_runtime::NativeProviderRequest {
            command: &command,
            ordinal: 2,
            url: "https://gateway.test/v1/responses",
            body: &body,
            provenance: None,
            transport_pinned: false,
            configured_timeout: Duration::from_secs(5),
        };

        let allow = Recording(Mutex::new(Vec::new()), true);
        let mut sent = Vec::new();
        admit_metered_call(Some(&allow), &request, &mut |timeout| {
            sent.push(timeout);
            Ok(())
        })
        .unwrap();
        assert_eq!(sent, vec![Duration::from_secs(5)]);
        assert_eq!(
            allow.0.lock().unwrap().as_slice(),
            [("turn-command-9".to_owned(), 2, NATIVE_MODEL_OUTPUT_LIMIT)]
        );

        let refuse = Recording(Mutex::new(Vec::new()), false);
        let mut sent = 0;
        assert!(admit_metered_call(Some(&refuse), &request, &mut |_| {
            sent += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(sent, 0, "a refused call is never sent");

        let mut sent = 0;
        admit_metered_call(None, &request, &mut |_| {
            sent += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(sent, 1, "an unmetered call sends as before");
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
                writable: None,
                presented_as: None,
            }],
            provider_binding: ProviderBindingRef {
                binding_id: "gaugedesk:provider:primary".to_owned(),
                credential: CredentialRef {
                    credential_id: "credential:gaugedesk/account/616c696365/6f70656e6169/v1"
                        .to_owned(),
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
    fn policy_admission_refuses_a_different_signer_under_the_same_key() {
        let key = SigningKey::from_seed(&[7u8; 32]).expect("root key");
        let signed = sign_policy_envelope(
            &harness_policy_at("https://api.openai.com"),
            &AuthorityId::new("project:foreign"),
            &key,
        )
        .unwrap();
        let error = AdmittedPolicyEpoch::verify_with(
            PolicyEpoch::new(1).unwrap(),
            &signed,
            &harness_policy_root(),
        )
        .err()
        .expect("a signature is not issuer standing");
        assert!(error.to_string().contains("signer does not match"));

        let root = tempfile::tempdir().unwrap();
        let runtime_root = root.path().join("runtime");
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("transport:host"),
            harness_policy_root(),
            &runtime_root,
        );
        assert!(factory.runtime_for_chat("chat", 1, &signed).is_err());
        assert!(
            !runtime_root.exists(),
            "refusal must precede runtime writes"
        );
    }

    #[test]
    fn project_policy_reopens_and_forks_with_only_its_original_public_root() {
        let root = tempfile::tempdir().unwrap();
        let worktree = tempfile::tempdir().unwrap();
        let actor = AuthorityId::new("transport:project-host");
        let issuer = AuthorityId::new("project:original");
        // Only the signed policy and public root leave the signing scope.
        let (signed, policy_root) = {
            let key = SigningKey::from_seed(&[8u8; 32]).unwrap();
            (
                sign_hosted_policy_envelope(
                    &harness_policy_at("https://api.openai.com"),
                    &issuer,
                    &key,
                    1,
                )
                .unwrap(),
                GovernanceRootVerifier::new(issuer.clone(), key.public_key()),
            )
        };
        let factory = WhipHarnessFactory::new(actor.clone(), policy_root.clone(), root.path());
        let mut spec = continuity_spec(
            worktree.path(),
            "https://api.openai.com",
            gaugedesk_harness::ChatMode::Edit,
            None,
            Some("Inspect the project."),
        );
        spec.signed_policy_envelope = Some(signed.clone());
        let first = factory.create_harness(&spec).unwrap();
        assert_eq!(first.respondent_ref, actor.as_str());
        assert_eq!(first.runtime.policy_ref().signer, issuer.as_str());
        let policy = first.runtime.policy_ref().clone();
        let position = first.runtime.current_position(&first.instance_ref).unwrap();
        let source_instance = first.instance_ref.clone();
        drop(first);
        let source = HarnessContinuitySpec {
            chat_id: spec.chat_id.clone(),
            runtime_placement_id: spec.runtime_placement_id.clone(),
            worktree: spec.worktree.clone(),
            mode: spec.mode,
            package_root: None,
            package_version_ref: None,
            system_prompt: spec.system_prompt.clone(),
            policy_epoch: spec.policy_epoch,
            signed_policy_envelope: spec.signed_policy_envelope.clone(),
            source_position: Some(RuntimePosition {
                instance_ref: position.instance_ref,
                sequence: position.sequence,
            }),
        };
        let target = HarnessContinuitySpec {
            chat_id: "forked-project-chat".into(),
            source_position: None,
            ..source.clone()
        };
        drop(factory);
        // Reconstruct from public evidence alone, as after custody has gone.
        let reopened = WhipHarnessFactory::new(actor, policy_root, root.path());
        let original = reopened.create_harness(&spec).unwrap();
        assert_eq!(original.instance_ref, source_instance);
        assert_eq!(original.runtime.policy_ref(), &policy);
        drop(original);
        reopened.clone_continuity(&source, &target).unwrap();
        reopened.clone_continuity(&source, &target).unwrap();
        let fork = reopened
            .create_harness(&HarnessSpec {
                chat_id: target.chat_id.clone(),
                ..spec
            })
            .unwrap();
        assert_ne!(fork.instance_ref, source_instance);
        assert_eq!(fork.runtime.policy_ref(), &policy);
        assert_eq!(
            source.signed_policy_envelope.as_deref(),
            Some(signed.as_str())
        );

        let wrong = WhipHarnessFactory::new(
            AuthorityId::new("transport:project-host"),
            harness_policy_root(),
            root.path().join("foreign"),
        );
        assert!(wrong.clone_continuity(&source, &target).is_err());
        assert!(!root.path().join("foreign").exists());
    }

    #[test]
    fn first_chat_creates_file_continues_and_reopens_through_real_runtime() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
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
  "capabilities":["workspace.read","workspace.write","command.run","tracker.file"],
  "agent_abilities":["workspace.read","workspace.write","command.run","tracker.file"],
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
    capabilities ["workspace.read", "workspace.write", "command.run", "tracker.file"]
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
            signed_policy_envelope: Some(signed_harness_policy_at(&origin)),
            prior_policy_envelopes: Vec::new(),
            provider_binding_ref: Some("model".to_owned()),
            credential_ref: Some(
                "credential:gaugedesk/account/616c696365/6f70656e6169/v1".to_owned(),
            ),
            placement_ceiling_ref: Some("local".to_owned()),
            workspace_targets: vec![gaugedesk_harness::WorkspaceTargetBinding {
                target_id: "personal".into(),
                resource_handle: "target:personal".into(),
                name: "Personal".into(),
                root: "targets/t-personal".into(),
                readable: true,
                writable: true,
                output: true,
            }],
            runtime_placement_id: Some("placement-test".to_owned()),
            provider: Some("openai".to_owned()),
            model: Some("gpt-test".to_owned()),
            base_url: None,
            thinking: None,
            system_prompt: None,
            credential_capability: Some(test_credential_capability()),
            office_inference: None,
            sandbox: gaugedesk_harness::sandbox::SandboxPolicy::new(vec![worktree
                .path()
                .to_path_buf()])
            .read_only(vec![worktree.path().join(".whipple")])
            .filter_egress(vec!["api.openai.com".to_owned(), "127.0.0.1".to_owned()]),
            roster: Vec::new(),
        };
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            root.path(),
        );
        let mut first = factory.create_harness(&spec).expect("first harness");
        // The fixed OpenAI endpoint is replaced only in this test fixture;
        // the signed runtime policy admits this exact loopback endpoint.
        first.provider.base_url = origin.clone();

        // A controlled provider speaks the actual Responses HTTP protocol.
        // Harness, credentials, admission, kernel, native transport and file
        // tools stay on their production paths; no scripted agent is involved.
        let calls = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let recorded = Arc::clone(&calls);
        let server = std::thread::spawn(move || {
            for ordinal in 0..6 {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        result => panic!("provider accept failed: {result:?}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let start = loop {
                    let count = socket.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&chunk[..count]);
                    if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&bytes[..start]).to_lowercase();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                while bytes.len() < start + length {
                    let count = socket.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&chunk[..count]);
                }
                let request: serde_json::Value =
                    serde_json::from_slice(&bytes[start..start + length]).unwrap();
                recorded.lock().unwrap().push(request.clone());
                let body = match ordinal {
                    0 | 1 | 3 => {
                        assert!(request.to_string().contains("Personal"));
                        if ordinal == 1 {
                            // Reproduce the observed first-chat tool refusal:
                            // its result must retain its matching model call
                            // so the provider can correct the path and continue.
                            let input = request["input"].as_array().unwrap();
                            assert!(input.iter().any(|item| item["type"] == "function_call"
                                && item["call_id"] == "write-0"));
                            assert!(input.iter().any(|item| item["type"]
                                == "function_call_output"
                                && item["call_id"] == "write-0"
                                && item["output"]
                                    .as_str()
                                    .is_some_and(|text| text.contains("outside the admitted"))));
                        }
                        let content = if ordinal < 2 {
                            "first poem"
                        } else {
                            "second poem"
                        };
                        let path = if ordinal == 0 {
                            "poem.md"
                        } else {
                            "Personal/poem.md"
                        };
                        serde_json::json!({"output":[{"type":"function_call",
                            "call_id":format!("write-{ordinal}"),"name":"write",
                            "arguments":serde_json::json!({"path":path,"content":content}).to_string()}]})
                    }
                    2 | 4 => {
                        let input = request["input"].as_array().expect("Responses input");
                        let id = format!("write-{}", ordinal - 1);
                        assert!(input
                            .iter()
                            .any(|item| item["type"] == "function_call" && item["call_id"] == id));
                        assert!(input
                            .iter()
                            .any(|item| item["type"] == "function_call_output"
                                && item["call_id"] == id));
                        serde_json::json!({"output_text":"Done.","usage":{"input_tokens":100,"output_tokens":3}})
                    }
                    _ => serde_json::json!({"error":{"message":"synthetic provider refusal"}}),
                };
                let (status, content_type, wire) = if ordinal == 5 {
                    ("400 Bad Request", "application/json", body.to_string())
                } else if headers.contains("text/event-stream") {
                    (
                        "200 OK",
                        "text/event-stream",
                        format!(
                            "data: {}\n\ndata: [DONE]\n\n",
                            serde_json::json!({"type":"response.completed","response":body})
                        ),
                    )
                } else {
                    ("200 OK", "application/json", body.to_string())
                };
                write!(socket,"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{wire}",wire.len()).unwrap();
            }
        });
        fn drive(harness: &mut WhipHarness, prompt: &str) {
            let outcome = harness
                .run_turn(&gaugedesk_harness::AllowAllGate, prompt, &[], &mut |_| {})
                .unwrap();
            assert!(outcome.error.is_none(), "{:?}", outcome.error);
            assert_eq!(outcome.assistant_text, "Done.");
            assert!(outcome.observations.iter().any(|observation| observation
                .tool
                .as_ref()
                .is_some_and(|tool| tool.name == "write" && tool.ok == Some(true))));
        }
        std::fs::create_dir_all(worktree.path().join("targets/t-personal")).unwrap();
        drive(&mut first, "add a file called poem.md");
        let file = worktree.path().join("targets/t-personal/poem.md");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "first poem");
        let instance = first.instance_ref.clone();
        drop(first);
        let mut reopened = factory.create_harness(&spec).unwrap();
        reopened.provider.base_url = origin;
        assert_eq!(reopened.instance_ref, instance);
        drive(&mut reopened, "change the poem");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "second poem");
        assert!(
            calls.lock().unwrap()[3]
                .to_string()
                .contains("add a file called poem.md"),
            "the reopened second turn retains the first request"
        );
        let refused = reopened
            .run_turn(
                &gaugedesk_harness::AllowAllGate,
                "exercise a provider refusal",
                &[],
                &mut |_| {},
            )
            .unwrap();
        assert!(refused
            .error
            .as_deref()
            .unwrap()
            .contains("synthetic provider refusal"));
        server.join().unwrap();
        drop(reopened);
        assert_eq!(
            factory.create_harness(&spec).unwrap().instance_ref,
            instance
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "second poem");
    }

    /// A loopback Responses endpoint that answers `turns` requests with
    /// "Done." and records each request body.
    fn recording_provider(
        turns: usize,
    ) -> (
        String,
        Arc<Mutex<Vec<serde_json::Value>>>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let recorded = Arc::clone(&calls);
        let server = std::thread::spawn(move || {
            for _ in 0..turns {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        result => panic!("provider accept failed: {result:?}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let start = loop {
                    let count = socket.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&chunk[..count]);
                    if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&bytes[..start]).to_lowercase();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                while bytes.len() < start + length {
                    let count = socket.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&chunk[..count]);
                }
                recorded
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&bytes[start..start + length]).unwrap());
                let body = serde_json::json!({"output_text":"Done.",
                    "usage":{"input_tokens":1,"output_tokens":1}});
                let (content_type, wire) = if headers.contains("text/event-stream") {
                    (
                        "text/event-stream",
                        format!(
                            "data: {}\n\ndata: [DONE]\n\n",
                            serde_json::json!({"type":"response.completed","response":body})
                        ),
                    )
                } else {
                    ("application/json", body.to_string())
                };
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{wire}",
                    wire.len()
                )
                .unwrap();
            }
        });
        (origin, calls, server)
    }

    pub(super) fn continuity_spec(
        worktree: &Path,
        origin: &str,
        mode: gaugedesk_harness::ChatMode,
        package: Option<(&Path, &str)>,
        system_prompt: Option<&str>,
    ) -> HarnessSpec {
        HarnessSpec {
            chat_id: "chat-continuity".to_owned(),
            worktree: worktree.to_path_buf(),
            mode,
            package_root: package.map(|(root, _)| root.to_path_buf()),
            package_version_ref: package.map(|(_, reference)| reference.to_owned()),
            policy_epoch: Some(1),
            signed_policy_envelope: Some(signed_harness_policy_at(origin)),
            prior_policy_envelopes: Vec::new(),
            provider_binding_ref: Some("model".to_owned()),
            credential_ref: Some(
                "credential:gaugedesk/account/616c696365/6f70656e6169/v1".to_owned(),
            ),
            placement_ceiling_ref: Some("local".to_owned()),
            workspace_targets: Vec::new(),
            runtime_placement_id: Some("placement-test".to_owned()),
            provider: Some("openai".to_owned()),
            model: Some("gpt-test".to_owned()),
            base_url: None,
            thinking: None,
            system_prompt: system_prompt.map(str::to_owned),
            credential_capability: Some(test_credential_capability()),
            office_inference: None,
            sandbox: gaugedesk_harness::sandbox::SandboxPolicy::new(vec![worktree.to_path_buf()])
                .read_only(vec![worktree.join(".whipple")])
                .filter_egress(vec!["api.openai.com".to_owned(), "127.0.0.1".to_owned()]),
            roster: Vec::new(),
        }
    }

    fn continuity_turn(
        factory: &WhipHarnessFactory,
        spec: &HarnessSpec,
        origin: &str,
        prompt: &str,
    ) -> String {
        let mut harness = factory.create_harness(spec).expect("harness");
        harness.provider.base_url = origin.to_owned();
        let outcome = harness
            .run_turn(&gaugedesk_harness::AllowAllGate, prompt, &[], &mut |_| {})
            .unwrap();
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        harness.instance_ref.clone()
    }

    #[test]
    fn an_edit_chat_keeps_its_conversation_when_the_editor_persona_changes() {
        let root = tempfile::tempdir().expect("runtime root");
        let worktree = tempfile::tempdir().expect("worktree");
        let (origin, calls, server) = recording_provider(3);
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            root.path(),
        );
        let edit = gaugedesk_harness::ChatMode::Edit;
        let before = continuity_spec(worktree.path(), &origin, edit, None, Some("PERSONA ONE"));
        let after = continuity_spec(worktree.path(), &origin, edit, None, Some("PERSONA TWO"));

        continuity_turn(&factory, &before, &origin, "FIRST-REQUEST");
        let adopted = continuity_turn(&factory, &after, &origin, "SECOND-REQUEST");
        let reopened = continuity_turn(&factory, &after, &origin, "THIRD-REQUEST");
        server.join().unwrap();

        let calls = calls.lock().unwrap();
        let second = calls[1].to_string();
        assert!(second.contains("PERSONA TWO"), "the new persona applies");
        assert!(!second.contains("PERSONA ONE"));
        assert!(
            second.contains("FIRST-REQUEST"),
            "the first turn is still in the thread"
        );
        assert_eq!(reopened, adopted, "a reopen continues the adopted instance");
        let third = calls[2].to_string();
        assert!(third.contains("FIRST-REQUEST") && third.contains("SECOND-REQUEST"));
    }

    #[test]
    fn a_work_chat_keeps_its_conversation_across_agent_versions() {
        let root = tempfile::tempdir().expect("runtime root");
        let worktree = tempfile::tempdir().expect("worktree");
        let (origin, calls, server) = recording_provider(2);
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            root.path(),
        );
        let version = |number: u32, persona: &str| {
            let package_root = worktree.path().join(format!(".whipple/versions/{number}"));
            std::fs::create_dir_all(&package_root).unwrap();
            std::fs::write(
                package_root.join("package.json"),
                r#"{"schema":"whipplescript.agent_package.v0","source":"method.whip",
"workflow":"Method","agent":"assistant","system_prompt":"persona.md",
"capabilities":["workspace.read"],"agent_abilities":["workspace.read"],"max_steps":8}"#,
            )
            .unwrap();
            std::fs::write(
                package_root.join("method.whip"),
                r#"
file store project { root "." allow read ["**"] }
workflow Method {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
    capabilities ["workspace.read"]
  }
  rule converse when started => {
    tell assistant requires ["workspace.read"]
      with access to project { read ["**"] }
      "Run."
  }
}
"#,
            )
            .unwrap();
            std::fs::write(package_root.join("persona.md"), persona).unwrap();
            let reference = AuthoredAgentPackage::load(&package_root)
                .unwrap()
                .version_ref()
                .to_owned();
            (package_root, reference)
        };
        let (one_root, one_ref) = version(1, "VERSION ONE");
        let (two_root, two_ref) = version(2, "VERSION TWO");
        let use_mode = gaugedesk_harness::ChatMode::Use;
        let one = continuity_spec(
            worktree.path(),
            &origin,
            use_mode,
            Some((&one_root, &one_ref)),
            None,
        );
        let two = continuity_spec(
            worktree.path(),
            &origin,
            use_mode,
            Some((&two_root, &two_ref)),
            None,
        );

        continuity_turn(&factory, &one, &origin, "FIRST-REQUEST");
        continuity_turn(&factory, &two, &origin, "SECOND-REQUEST");
        server.join().unwrap();

        let second = calls.lock().unwrap()[1].to_string();
        assert!(second.contains("VERSION TWO") && !second.contains("VERSION ONE"));
        assert!(
            second.contains("FIRST-REQUEST"),
            "the first turn is still in the thread"
        );
    }

    fn signed_harness_policy_for_model(base_url: &str, model: &str) -> String {
        let authority = AuthorityId::new("authority:owner");
        let key = SigningKey::from_seed(&[7u8; 32]).expect("key");
        sign_policy_envelope(
            &harness_policy_for("openai", model, base_url, "openai-responses"),
            &authority,
            &key,
        )
        .expect("signed harness policy")
    }

    /// `before`'s chat reopened under epoch 2, whose envelope names another
    /// model: what switching an edit chat's model does.
    fn after_a_model_switch(before: &HarnessSpec, origin: &str) -> HarnessSpec {
        let mut after = before.clone();
        after.policy_epoch = Some(2);
        after.signed_policy_envelope =
            Some(signed_harness_policy_for_model(origin, "gpt-test-next"));
        after.model = Some("gpt-test-next".to_owned());
        after.prior_policy_envelopes =
            vec![(1, before.signed_policy_envelope.clone().expect("epoch 1"))];
        after
    }

    /// WS-660, DR-0412: a chat whose policy epoch advances because its model
    /// was switched keeps its conversation. On 2026-10-09 an edit chat moved
    /// from one model to another between turns, and the editor then denied
    /// having made the edits it had made, because it was started again.
    #[test]
    fn a_chat_keeps_its_conversation_when_its_model_is_switched() {
        let root = tempfile::tempdir().expect("runtime root");
        let worktree = tempfile::tempdir().expect("worktree");
        let (origin, calls, server) = recording_provider(3);
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            root.path(),
        );
        let edit = gaugedesk_harness::ChatMode::Edit;
        let before = continuity_spec(worktree.path(), &origin, edit, None, Some("EDITOR"));
        let after = after_a_model_switch(&before, &origin);

        let first = continuity_turn(&factory, &before, &origin, "FIRST-REQUEST");
        let carried = continuity_turn(&factory, &after, &origin, "SECOND-REQUEST");
        let reopened = continuity_turn(&factory, &after, &origin, "THIRD-REQUEST");
        server.join().unwrap();

        assert_ne!(carried, first, "the new epoch runs on its own instance");
        assert_eq!(reopened, carried, "a reopen continues the carried instance");
        let calls = calls.lock().unwrap();
        let second = calls[1].to_string();
        assert!(second.contains("gpt-test-next"), "{second}");
        assert!(
            second.contains("FIRST-REQUEST"),
            "the turn before the switch is still in the thread"
        );
        let third = calls[2].to_string();
        assert!(third.contains("FIRST-REQUEST") && third.contains("SECOND-REQUEST"));
    }

    /// DR-0412 §4: a chat whose conversation cannot be carried says why and
    /// does not start again beneath a transcript that shows earlier turns.
    #[test]
    fn a_chat_that_cannot_carry_its_conversation_says_so() {
        let root = tempfile::tempdir().expect("runtime root");
        let worktree = tempfile::tempdir().expect("worktree");
        let (origin, _calls, server) = recording_provider(1);
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            root.path(),
        );
        let edit = gaugedesk_harness::ChatMode::Edit;
        let before = continuity_spec(worktree.path(), &origin, edit, None, Some("EDITOR"));
        let mut after = after_a_model_switch(&before, &origin);
        after.prior_policy_envelopes.clear();

        continuity_turn(&factory, &before, &origin, "FIRST-REQUEST");
        server.join().unwrap();
        let Err(refused) = factory.create_harness(&after) else {
            panic!("a conversation recorded under an epoch not on record started again");
        };
        let refused = refused.to_string();
        assert!(refused.contains("could not be carried"), "{refused}");
        assert!(refused.contains("no longer on record"), "{refused}");
    }

    /// DR-0412 §3: a turn that never settled is neither carried nor guessed.
    /// The conversation continues from the turn before it, and the chat is
    /// told so once.
    #[test]
    fn a_turn_that_never_settled_is_cut_and_the_chat_says_so() {
        let root = tempfile::tempdir().expect("runtime root");
        let worktree = tempfile::tempdir().expect("worktree");
        let (origin, calls, server) = recording_provider(3);
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            root.path(),
        );
        let edit = gaugedesk_harness::ChatMode::Edit;
        let before = continuity_spec(worktree.path(), &origin, edit, None, Some("EDITOR"));
        let after = after_a_model_switch(&before, &origin);

        continuity_turn(&factory, &before, &origin, "FIRST-REQUEST");
        continuity_turn(&factory, &before, &origin, "LOST-REQUEST");
        // The second turn's effect is left running, as a crash mid-turn leaves it.
        let orphaned =
            rusqlite::Connection::open(chat_runtime_database(root.path(), &before.chat_id))
                .expect("chat runtime")
                .execute(
                    "UPDATE effects SET status = 'running' \
             WHERE rowid = (SELECT MAX(rowid) FROM effects WHERE kind = 'agent.tell')",
                    [],
                )
                .expect("orphan the second turn");
        assert_eq!(orphaned, 1);

        let mut harness = factory.create_harness(&after).expect("carried with a cut");
        let notice = harness
            .take_continuity_notice()
            .expect("the chat is told about the unresolved turn");
        assert!(notice.contains("did not finish"), "{notice}");
        assert!(harness.take_continuity_notice().is_none(), "said once");
        harness.provider.base_url = origin.clone();
        let outcome = harness
            .run_turn(
                &gaugedesk_harness::AllowAllGate,
                "AFTER-THE-CUT",
                &[],
                &mut |_| {},
            )
            .unwrap();
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        server.join().unwrap();

        let calls = calls.lock().unwrap();
        let third = calls[2].to_string();
        assert!(third.contains("FIRST-REQUEST"), "{third}");
        assert!(
            !third.contains("LOST-REQUEST"),
            "the unresolved turn is not carried: {third}"
        );
    }

    #[test]
    fn whip_harness_reopens_the_same_instance_and_owns_workspace_tools() {
        use std::sync::atomic::AtomicUsize;
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
  "capabilities":["workspace.read","workspace.write","command.run","tracker.file"],
  "agent_abilities":["workspace.read","workspace.write","command.run","tracker.file"],
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
    capabilities ["workspace.read", "workspace.write", "command.run", "tracker.file"]
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
            prior_policy_envelopes: Vec::new(),
            provider_binding_ref: Some("model".to_owned()),
            credential_ref: Some(
                "credential:gaugedesk/account/616c696365/6f70656e6169/v1".to_owned(),
            ),
            placement_ceiling_ref: Some("local".to_owned()),
            workspace_targets: Vec::new(),
            runtime_placement_id: Some("placement-test".to_owned()),
            provider: Some("openai".to_owned()),
            model: Some("gpt-test".to_owned()),
            base_url: None,
            thinking: None,
            system_prompt: None,
            credential_capability: Some(test_credential_capability()),
            office_inference: None,
            sandbox: gaugedesk_harness::sandbox::SandboxPolicy::new(vec![worktree
                .path()
                .to_path_buf()])
            .read_only(vec![worktree.path().join(".whipple")])
            .filter_egress(vec!["api.openai.com".to_owned()]),
            roster: Vec::new(),
        };
        let factory = WhipHarnessFactory::new(
            AuthorityId::new("authority:owner"),
            harness_policy_root(),
            root.path(),
        );
        let mut first = factory.create_harness(&spec).expect("first harness");
        assert!(first
            .package
            .resolve(first.package.version_ref())
            .unwrap()
            .tools
            .iter()
            .any(|tool| tool.name == "add_todo"));
        let unavailable = super::ProjectTaskPackage {
            inner: &first.package,
            task_filing_admitted: false,
            recipients: Vec::new(),
        };
        assert!(!unavailable
            .resolve_package(first.package.version_ref())
            .unwrap()
            .tools
            .iter()
            .any(|tool| tool.name == "add_todo"));
        assert!(!first
            .new_turn_command("question", &[], 1, None)
            .resources
            .iter()
            .any(|resource| resource.handle == "tasks"));
        struct AdmittedTask;
        impl gaugedesk_harness::TaskFiler for AdmittedTask {
            fn file_task(
                &self,
                _call_id: &str,
                _content: &str,
                _assigned_to: Option<&str>,
            ) -> Result<String, String> {
                Ok("issue-1".to_owned())
            }
        }
        first.bind_task_filer(Some(Arc::new(AdmittedTask)));
        let task_turn = first.new_turn_command("question", &[], 1, None);
        task_turn
            .validate()
            .expect("tracker is a valid host resource");
        assert!(
            first
                .initial_model_provenance(&task_turn, &[])
                .user
                .complete
        );
        let answer_sources = ["question-answer:chat-1:q-1:digest".to_owned()];
        first.bind_user_context_provenance(Some(&answer_sources));
        let answered = first.initial_model_provenance(&task_turn, &[]);
        assert!(answered.user.complete);
        assert_eq!(answered.user.source_handles[1], answer_sources[0]);
        first.bind_user_context_provenance(None);
        assert!(
            !first
                .initial_model_provenance(&task_turn, &[])
                .user
                .complete
        );
        first.bind_user_context_provenance(Some(&[]));
        let mut image_turn = task_turn.clone();
        image_turn.input.images.push(ResourceRef {
            handle: "turn_images".to_owned(),
            kind: "image".to_owned(),
            selector: Some("0".to_owned()),
            writable: None,
            presented_as: None,
        });
        assert!(
            !first
                .initial_model_provenance(&image_turn, &[])
                .user
                .complete
        );
        let image_body = ImageContent {
            kind: gaugedesk_harness::ImageKind::Image,
            data: "aW1hZ2U=".to_owned(),
            mime_type: "image/png".to_owned(),
        };
        let image_sources =
            first.initial_model_provenance(&image_turn, std::slice::from_ref(&image_body));
        assert!(image_sources.user.complete);
        assert_eq!(
            image_sources.user.source_handles[1],
            live_turn_image_source("chat-1", &image_body).unwrap()
        );
        assert!(task_turn.resources.iter().any(|resource| {
            resource.handle == "tasks" && resource.kind == "tracker" && resource.writable.is_none()
        }));
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
        // First check is the GaugeDesk turn-entry check; the owner must call
        // the actual TurnResources hook next, before any provider resolution.
        struct EndsAtOwner(std::sync::atomic::AtomicUsize);
        impl gaugedesk_harness::TurnAccess for EndsAtOwner {
            fn check_current(&self) -> Result<(), String> {
                if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    Ok(())
                } else {
                    Err("private authority detail must not escape".into())
                }
            }
        }
        let access = Arc::new(EndsAtOwner(std::sync::atomic::AtomicUsize::new(0)));
        struct RequiredPayloads;
        impl gaugedesk_harness::WorkspacePayloadRetention for RequiredPayloads {
            fn retain(
                &self,
                _: &gaugedesk_harness::PreparedWorkspaceFile,
                _: &[u8],
            ) -> Result<(), String> {
                Err("synthetic custody fixture refuses mutation".into())
            }
        }
        struct CurrentAccess;
        impl gaugedesk_harness::TurnAccess for CurrentAccess {
            fn check_current(&self) -> Result<(), String> {
                Ok(())
            }
        }
        first
            .bind_turn_access(Some(Arc::new(CurrentAccess)))
            .unwrap();
        let missing_before = first.runtime.current_position(&first.instance_ref).unwrap();
        let missing = first
            .run_turn(
                &gaugedesk_harness::AllowAllGate,
                "synthetic clinical input",
                &[],
                &mut |_| {},
            )
            .unwrap_err();
        assert!(missing
            .to_string()
            .contains("office workspace payload retention unavailable"));
        assert_eq!(
            first.runtime.current_position(&first.instance_ref).unwrap(),
            missing_before
        );
        first.bind_turn_access(Some(access.clone())).unwrap();
        first
            .bind_workspace_payload_retention(Some(Arc::new(RequiredPayloads)))
            .unwrap();
        let before = first.runtime.current_position(&first.instance_ref).unwrap();
        let mut observations = Vec::new();
        let refusal = first
            .run_turn(
                &gaugedesk_harness::AllowAllGate,
                "synthetic clinical input",
                &[],
                &mut |observation| observations.push(observation.clone()),
            )
            .unwrap_err();
        assert!(access.0.load(std::sync::atomic::Ordering::SeqCst) >= 2);
        assert!(
            refusal.to_string().contains("host turn access ended"),
            "{refusal}"
        );
        assert!(!refusal.to_string().contains("private authority detail"));
        assert!(observations.is_empty());
        assert_eq!(
            first.runtime.current_position(&first.instance_ref).unwrap(),
            before
        );
        assert!(first.turn_access.is_none());
        assert!(first.payload_retention.is_none());
        first.bind_turn_access(Some(access)).unwrap();
        first.bind_turn_access(None).unwrap();
        assert!(first.turn_access.is_none());
        // Run the actual product TurnResources through the owner runtime. The
        // response script is local; no network or hosted model is involved.
        use whipplescript_kernel::sansio::{HostDriver, IoRequest, IoResult};
        struct WitnessDriver(std::cell::RefCell<std::collections::VecDeque<serde_json::Value>>);
        impl HostDriver for WitnessDriver {
            fn fulfill(&self, _request: &IoRequest) -> IoResult {
                IoResult::Http(Ok(sansio_types::HttpResponse {
                    status: 200,
                    body: self.0.borrow_mut().pop_front().expect("scripted response"),
                }))
            }
        }
        let command = first.new_turn_command("write synthetic fixture", &[], 2, None);
        assert!(first
            .prepare_runtime_turn("write synthetic fixture", &[])
            .is_err());
        first.bind_runtime_command_id(Some(&command.command_id));
        let image = ImageContent {
            kind: gaugedesk_harness::ImageKind::Image,
            data: "AA==".into(),
            mime_type: "image/png".into(),
        };
        let mut changed_image = image.clone();
        changed_image.data = "AQ==".into();
        let before_images = first.runtime.pinned_position(&first.instance_ref).unwrap();
        let image_prepared = first
            .prepare_runtime_turn("write synthetic fixture", std::slice::from_ref(&image))
            .unwrap();
        let same_index_command = first.new_turn_command(
            "write synthetic fixture",
            std::slice::from_ref(&changed_image),
            0,
            Some(command.command_id.clone()),
        );
        assert_eq!(
            serde_json::from_str::<StartTurnCommand>(&image_prepared.command_json).unwrap(),
            same_index_command
        );
        assert!(first
            .prepare_runtime_turn(
                "write synthetic fixture",
                std::slice::from_ref(&changed_image)
            )
            .unwrap_err()
            .to_string()
            .contains("prepared runtime intent changed"));
        let mut changed_mime = image.clone();
        changed_mime.mime_type = "image/jpeg".into();
        assert!(first
            .prepare_runtime_turn("write synthetic fixture", &[changed_mime])
            .is_err());
        assert_eq!(
            first
                .prepare_runtime_turn("write synthetic fixture", &[image])
                .unwrap(),
            image_prepared
        );
        let refusal = first
            .run_turn(
                &gaugedesk_harness::AllowAllGate,
                "write synthetic fixture",
                &[changed_image],
                &mut |_| {},
            )
            .unwrap_err();
        assert!(
            refusal
                .to_string()
                .contains("prepared runtime intent changed"),
            "{refusal}"
        );
        assert_eq!(
            first.runtime.pinned_position(&first.instance_ref).unwrap(),
            before_images
        );
        assert!(first.prepared_runtime.is_none());
        first.bind_runtime_command_id(Some(&command.command_id));
        let original_start = first.runtime.pinned_position(&first.instance_ref).unwrap();
        struct PreparationAccess {
            calls: AtomicUsize,
            deny_at: usize,
        }
        impl gaugedesk_harness::TurnAccess for PreparationAccess {
            fn check_current(&self) -> Result<(), String> {
                if self.calls.fetch_add(1, Ordering::SeqCst) + 1 >= self.deny_at {
                    Err("private preparation authority detail".into())
                } else {
                    Ok(())
                }
            }
        }
        for deny_at in [1, 2] {
            let access = Arc::new(PreparationAccess {
                calls: AtomicUsize::new(0),
                deny_at,
            });
            first.bind_turn_access(Some(access.clone())).unwrap();
            let error = first
                .prepare_runtime_turn("write synthetic fixture", &[])
                .unwrap_err();
            assert!(!error
                .to_string()
                .contains("private preparation authority detail"));
            assert_eq!(access.calls.load(Ordering::SeqCst), deny_at);
            assert!(first.prepared_runtime.is_none());
            assert_eq!(
                first.runtime.pinned_position(&first.instance_ref).unwrap(),
                original_start
            );
        }
        first.bind_turn_access(None).unwrap();
        let prepared = first
            .prepare_runtime_turn("write synthetic fixture", &[])
            .unwrap();
        assert_eq!(
            serde_json::from_str::<StartTurnCommand>(&prepared.command_json).unwrap(),
            command
        );
        assert_eq!(
            prepared.start_position.instance_ref,
            original_start.instance_ref
        );
        assert_eq!(prepared.start_position.sequence, original_start.sequence);
        assert_eq!(prepared.start_head_digest, original_start.head_digest);
        assert!(!prepared.command_json.contains("test-key"));
        assert_eq!(
            first.runtime.pinned_position(&first.instance_ref).unwrap(),
            original_start
        );
        assert_eq!(
            first
                .prepare_runtime_turn("write synthetic fixture", &[])
                .unwrap(),
            prepared
        );
        assert!(first
            .prepare_runtime_turn("changed original task", &[])
            .is_err());
        let mut sink = |_observation: &Observation| {};
        type CapturedPayloads =
            Arc<Mutex<Vec<(gaugedesk_harness::PreparedWorkspaceFile, Vec<u8>)>>>;
        #[derive(Clone)]
        struct CapturePayloads(CapturedPayloads);
        impl gaugedesk_harness::WorkspacePayloadRetention for CapturePayloads {
            fn retain(
                &self,
                file: &gaugedesk_harness::PreparedWorkspaceFile,
                body: &[u8],
            ) -> Result<(), String> {
                self.0.lock().unwrap().push((file.clone(), body.to_vec()));
                Ok(())
            }
        }
        let captures = Arc::new(Mutex::new(Vec::new()));
        let retained_workspace = first
            .workspace_with_retention(Some(Arc::new(CapturePayloads(captures.clone()))))
            .unwrap()
            .unwrap();
        let resources = TurnResources {
            workspace: &retained_workspace,
            workspace_resources: &command.resources,
            chat_id: &first.chat_id,
            mode: first.mode,
            images: &[],
            task_filer: None,
            external_tool_handler: None,
            access: None,
            command_id: command.command_id.clone(),
            live: std::cell::RefCell::new(&mut sink),
            streamed: std::cell::Cell::new(false),
            office_request_url: None,
            managed_call_meter: None,
        };
        let driver = WitnessDriver(std::cell::RefCell::new(std::collections::VecDeque::from([
            serde_json::json!({ "output": [{ "type":"function_call", "call_id":"write-one", "name":"write", "arguments":"{\"path\":\"result.txt\",\"content\":\"synthetic result\"}" }], "usage":{"input_tokens":10,"output_tokens":2} }),
            serde_json::json!({ "output_text":"wrote the fixture", "usage":{"input_tokens":12,"output_tokens":3} }),
        ])));
        let provenance = first.initial_model_provenance(&command, &[]);
        let execution = first
            .runtime
            .run_turn_with_driver_and_provenance(
                &command,
                &first.package,
                &first.provider,
                &resources,
                &driver,
                &provenance,
            )
            .expect("native witnessed turn");
        // Typed projection probe; these synthetic calls are never stored or executed.
        let question_arguments = serde_json::json!({ "question": " Choose a path ",
            "choices": ["first", 3, "second"], "to": "staff", "blocking": true });
        let mut question_execution = execution.clone();
        let question_call = ProjectedToolCall {
            call_id: "synthetic-question".into(),
            name: "ask".into(),
            arguments: question_arguments.clone(),
            result: Some("{\"asked\":true}".into()),
            ok: Some(true),
        };
        question_execution.output.as_mut().unwrap().segments =
            vec![TurnContentSegment::Tool(question_call.clone())];
        let projected = project_turn_execution(
            question_execution.clone(),
            Vec::new(),
            &command,
            &mut |_| {},
            false,
        )
        .unwrap();
        assert_eq!(
            projected.asked_questions,
            vec![gaugedesk_harness::AskedQuestion {
                question: "Choose a path".into(),
                choices: vec!["first".into(), "second".into()],
                to: Some("staff".into()),
                blocking: true,
            }]
        );
        for status in [Some(false), None] {
            let mut failed = question_execution.clone();
            let mut call = question_call.clone();
            call.ok = status;
            failed.output.as_mut().unwrap().segments = vec![TurnContentSegment::Tool(call)];
            assert!(
                project_turn_execution(failed, Vec::new(), &command, &mut |_| {}, false)
                    .unwrap()
                    .asked_questions
                    .is_empty()
            );
        }
        let mut invalid = question_execution;
        let mut call = question_call;
        call.arguments = serde_json::json!({ "question": " " });
        invalid.output.as_mut().unwrap().segments = vec![TurnContentSegment::Tool(call)];
        assert!(project_turn_execution(invalid, Vec::new(), &command, &mut |_| {}, false).is_err());
        let receipt = execution.receipt.unwrap();
        receipt.validate_for(&command).unwrap();
        assert_eq!(receipt.status, TurnStatus::Completed);
        let cut_ref = receipt
            .workspace_cut_ref
            .as_ref()
            .expect("the actual adapter must preserve the complete owner witness");
        let recorded = whipplescript_store::SqliteStore::open_read_only(chat_runtime_database(
            root.path(),
            &spec.chat_id,
        ))
        .unwrap()
        .list_evidence(&command.instance_ref)
        .unwrap()
        .into_iter()
        .find(|evidence| &evidence.evidence_id == cut_ref)
        .unwrap();
        assert_eq!(recorded.kind, "host.turn.workspace_cut");
        assert_eq!(
            recorded.correlation_id.as_deref(),
            Some(command.command_id.as_str())
        );
        let body: serde_json::Value = serde_json::from_str(&recorded.metadata_json).unwrap();
        assert_eq!(body["complete"], true);
        let writes = body["writes"].as_array().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0]["path"], "result.txt");
        assert_eq!(writes[0]["kind"], "add");
        assert_eq!(writes[0]["bytes"], 16);
        let captured = captures.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].0.path, "result.txt");
        assert_eq!(captured[0].0.kind, "add");
        assert_eq!(captured[0].0.bytes, 16);
        assert_eq!(captured[0].0.sha256, stable_text_hash("synthetic result"));
        assert_eq!(captured[0].1, b"synthetic result");
        drop(captured);
        assert_eq!(
            writes[0]["content_hash"],
            stable_text_hash("synthetic result")
        );
        assert_eq!(
            std::fs::read(worktree.path().join("result.txt")).unwrap(),
            b"synthetic result"
        );
        assert!(driver.0.borrow().is_empty());
        assert!(
            matches!(resources.take_turn_witness(), TurnWitness::Witnessed { writes, reads } if writes.is_empty() && reads.is_empty())
        );
        let mut absent = command.clone();
        absent.command_id = "unrecorded-original-command".into();
        assert!(
            original_workspace_witness(&first.runtime, &absent, &resources, None)
                .unwrap()
                .is_none()
        );
        let missing =
            original_workspace_witness(&first.runtime, &absent, &resources, Some(&receipt))
                .unwrap_err();
        assert!(missing
            .to_string()
            .contains("original runtime workspace witness unavailable"));
        let mut changed_receipt = receipt.clone();
        changed_receipt.command_id = "another-completed-command".into();
        let changed = original_workspace_witness(
            &first.runtime,
            &command,
            &resources,
            Some(&changed_receipt),
        )
        .unwrap_err();
        assert!(changed
            .to_string()
            .contains("original runtime workspace receipt changed"));
        drop(resources);
        std::fs::write(worktree.path().join("result.txt"), "later unadmitted edit").unwrap();
        std::fs::write(
            worktree.path().join("unrelated.txt"),
            "unrelated pending work",
        )
        .unwrap();
        let original_position = first.runtime.current_position(&first.instance_ref).unwrap();
        assert!(original_position.sequence > prepared.start_position.sequence);
        struct OriginalReadAccess;
        impl gaugedesk_harness::TurnAccess for OriginalReadAccess {
            fn check_current(&self) -> Result<(), String> {
                Ok(())
            }
        }
        let read_spec = gaugedesk_harness::RecordedRuntimeSpec {
            chat_id: &spec.chat_id,
            command_id: &command.command_id,
            policy_epoch: spec.policy_epoch.unwrap(),
            signed_policy_envelope: spec.signed_policy_envelope.as_deref().unwrap(),
            preparation: &prepared,
            images: &[],
            access: &OriginalReadAccess,
        };
        assert_eq!(
            factory.recorded_policy_epoch(&prepared).unwrap(),
            spec.policy_epoch.unwrap()
        );
        let database = chat_runtime_database(root.path(), &spec.chat_id);
        let before_read = std::fs::read(&database).unwrap();
        let observed = factory.observe_recorded_runtime(&read_spec).unwrap();
        assert_eq!(
            observed.runtime_start_position,
            Some(prepared.start_position.clone())
        );
        let saved_witness = observed.runtime_workspace_witness.unwrap();
        assert_eq!(
            serde_json::from_str::<TurnReceipt>(&saved_witness.receipt_json).unwrap(),
            receipt
        );
        assert_eq!(saved_witness.writes.len(), 1);
        assert_eq!(
            saved_witness.writes[0].content_hash,
            stable_text_hash("synthetic result")
        );
        assert_eq!(std::fs::read(&database).unwrap(), before_read);
        assert_eq!(
            first.runtime.current_position(&first.instance_ref).unwrap(),
            original_position
        );
        assert_eq!(
            std::fs::read(worktree.path().join("result.txt")).unwrap(),
            b"later unadmitted edit"
        );
        let mut changed = prepared.clone();
        changed.input_digest = gaugedesk_harness::runtime_input_digest("substituted prompt", &[]);
        let changed_spec = gaugedesk_harness::RecordedRuntimeSpec {
            preparation: &changed,
            ..read_spec
        };
        assert!(factory
            .observe_recorded_runtime(&changed_spec)
            .unwrap_err()
            .to_string()
            .contains("original runtime preparation changed"));
        struct CountingReadAccess {
            calls: AtomicUsize,
            deny_at: usize,
        }
        impl gaugedesk_harness::TurnAccess for CountingReadAccess {
            fn check_current(&self) -> Result<(), String> {
                if self.calls.fetch_add(1, Ordering::SeqCst) + 1 >= self.deny_at {
                    Err("private authority detail".into())
                } else {
                    Ok(())
                }
            }
        }
        let counted = CountingReadAccess {
            calls: AtomicUsize::new(0),
            deny_at: usize::MAX,
        };
        let counted_spec = gaugedesk_harness::RecordedRuntimeSpec {
            access: &counted,
            ..read_spec
        };
        factory.observe_recorded_runtime(&counted_spec).unwrap();
        let count = counted.calls.load(Ordering::SeqCst);
        assert!(count > 2);
        for deny_at in 1..=count {
            let access = CountingReadAccess {
                calls: AtomicUsize::new(0),
                deny_at,
            };
            let revoked_spec = gaugedesk_harness::RecordedRuntimeSpec {
                access: &access,
                ..read_spec
            };
            let error = factory
                .observe_recorded_runtime(&revoked_spec)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("private authority detail"));
            assert_eq!(std::fs::read(&database).unwrap(), before_read);
            assert_eq!(
                first.runtime.current_position(&first.instance_ref).unwrap(),
                original_position
            );
        }
        let mut absent_command = command.clone();
        absent_command.command_id = "unrecorded-original-command".into();
        let mut absent_preparation = prepared.clone();
        absent_preparation.command_json = serde_json::to_string(&absent_command).unwrap();
        let absent_spec = gaugedesk_harness::RecordedRuntimeSpec {
            command_id: &absent_command.command_id,
            preparation: &absent_preparation,
            ..read_spec
        };
        assert!(factory
            .observe_recorded_runtime(&absent_spec)
            .unwrap_err()
            .to_string()
            .contains("original saved runtime execution unavailable"));
        let invalid_policy_spec = gaugedesk_harness::RecordedRuntimeSpec {
            signed_policy_envelope: "invalid signed original policy",
            ..read_spec
        };
        assert!(factory
            .observe_recorded_runtime(&invalid_policy_spec)
            .is_err());
        assert_eq!(std::fs::read(&database).unwrap(), before_read);
        let missing_chat = "absent-native-runtime";
        let missing_spec = gaugedesk_harness::RecordedRuntimeSpec {
            chat_id: missing_chat,
            ..read_spec
        };
        assert!(factory.observe_recorded_runtime(&missing_spec).is_err());
        assert!(!chat_runtime_database(root.path(), missing_chat).exists());
        struct RemovedReadAccess;
        impl gaugedesk_harness::TurnAccess for RemovedReadAccess {
            fn check_current(&self) -> Result<(), String> {
                Err("private reason".into())
            }
        }
        let denied_spec = gaugedesk_harness::RecordedRuntimeSpec {
            access: &RemovedReadAccess,
            ..read_spec
        };
        let denied = factory
            .observe_recorded_runtime(&denied_spec)
            .unwrap_err()
            .to_string();
        assert!(denied.contains("original turn access ended"));
        assert!(!denied.contains("private reason"));
        assert_eq!(std::fs::read(&database).unwrap(), before_read);

        assert_eq!(
            first
                .prepare_runtime_turn("write synthetic fixture", &[])
                .unwrap(),
            prepared
        );
        for substitution in ["command", "targets"] {
            let mut changed = prepared.clone();
            if substitution == "command" {
                let mut intent = command.clone();
                intent.input.text.push_str("changed");
                changed.command_json = serde_json::to_string(&intent).unwrap();
            } else {
                changed
                    .workspace_targets
                    .push(gaugedesk_harness::WorkspaceTargetBinding {
                        target_id: "substituted-target".into(),
                        resource_handle: "substituted".into(),
                        root: worktree.path().to_string_lossy().into_owned(),
                        name: String::new(),
                        readable: true,
                        writable: false,
                        output: false,
                    });
            }
            first.prepared_runtime = Some(changed);
            first.bind_runtime_command_id(Some(&command.command_id));
            assert!(first
                .run_turn(
                    &gaugedesk_harness::AllowAllGate,
                    "write synthetic fixture",
                    &[],
                    &mut sink
                )
                .unwrap_err()
                .to_string()
                .contains("prepared runtime intent changed"));
            assert_eq!(
                first.runtime.current_position(&first.instance_ref).unwrap(),
                original_position
            );
        }
        first.prepared_runtime = Some(prepared.clone());
        first.bind_runtime_command_id(Some(&command.command_id));
        let replay = first
            .run_turn(
                &gaugedesk_harness::AllowAllGate,
                "write synthetic fixture",
                &[],
                &mut sink,
            )
            .expect("actual native harness retained replay");
        assert_eq!(
            replay.runtime_start_position.as_ref(),
            Some(&prepared.start_position)
        );
        assert!(first.prepared_runtime.is_none());
        let witness = replay
            .runtime_workspace_witness
            .expect("original owner witness in outcome");
        let carried_receipt: TurnReceipt = serde_json::from_str(&witness.receipt_json).unwrap();
        assert_eq!(carried_receipt, receipt);
        assert_eq!(witness.writes.len(), 1);
        assert_eq!(witness.writes[0].path, "result.txt");
        assert_eq!(witness.writes[0].kind, "add");
        assert_eq!(
            witness.writes[0].content_hash,
            stable_text_hash("synthetic result")
        );
        assert_eq!(witness.writes[0].bytes, 16);
        assert_eq!(
            first.runtime.current_position(&first.instance_ref).unwrap(),
            original_position
        );
        assert_eq!(
            std::fs::read(worktree.path().join("result.txt")).unwrap(),
            b"later unadmitted edit"
        );
        let instance = first.instance_ref.clone();
        drop(first);
        let mut reopened = factory.create_harness(&spec).expect("reopened harness");
        reopened.bind_task_filer(Some(Arc::new(AdmittedTask)));
        reopened.bind_runtime_command_id(Some(&command.command_id));
        let replay = reopened
            .run_turn(
                &gaugedesk_harness::AllowAllGate,
                "write synthetic fixture",
                &[],
                &mut sink,
            )
            .expect("actual restarted native harness replay");
        assert_eq!(replay.runtime_workspace_witness.as_ref(), Some(&witness));
        assert_eq!(
            reopened.runtime.current_position(&instance).unwrap(),
            original_position
        );
        assert_eq!(reopened.instance_ref, instance);
        let mut changed_policy = spec.clone();
        changed_policy.policy_epoch = Some(2);
        // The engine hands a reopened chat the epochs before its current one,
        // so its conversation is carried into the new instance (DR-0412).
        changed_policy.prior_policy_envelopes =
            vec![(1, spec.signed_policy_envelope.clone().expect("epoch 1"))];
        let changed = factory
            .create_harness(&changed_policy)
            .expect("new policy epoch opens a new instance");
        assert_ne!(changed.instance_ref, instance);
        assert_eq!(
            factory
                .create_harness(&changed_policy)
                .expect("replay under the new epoch")
                .instance_ref,
            changed.instance_ref
        );
        let exact_source_position = reopened
            .runtime
            .current_position(&reopened.instance_ref)
            .expect("source position");

        let respondent = AuthorityId::new("authority:authenticated-member");
        // A chat's epoch only advances, so the newest one opens it now.
        let mut attributed = factory
            .create_harness(&changed_policy)
            .expect("attributed harness");
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
            harness_policy_root(),
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

    /// HIPAA-2: a turn bound to an office-approved inference endpoint.
    mod office_inference {
        use super::*;
        use gaugedesk_harness::{OfficeInferenceEndpoint, OfficeTlsIdentity};
        use std::io::Write as _;
        use std::net::{SocketAddr, TcpListener};

        const MODEL: &str = "office-llm";

        /// One request a loopback listener received: request line, lowercase
        /// headers and body.
        struct Received {
            line: String,
            headers: String,
            body: serde_json::Value,
        }

        /// Accept up to `turns` connections within the deadline, answer each
        /// with `respond`, and return what arrived. A listener nobody calls
        /// returns an empty list rather than hanging the test.
        fn listener(
            turns: usize,
            respond: fn(&Received, &mut std::net::TcpStream),
        ) -> (SocketAddr, std::thread::JoinHandle<Vec<Received>>) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let mut received = Vec::new();
                let deadline = Instant::now() + Duration::from_secs(10);
                while received.len() < turns {
                    let mut socket = match listener.accept() {
                        Ok((socket, _)) => socket,
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        Err(_) => break,
                    };
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let mut chunk = [0; 4096];
                    let start = loop {
                        let count = socket.read(&mut chunk).unwrap_or(0);
                        if count == 0 {
                            break None;
                        }
                        bytes.extend_from_slice(&chunk[..count]);
                        if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                            break Some(index + 4);
                        }
                    };
                    // A connection that sends no request (a test waking the
                    // listener) is counted as an empty arrival.
                    let Some(start) = start else {
                        received.push(Received {
                            line: String::new(),
                            headers: String::new(),
                            body: serde_json::Value::Null,
                        });
                        continue;
                    };
                    let head = String::from_utf8_lossy(&bytes[..start]).to_string();
                    let (line, headers) = head.split_once("\r\n").unwrap();
                    let headers = headers.to_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    while bytes.len() < start + length {
                        let count = socket.read(&mut chunk).unwrap();
                        assert!(count > 0);
                        bytes.extend_from_slice(&chunk[..count]);
                    }
                    let request = Received {
                        line: line.to_owned(),
                        headers,
                        body: serde_json::from_slice(&bytes[start..start + length])
                            .unwrap_or(serde_json::Value::Null),
                    };
                    respond(&request, &mut socket);
                    received.push(request);
                }
                received
            });
            (address, server)
        }

        fn answer(request: &Received, socket: &mut std::net::TcpStream) {
            let usage = serde_json::json!({"prompt_tokens": 1, "completion_tokens": 1});
            let (content_type, wire) = if request.headers.contains("text/event-stream") {
                (
                    "text/event-stream",
                    format!(
                        "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
                        serde_json::json!({"choices":[{"index":0,"delta":{"role":"assistant","content":"Done."}}]}),
                        serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":usage}),
                    ),
                )
            } else {
                (
                    "application/json",
                    serde_json::json!({
                        "choices":[{"index":0,"message":{"role":"assistant","content":"Done."},"finish_reason":"stop"}],
                        "usage":usage,
                    })
                    .to_string(),
                )
            };
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{wire}",
                wire.len()
            )
            .unwrap();
        }

        fn office(base_url: &str, addresses: Vec<SocketAddr>) -> OfficeInferenceEndpoint {
            OfficeInferenceEndpoint {
                base_url: base_url.to_owned(),
                model: MODEL.to_owned(),
                addresses,
                tls: None,
            }
        }

        /// The spec an office enrollment would hand the runtime: the approved
        /// endpoint as an `openai-generic` provider, signed into the policy,
        /// with egress admitted to the endpoint host alone.
        fn office_spec(
            worktree: &Path,
            base_url: &str,
            office: OfficeInferenceEndpoint,
        ) -> HarnessSpec {
            let host = openai_generic_endpoint_host(base_url).unwrap();
            let authority = AuthorityId::new("authority:owner");
            let key = SigningKey::from_seed(&[7u8; 32]).expect("key");
            let policy =
                harness_policy_for("openai-generic", MODEL, base_url, "openai-chat-compat");
            HarnessSpec {
                chat_id: "chat-office".to_owned(),
                worktree: worktree.to_path_buf(),
                mode: gaugedesk_harness::ChatMode::Edit,
                package_root: None,
                package_version_ref: None,
                policy_epoch: Some(1),
                signed_policy_envelope: Some(
                    sign_policy_envelope(&policy, &authority, &key).expect("signed policy"),
                ),
                prior_policy_envelopes: Vec::new(),
                provider_binding_ref: Some("model".to_owned()),
                credential_ref: Some(
                    "credential:gaugedesk/account/616c696365/6f70656e6169/v1".to_owned(),
                ),
                placement_ceiling_ref: Some("local".to_owned()),
                workspace_targets: Vec::new(),
                runtime_placement_id: Some("placement-office".to_owned()),
                provider: Some("openai-generic".to_owned()),
                model: Some(MODEL.to_owned()),
                base_url: Some(base_url.to_owned()),
                thinking: None,
                system_prompt: Some("You are the office assistant.".to_owned()),
                credential_capability: Some(test_credential_capability()),
                office_inference: Some(office),
                sandbox: gaugedesk_harness::sandbox::SandboxPolicy::new(vec![
                    worktree.to_path_buf()
                ])
                .read_only(vec![worktree.join(".whipple")])
                .filter_egress(vec![host]),
                roster: Vec::new(),
            }
        }

        fn factory(root: &Path) -> WhipHarnessFactory {
            WhipHarnessFactory::new(
                AuthorityId::new("authority:owner"),
                harness_policy_root(),
                root,
            )
        }

        fn refused(spec: &HarnessSpec) -> String {
            let error = ProviderConfig::from_spec(spec)
                .err()
                .expect("the office binding must refuse");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
            error.to_string()
        }

        /// The real journey: a whole governed turn reaches the approved
        /// loopback endpoint through the pinned transport, with the linked
        /// credential and the approved model, and nowhere else.
        #[test]
        fn an_office_turn_reaches_the_approved_loopback_endpoint() {
            let root = tempfile::tempdir().unwrap();
            let worktree = tempfile::tempdir().unwrap();
            let (address, server) = listener(1, answer);
            let base_url = format!("http://{address}/v1");
            let spec = office_spec(worktree.path(), &base_url, office(&base_url, vec![address]));

            let mut harness = factory(root.path())
                .create_harness(&spec)
                .expect("office harness");
            let outcome = harness
                .run_turn(
                    &gaugedesk_harness::AllowAllGate,
                    "OFFICE-PROMPT",
                    &[],
                    &mut |_| {},
                )
                .expect("office turn");
            assert!(outcome.error.is_none(), "{:?}", outcome.error);

            let received = server.join().unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].line, "POST /v1/chat/completions HTTP/1.1");
            assert!(received[0]
                .headers
                .contains("authorization: bearer test-key"));
            assert_eq!(received[0].body["model"], MODEL);
            assert!(received[0].body.to_string().contains("OFFICE-PROMPT"));
        }

        /// The pinned transport, not admission alone, carries the request: an
        /// endpoint changed after admission (as a later host override would)
        /// is refused at send, and the other listener never sees the prompt.
        #[test]
        fn an_endpoint_changed_after_admission_is_refused_at_send() {
            let root = tempfile::tempdir().unwrap();
            let worktree = tempfile::tempdir().unwrap();
            let (address, server) = listener(1, answer);
            let (other, other_server) = listener(1, answer);
            let base_url = format!("http://{address}/v1");
            let spec = office_spec(worktree.path(), &base_url, office(&base_url, vec![address]));

            let mut harness = factory(root.path()).create_harness(&spec).unwrap();
            harness.provider.base_url = format!("http://{other}/v1");
            let failed = match harness.run_turn(
                &gaugedesk_harness::AllowAllGate,
                "CHANGED-PROMPT",
                &[],
                &mut |_| {},
            ) {
                Ok(outcome) => outcome.error.is_some(),
                Err(_) => true,
            };
            assert!(failed, "a changed endpoint must stop the turn");
            for (wake, server) in [(address, server), (other, other_server)] {
                let _ = std::net::TcpStream::connect(wake);
                assert!(server
                    .join()
                    .unwrap()
                    .iter()
                    .all(|request| request.line.is_empty()));
            }
        }

        /// Restart: a fresh factory over the same runtime root, as after a
        /// process restart, admits the same binding again and reaches only the
        /// approved endpoint — and refuses it again when the selection drifted.
        #[test]
        fn a_restarted_runtime_re_admits_the_binding_and_nothing_wider() {
            let root = tempfile::tempdir().unwrap();
            let worktree = tempfile::tempdir().unwrap();
            let (address, server) = listener(2, answer);
            let base_url = format!("http://{address}/v1");
            let spec = office_spec(worktree.path(), &base_url, office(&base_url, vec![address]));
            for prompt in ["BEFORE-RESTART", "AFTER-RESTART"] {
                let mut harness = factory(root.path()).create_harness(&spec).unwrap();
                let outcome = harness
                    .run_turn(&gaugedesk_harness::AllowAllGate, prompt, &[], &mut |_| {})
                    .unwrap();
                assert!(outcome.error.is_none(), "{:?}", outcome.error);
            }
            assert_eq!(server.join().unwrap().len(), 2);

            let mut drifted = spec;
            drifted.model = Some("cloud-model".to_owned());
            assert!(factory(root.path()).create_harness(&drifted).is_err());
        }

        /// Outage: the approved endpoint is down. The turn stops with an error
        /// and no request reaches any other address; there is no fallback.
        #[test]
        fn an_office_outage_stops_the_turn_without_fallback() {
            let root = tempfile::tempdir().unwrap();
            let worktree = tempfile::tempdir().unwrap();
            let down = TcpListener::bind("127.0.0.1:0").unwrap();
            let down_address = down.local_addr().unwrap();
            drop(down);
            let (decoy, decoy_server) = listener(1, answer);
            let base_url = format!("http://{down_address}/v1");
            let spec = office_spec(
                worktree.path(),
                &base_url,
                office(&base_url, vec![down_address]),
            );

            let mut harness = factory(root.path()).create_harness(&spec).unwrap();
            let failed = match harness.run_turn(
                &gaugedesk_harness::AllowAllGate,
                "OUTAGE-PROMPT",
                &[],
                &mut |_| {},
            ) {
                Ok(outcome) => outcome.error.is_some(),
                Err(_) => true,
            };
            assert!(failed, "an unreachable office endpoint must stop the turn");
            // Wake the decoy so its thread ends; it must have seen nothing but this.
            let _ = std::net::TcpStream::connect(decoy);
            let seen = decoy_server.join().unwrap();
            assert!(seen.iter().all(|request| request.line.is_empty()));
        }

        /// Redirect: the approved endpoint answers with a redirect to another
        /// listener. The pinned transport follows nothing; the second listener
        /// never sees the prompt.
        #[test]
        fn an_office_endpoint_redirect_is_never_followed() {
            static DECOY: OnceLock<SocketAddr> = OnceLock::new();
            fn redirect(_: &Received, socket: &mut std::net::TcpStream) {
                write!(
                    socket,
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{}/v1/chat/completions\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    DECOY.get().unwrap()
                )
                .unwrap();
            }
            let (decoy, decoy_server) = listener(1, answer);
            DECOY.set(decoy).unwrap();
            let root = tempfile::tempdir().unwrap();
            let worktree = tempfile::tempdir().unwrap();
            let (address, server) = listener(1, redirect);
            let base_url = format!("http://{address}/v1");
            let spec = office_spec(worktree.path(), &base_url, office(&base_url, vec![address]));
            let mut harness = factory(root.path()).create_harness(&spec).unwrap();
            let failed = match harness.run_turn(
                &gaugedesk_harness::AllowAllGate,
                "REDIRECT-PROMPT",
                &[],
                &mut |_| {},
            ) {
                Ok(outcome) => outcome.error.is_some(),
                Err(_) => true,
            };
            assert!(failed, "a redirected office request must stop the turn");
            let received = server.join().unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].line, "POST /v1/chat/completions HTTP/1.1");
            // Wake the decoy; the only arrival it may have is this empty one.
            let _ = std::net::TcpStream::connect(decoy);
            let seen = decoy_server.join().unwrap();
            assert!(seen.iter().all(|request| request.line.is_empty()));
        }

        /// A host, chat or credential override of provider, model or endpoint
        /// is refused rather than reached.
        #[test]
        fn an_office_binding_refuses_every_override() {
            let worktree = tempfile::tempdir().unwrap();
            let address: SocketAddr = "127.0.0.1:18080".parse().unwrap();
            let base_url = format!("http://{address}/v1");
            let spec = office_spec(worktree.path(), &base_url, office(&base_url, vec![address]));
            assert!(ProviderConfig::from_spec(&spec).is_ok());

            // A cloud provider in place of the office endpoint.
            let mut cloud = spec.clone();
            cloud.provider = Some("openai".to_owned());
            cloud.base_url = None;
            cloud.sandbox.allowed_hosts = vec!["api.openai.com".to_owned()];
            assert!(refused(&cloud).contains("not the office-operated endpoint"));

            // The same provider at another endpoint (a linked credential's URL).
            let mut elsewhere = spec.clone();
            elsewhere.base_url = Some("https://llm.example.com/v1".to_owned());
            elsewhere.sandbox.allowed_hosts = vec!["llm.example.com".to_owned()];
            assert!(refused(&elsewhere).contains("approved base URL"));

            // Another model at the approved endpoint.
            let mut model = spec.clone();
            model.model = Some("other-model".to_owned());
            assert!(refused(&model).contains("approved model"));
        }

        /// Tool, shell and web egress beyond the endpoint is unreviewed.
        #[test]
        fn an_office_binding_refuses_unreviewed_egress() {
            let worktree = tempfile::tempdir().unwrap();
            let address: SocketAddr = "127.0.0.1:18080".parse().unwrap();
            let base_url = format!("http://{address}/v1");
            let spec = office_spec(worktree.path(), &base_url, office(&base_url, vec![address]));

            let mut wider = spec.clone();
            wider
                .sandbox
                .allowed_hosts
                .push("search.example.com".to_owned());
            assert!(refused(&wider).contains("another host"));

            let mut unfiltered = spec.clone();
            unfiltered.sandbox.network = Network::Allow;
            assert!(refused(&unfiltered).contains("unfiltered egress"));
        }

        /// The address set is the destination: no DNS name stands in for an
        /// address, no address may differ from the URL's, and cleartext is
        /// limited to literal loopback.
        #[test]
        fn an_office_binding_pins_the_destination_without_dns() {
            let worktree = tempfile::tempdir().unwrap();
            let address: SocketAddr = "127.0.0.1:18080".parse().unwrap();

            // `localhost` would be resolved; only a literal address is a pin.
            let named = "http://localhost:18080/v1";
            let spec = office_spec(worktree.path(), named, office(named, vec![address]));
            assert!(refused(&spec).contains("address set or TLS identity"));

            // An address on another port, or another address, than the URL's.
            let base_url = format!("http://{address}/v1");
            for other in ["127.0.0.1:18081", "127.0.0.2:18080"] {
                let other: SocketAddr = other.parse().unwrap();
                let spec = office_spec(worktree.path(), &base_url, office(&base_url, vec![other]));
                assert!(refused(&spec).contains("address set or TLS identity"));
            }

            // An empty address set.
            let spec = office_spec(worktree.path(), &base_url, office(&base_url, Vec::new()));
            assert!(refused(&spec).contains("address set or TLS identity"));

            // A LAN endpoint without a pinned TLS identity.
            let lan = "https://office-llm.lan/v1";
            let lan_address: SocketAddr = "192.168.10.20:443".parse().unwrap();
            let spec = office_spec(worktree.path(), lan, office(lan, vec![lan_address]));
            assert!(refused(&spec).contains("address set or TLS identity"));

            // A LAN endpoint with an empty TLS identity.
            let mut empty_tls = office(lan, vec![lan_address]);
            empty_tls.tls = Some(OfficeTlsIdentity {
                trust_roots_der: Vec::new(),
                certificate_sha256: Vec::new(),
            });
            let spec = office_spec(worktree.path(), lan, empty_tls);
            assert!(refused(&spec).contains("address set or TLS identity"));
        }

        /// A hosted runtime and the organization model broker route a turn's
        /// model calls off this office's systems, so both refuse the binding.
        #[test]
        fn an_office_binding_refuses_hosted_and_broker_routes() {
            let root = tempfile::tempdir().unwrap();
            let worktree = tempfile::tempdir().unwrap();
            let address: SocketAddr = "127.0.0.1:18080".parse().unwrap();
            let base_url = format!("http://{address}/v1");
            let spec = office_spec(worktree.path(), &base_url, office(&base_url, vec![address]));

            let broker = OrganizationModelBrokerConfig::new(
                "https://hub.example.com",
                "account-session",
                "organization:acme",
                "project:one",
                "chat-office",
                AuthorityBinding {
                    authority: AuthorityId::new("authority:model"),
                    organization: gaugedesk_core::ids::ScopeId::new("organization:acme"),
                    environment: "test".to_owned(),
                },
            )
            .unwrap();
            let brokered = factory(root.path())
                .with_organization_model_broker(broker)
                .unwrap();
            let error = brokered
                .create_harness(&spec)
                .err()
                .expect("broker refuses");
            assert!(
                error.to_string().contains("organization model broker"),
                "{error}"
            );
            let error = HarnessFactory::create(&brokered, &spec)
                .err()
                .expect("broker refuses through the seam too");
            assert!(
                error
                    .to_string()
                    .contains("office inference endpoint refused"),
                "{error}"
            );
        }
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
