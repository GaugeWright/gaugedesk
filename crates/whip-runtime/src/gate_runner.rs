//! Running a project's gate program (ADR 0110 §2, GATE-3b).
//!
//! GaugeDesk is a third WhippleScript host here, alongside the CLI's native
//! binding and `whipplescript-host-do`. All three drive the same
//! [`InstanceStepMachine`] over the same public kernel APIs — `rule_pass`,
//! `effect_handlers`, `coerce_native`, `sansio` — so a gate behaves identically
//! wherever it runs and nothing about its semantics is reimplemented here.
//!
//! That matters more than convenience. The alternative was shelling out to the
//! `whip` binary, which would have meant handing a provider key to a subprocess
//! across the boundary GaugeDesk otherwise holds carefully, and pinning the
//! library to one revision while the binary drifted to another — the shape that
//! let the collection sealing construction diverge undetected for a whole slice.
//!
//! The gate is a deliberately small host: it reads its file store and it
//! coerces. Any other effect is an error rather than a silent skip, because a
//! gate that quietly ignored an effect it did not understand would be a gate
//! with an unexamined hole in it.

use std::path::{Path, PathBuf};

use whipplescript_kernel::coerce::{CoerceRequest, CoerceResult, CoerceStatus};
/// Re-exported so a caller can build a [`GateCoercionConfig`] without taking a
/// direct kernel dependency for the provider configuration type.
pub use whipplescript_kernel::coerce_native::CoerceProvider as CoerceBackend;

use whipplescript_kernel::coerce_native::{
    build_coerce_call_parts, build_request, parse_response, CoerceCall, CoerceProvider,
};
use whipplescript_kernel::effect_config::EffectConfig;
use whipplescript_kernel::effect_handlers::{run_file_effect_generic, run_queue_effect_generic};
use whipplescript_kernel::instance_machine::{
    EffectStep, InstanceDriver, InstanceOutcome, InstanceStepMachine,
};
use whipplescript_kernel::rule_lowering::json_from_str;
use whipplescript_kernel::rule_pass::step_instance_generic;
use whipplescript_kernel::sansio::{
    run_to_completion, HostDriver, HttpRequest, HttpResponse, IoRequest, IoResult, TransportError,
};
use whipplescript_kernel::{CoerceExecution, ProgramVersionInput, RuntimeKernel};
use whipplescript_parser::IrProgram;
use whipplescript_store::files::NativeFileStore;
use whipplescript_store::native_stores::NativeStores;
use whipplescript_store::{
    stable_hash_hex, ClaimableEffect, InstanceView, RunStart, RuntimeStore, StoreError,
};

/// An admitted source/IR pair and the current project governance envelope.
/// Retaining source is necessary: the IR snapshot is inspectable, not an
/// executable serialization that can replace the authored program on restart.
#[derive(Clone, Debug)]
pub struct GateProgram {
    source: String,
    ir: IrProgram,
    envelope: String,
}

impl GateProgram {
    pub fn compile(source: &str, envelope: &str) -> Result<Self, GateRunError> {
        let verified = crate::ifc::VerifiedEnvelope::verify_text(envelope)
            .map_err(GateRunError::NoDisposition)?;
        let compiled = crate::compile_whip_program(source);
        let ir = compiled.ir.ok_or_else(|| {
            GateRunError::NoDisposition(format!(
                "the gate does not compile: {}",
                compiled.diagnostics.join("; ")
            ))
        })?;
        let diagnostics = crate::ifc::check_with_envelope(&ir, &verified);
        if !diagnostics.is_empty() {
            return Err(GateRunError::NoDisposition(format!(
                "the gate violates current governance: {diagnostics:?}"
            )));
        }
        Ok(Self {
            source: source.to_owned(),
            ir,
            envelope: envelope.to_owned(),
        })
    }
}

/// What the gate needs to reach a model.
///
/// GaugeDesk owns this rather than resolving it from operator environment and
/// `whip auth` the way the CLI does. That is the point: the key comes from
/// GaugeDesk's own credential store and never leaves this process, which is
/// exactly what shelling out to `whip` would have given up. The pinned
/// WhippleScript revision has no host-facing config type of its own — the
/// kernel's `CoerceCall` is the interface, and this is the host's half of it.
#[derive(Clone, Debug)]
pub struct GateCoercionConfig {
    pub backend: CoerceProvider,
    /// Stable identity for the run record and the admission fingerprint.
    pub provider_id: String,
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub max_tokens: u32,
}

/// The fact a gate records its verdict as. The envelope governs this name.
const SCREENING_FACT: &str = "Screening";

/// The stamp a gate's queue effects record.
///
/// A gate's durable ordering is its own instance log, not this value, so a fixed
/// stamp keeps a run replayable rather than making it depend on when it ran.
const GATE_CLOCK: &str = "2026-01-01T00:00:00Z";

/// The fact a parked review leaves behind, carrying item and request id.
const PENDING_FACT: &str = "Pending";

/// The tracker a reviewer's answer is filed into. The envelope vouches it, which
/// is what lets a claim on it endorse (WhippleScript DR-0051 §3).
const VERDICT_QUEUE: &str = "verdicts";

/// Public correlation emitted beside the vouched verdict by one program firing.
const SETTLED_FACT: &str = "Settled";

/// The signal an arrival is delivered on. Declared by both shipped gates, and
/// the only way an item reaches one (GATE-3i).
const ARRIVAL_SIGNAL: &str = "quarantine.arrived";

/// A gate's decision about one item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Keep,
    Flag,
}

impl Disposition {
    /// The literal the `Screening` union declares, and the title a reviewer's
    /// verdict is filed under so `settle` matches it.
    pub fn key(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Flag => "flag",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "keep" => Some(Self::Keep),
            "flag" => Some(Self::Flag),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum GateRunError {
    Store(StoreError),
    /// The program filed a review request for this item and has not ruled yet.
    AwaitingReview,
    /// The gate settled without a usable disposition, or produced one outside
    /// the closed union its own class declares.
    NoDisposition(String),
}

impl std::fmt::Display for GateRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "gate run failed: {error:?}"),
            Self::AwaitingReview => write!(f, "the gate is awaiting this item's reviewer"),
            Self::NoDisposition(detail) => {
                write!(f, "the gate produced no usable disposition: {detail}")
            }
        }
    }
}

impl std::error::Error for GateRunError {}

impl From<StoreError> for GateRunError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// The host's outbound side, behind a trait so the screening path is testable
/// without a provider.
pub trait GateTransport {
    fn fetch(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError>;
}

struct TransportHost<'a, T: GateTransport>(&'a T);

impl<T: GateTransport> HostDriver for TransportHost<'_, T> {
    fn fulfill(&self, request: &IoRequest) -> IoResult {
        let IoRequest::Http(http) = request;
        IoResult::Http(self.0.fetch(http))
    }
}

/// The gate's driver: file reads and coercions, nothing else.
struct GateDriver<'a> {
    kernel: RuntimeKernel<NativeStores>,
    instance_id: String,
    ir: &'a IrProgram,
    coerce: &'a GateCoercionConfig,
    files: NativeFileStore,
    /// The directory the program's file store resolves against — the project's
    /// quarantine. Nothing else may be given this program to run.
    store_root: PathBuf,
}

impl GateDriver<'_> {
    /// Rewrite a file effect's declared store root to this run's real
    /// directory. Only the root moves; the path, the `allow` globs, and the
    /// escape checks the kernel applies against it are untouched, so a program
    /// that tried to climb out of its store is refused exactly as before.
    fn with_mapped_root(&self, effect: &ClaimableEffect) -> ClaimableEffect {
        let mut input = json_from_str(&effect.input_json);
        if let Some(object) = input.as_object_mut() {
            object.insert(
                "root".to_owned(),
                serde_json::Value::String(self.store_root.to_string_lossy().into_owned()),
            );
        }
        ClaimableEffect {
            input_json: input.to_string(),
            ..effect.clone()
        }
    }
}

impl InstanceDriver for GateDriver<'_> {
    fn advance_rules(&mut self) -> Result<bool, StoreError> {
        step_instance_generic(
            &mut self.kernel,
            &self.instance_id,
            self.ir,
            Some(self.store_root.as_path()),
            None,
        )?;
        // Terminality is instance status, not a field on the step report.
        Ok(self
            .kernel
            .store()
            .status(&self.instance_id)?
            .map(|status| status.instance.status != "running")
            .unwrap_or(true))
    }

    fn next_ready_effect(&mut self) -> Result<Option<ClaimableEffect>, StoreError> {
        Ok(self
            .kernel
            .claimable_effects(&self.instance_id)?
            .into_iter()
            .next())
    }

    fn run_effect(
        &mut self,
        effect: &ClaimableEffect,
        incoming: Option<Result<HttpResponse, TransportError>>,
    ) -> Result<EffectStep, StoreError> {
        let event = match effect.kind.as_str() {
            "file.read" => {
                // The program declares a *logical* store root (`./quarantine`),
                // which the lowering puts in the effect input. Mapping it onto
                // this project's real quarantine directory is the host's job,
                // and doing it here rather than by process cwd is what lets one
                // compiled gate serve every project without the runs colliding.
                let mapped = self.with_mapped_root(effect);
                run_file_effect_generic(&mut self.kernel, &self.files, &self.instance_id, &mapped)?
            }
            // The tracker legs: filing a review question, claiming it, finishing
            // it. Without these a gate that reaches a person compiles, admits,
            // runs — and then silently never records that it asked, because the
            // `file issue` effect is claimable and nothing ever claims it.
            "tracker.file" | "tracker.claim" | "tracker.finish" | "tracker.release"
            | "tracker.renew" => run_queue_effect_generic(
                &mut self.kernel,
                &self.instance_id,
                effect,
                GATE_CLOCK,
                &EffectConfig::default(),
            )?,
            "schema.coerce" => {
                let input = json_from_str(&effect.input_json);
                let function_name = input
                    .get("function_name")
                    .and_then(|value| value.as_str())
                    .unwrap_or("coerce")
                    .to_owned();
                let arguments = input
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));
                let output_type = input
                    .get("output_type")
                    .and_then(|value| value.as_str())
                    .unwrap_or("json")
                    .to_owned();
                let (prompt, output_schema, wrapped, schema_name) =
                    build_coerce_call_parts(self.ir, &function_name, &arguments)
                        .map_err(StoreError::Conflict)?;
                // Stable per-effect identities, so a resume of the same coerce
                // is the same call rather than a second one.
                let run_id = format!("{}:{}:coerce-run", self.instance_id, effect.effect_id);
                let lease_id = format!("{}:{}:coerce-lease", self.instance_id, effect.effect_id);
                let idem_key = format!("{}:{}:coerce", self.instance_id, effect.effect_id);
                // Evidence hashes identify the host that produced the run, the
                // same way the DO stamps its own. They are provenance, not
                // content addressing.
                let request = CoerceRequest {
                    function_name,
                    arguments_json: arguments.to_string(),
                    output_type,
                    generated_coerce_source_hash: "gaugedesk-gate".to_owned(),
                    input_schema_hash: "gaugedesk-gate".to_owned(),
                    output_schema_hash: "gaugedesk-gate".to_owned(),
                };
                match incoming {
                    // Prepare: build the provider request and suspend on it.
                    None => {
                        self.kernel.start_run(RunStart {
                            instance_id: &self.instance_id,
                            effect_id: &effect.effect_id,
                            run_id: &run_id,
                            provider: &self.coerce.provider_id,
                            worker_id: "gaugedesk-gate",
                            lease_id: &lease_id,
                            lease_expires_at: "2030-01-01T00:00:00Z",
                            metadata_json: "{}",
                        })?;
                        let call = CoerceCall {
                            provider: self.coerce.backend,
                            base_url: &self.coerce.base_url,
                            api_key: &self.coerce.api_key,
                            model: &self.coerce.model,
                            prompt: &prompt,
                            media: None,
                            output_schema: &output_schema,
                            schema_name: &schema_name,
                            max_tokens: self.coerce.max_tokens,
                            codex: None,
                            idempotency_key: &idem_key,
                        };
                        return Ok(EffectStep::NeedsHttp(build_request(&call)));
                    }
                    // Finish: decode the response and settle through the kernel.
                    resumed => {
                        let result = match resumed {
                            Some(Ok(response)) => {
                                parse_response(self.coerce.backend, &response, wrapped)
                            }
                            other => CoerceResult {
                                status: CoerceStatus::Failed,
                                value_json: None,
                                error_json: Some(
                                    serde_json::json!({ "transport": format!("{other:?}") })
                                        .to_string(),
                                ),
                                summary: "coerce transport error".to_owned(),
                                transcript: String::new(),
                                usage_json: r#"{"input_tokens":0,"output_tokens":0}"#.to_owned(),
                            },
                        };
                        let execution = CoerceExecution {
                            instance_id: &self.instance_id,
                            effect_id: &effect.effect_id,
                            run_id: &run_id,
                            provider: &self.coerce.provider_id,
                            worker_id: "gaugedesk-gate",
                            lease_id: &lease_id,
                            lease_expires_at: "2030-01-01T00:00:00Z",
                            request: &request,
                            model: Some(&self.coerce.model),
                        };
                        self.kernel.settle_coerce_result(execution, &result)?
                    }
                }
            }
            // Deliberately not a silent skip.
            other => {
                return Err(StoreError::Conflict(format!(
                    "the gate host does not implement the `{other}` effect"
                )))
            }
        };
        Ok(EffectStep::Done(event))
    }
}

/// Run a compiled gate over one arrival and return its disposition.
///
/// `item` is the arrival's identity, delivered as a `quarantine.arrived` signal
/// so the gate can record which item a verdict concerns (GATE-3i). `store_root`
/// is that arrival's **own** staging directory, holding its payload as
/// `item.json`.
///
/// Identity therefore rides in two places, and neither is the filename.
/// Correlation travels in the signal; isolation is the per-arrival root. That
/// retires the rendezvous hazard — `item.json` under one shared quarantine root
/// meant two concurrent runs on a project overwrote each other's staged item —
/// while the program keeps a literal path.
///
/// **It keeps a literal path because a computed one does not work.**
/// `read text from quarantine at <expr>` compiles, and then lowers the
/// expression as a *literal string*: the effect goes out with
/// `"path":"arrival.item"` and reads a file by that name. That is fail-open —
/// the program looks dynamic and silently is not — and it is why the item id
/// selects a directory here rather than a filename.
///
/// `state_dir` holds the run's durable stores.
pub fn run_gate<T: GateTransport>(
    program: &GateProgram,
    coerce: &GateCoercionConfig,
    item: &str,
    store_root: &Path,
    state_dir: &Path,
    transport: &T,
) -> Result<Disposition, GateRunError> {
    std::fs::create_dir_all(state_dir)
        .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
    let store = NativeStores::open(
        state_dir.join("runtime.sqlite"),
        state_dir.join("coord.sqlite"),
        state_dir.join("items.sqlite"),
    )?;
    whipplescript::std_manifests::register_all(&store.runtime).map_err(GateRunError::Store)?;
    let mut kernel = RuntimeKernel::new(store);
    let (instance_id, retained) = if let Some(instance) = instance_for_item(&kernel, item)? {
        let retained = retained_program(&kernel, &instance, program)?;
        (instance.instance_id, retained)
    } else {
        let snapshot = program.ir.to_snapshot();
        let source_hash = kernel.store().put_content(&program.source)?;
        let ir_hash = stable_hash_hex(&snapshot);
        let version = kernel.create_program_version_for_program(
            ProgramVersionInput {
                program_name: "gate",
                source_hash: &source_hash,
                ir_hash: &ir_hash,
                compiler_version: concat!("gaugedesk-whip-runtime/", env!("CARGO_PKG_VERSION")),
                ir_snapshot: Some(&snapshot),
            },
            &program.ir,
        )?;
        let mut existing = gate_instances(&kernel)?
            .into_iter()
            .filter(|instance| instance.version_id == version.version_id);
        let first = existing.next();
        if existing.next().is_some() {
            return Err(GateRunError::NoDisposition(
                "multiple instances claim this gate version; preserve the queues and repair instance routing".into()
            ));
        }
        let instance_id = if let Some(instance) = first {
            instance.instance_id
        } else {
            kernel.create_instance(&version, "{}")?
        };
        // Resume a creation interrupted before start, without minting another
        // start event for an existing instance on each later arrival.
        if !kernel
            .store()
            .list_events(&instance_id)?
            .iter()
            .any(|event| event.event_type == "external.started")
        {
            kernel.ingest_external_event(&instance_id, "external.started", "{}", Some("start"))?;
        }
        (instance_id, program.clone())
    };
    drive_gate(
        kernel,
        &instance_id,
        &retained.ir,
        coerce,
        item,
        store_root,
        transport,
    )
}

fn drive_gate<T: GateTransport>(
    mut kernel: RuntimeKernel<NativeStores>,
    instance_id: &str,
    ir: &IrProgram,
    coerce: &GateCoercionConfig,
    item: &str,
    store_root: &Path,
    transport: &T,
) -> Result<Disposition, GateRunError> {
    let instance_id = instance_id.to_owned();
    // Deliver the arrival. A signal is two steps: the external event records
    // that something arrived, and the derived fact is what
    // `when quarantine.arrived as arrival` matches.
    //
    // Both are keyed by the item, so re-driving this instance — which is what a
    // reviewer's answer does — finds the arrival already recorded rather than
    // screening the same item twice. That is a no-op, not a failure.
    let arrival = serde_json::json!({ "item": item }).to_string();
    match kernel.ingest_external_event(
        &instance_id,
        ARRIVAL_SIGNAL,
        &arrival,
        Some(&format!("arrival:{item}")),
    ) {
        Ok(received) => {
            kernel.derive_fact(
                &instance_id,
                ARRIVAL_SIGNAL,
                &received.event_id,
                &arrival,
                Some(&received.event_id),
                Some(&format!("arrival-fact:{item}")),
            )?;
        }
        Err(StoreError::Conflict(_)) => {}
        Err(error) => return Err(error.into()),
    }

    let driver = GateDriver {
        kernel,
        instance_id,
        ir,
        coerce,
        files: NativeFileStore,
        store_root: store_root.to_path_buf(),
    };

    // Drive to a genuine terminal. One pass parks as soon as the coercion
    // suspends on its provider round; settling it makes the `after` branch
    // ready, so the machine must be re-driven until it stops making progress.
    let mut driver = driver;
    let mut outcome = InstanceOutcome::Parked;
    // Evaluate rules once before the first machine pass. The arrival is a
    // signal fact, so nothing is claimable until the rules have been advanced
    // against it — and a machine started with no ready effect reports terminal
    // immediately, which looked exactly like a gate that declined to rule. The
    // old seeded `table` hid this by materializing its fact at start.
    driver.advance_rules()?;
    for _ in 0..8 {
        let mut machine = InstanceStepMachine::new(driver);
        outcome = run_to_completion(&mut machine, &TransportHost(transport));
        driver = machine.into_driver();
        if matches!(
            outcome,
            InstanceOutcome::Terminal | InstanceOutcome::Failed(_)
        ) {
            break;
        }
        if driver.advance_rules()? {
            break;
        }
    }
    if let InstanceOutcome::Failed(error) = outcome {
        return Err(GateRunError::Store(error));
    }
    disposition_from(&driver, item)
}

fn gate_instances(kernel: &RuntimeKernel<NativeStores>) -> Result<Vec<InstanceView>, GateRunError> {
    let mut gates = Vec::new();
    for instance in kernel.store().list_instances()? {
        let version = kernel.store().get_program_version(&instance.version_id)?
            .ok_or_else(|| GateRunError::NoDisposition(format!(
                "instance {} has no retained program version; preserve its queue and repair the store", instance.instance_id
            )))?;
        if version.program_name == "gate" {
            gates.push(instance);
        }
    }
    Ok(gates)
}

fn instance_for_item(
    kernel: &RuntimeKernel<NativeStores>,
    item: &str,
) -> Result<Option<InstanceView>, GateRunError> {
    let mut owner = None;
    for instance in gate_instances(kernel)? {
        let received = kernel
            .store()
            .list_events(&instance.instance_id)?
            .iter()
            .any(|event| {
                event.event_type == ARRIVAL_SIGNAL
                    && json_from_str(&event.payload_json)
                        .get("item")
                        .and_then(serde_json::Value::as_str)
                        == Some(item)
            });
        if received {
            if owner.is_some() {
                return Err(GateRunError::NoDisposition(format!(
                    "item {item} arrived in multiple gate instances; preserve pending work and repair routing"
                )));
            }
            owner = Some(instance);
        }
    }
    Ok(owner)
}

fn retained_program(
    kernel: &RuntimeKernel<NativeStores>,
    instance: &InstanceView,
    current: &GateProgram,
) -> Result<GateProgram, GateRunError> {
    let repair = |detail: &str| {
        GateRunError::NoDisposition(format!(
        "gate instance {} cannot resume: {detail}; pending work is preserved; restore the exact retained program/version evidence before retrying",
        instance.instance_id
    ))
    };
    let version = kernel
        .store()
        .get_program_version(&instance.version_id)?
        .ok_or_else(|| repair("program version is missing"))?;
    let source = kernel
        .store()
        .get_content(&version.source_hash)?
        .ok_or_else(|| {
            repair("original source is unavailable (legacy versions did not retain it)")
        })?;
    let snapshot = kernel
        .store()
        .get_content(&version.ir_hash)?
        .ok_or_else(|| repair("original IR snapshot is unavailable"))?;
    if stable_hash_hex(&source) != version.source_hash
        || stable_hash_hex(&snapshot) != version.ir_hash
    {
        return Err(repair(
            "retained source or IR content does not match its version",
        ));
    }
    // A program edit selects the next arrival's workflow, not this item's.
    // Current governance still admits/refuses the old workflow before effects.
    let retained = GateProgram::compile(&source, &current.envelope)?;
    if retained.ir.to_snapshot() != snapshot {
        return Err(repair(
            "the current compiler does not reproduce the recorded IR",
        ));
    }
    Ok(retained)
}

/// Read the item-bound pair of assertions the program committed together.
///
/// Deliberately only program assertions. The kernel also emits a `schema.coerce.succeeded`
/// effect outcome carrying the same value, and reading it would work — but it is
/// the runtime's bookkeeping, not the program's assertion. The `record` is what
/// the envelope governs (`grant fact screening -> fact:Screening from Operator`)
/// and what the endorsement crossing targets, so reading anything else would
/// mean the step `gate::admit` verifies is not the step the verdict comes from.
///
/// Read their committing event, not the live set-like fact projection: equal
/// dispositions for different items have equal fact content. Live rows may
/// coalesce, but each distinct firing records its assertions in the immutable
/// log, which remains the item-bound authority across restarts.
///
/// The value must be one of the two the class declares. Anything else fails
/// rather than defaulting, because a verdict that could not be understood must
/// never read as approval.
fn disposition_from(driver: &GateDriver<'_>, item: &str) -> Result<Disposition, GateRunError> {
    let mut result = None;
    for event in driver.kernel.store().list_events(&driver.instance_id)? {
        if event.event_type != "rule.committed" || event.source != "kernel" {
            continue;
        }
        let payload = json_from_str(&event.payload_json);
        let Some(facts) = payload.get("facts").and_then(serde_json::Value::as_array) else {
            continue;
        };
        if !facts.iter().any(|fact| {
            fact["name"] == SETTLED_FACT && fact["value"]["item"].as_str() == Some(item)
        }) {
            continue;
        }
        let screenings = facts
            .iter()
            .filter(|fact| fact["name"] == SCREENING_FACT)
            .collect::<Vec<_>>();
        let settlements = facts
            .iter()
            .filter(|fact| fact["name"] == SETTLED_FACT)
            .collect::<Vec<_>>();
        if screenings.len() != 1 || settlements.len() != 1 || result.is_some() {
            return Err(GateRunError::NoDisposition(format!(
                "the gate did not commit one unambiguous item/verdict pair ({} verdicts, {} settlements, prior result {})",
                screenings.len(), settlements.len(), result.is_some()
            )));
        }
        let disposition = screenings[0]["value"]["disposition"]
            .as_str()
            .and_then(Disposition::parse)
            .ok_or_else(|| {
                GateRunError::NoDisposition(
                    "the item-bound Screening carries no valid disposition".to_owned(),
                )
            })?;
        result = Some(disposition);
    }
    if let Some(disposition) = result {
        return Ok(disposition);
    }
    if pending_request_for(&driver.kernel, &driver.instance_id, item)?.is_some() {
        return Err(GateRunError::AwaitingReview);
    }
    Err(GateRunError::NoDisposition(format!(
        "the gate has not committed a `{SETTLED_FACT}` / `{SCREENING_FACT}` pair for this item; inspect its runtime failure or repair the project's gate correlation contract"
    )))
}

/// Deliver a person's verdict to a project's gate, and drive it.
///
/// This is what makes ADR 0117 §1 true: the gate is the only *producer* of a
/// verdict, so a reviewer's answer enters as a claim on the queue the gate is
/// parked against rather than as a call that moves bytes behind its back. The
/// HTTP route stays the transport; what changes is that it no longer decides.
///
/// A parked review supplies the request id used in the human-facing answer.
/// Public item correlation is filed separately from that vouched verdict, so
/// neither source can raise the other's free-text identifiers across the
/// integrity boundary.
///
/// Returns the disposition when the gate settled, and `None` when it did not —
/// an unknown item, an answer for something already ruled, or a gate that needs
/// another pass.
pub fn deliver_verdict<T: GateTransport>(
    program: &GateProgram,
    coerce: &GateCoercionConfig,
    item: &str,
    verdict: Disposition,
    store_root: &Path,
    state_dir: &Path,
    transport: &T,
) -> Result<Option<Disposition>, GateRunError> {
    let store = NativeStores::open(
        state_dir.join("runtime.sqlite"),
        state_dir.join("coord.sqlite"),
        state_dir.join("items.sqlite"),
    )?;
    let kernel = RuntimeKernel::new(store);
    let Some(instance) = instance_for_item(&kernel, item)? else {
        return Ok(None);
    };
    let instance_id = instance.instance_id.clone();

    let Some(request) = pending_request_for(&kernel, &instance_id, item)? else {
        return Ok(None);
    };
    // Verify/re-admit before filing an answer. Missing legacy evidence may
    // not enqueue a verdict that some replacement workflow could consume.
    let retained = retained_program(&kernel, &instance, program)?;

    // The reviewer's answer is the only vouched input. The program matches its
    // request to Pending and emits public correlation in the same firing as the
    // closed Screening disposition; the host does not announce settlement.
    let mut store = kernel.into_store();
    store.items.file_item(
        VERDICT_QUEUE,
        verdict.key(),
        &request,
        &[],
        &serde_json::Value::Null,
        Some("reviewer"),
    )?;

    match drive_gate(
        RuntimeKernel::new(store),
        &instance_id,
        &retained.ir,
        coerce,
        item,
        store_root,
        transport,
    ) {
        Ok(disposition) => Ok(Some(disposition)),
        Err(GateRunError::AwaitingReview) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The request id a parked review is waiting on for this item.
///
/// Read from the `Pending` fact the gate recorded, which carries both halves —
/// the public bookkeeping ADR 0117 §3 kept off the vouched verdict.
fn pending_request_for(
    kernel: &RuntimeKernel<NativeStores>,
    instance_id: &str,
    item: &str,
) -> Result<Option<String>, GateRunError> {
    for fact in kernel.store().list_facts(instance_id)? {
        if fact.name != PENDING_FACT {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&fact.value_json) else {
            continue;
        };
        if value.get("item").and_then(serde_json::Value::as_str) == Some(item) {
            if let Some(request) = value.get("request").and_then(serde_json::Value::as_str) {
                return Ok(Some(request.to_owned()));
            }
        }
    }
    Ok(None)
}

/// How many of this project's gate items are waiting on a person.
///
/// ADR 0117 §5: the review surface counts items awaiting a *reviewer*, not every
/// `Pending` quarantine row — an item still being screened awaits the gate, not
/// the person. The gate's own `Pending` fact is exactly that set: it is recorded
/// when the gate files its question and retracted by `done p` when a verdict
/// settles it.
///
/// Read from the facts rather than by counting open `review` issues, because the
/// two do not agree: `settle` finishes the *verdicts* issue a reviewer filed
/// into and leaves the *review* issue that asked the question open, so an open-
/// issue count would keep counting questions that have already been answered.
pub fn reviews_awaiting_a_person(state_dir: &Path) -> Result<usize, GateRunError> {
    if !state_dir
        .join("runtime.sqlite")
        .try_exists()
        .map_err(|error| GateRunError::NoDisposition(error.to_string()))?
    {
        return Ok(0);
    }
    let store = NativeStores::open(
        state_dir.join("runtime.sqlite"),
        state_dir.join("coord.sqlite"),
        state_dir.join("items.sqlite"),
    )?;
    let kernel = RuntimeKernel::new(store);
    let mut waiting = 0;
    // The durable instance registry, not rebuildable marker files, owns every
    // previous version's pending reviews.
    for instance in gate_instances(&kernel)? {
        for fact in kernel.store().list_facts(&instance.instance_id)? {
            if fact.name == PENDING_FACT {
                waiting += 1;
            }
        }
    }
    Ok(waiting)
}
