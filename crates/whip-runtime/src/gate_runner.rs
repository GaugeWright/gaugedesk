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
/// Re-exported so a host can build a [`GateCoercionConfig`] without taking a
/// direct kernel dependency — GaugeDesk deliberately keeps the parser and kernel
/// as dev-dependencies, so anything a runtime caller needs comes through here.
pub use whipplescript_kernel::coerce_native::CoerceProvider as CoerceBackend;
pub use whipplescript_parser::IrProgram as GateProgram;

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
use whipplescript_store::{ClaimableEffect, RunStart, RuntimeStore, StoreError};

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

/// A stable key for one compiled gate, so a project's instance is reused across
/// arrivals but a rewritten gate starts a fresh one.
fn program_key(ir: &IrProgram) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    format!("{ir:?}").hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

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
    /// The gate settled without a usable disposition, or produced one outside
    /// the closed union its own class declares.
    NoDisposition(String),
}

impl std::fmt::Display for GateRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "gate run failed: {error:?}"),
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
    ir: &IrProgram,
    coerce: &GateCoercionConfig,
    item: &str,
    store_root: &Path,
    state_dir: &Path,
    transport: &T,
) -> Result<Disposition, GateRunError> {
    std::fs::create_dir_all(state_dir)
        .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
    // Three native connections, the composition `step_instance_generic`'s
    // `RuntimeStore + Coordination + WorkItems` bound requires.
    let store = NativeStores::open(
        state_dir.join("runtime.sqlite"),
        state_dir.join("coord.sqlite"),
        state_dir.join("items.sqlite"),
    )?;
    // 0.2.2 made the admission gate real for the std packages: a `file.read`
    // whose capability rows were never seeded blocks as
    // `blocked_by_capability`. 0.2.3 makes those manifests reachable from the
    // library, so a host seeds them the same way `whip` does rather than
    // reimplementing it.
    whipplescript::std_manifests::register_all(&store.runtime).map_err(GateRunError::Store)?;
    let mut kernel = RuntimeKernel::new(store);
    // 0.2.2 gates effects on the program version's declared ability ceiling, so
    // the version must be derived *from the IR* — a bare version declares no
    // capabilities and every effect lands `blocked_by_capability`.
    let version = kernel.create_program_version_for_program(
        ProgramVersionInput {
            program_name: "gate",
            source_hash: "gate",
            ir_hash: "gate",
            compiler_version: env!("CARGO_PKG_VERSION"),
        },
        ir,
    )?;
    // Open-or-create the project's gate instance rather than making a fresh one
    // per arrival (ADR 0117 §2). A parked review lives in an instance, so a new
    // instance per item would strand every question a person has not answered
    // yet — and re-driving after their answer would have nothing to re-drive.
    //
    // Keyed by the program so a *changed* gate gets its own instance: items
    // already in flight finish under the gate that started them, which is what
    // ADR 0117 §7 says a mid-queue edit means.
    let marker = state_dir.join(format!("instance-{}", program_key(ir)));
    let instance_id = match std::fs::read_to_string(&marker) {
        Ok(existing) if kernel.store().status(existing.trim())?.is_some() => {
            existing.trim().to_owned()
        }
        _ => {
            let created = kernel.create_instance(&version, "{}")?;
            // Started exactly once, at creation. Re-ingesting it on a later
            // pass is a *distinct commit under an already-used key*, which the
            // store refuses — and that refusal is right: an instance does not
            // start twice.
            kernel.ingest_external_event(&created, "external.started", "{}", Some("start"))?;
            std::fs::write(&marker, &created)
                .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
            created
        }
    };

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
    disposition_from(&driver)
}

/// Read the gate's verdict out of the governed fact the program recorded.
///
/// Deliberately only that fact. The kernel also emits a `schema.coerce.succeeded`
/// effect outcome carrying the same value, and reading it would work — but it is
/// the runtime's bookkeeping, not the program's assertion. The `record` is what
/// the envelope governs (`grant fact screening -> fact:Screening from Operator`)
/// and what the endorsement crossing targets, so reading anything else would
/// mean the step `gate::admit` verifies is not the step the verdict comes from.
///
/// The value must be one of the two the class declares. Anything else fails
/// rather than defaulting, because a verdict that could not be understood must
/// never read as approval.
fn disposition_from(driver: &GateDriver<'_>) -> Result<Disposition, GateRunError> {
    let facts = driver.kernel.store().list_facts(&driver.instance_id)?;
    let recorded = facts
        .iter()
        .find(|fact| fact.name == SCREENING_FACT)
        .map(|fact| json_from_str(&fact.value_json));
    let Some(value) = recorded else {
        return Err(GateRunError::NoDisposition(format!(
            "the gate settled without recording a `{SCREENING_FACT}` fact"
        )));
    };
    let disposition = value
        .get("disposition")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            GateRunError::NoDisposition(format!("`{SCREENING_FACT}` carries no disposition"))
        })?;
    Disposition::parse(disposition).ok_or_else(|| {
        GateRunError::NoDisposition(format!(
            "`{disposition}` is outside the union the gate declares"
        ))
    })
}

/// Deliver a person's verdict to a project's gate, and drive it.
///
/// This is what makes ADR 0117 §1 true: the gate is the only *producer* of a
/// verdict, so a reviewer's answer enters as a claim on the queue the gate is
/// parked against rather than as a call that moves bytes behind its back. The
/// HTTP route stays the transport; what changes is that it no longer decides.
///
/// The correlation runs the other way from `Settled`: a parked review left a
/// `Pending { item, request }` fact, so the item id finds the request id the
/// gate is waiting on, and the verdict is filed with that id as its body —
/// which is exactly what the gate's `settle` rule matches.
///
/// Returns the disposition when the gate settled, and `None` when it did not —
/// an unknown item, an answer for something already ruled, or a gate that needs
/// another pass.
pub fn deliver_verdict<T: GateTransport>(
    ir: &IrProgram,
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
    let marker = state_dir.join(format!("instance-{}", program_key(ir)));
    let Ok(instance_id) = std::fs::read_to_string(&marker) else {
        // No instance means nothing ever screened this project, so there is no
        // parked question for this answer to be about.
        return Ok(None);
    };
    let instance_id = instance_id.trim().to_owned();

    let Some(request) = pending_request_for(&kernel, &instance_id, item)? else {
        return Ok(None);
    };

    // The reviewer's answer, filed into the queue the envelope vouches. The
    // title is the disposition because that is what `settle` reads, and the body
    // is the request id because that is what it correlates on.
    let mut store = kernel.into_store();
    store.items.file_item(
        VERDICT_QUEUE,
        verdict.key(),
        &request,
        &[],
        &serde_json::Value::Null,
        Some("reviewer"),
    )?;

    run_gate(ir, coerce, item, store_root, state_dir, transport).map(Some)
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
    let marker_dir = std::fs::read_dir(state_dir);
    let Ok(entries) = marker_dir else {
        // No gate has ever run for this project. Nothing is waiting.
        return Ok(0);
    };
    let mut instance_ids: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("instance-") {
            continue;
        }
        if let Ok(id) = std::fs::read_to_string(entry.path()) {
            let id = id.trim().to_owned();
            if !id.is_empty() {
                instance_ids.push(id);
            }
        }
    }
    if instance_ids.is_empty() {
        return Ok(0);
    }
    let store = NativeStores::open(
        state_dir.join("runtime.sqlite"),
        state_dir.join("coord.sqlite"),
        state_dir.join("items.sqlite"),
    )?;
    let kernel = RuntimeKernel::new(store);
    let mut waiting = 0;
    // Every instance, not only the current one: ADR 0117 §7 says items in flight
    // finish under the gate that started them, so a project whose gate was
    // edited has questions parked in the previous instance that a person still
    // owes an answer to.
    for instance_id in instance_ids {
        for fact in kernel.store().list_facts(&instance_id)? {
            if fact.name == PENDING_FACT {
                waiting += 1;
            }
        }
    }
    Ok(waiting)
}
