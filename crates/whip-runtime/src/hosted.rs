use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use gaugewright_harness::{
    EgressGate, Harness, HarnessContinuitySpec, HarnessSpec, ImageContent, InterruptHandle,
    ModelUsage, Observation, OutputFieldFlow, RuntimePosition, ToolInfo, TurnOutcome,
};
use serde_json::{json, Value};

use super::{
    AuthoredAgentPackage, CredentialRef, EventPosition, ForkInstanceCommand, OpenInstanceCommand,
    PolicyEpochRef, ProviderBindingRef, ResourceRef, StartTurnCommand, TurnInput,
    WhipHarnessFactory, HOST_PROTOCOL,
};

const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 5_000;
const SYNC_CHUNK_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub struct DoHostConfig {
    transport: Arc<dyn DoHostTransport>,
    pub tenant_id: String,
    reuse_across_turns: bool,
}

impl std::fmt::Debug for DoHostConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DoHostConfig")
            .field("transport", &self.transport)
            .field("tenant_id", &self.tenant_id)
            .field("reuse_across_turns", &self.reuse_across_turns)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct DoHostRequest {
    pub method: String,
    pub tenant_id: String,
    pub placement_id: String,
    /// Placement-local route including its canonical query string.
    pub path: String,
    pub body: Vec<u8>,
    pub accept: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DoHostResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The hosted WhippleScript protocol is independent of how an operation is
/// admitted. Public/legacy hosts use a bearer lane; a managed Machine supplies
/// a Home-command transport that signs each exact request. The harness and
/// protocol projection remain shared.
pub trait DoHostTransport: Send + Sync + std::fmt::Debug {
    fn send(&self, request: DoHostRequest) -> io::Result<DoHostResponse>;

    fn supports_streaming(&self) -> bool {
        false
    }

    fn open_stream(&self, _request: DoHostRequest) -> io::Result<Box<dyn BufRead + Send>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "host transport does not expose a streaming lane",
        ))
    }
}

#[derive(Debug)]
struct BearerDoHostTransport {
    base_url: String,
    control_token: String,
    agent: ureq::Agent,
}

impl BearerDoHostTransport {
    fn url(&self, request: &DoHostRequest) -> String {
        format!(
            "{}/v1/tenants/{}/placements/{}{}",
            self.base_url,
            encode(&request.tenant_id),
            encode(&request.placement_id),
            request.path
        )
    }

    fn request(&self, request: &DoHostRequest) -> ureq::Request {
        let mut builder = self
            .agent
            .request(&request.method, &self.url(request))
            .set("authorization", &format!("Bearer {}", self.control_token));
        if let Some(accept) = &request.accept {
            builder = builder.set("accept", accept);
        }
        builder
    }
}

impl DoHostTransport for BearerDoHostTransport {
    fn send(&self, request: DoHostRequest) -> io::Result<DoHostResponse> {
        let response = if request.method == "POST" {
            self.request(&request)
                .set("content-type", "application/json")
                .send_bytes(&request.body)
        } else {
            self.request(&request).call()
        }
        .map_err(http_error)?;
        let status = response.status();
        let mut body = Vec::new();
        response
            .into_reader()
            .take(32 * 1024 * 1024)
            .read_to_end(&mut body)?;
        Ok(DoHostResponse { status, body })
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn open_stream(&self, request: DoHostRequest) -> io::Result<Box<dyn BufRead + Send>> {
        let response = self.request(&request).call().map_err(http_error)?;
        Ok(Box::new(BufReader::new(response.into_reader())))
    }
}

impl DoHostConfig {
    pub fn new(
        base_url: impl Into<String>,
        control_token: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> io::Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let control_token = control_token.into();
        let tenant_id = tenant_id.into();
        if base_url.is_empty() || control_token.is_empty() || tenant_id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DO host URL, token, and tenant are required",
            ));
        }
        Ok(Self {
            transport: Arc::new(BearerDoHostTransport {
                base_url,
                control_token,
                agent: ureq::AgentBuilder::new().build(),
            }),
            tenant_id,
            reuse_across_turns: true,
        })
    }

    pub fn with_transport(
        tenant_id: impl Into<String>,
        transport: Arc<dyn DoHostTransport>,
        reuse_across_turns: bool,
    ) -> io::Result<Self> {
        let tenant_id = tenant_id.into();
        if tenant_id.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DO host tenant is required",
            ));
        }
        Ok(Self {
            transport,
            tenant_id,
            reuse_across_turns,
        })
    }

    pub(crate) fn reuse_across_turns(&self) -> bool {
        self.reuse_across_turns
    }
}

pub(crate) fn create_harness(
    factory: &WhipHarnessFactory,
    config: &DoHostConfig,
    spec: &HarnessSpec,
) -> io::Result<Box<dyn Harness>> {
    let create_started = Instant::now();
    let package_started = Instant::now();
    let package = WhipHarnessFactory::package_for(
        spec.mode,
        spec.package_root.as_deref(),
        spec.package_version_ref.as_deref(),
        spec.system_prompt.as_deref(),
    )?;
    let package_ms = package_started.elapsed().as_secs_f64() * 1000.0;
    let epoch = required(spec.policy_epoch, "policy epoch")?;
    let signed = required_ref(
        spec.signed_policy_envelope.as_deref(),
        "signed policy envelope",
    )?;
    let placement = required_ref(spec.runtime_placement_id.as_deref(), "runtime placement id")?;
    let policy_started = Instant::now();
    let policy: PolicyEpochRef = serde_json::from_value(post_json(
        config,
        placement,
        "/host/policy",
        &json!({
            "epoch": epoch,
            "signed_envelope": signed,
        }),
    )?)
    .map_err(invalid_data)?;
    let policy_ms = policy_started.elapsed().as_secs_f64() * 1000.0;
    let open = super::OpenInstanceCommand {
        protocol: HOST_PROTOCOL.to_owned(),
        request_id: format!(
            "gaugedesk:{}:{}:{}:{}",
            spec.chat_id,
            package.version_ref(),
            policy.epoch,
            policy.envelope_hash,
        ),
        package_version_ref: package.version_ref().to_owned(),
        policy: policy.clone(),
    };
    let open_started = Instant::now();
    let opened = post_json(
        config,
        placement,
        "/host/instances/open",
        &host_request(&open, &package)?,
    )?;
    let open_ms = open_started.elapsed().as_secs_f64() * 1000.0;
    let instance_ref = opened
        .get("instance_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_data("DO open response omitted instance_ref"))?
        .to_owned();

    let read_only = spec.sandbox.read_only_roots.to_vec();
    let mut harness = DoHarness {
        config: config.clone(),
        placement: placement.to_owned(),
        worktree: spec.worktree.clone(),
        read_only,
        package,
        instance_ref,
        policy,
        chat_id: spec.chat_id.clone(),
        provider_binding_ref: required_ref(
            spec.provider_binding_ref.as_deref(),
            "provider binding ref",
        )?
        .to_owned(),
        credential_ref: required_ref(spec.credential_ref.as_deref(), "credential ref")?.to_owned(),
        provider: required_ref(spec.provider.as_deref(), "provider")?.to_owned(),
        model: required_ref(spec.model.as_deref(), "model")?.to_owned(),
        placement_ceiling_ref: required_ref(
            spec.placement_ceiling_ref.as_deref(),
            "placement ceiling ref",
        )?
        .to_owned(),
        actor_ref: factory.authority.as_str().to_owned(),
        turn_sequence: 0,
        runtime_command_id: None,
        active_command: Arc::new(Mutex::new(None)),
        synced_paths: BTreeSet::new(),
    };
    let push_started = Instant::now();
    harness.push_workspace()?;
    let initial_push_workspace_ms = push_started.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "{}",
        json!({
            "event": "gaugewright_turn_timing",
            "component": "gaugedesk_do_harness_create",
            "chat_id": spec.chat_id,
            "timing_ms": {
                "package": package_ms,
                "policy": policy_ms,
                "instance_open": open_ms,
                "initial_push_workspace": initial_push_workspace_ms,
                "total": create_started.elapsed().as_secs_f64() * 1000.0,
            }
        })
    );
    Ok(Box::new(harness))
}

pub(crate) fn clone_continuity(
    config: &DoHostConfig,
    source: &HarnessContinuitySpec,
    target: &HarnessContinuitySpec,
) -> io::Result<()> {
    if source.mode != target.mode {
        return Err(invalid_data(
            "WhippleScript continuity fork cannot change chat mode",
        ));
    }
    let placement = required_ref(
        source.runtime_placement_id.as_deref(),
        "hosted continuity source placement",
    )?;
    if target.runtime_placement_id.as_deref() != Some(placement) {
        return Err(invalid_data(
            "hosted continuity source and target must share one admitted placement",
        ));
    }
    let source_package = WhipHarnessFactory::package_for(
        source.mode,
        source.package_root.as_deref(),
        source.package_version_ref.as_deref(),
        source.system_prompt.as_deref(),
    )?;
    let target_package = WhipHarnessFactory::package_for(
        target.mode,
        target.package_root.as_deref(),
        target.package_version_ref.as_deref(),
        target.system_prompt.as_deref(),
    )?;
    if source_package.version_ref() != target_package.version_ref() {
        return Err(invalid_data(
            "WhippleScript continuity fork requires the same package identity",
        ));
    }
    let epoch = required(source.policy_epoch, "WhippleScript source policy epoch")?;
    let signed = required_ref(
        source.signed_policy_envelope.as_deref(),
        "WhippleScript source signed policy",
    )?;
    let policy: PolicyEpochRef = serde_json::from_value(post_json(
        config,
        placement,
        "/host/policy",
        &json!({ "epoch": epoch, "signed_envelope": signed }),
    )?)
    .map_err(invalid_data)?;
    let source_open = continuity_open_command(
        &source.chat_id,
        source_package.version_ref(),
        policy.clone(),
    );
    let opened = post_json(
        config,
        placement,
        "/host/instances/open",
        &host_request(&source_open, &source_package)?,
    )?;
    let source_instance = required_json_string(&opened, "instance_ref", "DO source open")?;
    let source_position = if let Some(position) = &source.source_position {
        if position.instance_ref != source_instance {
            return Err(invalid_data(
                "WhippleScript continuity position belongs to a different source instance",
            ));
        }
        EventPosition {
            instance_ref: position.instance_ref.clone(),
            sequence: position.sequence,
        }
    } else {
        let value = get_json(
            config,
            placement,
            &format!("/host/instances/{}/position", encode(&source_instance)),
        )?;
        let position = parse_position(&value, "DO continuity source position")?;
        EventPosition {
            instance_ref: position.instance_ref,
            sequence: position.sequence,
        }
    };
    let export = get_json(
        config,
        placement,
        &format!(
            "/host/instances/{}/fork-export?sequence={}",
            encode(&source_instance),
            source_position.sequence
        ),
    )?;
    let target_open = continuity_open_command(
        &target.chat_id,
        target_package.version_ref(),
        policy.clone(),
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
        policy,
    };
    command.validate().map_err(invalid_data)?;
    post_json(
        config,
        placement,
        "/host/forks/import",
        &host_fork_request(&command, &target_package, export)?,
    )?;
    Ok(())
}

fn continuity_open_command(
    chat_id: &str,
    package_version_ref: &str,
    policy: PolicyEpochRef,
) -> OpenInstanceCommand {
    OpenInstanceCommand {
        protocol: HOST_PROTOCOL.to_owned(),
        request_id: format!(
            "gaugedesk:{chat_id}:{package_version_ref}:{}:{}",
            policy.epoch, policy.envelope_hash
        ),
        package_version_ref: package_version_ref.to_owned(),
        policy,
    }
}

struct DoHarness {
    config: DoHostConfig,
    placement: String,
    worktree: PathBuf,
    read_only: Vec<PathBuf>,
    package: AuthoredAgentPackage,
    instance_ref: String,
    policy: PolicyEpochRef,
    chat_id: String,
    provider_binding_ref: String,
    credential_ref: String,
    provider: String,
    model: String,
    placement_ceiling_ref: String,
    actor_ref: String,
    turn_sequence: u64,
    runtime_command_id: Option<String>,
    active_command: Arc<Mutex<Option<String>>>,
    synced_paths: BTreeSet<String>,
}

impl Harness for DoHarness {
    fn bind_authenticated_actor(&mut self, actor_ref: &str) {
        if !actor_ref.trim().is_empty() {
            self.actor_ref = actor_ref.to_owned();
        }
    }

    fn bind_runtime_command_id(&mut self, command_id: Option<&str>) {
        self.runtime_command_id = command_id.map(str::to_owned);
    }

    fn run_turn(
        &mut self,
        _gate: &dyn EgressGate,
        prompt: &str,
        images: &[ImageContent],
        sink: &mut dyn FnMut(&Observation),
    ) -> io::Result<TurnOutcome> {
        let turn_started = Instant::now();
        let push_started = Instant::now();
        self.push_workspace()?;
        let push_workspace_ms = push_started.elapsed().as_secs_f64() * 1000.0;
        let position_started = Instant::now();
        let runtime_start_position = get_json(
            &self.config,
            &self.placement,
            &format!("/host/instances/{}/position", encode(&self.instance_ref)),
        )?;
        let position_ms = position_started.elapsed().as_secs_f64() * 1000.0;
        self.turn_sequence += 1;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut resources = Vec::new();
        let has = |name: &str| {
            self.package
                .agent_abilities()
                .iter()
                .any(|item| item == name)
        };
        if has("workspace.read") || has("workspace.write") {
            resources.push(ResourceRef {
                handle: "project".into(),
                kind: "file_store".into(),
                selector: None,
            });
        }
        if has("command.run") {
            resources.push(ResourceRef {
                handle: "command".into(),
                kind: "command".into(),
                selector: None,
            });
        }
        // ADR 0111: no suspended epoch to resume. Every hosted turn is an
        // ordinary turn; an agent needing a person files a task instead.
        let command_id = self.runtime_command_id.clone().unwrap_or_else(|| {
            format!("gaugedesk:{}:{}:{nonce}", self.chat_id, self.turn_sequence)
        });
        let command = StartTurnCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: command_id.clone(),
            run_ref: format!("gaugedesk:run:{command_id}"),
            instance_ref: self.instance_ref.clone(),
            package_version_ref: self.package.version_ref().to_owned(),
            policy: self.policy.clone(),
            actor_ref: self.actor_ref.clone(),
            input: TurnInput {
                text: prompt.to_owned(),
                images: images
                    .iter()
                    .enumerate()
                    .map(|(index, _)| ResourceRef {
                        handle: "turn_images".into(),
                        kind: "image".into(),
                        selector: Some(index.to_string()),
                    })
                    .collect(),
            },
            resources: resources.clone(),
            provider_binding: ProviderBindingRef {
                binding_id: self.provider_binding_ref.clone(),
                credential: CredentialRef {
                    credential_id: self.credential_ref.clone(),
                },
            },
            placement_ceiling_ref: self.placement_ceiling_ref.clone(),
        };
        command.validate().map_err(invalid_data)?;
        let route = "/host/turns".to_owned();
        let request = host_turn_request(&command, &self.package, images)?;
        *self
            .active_command
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(command_id.clone());
        let (started, streamed_text, stream_timing) = post_json_with_turn_stream(
            &self.config,
            &self.placement,
            &self.instance_ref,
            &command_id,
            &route,
            &request,
            sink,
        )?;
        if started.get("outcome").and_then(Value::as_str) == Some("failed") {
            *self
                .active_command
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = None;
            return Err(invalid_data("hosted WhippleScript turn failed"));
        }
        let result_started = Instant::now();
        let result = get_json(
            &self.config,
            &self.placement,
            &format!(
                "/host/instances/{}/turns/{}/result",
                encode(&self.instance_ref),
                encode(&command_id)
            ),
        )?;
        let result_ms = result_started.elapsed().as_secs_f64() * 1000.0;
        *self
            .active_command
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
        let pull_started = Instant::now();
        self.pull_workspace()?;
        let pull_workspace_ms = pull_started.elapsed().as_secs_f64() * 1000.0;
        let project_started = Instant::now();
        let mut outcome = project_result_inner(
            &result,
            &resources,
            &self.provider,
            &self.model,
            sink,
            !streamed_text,
        )?;
        let project_ms = project_started.elapsed().as_secs_f64() * 1000.0;
        outcome.runtime_start_position = Some(parse_position(
            &runtime_start_position,
            "DO start position",
        )?);
        eprintln!(
            "{}",
            json!({
                "event": "gaugewright_turn_timing",
                "component": "gaugedesk_do_harness",
                "trace_id": command_id,
                "chat_id": self.chat_id,
                "timing_ms": {
                    "push_workspace": push_workspace_ms,
                    "position": position_ms,
                    "stream_ready": stream_timing.stream_ready_ms,
                    "first_delta": stream_timing.first_delta_ms,
                    "turn_post_complete": stream_timing.turn_post_complete_ms,
                    "stream_terminal": stream_timing.terminal_ms,
                    "stream_orchestration": stream_timing.total_ms,
                    "result_fetch": result_ms,
                    "pull_workspace": pull_workspace_ms,
                    "result_projection": project_ms,
                    "total": turn_started.elapsed().as_secs_f64() * 1000.0,
                },
                "durable_object_timing_ms": started.get("timing_ms"),
            })
        );
        Ok(outcome)
    }

    fn interrupt_handle(&self) -> Option<InterruptHandle> {
        let config = self.config.clone();
        let placement = self.placement.clone();
        let instance = self.instance_ref.clone();
        let active = Arc::clone(&self.active_command);
        Some(Arc::new(move || {
            let command = active.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if let Some(command) = command {
                let _ = post_json(
                    &config,
                    &placement,
                    &format!(
                        "/host/instances/{}/turns/{}/cancel",
                        encode(&instance),
                        encode(&command)
                    ),
                    &json!({}),
                );
            }
        }))
    }
}

impl DoHarness {
    fn push_workspace(&mut self) -> io::Result<()> {
        let files = collect_files(&self.worktree, &self.read_only)?;
        self.synced_paths = files.keys().cloned().collect();
        let mut chunk = Vec::new();
        let mut bytes = 0usize;
        for (path, content) in &files {
            let size = path.len() + content.len() + 64;
            if !chunk.is_empty() && bytes + size > SYNC_CHUNK_BYTES {
                self.send_file_chunk(&chunk, false)?;
                chunk.clear();
                bytes = 0;
            }
            chunk.push(json!({ "path": path, "content": content }));
            bytes += size;
        }
        if !chunk.is_empty() {
            self.send_file_chunk(&chunk, false)?;
        }
        post_json(
            &self.config,
            &self.placement,
            &format!("/host/instances/{}/files/sync", encode(&self.instance_ref)),
            &json!({ "files": [], "retain_paths": self.synced_paths }),
        )?;
        Ok(())
    }

    fn send_file_chunk(&self, files: &[Value], delete_missing: bool) -> io::Result<()> {
        post_json(
            &self.config,
            &self.placement,
            &format!("/host/instances/{}/files/sync", encode(&self.instance_ref)),
            &json!({ "files": files, "delete_missing": delete_missing }),
        )?;
        Ok(())
    }

    fn pull_workspace(&self) -> io::Result<()> {
        let listing = get_json(
            &self.config,
            &self.placement,
            &format!("/host/instances/{}/files", encode(&self.instance_ref)),
        )?;
        let mut remote = BTreeSet::new();
        for item in listing
            .get("files")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(path) = item.get("path").and_then(Value::as_str) else {
                continue;
            };
            validate_path(path)?;
            remote.insert(path.to_owned());
            let content = get_text(
                &self.config,
                &self.placement,
                &format!(
                    "/host/instances/{}/files?path={}",
                    encode(&self.instance_ref),
                    encode(path)
                ),
            )?;
            let target = self.worktree.join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(target, content)?;
        }
        for removed in self.synced_paths.difference(&remote) {
            let target = self.worktree.join(removed);
            if target.exists() {
                fs::remove_file(target)?;
            }
        }
        Ok(())
    }
}

fn host_request<T: serde::Serialize>(
    command: &T,
    package: &AuthoredAgentPackage,
) -> io::Result<Value> {
    Ok(json!({
        "command": serde_json::to_value(command).map_err(invalid_data)?,
        "package": {
            "manifest": package.manifest_document(),
            "source": package.source_document(),
            "system_prompt": package.system_prompt_document(),
        }
    }))
}

fn host_turn_request(
    command: &StartTurnCommand,
    package: &AuthoredAgentPackage,
    images: &[ImageContent],
) -> io::Result<Value> {
    let mut request = host_request(command, package)?;
    request["image_bodies"] = Value::Array(
        images
            .iter()
            .map(|image| {
                json!({
                    "media_type": image.mime_type,
                    "data_base64": image.data,
                })
            })
            .collect(),
    );
    Ok(request)
}

fn host_fork_request(
    command: &ForkInstanceCommand,
    package: &AuthoredAgentPackage,
    export: Value,
) -> io::Result<Value> {
    let mut request = host_request(command, package)?;
    request["export"] = export;
    Ok(request)
}

#[cfg(test)]
fn project_result(
    result: &Value,
    resources: &[ResourceRef],
    provider: &str,
    model: &str,
    sink: &mut dyn FnMut(&Observation),
) -> io::Result<TurnOutcome> {
    project_result_inner(result, resources, provider, model, sink, true)
}

fn project_result_inner(
    result: &Value,
    resources: &[ResourceRef],
    provider: &str,
    model: &str,
    sink: &mut dyn FnMut(&Observation),
    emit_final_text: bool,
) -> io::Result<TurnOutcome> {
    let runtime_evidence_pointers = result
        .get("runtime_evidence_pointers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|pointer| serde_json::to_string(pointer).map_err(invalid_data))
        .collect::<io::Result<Vec<_>>>()?;
    let mut outcome = TurnOutcome {
        runtime_evidence_pointers,
        ..TurnOutcome::default()
    };
    let messages = result
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let start = messages
        .iter()
        .rposition(|message| {
            message.get("User").is_some()
                || message.get("role").and_then(Value::as_str) == Some("user")
        })
        .map_or(0, |i| i + 1);
    let mut calls: BTreeMap<String, ToolInfo> = BTreeMap::new();
    for message in &messages[start..] {
        if let Some(assistant) = message.get("Assistant").or_else(|| {
            (message.get("role").and_then(Value::as_str) == Some("assistant")).then_some(message)
        }) {
            let tool_calls = assistant
                .get("tool_calls")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if tool_calls.is_empty() {
                outcome.assistant_text = assistant
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
            }
            for call in tool_calls {
                let id = call
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let name = call
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                calls.insert(
                    id.clone(),
                    ToolInfo {
                        name,
                        call_id: id,
                        target: None,
                        args: call
                            .get("arguments")
                            .cloned()
                            .unwrap_or(Value::Null)
                            .to_string(),
                        ok: None,
                        result: None,
                    },
                );
            }
        }
        let results = message
            .get("ToolResults")
            .and_then(Value::as_array)
            .or_else(|| {
                (message.get("role").and_then(Value::as_str) == Some("tool_results"))
                    .then(|| message.get("results").and_then(Value::as_array))
                    .flatten()
            });
        if let Some(results) = results {
            for item in results {
                if let Some(call) = item
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .and_then(|id| calls.get_mut(id))
                {
                    call.ok = Some(
                        !item
                            .get("is_error")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    );
                    call.result = item
                        .get("content")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                }
            }
        }
    }
    // The hosted turn container may return only its terminal summary. That summary is the
    // provider's final assistant text; the Durable Object can therefore complete without a
    // separate brokered-transcript event. Preserve the richer transcript projection when it
    // exists, but do not render a successful public turn as an empty assistant response merely
    // because that optional event is absent.
    if outcome.assistant_text.is_empty()
        && result.get("run_status").and_then(Value::as_str) == Some("completed")
    {
        outcome.assistant_text = result
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
    }
    for call in calls.into_values() {
        outcome.mediated_tool_calls.push(call.name.clone());
        let observation = Observation {
            kind: "tool_result",
            detail: call.name.clone(),
            tool: Some(call),
        };
        sink(&observation);
        outcome.observations.push(observation);
    }
    if emit_final_text && !outcome.assistant_text.is_empty() {
        sink(&Observation {
            kind: "text",
            detail: outcome.assistant_text.clone(),
            tool: None,
        });
    }
    outcome.output_flow_signature = result
        .get("output_flow_signature")
        .and_then(Value::as_array)
        .map(|flows| {
            flows
                .iter()
                .map(|flow| {
                    Ok(OutputFieldFlow {
                        field: required_json_string(flow, "field", "hosted output flow")?,
                        read_handles: flow
                            .get("reads")
                            .cloned()
                            .map(serde_json::from_value)
                            .transpose()
                            .map_err(invalid_data)?
                            .unwrap_or_default(),
                    })
                })
                .collect::<io::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_else(|| {
            let handles = resources
                .iter()
                .map(|resource| resource.handle.clone())
                .collect::<Vec<_>>();
            ["assistant_text", "tool_calls"]
                .into_iter()
                .map(|field| OutputFieldFlow {
                    field: field.into(),
                    read_handles: handles.clone(),
                })
                .collect()
        });
    if let Some(receipt) = result.get("receipt").filter(|value| !value.is_null()) {
        outcome.runtime_terminal_position = Some(parse_position(
            receipt
                .get("terminal_position")
                .ok_or_else(|| invalid_data("DO receipt omitted terminal_position"))?,
            "DO receipt terminal position",
        )?);
    }
    if let Some(usage) = result
        .get("usage_observation")
        .filter(|value| !value.is_null())
    {
        outcome.managed_usage = Some(ModelUsage {
            usage_ref: required_json_string(usage, "usage_ref", "hosted usage observation")?,
            provider: provider.to_owned(),
            model: model.to_owned(),
            input_tokens: usage
                .get("input_tokens")
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid_data("hosted usage observation omitted input_tokens"))?,
            output_tokens: usage
                .get("output_tokens")
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid_data("hosted usage observation omitted output_tokens"))?,
        });
    }
    let status = result
        .get("run_status")
        .or_else(|| result.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if !matches!(status, "completed" | "succeeded") {
        outcome.error = Some(format!("WhippleScript turn ended {status}"));
    }
    if matches!(status, "completed" | "succeeded")
        && matches!(provider, "cloudflare-ai-gateway" | "cloudflare-workers-ai")
        && outcome.managed_usage.is_none()
    {
        return Err(invalid_data(
            "hosted managed turn completed without a metering observation",
        ));
    }
    Ok(outcome)
}

fn parse_position(value: &Value, name: &str) -> io::Result<RuntimePosition> {
    Ok(RuntimePosition {
        instance_ref: required_json_string(value, "instance_ref", name)?,
        sequence: value
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_data(format!("{name} omitted sequence")))?,
    })
}

fn required_json_string(value: &Value, field: &str, name: &str) -> io::Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid_data(format!("{name} omitted {field}")))
}

fn collect_files(root: &Path, read_only: &[PathBuf]) -> io::Result<BTreeMap<String, String>> {
    fn walk(
        root: &Path,
        dir: &Path,
        read_only: &[PathBuf],
        out: &mut BTreeMap<String, String>,
    ) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.file_name().and_then(|v| v.to_str()) == Some(".git")
                || read_only.iter().any(|item| path.starts_with(item))
            {
                continue;
            }
            let ty = entry.file_type()?;
            if ty.is_dir() {
                walk(root, &path, read_only, out)?;
            } else if ty.is_file() {
                if out.len() >= MAX_FILES {
                    return Err(invalid_data("workspace exceeds 5000-file DO limit"));
                }
                let bytes = fs::read(&path)?;
                if bytes.len() > MAX_FILE_BYTES {
                    return Err(invalid_data("workspace file exceeds 8 MiB DO limit"));
                }
                let content = String::from_utf8(bytes)
                    .map_err(|_| invalid_data("hosted workspace contains a non-UTF-8 file"))?;
                let relative = path
                    .strip_prefix(root)
                    .map_err(invalid_data)?
                    .to_string_lossy()
                    .replace('\\', "/");
                validate_path(&relative)?;
                out.insert(relative, content);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, read_only, &mut out)?;
    Ok(out)
}

fn validate_path(path: &str) -> io::Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        Err(invalid_data("DO returned an invalid workspace path"))
    } else {
        Ok(())
    }
}

fn transport_request(
    config: &DoHostConfig,
    placement: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
    accept: Option<&str>,
) -> DoHostRequest {
    DoHostRequest {
        method: method.to_owned(),
        tenant_id: config.tenant_id.clone(),
        placement_id: placement.to_owned(),
        path: path.to_owned(),
        body,
        accept: accept.map(str::to_owned),
    }
}

fn require_success(response: DoHostResponse) -> io::Result<Vec<u8>> {
    if response.body.len() > 32 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DO host response exceeded the 32 MiB protocol ceiling",
        ));
    }
    if (200..300).contains(&response.status) {
        return Ok(response.body);
    }
    let detail = String::from_utf8_lossy(&response.body);
    let detail = detail.trim();
    Err(io::Error::other(if detail.is_empty() {
        format!("DO host request failed with HTTP {}", response.status)
    } else {
        format!(
            "DO host request failed with HTTP {}: {detail}",
            response.status
        )
    }))
}

fn post_json(
    config: &DoHostConfig,
    placement: &str,
    suffix: &str,
    body: &Value,
) -> io::Result<Value> {
    let body = serde_json::to_vec(body).map_err(invalid_data)?;
    let response = config.transport.send(transport_request(
        config, placement, "POST", suffix, body, None,
    ))?;
    serde_json::from_slice(&require_success(response)?).map_err(invalid_data)
}

enum TurnStreamEvent {
    Ready,
    Delta(String),
    Terminal,
    Unavailable,
}

#[derive(Default)]
struct TurnStreamTiming {
    stream_ready_ms: Option<f64>,
    first_delta_ms: Option<f64>,
    turn_post_complete_ms: Option<f64>,
    terminal_ms: Option<f64>,
    total_ms: f64,
}

fn post_json_with_turn_stream(
    config: &DoHostConfig,
    placement: &str,
    instance: &str,
    command: &str,
    turn_suffix: &str,
    body: &Value,
    sink: &mut dyn FnMut(&Observation),
) -> io::Result<(Value, bool, TurnStreamTiming)> {
    let started_at = Instant::now();
    let mut timing = TurnStreamTiming::default();
    if !config.transport.supports_streaming() {
        return post_json(config, placement, turn_suffix, body).map(|value| {
            timing.total_ms = started_at.elapsed().as_secs_f64() * 1000.0;
            (value, false, timing)
        });
    }
    let (stream_tx, stream_rx) = mpsc::channel();
    let stream_config = config.clone();
    let stream_placement = placement.to_owned();
    let stream_suffix = format!(
        "/host/instances/{}/turns/{}/stream",
        encode(instance),
        encode(command)
    );
    thread::spawn(move || {
        let stream = stream_config.transport.open_stream(transport_request(
            &stream_config,
            &stream_placement,
            "GET",
            &stream_suffix,
            Vec::new(),
            Some("text/event-stream"),
        ));
        let stream = match stream {
            Ok(stream) => stream,
            Err(_) => {
                let _ = stream_tx.send(TurnStreamEvent::Unavailable);
                return;
            }
        };
        let _ = stream_tx.send(TurnStreamEvent::Ready);
        read_turn_stream(stream, &stream_tx);
    });

    // Establish the subscription before starting the command. An older Worker
    // returns 404 here; rolling deploys then retain terminal-only behavior
    // rather than failing the admitted turn.
    let stream_available = matches!(
        stream_rx.recv_timeout(Duration::from_secs(10)),
        Ok(TurnStreamEvent::Ready)
    );
    timing.stream_ready_ms = stream_available.then(|| started_at.elapsed().as_secs_f64() * 1000.0);
    if !stream_available {
        return post_json(config, placement, turn_suffix, body).map(|value| {
            timing.total_ms = started_at.elapsed().as_secs_f64() * 1000.0;
            (value, false, timing)
        });
    }

    let (turn_tx, turn_rx) = mpsc::channel();
    let turn_config = config.clone();
    let turn_placement = placement.to_owned();
    let turn_suffix = turn_suffix.to_owned();
    let turn_body = body.clone();
    thread::spawn(move || {
        let _ = turn_tx.send(post_json(
            &turn_config,
            &turn_placement,
            &turn_suffix,
            &turn_body,
        ));
    });

    let mut streamed_text = false;
    let mut terminal = false;
    let mut turn_result = None;
    let mut turn_completed_at = None;
    while turn_result.is_none() || !terminal {
        if turn_result.is_none() {
            if let Ok(result) = turn_rx.try_recv() {
                turn_result = Some(result);
                turn_completed_at = Some(Instant::now());
                timing.turn_post_complete_ms = Some(started_at.elapsed().as_secs_f64() * 1000.0);
            }
        }
        match stream_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(TurnStreamEvent::Delta(delta)) => {
                timing
                    .first_delta_ms
                    .get_or_insert_with(|| started_at.elapsed().as_secs_f64() * 1000.0);
                streamed_text = true;
                sink(&Observation {
                    kind: "text",
                    detail: delta,
                    tool: None,
                });
            }
            Ok(TurnStreamEvent::Terminal | TurnStreamEvent::Unavailable) => {
                terminal = true;
                timing.terminal_ms = Some(started_at.elapsed().as_secs_f64() * 1000.0);
            }
            Ok(TurnStreamEvent::Ready) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => terminal = true,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The POST owns the provider timeout. Once it completes, give
                // the already-enqueued terminal marker a short drain window.
                if turn_completed_at.is_some_and(|at| at.elapsed() >= Duration::from_secs(2)) {
                    terminal = true;
                }
            }
        }
    }
    let result = turn_result.unwrap_or_else(|| {
        turn_rx
            .recv()
            .unwrap_or_else(|_| Err(io::Error::other("DO turn worker disconnected")))
    })?;
    timing.total_ms = started_at.elapsed().as_secs_f64() * 1000.0;
    Ok((result, streamed_text, timing))
}

fn read_turn_stream(response: Box<dyn BufRead + Send>, sender: &mpsc::Sender<TurnStreamEvent>) {
    let mut event = String::new();
    let mut data = String::new();
    for line in response.lines() {
        let Ok(line) = line else {
            break;
        };
        if line.is_empty() {
            match event.as_str() {
                "text_delta" => {
                    if let Ok(value) = serde_json::from_str::<Value>(&data) {
                        if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                            let _ = sender.send(TurnStreamEvent::Delta(delta.to_owned()));
                        }
                    }
                }
                "terminal" => {
                    let _ = sender.send(TurnStreamEvent::Terminal);
                    return;
                }
                _ => {}
            }
            event.clear();
            data.clear();
        } else if let Some(value) = line.strip_prefix("event:") {
            event = value.trim().to_owned();
        } else if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.trim());
        }
    }
    let _ = sender.send(TurnStreamEvent::Terminal);
}
fn get_json(config: &DoHostConfig, placement: &str, suffix: &str) -> io::Result<Value> {
    let response = config.transport.send(transport_request(
        config,
        placement,
        "GET",
        suffix,
        Vec::new(),
        None,
    ))?;
    serde_json::from_slice(&require_success(response)?).map_err(invalid_data)
}
fn get_text(config: &DoHostConfig, placement: &str, suffix: &str) -> io::Result<String> {
    let response = config.transport.send(transport_request(
        config,
        placement,
        "GET",
        suffix,
        Vec::new(),
        None,
    ))?;
    String::from_utf8(require_success(response)?).map_err(invalid_data)
}
fn http_error(error: ureq::Error) -> io::Error {
    match error {
        ureq::Error::Status(status, response) => {
            let mut body = String::new();
            let _ = response
                .into_reader()
                .take(8 * 1024)
                .read_to_string(&mut body);
            let detail = body.trim();
            if detail.is_empty() {
                io::Error::other(format!("DO host request failed with HTTP {status}"))
            } else {
                io::Error::other(format!(
                    "DO host request failed with HTTP {status}: {detail}"
                ))
            }
        }
        error => io::Error::other(format!("DO host request failed: {error}")),
    }
}
fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn required<T>(value: Option<T>, name: &str) -> io::Result<T> {
    value.ok_or_else(|| invalid_data(format!("{name} is required")))
}
fn required_ref<'a>(value: Option<&'a str>, name: &str) -> io::Result<&'a str> {
    value
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid_data(format!("{name} is required")))
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug, Default)]
    struct RecordingTransport {
        requests: Mutex<Vec<DoHostRequest>>,
    }

    impl DoHostTransport for RecordingTransport {
        fn send(&self, request: DoHostRequest) -> io::Result<DoHostResponse> {
            self.requests.lock().unwrap().push(request);
            Ok(DoHostResponse {
                status: 200,
                body: br#"{"ok":true}"#.to_vec(),
            })
        }
    }

    #[test]
    fn custom_transport_receives_exact_placement_local_operation() {
        let transport = Arc::new(RecordingTransport::default());
        let config = DoHostConfig::with_transport("tenant:one", transport.clone(), false).unwrap();

        let response = post_json(
            &config,
            "placement:one",
            "/host/turns",
            &json!({ "command": "one" }),
        )
        .unwrap();

        assert_eq!(response, json!({ "ok": true }));
        assert!(!config.reuse_across_turns());
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].tenant_id, "tenant:one");
        assert_eq!(requests[0].placement_id, "placement:one");
        assert_eq!(requests[0].path, "/host/turns");
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
            json!({ "command": "one" })
        );
    }

    fn read_http_request(stream: &mut std::net::TcpStream) {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 2048];
        let mut expected = None;
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            if expected.is_none() {
                if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let headers = String::from_utf8_lossy(&bytes[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::trim)
                                .and_then(|value| value.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    expected = Some(header_end + 4 + content_length);
                }
            }
            if expected.is_some_and(|length| bytes.len() >= length) {
                break;
            }
        }
    }

    fn write_chunk(stream: &mut std::net::TcpStream, value: &str) {
        write!(stream, "{:X}\r\n{value}\r\n", value.len()).expect("write chunk");
        stream.flush().expect("flush chunk");
    }

    #[test]
    fn hosted_turn_relays_do_deltas_before_terminal_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut live, _) = listener.accept().expect("live connection");
            read_http_request(&mut live);
            live.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .unwrap();
            live.flush().unwrap();

            let (mut turn, _) = listener.accept().expect("turn connection");
            read_http_request(&mut turn);
            write_chunk(
                &mut live,
                "event: text_delta\ndata: {\"delta\":\"hello\"}\n\n",
            );
            write_chunk(&mut live, "event: terminal\ndata: {}\n\n");
            live.write_all(b"0\r\n\r\n").unwrap();
            live.flush().unwrap();
            let body = r#"{"admitted":true,"outcome":"terminal"}"#;
            write!(
                turn,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            turn.flush().unwrap();
        });
        let config = DoHostConfig::new(format!("http://{address}"), "token", "tenant").unwrap();
        let mut observed = Vec::new();
        let (result, streamed, timing) = post_json_with_turn_stream(
            &config,
            "placement",
            "instance",
            "command",
            "/host/turns",
            &json!({ "command": "test" }),
            &mut |event| observed.push(event.detail.clone()),
        )
        .unwrap();

        server.join().unwrap();
        assert!(streamed);
        assert!(timing.first_delta_ms.is_some());
        assert_eq!(observed, vec!["hello"]);
        assert_eq!(result["outcome"], "terminal");
    }

    #[test]
    fn hosted_projection_folds_assistant_and_tool_messages() {
        let result = json!({
            "run_status": "completed",
            "runtime_evidence_pointers": [{
                "pointer_kind": "turn_receipt",
                "pointer": { "command_id": "turn-1" }
            }],
            "receipt": {
                "terminal_position": { "instance_ref": "instance-1", "sequence": 19 }
            },
            "output_flow_signature": [{
                "field": "assistant_text", "reads": ["command"]
            }, {
                "field": "tool_calls", "reads": ["command"]
            }],
            "messages": [
                { "role": "user", "text": "inspect" },
                { "role": "assistant", "text": "", "tool_calls": [{
                    "id": "call-1", "name": "bash", "arguments": { "command": "printf ok" }
                }] },
                { "role": "tool_results", "results": [{
                    "tool_call_id": "call-1", "tool_name": "bash", "content": "ok", "is_error": false
                }] },
                { "role": "assistant", "text": "done", "tool_calls": [] }
            ]
        });
        let resources = vec![ResourceRef {
            handle: "command".into(),
            kind: "command".into(),
            selector: None,
        }];
        let mut streamed = Vec::new();
        let outcome = project_result(&result, &resources, "openai", "gpt-test", &mut |item| {
            streamed.push(item.clone())
        })
        .expect("projection");
        assert_eq!(outcome.assistant_text, "done");
        assert_eq!(outcome.mediated_tool_calls, vec!["bash"]);
        assert_eq!(
            outcome.observations[0]
                .tool
                .as_ref()
                .and_then(|tool| tool.ok),
            Some(true)
        );
        assert_eq!(
            outcome.output_flow_signature[0].read_handles,
            vec!["command"]
        );
        assert!(outcome.error.is_none());
        assert_eq!(outcome.runtime_evidence_pointers.len(), 1);
        assert_eq!(
            outcome.runtime_terminal_position,
            Some(RuntimePosition {
                instance_ref: "instance-1".into(),
                sequence: 19,
            })
        );
        assert_eq!(streamed.len(), 2);
    }

    #[test]
    fn hosted_projection_uses_completed_summary_without_transcript_event() {
        let result = json!({
            "run_status": "completed",
            "summary": "GaugeWright panel is live.",
            "messages": []
        });
        let mut streamed = Vec::new();
        let outcome = project_result(&result, &[], "openai", "gpt-test", &mut |item| {
            streamed.push(item.clone())
        })
        .expect("projection");

        assert_eq!(outcome.assistant_text, "GaugeWright panel is live.");
        assert_eq!(
            streamed.last().map(|item| item.detail.as_str()),
            Some("GaugeWright panel is live.")
        );
    }

    #[test]
    fn hosted_managed_projection_requires_and_carries_usage() {
        let result = json!({
            "run_status": "completed",
            "usage_observation": {
                "usage_ref": "whip:evidence:usage:7",
                "input_tokens": 11,
                "output_tokens": 4
            },
            "messages": [{ "role": "assistant", "text": "done", "tool_calls": [] }]
        });
        let usage = project_result(
            &result,
            &[],
            "cloudflare-workers-ai",
            "@cf/model",
            &mut |_| {},
        )
        .unwrap()
        .managed_usage
        .unwrap();
        assert_eq!(usage.usage_ref, "whip:evidence:usage:7");
        assert_eq!(usage.provider, "cloudflare-workers-ai");
        assert_eq!(usage.model, "@cf/model");
        assert_eq!(usage.input_tokens, 11);
        assert_eq!(usage.output_tokens, 4);

        let byok_usage = project_result(&result, &[], "openai", "gpt-5", &mut |_| {})
            .unwrap()
            .managed_usage
            .expect("public BYOK turns retain the same runtime usage evidence");
        assert_eq!(byok_usage.usage_ref, "whip:evidence:usage:7");
        assert_eq!(byok_usage.provider, "openai");

        let missing = json!({
            "run_status": "completed",
            "messages": [{ "role": "assistant", "text": "done", "tool_calls": [] }]
        });
        assert!(project_result(
            &missing,
            &[],
            "cloudflare-workers-ai",
            "@cf/model",
            &mut |_| {},
        )
        .is_err());
    }

    #[test]
    fn hosted_paths_and_route_components_fail_closed() {
        assert!(validate_path("src/main.rs").is_ok());
        assert!(validate_path("../secret").is_err());
        assert_eq!(encode("tenant/a"), "tenant%2Fa");
    }
}
