//! Operator-bound native campaign execution. Home owns the private source and
//! resolves one governed work-harness template before either shadow arm runs.

use std::path::PathBuf;

use gaugedesk_boundary::AgentConfig;
use gaugedesk_harness::{sandbox::Network, ChatMode, HarnessFactory, HarnessSpec};
use gaugedesk_workspace::Instance;
use serde::Serialize;

use crate::agent_improve_adoption::AgentDefinitionSnapshot;
use crate::agent_improve_campaign::{
    run_hosted_managed_campaign_with_reservation, run_native_campaign_with_reservation,
    CampaignSnapshot, HostedCampaignExecution, ManagedCampaignFunding, NativeCampaignGate,
    OptimizerFeedback,
};
use crate::agent_improve_custody::{desktop_improve_actor, desktop_improve_bearer};
use crate::agent_improve_evidence::AgentImproveEvidenceRecord;
use crate::engine::{
    default_external_tools, egress_posture, llm_credential_status, method_surface_readonly_roots,
    model_endpoint_hosts, resolve_turn_model, resolve_turn_provider, MembraneGate,
};
use crate::library::{gen_id, InstanceKind};
use crate::policy_compiler::PolicyCompilationInput;
use crate::{LockUnpoisoned, SharedWorkbench};

#[derive(Serialize)]
pub struct NativeImproveResult {
    pub optimizer_feedback: OptimizerFeedback,
    pub reviewer: AgentImproveEvidenceRecord,
}

struct NativeImprovePrepared {
    _scratch: tempfile::TempDir,
    agent_id: String,
    target_id: String,
    target_root: PathBuf,
    candidate_repo: PathBuf,
    expected_main_cut: String,
    campaign: CampaignSnapshot,
    template: HarnessSpec,
    factory: gaugedesk_whip_runtime::WhipHarnessFactory,
    gate: MembraneGate,
    funding: Option<ManagedCampaignFunding>,
}

enum ImproveExecution {
    Native,
    Hosted(crate::managed_funding::FundingAuthority, String),
}

/// The desktop IPC caller supplies identities, never paths, policy or secret
/// material. A live edit turn cannot race the candidate snapshot. All model
/// turns run without holding Home's admission mutex.
pub fn evaluate_agent_improve_from_desktop(
    wb: &SharedWorkbench,
    agent_id: &str,
    edit_chat_id: &str,
    campaign_ref: &str,
) -> Result<NativeImproveResult, String> {
    let bearer = desktop_improve_bearer(wb)?;
    let actor = {
        let guard = wb.lock_unpoisoned();
        desktop_improve_actor(&guard, bearer.as_deref())?
    };
    let _claim = crate::engine::claim_turn(edit_chat_id)
        .ok_or("Finish the edit-chat turn before evaluating this Agent")?;
    let prepared = NativeImprovePrepared::prepare(
        wb,
        agent_id,
        edit_chat_id,
        campaign_ref,
        actor.as_deref(),
        ImproveExecution::Native,
    )?;
    prepared.run(wb, actor.as_deref())
}

/// Home-only hosted evaluation. The caller must have authenticated the actor
/// and tenant before this boundary; it may supply identities, never candidate
/// paths, private cases, policy bytes, placement ids, or funding references.
pub fn evaluate_agent_improve_from_hosted(
    wb: &SharedWorkbench,
    agent_id: &str,
    edit_chat_id: &str,
    campaign_ref: &str,
    actor: &str,
    tenant_scope: &str,
    funding_authority: crate::managed_funding::FundingAuthority,
) -> Result<NativeImproveResult, String> {
    let _claim = crate::engine::claim_turn(edit_chat_id)
        .ok_or("Finish the edit-chat turn before evaluating this Agent")?;
    let prepared = NativeImprovePrepared::prepare(
        wb,
        agent_id,
        edit_chat_id,
        campaign_ref,
        Some(actor),
        ImproveExecution::Hosted(funding_authority, tenant_scope.to_owned()),
    )?;
    prepared.run(wb, Some(actor))
}

pub fn adopt_agent_improve_from_desktop(
    wb: &SharedWorkbench,
    agent_id: &str,
    evidence_id: &str,
) -> Result<Vec<String>, String> {
    let bearer = desktop_improve_bearer(wb)?;
    let mut guard = wb.lock_unpoisoned();
    let actor = desktop_improve_actor(&guard, bearer.as_deref())?;
    guard.adopt_agent_improve_evidence_for_source_owner(agent_id, evidence_id, actor.as_deref())
}

pub fn latest_agent_improve_evidence_from_desktop(
    wb: &SharedWorkbench,
    agent_id: &str,
    campaign_ref: &str,
) -> Result<Option<AgentImproveEvidenceRecord>, String> {
    let bearer = desktop_improve_bearer(wb)?;
    let guard = wb.lock_unpoisoned();
    let actor = desktop_improve_actor(&guard, bearer.as_deref())?;
    guard.latest_agent_improve_evidence_for_source_owner(agent_id, campaign_ref, actor.as_deref())
}

impl NativeImprovePrepared {
    fn prepare(
        wb: &SharedWorkbench,
        agent_id: &str,
        edit_chat_id: &str,
        campaign_ref: &str,
        actor: Option<&str>,
        execution: ImproveExecution,
    ) -> Result<Self, String> {
        let (
            target_id,
            target_root,
            candidate_path,
            expected_main_cut,
            baseline,
            campaign,
            config,
            actor_name,
            provider,
            model,
            base_url_override,
            mut credential_ref,
            class,
            factory,
            roster,
            actor_attributes,
            org_policy,
            advancement_scopes,
            isolated,
        ) = {
            let mut guard = wb.lock_unpoisoned();
            guard.verify_agent_improve_source_owner(agent_id, actor)?;
            let authoring_instance = guard
                .library
                .agents
                .get(agent_id)
                .ok_or("Agent improve source Agent does not exist")?
                .instance_id
                .clone();
            let chat = guard
                .library
                .chats
                .get(edit_chat_id)
                .ok_or("Agent improve edit chat does not exist")?;
            let instance = guard
                .library
                .instances
                .get(&chat.instance_id)
                .ok_or("Agent improve edit chat instance is unavailable")?;
            if instance.kind != InstanceKind::Authoring
                || instance.agent_id != agent_id
                || instance.id != authoring_instance
            {
                return Err("Agent improve candidate must be this Agent's edit chat".to_owned());
            }
            let context = guard
                .engagement_task_context(edit_chat_id)
                .ok_or("Agent improve edit chat workspace is unavailable")?;
            if context.mode != ChatMode::Edit {
                return Err("Agent improve candidate must come from an edit chat".to_owned());
            }
            let target_id = guard.improve_authoring_target(agent_id)?;
            let workspace = guard
                .targets
                .get(&target_id)
                .ok_or("Agent improve authoring target is unavailable")?;
            let expected_main_cut = workspace
                .current_main_cut()
                .map_err(|error| error.to_string())?
                .ok_or("Agent improve authoring Main cut is missing")?;
            let baseline = AgentDefinitionSnapshot::from_main(workspace.as_ref())?;
            let campaign = guard.load_agent_improve_campaign(agent_id, campaign_ref)?;
            let config =
                AgentConfig::from_json(&guard.effective_agent_config_for_chat(edit_chat_id)?)
                    .unwrap_or_default();
            let actor_name = actor
                .map(str::to_owned)
                .unwrap_or_else(|| guard.authority().as_str().to_owned());
            let class = guard.model_execution_class();
            let linked = guard.linked_providers_for_chat_in_class(edit_chat_id, &actor_name, class);
            let provider = resolve_turn_provider(
                gaugedesk_env::var("MODEL_PROVIDER"),
                config.provider.clone(),
                &linked,
            );
            let model = resolve_turn_model(gaugedesk_env::var("MODEL"), config.model.clone())
                .or_else(|| guard.declared_default_model_for_actor(&actor_name, &provider));
            let base_url_override = if provider == "openai-generic" {
                guard.credential_base_url_for_chat_in_class(
                    edit_chat_id,
                    &provider,
                    &actor_name,
                    class,
                )
            } else {
                None
            };
            let credential_ref =
                guard.credential_ref_for_chat_in_class(edit_chat_id, &provider, &actor_name, class);
            let factory = guard
                .whip_harness_factory()
                .map_err(|error| error.to_string())?;
            let org_scope = match &execution {
                ImproveExecution::Native => crate::org::ORG_SCOPE,
                ImproveExecution::Hosted(_, tenant_scope) => tenant_scope.as_str(),
            };
            let org = crate::org::Org::rebuild_in(guard.store_ref(), org_scope)
                .map_err(|error| format!("{error:?}"))?;
            let actor_attributes = guard.idp.as_ref().map_or_else(
                || gaugedesk_core::abac::AuthorityAttributes {
                    clearance: gaugedesk_core::abac::Clearance(3),
                    roles: std::collections::BTreeSet::from([gaugedesk_core::abac::Role::owner()]),
                    region: org
                        .security
                        .as_ref()
                        .and_then(|security| security.residency_region.as_deref())
                        .or_else(|| {
                            org.org
                                .as_ref()
                                .and_then(|record| record.default_region.as_deref())
                        })
                        .map(gaugedesk_core::abac::Region::new),
                    ..Default::default()
                },
                |idp| {
                    org.with_directory_role(
                        idp.claims(&gaugedesk_core::boundary::Authority::from(
                            actor_name.as_str(),
                        )),
                        &actor_name,
                    )
                },
            );
            let advancement_scopes = crate::advancement::AdvancementRules::parse(
                guard
                    .account_settings()
                    .ok()
                    .and_then(|settings| {
                        settings
                            .get(crate::advancement::ADVANCEMENT_RULES_SETTING)
                            .cloned()
                    })
                    .as_deref(),
            )
            .declared_scopes();
            let isolated = guard.chat_network_isolated(edit_chat_id);
            (
                target_id.clone(),
                guard.targets_dir().join(&target_id),
                context.worktree,
                expected_main_cut,
                baseline,
                campaign,
                config,
                actor_name,
                provider,
                model,
                base_url_override,
                credential_ref,
                class,
                factory,
                guard
                    .roster()
                    .into_iter()
                    .map(|person| (person.authority, person.display))
                    .collect::<Vec<_>>(),
                actor_attributes,
                org.policy(),
                advancement_scopes,
                isolated,
            )
        };
        let funding = match execution {
            ImproveExecution::Native => {
                // Native model connections have no managed usage reservation.
                if matches!(
                    provider.as_str(),
                    "cloudflare-ai-gateway" | "cloudflare-workers-ai"
                ) {
                    return Err(
                        "Native Agent improve needs managed-inference funding admission".to_owned(),
                    );
                }
                None
            }
            ImproveExecution::Hosted(funding_authority, tenant_scope) => {
                if provider != crate::managed_inference::METERED_GATEWAY_PROVIDER
                    || factory.kind() != "whip-do"
                {
                    return Err(
                        "Hosted Agent improve needs the metered WhippleScript DO placement"
                            .to_owned(),
                    );
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|error| error.to_string())?
                    .as_secs();
                let guard = wb.lock_unpoisoned();
                guard.verify_agent_improve_source_owner(agent_id, actor)?;
                let account_scope = guard.account_scope_for_actor(&actor_name);
                let grant = crate::managed_funding::resolve_plan(
                    guard.store_ref(),
                    &gaugedesk_core::ids::ScopeId::new(&account_scope),
                    &gaugedesk_core::ids::ScopeId::new(&tenant_scope),
                    &funding_authority.context(now),
                )
                .map_err(|error| format!("{error:?}"))?
                .map_err(|denial| format!("Hosted Agent improve funding refused: {denial:?}"))?;
                let billing_scope = grant.evidence().scope.as_str().to_owned();
                credential_ref = grant.reference();
                Some(ManagedCampaignFunding {
                    account_scope,
                    tenant_scope,
                    billing_scope,
                    funding_ref: credential_ref.clone(),
                    provider: provider.clone(),
                    funding_authority,
                })
            }
        };
        let scratch = tempfile::tempdir().map_err(|error| error.to_string())?;
        if funding.is_none() {
            factory
                .isolated_native_shadow(scratch.path().join("native-check"))
                .map_err(|error| error.to_string())?;
        }
        if funding.is_none()
            && provider == "openai-codex"
            && class == crate::account::ModelExecutionClass::LocalInteractive
        {
            crate::codex_oauth::ensure_local_credential_record(wb)?;
            credential_ref = wb.lock_unpoisoned().credential_ref_for_chat_in_class(
                edit_chat_id,
                &provider,
                &actor_name,
                class,
            );
        }
        let capability = if funding.is_some() {
            None
        } else if provider == "openai-codex" {
            crate::codex_oauth::resolve_turn_credential(wb, &actor_name, class)?.map(|credential| {
                crate::account::resolved_credential_capability(
                    credential_ref.clone(),
                    credential.access,
                    Some(credential.account_id),
                )
            })
        } else if provider == "xai-grok" {
            crate::xai_oauth::resolve_turn_credential(wb, &actor_name, class)?.map(|credential| {
                crate::account::resolved_credential_capability(
                    credential_ref.clone(),
                    credential.access,
                    None,
                )
            })
        } else {
            wb.lock_unpoisoned()
                .credential_capability_for_chat_in_class(
                    edit_chat_id,
                    &provider,
                    &actor_name,
                    class,
                )
        };
        if funding.is_none() {
            llm_credential_status(&provider, capability.as_deref(), &factory)
                .map_err(|error| format!("Agent improve model access: {error}"))?;
        }
        let (model, policy_base_url, wire, endpoint_host, template_base_url) = if funding.is_some()
        {
            let model = model
                .as_deref()
                .filter(|model| !model.trim().is_empty())
                .ok_or("Hosted Agent improve needs an exact managed model")?;
            let route = crate::managed_inference::hosted_metered_route(model);
            (
                route.model,
                route.base_url.clone(),
                route.wire.to_owned(),
                "gateway.ai.cloudflare.com".to_owned(),
                Some(route.base_url),
            )
        } else {
            let descriptor = gaugedesk_whip_runtime::native_provider_descriptor(
                &provider,
                model.as_deref(),
                base_url_override.as_deref(),
            )
            .map_err(|error| error.to_string())?;
            (
                descriptor.model,
                descriptor.base_url,
                descriptor.wire.to_owned(),
                descriptor.endpoint_host,
                base_url_override,
            )
        };
        let candidate = AgentDefinitionSnapshot::capture(&candidate_path)?;
        if baseline.changed_paths(&candidate).is_empty() {
            return Err(
                "Change this Agent's authored files in the edit chat before evaluating".to_owned(),
            );
        }
        let candidate_repo = scratch.path().join("candidate");
        candidate.materialize(&candidate_repo)?;
        let baseline_repo = scratch.path().join("baseline");
        baseline.materialize(&baseline_repo)?;
        let baseline_package = crate::agent_release::snapshot_authored_package(
            &baseline_repo,
            &scratch.path().join("baseline-package"),
        )
        .map_err(|error| error.to_string())?;
        let template_root = scratch.path().join("template");
        std::fs::create_dir(&template_root).map_err(|error| error.to_string())?;
        let posture = egress_posture(
            isolated,
            gaugedesk_env::var("ALLOW_UNFILTERED_EGRESS").as_deref() == Some("1"),
        );
        let hosts = if funding.is_some() || provider == "openai-generic" {
            vec![endpoint_host]
        } else {
            model_endpoint_hosts(Some(&provider))
        };
        let mut read_only = method_surface_readonly_roots(&template_root, ChatMode::Use);
        read_only.extend([
            template_root.join(".whipple"),
            template_root.join(".gaugedesk-runtime"),
        ]);
        read_only.sort();
        read_only.dedup();
        let sandbox = gaugedesk_harness::sandbox::SandboxPolicy::new(vec![template_root.clone()])
            .read_only(read_only);
        let sandbox = match posture {
            Network::Filtered => sandbox.filter_egress(hosts),
            Network::Allow => sandbox.allow_hosts(hosts).allow_unfiltered_egress(true),
            Network::Deny => sandbox.allow_hosts(hosts),
        };
        let chat_id = gen_id("agent-improve-runtime");
        let compiled = {
            let mut guard = wb.lock_unpoisoned();
            guard.verify_agent_improve_source_owner(agent_id, actor)?;
            let workspace = guard
                .targets
                .get(&target_id)
                .ok_or("Agent improve authoring target is unavailable")?;
            if workspace
                .current_main_cut()
                .map_err(|error| error.to_string())?
                .as_deref()
                != Some(&expected_main_cut)
            {
                return Err("Agent draft changed while preparing improvement".to_owned());
            }
            guard.compile_whipple_policy(PolicyCompilationInput {
                chat_id: chat_id.clone(),
                project_id: None,
                actor: actor_name,
                actor_attributes,
                org_policy,
                turn_purpose: None,
                package_capabilities: baseline_package.capabilities().iter().cloned().collect(),
                provider: provider.clone(),
                model: model.clone(),
                base_url: policy_base_url.clone(),
                credential_ref: credential_ref.clone(),
                private_model_broker: None,
                wire,
                placement_kind: if funding.is_some() { "do" } else { "local" }.to_owned(),
                command_network: sandbox.network != Network::Deny,
                resources: Vec::new(),
                task_tracker: None,
                target_bindings: Vec::new(),
                advancement_scopes,
            })?
        };
        let template = HarnessSpec {
            chat_id,
            worktree: template_root,
            mode: ChatMode::Use,
            package_root: None,
            package_version_ref: None,
            policy_epoch: Some(compiled.epoch),
            signed_policy_envelope: Some(compiled.signed_envelope),
            provider_binding_ref: Some(compiled.provider_binding_ref),
            credential_ref: Some(compiled.credential_ref),
            placement_ceiling_ref: Some(compiled.placement_ceiling_ref),
            workspace_targets: Vec::new(),
            runtime_placement_id: funding.as_ref().map(|_| gen_id("agent-improve-placement")),
            provider: Some(provider),
            model: Some(model),
            base_url: template_base_url,
            thinking: config.thinking.clone(),
            system_prompt: None,
            credential_capability: capability,
            sandbox,
            roster,
        };
        Ok(Self {
            _scratch: scratch,
            agent_id: agent_id.to_owned(),
            target_id,
            target_root,
            candidate_repo,
            expected_main_cut,
            campaign,
            template,
            factory,
            gate: MembraneGate::new(&config, default_external_tools()).with_mode(ChatMode::Use),
            funding,
        })
    }

    fn run(self, wb: &SharedWorkbench, actor: Option<&str>) -> Result<NativeImproveResult, String> {
        let workspace = Instance::open_at(&self.target_root);
        if workspace
            .current_main_cut()
            .map_err(|error| error.to_string())?
            .as_deref()
            != Some(&self.expected_main_cut)
        {
            return Err("Agent draft changed before improvement evaluation".to_owned());
        }
        let mut reserve = || {
            wb.lock_unpoisoned()
                .reserve_agent_improve_sealed_exposure(&self.agent_id, self.campaign.reference())
        };
        let selected = match self.funding {
            Some(funding) => run_hosted_managed_campaign_with_reservation(
                wb,
                HostedCampaignExecution {
                    factory: &self.factory,
                    template: &self.template,
                    target_id: &self.target_id,
                    workspace: &workspace,
                    candidate_repo: &self.candidate_repo,
                    campaign: &self.campaign,
                },
                NativeCampaignGate {
                    egress: &self.gate,
                    reserve_sealed: &mut reserve,
                },
                funding,
            )?,
            None => run_native_campaign_with_reservation(
                &self.factory,
                &self.template,
                &self.target_id,
                &workspace,
                &self.candidate_repo,
                &self.campaign,
                NativeCampaignGate {
                    egress: &self.gate,
                    reserve_sealed: &mut reserve,
                },
            )?,
        };
        let optimizer_feedback = selected.optimizer_feedback();
        let reviewer = {
            let mut guard = wb.lock_unpoisoned();
            guard.verify_agent_improve_source_owner(&self.agent_id, actor)?;
            let current = guard
                .targets
                .get(&self.target_id)
                .ok_or("Agent improve authoring target is unavailable")?
                .current_main_cut()
                .map_err(|error| error.to_string())?;
            if current.as_deref() != Some(&self.expected_main_cut) {
                return Err("Agent draft changed during improvement evaluation".to_owned());
            }
            let id =
                guard.append_agent_improve_evidence(&self.agent_id, &self.campaign, &selected)?;
            guard.agent_improve_evidence(&self.agent_id, &id)?
        };
        Ok(NativeImproveResult {
            optimizer_feedback,
            reviewer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_harness::HarnessFactory;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn answer_model_request(stream: &mut TcpStream) -> (bool, bool) {
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 4096];
        let header_end = loop {
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0, "model request ended before its headers");
            request.extend_from_slice(&chunk[..count]);
            if let Some(index) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
        assert!(header.starts_with("POST /v1/chat/completions HTTP/1.1"));
        let content_length = header
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|length| length.trim().parse::<usize>().ok())
            })
            .unwrap();
        while request.len() - header_end < content_length {
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0, "model request ended before its body");
            request.extend_from_slice(&chunk[..count]);
        }
        let body =
            String::from_utf8(request[header_end..header_end + content_length].to_vec()).unwrap();
        let candidate = body.contains("candidate-native-context-marker");
        let token = (0..4)
            .map(|index| format!("token-{index}"))
            .find(|token| body.contains(token))
            .expect("one scenario prompt reaches the model");
        let answer = if candidate { token } else { "wrong".to_owned() };
        let event = serde_json::json!({
            "choices": [{"delta": {"content": answer}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2}
        });
        let payload = format!("data: {event}\n\ndata: [DONE]\n\n");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            payload.len()
        )
        .unwrap();
        stream.write_all(payload.as_bytes()).unwrap();
        (
            candidate,
            header
                .to_ascii_lowercase()
                .contains("authorization: bearer sk-test"),
        )
    }

    #[test]
    fn native_campaign_runs_real_model_turns_and_reserves_held_out_cases() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}/v1", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(60);
            while !server_stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => seen.push(answer_model_request(&mut stream)),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("model listener failed: {error}"),
                }
            }
            seen
        });

        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let (chat_id, candidate_path, campaign_ref) = {
            let mut guard = wb.lock_unpoisoned();
            let actor = guard.authority().as_str().to_owned();
            let scope = guard.account_scope_for_actor(&actor);
            let sealed = crate::account::seal_token(guard.account_key(), "sk-test").unwrap();
            guard
                .upsert_account_credential_in(&scope, "openai-generic".to_owned(), sealed, origin)
                .unwrap();
            guard
                .library
                .agents
                .get_mut(crate::DEFAULT_AGENT)
                .unwrap()
                .config = r#"{"provider":"openai-generic","model":"loopback-test"}"#.to_owned();
            let chat = guard
                .create_chat_under_agent(crate::DEFAULT_AGENT, "Edit Agent")
                .unwrap_or_else(|_| panic!("create edit chat"));
            let pool = serde_json::to_vec(&serde_json::json!({
                "schema":"gaugedesk.agent-improve.pool.v1",
                "gauges":[{"name":"quality","description":"Answer requested token"}],
                "selection":{"ascend":{"quality":null}},
                "scenarios": (0..4).map(|index| serde_json::json!({
                    "id":format!("case-{index}"),
                    "prompt":format!("Answer token-{index}"),
                    "checks":{"quality":{"kind":"assistant-contains","text":format!("token-{index}")}}
                })).collect::<Vec<_>>()
            })).unwrap();
            let reference = guard
                .register_agent_improve_pool(crate::DEFAULT_AGENT, &pool)
                .unwrap();
            let chat_id = chat["id"].as_str().unwrap().to_owned();
            let path = guard.engagement_task_context(&chat_id).unwrap().worktree;
            (chat_id, path, reference)
        };
        let persona = candidate_path.join("agent/AGENTS.md");
        let old = std::fs::read_to_string(&persona).unwrap();
        std::fs::write(
            &persona,
            format!("{old}\ncandidate-native-context-marker\n"),
        )
        .unwrap();
        let result = NativeImprovePrepared::prepare(
            &wb,
            crate::DEFAULT_AGENT,
            &chat_id,
            &campaign_ref,
            None,
            ImproveExecution::Native,
        )
        .and_then(|prepared| prepared.run(&wb, None));
        stop.store(true, Ordering::Relaxed);
        let seen = server.join().unwrap();
        let result = result.unwrap();
        assert_eq!(
            seen.len(),
            8,
            "four cases run through both real harnesses: {seen:?}, {:?}",
            result.reviewer.card
        );
        assert_eq!(seen.iter().filter(|(candidate, _)| *candidate).count(), 4);
        assert!(seen.iter().all(|(_, credential)| *credential));
        assert!(result.reviewer.card.open_verdict.proposable);
        assert!(result.reviewer.card.final_verdict.proposable);
        assert_eq!(result.reviewer.card.holdout_status, "held-out");
        assert_eq!(result.reviewer.card.sealed_evaluated, 2);
        assert!(result.optimizer_feedback.open_verdict.proposable);
        assert_eq!(result.optimizer_feedback.open_scenario_ids.len(), 2);
    }

    #[test]
    fn operator_bound_candidate_opens_both_real_native_arms() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let (chat_id, candidate_path, campaign_ref) = {
            let mut guard = wb.lock_unpoisoned();
            let actor = guard.authority().as_str().to_owned();
            let scope = guard.account_scope_for_actor(&actor);
            let sealed = crate::account::seal_token(guard.account_key(), "sk-test").unwrap();
            guard
                .upsert_account_credential_in(&scope, "openai".to_owned(), sealed, String::new())
                .unwrap();
            guard
                .library
                .agents
                .get_mut(crate::DEFAULT_AGENT)
                .unwrap()
                .config = r#"{"provider":"openai","model":"gpt-test"}"#.to_owned();
            let chat = guard
                .create_chat_under_agent(crate::DEFAULT_AGENT, "Edit Agent")
                .unwrap_or_else(|_| panic!("create edit chat"));
            let pool = serde_json::to_vec(&serde_json::json!({
                "schema":"gaugedesk.agent-improve.pool.v1",
                "gauges":[{"name":"quality","description":"Answer requested token"}],
                "selection":{"ascend":{"quality":null}},
                "scenarios": (0..4).map(|index| serde_json::json!({
                    "id":format!("case-{index}"),
                    "prompt":format!("Answer token-{index}"),
                    "checks":{"quality":{"kind":"assistant-contains","text":format!("token-{index}")}}
                })).collect::<Vec<_>>()
            })).unwrap();
            let reference = guard
                .register_agent_improve_pool(crate::DEFAULT_AGENT, &pool)
                .unwrap();
            let chat_id = chat["id"].as_str().unwrap().to_owned();
            let path = guard.engagement_task_context(&chat_id).unwrap().worktree;
            (chat_id, path, reference)
        };
        let persona = candidate_path.join("agent/AGENTS.md");
        let old = std::fs::read_to_string(&persona).unwrap();
        std::fs::write(
            &persona,
            format!("{old}\nAnswer requested tokens exactly.\n"),
        )
        .unwrap();
        let prepared = NativeImprovePrepared::prepare(
            &wb,
            crate::DEFAULT_AGENT,
            &chat_id,
            &campaign_ref,
            None,
            ImproveExecution::Native,
        )
        .unwrap();
        assert_eq!(prepared.campaign.reference(), campaign_ref);
        assert_eq!(prepared.template.provider.as_deref(), Some("openai"));
        assert!(prepared.template.signed_policy_envelope.is_some());
        let workspace = Instance::open_at(&prepared.target_root);
        let scenario = tempfile::tempdir().unwrap();
        let pair = crate::agent_improve::prepare_native_shadow_pair_from_authoring(
            &prepared.template,
            &workspace,
            &prepared.candidate_repo,
            scenario.path(),
        )
        .unwrap();
        let isolated = prepared
            .factory
            .isolated_native_shadow(root.path().join("native-proof"))
            .unwrap();
        isolated
            .create(pair.baseline_spec())
            .unwrap()
            .shutdown()
            .unwrap();
        isolated
            .create(pair.candidate_spec())
            .unwrap()
            .shutdown()
            .unwrap();
    }
}
