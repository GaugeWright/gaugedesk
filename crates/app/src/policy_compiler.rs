//! GaugeDesk product facts compiled into WhippleScript's governance policy.
//!
//! GaugeDesk owns the inputs and epoch lifecycle; WhippleScript owns the schema,
//! canonicalization, signature bytes, and enforcement.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use gaugedesk_core::abac::{
    permitted_with_policy, Action, AuthorityAttributes, Classification, Context, Decision, Policy,
};
use gaugedesk_core::resource::ResourceRecord;
use gaugedesk_whip_runtime::{
    sign_hosted_policy_envelope, GovernanceRootVerifier, HostGovernancePolicy,
    ProviderBindingPolicy, ResourcePolicy, WhipplePlacementPolicy, QUESTION_ASK_CAPABILITY,
    QUESTION_RESOURCE, TARGET_MANIFEST_RESOURCE,
};

use crate::library::RecordOp;
use crate::Workbench;

const POLICY_RECORD_KIND: &str = "whip_policy_epoch";
const POLICY_RECORD_ID: &str = "active";
pub(crate) const PROVIDER_BINDING_HANDLE: &str = "model";
pub(crate) const PLACEMENT_HANDLE: &str = "local";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyCompilationInput {
    pub chat_id: String,
    pub project_id: Option<String>,
    pub actor: String,
    pub actor_attributes: AuthorityAttributes,
    pub org_policy: Policy,
    pub turn_purpose: Option<String>,
    pub package_capabilities: BTreeSet<String>,
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub credential_ref: String,
    /// Explicit plaintext recipient for private organization-owned model
    /// requests. `None` is the ordinary direct provider path. Supplying one
    /// adds that authority to the input label; selecting a provider alone does
    /// not imply this disclosure.
    pub private_model_broker: Option<String>,
    pub wire: String,
    pub placement_kind: String,
    pub command_network: bool,
    pub resources: Vec<ResourceRecord>,
    /// Current project tracker admitted separately from chat context resources.
    pub task_tracker: Option<ResourceRecord>,
    /// Complete stable-target process binding derived from the chat's pinned
    /// target-set revision. Empty is the single undivided edit-workspace shape.
    pub target_bindings: Vec<crate::target_change_set::ProcessTargetBinding>,
    /// The operator's auto-keep scopes (ATTN-3), declared into the envelope as
    /// the [`crate::advancement::OPERATOR_WRITES_GUARANTEE`] dynamic guarantee
    /// (ADR 0082 §5, WhippleScript DR-0036). Empty = nothing declared.
    pub advancement_scopes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompiledPolicyEpoch {
    pub epoch: u64,
    pub signed_envelope: String,
    pub policy_root: GovernanceRootVerifier,
    pub provider_binding_ref: String,
    pub credential_ref: String,
    pub placement_ceiling_ref: String,
    pub task_tracker_admitted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PolicyEpochRecord {
    id: String,
    #[serde(default)]
    op: RecordOp,
    epoch: u64,
    unsigned_policy: String,
    signed_envelope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
}

#[derive(Default)]
struct PolicyEpochHistory {
    active: Option<PolicyEpochRecord>,
    last_published: u64,
}

impl Workbench {
    /// Compile live product decisions and publish a new immutable epoch only
    /// when their canonical WhippleScript document changes.
    pub(crate) fn compile_whipple_policy(
        &mut self,
        input: PolicyCompilationInput,
    ) -> Result<CompiledPolicyEpoch, String> {
        let policy = compile_policy(&input)?;
        let task_tracker_admitted = policy.bindings.contains_key("tasks");
        let unsigned_policy = declare_guarantees(policy.to_json()?, &input.advancement_scopes)?;
        let (history, basis) =
            self.chat_policy_basis(&input.chat_id, input.project_id.as_deref())?;
        let unchanged = history
            .active
            .as_ref()
            .map(|previous| gaugedesk_whip_runtime::canonicalize(&previous.unsigned_policy))
            .transpose()?
            .as_ref()
            == Some(&gaugedesk_whip_runtime::canonicalize(&unsigned_policy)?);
        let (record, policy_root) = match history.active {
            Some(previous) if unchanged => {
                let (root, roots_basis) =
                    self.chat_policy_root(&input.chat_id, input.project_id.as_deref(), &previous)?;
                let combined = basis
                    .combine(roots_basis)
                    .map_err(|error| format!("{error:?}"))?;
                self.store_mut()
                    .with_dispatch_basis(&combined, || ())
                    .map_err(|error| format!("chat policy authority changed: {error:?}"))?;
                (previous, root)
            }
            previous => {
                let epoch = history
                    .last_published
                    .checked_add(1)
                    .ok_or("WhippleScript policy epoch overflowed")?;
                if let Some(previous) = &previous {
                    let (_, roots_basis) = self.chat_policy_root(
                        &input.chat_id,
                        input.project_id.as_deref(),
                        previous,
                    )?;
                    // Original history must verify even when the new document differs.
                    // Its captured roots are fenced with this publication below.
                    let basis = basis
                        .combine(roots_basis)
                        .map_err(|error| format!("{error:?}"))?;
                    return self.publish_chat_policy(
                        input,
                        unsigned_policy,
                        task_tracker_admitted,
                        epoch,
                        &basis,
                    );
                }
                return self.publish_chat_policy(
                    input,
                    unsigned_policy,
                    task_tracker_admitted,
                    epoch,
                    &basis,
                );
            }
        };
        Ok(CompiledPolicyEpoch {
            epoch: record.epoch,
            signed_envelope: record.signed_envelope,
            policy_root,
            provider_binding_ref: PROVIDER_BINDING_HANDLE.to_owned(),
            credential_ref: input.credential_ref,
            placement_ceiling_ref: PLACEMENT_HANDLE.to_owned(),
            task_tracker_admitted,
        })
    }

    fn publish_chat_policy(
        &mut self,
        input: PolicyCompilationInput,
        unsigned_policy: String,
        task_tracker_admitted: bool,
        epoch: u64,
        basis: &gaugedesk_store::command_dispatch::DispatchReadBasis,
    ) -> Result<CompiledPolicyEpoch, String> {
        let (issuer, key) = match input.project_id.as_deref() {
            Some(project) => {
                self.initialize_project_authority_against(project, basis)
                    .map_err(|e| e.to_string())?;
                let (issuer, _) = self
                    .project_authority_identity(project)
                    .map_err(|e| e.to_string())?;
                (
                    issuer,
                    self.project_signing_key(project)
                        .map_err(|e| e.to_string())?,
                )
            }
            None => (
                self.authority().clone(),
                gaugedesk_core::signature::SigningKey::from_seed(&self.governance_seed())
                    .map_err(|e| e.reason)?,
            ),
        };
        let root = GovernanceRootVerifier::new(issuer.clone(), key.public_key());
        let record = PolicyEpochRecord {
            id: POLICY_RECORD_ID.into(),
            op: RecordOp::Upsert,
            epoch,
            signed_envelope: sign_hosted_policy_envelope(&unsigned_policy, &issuer, &key, epoch)?,
            unsigned_policy,
            issuer: Some(issuer.as_str().into()),
        };
        let snapshot = policy_snapshot(&input.chat_id, &record, &root)?;
        let facts = [gaugedesk_store::CommandRecordFact {
            scope_id: input.chat_id.clone(),
            kind: POLICY_RECORD_KIND.into(),
            payload: serde_json::to_string(&record).map_err(|e| e.to_string())?,
        }];
        self.store_mut()
            .with_dispatch_record_admission(basis, |admission| {
                admission.commit(&input.chat_id, &policy_epoch_key(epoch), &snapshot, &facts)
            })
            .map_err(|error| format!("chat policy authority changed: {error:?}"))?
            .map_err(|error| format!("chat policy publication refused: {error:?}"))?;
        if let Some(harness) = self.sessions.remove(&input.chat_id) {
            crate::workbench_state::shutdown_shared_harness(harness);
        }
        Ok(CompiledPolicyEpoch {
            epoch,
            signed_envelope: record.signed_envelope,
            policy_root: root,
            provider_binding_ref: PROVIDER_BINDING_HANDLE.into(),
            credential_ref: input.credential_ref,
            placement_ceiling_ref: PLACEMENT_HANDLE.into(),
            task_tracker_admitted,
        })
    }

    fn chat_policy_basis(
        &self,
        chat: &str,
        project: Option<&str>,
    ) -> Result<
        (
            PolicyEpochHistory,
            gaugedesk_store::command_dispatch::DispatchReadBasis,
        ),
        String,
    > {
        let handoff = project.map(crate::federation::handoff_scope);
        let mut scopes = vec![crate::library::LIBRARY_SCOPE, chat];
        if let Some(scope) = &handoff {
            scopes.push(scope);
        }
        self.store_ref()
            .read_for_dispatch(&scopes, |store| {
                let library = crate::library::Library::rebuild(store)?;
                let record = library
                    .chats
                    .get(chat)
                    .ok_or_else(|| policy_rejection("chat policy owner is unavailable"))?;
                let instance = library
                    .instances
                    .get(&record.instance_id)
                    .ok_or_else(|| policy_rejection("chat policy placement is unavailable"))?;
                if instance.project_id.as_deref() != project {
                    return Err(policy_rejection(
                        "chat policy project does not match its durable owner",
                    ));
                }
                match project {
                    Some(project) => {
                        if instance.kind != crate::library::InstanceKind::Using
                            || library
                                .projects
                                .get(project)
                                .is_none_or(|p| p.home_id != *self.home_id())
                        {
                            return Err(policy_rejection(
                                "chat policy project authority is not local",
                            ));
                        }
                        crate::federation::require_project_writes_available(store, project)?;
                    }
                    None => {
                        if instance.kind != crate::library::InstanceKind::Authoring
                            || !library.agents.contains_key(&instance.agent_id)
                        {
                            return Err(policy_rejection("chat has no admitted authoring owner"));
                        }
                    }
                }
                latest_epoch_in(store, chat)
            })
            .map_err(|error| format!("chat policy basis refused: {error:?}"))
    }

    pub(crate) fn recorded_chat_policy_root(
        &self,
        chat: &str,
        project: &str,
        epoch: u64,
    ) -> Result<
        (
            GovernanceRootVerifier,
            gaugedesk_store::command_dispatch::DispatchReadBasis,
        ),
        String,
    > {
        let record = recorded_policy_record(self.store_ref(), chat, epoch)?;
        self.chat_policy_root(chat, Some(project), &record)
    }

    fn chat_policy_root(
        &self,
        chat: &str,
        project: Option<&str>,
        record: &PolicyEpochRecord,
    ) -> Result<
        (
            GovernanceRootVerifier,
            gaugedesk_store::command_dispatch::DispatchReadBasis,
        ),
        String,
    > {
        let issuer = record
            .issuer
            .as_deref()
            .unwrap_or(self.authority().as_str());
        let (root, basis) = match project {
            Some(project) => {
                if self
                    .store_ref()
                    .project_authority_key(project)
                    .map_err(|e| format!("{e:?}"))?
                    .is_some_and(|key| key.authority_id == issuer)
                {
                    let (issuer, key) = self
                        .project_authority_identity(project)
                        .map_err(|e| e.to_string())?;
                    let (_, basis) = self
                        .store_ref()
                        .read_for_dispatch(
                            &[&crate::federation::handoff_scope(project)],
                            |_| Ok(()),
                        )
                        .map_err(|e| format!("{e:?}"))?;
                    (GovernanceRootVerifier::new(issuer, key), basis)
                } else {
                    self.project_policy_root(project, issuer)?
                }
            }
            None => {
                if issuer != self.authority().as_str() {
                    return Err("original authoring policy authority is unavailable".into());
                }
                let (_, basis) = self
                    .store_ref()
                    .read_for_dispatch(&[crate::library::LIBRARY_SCOPE], |_| Ok(()))
                    .map_err(|e| format!("{e:?}"))?;
                (
                    GovernanceRootVerifier::new(
                        self.authority().clone(),
                        self.governance_public_key(),
                    ),
                    basis,
                )
            }
        };
        gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
            gaugedesk_whip_runtime::PolicyEpoch::new(record.epoch).map_err(|e| e.to_string())?,
            &record.signed_envelope,
            &root,
        )
        .map_err(|e| e.to_string())?;
        if gaugedesk_whip_runtime::canonicalize(&record.signed_envelope)?
            != gaugedesk_whip_runtime::canonicalize(&record.unsigned_policy)?
        {
            return Err("retained chat policy differs from its signed document".into());
        }
        if record.issuer.is_some()
            && self
                .store_ref()
                .committed_record_snapshot(chat, &policy_epoch_key(record.epoch))
                .map_err(|e| format!("{e:?}"))?
                .as_deref()
                != Some(policy_snapshot(chat, record, &root)?.as_str())
        {
            return Err("chat policy has no matching original publication receipt".into());
        }
        Ok((root, basis))
    }

    /// Verify a transport's original policy coordinate from this Home's
    /// retained chat history and independently selected public root. This
    /// preserves original epochs and supplies no current execution grant.
    pub fn verify_retained_chat_policy(
        &self,
        chat: &str,
        project: Option<&str>,
        expected: &gaugedesk_whip_runtime::PolicyEpochRef,
    ) -> Result<gaugedesk_whip_runtime::AdmittedPolicyEpoch, String> {
        let (_, basis) = self.chat_policy_basis(chat, project)?;
        let mut original = None;
        for body in self
            .store_ref()
            .records(chat, POLICY_RECORD_KIND)
            .map_err(|e| format!("{e:?}"))?
        {
            let record: PolicyEpochRecord =
                serde_json::from_str(&body).map_err(|e| e.to_string())?;
            if record.op == RecordOp::Upsert
                && record.epoch == expected.epoch
                && original.replace(record).is_some()
            {
                return Err("original chat policy epoch is ambiguous".into());
            }
        }
        let original = original.ok_or("original chat policy epoch is unavailable")?;
        let (root, root_basis) = self.chat_policy_root(chat, project, &original)?;
        let basis = basis.combine(root_basis).map_err(|e| format!("{e:?}"))?;
        let admitted = gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
            gaugedesk_whip_runtime::PolicyEpoch::new(original.epoch).map_err(|e| e.to_string())?,
            &original.signed_envelope,
            &root,
        )
        .map_err(|e| e.to_string())?;
        if admitted.protocol_ref() != expected {
            return Err(
                "original chat policy reference differs from its retained publication".into(),
            );
        }
        let (_, current) = self.chat_policy_basis(chat, project)?;
        basis
            .combine(current)
            .map_err(|e| format!("original chat policy basis changed: {e:?}"))?;
        Ok(admitted)
    }

    pub(crate) fn whipple_policy_binding(
        &self,
        chat: &str,
    ) -> Result<
        Option<(
            GovernanceRootVerifier,
            gaugedesk_store::command_dispatch::DispatchReadBasis,
        )>,
        String,
    > {
        let library =
            crate::library::Library::rebuild(self.store_ref()).map_err(|e| format!("{e:?}"))?;
        let (history, basis) = self.chat_policy_basis(chat, library.project_of_chat(chat))?;
        history
            .active
            .map(|record| {
                let (root, root_basis) =
                    self.chat_policy_root(chat, library.project_of_chat(chat), &record)?;
                let basis = basis.combine(root_basis).map_err(|e| format!("{e:?}"))?;
                Ok((root, basis))
            })
            .transpose()
    }

    pub(crate) fn latest_whipple_policy(
        &self,
        chat_id: &str,
    ) -> Result<Option<(u64, String)>, String> {
        latest_epoch(self, chat_id)
            .map(|record| record.map(|record| (record.epoch, record.signed_envelope)))
    }
}

/// Declare the operator's auto-keep scopes as a dynamic envelope guarantee
/// (DR-0036 §2: `{"guarantees":[{"name","paths"}]}` — WhippleScript owns the
/// schema and evaluation; GaugeDesk only composes the declaration). A runtime
/// predating DR-0036 ignores the key (its parser reads known keys only), so
/// declaring is forward-compatible; the report's dynamic section appears once
/// the runtime evaluates it. No scopes → the envelope is untouched, so
/// existing epochs stay hash-stable.
fn declare_guarantees(unsigned_policy: String, scopes: &[String]) -> Result<String, String> {
    if scopes.is_empty() {
        return Ok(unsigned_policy);
    }
    let mut value: serde_json::Value =
        serde_json::from_str(&unsigned_policy).map_err(|error| error.to_string())?;
    value["guarantees"] = serde_json::json!([{
        "name": crate::advancement::OPERATOR_WRITES_GUARANTEE,
        "paths": scopes,
    }]);
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

/// Locate an original epoch without compiling or selecting current settings.
/// The native recorded-runtime owner still verifies the envelope and its exact
/// identity against the original command; this lookup grants no access.
pub(crate) fn recorded_policy_envelope(
    store: &gaugedesk_store::Store,
    chat_id: &str,
    epoch: u64,
) -> Result<String, String> {
    Ok(recorded_policy_record(store, chat_id, epoch)?.signed_envelope)
}

fn recorded_policy_record(
    store: &gaugedesk_store::Store,
    chat_id: &str,
    epoch: u64,
) -> Result<PolicyEpochRecord, String> {
    if epoch == 0 {
        return Err("original runtime policy unavailable".into());
    }
    let records = store
        .records(chat_id, POLICY_RECORD_KIND)
        .map_err(|error| format!("{error:?}"))?
        .into_iter()
        .map(|body| {
            serde_json::from_str::<PolicyEpochRecord>(&body).map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let matches = records
        .iter()
        .filter(|record| record.epoch == epoch)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [record]
            if record.id == POLICY_RECORD_ID
                && record.op == RecordOp::Upsert
                && !record.unsigned_policy.is_empty()
                && !record.signed_envelope.is_empty() =>
        {
            Ok((*record).clone())
        }
        _ => Err("original runtime policy unavailable".into()),
    }
}

fn policy_epoch_key(epoch: u64) -> String {
    format!("whip-policy-epoch:{epoch}")
}

fn policy_snapshot(
    chat: &str,
    record: &PolicyEpochRecord,
    root: &GovernanceRootVerifier,
) -> Result<String, String> {
    serde_json::to_string(&(
        "gaugedesk.chat-policy-epoch.v1",
        chat,
        record.epoch,
        gaugedesk_whip_runtime::canonicalize(&record.unsigned_policy)?,
        root.expected_signer().as_str(),
        root.expected_key().as_str(),
    ))
    .map_err(|e| e.to_string())
}

fn policy_rejection(reason: &'static str) -> gaugedesk_store::AdmitError {
    gaugedesk_store::AdmitError::Rejected(gaugedesk_core::Rejection { reason })
}

fn latest_epoch(wb: &Workbench, chat_id: &str) -> Result<Option<PolicyEpochRecord>, String> {
    latest_epoch_in(wb.store_ref(), chat_id)
        .map(|history| history.active)
        .map_err(|error| format!("{error:?}"))
}

fn latest_epoch_in(
    store: &gaugedesk_store::Store,
    chat_id: &str,
) -> Result<PolicyEpochHistory, gaugedesk_store::AdmitError> {
    let mut history = PolicyEpochHistory::default();
    for body in store.records(chat_id, POLICY_RECORD_KIND)? {
        let record: PolicyEpochRecord = serde_json::from_str(&body)?;
        if record.id != POLICY_RECORD_ID || (record.op == RecordOp::Upsert && record.epoch == 0) {
            return Err(policy_rejection("retained chat policy identity is invalid"));
        }
        history.last_published = history.last_published.max(record.epoch);
        history.active = match record.op {
            RecordOp::Upsert => Some(record),
            RecordOp::Tombstone => None,
        };
    }
    Ok(history)
}

fn compile_policy(input: &PolicyCompilationInput) -> Result<HostGovernancePolicy, String> {
    require_nonempty("chat id", &input.chat_id)?;
    require_nonempty("actor", &input.actor)?;
    require_nonempty("provider", &input.provider)?;
    require_nonempty("model", &input.model)?;
    require_nonempty("provider base URL", &input.base_url)?;
    require_nonempty("credential reference", &input.credential_ref)?;
    if let Some(broker) = &input.private_model_broker {
        require_nonempty("private model broker", broker)?;
    }
    require_nonempty("placement kind", &input.placement_kind)?;

    let actor_role = authority_role(&input.actor);
    let active_resources = input
        .resources
        .iter()
        .filter(|record| !record.tombstoned)
        .collect::<Vec<_>>();
    if let Some(tracker) = &input.task_tracker {
        validate_resources_for_action(
            &[tracker],
            &input.actor_attributes,
            &input.org_policy,
            input.turn_purpose.as_deref(),
            input.placement_kind == "attested",
            Action::Run,
        )?;
    }
    validate_execution_resources(
        &active_resources,
        &input.actor_attributes,
        &input.org_policy,
        input.turn_purpose.as_deref(),
        input.placement_kind == "attested",
    )?;

    let mut workspace_readers = BTreeSet::new();
    for record in &active_resources {
        workspace_readers.extend(resource_reader_roles(record));
    }
    workspace_readers.extend(
        input
            .target_bindings
            .iter()
            .flat_map(|binding| binding.authorities.iter())
            .map(|authority| authority_role(authority)),
    );
    if workspace_readers.is_empty() {
        workspace_readers.insert(actor_role.clone());
    }
    if let Some(broker) = &input.private_model_broker {
        workspace_readers.insert(authority_role(broker));
    }
    let labeled = |principal| ResourcePolicy {
        reader: workspace_readers.clone(),
        writer: BTreeSet::from([actor_role.clone()]),
        principal,
        internal: false,
    };
    let provider_address = format!(
        "provider:{}:{}",
        input.provider,
        short_hash(&format!("{}\0{}", input.model, input.base_url))
    );
    let placement_address = format!(
        "placement:{}:{}",
        input.placement_kind,
        input.project_id.as_deref().unwrap_or("personal")
    );
    let mut policy_resources = BTreeMap::from([
        (
            format!("memory:turn-images:{}", input.chat_id),
            labeled(false),
        ),
        (
            format!("command:workspace:{}", input.chat_id),
            labeled(true),
        ),
        (format!("human:{}", input.actor), labeled(true)),
        (provider_address.clone(), labeled(true)),
        ("provider:owned".to_owned(), labeled(true)),
        (placement_address.clone(), labeled(true)),
    ]);
    let mut policy_bindings = BTreeMap::from([
        (
            "turn_images".to_owned(),
            format!("memory:turn-images:{}", input.chat_id),
        ),
        (
            "command".to_owned(),
            format!("command:workspace:{}", input.chat_id),
        ),
        ("human".to_owned(), format!("human:{}", input.actor)),
        (PROVIDER_BINDING_HANDLE.to_owned(), provider_address),
        ("owned".to_owned(), "provider:owned".to_owned()),
        (PLACEMENT_HANDLE.to_owned(), placement_address),
    ]);
    if input.package_capabilities.contains(QUESTION_ASK_CAPABILITY) {
        let address = format!("question:chat:{}", input.chat_id);
        policy_resources.insert(address.clone(), labeled(true));
        policy_bindings.insert(QUESTION_RESOURCE.to_owned(), address);
    }
    if let Some(tracker) = &input.task_tracker {
        if !input.package_capabilities.contains("tracker.file") {
            return Err("task tracker requires the package tracker.file capability".to_owned());
        }
        let address = tracker.resource.id.as_str().to_owned();
        // Project task readers follow the selected project targets, not the
        // union of every extra context resource admitted to this chat. An
        // outside resource must not widen the task sink merely by being read.
        let mut reader = BTreeSet::from([actor_role.clone()]);
        reader.extend(input.target_bindings.iter().flat_map(|binding| {
            binding
                .authorities
                .iter()
                .map(|authority| authority_role(authority))
        }));
        policy_resources.insert(
            address.clone(),
            ResourcePolicy {
                reader,
                writer: BTreeSet::from([actor_role.clone()]),
                principal: false,
                internal: false,
            },
        );
        policy_bindings.insert("tasks".to_owned(), address);
    }
    // Authored host packages statically declare `project`; it remains an
    // abstract IFC surface so WhippleScript can verify the package. A sparse
    // target turn never sends this handle to a resolver, so it cannot restore
    // undivided workspace access. Concrete runtime access comes only from the
    // per-target bindings below.
    let project_address = format!("file:workspace:{}", input.chat_id);
    policy_resources.insert(project_address.clone(), labeled(false));
    policy_bindings.insert("project".to_owned(), project_address);
    if !input.target_bindings.is_empty() {
        let address = format!("file:target-manifest:{}", input.chat_id);
        policy_resources.insert(address.clone(), labeled(false));
        policy_bindings.insert(TARGET_MANIFEST_RESOURCE.to_owned(), address);
    }
    let mut policy = HostGovernancePolicy {
        resources: policy_resources,
        bindings: policy_bindings,
        parties: BTreeMap::from([(input.actor.clone(), actor_role.clone())]),
        capabilities: input.package_capabilities.clone(),
        provider_bindings: BTreeMap::from([(
            PROVIDER_BINDING_HANDLE.to_owned(),
            ProviderBindingPolicy {
                provider: input.provider.clone(),
                model: input.model.clone(),
                base_url: input.base_url.clone(),
                credential_ref: input.credential_ref.clone(),
                wire: Some(input.wire.clone()),
            },
        )]),
        placements: BTreeMap::from([(
            PLACEMENT_HANDLE.to_owned(),
            WhipplePlacementPolicy {
                kind: input.placement_kind.clone(),
                provider_bindings: BTreeSet::from([PROVIDER_BINDING_HANDLE.to_owned()]),
                command_network: input.command_network,
            },
        )]),
        ..HostGovernancePolicy::default()
    };
    if let Some(broker) = &input.private_model_broker {
        policy
            .parties
            .insert(broker.clone(), authority_role(broker));
    }

    for binding in &input.target_bindings {
        let address = format!("file:target:{}", short_hash(&binding.target_id));
        let mut reader = binding
            .authorities
            .iter()
            .map(|authority| authority_role(authority))
            .collect::<BTreeSet<_>>();
        // Selection/access admission has already established this actor's read
        // authority. Supplying it here is faithful carriage, not a second
        // target-boundary decision.
        reader.insert(actor_role.clone());
        policy.resources.insert(
            address.clone(),
            ResourcePolicy {
                reader,
                // This is the integrity label of data written through the
                // resource, not an ACL. Read-only participation is carried as
                // ResourceRef capability attenuation and enforced by Whip on
                // both placements; an empty writer label would mean untrusted
                // data, not "nobody may write".
                writer: BTreeSet::from([actor_role.clone()]),
                principal: false,
                internal: false,
            },
        );
        policy
            .bindings
            .insert(binding.resource_handle.clone(), address);
        for authority in &binding.authorities {
            policy
                .parties
                .entry(authority.clone())
                .or_insert_with(|| authority_role(authority));
        }
    }

    for record in &active_resources {
        let id = record.resource.id.as_str();
        let address = format!("gaugedesk:resource:{id}");
        let handle = format!("resource:{id}");
        let reader = resource_reader_roles(record);
        for authority in &record.stakeholders {
            policy
                .parties
                .entry(authority.as_str().to_owned())
                .or_insert_with(|| authority_role(authority.as_str()));
        }
        let writer_role = authority_role(record.resource.owner.as_str());
        policy
            .parties
            .entry(record.resource.owner.as_str().to_owned())
            .or_insert_with(|| writer_role.clone());
        policy.resources.insert(
            address.clone(),
            ResourcePolicy {
                reader,
                writer: BTreeSet::from([writer_role]),
                principal: false,
                internal: false,
            },
        );
        policy.bindings.insert(handle, address);
    }
    let clearances = actor_clearances(
        &input.actor_attributes,
        input.turn_purpose.as_deref(),
        &input.resources,
        input
            .target_bindings
            .iter()
            .flat_map(|binding| binding.authorities.iter().map(String::as_str)),
    );
    policy.delegations.extend(
        clearances
            .into_iter()
            .filter(|clearance| clearance != &actor_role)
            .map(|clearance| [actor_role.clone(), clearance]),
    );
    if input.task_tracker.is_some() {
        let document = policy.to_json()?;
        let verified = gaugedesk_whip_runtime::ifc::VerifiedEnvelope::verify_text(&document)?;
        let sources = std::iter::once("turn_images".to_owned())
            .chain(std::iter::once("project".to_owned()))
            .chain(
                input
                    .target_bindings
                    .iter()
                    .map(|binding| binding.resource_handle.clone()),
            )
            .chain(
                active_resources
                    .iter()
                    .map(|record| format!("resource:{}", record.resource.id.as_str())),
            );
        if sources
            .into_iter()
            .any(|source| verified.check_resource_flow(&source, "tasks").is_err())
        {
            if let Some(address) = policy.bindings.remove("tasks") {
                policy.resources.remove(&address);
            }
        }
    }
    policy.validate()?;
    Ok(policy)
}

pub(crate) fn validate_execution_resources(
    resources: &[&ResourceRecord],
    actor_attributes: &AuthorityAttributes,
    org_policy: &Policy,
    purpose: Option<&str>,
    ceiling_attested: bool,
) -> Result<(), String> {
    validate_resources_for_action(
        resources,
        actor_attributes,
        org_policy,
        purpose,
        ceiling_attested,
        Action::Run,
    )
}

pub(crate) fn validate_resources_for_action(
    resources: &[&ResourceRecord],
    actor_attributes: &AuthorityAttributes,
    org_policy: &Policy,
    purpose: Option<&str>,
    ceiling_attested: bool,
    action: Action,
) -> Result<(), String> {
    for record in resources {
        if !permitted_with_policy(
            true,
            org_policy,
            &Decision {
                actor: actor_attributes.clone(),
                resource: record.attributes.clone(),
                action,
                context: Context {
                    // A remote host is not automatically an attested host.
                    // Cloudflare DO is hosted/unattested; only the explicit
                    // confidential-compute placement may raise this ceiling.
                    ceiling_attested,
                },
            },
        ) {
            return Err(format!(
                "organization policy denies runtime access to resource `{}`",
                record.resource.id.as_str()
            ));
        }
        if !record.attributes.purpose.is_empty()
            && purpose.is_none_or(|purpose| {
                !record
                    .attributes
                    .purpose
                    .iter()
                    .any(|allowed| allowed.as_str() == purpose)
            })
        {
            return Err(format!(
                "resource `{}` requires an admitted run purpose ({})",
                record.resource.id.as_str(),
                record
                    .attributes
                    .purpose
                    .iter()
                    .map(|purpose| purpose.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    Ok(())
}

pub(crate) fn actor_clearances<'a>(
    actor_attributes: &AuthorityAttributes,
    purpose: Option<&str>,
    resources: &[ResourceRecord],
    target_authorities: impl IntoIterator<Item = &'a str>,
) -> BTreeSet<String> {
    let mut clearances = BTreeSet::new();
    clearances.insert("classification:public".to_owned());
    // The role floor, not the raw claim: an IdP that asserts no clearance leaves
    // `Clearance::default()`, which clears only `public`, while an unlabeled
    // resource is fail-closed `Regulated` — so the default actor could not read
    // the default resource and an agent turn over an ordinary project was
    // refused for a reason nobody chose. See `Clearance::implied_by`.
    let clearance = actor_attributes.effective_clearance();
    for (level, name) in [
        (1, "classification:internal"),
        (2, "classification:pii"),
        (3, "classification:regulated"),
    ] {
        if clearance.0 >= level {
            clearances.insert(name.to_owned());
        }
    }
    clearances.extend(
        actor_attributes
            .roles
            .iter()
            .map(|role| format!("role:{}", role.as_str())),
    );
    if let Some(region) = &actor_attributes.region {
        clearances.insert(format!("residency:{}", region.as_str()));
    }
    if let Some(purpose) = purpose {
        clearances.insert(format!("purpose:{purpose}"));
    }
    // A granted GaugeDesk resource-access decision explicitly clears this actor
    // for the stakeholder compartments on the resources handed to the runtime.
    for record in resources {
        clearances.extend(
            record
                .stakeholders
                .iter()
                .map(|authority| authority_role(authority.as_str())),
        );
    }
    clearances.extend(target_authorities.into_iter().map(authority_role));
    clearances
}

pub(crate) fn resource_reader_roles(record: &ResourceRecord) -> BTreeSet<String> {
    let mut roles = record
        .stakeholders
        .iter()
        .map(|authority| authority_role(authority.as_str()))
        .collect::<BTreeSet<_>>();
    roles.insert(format!(
        "classification:{}",
        match record.attributes.classification {
            Classification::Public => "public",
            Classification::Internal => "internal",
            Classification::Pii => "pii",
            Classification::Regulated => "regulated",
        }
    ));
    if let Some(region) = &record.attributes.region {
        roles.insert(format!("residency:{}", region.as_str()));
    }
    roles.extend(
        record
            .attributes
            .purpose
            .iter()
            .map(|purpose| format!("purpose:{}", purpose.as_str())),
    );
    roles
}

pub(crate) fn authority_role(authority: &str) -> String {
    format!("authority:{}", short_hash(authority))
}

fn short_hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..24].to_owned()
}

fn require_nonempty(what: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{what} must not be empty"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::boundary::Authority;
    use gaugedesk_core::resource::{ContentLocator, Resource, ResourceId, ResourceKind};
    use gaugedesk_store::Store;
    use gaugedesk_whip_runtime::sign_policy_envelope;

    fn input() -> PolicyCompilationInput {
        PolicyCompilationInput {
            chat_id: "chat-1".to_owned(),
            project_id: Some("project-1".to_owned()),
            actor: "operator-1".to_owned(),
            actor_attributes: AuthorityAttributes {
                clearance: gaugedesk_core::abac::Clearance(3),
                ..AuthorityAttributes::default()
            },
            org_policy: Policy::default(),
            turn_purpose: None,
            package_capabilities: BTreeSet::from([
                "workspace.read".to_owned(),
                "workspace.write".to_owned(),
            ]),
            provider: "openai".to_owned(),
            model: "gpt-5".to_owned(),
            base_url: "https://api.openai.com".to_owned(),
            credential_ref: "credential:gaugedesk/account/alice/openai/v1".to_owned(),
            private_model_broker: None,
            wire: "openai-responses".to_owned(),
            placement_kind: "local".to_owned(),
            command_network: false,
            resources: Vec::new(),
            task_tracker: None,
            target_bindings: Vec::new(),
            advancement_scopes: Vec::new(),
        }
    }

    #[test]
    fn question_resource_is_governed_only_for_an_admitted_asking_agent() {
        let mut turn = input();
        let without = compile_policy(&turn).expect("policy without asking");
        assert!(!without.bindings.contains_key(QUESTION_RESOURCE));

        turn.package_capabilities
            .insert(QUESTION_ASK_CAPABILITY.to_owned());
        let with = compile_policy(&turn).expect("policy with asking");
        let address = with
            .bindings
            .get(QUESTION_RESOURCE)
            .expect("governed question binding");
        let resource = with.resources.get(address).expect("question label");
        assert!(resource.principal);
        assert_eq!(resource, with.resources.get("human:operator-1").unwrap());
    }

    #[test]
    fn task_tracker_is_offered_only_when_every_admitted_input_can_flow_to_it() {
        let make = |id: &str, owner: &str| {
            ResourceRecord::new(
                Resource::input(
                    ResourceId::new(id),
                    ResourceKind::context(),
                    Authority::from(owner),
                ),
                ContentLocator::Content {
                    handle: id.to_owned(),
                },
                |_| Authority::from(owner),
            )
        };
        let mut turn = input();
        turn.package_capabilities.insert("tracker.file".to_owned());
        turn.task_tracker = Some(make("tracker:tasks", "home"));
        let plain = compile_policy(&turn).unwrap();
        assert!(plain.bindings.contains_key("tasks"));

        turn.resources
            .push(make("private-context", "outside-client"));
        let with_external_input = compile_policy(&turn).unwrap();
        assert!(!with_external_input.bindings.contains_key("tasks"));
        assert!(!with_external_input.resources.contains_key("tracker:tasks"));
    }

    /// The envelope an OIDC actor gets when the IdP asserts no clearance.
    ///
    /// This is the production case: the wiring canary's owner authenticated
    /// through OIDC, whose claims carry no clearance, so the compiled epoch
    /// cleared only `classification:public` while the project it owned was
    /// unlabeled — therefore fail-closed `Regulated` — and the agent turn was
    /// denied `denied read in rule \`converse\``. The role is the authorization
    /// fact the directory carries, so it supplies the floor.
    #[test]
    fn an_owner_clears_regulated_without_a_clearance_claim() {
        let mut owner = input();
        owner.actor_attributes = AuthorityAttributes {
            clearance: gaugedesk_core::abac::Clearance(0),
            roles: BTreeSet::from([gaugedesk_core::abac::Role::owner()]),
            ..AuthorityAttributes::default()
        };
        let epoch = compile_policy(&owner)
            .expect("policy")
            .to_json()
            .expect("json");
        for level in ["public", "internal", "pii", "regulated"] {
            assert!(
                epoch.contains(&format!("classification:{level}")),
                "an owner must clear {level}: {epoch}",
            );
        }

        // A billing-only authority is never run/access authority (INV-18), so
        // the floor lifts it no further than the fail-closed default.
        let mut billing = input();
        billing.actor_attributes = AuthorityAttributes {
            clearance: gaugedesk_core::abac::Clearance(0),
            roles: BTreeSet::from([gaugedesk_core::abac::Role::billing()]),
            ..AuthorityAttributes::default()
        };
        let epoch = compile_policy(&billing)
            .expect("policy")
            .to_json()
            .expect("json");
        assert!(epoch.contains("classification:public"), "{epoch}");
        assert!(
            !epoch.contains("classification:regulated"),
            "billing must not reach regulated: {epoch}",
        );
    }

    #[test]
    fn auto_keep_scopes_declare_the_operator_guarantee() {
        // No scopes → the envelope is untouched (existing epochs hash-stable).
        let bare = compile_policy(&input())
            .expect("policy")
            .to_json()
            .expect("json");
        assert_eq!(declare_guarantees(bare.clone(), &[]).expect("noop"), bare);

        // Scopes → one declared guarantee under the stable operator name.
        let declared =
            declare_guarantees(bare, &["docs/**".to_owned(), "*.md".to_owned()]).expect("declare");
        let value: serde_json::Value = serde_json::from_str(&declared).expect("parse");
        assert_eq!(
            value["guarantees"],
            serde_json::json!([{
                "name": crate::advancement::OPERATOR_WRITES_GUARANTEE,
                "paths": ["docs/**", "*.md"],
            }])
        );
    }

    #[test]
    fn compilation_binds_product_authority_package_provider_and_placement() {
        let policy = compile_policy(&input()).expect("policy");
        let expected_role = authority_role("operator-1");
        assert_eq!(
            policy.parties.get("operator-1").map(String::as_str),
            Some(expected_role.as_str())
        );
        assert!(policy.capabilities.contains("workspace.write"));
        assert_eq!(
            policy
                .provider_bindings
                .get(PROVIDER_BINDING_HANDLE)
                .map(|binding| binding.credential_ref.as_str()),
            Some("credential:gaugedesk/account/alice/openai/v1")
        );
        assert_eq!(
            policy
                .provider_bindings
                .get(PROVIDER_BINDING_HANDLE)
                .and_then(|binding| binding.wire.as_deref()),
            Some("openai-responses")
        );
        assert!(policy
            .placements
            .get(PLACEMENT_HANDLE)
            .is_some_and(|placement| !placement.command_network));
    }

    #[test]
    fn private_model_broker_is_an_explicit_input_reader_not_an_implied_provider_right() {
        let direct = compile_policy(&input()).expect("direct policy");
        assert!(!direct.parties.contains_key("authority:private-broker"));

        let mut brokered = input();
        brokered.private_model_broker = Some("authority:private-broker".to_owned());
        let brokered = compile_policy(&brokered).expect("brokered policy");
        let broker_role = authority_role("authority:private-broker");
        assert_eq!(
            brokered
                .parties
                .get("authority:private-broker")
                .map(String::as_str),
            Some(broker_role.as_str())
        );
        let provider = brokered
            .bindings
            .get(PROVIDER_BINDING_HANDLE)
            .and_then(|address| brokered.resources.get(address))
            .expect("provider input label");
        assert!(provider.reader.contains(&broker_role));
    }

    #[test]
    fn compilation_binds_the_complete_sparse_target_set_with_write_ceiling() {
        let mut input = input();
        input.target_bindings = vec![
            crate::target_change_set::ProcessTargetBinding {
                target_id: "target-a".to_owned(),
                resource_handle: "target:t-a".to_owned(),
                root: "targets/t-a".to_owned(),
                native_basis: "git:aaaa".to_owned(),
                adapter_family: "git".to_owned(),
                path_scope: vec![".".to_owned()],
                capabilities: crate::library::TargetCapabilities::managed_default(),
                participation: crate::library::TargetParticipationMode::Writable,
                authorities: vec!["client-a".to_owned()],
                readable: true,
                writable: true,
                output: true,
                name: String::new(),
            },
            crate::target_change_set::ProcessTargetBinding {
                target_id: "target-b".to_owned(),
                resource_handle: "target:t-b".to_owned(),
                root: "targets/t-b".to_owned(),
                native_basis: "folder:bbbb".to_owned(),
                adapter_family: "folder".to_owned(),
                path_scope: vec!["docs/**".to_owned()],
                capabilities: crate::library::TargetCapabilities::managed_default(),
                participation: crate::library::TargetParticipationMode::ReadOnly,
                authorities: vec!["client-b".to_owned()],
                readable: true,
                writable: false,
                output: false,
                name: String::new(),
            },
        ];

        let policy = compile_policy(&input).expect("multi-target policy");
        assert!(policy.bindings.contains_key("project"));
        assert!(policy.bindings.contains_key(TARGET_MANIFEST_RESOURCE));
        let writable_address = policy.bindings.get("target:t-a").expect("writable handle");
        let read_only_address = policy.bindings.get("target:t-b").expect("read-only handle");
        assert!(!policy.resources[writable_address].writer.is_empty());
        assert!(!policy.resources[read_only_address].writer.is_empty());
        assert!(policy.resources[writable_address]
            .reader
            .contains(&authority_role("client-a")));
        assert!(policy.resources[read_only_address]
            .reader
            .contains(&authority_role("client-b")));

        // Exercise the actual WhippleScript trust boundary, not only this
        // compiler's Rust shape. The authored package still names its abstract
        // `project` surface, while runtime commands carry only these concrete
        // target handles and the immutable manifest.
        let authority = gaugedesk_core::ids::AuthorityId::new("authority:policy-test");
        let key = gaugedesk_core::signature::SigningKey::from_seed(&[41u8; 32]).unwrap();
        let signed =
            sign_policy_envelope(&policy.to_json().expect("policy json"), &authority, &key)
                .expect("signed policy");
        let verifier =
            gaugedesk_whip_runtime::GovernanceRootVerifier::new(authority, key.public_key());
        let admitted = gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
            gaugedesk_whip_runtime::PolicyEpoch::new(1).unwrap(),
            &signed,
            &verifier,
        )
        .expect("WhippleScript admits the exact sparse policy");
        assert!(admitted.governs("project"));
        assert!(admitted.governs("target:t-a"));
        assert!(admitted.governs("target:t-b"));
        assert!(admitted.governs(TARGET_MANIFEST_RESOURCE));
    }

    #[test]
    fn compilation_projects_real_resource_stakeholders_into_reader_labels() {
        let resource = Resource::input(
            ResourceId::new("customer-data"),
            ResourceKind::context(),
            Authority::from("client"),
        );
        let record = ResourceRecord::new(
            resource,
            ContentLocator::Content {
                handle: "content-1".to_owned(),
            },
            |_| Authority::from("client"),
        );
        let mut input = input();
        input.resources.push(record);
        let policy = compile_policy(&input).expect("policy");
        let label = policy
            .resources
            .get("gaugedesk:resource:customer-data")
            .expect("resource label");
        assert!(label.reader.contains(&authority_role("client")));
        assert!(label.reader.contains("classification:regulated"));
        assert!(policy
            .resources
            .get("file:workspace:chat-1")
            .is_some_and(|workspace| workspace.reader == label.reader));
        assert!(policy
            .delegations
            .contains(&[authority_role("operator-1"), authority_role("client")]));
        assert_eq!(
            policy.bindings.get("resource:customer-data"),
            Some(&"gaugedesk:resource:customer-data".to_owned())
        );
    }

    #[test]
    fn purpose_constrained_resource_fails_closed_without_an_admitted_run_purpose() {
        let resource = Resource::input(
            ResourceId::new("customer-data"),
            ResourceKind::context(),
            Authority::from("client"),
        );
        let record = ResourceRecord::new(
            resource,
            ContentLocator::Content {
                handle: "content-1".to_owned(),
            },
            |_| Authority::from("client"),
        )
        .with_attributes(gaugedesk_core::abac::ResourceAttributes {
            purpose: BTreeSet::from([gaugedesk_core::abac::Purpose::new("support")]),
            ..Default::default()
        });
        let mut input = input();
        input.resources.push(record);
        assert!(compile_policy(&input)
            .expect_err("missing purpose decision must deny")
            .contains("requires an admitted run purpose"));
        input.turn_purpose = Some("support".to_owned());
        assert!(compile_policy(&input).is_ok());
    }

    fn project_chat(wb: &mut Workbench, project: &str, chat: &str) {
        let rows = [
            (
                "project",
                serde_json::json!({
                    "id": project, "name": project, "home_id": wb.home_id(),
                    "is_default": false, "network_isolated": false
                }),
            ),
            (
                "instance",
                serde_json::json!({
                    "id": format!("placement:{chat}"), "kind": "using",
                    "agent_id": "agent", "project_id": project
                }),
            ),
            (
                "chat",
                serde_json::json!({
                    "id": chat, "instance_id": format!("placement:{chat}"), "title": chat
                }),
            ),
        ];
        for (kind, body) in rows {
            wb.store_mut()
                .append_record(crate::library::LIBRARY_SCOPE, kind, &body.to_string())
                .unwrap();
        }
    }

    fn project_workbench() -> Workbench {
        let mut wb = Workbench::new(Store::open_in_memory().unwrap());
        project_chat(&mut wb, "project-1", "chat-1");
        wb
    }

    fn legacy_epoch(wb: &mut Workbench, epoch: u64) -> PolicyEpochRecord {
        let input = input();
        let unsigned_policy = compile_policy(&input).unwrap().to_json().unwrap();
        let key = gaugedesk_core::signature::SigningKey::from_seed(&wb.governance_seed()).unwrap();
        let record = PolicyEpochRecord {
            id: POLICY_RECORD_ID.into(),
            op: RecordOp::Upsert,
            epoch,
            signed_envelope: sign_policy_envelope(&unsigned_policy, wb.authority(), &key).unwrap(),
            unsigned_policy,
            issuer: None,
        };
        wb.store_mut()
            .append_record(
                "chat-1",
                POLICY_RECORD_KIND,
                &serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
        record
    }

    fn persistent_project_workbench(root: &std::path::Path) -> Workbench {
        let mut wb =
            Workbench::new(Store::open(root.join("product.sqlite").to_str().unwrap()).unwrap())
                .with_root(root)
                .with_content_vault(std::sync::Arc::new(
                    crate::content_vault::ContentVault::new(
                        root.join("content-keys"),
                        Box::new(crate::at_rest::LoopbackKeyWrap::new([7; 32])),
                    ),
                ));
        project_chat(&mut wb, "project-1", "chat-1");
        wb
    }

    #[test]
    fn new_project_policy_binds_its_own_public_authority_and_epoch() {
        let mut wb = project_workbench();
        let first = wb.compile_whipple_policy(input()).unwrap();
        let (issuer, key) = wb.project_authority_identity("project-1").unwrap();
        assert_eq!(
            first.policy_root,
            GovernanceRootVerifier::new(issuer.clone(), key)
        );
        assert_ne!(first.policy_root.expected_signer(), wb.authority());
        let attestation = gaugedesk_whip_runtime::SignedEnvelope::verify_attestation_with(
            &first.signed_envelope,
            &first.policy_root,
        )
        .unwrap();
        assert_eq!(attestation.epoch, Some(first.epoch));
        assert_eq!(attestation.authority.as_deref(), Some(issuer.as_str()));
        assert_eq!(attestation.signer, issuer.as_str());
        assert!(
            gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
                gaugedesk_whip_runtime::PolicyEpoch::new(first.epoch + 1).unwrap(),
                &first.signed_envelope,
                &first.policy_root,
            )
            .is_err(),
            "epoch substitution must fail"
        );
        let root = tempfile::tempdir().unwrap();
        gaugedesk_whip_runtime::GovernedHostRuntime::open_with_verifier(
            root.path().join("runtime.sqlite"),
            first.epoch,
            &first.signed_envelope,
            &first.policy_root,
        )
        .expect("the actual native runtime admits the compiler output");
    }

    #[test]
    fn two_projects_on_the_same_host_never_share_chat_policy_roots() {
        let mut wb = project_workbench();
        project_chat(&mut wb, "project-2", "chat-2");
        let one = wb.compile_whipple_policy(input()).unwrap();
        let mut second = input();
        second.chat_id = "chat-2".into();
        second.project_id = Some("project-2".into());
        let two = wb.compile_whipple_policy(second).unwrap();
        assert_ne!(one.policy_root, two.policy_root);
        assert!(gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
            gaugedesk_whip_runtime::PolicyEpoch::new(one.epoch).unwrap(),
            &one.signed_envelope,
            &two.policy_root,
        )
        .is_err());
    }

    #[test]
    fn retained_chat_policy_reader_checks_every_original_coordinate_and_owner() {
        let mut wb = project_workbench();
        project_chat(&mut wb, "project-2", "chat-2");
        let one = wb.compile_whipple_policy(input()).unwrap();
        let admitted = gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
            gaugedesk_whip_runtime::PolicyEpoch::new(one.epoch).unwrap(),
            &one.signed_envelope,
            &one.policy_root,
        )
        .unwrap();
        let reference = admitted.protocol_ref().clone();
        let mut other_input = input();
        other_input.chat_id = "chat-2".into();
        other_input.project_id = Some("project-2".into());
        let other = wb.compile_whipple_policy(other_input).unwrap();
        let other_reference = gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
            gaugedesk_whip_runtime::PolicyEpoch::new(other.epoch).unwrap(),
            &other.signed_envelope,
            &other.policy_root,
        )
        .unwrap()
        .protocol_ref()
        .clone();
        assert!(wb
            .verify_retained_chat_policy("chat-2", Some("project-2"), &other_reference)
            .is_ok());
        assert!(wb
            .verify_retained_chat_policy("chat-2", Some("project-1"), &other_reference)
            .err()
            .unwrap()
            .contains("durable owner"));
        assert_eq!(
            wb.verify_retained_chat_policy("chat-1", Some("project-1"), &reference)
                .unwrap()
                .protocol_ref(),
            &reference
        );
        assert!(wb
            .verify_retained_chat_policy("chat-2", Some("project-1"), &reference)
            .is_err());
        assert!(wb
            .verify_retained_chat_policy("unknown", Some("project-1"), &reference)
            .is_err());
        for changed in [
            {
                let mut changed = reference.clone();
                changed.epoch += 1;
                changed
            },
            {
                let mut changed = reference.clone();
                changed.envelope_hash = "0".repeat(64);
                changed
            },
            {
                let mut changed = reference.clone();
                changed.signer = wb.authority().as_str().into();
                changed
            },
            {
                let mut changed = reference.clone();
                changed.key_id = Some(wb.governance_public_key().as_str().into());
                changed
            },
        ] {
            assert!(wb
                .verify_retained_chat_policy("chat-1", Some("project-1"), &changed)
                .is_err());
        }
        let original = latest_epoch(&wb, "chat-1").unwrap().unwrap();
        wb.store_mut()
            .append_record(
                "chat-1",
                POLICY_RECORD_KIND,
                &serde_json::to_string(&original).unwrap(),
            )
            .unwrap();
        assert!(wb
            .verify_retained_chat_policy("chat-1", Some("project-1"), &reference)
            .err()
            .unwrap()
            .contains("ambiguous"));
    }

    #[test]
    fn retained_chat_policy_reader_preserves_legacy_and_project_history_without_private_custody() {
        let root = tempfile::tempdir().unwrap();
        let mut wb = persistent_project_workbench(root.path());
        let legacy = legacy_epoch(&mut wb, 7);
        let legacy_root =
            GovernanceRootVerifier::new(wb.authority().clone(), wb.governance_public_key());
        let legacy_ref = gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
            gaugedesk_whip_runtime::PolicyEpoch::new(7).unwrap(),
            &legacy.signed_envelope,
            &legacy_root,
        )
        .unwrap()
        .protocol_ref()
        .clone();
        let mut changed = input();
        changed.model = "new-model".into();
        let project = wb.compile_whipple_policy(changed).unwrap();
        assert_eq!(project.epoch, 8);
        let project_ref = gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
            gaugedesk_whip_runtime::PolicyEpoch::new(project.epoch).unwrap(),
            &project.signed_envelope,
            &project.policy_root,
        )
        .unwrap()
        .protocol_ref()
        .clone();
        let before = wb
            .store_ref()
            .records("chat-1", POLICY_RECORD_KIND)
            .unwrap();
        std::fs::remove_file(
            root.path()
                .join("content-keys/projects")
                .join(format!("{}.key", crate::org::sha256_hex("project-1"))),
        )
        .unwrap();
        for reference in [legacy_ref, project_ref] {
            assert_eq!(
                wb.verify_retained_chat_policy("chat-1", Some("project-1"), &reference)
                    .unwrap()
                    .protocol_ref(),
                &reference
            );
        }
        assert_eq!(
            wb.store_ref()
                .records("chat-1", POLICY_RECORD_KIND)
                .unwrap(),
            before
        );
    }

    #[test]
    fn retained_chat_policy_reader_refuses_a_late_real_history_append() {
        // Failure injection uses the actual product writer and original signed
        // publication; it supplies neither an alternate policy nor a verifier.
        struct LateAppend {
            path: String,
            body: String,
            reads: std::sync::atomic::AtomicUsize,
        }
        impl gaugedesk_store::ContentCodec for LateAppend {
            fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
                Ok(payload.into())
            }
            fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String> {
                if scope == "chat-1"
                    && kind == POLICY_RECORD_KIND
                    && self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1
                {
                    let mut writer = Store::open(&self.path).expect("real concurrent writer");
                    writer
                        .append_record(scope, kind, &self.body)
                        .expect("real late history append");
                }
                Some(payload.into())
            }
        }
        let root = tempfile::tempdir().unwrap();
        let mut wb = persistent_project_workbench(root.path());
        let policy = wb.compile_whipple_policy(input()).unwrap();
        let reference = gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
            gaugedesk_whip_runtime::PolicyEpoch::new(policy.epoch).unwrap(),
            &policy.signed_envelope,
            &policy.policy_root,
        )
        .unwrap()
        .protocol_ref()
        .clone();
        let original = latest_epoch(&wb, "chat-1").unwrap().unwrap();
        let path = wb.store_ref().path().to_owned();
        wb.store = Store::open(&path)
            .unwrap()
            .with_codec(std::sync::Arc::new(LateAppend {
                path,
                body: serde_json::to_string(&original).unwrap(),
                reads: std::sync::atomic::AtomicUsize::new(0),
            }));
        assert!(wb
            .verify_retained_chat_policy("chat-1", Some("project-1"), &reference)
            .err()
            .unwrap()
            .contains("basis changed"));
        assert_eq!(
            wb.store_ref()
                .records("chat-1", POLICY_RECORD_KIND)
                .unwrap()
                .len(),
            2,
            "the writer really appended while the original record was being read"
        );
    }

    #[test]
    fn compiler_refuses_unknown_chat_and_project_substitution_before_key_creation() {
        let mut wb = Workbench::new(Store::open_in_memory().unwrap());
        assert!(wb.compile_whipple_policy(input()).is_err());
        assert!(wb
            .store_ref()
            .project_authority_key("project-1")
            .unwrap()
            .is_none());
        project_chat(&mut wb, "project-1", "chat-1");
        let mut substituted = input();
        substituted.project_id = Some("project-2".into());
        assert!(wb
            .compile_whipple_policy(substituted)
            .unwrap_err()
            .contains("durable owner"));
        assert!(wb
            .store_ref()
            .project_authority_key("project-2")
            .unwrap()
            .is_none());
        let mut missing = input();
        missing.project_id = None;
        assert!(
            wb.compile_whipple_policy(missing).is_err(),
            "missing project cannot become authoring"
        );
        assert!(wb
            .store_ref()
            .records("chat-1", POLICY_RECORD_KIND)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn unchanged_legacy_policy_reuses_exact_identity_without_project_signing_custody() {
        let mut wb = project_workbench();
        let previous = legacy_epoch(&mut wb, 5);
        let before = wb.store_ref().events("chat-1").unwrap();
        let reused = wb.compile_whipple_policy(input()).unwrap();
        assert_eq!(reused.epoch, 5);
        assert_eq!(reused.signed_envelope, previous.signed_envelope);
        assert_eq!(reused.policy_root.expected_signer(), wb.authority());
        assert_eq!(wb.store_ref().events("chat-1").unwrap(), before);
        assert!(wb
            .store_ref()
            .project_authority_key("project-1")
            .unwrap()
            .is_none());
        let mut changed = input();
        changed.model = "next-model".into();
        let next = wb.compile_whipple_policy(changed).unwrap();
        assert_eq!(next.epoch, 6);
        assert_ne!(
            next.policy_root.expected_signer(),
            reused.policy_root.expected_signer()
        );
        assert_eq!(
            wb.store_ref()
                .records("chat-1", POLICY_RECORD_KIND)
                .unwrap()[0],
            serde_json::to_string(&previous).unwrap()
        );
    }

    #[test]
    fn equivalent_legacy_json_reuses_the_exact_original_epoch_and_envelope() {
        let mut wb = project_workbench();
        let mut previous = legacy_epoch(&mut wb, 5);
        previous.unsigned_policy = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(&previous.unsigned_policy).unwrap(),
        )
        .unwrap();
        wb.store_mut()
            .append_record(
                "chat-1",
                POLICY_RECORD_KIND,
                &serde_json::to_string(&previous).unwrap(),
            )
            .unwrap();
        let before = wb.store_ref().events("chat-1").unwrap();
        let reused = wb.compile_whipple_policy(input()).unwrap();
        assert_eq!(reused.epoch, previous.epoch);
        assert_eq!(reused.signed_envelope, previous.signed_envelope);
        assert_eq!(reused.policy_root.expected_signer(), wb.authority());
        assert_eq!(wb.store_ref().events("chat-1").unwrap(), before);
        assert!(wb
            .store_ref()
            .project_authority_key("project-1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn retained_project_policy_replays_without_custody_but_new_epoch_refuses() {
        let root = tempfile::tempdir().unwrap();
        let mut wb = persistent_project_workbench(root.path());
        let first = wb.compile_whipple_policy(input()).unwrap();
        let key_path = root
            .path()
            .join("content-keys/projects")
            .join(format!("{}.key", crate::org::sha256_hex("project-1")));
        std::fs::remove_file(&key_path).unwrap();
        let before = wb.store_ref().events("chat-1").unwrap();
        let same = wb.compile_whipple_policy(input()).unwrap();
        assert_eq!(first, same);
        assert_eq!(wb.store_ref().events("chat-1").unwrap(), before);
        let mut changed = input();
        changed.model = "next-model".into();
        assert!(wb.compile_whipple_policy(changed).is_err());
        assert!(!key_path.exists());
        assert_eq!(wb.store_ref().events("chat-1").unwrap(), before);
    }

    #[test]
    fn exhausted_epoch_never_saturates_or_publishes_a_different_document() {
        let mut wb = project_workbench();
        legacy_epoch(&mut wb, u64::MAX);
        let before = wb.store_ref().events("chat-1").unwrap();
        let mut changed = input();
        changed.model = "next-model".into();
        assert!(wb
            .compile_whipple_policy(changed)
            .unwrap_err()
            .contains("overflowed"));
        assert_eq!(wb.store_ref().events("chat-1").unwrap(), before);
        assert!(wb
            .store_ref()
            .project_authority_key("project-1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn changed_chat_basis_refuses_publication_without_adding_policy_facts() {
        let mut wb = project_workbench();
        wb.initialize_project_authority("project-1").unwrap();
        let (_, basis) = wb.chat_policy_basis("chat-1", Some("project-1")).unwrap();
        wb.store_mut()
            .append_record("chat-1", "intervening", "{}")
            .unwrap();
        let before = wb.store_ref().events("chat-1").unwrap();
        let input = input();
        let unsigned = compile_policy(&input).unwrap().to_json().unwrap();
        assert!(wb
            .publish_chat_policy(input, unsigned, false, 1, &basis)
            .is_err());
        assert_eq!(wb.store_ref().events("chat-1").unwrap(), before);
    }

    #[test]
    fn tampered_legacy_signature_cannot_be_reused_or_superseded_by_a_new_epoch() {
        let mut wb = project_workbench();
        let mut old = legacy_epoch(&mut wb, 5);
        old.signed_envelope = old.signed_envelope.replace("openai", "altered");
        wb.store_mut()
            .append_record(
                "chat-1",
                POLICY_RECORD_KIND,
                &serde_json::to_string(&old).unwrap(),
            )
            .unwrap();
        let before = wb.store_ref().events("chat-1").unwrap();
        assert!(wb.compile_whipple_policy(input()).is_err());
        let mut changed = input();
        changed.model = "next-model".into();
        assert!(wb.compile_whipple_policy(changed).is_err());
        assert_eq!(wb.store_ref().events("chat-1").unwrap(), before);
    }

    #[test]
    fn unchanged_facts_reuse_epoch_and_changed_facts_publish_the_next_epoch() {
        let mut wb = project_workbench();
        let first = wb.compile_whipple_policy(input()).expect("first epoch");
        let same = wb.compile_whipple_policy(input()).expect("same epoch");
        assert_eq!(same.epoch, first.epoch);
        assert_eq!(same.signed_envelope, first.signed_envelope);

        let mut changed = input();
        changed.model = "gpt-5.1".to_owned();
        let next = wb.compile_whipple_policy(changed).expect("next epoch");
        assert_eq!(next.epoch, first.epoch + 1);
        assert_ne!(next.signed_envelope, first.signed_envelope);
        assert!(!next.signed_envelope.contains("sk-secret"));
        let before = wb.store.records("chat-1", POLICY_RECORD_KIND).unwrap();
        assert_eq!(
            recorded_policy_envelope(&wb.store, "chat-1", first.epoch).unwrap(),
            first.signed_envelope
        );
        assert_eq!(
            wb.store.records("chat-1", POLICY_RECORD_KIND).unwrap(),
            before
        );
        assert!(recorded_policy_envelope(&wb.store, "chat-1", 0).is_err());
        assert!(recorded_policy_envelope(&wb.store, "chat-1", next.epoch + 1).is_err());
        assert!(recorded_policy_envelope(&wb.store, "other-chat", first.epoch).is_err());
        assert_eq!(
            wb.latest_whipple_policy("chat-1")
                .expect("latest")
                .map(|(epoch, _)| epoch),
            Some(next.epoch)
        );
    }
    #[test]
    fn recorded_policy_refuses_duplicate_missing_or_ineligible_original_rows() {
        for case in [
            "duplicate",
            "missing",
            "tombstone",
            "wrong-id",
            "empty-signature",
            "malformed",
        ] {
            let mut wb = project_workbench();
            let original = wb.compile_whipple_policy(input()).unwrap();
            let rows = wb.store.records("chat-1", POLICY_RECORD_KIND).unwrap();
            let mut record: PolicyEpochRecord = serde_json::from_str(&rows[0]).unwrap();
            let mut observed = Store::open_in_memory().unwrap();
            if case == "duplicate" {
                observed
                    .append_record("chat-1", POLICY_RECORD_KIND, &rows[0])
                    .unwrap();
            }
            match case {
                "missing" => {}
                "malformed" => {
                    observed
                        .append_record("chat-1", POLICY_RECORD_KIND, "malformed")
                        .unwrap();
                }
                _ => {
                    match case {
                        "tombstone" => record.op = RecordOp::Tombstone,
                        "wrong-id" => record.id = "replacement".into(),
                        "empty-signature" => record.signed_envelope.clear(),
                        "duplicate" => {}
                        _ => unreachable!(),
                    }
                    observed
                        .append_record(
                            "chat-1",
                            POLICY_RECORD_KIND,
                            &serde_json::to_string(&record).unwrap(),
                        )
                        .unwrap();
                }
            }
            let before = observed.records("chat-1", POLICY_RECORD_KIND);
            assert!(
                recorded_policy_envelope(&observed, "chat-1", original.epoch).is_err(),
                "{case}"
            );
            assert_eq!(
                observed.records("chat-1", POLICY_RECORD_KIND).unwrap(),
                before.unwrap()
            );
        }
    }

    #[test]
    fn tombstoning_the_active_policy_never_reuses_a_published_epoch() {
        let mut wb = project_workbench();
        let first = wb.compile_whipple_policy(input()).unwrap();
        let mut removed = latest_epoch(&wb, "chat-1").unwrap().unwrap();
        removed.op = RecordOp::Tombstone;
        wb.store_mut()
            .append_record(
                "chat-1",
                POLICY_RECORD_KIND,
                &serde_json::to_string(&removed).unwrap(),
            )
            .unwrap();
        assert!(wb.latest_whipple_policy("chat-1").unwrap().is_none());

        let next = wb.compile_whipple_policy(input()).unwrap();
        assert_eq!(next.epoch, first.epoch + 1);
        assert_eq!(wb.compile_whipple_policy(input()).unwrap(), next);
        assert_eq!(
            wb.store_ref()
                .records("chat-1", POLICY_RECORD_KIND)
                .unwrap()
                .len(),
            3,
        );
    }

    #[test]
    fn a_valid_project_signature_without_its_publication_receipt_is_refused() {
        let mut wb = project_workbench();
        wb.initialize_project_authority("project-1").unwrap();
        let (issuer, _) = wb.project_authority_identity("project-1").unwrap();
        let key = wb.project_signing_key("project-1").unwrap();
        let unsigned_policy = compile_policy(&input()).unwrap().to_json().unwrap();
        let record = PolicyEpochRecord {
            id: POLICY_RECORD_ID.into(),
            op: RecordOp::Upsert,
            epoch: 1,
            signed_envelope: sign_hosted_policy_envelope(&unsigned_policy, &issuer, &key, 1)
                .unwrap(),
            unsigned_policy,
            issuer: Some(issuer.as_str().into()),
        };
        wb.store_mut()
            .append_record(
                "chat-1",
                POLICY_RECORD_KIND,
                &serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
        let before = wb.store_ref().events("chat-1").unwrap();
        assert!(wb
            .compile_whipple_policy(input())
            .unwrap_err()
            .contains("publication receipt"));
        let mut changed = input();
        changed.model = "next-model".into();
        assert!(wb.compile_whipple_policy(changed).is_err());
        assert_eq!(wb.store_ref().events("chat-1").unwrap(), before);
    }

    #[test]
    fn harness_cache_changes_only_after_successful_new_epoch_publication() {
        fn cached() -> crate::workbench_state::SharedHarness {
            std::sync::Arc::new(std::sync::Mutex::new(Some(Box::new(
                gaugedesk_harness::testing::ScriptedHarness::new(Vec::new()),
            )
                as Box<dyn gaugedesk_harness::Harness>)))
        }
        let root = tempfile::tempdir().unwrap();
        let mut wb = persistent_project_workbench(root.path());
        wb.compile_whipple_policy(input()).unwrap();
        let original = cached();
        wb.sessions.insert("chat-1".into(), original.clone());
        wb.compile_whipple_policy(input()).unwrap();
        assert!(std::sync::Arc::ptr_eq(&wb.sessions["chat-1"], &original));

        let mut changed = input();
        changed.model = "next-model".into();
        wb.compile_whipple_policy(changed.clone()).unwrap();
        assert!(!wb.sessions.contains_key("chat-1"));
        let retained = cached();
        wb.sessions.insert("chat-1".into(), retained.clone());
        let key_path = root
            .path()
            .join("content-keys/projects")
            .join(format!("{}.key", crate::org::sha256_hex("project-1"),));
        std::fs::remove_file(key_path).unwrap();
        changed.model = "another-model".into();
        assert!(wb.compile_whipple_policy(changed).is_err());
        assert!(std::sync::Arc::ptr_eq(&wb.sessions["chat-1"], &retained));
    }

    #[test]
    fn product_factory_binding_selects_the_original_root_and_preserves_transport() {
        let mut wb = project_workbench();
        let policy = wb.compile_whipple_policy(input()).unwrap();
        let original = wb.whip_harness_factory().unwrap();
        assert!(original
            .verify_policy(policy.epoch, &policy.signed_envelope)
            .is_err());
        for factory in [
            original.clone(),
            original.with_do_host(
                gaugedesk_whip_runtime::DoHostConfig::new(
                    "https://host.example.invalid",
                    "fixture-control-token",
                    "fixture-tenant",
                )
                .unwrap(),
            ),
        ] {
            use gaugedesk_harness::HarnessFactory;
            let kind = factory.kind();
            let selected = crate::harness_select::TurnHarnessFactory::from(factory)
                .bind_policy_root(policy.policy_root.clone());
            assert_eq!(selected.kind(), kind);
            let crate::harness_select::TurnHarnessFactory::Whip(bound) = selected else {
                panic!("the real adapter must remain configurable");
            };
            bound
                .verify_policy(policy.epoch, &policy.signed_envelope)
                .unwrap();
        }
    }
}
