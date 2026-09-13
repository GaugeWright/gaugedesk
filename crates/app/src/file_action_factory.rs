//! Native editor command construction from current committed Home authority.
//! This factory admits work; runtime delivery, execution and result retrieval
//! remain separate. No production route is switched by this module.

use crate::{
    action_inputs::NativeActionInputCustody,
    action_policy::{prepare_action_policy, ActionPolicyIdentity},
    file_action_policy::{compile_file_save_policy, FileSavePolicyInput},
    identity::{ActorAuthentication, AuthenticatedActionContext},
    library::{
        InstanceKind, Library, TargetParticipationMode, TargetVcsPosture, WorkTargetKind,
        WorkTargetOwner, WorkTargetStatus, LIBRARY_SCOPE,
    },
    org::{Org, ORG_SCOPE},
    Workbench,
};
use gaugedesk_core::{
    abac::AuthorityAttributes,
    boundary::Authority,
    resource::{ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord},
    signature::SigningKey,
};
use gaugedesk_store::{command_dispatch::CommandDispatch, AdmitError, Store};
use gaugedesk_whip_runtime::{
    host_actions::{action::*, CompiledHostAction, ProductActionAdmission},
    ifc, GovernanceRootVerifier, HostGovernancePolicy, ResourceRef,
};
use std::collections::{BTreeMap, BTreeSet};

const SOURCE: &str = r#"use std.files
workflow GaugeDeskEditorFileSave
input content InputReference
output result Saved
failure error SaveFailed
class InputReference { handle string version_ref string label_ref string }
class Saved { content_hash string }
class SaveFailed { reason string }
file store admitted_input {
  root "/action/input"
  allow read ["content"]
}
file store admitted_target {
  root "/action/output"
  allow write ["target"]
}
rule save
  when InputReference as reference
=> {
  read reference from admitted_input at "content" as loaded
  after loaded succeeds as draft {
    write reference to admitted_target at "target" {
      body draft.content_reference
      mode upsert
    } as written
    after written succeeds as saved { complete result { content_hash saved.content_hash } }
    after written fails as failed { fail error { reason failed.reason } }
  }
  after loaded fails as unavailable { fail error { reason unavailable.reason } }
}
"#;

/// The executable is product-owned and fixed, never supplied by a caller.
pub fn editor_file_save_workflow() -> Result<CompiledHostAction, String> {
    CompiledHostAction::compile("file.save", SOURCE, None)
        .map_err(|error| format!("editor file workflow is invalid: {error:?}"))
}

/// User intent only. Actor, labels, storage paths, policy and capabilities are
/// derived by the factory. Agent transformations need their retained read-taint
/// input path; they cannot discard that provenance through this editor factory.
pub struct EditorFileSave<'a> {
    pub chat_id: &'a str,
    pub request_id: &'a str,
    pub path: &'a str,
    pub base_cut: &'a str,
    pub content: &'a str,
}

pub struct AdmittedEditorFileSave {
    pub command: HostActionCommand,
    pub replayed: bool,
}

/// Addresses one recorded attempt; it conveys no authority or outcome.
#[derive(Clone, Copy, Debug)]
pub struct EditorFileSaveAttempt<'a> {
    pub effect_id: &'a str,
    pub run_id: &'a str,
}

/// New reconciliation intent, with a stable identity distinct from the save.
pub struct EditorFileSaveReconciliation<'a> {
    pub request_id: &'a str,
    pub attempt: EditorFileSaveAttempt<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileAuthority {
    target_id: String,
    project_id: String,
    workspace_path: String,
    policy: HostGovernancePolicy,
    valid_until_ms: Option<u64>,
    resolution_scope: whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope,
    read_clearances: BTreeSet<String>,
}

impl FileAuthority {
    fn bind_deadline(
        &self,
        basis: gaugedesk_store::command_dispatch::DispatchReadBasis,
    ) -> Result<gaugedesk_store::command_dispatch::DispatchReadBasis, AdmitError> {
        match self.valid_until_ms {
            Some(milliseconds) => std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::from_millis(milliseconds))
                .map(|deadline| basis.with_deadline(deadline))
                .ok_or_else(|| invalid("account authority deadline is out of range")),
            None => Ok(basis),
        }
    }
}

fn invalid(reason: &'static str) -> AdmitError {
    AdmitError::Rejected(gaugedesk_core::Rejection { reason })
}

fn normalized(path: &str) -> bool {
    !path.contains('\\')
        && !path.contains('\0')
        && !path.split('/').any(|part| matches!(part, "" | "." | ".."))
}

/// Every authority used here is folded from the event scopes fenced below.
/// In-memory library updates and request-supplied tenant headers grant nothing.
fn current_authority(
    store: &Store,
    home: &gaugedesk_core::ids::HomeId,
    context: &AuthenticatedActionContext,
    request: &EditorFileSave<'_>,
) -> Result<FileAuthority, AdmitError> {
    if request.base_cut.trim().is_empty() {
        return Err(invalid("file action has no admitted base"));
    }
    current_target_authority(
        store,
        home,
        context,
        &NativeTargetIntent {
            chat_id: request.chat_id,
            request_id: request.request_id,
            path: request.path,
        },
        NativeActionKind::FileSave,
    )
}

struct NativeTargetIntent<'a> {
    chat_id: &'a str,
    request_id: &'a str,
    path: &'a str,
}

#[derive(Clone, Copy)]
enum NativeActionKind {
    FileSave,
    RecordCorrections,
    InspectHistory,
}

fn current_target_authority(
    store: &Store,
    home: &gaugedesk_core::ids::HomeId,
    context: &AuthenticatedActionContext,
    request: &NativeTargetIntent<'_>,
    kind: NativeActionKind,
) -> Result<FileAuthority, AdmitError> {
    current_target_authority_with_source(store, home, context, request, kind, None)
}

fn current_target_authority_with_source(
    store: &Store,
    home: &gaugedesk_core::ids::HomeId,
    context: &AuthenticatedActionContext,
    request: &NativeTargetIntent<'_>,
    kind: NativeActionKind,
    source: Option<&gaugedesk_whip_runtime::ResourcePolicy>,
) -> Result<FileAuthority, AdmitError> {
    if !normalized(request.path)
        || request.request_id.trim().is_empty()
        || gaugedesk_boundary::is_control_surface_path(request.path)
    {
        return Err(invalid(
            "file action has invalid intent or targets a control surface",
        ));
    }
    let mut valid_until_ms = None;
    match context.authentication() {
        ActorAuthentication::AccountSession { session_ref } => {
            // An unavailable source record cannot disappear from an authority
            // fold and expose an older still-active session or grant.
            store.retained_events(crate::account_auth::ACCOUNT_AUTH_SCOPE)?;
            let auth = crate::account_auth::AccountAuth::rebuild(store)?;
            let session = auth
                .sessions
                .get(session_ref)
                .ok_or_else(|| invalid("account action session is not durably active"))?;
            let expires = session
                .issued_at_ms
                .saturating_add(session.lifetime_secs.saturating_mul(1000));
            valid_until_ms = Some(expires);
            if session.account_id != context.actor().as_str()
                || expires <= crate::account::session_now_ms()
            {
                return Err(invalid(
                    "account action session is expired or belongs to another actor",
                ));
            }
        }
        ActorAuthentication::MachineController { grant_ref } => {
            store.retained_events(crate::mobile_machine_session::SCOPE)?;
            let grant = crate::mobile_machine_session::current_action_grant(store, grant_ref)?
                .ok_or_else(|| invalid("controller action grant is not active"))?;
            if &grant.machine != home || grant.device.as_str() != context.actor().as_str() {
                return Err(invalid(
                    "controller action grant has the wrong Home or device",
                ));
            }
        }
        ActorAuthentication::IdentityProvider => {}
        ActorAuthentication::NativeEditorDispatchGrant { .. } => {
            return Err(invalid(
                "action-scoped authority requires its exact admitted command",
            ));
        }
    }
    let library = Library::rebuild(store)?;
    let org = Org::rebuild(store)?;
    let chat = library
        .chats
        .get(request.chat_id)
        .ok_or_else(|| invalid("chat is unavailable"))?;
    let instance = library
        .instances
        .get(&chat.instance_id)
        .ok_or_else(|| invalid("chat placement is unavailable"))?;
    // Authoring has an archetype authority rather than a project grant. That
    // authority needs its own factory admission; it is never invented here.
    let project_id = instance
        .project_id
        .as_deref()
        .filter(|_| instance.kind == InstanceKind::Using)
        .ok_or_else(|| invalid("editor action requires its project authority"))?;
    let project = library
        .projects
        .get(project_id)
        .ok_or_else(|| invalid("project is unavailable"))?;
    if &project.home_id != home || !org.can_access_project(context.actor().as_str(), project_id) {
        return Err(invalid("actor has no current grant on this Home project"));
    }
    let set = library
        .current_target_set(request.chat_id)
        .ok_or_else(|| invalid("chat has no committed target selection"))?;
    let (member, relative) = if let Some(rooted) = request.path.strip_prefix("targets/") {
        let (encoded, relative) = rooted
            .split_once('/')
            .ok_or_else(|| invalid("target-relative file path is missing"))?;
        let member = set
            .members
            .iter()
            .find(|member| {
                crate::library::target_id_path_v1(&member.target_id).is_ok_and(|id| id == encoded)
            })
            .ok_or_else(|| invalid("file target is not selected"))?;
        (member, relative)
    } else if let [member] = set.members.as_slice() {
        (member, request.path)
    } else {
        return Err(invalid("multi-target file action must name one target"));
    };
    let target = library
        .work_targets
        .get(&member.target_id)
        .ok_or_else(|| invalid("file target is unavailable"))?;
    if target.owner
        != (WorkTargetOwner::Project {
            project_id: project_id.into(),
        })
        || target.status != WorkTargetStatus::Available
        || target.locator_handle.trim().is_empty()
        || target.adapter_family != member.adapter_family
        || target.kind != WorkTargetKind::Managed
        || target.vcs_posture != TargetVcsPosture::Managed
        || !target.capabilities.read
        || (!matches!(kind, NativeActionKind::InspectHistory) && !target.capabilities.propose)
        || !member.capability_ceiling.read
        || (!matches!(kind, NativeActionKind::InspectHistory) && !member.capability_ceiling.propose)
        || (!matches!(kind, NativeActionKind::InspectHistory)
            && member.participation != TargetParticipationMode::Writable)
        || !crate::engagement_routes::path_is_in_scope(relative, &target.path_scope)
        || !crate::engagement_routes::path_is_in_scope(relative, &member.path_scope)
        || !library
            .placement_targets
            .get(&instance.id)
            .is_some_and(|eligible| eligible.target_ids.contains(&target.id))
    {
        return Err(invalid("file action exceeds current target authority"));
    }
    if gaugedesk_boundary::is_control_surface_path(relative)
        || gaugedesk_boundary::is_method_surface_path(relative)
        || relative.starts_with(".whipple/versions/")
        || relative.contains("/.whipple/versions/")
        || relative.starts_with(".whipple/discipline/versions/")
        || relative.contains("/.whipple/discipline/versions/")
    {
        return Err(invalid(
            "work file action cannot mutate runtime or archetype controls",
        ));
    }
    let owner = Authority::from(target.authority.as_str());
    let stakeholders: BTreeSet<_> = target
        .parties
        .iter()
        .map(|party| Authority::from(party.as_str()))
        .chain(std::iter::once(owner.clone()))
        .collect();
    let resource = |handle: &str| ResourceRecord {
        resource: Resource::input(
            ResourceId::new(format!("target:{}:{handle}", target.id)),
            ResourceKind::context(),
            owner.clone(),
        ),
        stakeholders: stakeholders.clone(),
        locator: ContentLocator::Content {
            handle: target.locator_handle.clone(),
        },
        tombstoned: false,
        attributes: target.attributes.clone(),
    };
    let attributes: AuthorityAttributes =
        org.with_directory_role(context.claims().clone(), context.actor().as_str());
    let policy_input = FileSavePolicyInput {
        actor: context.actor().clone(),
        actor_attributes: attributes,
        org_policy: org.policy(),
        purpose: project.run_purpose.clone(),
        ceiling_attested: false,
        input: resource("draft"),
        target: resource("file"),
    };
    let policy = if matches!(kind, NativeActionKind::InspectHistory) {
        crate::file_action_policy::compile_file_resource_policy(
            &policy_input,
            gaugedesk_core::abac::Action::Access,
        )
    } else {
        compile_file_save_policy(&policy_input)
    }
    .map_err(|_| invalid("current resource policy refuses this actor"))?;
    let read_clearances = crate::policy_compiler::actor_clearances(
        &policy_input.actor_attributes,
        policy_input.purpose.as_deref(),
        &[policy_input.input.clone(), policy_input.target.clone()],
        std::iter::empty(),
    );
    let encoded = crate::library::target_id_path_v1(&target.id)
        .map_err(|_| invalid("file target identity is invalid"))?;
    let resolution_scope = resolution_scope::scope(
        home.as_str(),
        &target.authority,
        project_id,
        &target.id,
        &target.path_scope,
        &member.path_scope,
        &policy,
    )
    .map_err(|_| invalid("current resolution memory scope is unavailable"))?;
    // Scope is the same target compartment a save observes. Recording then
    // receives its own explicit policy, with no file capability or binding.
    let policy = match kind {
        NativeActionKind::FileSave | NativeActionKind::InspectHistory => policy,
        NativeActionKind::RecordCorrections => match source {
            Some(source) => {
                crate::resolution_recording_policy::compile_saved_source_recording_policy(
                    &policy_input,
                    std::slice::from_ref(source),
                )
            }
            None => crate::resolution_recording_policy::compile_resolution_recording_policy(
                &policy_input,
            ),
        }
        .map_err(|_| invalid("current correction resource policy refuses this actor"))?,
    };
    Ok(FileAuthority {
        target_id: target.id.clone(),
        project_id: project_id.into(),
        workspace_path: format!("targets/{encoded}/{relative}"),
        resolution_scope,
        read_clearances,
        policy,
        valid_until_ms,
    })
}

impl Workbench {
    /// Native project-editor admission. The supplied context must come from the
    /// Home authentication boundary; the input store is trusted Home config.
    /// Production routes remain on their existing path until execution/recovery
    /// and migration budgets are qualified; this method is the real factory they
    /// will call, with no model or synthetic chat construction.
    pub fn admit_editor_file_save(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        request: &EditorFileSave<'_>,
    ) -> Result<AdmittedEditorFileSave, String> {
        if inputs.authority_scope() != self.home_id().as_str() {
            return Err("file input custody belongs to another Home".into());
        }
        let home = self.home_id().clone();
        let read = |store: &Store| current_authority(store, &home, context, request);
        let (authority, _) = self
            .store_ref()
            .read_for_dispatch(
                &[
                    LIBRARY_SCOPE,
                    ORG_SCOPE,
                    crate::account_auth::ACCOUNT_AUTH_SCOPE,
                    crate::mobile_machine_session::SCOPE,
                ],
                read,
            )
            .map_err(|error| format!("file action authorization refused: {error:?}"))?;
        let target = self
            .engagements
            .get(request.chat_id)
            .ok_or("chat workspace is unavailable")?
            .native_file_action_target(&authority.workspace_path, request.base_cut)
            .map_err(|error| format!("{error:?}"))?;
        let action = editor_file_save_workflow()?;
        let identity = ActionPolicyIdentity {
            issuer: self.authority().as_str().into(),
            scope: serde_json::to_string(&(
                "gaugedesk.editor-file.v1",
                &authority.project_id,
                request.chat_id,
            ))
            .map_err(|error| format!("{error:?}"))?,
            request_id: request.request_id.into(),
        };
        let signing_key =
            SigningKey::from_seed(&self.governance_seed()).map_err(|error| error.reason)?;
        let root = GovernanceRootVerifier::new(self.authority().clone(), signing_key.public_key());
        let policy =
            prepare_action_policy(self.store_mut(), &identity, &authority.policy, &signing_key)?;
        let envelope =
            ifc::VerifiedEnvelope::verify_signed_text_with(policy.signed_envelope(), &root)?;
        let diagnostics = ifc::check_with_envelope(action.program(), &envelope);
        if !diagnostics.is_empty() {
            return Err("editor file workflow violates the admitted policy".into());
        }
        // These opaque labels point to bindings in the exact signed document;
        // GaugeDesk does not reproduce the runtime's label algebra.
        let label = |binding| format!("policy:{}:{binding}", policy.policy_ref().envelope_hash);
        let input = inputs
            .prepare("admitted_input", &label("admitted_input"), request.content)
            .map_err(|error| format!("{error:?}"))?;
        let command = HostActionCommand {
            protocol: HOST_ACTION_PROTOCOL.into(),
            issuer: identity.issuer,
            scope: identity.scope,
            request_id: request.request_id.into(),
            operation: "file.save".into(),
            program_version_ref: action.version_ref().into(),
            input_schema_ref: action.input_schema_ref().into(),
            policy: policy.policy_ref().clone(),
            provenance: ActionProvenance {
                initiator: context.actor().as_str().into(),
                executor: context.actor().as_str().into(),
                delegation: vec![],
                origin: "editor.save".into(),
                causes: vec![],
            },
            inputs: BTreeMap::from([("content".into(), input.clone())]),
            resources: BTreeMap::from([
                (
                    "resolutions".into(),
                    resolution_scope::resource(
                        &authority.resolution_scope,
                        &policy.policy_ref().envelope_hash,
                    )?,
                ),
                (
                    "target".into(),
                    ActionResource {
                        resource: ResourceRef {
                            handle: "admitted_target".into(),
                            kind: "file_store".into(),
                            selector: Some(
                                serde_json::to_string(&(
                                    &authority.target_id,
                                    target.branch(),
                                    target.path(),
                                ))
                                .map_err(|error| format!("{error:?}"))?,
                            ),
                            writable: Some(true),
                        },
                        basis: ActionBasis::Version {
                            version_ref: target.base().into(),
                        },
                        label_ref: label("admitted_target"),
                    },
                ),
            ]),
        };
        let scope = command
            .instance_ref()
            .map_err(|error| format!("invalid editor action: {error:?}"))?;
        let dispatch = CommandDispatch {
            runtime_ref: format!("{}:native", self.home_id()),
            command_ref: command
                .fingerprint()
                .map_err(|error| format!("invalid editor action: {error:?}"))?,
        };
        let (current, basis) = self
            .store_ref()
            .read_for_dispatch(
                &[
                    LIBRARY_SCOPE,
                    ORG_SCOPE,
                    crate::account_auth::ACCOUNT_AUTH_SCOPE,
                    crate::mobile_machine_session::SCOPE,
                ],
                read,
            )
            .map_err(|error| format!("file action authorization refused: {error:?}"))?;
        if current != authority {
            return Err("file authority changed during preparation".into());
        }
        let basis = current
            .bind_deadline(basis)
            .map_err(|error| format!("file authority deadline refused: {error:?}"))?;
        let admitted = inputs
            .publish(std::slice::from_ref(&input), || {
                target.publish_base(|| {
                    self.store_mut()
                        .admit_with_dispatch_against::<ProductActionAdmission>(
                            &scope,
                            &command.request_id,
                            command.clone(),
                            &dispatch,
                            &basis,
                        )
                        .map_err(|error| {
                            whipplescript_store::StoreError::Conflict(format!(
                                "file admission refused: {error:?}"
                            ))
                        })
                })
            })
            .map_err(|error| format!("{error:?}"))?;
        Ok(AdmittedEditorFileSave {
            command,
            replayed: admitted.replayed,
        })
    }
}

#[cfg(test)]
#[path = "file_action_factory_tests.rs"]
mod tests;

#[path = "file_action_delivery.rs"]
mod delivery;

#[path = "file_action_execution.rs"]
mod execution;

#[path = "file_action_recovery.rs"]
mod recovery;

#[path = "file_action_ownership.rs"]
mod ownership;

pub use ownership::NativeEditorActionRuntime;
pub use recovery::{
    AdmittedEditorSavedResult, EditorFileSaveObservation, NativeEditorSavedResult,
    RetainedEditorFileSaveSource,
};

#[path = "file_action_storage.rs"]
mod storage;

pub use storage::{NativeActionStorage, NativeActionStorageConfig};

#[path = "file_action_dispatch_grant.rs"]
mod dispatch_grant;

pub use dispatch_grant::{NativeEditorDispatchAuthority, NativeEditorDispatchGrant};

#[path = "file_action_driver.rs"]
mod driver;

pub use driver::{NativeEditorSaveDriver, NativeEditorSaveProgress};

#[path = "file_action_supervisor.rs"]
mod supervisor;

pub use supervisor::{
    supervise_native_editor_dispatch, NativeEditorDispatchNotice, NativeEditorDispatchOutcome,
    NativeEditorSupervisorConfig,
};

#[path = "file_action_resolution_scope.rs"]
mod resolution_scope;

#[path = "resolution_recording_factory.rs"]
mod recording;

pub use recording::{
    AdmittedEditorCorrectionReconciliation, AdmittedEditorCorrectionResult,
    AdmittedEditorCorrections, CorrectionReconciliationAcknowledgment, EditorCorrectionObservation,
    EditorCorrectionReconciliation, EditorCorrectionResultRequest, EditorCorrections,
    NativeCorrectionReconciliationRuntime, NativeEditorCorrectionResult,
};
