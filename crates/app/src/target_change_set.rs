//! Immutable multi-target process and candidate declarations (ADR 0150 §3/§4).
//!
//! Mutable settlement state deliberately does not live here. A declaration is
//! admitted once after every touched partition has an exact candidate snapshot;
//! MTARGET-5's coordinator references these records and owns later effects.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::engine::{TaskResult, TurnForkSnapshot};
use crate::library::{TargetCapabilities, TargetParticipationMode};
use crate::target_adapter::{TargetActKind, TargetActStatus};
use crate::Workbench;

pub(crate) const TURN_PROCESS_DECLARATION_KIND: &str = "turn_process_declaration";
pub(crate) const TARGET_CHANGE_SET_DECLARATION_KIND: &str = "target_change_set_declaration";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProcessTargetBinding {
    pub(crate) target_id: String,
    pub(crate) resource_handle: String,
    pub(crate) root: String,
    pub(crate) native_basis: String,
    pub(crate) adapter_family: String,
    pub(crate) path_scope: Vec<String>,
    pub(crate) capabilities: TargetCapabilities,
    pub(crate) participation: TargetParticipationMode,
    pub(crate) authorities: Vec<String>,
    pub(crate) readable: bool,
    pub(crate) writable: bool,
    pub(crate) output: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TurnProcessDeclaration {
    pub(crate) schema: String,
    pub(crate) id: String,
    pub(crate) run_ref: String,
    pub(crate) chat_id: String,
    pub(crate) project_id: String,
    pub(crate) placement_id: String,
    pub(crate) package_version_ref: String,
    pub(crate) target_set_revision: u64,
    pub(crate) executable: String,
    pub(crate) read_targets: Vec<String>,
    pub(crate) write_targets: Vec<String>,
    pub(crate) output_targets: Vec<String>,
    pub(crate) bindings: Vec<ProcessTargetBinding>,
    pub(crate) governance_epoch: u64,
    pub(crate) governance_envelope_digest: String,
}

impl TurnProcessDeclaration {
    pub(crate) fn bind_governance(&mut self, epoch: u64, envelope: &str) {
        self.governance_epoch = epoch;
        self.governance_envelope_digest = digest(envelope.as_bytes());
    }

    pub(crate) fn bind_run(&mut self, user_entry_id: i64) -> Result<(), String> {
        if !self.run_ref.is_empty() || !self.id.is_empty() {
            return Err("turn process declaration is already bound".to_owned());
        }
        self.run_ref = format!("{}:{user_entry_id}", self.chat_id);
        self.id = content_id("turn-process", self)?;
        Ok(())
    }

    pub(crate) fn harness_bindings(&self) -> Vec<gaugedesk_harness::WorkspaceTargetBinding> {
        self.bindings
            .iter()
            .map(|binding| gaugedesk_harness::WorkspaceTargetBinding {
                target_id: binding.target_id.clone(),
                resource_handle: binding.resource_handle.clone(),
                root: binding.root.clone(),
                readable: binding.readable,
                writable: binding.writable,
                output: binding.output,
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TargetCandidateSnapshot {
    pub(crate) target_id: String,
    pub(crate) native_basis: String,
    /// Stable Home-local collaboration workspace holding `candidate_cut`.
    #[serde(default)]
    pub(crate) candidate_workspace_id: String,
    /// Stable WhippleScript line ref from which the exact historical cut can
    /// be materialized even after the originating chat handle is closed.
    #[serde(default)]
    pub(crate) candidate_line_ref: String,
    pub(crate) candidate_identity: String,
    pub(crate) candidate_cut: String,
    pub(crate) candidate_digest: String,
    pub(crate) path_scope: Vec<String>,
    pub(crate) adapter_family: String,
    pub(crate) changed_paths: Vec<String>,
    pub(crate) checks: Vec<String>,
    pub(crate) policy_decision_handles: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RequestedTargetAct {
    pub(crate) target_id: String,
    pub(crate) act: TargetActKind,
    pub(crate) expected_basis: String,
    pub(crate) expected_result_digest: String,
    pub(crate) operation_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TargetChangeSetDeclaration {
    pub(crate) schema: String,
    pub(crate) id: String,
    pub(crate) chat_id: String,
    pub(crate) run_ref: String,
    pub(crate) project_id: String,
    pub(crate) placement_id: String,
    pub(crate) package_version_ref: String,
    pub(crate) target_set_revision: u64,
    pub(crate) turn_process_declaration_id: String,
    pub(crate) candidate_snapshots: Vec<TargetCandidateSnapshot>,
    pub(crate) requested_acts: Vec<RequestedTargetAct>,
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn content_id(prefix: &str, value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{prefix}:{}", hex::encode(Sha256::digest(bytes))))
        .map_err(|error| error.to_string())
}

impl Workbench {
    pub(crate) fn prepare_turn_process_declaration(
        &self,
        chat_id: &str,
        executable: &str,
        package_version_ref: Option<&str>,
        governance_epoch: u64,
        governance_envelope: Option<&str>,
    ) -> Result<Option<TurnProcessDeclaration>, String> {
        let Some(chat) = self.library.chats.get(chat_id) else {
            return Ok(None);
        };
        let instance = self
            .library
            .instances
            .get(&chat.instance_id)
            .ok_or_else(|| "chat placement is unavailable".to_owned())?;
        if instance.kind != crate::library::InstanceKind::Using {
            return Ok(None);
        }
        let project_id = instance
            .project_id
            .clone()
            .ok_or_else(|| "work chat has no project".to_owned())?;
        let target_set = self
            .library
            .current_target_set(chat_id)
            .ok_or_else(|| "work chat has no target set".to_owned())?;
        let compatibility = self.library.chat_targets.get(chat_id);
        let mut bindings = target_set
            .members
            .iter()
            .map(|member| {
                let target = self
                    .library
                    .work_targets
                    .get(&member.target_id)
                    .ok_or_else(|| format!("target {} is unavailable", member.target_id))?;
                let encoded = crate::library::target_id_path_v1(&member.target_id)?;
                let native_basis = compatibility
                    .filter(|binding| binding.target_id == member.target_id)
                    .map(|binding| binding.basis.clone())
                    .or_else(|| target.current_basis.clone())
                    .ok_or_else(|| format!("target {} has no exact basis", member.target_id))?;
                let mut authorities = target.parties.clone();
                authorities.push(target.authority.clone());
                authorities.sort();
                authorities.dedup();
                let writable = member.participation == TargetParticipationMode::Writable
                    && member.capability_ceiling.propose;
                Ok(ProcessTargetBinding {
                    target_id: member.target_id.clone(),
                    resource_handle: format!("target:{encoded}"),
                    root: format!("targets/{encoded}"),
                    native_basis,
                    adapter_family: member.adapter_family.clone(),
                    path_scope: member.path_scope.clone(),
                    capabilities: member.capability_ceiling.clone(),
                    participation: member.participation,
                    authorities,
                    readable: member.capability_ceiling.read,
                    writable,
                    output: writable,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        bindings.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        if bindings.is_empty() || bindings.iter().any(|binding| !binding.readable) {
            return Err("turn target process declaration must name readable targets".to_owned());
        }
        let select = |predicate: fn(&ProcessTargetBinding) -> bool| {
            bindings
                .iter()
                .filter(|binding| predicate(binding))
                .map(|binding| binding.target_id.clone())
                .collect::<Vec<_>>()
        };
        Ok(Some(TurnProcessDeclaration {
            schema: "gaugedesk.turn-process.v1".to_owned(),
            id: String::new(),
            run_ref: String::new(),
            chat_id: chat_id.to_owned(),
            project_id,
            placement_id: chat.instance_id.clone(),
            package_version_ref: package_version_ref.unwrap_or_default().to_owned(),
            target_set_revision: target_set.revision,
            executable: executable.to_owned(),
            read_targets: select(|binding| binding.readable),
            write_targets: select(|binding| binding.writable),
            output_targets: select(|binding| binding.output),
            bindings,
            governance_epoch,
            governance_envelope_digest: digest(governance_envelope.unwrap_or_default().as_bytes()),
        }))
    }

    pub(crate) fn record_target_change_set(
        &mut self,
        chat_id: &str,
        result: &TaskResult,
    ) -> Result<Option<TargetChangeSetDeclaration>, String> {
        let Some(candidate_cut) = result.commit.as_deref() else {
            return Ok(None);
        };
        let boundary = self
            .store_ref()
            .records(chat_id, crate::engine::TURN_BOUNDARY_KIND)
            .map_err(|error| format!("{error:?}"))?
            .into_iter()
            .last()
            .ok_or_else(|| "turn has no durable boundary".to_owned())?;
        let boundary: crate::engine::TurnBoundaryRecord =
            serde_json::from_str(&boundary).map_err(|error| error.to_string())?;
        let TurnForkSnapshot {
            process_declaration: Some(process),
            ..
        } = boundary
            .fork_snapshot
            .ok_or_else(|| "turn has no exact target snapshot".to_owned())?
        else {
            return Ok(None);
        };
        if process.id.is_empty() || process.run_ref.is_empty() {
            return Err("turn process declaration was not durably bound".to_owned());
        }

        let changed = crate::advancement::TurnFacts::changed_paths_of(&result.diff);
        let mut by_target = BTreeMap::<String, BTreeSet<String>>::new();
        for path in changed {
            let matches = process
                .bindings
                .iter()
                .filter(|binding| {
                    path == binding.root || path.starts_with(&format!("{}/", binding.root))
                })
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(format!(
                    "changed path `{path}` does not resolve to exactly one declared target"
                ));
            }
            let binding = matches[0];
            if !binding.writable {
                return Err(format!(
                    "changed path `{path}` belongs to non-writable target {}",
                    binding.target_id
                ));
            }
            let relative = path
                .strip_prefix(&format!("{}/", binding.root))
                .unwrap_or("")
                .to_owned();
            by_target
                .entry(binding.target_id.clone())
                .or_default()
                .insert(relative);
        }
        if by_target.is_empty() {
            return Ok(None);
        }

        let engagement = self
            .engagements
            .get(chat_id)
            .ok_or_else(|| "chat candidate is unavailable".to_owned())?;
        let candidate_workspace_id = self
            .engagement_index
            .get(chat_id)
            .filter(|workspace_id| self.collaboration_workspaces.contains_key(*workspace_id))
            .cloned()
            .ok_or_else(|| "chat collaboration workspace is unavailable".to_owned())?;
        let candidate_line_ref = engagement.branch().to_owned();
        let checks = result
            .guarantee_outcomes
            .iter()
            .map(|check| format!("{}={}", check.name, check.outcome))
            .collect::<Vec<_>>();
        let policy_handle = format!(
            "whipple-policy:{}:{}:{}",
            chat_id, process.governance_epoch, process.governance_envelope_digest
        );
        let mut candidate_snapshots = Vec::new();
        let mut requested_acts = Vec::new();
        for (target_id, paths) in by_target {
            let binding = process
                .bindings
                .iter()
                .find(|binding| binding.target_id == target_id)
                .expect("grouped from process bindings");
            let mut snapshot_bytes = Vec::new();
            for path in &paths {
                snapshot_bytes.extend_from_slice(path.as_bytes());
                snapshot_bytes.push(0);
                let absolute = Path::new(engagement.path()).join(&binding.root).join(path);
                if absolute.is_file() {
                    let body = std::fs::read(&absolute).map_err(|error| error.to_string())?;
                    snapshot_bytes.extend_from_slice(b"file\0");
                    snapshot_bytes.extend_from_slice(&body);
                } else if !absolute.exists() {
                    snapshot_bytes.extend_from_slice(b"deleted\0");
                } else {
                    return Err(format!(
                        "changed candidate `{}` is not a file",
                        absolute.display()
                    ));
                }
                snapshot_bytes.push(0xff);
            }
            let candidate_digest = digest(&snapshot_bytes);
            let operation_id = digest(
                format!("propose\0{chat_id}\0{candidate_cut}\0{target_id}\0{candidate_digest}")
                    .as_bytes(),
            );
            candidate_snapshots.push(TargetCandidateSnapshot {
                target_id: target_id.clone(),
                native_basis: binding.native_basis.clone(),
                candidate_workspace_id: candidate_workspace_id.clone(),
                candidate_line_ref: candidate_line_ref.clone(),
                candidate_identity: format!(
                    "collaboration-cut:{candidate_cut}#target:{}",
                    binding.target_id
                ),
                candidate_cut: candidate_cut.to_owned(),
                candidate_digest: candidate_digest.clone(),
                path_scope: binding.path_scope.clone(),
                adapter_family: binding.adapter_family.clone(),
                changed_paths: paths.into_iter().collect(),
                checks: checks.clone(),
                policy_decision_handles: vec![policy_handle.clone()],
            });
            requested_acts.push(RequestedTargetAct {
                target_id,
                act: TargetActKind::Propose,
                expected_basis: binding.native_basis.clone(),
                expected_result_digest: candidate_digest,
                operation_id,
            });
        }
        candidate_snapshots.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        requested_acts.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        let mut declaration = TargetChangeSetDeclaration {
            schema: "gaugedesk.target-change-set.v1".to_owned(),
            id: String::new(),
            chat_id: chat_id.to_owned(),
            run_ref: process.run_ref.clone(),
            project_id: process.project_id.clone(),
            placement_id: process.placement_id.clone(),
            package_version_ref: process.package_version_ref.clone(),
            target_set_revision: process.target_set_revision,
            turn_process_declaration_id: process.id,
            candidate_snapshots,
            requested_acts,
        };
        declaration.id = content_id("target-change-set", &declaration)?;
        let payload = serde_json::to_string(&declaration).map_err(|error| error.to_string())?;
        self.store_mut()
            .append_record(chat_id, TARGET_CHANGE_SET_DECLARATION_KIND, &payload)
            .map_err(|error| format!("{error:?}"))?;
        for candidate in &declaration.candidate_snapshots {
            self.record_target_act(
                Some(chat_id),
                &candidate.target_id,
                TargetActKind::Propose,
                Some(candidate.candidate_identity.clone()),
                candidate.checks.clone(),
                None,
                TargetActStatus::Completed,
                None,
            )?;
        }
        Ok(Some(declaration))
    }
}

pub(crate) fn admit_turn_process_declaration(
    store: &mut gaugedesk_store::Store,
    scope: &str,
    user_entry_id: i64,
    snapshot: &mut Option<TurnForkSnapshot>,
) -> Result<(), gaugedesk_store::AdmitError> {
    let Some(process) = snapshot
        .as_mut()
        .and_then(|snapshot| snapshot.process_declaration.as_mut())
    else {
        return Ok(());
    };
    process.bind_run(user_entry_id).map_err(|error| {
        gaugedesk_store::AdmitError::Codec(format!("turn process declaration: {error}"))
    })?;
    let payload = serde_json::to_string(process).map_err(gaugedesk_store::AdmitError::Json)?;
    store.append_record(scope, TURN_PROCESS_DECLARATION_KIND, &payload)?;
    Ok(())
}
