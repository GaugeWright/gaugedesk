//! Home-owned shell for multi-target settlement coordination (MTARGET-5).
//!
//! The core reducers own lifecycle truth. This module resolves immutable
//! candidate declarations, current target bases, adapter contracts, and ordered
//! lane evidence before admitting reducer commands. Target I/O remains in the
//! adapters and can run only after [`Workbench::start_settlement_member`]
//! returns an exact permit.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use gaugedesk_core::ids::PublicKey;
use gaugedesk_core::signature::{verify_signature, Signature, SigningKey};
use gaugedesk_core::target_settlement::{
    decide, decide_target_lane, AuthenticatedTargetReceipt, CompensationReceiptLink,
    MemberPreflightEvidence, ReceiptOutcome, SettlementAct, SettlementMemberDeclaration,
    SettlementMemberPhase, TargetLaneMember, TargetLanePermit, TargetSettlementCommand,
    TargetSettlementDeclaration, TargetSettlementLaneCommand, TargetSettlementLaneState,
    TargetSettlementState,
};
use gaugedesk_workspace::MergeOutcome;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::target_adapter::{TargetActKind, TargetActStatus};
use crate::target_change_set::{
    TargetCandidateSnapshot, TargetChangeSetDeclaration, TARGET_CHANGE_SET_DECLARATION_KIND,
};
use crate::{LockUnpoisoned, Workbench};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RequestedSettlementMember {
    pub(crate) target_id: String,
    pub(crate) act: TargetActKind,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateTargetSettlementBody {
    #[serde(default)]
    pub source_change_set_ref: Option<String>,
    #[serde(default)]
    pub promotion_manifest_ref: Option<String>,
    pub members: Vec<CreateTargetSettlementMemberBody>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateTargetSettlementMemberBody {
    pub target_id: String,
    pub act: TargetActKind,
}

#[derive(Debug, Deserialize)]
pub struct CompensateTargetSettlementBody {
    pub receipt_links: Vec<CompensationReceiptLink>,
}

#[derive(Debug, Deserialize)]
pub struct AbandonTargetSettlementBody {
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct CancelTargetSettlementBody {
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct SupersedeTargetSettlementMemberBody {
    pub later_declaration_id: String,
    pub later_member_id: String,
}

pub(crate) fn settlement_scope(declaration_id: &str) -> String {
    format!("target-settlement::{declaration_id}")
}

fn lane_scope(target_id: &str) -> String {
    format!("target-settlement-lane::{target_id}")
}

const TARGET_SETTLEMENT_CHAT_REF_KIND: &str = "target_settlement_ref";

type CandidateFileSnapshot = Vec<(String, Option<Vec<u8>>)>;

#[derive(Deserialize, Serialize)]
struct TargetSettlementChatRef {
    schema: String,
    declaration_id: String,
}

fn digest(value: impl AsRef<[u8]>) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value.as_ref())))
}

fn target_receipt_payload(receipt: &AuthenticatedTargetReceipt) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&(
        &receipt.member_id,
        &receipt.target_id,
        &receipt.operation_id,
        &receipt.expected_basis,
        &receipt.resulting_basis,
        &receipt.resulting_digest,
        receipt.outcome,
        &receipt.authority_ref,
        &receipt.failure_reason,
    ))
    .map_err(|error| error.to_string())
}

const PROJECT_RECEIPT_FRAME: &str = "gaugedesk.target-receipt.project.v1";
const PROJECT_RECEIPT_PREFIX: &str = "project-p256-v1:";

// Process-local custody for one bounded effect/query; never an actor grant.
struct SettlementSigner {
    project: String,
    key: SigningKey,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectReceiptAuthentication {
    project: String,
    authority: String,
    signature: String,
}

fn project_receipt_payload(
    receipt: &AuthenticatedTargetReceipt,
    project: &str,
    authority: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&(
        PROJECT_RECEIPT_FRAME,
        project,
        authority,
        target_receipt_payload(receipt)?,
    ))
    .map_err(|error| error.to_string())
}

fn verify_target_receipt_authentication(
    store: &gaugedesk_store::Store,
    receipt: &AuthenticatedTargetReceipt,
    project: &str,
    legacy_signer: Option<&PublicKey>,
) -> Result<(), String> {
    let (public_key, signature, payload) = if let Some(encoded) = receipt
        .authentication_ref
        .strip_prefix(PROJECT_RECEIPT_PREFIX)
    {
        let frame: ProjectReceiptAuthentication =
            serde_json::from_str(encoded).map_err(|error| error.to_string())?;
        let retained = store
            .project_authority_key(project)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "receipt project authority is unavailable".to_owned())?;
        let key = PublicKey::new(retained.public_key);
        if frame.project != project
            || frame.authority != retained.authority_id
            || crate::project_authority::authority(&key).as_str() != frame.authority
            || (retained.custody == "incoming-project-v1"
                && store
                    .committed_record_snapshot(
                        &crate::federation::handoff_scope(project),
                        "receive",
                    )
                    .map_err(|error| format!("{error:?}"))?
                    .is_none())
        {
            return Err("receipt has an untrusted project authority".to_owned());
        }
        let payload = project_receipt_payload(receipt, project, &frame.authority)?;
        (key, frame.signature, payload)
    } else {
        let encoded = receipt
            .authentication_ref
            .strip_prefix("p256:")
            .ok_or_else(|| "compensation receipt has no supported authentication".to_owned())?;
        let (public_key, signature) = encoded
            .split_once(':')
            .ok_or_else(|| "compensation receipt authentication is malformed".to_owned())?;
        let legacy_signer = legacy_signer
            .ok_or_else(|| "original legacy receipt root is unavailable".to_owned())?;
        if public_key != legacy_signer.as_str() {
            return Err("legacy receipt has an untrusted signer".to_owned());
        }
        (
            legacy_signer.clone(),
            signature.to_owned(),
            target_receipt_payload(receipt)?,
        )
    };
    let signature = hex::decode(signature)
        .map(Signature::new)
        .map_err(|_| "compensation receipt signature is not hex".to_owned())?;
    if receipt.receipt_ref != format!("target-receipt:{}", digest(&payload))
        || verify_signature(&payload, &signature, &public_key) != Ok(true)
    {
        return Err("compensation receipt authentication is invalid".to_owned());
    }
    Ok(())
}

fn core_act(act: TargetActKind) -> Result<SettlementAct, String> {
    match act {
        TargetActKind::Propose => Ok(SettlementAct::Propose),
        TargetActKind::Apply => Ok(SettlementAct::Apply),
        TargetActKind::Publish => Ok(SettlementAct::Publish),
        TargetActKind::Release => Ok(SettlementAct::Release),
        TargetActKind::Read => Err("read is not a settlement effect".to_owned()),
    }
}

fn capability_name(act: TargetActKind) -> &'static str {
    match act {
        TargetActKind::Read => "read",
        TargetActKind::Propose => "propose",
        TargetActKind::Apply => "apply",
        TargetActKind::Publish => "publish",
        TargetActKind::Release => "release",
    }
}

fn act_order(act: SettlementAct) -> u8 {
    match act {
        SettlementAct::Propose => 0,
        SettlementAct::Apply | SettlementAct::ManagedAdvance => 1,
        SettlementAct::Publish => 2,
        SettlementAct::Release => 3,
    }
}

fn adapter_contract(
    snapshot: &TargetCandidateSnapshot,
    act: SettlementAct,
) -> Option<&'static str> {
    if matches!(act, SettlementAct::Publish | SettlementAct::Release) {
        // Neither adapter currently exposes a provider-visible operation query
        // strong enough to recover an ambiguous publish/release outcome.
        return None;
    }
    match snapshot.adapter_family.as_str() {
        "managed:whipplescript-v1" | "whipplescript-v1" | "whipplescript" => {
            Some("whipplescript-target-receipt/v1")
        }
        "external-vcs:git-v1" | "git" => Some("git-compare-query/v1"),
        "external-folder:fingerprint-v1" | "folder" => Some("folder-compare-before-write-query/v1"),
        _ => None,
    }
}

pub(crate) fn snapshot_digest(files: &[(String, Option<Vec<u8>>)]) -> String {
    let mut bytes = Vec::new();
    for (path, body) in files {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        match body {
            Some(body) => {
                bytes.extend_from_slice(b"file\0");
                bytes.extend_from_slice(body);
            }
            None => bytes.extend_from_slice(b"deleted\0"),
        }
        bytes.push(0xff);
    }
    digest(bytes)
}

fn path_is_safe_and_scoped(path: &str, scopes: &[String]) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && scopes
            .iter()
            .any(|scope| scope == "." || path == scope || path.starts_with(&format!("{scope}/")))
}

#[derive(Debug)]
enum TargetEffectOutcome {
    Succeeded { resulting_basis: String },
    Refused { reason: String },
    Unknown { evidence_ref: String },
}

impl Workbench {
    fn target_change_set(
        &self,
        chat_id: &str,
        declaration_id: &str,
    ) -> Result<TargetChangeSetDeclaration, String> {
        self.store_ref()
            .records(chat_id, TARGET_CHANGE_SET_DECLARATION_KIND)
            .map_err(|error| format!("{error:?}"))?
            .into_iter()
            .map(|body| {
                serde_json::from_str::<TargetChangeSetDeclaration>(&body)
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|declaration| declaration.id == declaration_id)
            .ok_or_else(|| "target change-set declaration is unavailable".to_owned())
    }

    fn settlement_source(
        &self,
        declaration: &TargetSettlementDeclaration,
    ) -> Result<TargetChangeSetDeclaration, String> {
        let source =
            self.target_change_set(&declaration.chat_id, &declaration.source_change_set_ref)?;
        if source.chat_id != declaration.chat_id || source.project_id != declaration.project_id {
            return Err("settlement source identity does not match its declaration".to_owned());
        }
        self.validate_promotion_change_set(&source, declaration.promotion_manifest_ref.as_deref())?;
        Ok(source)
    }

    fn exact_candidate_files(
        &self,
        declaration: &TargetSettlementDeclaration,
        member: &SettlementMemberDeclaration,
    ) -> Result<(TargetCandidateSnapshot, CandidateFileSnapshot), String> {
        let source = self.settlement_source(declaration)?;
        let candidate = source
            .candidate_snapshots
            .into_iter()
            .find(|candidate| candidate.target_id == member.target_id)
            .ok_or_else(|| "settlement candidate disappeared".to_owned())?;
        if candidate.candidate_workspace_id.is_empty() || candidate.candidate_line_ref.is_empty() {
            return Err("candidate predates durable collaboration source addressing".to_owned());
        }
        if candidate
            .changed_paths
            .iter()
            .any(|path| !path_is_safe_and_scoped(path, &candidate.path_scope))
        {
            return Err("candidate contains a path outside its admitted target scope".to_owned());
        }
        let encoded = crate::library::target_id_path_v1(&candidate.target_id)?;
        let root = format!("targets/{encoded}");
        let roots = BTreeSet::from([root.clone()]);
        let workspace = self
            .collaboration_workspaces
            .get(&candidate.candidate_workspace_id)
            .ok_or_else(|| "candidate collaboration workspace is unavailable".to_owned())?;
        let temporary_id = crate::library::gen_id("settlement-source");
        let view = workspace
            .fork_engagement_subset_at(
                &temporary_id,
                &candidate.candidate_line_ref,
                workspace.mainline(),
                &candidate.candidate_cut,
                &roots,
            )
            .map_err(|error| error.to_string())?;
        let read_result = (|| {
            let existing = view
                .tree()
                .map_err(|error| error.to_string())?
                .into_iter()
                .filter(|entry| !entry.is_dir)
                .map(|entry| entry.path)
                .collect::<BTreeSet<_>>();
            let mut files = Vec::new();
            for path in &candidate.changed_paths {
                let materialized_path = format!("{root}/{path}");
                let body = if existing.contains(&materialized_path) {
                    Some(
                        view.read_file_bytes_capped(&materialized_path, usize::MAX)
                            .map_err(|error| error.to_string())?
                            .ok_or_else(|| "candidate file exceeds addressable size".to_owned())?,
                    )
                } else {
                    None
                };
                files.push((path.clone(), body));
            }
            if snapshot_digest(&files) != candidate.candidate_digest {
                return Err("materialized candidate does not match its immutable digest".to_owned());
            }
            Ok(files)
        })();
        drop(view);
        let cleanup = workspace
            .remove_engagement(&temporary_id)
            .map_err(|error| error.to_string());
        match (read_result, cleanup) {
            (Ok(files), Ok(())) => Ok((candidate, files)),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn verify_recorded_target_receipt(
        &self,
        project: &str,
        receipt: &AuthenticatedTargetReceipt,
    ) -> Result<(), String> {
        let legacy_signer = if receipt
            .authentication_ref
            .starts_with(PROJECT_RECEIPT_PREFIX)
        {
            None
        } else {
            Some(
                SigningKey::from_seed(&self.governance_seed())
                    .map_err(|error| error.reason.to_owned())?
                    .public_key(),
            )
        };
        verify_target_receipt_authentication(
            self.store_ref(),
            receipt,
            project,
            legacy_signer.as_ref(),
        )
    }

    fn known_settlement_outcome(
        &self,
        state: &TargetSettlementState,
        declaration: &TargetSettlementDeclaration,
        member_id: &str,
    ) -> Result<bool, String> {
        let member = state
            .members
            .get(member_id)
            .ok_or_else(|| "settlement member is not declared".to_owned())?;
        if !matches!(
            member.phase,
            SettlementMemberPhase::Succeeded | SettlementMemberPhase::Failed
        ) {
            return Ok(false);
        }
        self.require_owned_project(&declaration.project_id)
            .map_err(|error| error.to_string())?;
        let receipt = member
            .receipt
            .as_ref()
            .ok_or_else(|| "known settlement outcome has no receipt".to_owned())?;
        self.verify_recorded_target_receipt(&declaration.project_id, receipt)?;
        Ok(true)
    }

    /// Explicitly establish custody while project placement and handoff are
    /// current, before a target effect can start. This creates no actor standing.
    fn initialize_settlement_authority(
        &mut self,
        declaration: &TargetSettlementDeclaration,
    ) -> Result<SettlementSigner, String> {
        let project = &declaration.project_id;
        let handoff = crate::federation::handoff_scope(project);
        let (_, basis) = self.store_ref().read_for_dispatch(
            &[crate::library::LIBRARY_SCOPE, &handoff],
            |store| {
                crate::federation::require_project_writes_available(store, project)?;
                let library = crate::library::Library::rebuild(store)?;
                if declaration.members.iter().any(|member| {
                    library.work_targets.get(&member.target_id).is_none_or(|target| {
                        !matches!(&target.owner, crate::library::WorkTargetOwner::Project { project_id } if project_id == project)
                    })
                }) {
                    return Err(gaugedesk_store::AdmitError::Rejected(gaugedesk_core::Rejection {
                        reason: "settlement target belongs to another authority",
                    }));
                }
                Ok(())
            },
        ).map_err(|error| format!("{error:?}"))?;
        self.initialize_project_authority_against(project, &basis)
            .map_err(|error| error.to_string())?;
        Ok(SettlementSigner {
            project: project.clone(),
            key: self
                .project_signing_key(project)
                .map_err(|error| error.to_string())?,
        })
    }

    fn sign_target_receipt(
        &self,
        signer: &SettlementSigner,
        member: &SettlementMemberDeclaration,
        outcome: ReceiptOutcome,
        resulting_basis: Option<String>,
        resulting_digest: Option<String>,
        failure_reason: Option<String>,
    ) -> Result<AuthenticatedTargetReceipt, String> {
        let project = signer.project.as_str();
        self.require_owned_project(project)
            .map_err(|error| error.to_string())?;
        let library = crate::library::Library::rebuild(self.store_ref())
            .map_err(|error| format!("{error:?}"))?;
        let target = library
            .work_targets
            .get(&member.target_id)
            .ok_or_else(|| "settlement target is unavailable".to_owned())?;
        if !matches!(&target.owner, crate::library::WorkTargetOwner::Project { project_id } if project_id == project)
        {
            return Err("settlement target belongs to another authority".to_owned());
        }
        let authority_ref = target.authority.clone();
        let mut receipt = AuthenticatedTargetReceipt {
            receipt_ref: String::new(),
            member_id: member.member_id.clone(),
            target_id: member.target_id.clone(),
            operation_id: member.operation_id.clone(),
            expected_basis: member.expected_basis.clone(),
            resulting_basis,
            resulting_digest,
            outcome,
            authority_ref,
            authentication_ref: String::new(),
            failure_reason,
        };
        let signing_key = &signer.key;
        let authority = crate::project_authority::authority(&signing_key.public_key());
        let payload = project_receipt_payload(&receipt, project, authority.as_str())?;
        let signature = signing_key.sign(&payload);
        let frame = ProjectReceiptAuthentication {
            project: project.to_owned(),
            authority: authority.as_str().to_owned(),
            signature: hex::encode(signature.as_bytes()),
        };
        receipt.authentication_ref = format!(
            "{PROJECT_RECEIPT_PREFIX}{}",
            serde_json::to_string(&frame).map_err(|error| error.to_string())?
        );
        receipt.receipt_ref = format!("target-receipt:{}", digest(&payload));
        Ok(receipt)
    }

    fn execute_prepared_target_effect(
        &self,
        member: &SettlementMemberDeclaration,
        files: &[(String, Option<Vec<u8>>)],
    ) -> TargetEffectOutcome {
        if member.act == SettlementAct::Propose {
            return TargetEffectOutcome::Succeeded {
                resulting_basis: member.expected_basis.clone(),
            };
        }
        if matches!(member.act, SettlementAct::Publish | SettlementAct::Release) {
            return TargetEffectOutcome::Refused {
                reason: "act has no configured authoritative recovery adapter".to_owned(),
            };
        }
        let Some(workspace) = self.targets.get(&member.target_id) else {
            return TargetEffectOutcome::Refused {
                reason: "target workspace is unavailable".to_owned(),
            };
        };
        let effect_id = crate::library::gen_id("settlement-effect");
        let candidate = match workspace.create_engagement(&effect_id) {
            Ok(candidate) => candidate,
            Err(error) => {
                return TargetEffectOutcome::Refused {
                    reason: format!("could not prepare target candidate: {error}"),
                }
            }
        };
        let outcome = (|| {
            let observed = candidate
                .standing_revision()
                .map_err(|error| (false, format!("could not read target basis: {error}")))?
                .0;
            if observed != member.expected_basis {
                return Err((
                    false,
                    "target basis changed after all-member preflight".to_owned(),
                ));
            }
            for (path, body) in files {
                match body {
                    Some(body) => candidate.write_file_bytes(path, body).map_err(|error| {
                        (false, format!("could not stage target file: {error}"))
                    })?,
                    None => candidate
                        .remove_file(path)
                        .map_err(|error| (false, format!("could not stage deletion: {error}")))?,
                }
            }
            candidate
                .commit_turn(&member.operation_id)
                .map_err(|error| (false, format!("could not commit target candidate: {error}")))?;
            match candidate.merge_into_main() {
                Ok(MergeOutcome::Conflict) => Err((
                    false,
                    "target changed during compare-before-effect".to_owned(),
                )),
                Err(error) => Err((
                    true,
                    format!("target adapter returned an ambiguous effect error: {error}"),
                )),
                Ok(MergeOutcome::Clean) => candidate
                    .standing_revision()
                    .map(|revision| revision.0)
                    .map_err(|error| {
                        (
                            true,
                            format!(
                                "target advanced but its resulting basis is unavailable: {error}"
                            ),
                        )
                    }),
            }
        })();
        drop(candidate);
        let _ = workspace.remove_engagement(&effect_id);
        match outcome {
            Ok(resulting_basis) => TargetEffectOutcome::Succeeded { resulting_basis },
            Err((true, evidence_ref)) => TargetEffectOutcome::Unknown { evidence_ref },
            Err((false, reason)) => TargetEffectOutcome::Refused { reason },
        }
    }

    fn current_target_files(
        &self,
        candidate: &TargetCandidateSnapshot,
    ) -> Result<(String, CandidateFileSnapshot), String> {
        let workspace = self
            .targets
            .get(&candidate.target_id)
            .ok_or_else(|| "target workspace is unavailable".to_owned())?;
        let probe_id = crate::library::gen_id("settlement-query");
        let probe = workspace
            .create_engagement(&probe_id)
            .map_err(|error| error.to_string())?;
        let query_result = (|| {
            let basis = probe
                .standing_revision()
                .map_err(|error| error.to_string())?
                .0;
            let existing = probe
                .tree()
                .map_err(|error| error.to_string())?
                .into_iter()
                .filter(|entry| !entry.is_dir)
                .map(|entry| entry.path)
                .collect::<BTreeSet<_>>();
            let mut files = Vec::new();
            for path in &candidate.changed_paths {
                let body = if existing.contains(path) {
                    Some(
                        probe
                            .read_file_bytes_capped(path, usize::MAX)
                            .map_err(|error| error.to_string())?
                            .ok_or_else(|| "target file exceeds addressable size".to_owned())?,
                    )
                } else {
                    None
                };
                files.push((path.clone(), body));
            }
            Ok((basis, files))
        })();
        drop(probe);
        let cleanup = workspace
            .remove_engagement(&probe_id)
            .map_err(|error| error.to_string());
        match (query_result, cleanup) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn finish_started_settlement_member(
        &mut self,
        declaration_id: &str,
        declaration: &TargetSettlementDeclaration,
        member: &SettlementMemberDeclaration,
        candidate: TargetCandidateSnapshot,
        files: &[(String, Option<Vec<u8>>)],
        signer: &SettlementSigner,
    ) -> Result<TargetSettlementState, String> {
        let member_id = member.member_id.as_str();
        match self.execute_prepared_target_effect(member, files) {
            TargetEffectOutcome::Succeeded { resulting_basis } => {
                self.record_target_act(
                    Some(&declaration.chat_id),
                    &member.target_id,
                    match member.act {
                        SettlementAct::Propose => TargetActKind::Propose,
                        SettlementAct::Apply | SettlementAct::ManagedAdvance => {
                            TargetActKind::Apply
                        }
                        SettlementAct::Publish => TargetActKind::Publish,
                        SettlementAct::Release => TargetActKind::Release,
                    },
                    Some(candidate.candidate_identity),
                    candidate.checks,
                    Some(resulting_basis.clone()),
                    TargetActStatus::Completed,
                    None,
                )?;
                if member.act != SettlementAct::Propose {
                    let mut target = self
                        .library
                        .work_targets
                        .get(&member.target_id)
                        .cloned()
                        .ok_or_else(|| "settlement target disappeared".to_owned())?;
                    target.current_basis = Some(resulting_basis.clone());
                    self.write_work_target_record(target);
                }
                let receipt = self.sign_target_receipt(
                    signer,
                    member,
                    ReceiptOutcome::Succeeded,
                    Some(resulting_basis),
                    Some(member.expected_result_digest.clone()),
                    None,
                )?;
                self.record_settlement_receipt(declaration_id, receipt)
            }
            TargetEffectOutcome::Refused { reason } => {
                self.record_target_act(
                    Some(&declaration.chat_id),
                    &member.target_id,
                    match member.act {
                        SettlementAct::Propose => TargetActKind::Propose,
                        SettlementAct::Apply | SettlementAct::ManagedAdvance => {
                            TargetActKind::Apply
                        }
                        SettlementAct::Publish => TargetActKind::Publish,
                        SettlementAct::Release => TargetActKind::Release,
                    },
                    Some(candidate.candidate_identity),
                    candidate.checks,
                    None,
                    TargetActStatus::Refused,
                    Some(reason.clone()),
                )?;
                let receipt = self.sign_target_receipt(
                    signer,
                    member,
                    ReceiptOutcome::Failed,
                    None,
                    None,
                    Some(reason),
                )?;
                self.record_settlement_receipt(declaration_id, receipt)
            }
            TargetEffectOutcome::Unknown { evidence_ref } => {
                self.record_settlement_unknown(declaration_id, member_id, &evidence_ref)
            }
        }
    }

    pub(crate) fn execute_settlement_member(
        &mut self,
        declaration_id: &str,
        member_id: &str,
    ) -> Result<TargetSettlementState, String> {
        let scope = settlement_scope(declaration_id);
        let state = self
            .store_ref()
            .fold::<TargetSettlementState>(&scope)
            .map_err(|error| format!("{error:?}"))?;
        let declaration = state
            .declaration
            .clone()
            .ok_or_else(|| "settlement declaration is absent".to_owned())?;
        if self.project_moving(&declaration.project_id) {
            return Err(crate::federation::PAUSED_FOR_MOVE.to_owned());
        }
        let member = declaration
            .members
            .iter()
            .find(|member| member.member_id == member_id)
            .cloned()
            .ok_or_else(|| "settlement member is not declared".to_owned())?;
        if self.known_settlement_outcome(&state, &declaration, member_id)? {
            return Ok(state);
        }
        let (candidate, files) = self.exact_candidate_files(&declaration, &member)?;
        let signer = self.initialize_settlement_authority(&declaration)?;
        self.start_settlement_member(declaration_id, member_id)?;
        self.finish_started_settlement_member(
            declaration_id,
            &declaration,
            &member,
            candidate,
            &files,
            &signer,
        )
    }

    pub(crate) fn retry_settlement_member_effect(
        &mut self,
        declaration_id: &str,
        member_id: &str,
    ) -> Result<TargetSettlementState, String> {
        let state = self
            .store_ref()
            .fold::<TargetSettlementState>(&settlement_scope(declaration_id))
            .map_err(|error| format!("{error:?}"))?;
        let declaration = state
            .declaration
            .clone()
            .ok_or_else(|| "settlement declaration is absent".to_owned())?;
        if self.project_moving(&declaration.project_id) {
            return Err(crate::federation::PAUSED_FOR_MOVE.to_owned());
        }
        let member = declaration
            .members
            .iter()
            .find(|member| member.member_id == member_id)
            .cloned()
            .ok_or_else(|| "settlement member is not declared".to_owned())?;
        if state.members[member_id].phase == SettlementMemberPhase::Succeeded
            && self.known_settlement_outcome(&state, &declaration, member_id)?
        {
            return Ok(state);
        }
        let (candidate, files) = self.exact_candidate_files(&declaration, &member)?;
        let signer = self.initialize_settlement_authority(&declaration)?;
        self.retry_failed_settlement_member(declaration_id, member_id)?;
        self.finish_started_settlement_member(
            declaration_id,
            &declaration,
            &member,
            candidate,
            &files,
            &signer,
        )
    }

    pub(crate) fn query_settlement_member(
        &mut self,
        declaration_id: &str,
        member_id: &str,
    ) -> Result<Option<TargetSettlementState>, String> {
        let scope = settlement_scope(declaration_id);
        let state = self
            .store_ref()
            .fold::<TargetSettlementState>(&scope)
            .map_err(|error| format!("{error:?}"))?;
        let declaration = state
            .declaration
            .clone()
            .ok_or_else(|| "settlement declaration is absent".to_owned())?;
        let member = declaration
            .members
            .iter()
            .find(|member| member.member_id == member_id)
            .cloned()
            .ok_or_else(|| "settlement member is not declared".to_owned())?;
        if self.known_settlement_outcome(&state, &declaration, member_id)? {
            return Ok(Some(state));
        }
        let query_ref = format!(
            "target-query:{}",
            digest(format!(
                "{}\0{}\0{}",
                member.operation_id, member_id, state.members[member_id].attempts
            ))
        );
        let source = self.settlement_source(&declaration)?;
        let signer = self.initialize_settlement_authority(&declaration)?;
        self.request_settlement_query(declaration_id, member_id, &query_ref)?;
        let candidate = source
            .candidate_snapshots
            .into_iter()
            .find(|candidate| candidate.target_id == member.target_id)
            .ok_or_else(|| "settlement candidate disappeared".to_owned())?;
        let (observed_basis, observed_files) = self.current_target_files(&candidate)?;
        let observed_digest = snapshot_digest(&observed_files);
        let receipt = if observed_digest == member.expected_result_digest {
            Some(self.sign_target_receipt(
                &signer,
                &member,
                ReceiptOutcome::Succeeded,
                Some(observed_basis),
                Some(member.expected_result_digest.clone()),
                None,
            )?)
        } else if observed_basis == member.expected_basis {
            Some(self.sign_target_receipt(
                &signer,
                &member,
                ReceiptOutcome::Failed,
                Some(observed_basis),
                None,
                Some("authoritative target query proved no effect".to_owned()),
            )?)
        } else {
            None
        };
        match receipt {
            Some(receipt) => self
                .record_settlement_query_receipt(declaration_id, receipt)
                .map(Some),
            None => Ok(None),
        }
    }

    pub(crate) fn create_target_settlement(
        &mut self,
        chat_id: &str,
        source_change_set_ref: &str,
        promotion_manifest_ref: Option<String>,
        requested: Vec<RequestedSettlementMember>,
    ) -> Result<TargetSettlementState, String> {
        if requested.is_empty() {
            return Err("settlement must request at least one target act".to_owned());
        }
        let source = self.target_change_set(chat_id, source_change_set_ref)?;
        if source.chat_id != chat_id {
            return Err("settlement source belongs to another chat".to_owned());
        }
        self.validate_promotion_change_set(&source, promotion_manifest_ref.as_deref())?;
        let candidates = source
            .candidate_snapshots
            .iter()
            .map(|candidate| (candidate.target_id.as_str(), candidate))
            .collect::<BTreeMap<_, _>>();
        let mut seen = BTreeSet::new();
        let mut members = Vec::new();
        for request in requested {
            if !seen.insert(request.target_id.clone()) {
                return Err(
                    "one settlement declaration may request only one act per target".to_owned(),
                );
            }
            let candidate = candidates
                .get(request.target_id.as_str())
                .ok_or_else(|| "settlement target has no candidate in the change set".to_owned())?;
            let target = self
                .library
                .work_targets
                .get(&request.target_id)
                .ok_or_else(|| "settlement target is unavailable".to_owned())?;
            let admitted = match request.act {
                TargetActKind::Read => false,
                TargetActKind::Propose => target.capabilities.propose,
                TargetActKind::Apply => target.capabilities.apply,
                TargetActKind::Publish => target.capabilities.publish,
                TargetActKind::Release => target.capabilities.release,
            };
            if !admitted {
                return Err(format!(
                    "target {} does not grant {}",
                    request.target_id,
                    capability_name(request.act)
                ));
            }
            let act = core_act(request.act)?;
            let operation_id = digest(format!(
                "settlement-operation-v1\0{}\0{}\0{}\0{:?}\0{}",
                source.id,
                candidate.target_id,
                candidate.native_basis,
                act,
                candidate.candidate_digest
            ));
            let member_id = digest(format!("settlement-member-v1\0{operation_id}"));
            let policy_decision_handle = candidate
                .policy_decision_handles
                .first()
                .cloned()
                .ok_or_else(|| "candidate has no governance decision".to_owned())?;
            members.push(SettlementMemberDeclaration {
                member_id,
                target_id: candidate.target_id.clone(),
                operation_id,
                expected_basis: candidate.native_basis.clone(),
                candidate_digest: candidate.candidate_digest.clone(),
                expected_result_digest: candidate.candidate_digest.clone(),
                policy_decision_handle,
                adapter: candidate.adapter_family.clone(),
                act,
                retry_safe_after_failure: true,
                authoritative_query: adapter_contract(candidate, act).is_some(),
            });
        }
        members.sort_by(|left, right| {
            left.target_id
                .cmp(&right.target_id)
                .then_with(|| act_order(left.act).cmp(&act_order(right.act)))
        });
        let identity = serde_json::to_vec(&(
            &source.id,
            &source.project_id,
            &promotion_manifest_ref,
            &members,
        ))
        .map_err(|error| error.to_string())?;
        let declaration_id = format!("target-settlement:{}", digest(identity));
        let declaration = TargetSettlementDeclaration {
            declaration_id: declaration_id.clone(),
            project_id: source.project_id,
            chat_id: chat_id.to_owned(),
            source_change_set_ref: source.id,
            promotion_manifest_ref,
            members,
        };
        self.initialize_settlement_authority(&declaration)?;
        let state = self
            .store_mut()
            .admit_materialized::<TargetSettlementState>(
                &settlement_scope(&declaration_id),
                "declare",
                TargetSettlementCommand::Declare(declaration),
            )
            .map(|admission| admission.state)
            .map_err(|error| format!("{error:?}"))?;
        let reference = TargetSettlementChatRef {
            schema: "gaugedesk.target-settlement-ref.v1".to_owned(),
            declaration_id,
        };
        self.store_mut()
            .append_record(
                chat_id,
                TARGET_SETTLEMENT_CHAT_REF_KIND,
                &serde_json::to_string(&reference).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(state)
    }

    /// Immutable receipt evidence visible from a chat turn. Coordinator ids,
    /// lane permits, and operation ids are deliberately excluded: a fork may
    /// know what happened without gaining authority to retry its parent's act.
    #[cfg(test)]
    pub(crate) fn visible_target_settlement_handles(
        &self,
        chat_id: &str,
    ) -> Result<Vec<String>, String> {
        Ok(self
            .visible_target_settlement_evidence(chat_id)?
            .into_iter()
            .flat_map(|snapshot| snapshot.receipt_handles)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    pub(crate) fn visible_target_settlement_evidence(
        &self,
        chat_id: &str,
    ) -> Result<Vec<crate::engine::VisibleSettlementSnapshot>, String> {
        let mut declaration_ids = BTreeSet::new();
        let mut inherited = BTreeSet::new();
        for (scope, bound) in self.effective_log_lineage(chat_id) {
            for (_, kind, body) in self
                .store_ref()
                .events(&scope)
                .map_err(|error| format!("{error:?}"))?
                .into_iter()
                .filter(|(position, _, _)| bound.is_none_or(|bound| *position <= bound))
            {
                if kind == TARGET_SETTLEMENT_CHAT_REF_KIND && scope == chat_id {
                    let reference: TargetSettlementChatRef =
                        serde_json::from_str(&body).map_err(|error| error.to_string())?;
                    declaration_ids.insert(reference.declaration_id);
                } else if kind == crate::library_state::CHAT_FORK_ADMISSION_KIND {
                    let admission: crate::library_state::ChatForkAdmissionRecord =
                        serde_json::from_str(&body).map_err(|error| error.to_string())?;
                    inherited.extend(admission.visible_settlements);
                }
            }
        }
        let mut evidence = inherited;
        for declaration_id in declaration_ids {
            let scope = settlement_scope(&declaration_id);
            let position = self
                .store_ref()
                .events(&scope)
                .map_err(|error| format!("{error:?}"))?
                .last()
                .map(|(position, _, _)| *position)
                .ok_or_else(|| format!("settlement {declaration_id} has no durable state"))?;
            let state = self
                .store_ref()
                .fold::<TargetSettlementState>(&scope)
                .map_err(|error| format!("{error:?}"))?;
            let mut handles = BTreeSet::new();
            for member in state.members.values() {
                if let Some(receipt) = &member.receipt {
                    handles.insert(receipt.receipt_ref.clone());
                }
            }
            handles.extend(state.compensation_receipt_refs);
            evidence.insert(crate::engine::VisibleSettlementSnapshot {
                settlement_scope: scope,
                position,
                receipt_handles: handles.into_iter().collect(),
            });
        }
        Ok(evidence.into_iter().collect())
    }

    /// Re-resolve every member before enqueueing any target effect. A refusal
    /// records terminal coordinator truth and leaves every target lane untouched.
    pub(crate) fn preflight_target_settlement(
        &mut self,
        declaration_id: &str,
    ) -> Result<TargetSettlementState, String> {
        let scope = settlement_scope(declaration_id);
        let current = self
            .store_ref()
            .fold::<TargetSettlementState>(&scope)
            .map_err(|error| format!("{error:?}"))?;
        let declaration = current
            .declaration
            .clone()
            .ok_or_else(|| "settlement declaration is absent".to_owned())?;
        let source = self.settlement_source(&declaration)?;
        let mut state = match current.phase {
            gaugedesk_core::target_settlement::SettlementPhase::Declared => {
                self.store_mut()
                    .admit_materialized::<TargetSettlementState>(
                        &scope,
                        "begin-preflight",
                        TargetSettlementCommand::BeginPreflight,
                    )
                    .map_err(|error| format!("{error:?}"))?
                    .state
            }
            gaugedesk_core::target_settlement::SettlementPhase::Preflighting => current,
            gaugedesk_core::target_settlement::SettlementPhase::Refused => return Ok(current),
            gaugedesk_core::target_settlement::SettlementPhase::Ready => current,
            _ => return Ok(current),
        };
        let candidates = source
            .candidate_snapshots
            .iter()
            .map(|candidate| (candidate.target_id.as_str(), candidate))
            .collect::<BTreeMap<_, _>>();

        if state.phase == gaugedesk_core::target_settlement::SettlementPhase::Preflighting {
            for member in &declaration.members {
                if state.members[&member.member_id].phase != SettlementMemberPhase::Pending {
                    continue;
                }
                let candidate = candidates
                    .get(member.target_id.as_str())
                    .ok_or_else(|| "settlement candidate disappeared".to_owned())?;
                let target = self.library.work_targets.get(&member.target_id);
                let observed_basis = target
                    .and_then(|target| target.current_basis.clone())
                    .unwrap_or_else(|| "unavailable".to_owned());
                let contract = adapter_contract(candidate, member.act);
                let admitted = observed_basis == member.expected_basis
                    && candidate.candidate_digest == member.candidate_digest
                    && contract.is_some();
                let evidence = MemberPreflightEvidence {
                    member_id: member.member_id.clone(),
                    observed_basis,
                    observed_candidate_digest: candidate.candidate_digest.clone(),
                    adapter_contract_ref: contract.unwrap_or("unsupported-adapter").to_owned(),
                    governance_decision_ref: member.policy_decision_handle.clone(),
                    admitted,
                    refusal_reason: (!admitted).then(|| {
                        if contract.is_none() {
                            "target adapter has no authoritative recovery contract".to_owned()
                        } else {
                            "target basis or candidate changed before all-member preflight"
                                .to_owned()
                        }
                    }),
                };
                state = self
                    .store_mut()
                    .admit_materialized::<TargetSettlementState>(
                        &scope,
                        &format!("preflight:{}", member.member_id),
                        TargetSettlementCommand::RecordPreflight(evidence),
                    )
                    .map_err(|error| format!("{error:?}"))?
                    .state;
                if state.phase == gaugedesk_core::target_settlement::SettlementPhase::Refused {
                    return Ok(state);
                }
            }
        }
        if state.phase != gaugedesk_core::target_settlement::SettlementPhase::Ready {
            return Err("settlement preflight did not reach ready".to_owned());
        }

        // Enqueue only after every preflight succeeded. Cross-lane appends may
        // be recovered independently because no adapter effect has started.
        for member in &declaration.members {
            let lane_member = TargetLaneMember {
                settlement_scope: scope.clone(),
                declaration_id: declaration.declaration_id.clone(),
                member_id: member.member_id.clone(),
                target_id: member.target_id.clone(),
                operation_id: member.operation_id.clone(),
                expected_basis: member.expected_basis.clone(),
                expected_result_digest: member.expected_result_digest.clone(),
                attempt: 1,
            };
            self.store_mut()
                .admit_materialized::<TargetSettlementLaneState>(
                    &lane_scope(&member.target_id),
                    &format!("enqueue:{}", member.operation_id),
                    TargetSettlementLaneCommand::Enqueue(lane_member),
                )
                .map_err(|error| format!("{error:?}"))?;
        }
        Ok(state)
    }

    pub(crate) fn start_settlement_member(
        &mut self,
        declaration_id: &str,
        member_id: &str,
    ) -> Result<TargetLanePermit, String> {
        let scope = settlement_scope(declaration_id);
        let state = self
            .store_ref()
            .fold::<TargetSettlementState>(&scope)
            .map_err(|error| format!("{error:?}"))?;
        let declaration = state
            .declaration
            .clone()
            .ok_or_else(|| "settlement declaration is absent".to_owned())?;
        if declaration.promotion_manifest_ref.is_some() {
            self.settlement_source(&declaration)?;
        }
        let member = declaration
            .members
            .iter()
            .find(|member| member.member_id == member_id)
            .ok_or_else(|| "settlement member is not declared".to_owned())?;
        let attempt = state.members[member_id].attempts.saturating_add(1);
        let member_ref = format!("{scope}#{member_id}#attempt:{attempt}");
        let lane = self
            .store_mut()
            .admit_materialized::<TargetSettlementLaneState>(
                &lane_scope(&member.target_id),
                &format!("grant:{}", member.operation_id),
                TargetSettlementLaneCommand::Grant {
                    member_ref: member_ref.clone(),
                },
            )
            .map_err(|error| format!("{error:?}"))?
            .state;
        let permit = lane
            .queue
            .iter()
            .find(|entry| entry.member.member_ref() == member_ref)
            .and_then(|entry| entry.permit.clone())
            .ok_or_else(|| "target lane did not issue a permit".to_owned())?;
        self.store_mut()
            .admit_materialized::<TargetSettlementState>(
                &scope,
                &format!("start:{}", member.operation_id),
                TargetSettlementCommand::StartMember {
                    member_id: member_id.to_owned(),
                    lane_permit: permit.clone(),
                },
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(permit)
    }

    /// Record coordinator truth before releasing the ordered lane. A crash
    /// between those appends can only leave the lane conservatively blocked.
    pub(crate) fn record_settlement_receipt(
        &mut self,
        declaration_id: &str,
        receipt: AuthenticatedTargetReceipt,
    ) -> Result<TargetSettlementState, String> {
        let scope = settlement_scope(declaration_id);
        let current = self
            .store_ref()
            .fold::<TargetSettlementState>(&scope)
            .map_err(|error| format!("{error:?}"))?;
        let attempt = current.members[&receipt.member_id].attempts;
        let member_ref = format!("{scope}#{}#attempt:{attempt}", receipt.member_id);
        let target_id = receipt.target_id.clone();
        let operation_id = receipt.operation_id.clone();
        let receipt_ref = receipt.receipt_ref.clone();
        let state = self
            .store_mut()
            .admit_materialized::<TargetSettlementState>(
                &scope,
                &format!("receipt:{receipt_ref}"),
                TargetSettlementCommand::RecordReceipt(receipt),
            )
            .map_err(|error| format!("{error:?}"))?
            .state;
        self.store_mut()
            .admit_materialized::<TargetSettlementLaneState>(
                &lane_scope(&target_id),
                &format!("resolve:{operation_id}:{receipt_ref}"),
                TargetSettlementLaneCommand::RecordKnownOutcome {
                    member_ref,
                    receipt_ref,
                },
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(state)
    }

    pub(crate) fn record_settlement_unknown(
        &mut self,
        declaration_id: &str,
        member_id: &str,
        evidence_ref: &str,
    ) -> Result<TargetSettlementState, String> {
        let scope = settlement_scope(declaration_id);
        let current = self
            .store_ref()
            .fold::<TargetSettlementState>(&scope)
            .map_err(|error| format!("{error:?}"))?;
        let declaration = current
            .declaration
            .as_ref()
            .ok_or_else(|| "settlement declaration is absent".to_owned())?;
        let member = declaration
            .members
            .iter()
            .find(|member| member.member_id == member_id)
            .ok_or_else(|| "settlement member is not declared".to_owned())?;
        let member_ref = format!(
            "{scope}#{member_id}#attempt:{}",
            current.members[member_id].attempts
        );
        let state = self
            .store_mut()
            .admit_materialized::<TargetSettlementState>(
                &scope,
                &format!("unknown:{}:{evidence_ref}", member.operation_id),
                TargetSettlementCommand::RecordUnknown {
                    member_id: member_id.to_owned(),
                    evidence_ref: evidence_ref.to_owned(),
                },
            )
            .map_err(|error| format!("{error:?}"))?
            .state;
        self.store_mut()
            .admit_materialized::<TargetSettlementLaneState>(
                &lane_scope(&member.target_id),
                &format!("unknown:{}:{evidence_ref}", member.operation_id),
                TargetSettlementLaneCommand::RecordUnknownOutcome {
                    member_ref,
                    evidence_ref: evidence_ref.to_owned(),
                },
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(state)
    }

    pub(crate) fn request_settlement_query(
        &mut self,
        declaration_id: &str,
        member_id: &str,
        query_ref: &str,
    ) -> Result<TargetSettlementState, String> {
        let scope = settlement_scope(declaration_id);
        self.store_mut()
            .admit_materialized::<TargetSettlementState>(
                &scope,
                &format!("query:{member_id}:{query_ref}"),
                TargetSettlementCommand::RequestAuthoritativeQuery {
                    member_id: member_id.to_owned(),
                    query_ref: query_ref.to_owned(),
                },
            )
            .map(|admission| admission.state)
            .map_err(|error| format!("{error:?}"))
    }

    pub(crate) fn record_settlement_query_receipt(
        &mut self,
        declaration_id: &str,
        receipt: AuthenticatedTargetReceipt,
    ) -> Result<TargetSettlementState, String> {
        let scope = settlement_scope(declaration_id);
        let current = self
            .store_ref()
            .fold::<TargetSettlementState>(&scope)
            .map_err(|error| format!("{error:?}"))?;
        let attempt = current.members[&receipt.member_id].attempts;
        let member_ref = format!("{scope}#{}#attempt:{attempt}", receipt.member_id);
        let target_id = receipt.target_id.clone();
        let operation_id = receipt.operation_id.clone();
        let receipt_ref = receipt.receipt_ref.clone();
        let state = self
            .store_mut()
            .admit_materialized::<TargetSettlementState>(
                &scope,
                &format!("query-receipt:{receipt_ref}"),
                TargetSettlementCommand::RecordQueryReceipt(receipt),
            )
            .map_err(|error| format!("{error:?}"))?
            .state;
        self.store_mut()
            .admit_materialized::<TargetSettlementLaneState>(
                &lane_scope(&target_id),
                &format!("reconcile:{operation_id}:{receipt_ref}"),
                TargetSettlementLaneCommand::ReconcileUnknown {
                    member_ref,
                    receipt_ref,
                },
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(state)
    }

    pub(crate) fn retry_failed_settlement_member(
        &mut self,
        declaration_id: &str,
        member_id: &str,
    ) -> Result<TargetLanePermit, String> {
        let scope = settlement_scope(declaration_id);
        let current = self
            .store_ref()
            .fold::<TargetSettlementState>(&scope)
            .map_err(|error| format!("{error:?}"))?;
        let declaration = current
            .declaration
            .as_ref()
            .ok_or_else(|| "settlement declaration is absent".to_owned())?;
        if declaration.promotion_manifest_ref.is_some() {
            self.settlement_source(declaration)?;
        }
        let member = declaration
            .members
            .iter()
            .find(|member| member.member_id == member_id)
            .ok_or_else(|| "settlement member is not declared".to_owned())?
            .clone();
        let attempt = current.members[member_id].attempts.saturating_add(1);
        let lane_member = TargetLaneMember {
            settlement_scope: scope.clone(),
            declaration_id: declaration.declaration_id.clone(),
            member_id: member.member_id.clone(),
            target_id: member.target_id.clone(),
            operation_id: member.operation_id.clone(),
            expected_basis: member.expected_basis.clone(),
            expected_result_digest: member.expected_result_digest.clone(),
            attempt,
        };
        let lane_id = lane_scope(&member.target_id);
        self.store_mut()
            .admit_materialized::<TargetSettlementLaneState>(
                &lane_id,
                &format!("enqueue-retry:{}:{attempt}", member.operation_id),
                TargetSettlementLaneCommand::Enqueue(lane_member.clone()),
            )
            .map_err(|error| format!("{error:?}"))?;
        let member_ref = lane_member.member_ref();
        let lane = self
            .store_mut()
            .admit_materialized::<TargetSettlementLaneState>(
                &lane_id,
                &format!("grant-retry:{}:{attempt}", member.operation_id),
                TargetSettlementLaneCommand::Grant { member_ref },
            )
            .map_err(|error| format!("{error:?}"))?
            .state;
        let permit = lane
            .queue
            .iter()
            .find(|entry| entry.member == lane_member)
            .and_then(|entry| entry.permit.clone())
            .ok_or_else(|| "retry lane did not issue a permit".to_owned())?;
        self.store_mut()
            .admit_materialized::<TargetSettlementState>(
                &scope,
                &format!("retry:{}:{attempt}", member.operation_id),
                TargetSettlementCommand::RetryKnownFailure {
                    member_id: member_id.to_owned(),
                    lane_permit: permit.clone(),
                },
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(permit)
    }

    pub(crate) fn compensate_target_settlement(
        &mut self,
        declaration_id: &str,
        mut receipt_links: Vec<CompensationReceiptLink>,
    ) -> Result<TargetSettlementState, String> {
        receipt_links.sort_by(|left, right| {
            left.original_receipt_ref
                .cmp(&right.original_receipt_ref)
                .then_with(|| {
                    left.compensation_declaration_id
                        .cmp(&right.compensation_declaration_id)
                })
                .then_with(|| {
                    left.compensation_member_id
                        .cmp(&right.compensation_member_id)
                })
                .then_with(|| {
                    left.compensation_receipt_ref
                        .cmp(&right.compensation_receipt_ref)
                })
        });
        let scope = settlement_scope(declaration_id);
        let original_state = self
            .store_ref()
            .fold::<TargetSettlementState>(&scope)
            .map_err(|error| format!("{error:?}"))?;
        let original_declaration = original_state
            .declaration
            .as_ref()
            .ok_or_else(|| "settlement declaration is absent".to_owned())?;
        let successful = original_state
            .members
            .values()
            .filter_map(|member| {
                member.receipt.as_ref().and_then(|receipt| {
                    if receipt.outcome == ReceiptOutcome::Succeeded {
                        member
                            .lane_permit
                            .as_ref()
                            .map(|permit| (receipt.receipt_ref.clone(), (receipt, permit.sequence)))
                    } else {
                        None
                    }
                })
            })
            .collect::<BTreeMap<_, _>>();
        for link in &receipt_links {
            let (original, original_lane_sequence) =
                successful.get(&link.original_receipt_ref).ok_or_else(|| {
                    "compensation link names no successful original effect".to_owned()
                })?;
            if link.compensation_declaration_id == declaration_id {
                return Err("a settlement cannot compensate itself".to_owned());
            }
            let later_state = self
                .store_ref()
                .fold::<TargetSettlementState>(&settlement_scope(&link.compensation_declaration_id))
                .map_err(|error| format!("{error:?}"))?;
            let later_declaration = later_state
                .declaration
                .as_ref()
                .ok_or_else(|| "compensation settlement declaration is absent".to_owned())?;
            if later_declaration.declaration_id != link.compensation_declaration_id
                || later_declaration.project_id != original_declaration.project_id
            {
                return Err("compensation settlement belongs to a different project".to_owned());
            }
            let later_member = later_declaration
                .members
                .iter()
                .find(|member| member.member_id == link.compensation_member_id)
                .ok_or_else(|| "compensation member is unavailable".to_owned())?;
            let later_member_state = later_state
                .members
                .get(&link.compensation_member_id)
                .ok_or_else(|| "compensation member state is unavailable".to_owned())?;
            let later_receipt = later_member_state
                .receipt
                .as_ref()
                .filter(|receipt| {
                    receipt.receipt_ref == link.compensation_receipt_ref
                        && receipt.outcome == ReceiptOutcome::Succeeded
                })
                .ok_or_else(|| "compensation member has no exact successful receipt".to_owned())?;
            if later_member.target_id != original.target_id
                || later_member.expected_basis != original.resulting_basis.as_deref().unwrap_or("")
                || later_member.act == SettlementAct::Propose
                || later_member_state
                    .lane_permit
                    .as_ref()
                    .map(|permit| permit.sequence <= *original_lane_sequence)
                    .unwrap_or(true)
            {
                return Err(
                    "compensation must be a later lane effect on the same target and resulting basis"
                        .to_owned(),
                );
            }
            let expected_authority = self
                .library
                .work_targets
                .get(&later_member.target_id)
                .map(|target| target.authority.as_str())
                .ok_or_else(|| "compensation target is unavailable".to_owned())?;
            if later_receipt.authority_ref != expected_authority {
                return Err("compensation receipt names the wrong target authority".to_owned());
            }
            self.verify_recorded_target_receipt(&original_declaration.project_id, later_receipt)?;
        }

        self.store_mut()
            .admit_materialized::<TargetSettlementState>(
                &scope,
                &format!(
                    "compensate:{}",
                    digest(serde_json::to_vec(&receipt_links).map_err(|error| error.to_string())?)
                ),
                TargetSettlementCommand::MarkCompensated { receipt_links },
            )
            .map(|admission| admission.state)
            .map_err(|error| format!("{error:?}"))
    }

    pub(crate) fn abandon_target_settlement(
        &mut self,
        declaration_id: &str,
        reason: &str,
    ) -> Result<TargetSettlementState, String> {
        self.store_mut()
            .admit_materialized::<TargetSettlementState>(
                &settlement_scope(declaration_id),
                &format!("abandon:{}", digest(reason)),
                TargetSettlementCommand::AbandonPartial {
                    reason: reason.to_owned(),
                },
            )
            .map(|admission| admission.state)
            .map_err(|error| format!("{error:?}"))
    }

    pub(crate) fn cancel_target_settlement(
        &mut self,
        declaration_id: &str,
        reason: &str,
    ) -> Result<TargetSettlementState, String> {
        let scope = settlement_scope(declaration_id);
        let state = self
            .store_ref()
            .fold::<TargetSettlementState>(&scope)
            .map_err(|error| format!("{error:?}"))?;
        let declaration = state
            .declaration
            .clone()
            .ok_or_else(|| "settlement declaration is absent".to_owned())?;
        let cancellation_ref = format!("cancellation:{}", digest(reason));
        let command = if state.started_effects == 0 {
            TargetSettlementCommand::CancelBeforeEffects {
                reason: reason.to_owned(),
            }
        } else {
            TargetSettlementCommand::CancelUnstarted {
                reason: reason.to_owned(),
            }
        };
        // The coordinator is the cancellation authority. Validate its entire
        // transition before mutating any independently durable target lane.
        decide(&state, command.clone()).map_err(|error| error.reason.to_owned())?;
        for member in &declaration.members {
            if !matches!(
                state.members[&member.member_id].phase,
                SettlementMemberPhase::Pending | SettlementMemberPhase::PreflightPassed
            ) {
                continue;
            }
            let member_ref = format!("{scope}#{}#attempt:1", member.member_id);
            let lane_id = lane_scope(&member.target_id);
            let lane = self
                .store_ref()
                .fold::<TargetSettlementLaneState>(&lane_id)
                .map_err(|error| format!("{error:?}"))?;
            if lane.queue.iter().any(|entry| {
                entry.member.member_ref() == member_ref
                    && entry.phase
                        == gaugedesk_core::target_settlement::TargetLaneEntryPhase::Queued
            }) {
                self.store_mut()
                    .admit_materialized::<TargetSettlementLaneState>(
                        &lane_id,
                        &format!("cancel:{}", member.operation_id),
                        TargetSettlementLaneCommand::CancelQueued {
                            member_ref,
                            cancellation_ref: cancellation_ref.clone(),
                        },
                    )
                    .map_err(|error| format!("{error:?}"))?;
            }
        }
        self.store_mut()
            .admit_materialized::<TargetSettlementState>(
                &scope,
                &format!("cancel:{cancellation_ref}"),
                command,
            )
            .map(|admission| admission.state)
            .map_err(|error| format!("{error:?}"))
    }

    pub(crate) fn supersede_settlement_member(
        &mut self,
        earlier_declaration_id: &str,
        earlier_member_id: &str,
        later_declaration_id: &str,
        later_member_id: &str,
    ) -> Result<TargetSettlementState, String> {
        let earlier_scope = settlement_scope(earlier_declaration_id);
        let later_scope = settlement_scope(later_declaration_id);
        let earlier_state = self
            .store_ref()
            .fold::<TargetSettlementState>(&earlier_scope)
            .map_err(|error| format!("{error:?}"))?;
        let later_state = self
            .store_ref()
            .fold::<TargetSettlementState>(&later_scope)
            .map_err(|error| format!("{error:?}"))?;
        let earlier = earlier_state
            .declaration
            .as_ref()
            .and_then(|declaration| {
                declaration
                    .members
                    .iter()
                    .find(|member| member.member_id == earlier_member_id)
            })
            .cloned()
            .ok_or_else(|| "earlier settlement member is unavailable".to_owned())?;
        let later = later_state
            .declaration
            .as_ref()
            .and_then(|declaration| {
                declaration
                    .members
                    .iter()
                    .find(|member| member.member_id == later_member_id)
            })
            .cloned()
            .ok_or_else(|| "later settlement member is unavailable".to_owned())?;
        let earlier_declaration = earlier_state
            .declaration
            .as_ref()
            .expect("member resolution requires a declaration");
        let later_declaration = later_state
            .declaration
            .as_ref()
            .expect("member resolution requires a declaration");
        if earlier.target_id != later.target_id
            || later_state.members[later_member_id].phase != SettlementMemberPhase::PreflightPassed
        {
            return Err(
                "later member must have exact preflight for the same stable target".to_owned(),
            );
        }
        if earlier_declaration.project_id != later_declaration.project_id
            || earlier_declaration.declaration_id == later_declaration.declaration_id
        {
            return Err("supersession declarations must be distinct and project-scoped".to_owned());
        }
        let earlier_manifest_ref = earlier_declaration
            .promotion_manifest_ref
            .as_deref()
            .ok_or_else(|| "earlier settlement has no promoted project cut".to_owned())?;
        let later_manifest_ref = later_declaration
            .promotion_manifest_ref
            .as_deref()
            .ok_or_else(|| "later settlement has no promoted project cut".to_owned())?;
        self.settlement_source(earlier_declaration)?;
        self.settlement_source(later_declaration)?;
        let earlier_manifest = self.workstream_promotion_manifest(
            &earlier_declaration.chat_id,
            Some(earlier_manifest_ref),
        )?;
        let later_manifest = self
            .workstream_promotion_manifest(&later_declaration.chat_id, Some(later_manifest_ref))?;
        if earlier_manifest.project_id != earlier_declaration.project_id
            || later_manifest.project_id != later_declaration.project_id
            || earlier_manifest.workspace_id != later_manifest.workspace_id
            || earlier_manifest.proposed_main_cut == later_manifest.proposed_main_cut
        {
            return Err("supersession requires distinct cuts in one project workspace".to_owned());
        }
        let workspace = self
            .collaboration_workspaces
            .get(&earlier_manifest.workspace_id)
            .ok_or_else(|| "project collaboration workspace is unavailable".to_owned())?;
        let current_main_cut = workspace
            .current_main_cut()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "project collaboration Main has no durable cut".to_owned())?;
        let later_contains_earlier = workspace
            .cut_descends_from(
                &later_manifest.proposed_main_cut,
                &earlier_manifest.proposed_main_cut,
            )
            .map_err(|error| error.to_string())?;
        let main_contains_later = workspace
            .cut_descends_from(&current_main_cut, &later_manifest.proposed_main_cut)
            .map_err(|error| error.to_string())?;
        if !later_contains_earlier || !main_contains_later {
            return Err(
                "later settlement is not proven cumulative by promoted Main-cut ancestry"
                    .to_owned(),
            );
        }
        let earlier_ref = format!("{earlier_scope}#{earlier_member_id}#attempt:1");
        let later_ref = format!("{later_scope}#{later_member_id}#attempt:1");
        let preflight_ref = later_state.members[later_member_id]
            .preflight_evidence
            .as_ref()
            .map(|evidence| evidence.governance_decision_ref.clone())
            .ok_or_else(|| "later member has no exact preflight evidence".to_owned())?;
        let lane_id = lane_scope(&earlier.target_id);
        let lane_command = TargetSettlementLaneCommand::SupersedeQueued {
            earlier_member_ref: earlier_ref,
            later_member_ref: later_ref.clone(),
            preflight_ref,
        };
        let coordinator_command = TargetSettlementCommand::SupersedeNotStarted {
            member_id: earlier_member_id.to_owned(),
            later_member_ref: later_ref,
        };
        let lane_state = self
            .store_ref()
            .fold::<TargetSettlementLaneState>(&lane_id)
            .map_err(|error| format!("{error:?}"))?;
        decide_target_lane(&lane_state, lane_command.clone())
            .map_err(|error| error.reason.to_owned())?;
        decide(&earlier_state, coordinator_command.clone())
            .map_err(|error| error.reason.to_owned())?;
        self.store_mut()
            .admit_materialized::<TargetSettlementLaneState>(
                &lane_id,
                &format!(
                    "supersede:{}:by:{}",
                    earlier.operation_id, later.operation_id
                ),
                lane_command,
            )
            .map_err(|error| format!("{error:?}"))?;
        self.store_mut()
            .admit_materialized::<TargetSettlementState>(
                &earlier_scope,
                &format!("supersede:{}", earlier.operation_id),
                coordinator_command,
            )
            .map(|admission| admission.state)
            .map_err(|error| format!("{error:?}"))
    }
}

/// Whether a settlement's project is mid-move, when writes to it are refused
/// (DR-0201 §3). An unreadable settlement is left to its own refusal.
fn settlement_paused(workbench: &Workbench, declaration_id: &str) -> bool {
    workbench
        .store_ref()
        .fold::<TargetSettlementState>(&settlement_scope(declaration_id))
        .ok()
        .and_then(|state| state.declaration)
        .is_some_and(|declaration| workbench.project_moving(&declaration.project_id))
}

pub async fn create_target_settlement(
    State(workbench): State<crate::SharedWorkbench>,
    Path(chat_id): Path<String>,
    Json(body): Json<CreateTargetSettlementBody>,
) -> impl IntoResponse {
    let mut workbench = workbench.lock_unpoisoned();
    if !workbench.library.chats.contains_key(&chat_id) {
        return (StatusCode::NOT_FOUND, "no such chat").into_response();
    }
    if workbench.chat_project_moving(&chat_id) {
        return (StatusCode::CONFLICT, crate::federation::PAUSED_FOR_MOVE).into_response();
    }
    let requested = body
        .members
        .into_iter()
        .map(|member| RequestedSettlementMember {
            target_id: member.target_id,
            act: member.act,
        })
        .collect();
    let source_change_set_ref = match body.source_change_set_ref.or_else(|| {
        workbench
            .store_ref()
            .records(
                &chat_id,
                crate::target_change_set::TARGET_CHANGE_SET_DECLARATION_KIND,
            )
            .ok()?
            .into_iter()
            .last()
            .and_then(|body| {
                serde_json::from_str::<crate::target_change_set::TargetChangeSetDeclaration>(&body)
                    .ok()
                    .map(|declaration| declaration.id)
            })
    }) {
        Some(reference) => reference,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "chat has no immutable target change-set declaration to settle",
            )
                .into_response()
        }
    };
    let state = match workbench.create_target_settlement(
        &chat_id,
        &source_change_set_ref,
        body.promotion_manifest_ref,
        requested,
    ) {
        Ok(state) => state,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let declaration_id = state
        .declaration
        .as_ref()
        .map(|declaration| declaration.declaration_id.clone())
        .expect("declaration admission returns its identity");
    match workbench.preflight_target_settlement(&declaration_id) {
        Ok(state) => (StatusCode::CREATED, Json(state)).into_response(),
        Err(error) => (StatusCode::CONFLICT, error).into_response(),
    }
}

pub async fn get_target_settlement(
    State(workbench): State<crate::SharedWorkbench>,
    Path(declaration_id): Path<String>,
) -> impl IntoResponse {
    let workbench = workbench.lock_unpoisoned();
    match workbench
        .store_ref()
        .fold::<TargetSettlementState>(&settlement_scope(&declaration_id))
    {
        Ok(state) if state.declaration.is_some() => Json(state).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, "no such settlement").into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:?}")).into_response(),
    }
}

pub async fn execute_target_settlement_member(
    State(workbench): State<crate::SharedWorkbench>,
    Path((declaration_id, member_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut workbench = workbench.lock_unpoisoned();
    match workbench.execute_settlement_member(&declaration_id, &member_id) {
        Ok(state) => {
            let status = match state.members.get(&member_id).map(|member| member.phase) {
                Some(SettlementMemberPhase::Succeeded) => StatusCode::OK,
                Some(SettlementMemberPhase::Failed) => StatusCode::CONFLICT,
                Some(SettlementMemberPhase::Unknown) => StatusCode::ACCEPTED,
                _ => StatusCode::CONFLICT,
            };
            (status, Json(state)).into_response()
        }
        Err(error) => (StatusCode::CONFLICT, error).into_response(),
    }
}

pub async fn query_target_settlement_member(
    State(workbench): State<crate::SharedWorkbench>,
    Path((declaration_id, member_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut workbench = workbench.lock_unpoisoned();
    match workbench.query_settlement_member(&declaration_id, &member_id) {
        Ok(Some(state)) => (StatusCode::OK, Json(state)).into_response(),
        Ok(None) => (
            StatusCode::CONFLICT,
            "authoritative target state proves neither success nor no-effect failure",
        )
            .into_response(),
        Err(error) => (StatusCode::CONFLICT, error).into_response(),
    }
}

pub async fn retry_target_settlement_member(
    State(workbench): State<crate::SharedWorkbench>,
    Path((declaration_id, member_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut workbench = workbench.lock_unpoisoned();
    match workbench.retry_settlement_member_effect(&declaration_id, &member_id) {
        Ok(state) => {
            let status = match state.members.get(&member_id).map(|member| member.phase) {
                Some(SettlementMemberPhase::Succeeded) => StatusCode::OK,
                Some(SettlementMemberPhase::Failed) => StatusCode::CONFLICT,
                Some(SettlementMemberPhase::Unknown) => StatusCode::ACCEPTED,
                _ => StatusCode::CONFLICT,
            };
            (status, Json(state)).into_response()
        }
        Err(error) => (StatusCode::CONFLICT, error).into_response(),
    }
}

pub async fn compensate_target_settlement(
    State(workbench): State<crate::SharedWorkbench>,
    Path(declaration_id): Path<String>,
    Json(body): Json<CompensateTargetSettlementBody>,
) -> impl IntoResponse {
    let mut workbench = workbench.lock_unpoisoned();
    if settlement_paused(&workbench, &declaration_id) {
        return (StatusCode::CONFLICT, crate::federation::PAUSED_FOR_MOVE).into_response();
    }
    match workbench.compensate_target_settlement(&declaration_id, body.receipt_links) {
        Ok(state) => (StatusCode::OK, Json(state)).into_response(),
        Err(error) => (StatusCode::CONFLICT, error).into_response(),
    }
}

pub async fn abandon_target_settlement(
    State(workbench): State<crate::SharedWorkbench>,
    Path(declaration_id): Path<String>,
    Json(body): Json<AbandonTargetSettlementBody>,
) -> impl IntoResponse {
    let mut workbench = workbench.lock_unpoisoned();
    if settlement_paused(&workbench, &declaration_id) {
        return (StatusCode::CONFLICT, crate::federation::PAUSED_FOR_MOVE).into_response();
    }
    match workbench.abandon_target_settlement(&declaration_id, &body.reason) {
        Ok(state) => (StatusCode::OK, Json(state)).into_response(),
        Err(error) => (StatusCode::CONFLICT, error).into_response(),
    }
}

pub async fn cancel_target_settlement(
    State(workbench): State<crate::SharedWorkbench>,
    Path(declaration_id): Path<String>,
    Json(body): Json<CancelTargetSettlementBody>,
) -> impl IntoResponse {
    let mut workbench = workbench.lock_unpoisoned();
    if settlement_paused(&workbench, &declaration_id) {
        return (StatusCode::CONFLICT, crate::federation::PAUSED_FOR_MOVE).into_response();
    }
    match workbench.cancel_target_settlement(&declaration_id, &body.reason) {
        Ok(state) => (StatusCode::OK, Json(state)).into_response(),
        Err(error) => (StatusCode::CONFLICT, error).into_response(),
    }
}

pub async fn supersede_target_settlement_member(
    State(workbench): State<crate::SharedWorkbench>,
    Path((declaration_id, member_id)): Path<(String, String)>,
    Json(body): Json<SupersedeTargetSettlementMemberBody>,
) -> impl IntoResponse {
    let mut workbench = workbench.lock_unpoisoned();
    if settlement_paused(&workbench, &declaration_id) {
        return (StatusCode::CONFLICT, crate::federation::PAUSED_FOR_MOVE).into_response();
    }
    match workbench.supersede_settlement_member(
        &declaration_id,
        &member_id,
        &body.later_declaration_id,
        &body.later_member_id,
    ) {
        Ok(state) => (StatusCode::OK, Json(state)).into_response(),
        Err(error) => (StatusCode::CONFLICT, error).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_workbench, LockUnpoisoned, DEFAULT_PLACEMENT};
    use gaugedesk_core::target_settlement::{
        AuthenticatedTargetReceipt, ReceiptOutcome, SettlementPhase,
    };

    fn seed_change_set(
        workbench: &mut Workbench,
        chat_id: &str,
        suffix: &str,
    ) -> (TargetChangeSetDeclaration, String) {
        let target_id =
            workbench.library.placement_targets[DEFAULT_PLACEMENT].target_ids[0].clone();
        let target = workbench.library.work_targets[&target_id].clone();
        let project_id = match &target.owner {
            crate::library::WorkTargetOwner::Project { project_id } => project_id.clone(),
            crate::library::WorkTargetOwner::Archetype { .. } => panic!("project target"),
        };
        let encoded = crate::library::target_id_path_v1(&target_id).expect("encoded target id");
        let candidate_path = format!("targets/{encoded}/file.txt");
        let candidate_body = format!("candidate:{suffix}").into_bytes();
        let engagement = &workbench.engagements[chat_id];
        engagement
            .write_file_bytes(&candidate_path, &candidate_body)
            .expect("write candidate");
        let candidate_cut = engagement
            .commit_turn("seed settlement candidate")
            .expect("commit candidate")
            .expect("candidate cut")
            .0;
        let candidate_workspace_id = workbench.engagement_index[chat_id].clone();
        let candidate_line_ref = engagement.branch().to_owned();
        let candidate_digest = snapshot_digest(&[("file.txt".into(), Some(candidate_body))]);
        let declaration = TargetChangeSetDeclaration {
            schema: "gaugedesk.target-change-set.v1".into(),
            id: format!("target-change-set:{suffix}"),
            chat_id: chat_id.into(),
            run_ref: format!("{chat_id}:{suffix}"),
            project_id,
            placement_id: DEFAULT_PLACEMENT.into(),
            package_version_ref: "package:test".into(),
            target_set_revision: 1,
            turn_process_declaration_id: format!("turn-process:{suffix}"),
            candidate_snapshots: vec![TargetCandidateSnapshot {
                target_id: target_id.clone(),
                native_basis: target.current_basis.expect("basis"),
                candidate_workspace_id,
                candidate_line_ref,
                candidate_identity: format!("candidate-cut:{suffix}"),
                candidate_cut,
                candidate_digest,
                path_scope: vec![".".into()],
                adapter_family: target.adapter_family,
                changed_paths: vec!["file.txt".into()],
                checks: vec!["tests=held".into()],
                policy_decision_handles: vec![format!("policy:{suffix}")],
            }],
            requested_acts: Vec::new(),
        };
        workbench
            .store_mut()
            .append_record(
                chat_id,
                TARGET_CHANGE_SET_DECLARATION_KIND,
                &serde_json::to_string(&declaration).expect("declaration"),
            )
            .expect("record declaration");
        (declaration, target_id)
    }

    fn receipt(member: &SettlementMemberDeclaration, suffix: &str) -> AuthenticatedTargetReceipt {
        AuthenticatedTargetReceipt {
            receipt_ref: format!("receipt:{suffix}"),
            member_id: member.member_id.clone(),
            target_id: member.target_id.clone(),
            operation_id: member.operation_id.clone(),
            expected_basis: member.expected_basis.clone(),
            resulting_basis: Some(format!("resulting-basis:{suffix}")),
            resulting_digest: Some(member.expected_result_digest.clone()),
            outcome: ReceiptOutcome::Succeeded,
            authority_ref: format!("authority:{}", member.target_id),
            authentication_ref: format!("signature:{suffix}"),
            failure_reason: None,
        }
    }

    fn failed_receipt(
        member: &SettlementMemberDeclaration,
        suffix: &str,
    ) -> AuthenticatedTargetReceipt {
        AuthenticatedTargetReceipt {
            receipt_ref: format!("receipt:{suffix}"),
            member_id: member.member_id.clone(),
            target_id: member.target_id.clone(),
            operation_id: member.operation_id.clone(),
            expected_basis: member.expected_basis.clone(),
            resulting_basis: None,
            resulting_digest: None,
            outcome: ReceiptOutcome::Failed,
            authority_ref: format!("authority:{}", member.target_id),
            authentication_ref: format!("signature:{suffix}"),
            failure_reason: Some("provider proved no effect".into()),
        }
    }

    fn admit_settlement(
        workbench: &mut Workbench,
        declaration_id: &str,
        key: &str,
        command: TargetSettlementCommand,
    ) -> TargetSettlementState {
        workbench
            .store_mut()
            .admit_materialized::<TargetSettlementState>(
                &settlement_scope(declaration_id),
                key,
                command,
            )
            .expect("settlement command")
            .state
    }

    fn test_member(id: &str, target_id: &str, expected_basis: &str) -> SettlementMemberDeclaration {
        SettlementMemberDeclaration {
            member_id: format!("member:{id}"),
            target_id: target_id.to_owned(),
            operation_id: format!("operation:{id}"),
            expected_basis: expected_basis.to_owned(),
            candidate_digest: format!("candidate:{id}"),
            expected_result_digest: format!("result:{id}"),
            policy_decision_handle: format!("policy:{id}"),
            adapter: "managed:whipplescript-v1".into(),
            act: SettlementAct::Apply,
            retry_safe_after_failure: true,
            authoritative_query: true,
        }
    }

    fn test_preflight(member: &SettlementMemberDeclaration) -> MemberPreflightEvidence {
        MemberPreflightEvidence {
            member_id: member.member_id.clone(),
            observed_basis: member.expected_basis.clone(),
            observed_candidate_digest: member.candidate_digest.clone(),
            adapter_contract_ref: "whipplescript-target-receipt/v1".into(),
            governance_decision_ref: member.policy_decision_handle.clone(),
            admitted: true,
            refusal_reason: None,
        }
    }

    fn test_permit(member: &SettlementMemberDeclaration, sequence: u64) -> TargetLanePermit {
        TargetLanePermit {
            lane_id: format!("lane:{}", member.target_id),
            target_id: member.target_id.clone(),
            member_id: member.member_id.clone(),
            operation_id: member.operation_id.clone(),
            sequence,
            authority_position: format!("position:{sequence}"),
        }
    }

    #[test]
    fn shell_preflights_before_lane_start_and_settles_from_exact_receipt() {
        let root = tempfile::tempdir().expect("root");
        let workbench = open_workbench(root.path()).expect("workbench");
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, "settlement")
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id");
        let (source, target_id) = seed_change_set(&mut workbench, chat_id, "one");
        let declared = workbench
            .create_target_settlement(
                chat_id,
                &source.id,
                None,
                vec![RequestedSettlementMember {
                    target_id,
                    act: TargetActKind::Apply,
                }],
            )
            .expect("declare");
        let declaration_id = declared
            .declaration
            .as_ref()
            .unwrap()
            .declaration_id
            .clone();
        let ready = workbench
            .preflight_target_settlement(&declaration_id)
            .expect("preflight");
        assert_eq!(ready.phase, SettlementPhase::Ready);
        let member = ready.declaration.as_ref().unwrap().members[0].clone();
        workbench
            .start_settlement_member(&declaration_id, &member.member_id)
            .expect("lane permit");
        let completed = workbench
            .record_settlement_receipt(&declaration_id, receipt(&member, "one"))
            .expect("receipt");
        assert_eq!(completed.phase, SettlementPhase::Completed);
        let pinned = workbench
            .turn_fork_snapshot(chat_id, Some(7), Some("signed-policy"), None)
            .expect("fork vector")
            .expect("work chat vector");
        assert_eq!(pinned.visible_settlement_handles, vec!["receipt:one"]);
        assert_eq!(pinned.visible_settlements.len(), 1);
        assert_eq!(
            pinned.visible_settlements[0].settlement_scope,
            settlement_scope(&declaration_id)
        );
        assert!(pinned.visible_settlements[0].position >= 0);
        assert_eq!(
            pinned.visible_settlements[0].receipt_handles,
            vec!["receipt:one"]
        );
        assert!(!serde_json::to_string(&pinned.visible_settlement_handles)
            .unwrap()
            .contains(&declaration_id));

        let (later_source, later_target_id) = seed_change_set(&mut workbench, chat_id, "later");
        let later = workbench
            .create_target_settlement(
                chat_id,
                &later_source.id,
                None,
                vec![RequestedSettlementMember {
                    target_id: later_target_id,
                    act: TargetActKind::Apply,
                }],
            )
            .expect("later declaration");
        let later_id = later.declaration.unwrap().declaration_id;
        let later_ready = workbench
            .preflight_target_settlement(&later_id)
            .expect("later preflight");
        let later_member = later_ready.declaration.unwrap().members[0].clone();
        workbench
            .start_settlement_member(&later_id, &later_member.member_id)
            .expect("later permit");
        workbench
            .record_settlement_receipt(&later_id, receipt(&later_member, "later"))
            .expect("later receipt");
        assert_eq!(
            pinned.visible_settlement_handles,
            vec!["receipt:one"],
            "a previously captured fork point does not gain later settlement evidence"
        );
        assert_eq!(
            workbench
                .visible_target_settlement_handles(chat_id)
                .expect("current evidence"),
            vec!["receipt:later", "receipt:one"]
        );
    }

    #[test]
    fn stale_all_member_preflight_enqueues_no_effect() {
        let root = tempfile::tempdir().expect("root");
        let workbench = open_workbench(root.path()).expect("workbench");
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, "stale settlement")
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id");
        let (source, target_id) = seed_change_set(&mut workbench, chat_id, "stale");
        let declared = workbench
            .create_target_settlement(
                chat_id,
                &source.id,
                None,
                vec![RequestedSettlementMember {
                    target_id: target_id.clone(),
                    act: TargetActKind::Apply,
                }],
            )
            .expect("declare");
        workbench
            .library
            .work_targets
            .get_mut(&target_id)
            .expect("target")
            .current_basis = Some("basis:moved".into());
        let declaration_id = declared
            .declaration
            .as_ref()
            .unwrap()
            .declaration_id
            .clone();
        let refused = workbench
            .preflight_target_settlement(&declaration_id)
            .expect("refusal is durable");
        assert_eq!(refused.phase, SettlementPhase::Refused);
        let lane = workbench
            .store_ref()
            .fold::<TargetSettlementLaneState>(&lane_scope(&target_id))
            .expect("lane");
        assert!(lane.queue.is_empty());
    }

    #[test]
    fn unknown_shell_path_queries_before_releasing_the_lane() {
        let root = tempfile::tempdir().expect("root");
        let workbench = open_workbench(root.path()).expect("workbench");
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, "unknown settlement")
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id");
        let (source, target_id) = seed_change_set(&mut workbench, chat_id, "unknown");
        let declared = workbench
            .create_target_settlement(
                chat_id,
                &source.id,
                None,
                vec![RequestedSettlementMember {
                    target_id,
                    act: TargetActKind::Apply,
                }],
            )
            .expect("declare");
        let declaration_id = declared
            .declaration
            .as_ref()
            .unwrap()
            .declaration_id
            .clone();
        let ready = workbench
            .preflight_target_settlement(&declaration_id)
            .expect("preflight");
        let member = ready.declaration.as_ref().unwrap().members[0].clone();
        workbench
            .start_settlement_member(&declaration_id, &member.member_id)
            .expect("start");
        let unknown = workbench
            .record_settlement_unknown(&declaration_id, &member.member_id, "timeout:provider")
            .expect("unknown");
        assert_eq!(unknown.phase, SettlementPhase::ReconciliationRequired);
        assert!(workbench
            .record_settlement_receipt(&declaration_id, receipt(&member, "blind-retry"))
            .is_err());
        workbench
            .request_settlement_query(&declaration_id, &member.member_id, "query:provider:one")
            .expect("query");
        let completed = workbench
            .record_settlement_query_receipt(&declaration_id, receipt(&member, "queried"))
            .expect("query receipt");
        assert_eq!(completed.phase, SettlementPhase::Completed);
    }

    #[test]
    fn known_no_effect_failure_can_retry_with_a_new_lane_attempt() {
        let root = tempfile::tempdir().expect("root");
        let workbench = open_workbench(root.path()).expect("workbench");
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, "retry settlement")
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id");
        let (source, target_id) = seed_change_set(&mut workbench, chat_id, "retry");
        let declared = workbench
            .create_target_settlement(
                chat_id,
                &source.id,
                None,
                vec![RequestedSettlementMember {
                    target_id,
                    act: TargetActKind::Apply,
                }],
            )
            .expect("declare");
        let declaration_id = declared
            .declaration
            .as_ref()
            .unwrap()
            .declaration_id
            .clone();
        let ready = workbench
            .preflight_target_settlement(&declaration_id)
            .expect("preflight");
        let member = ready.declaration.as_ref().unwrap().members[0].clone();
        let first = workbench
            .start_settlement_member(&declaration_id, &member.member_id)
            .expect("first permit");
        workbench
            .record_settlement_receipt(&declaration_id, failed_receipt(&member, "known-failure"))
            .expect("known failure");
        let second = workbench
            .retry_failed_settlement_member(&declaration_id, &member.member_id)
            .expect("retry permit");
        assert!(second.sequence > first.sequence);
        let completed = workbench
            .record_settlement_receipt(&declaration_id, receipt(&member, "retry-success"))
            .expect("success");
        assert_eq!(completed.phase, SettlementPhase::Completed);
    }

    #[test]
    fn admitted_apply_materializes_the_exact_historical_candidate_in_the_target() {
        let root = tempfile::tempdir().expect("root");
        let workbench = open_workbench(root.path()).expect("workbench");
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, "execute settlement")
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id");
        let (source, target_id) = seed_change_set(&mut workbench, chat_id, "exact-effect");
        let declared = workbench
            .create_target_settlement(
                chat_id,
                &source.id,
                None,
                vec![RequestedSettlementMember {
                    target_id: target_id.clone(),
                    act: TargetActKind::Apply,
                }],
            )
            .expect("declare");
        let declaration_id = declared.declaration.unwrap().declaration_id;
        let ready = workbench
            .preflight_target_settlement(&declaration_id)
            .expect("preflight");
        let member_id = ready.declaration.unwrap().members[0].member_id.clone();
        let completed = workbench
            .execute_settlement_member(&declaration_id, &member_id)
            .expect("execute");
        assert_eq!(completed.phase, SettlementPhase::Completed);

        let workspace = &workbench.targets[&target_id];
        let probe_id = crate::library::gen_id("settlement-probe");
        let probe = workspace
            .create_engagement(&probe_id)
            .expect("target probe");
        assert_eq!(
            probe.read_file("file.txt").expect("settled file"),
            "candidate:exact-effect"
        );
        drop(probe);
        workspace
            .remove_engagement(&probe_id)
            .expect("remove probe");
    }

    fn ready_settlement(workbench: &mut Workbench, suffix: &str) -> TargetSettlementDeclaration {
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, suffix)
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id");
        let (source, target_id) = seed_change_set(workbench, chat_id, suffix);
        let declared = workbench
            .create_target_settlement(
                chat_id,
                &source.id,
                None,
                vec![RequestedSettlementMember {
                    target_id,
                    act: TargetActKind::Apply,
                }],
            )
            .expect("declare");
        let declaration = declared.declaration.expect("declaration");
        workbench
            .preflight_target_settlement(&declaration.declaration_id)
            .expect("preflight");
        declaration
    }

    #[test]
    fn actual_settlement_receipt_binds_project_and_reopens_without_private_custody() {
        let root = tempfile::tempdir().expect("root");
        let wb = open_workbench(root.path()).expect("workbench");
        let (project, receipt, public) = {
            let mut wb = wb.lock_unpoisoned();
            let declaration = ready_settlement(&mut wb, "project-receipt");
            let member = &declaration.members[0];
            let state = wb
                .execute_settlement_member(&declaration.declaration_id, &member.member_id)
                .expect("effect");
            let receipt = state.members[&member.member_id]
                .receipt
                .clone()
                .expect("actual receipt");
            let project = declaration.project_id;
            let public = wb.project_signing_key(&project).unwrap().public_key();
            assert_ne!(public, wb.governance_public_key());
            assert!(receipt
                .authentication_ref
                .starts_with(PROJECT_RECEIPT_PREFIX));
            let host = wb.governance_public_key();
            verify_target_receipt_authentication(wb.store_ref(), &receipt, &project, Some(&host))
                .unwrap();
            assert!(verify_target_receipt_authentication(
                wb.store_ref(),
                &receipt,
                "foreign-project",
                Some(&host)
            )
            .is_err());

            let frame: ProjectReceiptAuthentication = serde_json::from_str(
                receipt
                    .authentication_ref
                    .strip_prefix(PROJECT_RECEIPT_PREFIX)
                    .unwrap(),
            )
            .unwrap();
            let payload = project_receipt_payload(&receipt, &project, &frame.authority).unwrap();
            let signature = Signature::new(hex::decode(&frame.signature).unwrap());
            assert_eq!(verify_signature(&payload, &signature, &public), Ok(true));
            assert_ne!(verify_signature(&payload, &signature, &host), Ok(true));

            for field in ["project", "authority", "signature", "extra"] {
                let mut encoded = serde_json::to_value(&frame).unwrap();
                encoded[field] = "foreign".into();
                let mut changed = receipt.clone();
                changed.authentication_ref = format!("{PROJECT_RECEIPT_PREFIX}{encoded}");
                assert!(
                    verify_target_receipt_authentication(
                        wb.store_ref(),
                        &changed,
                        &project,
                        Some(&host)
                    )
                    .is_err(),
                    "{field}"
                );
            }
            let mut changed = receipt.clone();
            changed.resulting_digest = Some("sha256:other-body".into());
            assert!(verify_target_receipt_authentication(
                wb.store_ref(),
                &changed,
                &project,
                Some(&host)
            )
            .is_err());
            let mut changed = receipt.clone();
            changed.receipt_ref = "target-receipt:invented".into();
            assert!(verify_target_receipt_authentication(
                wb.store_ref(),
                &changed,
                &project,
                Some(&host)
            )
            .is_err());

            // A host-signed body under a project-shaped envelope is not a project act.
            let mut changed = receipt.clone();
            let mut frame = frame;
            let host_key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
            frame.signature = hex::encode(host_key.sign(&payload).as_bytes());
            changed.authentication_ref = format!(
                "{PROJECT_RECEIPT_PREFIX}{}",
                serde_json::to_string(&frame).unwrap()
            );
            assert!(verify_target_receipt_authentication(
                wb.store_ref(),
                &changed,
                &project,
                Some(&host)
            )
            .is_err());
            (project, receipt, public)
        };
        drop(wb);
        let reopened = open_workbench(root.path()).expect("reopen before custody loss");
        {
            let wb = reopened.lock_unpoisoned();
            let host = wb.governance_public_key();
            verify_target_receipt_authentication(wb.store_ref(), &receipt, &project, Some(&host))
                .unwrap();
            assert_eq!(
                wb.project_signing_key(&project).unwrap().public_key(),
                public
            );
        }
        drop(reopened);
        let custody = root
            .path()
            .join("content-keys/projects")
            .join(format!("{}.key", crate::org::sha256_hex(&project)));
        std::fs::remove_file(&custody).expect("remove project private custody");
        // The public reader needs only retained registration, even with a different host key.
        let store =
            gaugedesk_store::Store::open(root.path().join("gaugewright.db").to_str().unwrap())
                .expect("public registry reader");
        let foreign_host = SigningKey::from_seed(&[73; 32]).unwrap().public_key();
        verify_target_receipt_authentication(&store, &receipt, &project, None).unwrap();
        let before = serde_json::to_string(&receipt).unwrap();
        verify_target_receipt_authentication(&store, &receipt, &project, Some(&foreign_host))
            .unwrap();
        assert_eq!(serde_json::to_string(&receipt).unwrap(), before);
        assert!(!custody.exists());
        let mut incoming = store.project_authority_key(&project).unwrap().unwrap();
        incoming.custody = "incoming-project-v1".into();
        let mut staged = gaugedesk_store::Store::open_in_memory().unwrap();
        staged.retain_project_authority_key(&incoming).unwrap();
        assert!(
            verify_target_receipt_authentication(&staged, &receipt, &project, Some(&foreign_host))
                .is_err(),
            "staging is not receiving admission"
        );
    }

    #[test]
    fn legacy_receipt_keeps_original_identity_and_never_trusts_its_supplied_root() {
        let root = tempfile::tempdir().expect("root");
        let wb = open_workbench(root.path()).expect("workbench");
        let mut wb = wb.lock_unpoisoned();
        let declaration = ready_settlement(&mut wb, "legacy-receipt");
        let member = &declaration.members[0];
        let mut legacy = receipt(member, "legacy");
        legacy.authority_ref = wb.library.work_targets[&member.target_id].authority.clone();
        let payload = target_receipt_payload(&legacy).unwrap();
        let old = SigningKey::from_seed(&wb.governance_seed()).unwrap();
        legacy.receipt_ref = format!("target-receipt:{}", digest(&payload));
        legacy.authentication_ref = format!(
            "p256:{}:{}",
            old.public_key().as_str(),
            hex::encode(old.sign(&payload).as_bytes())
        );
        let original = serde_json::to_string(&legacy).unwrap();
        let before = wb
            .store_ref()
            .events(&settlement_scope(&declaration.declaration_id))
            .unwrap();
        verify_target_receipt_authentication(
            wb.store_ref(),
            &legacy,
            &declaration.project_id,
            Some(&old.public_key()),
        )
        .unwrap();
        assert_eq!(serde_json::to_string(&legacy).unwrap(), original);
        assert_eq!(
            wb.store_ref()
                .events(&settlement_scope(&declaration.declaration_id))
                .unwrap(),
            before
        );
        let project_key = wb
            .project_signing_key(&declaration.project_id)
            .unwrap()
            .public_key();
        assert!(verify_target_receipt_authentication(
            wb.store_ref(),
            &legacy,
            &declaration.project_id,
            Some(&project_key)
        )
        .is_err());
        let foreign = SigningKey::from_seed(&[81; 32]).unwrap();
        let mut forged = legacy.clone();
        forged.authentication_ref = format!(
            "p256:{}:{}",
            foreign.public_key().as_str(),
            hex::encode(foreign.sign(&payload).as_bytes())
        );
        assert!(verify_target_receipt_authentication(
            wb.store_ref(),
            &forged,
            &declaration.project_id,
            Some(&old.public_key())
        )
        .is_err());
    }

    #[test]
    fn actual_legacy_effect_and_query_receipt_replay_without_reminting() {
        let root = tempfile::tempdir().expect("root");
        let wb = open_workbench(root.path()).expect("workbench");
        let mut wb = wb.lock_unpoisoned();
        let declaration = ready_settlement(&mut wb, "legacy-query-replay");
        let member = &declaration.members[0];
        let id = &declaration.declaration_id;
        let (_, files) = wb.exact_candidate_files(&declaration, member).unwrap();
        wb.start_settlement_member(id, &member.member_id).unwrap();
        let TargetEffectOutcome::Succeeded { resulting_basis } =
            wb.execute_prepared_target_effect(member, &files)
        else {
            panic!("actual effect");
        };
        wb.record_settlement_unknown(id, &member.member_id, "original:lost-receipt")
            .unwrap();
        wb.request_settlement_query(id, &member.member_id, "original:query")
            .unwrap();
        // Original producer encoding, applied to the actual recovered target effect.
        let mut legacy = receipt(member, "legacy-query");
        legacy.resulting_basis = Some(resulting_basis);
        legacy.authority_ref = wb.library.work_targets[&member.target_id].authority.clone();
        let payload = target_receipt_payload(&legacy).unwrap();
        let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
        legacy.receipt_ref = format!("target-receipt:{}", digest(&payload));
        legacy.authentication_ref = format!(
            "p256:{}:{}",
            key.public_key().as_str(),
            hex::encode(key.sign(&payload).as_bytes())
        );
        let original = wb
            .record_settlement_query_receipt(id, legacy.clone())
            .unwrap();
        assert_eq!(original.phase, SettlementPhase::Completed);
        let coordinator = wb.store_ref().events(&settlement_scope(id)).unwrap();
        let lane = wb
            .store_ref()
            .events(&lane_scope(&member.target_id))
            .unwrap();
        let target = wb.targets[&member.target_id].current_main_cut().unwrap();
        let custody = root.path().join("content-keys/projects").join(format!(
            "{}.key",
            crate::org::sha256_hex(&declaration.project_id)
        ));
        std::fs::remove_file(&custody).unwrap();
        let query = wb
            .query_settlement_member(id, &member.member_id)
            .unwrap()
            .unwrap();
        let execute = wb.execute_settlement_member(id, &member.member_id).unwrap();
        let retry = wb
            .retry_settlement_member_effect(id, &member.member_id)
            .unwrap();
        for replay in [query, execute, retry] {
            assert_eq!(
                serde_json::to_value(replay).unwrap(),
                serde_json::to_value(&original).unwrap()
            );
        }
        assert_eq!(
            wb.store_ref().events(&settlement_scope(id)).unwrap(),
            coordinator
        );
        assert_eq!(
            wb.store_ref()
                .events(&lane_scope(&member.target_id))
                .unwrap(),
            lane
        );
        assert_eq!(
            wb.targets[&member.target_id].current_main_cut().unwrap(),
            target
        );
        assert!(!custody.exists());
        // The replay path verifies the original receipt rather than trusting labels.
        let mut forged = original.clone();
        forged
            .members
            .get_mut(&member.member_id)
            .unwrap()
            .receipt
            .as_mut()
            .unwrap()
            .authentication_ref = "p256:invented:00".into();
        assert!(wb
            .known_settlement_outcome(&forged, &declaration, &member.member_id)
            .is_err());
    }

    #[test]
    fn started_effect_uses_its_held_signer_when_private_custody_disappears() {
        let root = tempfile::tempdir().expect("root");
        let wb = open_workbench(root.path()).expect("workbench");
        let mut wb = wb.lock_unpoisoned();
        let declaration = ready_settlement(&mut wb, "held-signer");
        let member = &declaration.members[0];
        let (candidate, files) = wb.exact_candidate_files(&declaration, member).unwrap();
        let signer = wb.initialize_settlement_authority(&declaration).unwrap();
        wb.start_settlement_member(&declaration.declaration_id, &member.member_id)
            .unwrap();
        let custody = root.path().join("content-keys/projects").join(format!(
            "{}.key",
            crate::org::sha256_hex(&declaration.project_id)
        ));
        std::fs::remove_file(&custody).unwrap();
        assert!(wb.project_signing_key(&declaration.project_id).is_err());
        let completed = wb
            .finish_started_settlement_member(
                &declaration.declaration_id,
                &declaration,
                member,
                candidate,
                &files,
                &signer,
            )
            .expect("finish already admitted effect");
        assert_eq!(completed.phase, SettlementPhase::Completed);
        let receipt = completed.members[&member.member_id]
            .receipt
            .as_ref()
            .unwrap();
        verify_target_receipt_authentication(
            wb.store_ref(),
            receipt,
            &declaration.project_id,
            None,
        )
        .unwrap();
        assert!(!custody.exists());
    }

    #[test]
    fn missing_project_custody_refuses_execute_retry_and_query_before_any_change() {
        for door in ["execute", "retry", "query"] {
            let root = tempfile::tempdir().expect("root");
            let wb = open_workbench(root.path()).expect("workbench");
            let mut wb = wb.lock_unpoisoned();
            let declaration = ready_settlement(&mut wb, door);
            let member = &declaration.members[0];
            let id = &declaration.declaration_id;
            if door != "execute" {
                wb.start_settlement_member(id, &member.member_id)
                    .expect("start");
                if door == "retry" {
                    let signer = wb.initialize_settlement_authority(&declaration).unwrap();
                    let failed = wb
                        .sign_target_receipt(
                            &signer,
                            member,
                            ReceiptOutcome::Failed,
                            None,
                            None,
                            Some("known no effect".into()),
                        )
                        .unwrap();
                    wb.record_settlement_receipt(id, failed)
                        .expect("failed effect");
                } else {
                    wb.record_settlement_unknown(id, &member.member_id, "lost-receipt")
                        .expect("unknown");
                }
            }
            let coordinator = wb.store_ref().events(&settlement_scope(id)).unwrap();
            let lane = wb
                .store_ref()
                .events(&lane_scope(&member.target_id))
                .unwrap();
            let target = wb.targets[&member.target_id].current_main_cut().unwrap();
            let public = wb
                .project_signing_key(&declaration.project_id)
                .unwrap()
                .public_key();
            let custody = root.path().join("content-keys/projects").join(format!(
                "{}.key",
                crate::org::sha256_hex(&declaration.project_id)
            ));
            std::fs::remove_file(&custody).expect("remove custody");
            let error = match door {
                "execute" => wb
                    .execute_settlement_member(id, &member.member_id)
                    .unwrap_err(),
                "retry" => wb
                    .retry_settlement_member_effect(id, &member.member_id)
                    .unwrap_err(),
                "query" => wb
                    .query_settlement_member(id, &member.member_id)
                    .unwrap_err(),
                _ => unreachable!(),
            };
            assert!(!error.is_empty());
            assert_eq!(
                wb.store_ref().events(&settlement_scope(id)).unwrap(),
                coordinator,
                "{door}"
            );
            assert_eq!(
                wb.store_ref()
                    .events(&lane_scope(&member.target_id))
                    .unwrap(),
                lane,
                "{door}"
            );
            assert_eq!(
                wb.targets[&member.target_id].current_main_cut().unwrap(),
                target,
                "{door}"
            );
            assert_eq!(
                wb.store_ref()
                    .project_authority_key(&declaration.project_id)
                    .unwrap()
                    .unwrap()
                    .public_key,
                public.as_str()
            );
            assert!(!custody.exists(), "{door} must not remint");
        }
    }

    #[test]
    fn ambiguous_post_effect_outcome_is_settled_only_by_the_target_query() {
        let root = tempfile::tempdir().expect("root");
        let workbench = open_workbench(root.path()).expect("workbench");
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, "query settled effect")
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id");
        let (source, target_id) = seed_change_set(&mut workbench, chat_id, "query-effect");
        let declared = workbench
            .create_target_settlement(
                chat_id,
                &source.id,
                None,
                vec![RequestedSettlementMember {
                    target_id,
                    act: TargetActKind::Apply,
                }],
            )
            .expect("declare");
        let declaration_id = declared.declaration.unwrap().declaration_id;
        let ready = workbench
            .preflight_target_settlement(&declaration_id)
            .expect("preflight");
        let declaration = ready.declaration.unwrap();
        let member = declaration.members[0].clone();
        let (_, files) = workbench
            .exact_candidate_files(&declaration, &member)
            .expect("exact candidate");
        workbench
            .start_settlement_member(&declaration_id, &member.member_id)
            .expect("start");
        assert!(matches!(
            workbench.execute_prepared_target_effect(&member, &files),
            TargetEffectOutcome::Succeeded { .. }
        ));
        let unknown = workbench
            .record_settlement_unknown(&declaration_id, &member.member_id, "injected:lost-receipt")
            .expect("unknown");
        assert_eq!(unknown.phase, SettlementPhase::ReconciliationRequired);
        let completed = workbench
            .query_settlement_member(&declaration_id, &member.member_id)
            .expect("query")
            .expect("decisive query");
        assert_eq!(completed.phase, SettlementPhase::Completed);
        let receipt = completed.members[&member.member_id]
            .receipt
            .as_ref()
            .expect("query receipt");
        verify_target_receipt_authentication(
            workbench.store_ref(),
            receipt,
            &declaration.project_id,
            Some(&workbench.governance_public_key()),
        )
        .expect("project query signature");
        assert!(receipt
            .authentication_ref
            .starts_with(PROJECT_RECEIPT_PREFIX));
    }

    #[test]
    fn invalid_cancellation_changes_neither_coordinator_nor_target_lane() {
        let root = tempfile::tempdir().expect("root");
        let workbench = open_workbench(root.path()).expect("workbench");
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, "cancel settlement")
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id");
        let (source, target_id) = seed_change_set(&mut workbench, chat_id, "cancel");
        let declared = workbench
            .create_target_settlement(
                chat_id,
                &source.id,
                None,
                vec![RequestedSettlementMember {
                    target_id: target_id.clone(),
                    act: TargetActKind::Apply,
                }],
            )
            .expect("declare");
        let declaration_id = declared.declaration.unwrap().declaration_id;
        let before_coordinator = workbench
            .preflight_target_settlement(&declaration_id)
            .expect("preflight");
        let before_lane = workbench
            .store_ref()
            .fold::<TargetSettlementLaneState>(&lane_scope(&target_id))
            .expect("lane");

        assert!(workbench
            .cancel_target_settlement(&declaration_id, "   ")
            .is_err());
        assert_eq!(
            workbench
                .store_ref()
                .fold::<TargetSettlementState>(&settlement_scope(&declaration_id))
                .expect("coordinator after refusal"),
            before_coordinator
        );
        assert_eq!(
            workbench
                .store_ref()
                .fold::<TargetSettlementLaneState>(&lane_scope(&target_id))
                .expect("lane after refusal"),
            before_lane
        );
    }

    #[test]
    fn compensation_resolves_and_authenticates_exact_forward_repair_receipts() {
        let root = tempfile::tempdir().expect("root");
        let workbench = open_workbench(root.path()).expect("workbench");
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, "compensation settlement")
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id");
        let (source, target_id) = seed_change_set(&mut workbench, chat_id, "compensation");
        let project_id = source.project_id;
        workbench
            .initialize_project_authority(&project_id)
            .expect("project authority");
        let signer = SettlementSigner {
            project: project_id.clone(),
            key: workbench.project_signing_key(&project_id).unwrap(),
        };
        let original_id = "settlement:original";
        let original_member = test_member("original", &target_id, "basis:before");
        let skipped_member = test_member("skipped", &target_id, "basis:before");
        admit_settlement(
            &mut workbench,
            original_id,
            "declare",
            TargetSettlementCommand::Declare(TargetSettlementDeclaration {
                declaration_id: original_id.into(),
                project_id: project_id.clone(),
                chat_id: chat_id.into(),
                source_change_set_ref: "change-set:original".into(),
                promotion_manifest_ref: Some("promotion:original".into()),
                members: vec![original_member.clone(), skipped_member.clone()],
            }),
        );
        admit_settlement(
            &mut workbench,
            original_id,
            "preflight",
            TargetSettlementCommand::BeginPreflight,
        );
        admit_settlement(
            &mut workbench,
            original_id,
            "preflight-original",
            TargetSettlementCommand::RecordPreflight(test_preflight(&original_member)),
        );
        admit_settlement(
            &mut workbench,
            original_id,
            "preflight-skipped",
            TargetSettlementCommand::RecordPreflight(test_preflight(&skipped_member)),
        );
        admit_settlement(
            &mut workbench,
            original_id,
            "start-original",
            TargetSettlementCommand::StartMember {
                member_id: original_member.member_id.clone(),
                lane_permit: test_permit(&original_member, 1),
            },
        );
        let original_receipt = workbench
            .sign_target_receipt(
                &signer,
                &original_member,
                ReceiptOutcome::Succeeded,
                Some("basis:after-original".into()),
                Some(original_member.expected_result_digest.clone()),
                None,
            )
            .expect("signed original receipt");
        admit_settlement(
            &mut workbench,
            original_id,
            "receipt-original",
            TargetSettlementCommand::RecordReceipt(original_receipt.clone()),
        );
        let partial = admit_settlement(
            &mut workbench,
            original_id,
            "cancel-skipped",
            TargetSettlementCommand::CancelUnstarted {
                reason: "forward repair selected".into(),
            },
        );
        assert_eq!(partial.phase, SettlementPhase::PartiallyApplied);

        let early_repair_id = "settlement:early-repair";
        let early_repair_member = test_member("early-repair", &target_id, "basis:after-original");
        admit_settlement(
            &mut workbench,
            early_repair_id,
            "declare",
            TargetSettlementCommand::Declare(TargetSettlementDeclaration {
                declaration_id: early_repair_id.into(),
                project_id: project_id.clone(),
                chat_id: chat_id.into(),
                source_change_set_ref: "change-set:early-repair".into(),
                promotion_manifest_ref: Some("promotion:early-repair".into()),
                members: vec![early_repair_member.clone()],
            }),
        );
        admit_settlement(
            &mut workbench,
            early_repair_id,
            "preflight",
            TargetSettlementCommand::BeginPreflight,
        );
        admit_settlement(
            &mut workbench,
            early_repair_id,
            "preflight-early-repair",
            TargetSettlementCommand::RecordPreflight(test_preflight(&early_repair_member)),
        );
        admit_settlement(
            &mut workbench,
            early_repair_id,
            "start-early-repair",
            TargetSettlementCommand::StartMember {
                member_id: early_repair_member.member_id.clone(),
                lane_permit: test_permit(&early_repair_member, 1),
            },
        );
        let early_repair_receipt = workbench
            .sign_target_receipt(
                &signer,
                &early_repair_member,
                ReceiptOutcome::Succeeded,
                Some("basis:early-repair".into()),
                Some(early_repair_member.expected_result_digest.clone()),
                None,
            )
            .expect("signed same-position receipt");
        admit_settlement(
            &mut workbench,
            early_repair_id,
            "receipt-early-repair",
            TargetSettlementCommand::RecordReceipt(early_repair_receipt.clone()),
        );
        assert!(workbench
            .compensate_target_settlement(
                original_id,
                vec![CompensationReceiptLink {
                    original_receipt_ref: original_receipt.receipt_ref.clone(),
                    compensation_declaration_id: early_repair_id.into(),
                    compensation_member_id: early_repair_member.member_id,
                    compensation_receipt_ref: early_repair_receipt.receipt_ref,
                }],
            )
            .is_err());

        let forged_repair_id = "settlement:forged-repair";
        let forged_repair_member = test_member("forged-repair", &target_id, "basis:after-original");
        admit_settlement(
            &mut workbench,
            forged_repair_id,
            "declare",
            TargetSettlementCommand::Declare(TargetSettlementDeclaration {
                declaration_id: forged_repair_id.into(),
                project_id: project_id.clone(),
                chat_id: chat_id.into(),
                source_change_set_ref: "change-set:forged-repair".into(),
                promotion_manifest_ref: Some("promotion:forged-repair".into()),
                members: vec![forged_repair_member.clone()],
            }),
        );
        admit_settlement(
            &mut workbench,
            forged_repair_id,
            "preflight",
            TargetSettlementCommand::BeginPreflight,
        );
        admit_settlement(
            &mut workbench,
            forged_repair_id,
            "preflight-forged-repair",
            TargetSettlementCommand::RecordPreflight(test_preflight(&forged_repair_member)),
        );
        admit_settlement(
            &mut workbench,
            forged_repair_id,
            "start-forged-repair",
            TargetSettlementCommand::StartMember {
                member_id: forged_repair_member.member_id.clone(),
                lane_permit: test_permit(&forged_repair_member, 2),
            },
        );
        let mut forged_repair_receipt = workbench
            .sign_target_receipt(
                &signer,
                &forged_repair_member,
                ReceiptOutcome::Succeeded,
                Some("basis:forged-repair".into()),
                Some(forged_repair_member.expected_result_digest.clone()),
                None,
            )
            .expect("initially valid forged receipt body");
        forged_repair_receipt.authentication_ref = "p256:invented:00".into();
        admit_settlement(
            &mut workbench,
            forged_repair_id,
            "receipt-forged-repair",
            TargetSettlementCommand::RecordReceipt(forged_repair_receipt.clone()),
        );
        assert!(workbench
            .compensate_target_settlement(
                original_id,
                vec![CompensationReceiptLink {
                    original_receipt_ref: original_receipt.receipt_ref.clone(),
                    compensation_declaration_id: forged_repair_id.into(),
                    compensation_member_id: forged_repair_member.member_id,
                    compensation_receipt_ref: forged_repair_receipt.receipt_ref,
                }],
            )
            .is_err());

        let repair_id = "settlement:repair";
        let repair_member = test_member("repair", &target_id, "basis:after-original");
        admit_settlement(
            &mut workbench,
            repair_id,
            "declare",
            TargetSettlementCommand::Declare(TargetSettlementDeclaration {
                declaration_id: repair_id.into(),
                project_id: project_id.clone(),
                chat_id: chat_id.into(),
                source_change_set_ref: "change-set:repair".into(),
                promotion_manifest_ref: Some("promotion:repair".into()),
                members: vec![repair_member.clone()],
            }),
        );
        admit_settlement(
            &mut workbench,
            repair_id,
            "preflight",
            TargetSettlementCommand::BeginPreflight,
        );
        admit_settlement(
            &mut workbench,
            repair_id,
            "preflight-repair",
            TargetSettlementCommand::RecordPreflight(test_preflight(&repair_member)),
        );
        admit_settlement(
            &mut workbench,
            repair_id,
            "start-repair",
            TargetSettlementCommand::StartMember {
                member_id: repair_member.member_id.clone(),
                lane_permit: test_permit(&repair_member, 3),
            },
        );
        let repair_receipt = workbench
            .sign_target_receipt(
                &signer,
                &repair_member,
                ReceiptOutcome::Succeeded,
                Some("basis:repaired".into()),
                Some(repair_member.expected_result_digest.clone()),
                None,
            )
            .expect("signed repair receipt");
        admit_settlement(
            &mut workbench,
            repair_id,
            "receipt-repair",
            TargetSettlementCommand::RecordReceipt(repair_receipt.clone()),
        );
        assert!(workbench
            .compensate_target_settlement(
                original_id,
                vec![CompensationReceiptLink {
                    original_receipt_ref: original_receipt.receipt_ref.clone(),
                    compensation_declaration_id: repair_id.into(),
                    compensation_member_id: repair_member.member_id.clone(),
                    compensation_receipt_ref: "receipt:invented".into(),
                }],
            )
            .is_err());
        let link = CompensationReceiptLink {
            original_receipt_ref: original_receipt.receipt_ref,
            compensation_declaration_id: repair_id.into(),
            compensation_member_id: repair_member.member_id,
            compensation_receipt_ref: repair_receipt.receipt_ref.clone(),
        };
        let compensated = workbench
            .compensate_target_settlement(original_id, vec![link.clone()])
            .expect("authenticated compensation");
        assert_eq!(compensated.phase, SettlementPhase::Compensated);
        assert_eq!(compensated.compensation_receipt_links, vec![link]);
        assert_eq!(
            compensated.compensation_receipt_refs,
            vec![repair_receipt.receipt_ref]
        );
    }

    #[test]
    fn supersession_requires_a_later_promoted_main_cut_before_lane_mutation() {
        use crate::library::{RecordOp, WorkstreamRecord};
        use crate::workstream_promotion::{
            WorkstreamPromotionManifest, WORKSTREAM_PROMOTION_MANIFEST_KIND,
        };

        let root = tempfile::tempdir().expect("root");
        let workbench = open_workbench(root.path()).expect("workbench");
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, "supersession settlement")
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id").to_owned();
        let (earlier_source, target_id) =
            seed_change_set(&mut workbench, &chat_id, "supersession-earlier");
        let (fake_source, _) = seed_change_set(&mut workbench, &chat_id, "supersession-fake");
        let (later_source, _) = seed_change_set(&mut workbench, &chat_id, "supersession-later");
        workbench.write_workstream_record(WorkstreamRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: chat_id.clone(),
            op: RecordOp::Upsert,
            instance_id: DEFAULT_PLACEMENT.to_owned(),
            name: "Supersession fixture".to_owned(),
            created_position: 0,
        });
        let fake_cut = earlier_source.candidate_snapshots[0].candidate_cut.clone();
        let project_id = earlier_source.project_id.clone();
        let workspace_id = workbench.library.project_collaboration_workspaces[&project_id]
            .workspace_id
            .clone();
        let (earlier_cut, later_cut) = {
            let workspace = &workbench.collaboration_workspaces[&workspace_id];
            workspace
                .seed_main(&[("supersession-proof/earlier", "earlier")])
                .expect("earlier Main cut");
            let earlier_cut = workspace
                .current_main_cut()
                .expect("Main authority")
                .expect("earlier cut");
            workspace
                .seed_main(&[("supersession-proof/later", "later")])
                .expect("later Main cut");
            let later_cut = workspace
                .current_main_cut()
                .expect("Main authority")
                .expect("later cut");
            (earlier_cut, later_cut)
        };
        let manifest =
            |id: &str, proposed_main_cut: String, source: &TargetChangeSetDeclaration| {
                WorkstreamPromotionManifest {
                    schema: "gaugedesk.workstream-promotion-manifest.v1".into(),
                    id: id.into(),
                    workstream_id: chat_id.clone(),
                    project_id: project_id.clone(),
                    workspace_id: workspace_id.clone(),
                    reservation_id: format!("reservation:{id}"),
                    line_branch_id: format!("line:{id}"),
                    expected_line_cut: format!("line-cut:{id}"),
                    expected_main_cut: earlier_cut.clone(),
                    proposed_main_cut,
                    partitions: source.candidate_snapshots.clone(),
                }
            };
        let earlier_manifest = manifest("manifest:earlier", earlier_cut.clone(), &earlier_source);
        let fake_manifest = manifest("manifest:fake", fake_cut, &fake_source);
        let later_manifest = manifest("manifest:later", later_cut, &later_source);
        for manifest in [&earlier_manifest, &fake_manifest, &later_manifest] {
            workbench
                .store_mut()
                .append_record(
                    &chat_id,
                    WORKSTREAM_PROMOTION_MANIFEST_KIND,
                    &serde_json::to_string(manifest).expect("manifest"),
                )
                .expect("record manifest");
            let source = manifest
                .change_set(
                    DEFAULT_PLACEMENT.to_owned(),
                    manifest.partitions.clone(),
                    false,
                )
                .unwrap();
            workbench
                .store_mut()
                .append_record(
                    &chat_id,
                    TARGET_CHANGE_SET_DECLARATION_KIND,
                    &serde_json::to_string(&source).unwrap(),
                )
                .unwrap();
        }
        let earlier_source = earlier_manifest
            .change_set(
                DEFAULT_PLACEMENT.to_owned(),
                earlier_manifest.partitions.clone(),
                false,
            )
            .unwrap();
        let fake_source = fake_manifest
            .change_set(
                DEFAULT_PLACEMENT.to_owned(),
                fake_manifest.partitions.clone(),
                false,
            )
            .unwrap();
        let later_source = later_manifest
            .change_set(
                DEFAULT_PLACEMENT.to_owned(),
                later_manifest.partitions.clone(),
                false,
            )
            .unwrap();

        let earlier = workbench
            .create_target_settlement(
                &chat_id,
                &earlier_source.id,
                Some(earlier_manifest.id.clone()),
                vec![RequestedSettlementMember {
                    target_id: target_id.clone(),
                    act: TargetActKind::Apply,
                }],
            )
            .expect("earlier settlement");
        let earlier_id = earlier.declaration.unwrap().declaration_id;
        let earlier_ready = workbench
            .preflight_target_settlement(&earlier_id)
            .expect("earlier preflight");
        let earlier_member_id = earlier_ready.declaration.unwrap().members[0]
            .member_id
            .clone();

        let fake = workbench
            .create_target_settlement(
                &chat_id,
                &fake_source.id,
                Some(fake_manifest.id.clone()),
                vec![RequestedSettlementMember {
                    target_id: target_id.clone(),
                    act: TargetActKind::Apply,
                }],
            )
            .expect("fake settlement");
        let fake_id = fake.declaration.unwrap().declaration_id;
        let fake_ready = workbench
            .preflight_target_settlement(&fake_id)
            .expect("fake preflight");
        let fake_member_id = fake_ready.declaration.unwrap().members[0].member_id.clone();

        let lane_before = workbench
            .store_ref()
            .fold::<TargetSettlementLaneState>(&lane_scope(&target_id))
            .expect("lane before refusal");
        assert!(
            workbench
                .supersede_settlement_member(
                    &earlier_id,
                    &earlier_member_id,
                    &fake_id,
                    &fake_member_id,
                )
                .is_err()
        );
        assert_eq!(
            workbench
                .store_ref()
                .fold::<TargetSettlementLaneState>(&lane_scope(&target_id))
                .expect("lane after refusal"),
            lane_before,
            "same-target preflight without Main ancestry must be externally null"
        );

        let later = workbench
            .create_target_settlement(
                &chat_id,
                &later_source.id,
                Some(later_manifest.id),
                vec![RequestedSettlementMember {
                    target_id,
                    act: TargetActKind::Apply,
                }],
            )
            .expect("later settlement");
        let later_id = later.declaration.unwrap().declaration_id;
        let later_ready = workbench
            .preflight_target_settlement(&later_id)
            .expect("later preflight");
        let later_member_id = later_ready.declaration.as_ref().unwrap().members[0]
            .member_id
            .clone();

        // Model a declaration persisted by the old route: a real cumulative
        // manifest attached to another immutable source. Every resumption path
        // must validate it before mutating coordinator state or target lanes.
        let mut forged = later_ready.declaration.clone().unwrap();
        forged.declaration_id = "settlement:borrowed-manifest".into();
        forged.source_change_set_ref = fake_source.id;
        let forged_id = forged.declaration_id.clone();
        admit_settlement(
            &mut workbench,
            &forged_id,
            "declare",
            TargetSettlementCommand::Declare(forged),
        );
        admit_settlement(
            &mut workbench,
            &forged_id,
            "preflight",
            TargetSettlementCommand::BeginPreflight,
        );
        admit_settlement(
            &mut workbench,
            &forged_id,
            "evidence",
            TargetSettlementCommand::RecordPreflight(
                later_ready.members[&later_member_id]
                    .preflight_evidence
                    .clone()
                    .unwrap(),
            ),
        );
        let forged_scope = settlement_scope(&forged_id);
        let lane_id = lane_scope(&later_ready.declaration.as_ref().unwrap().members[0].target_id);
        let coordinator_before = workbench.store_ref().events(&forged_scope).unwrap();
        let lane_before = workbench.store_ref().events(&lane_id).unwrap();
        let outcomes = [
            workbench
                .preflight_target_settlement(&forged_id)
                .map(|_| ()),
            workbench
                .start_settlement_member(&forged_id, &later_member_id)
                .map(|_| ()),
            workbench
                .execute_settlement_member(&forged_id, &later_member_id)
                .map(|_| ()),
            workbench
                .query_settlement_member(&forged_id, &later_member_id)
                .map(|_| ()),
            workbench
                .retry_failed_settlement_member(&forged_id, &later_member_id)
                .map(|_| ()),
            workbench
                .supersede_settlement_member(
                    &earlier_id,
                    &earlier_member_id,
                    &forged_id,
                    &later_member_id,
                )
                .map(|_| ()),
        ];
        for outcome in outcomes {
            assert!(outcome.unwrap_err().contains("promotion manifest"));
        }
        assert_eq!(
            workbench.store_ref().events(&forged_scope).unwrap(),
            coordinator_before
        );
        assert_eq!(workbench.store_ref().events(&lane_id).unwrap(), lane_before);

        let superseded = workbench
            .supersede_settlement_member(
                &earlier_id,
                &earlier_member_id,
                &later_id,
                &later_member_id,
            )
            .expect("cumulative promoted cut supersedes");
        assert_eq!(
            superseded.members[&earlier_member_id].phase,
            SettlementMemberPhase::SupersededBeforeStart
        );
    }
}
