//! Exact witnessed project-file admission. This locator carries no authority;
//! the caller supplies the original held product writer's borrowed check.
#[path = "original_result_reader.rs"]
mod original_result_reader;
pub use original_result_reader::NativeObservedOfficeResult;

use super::{
    safe_manage_path, safe_path, safe_read_file, valid_native_action_target_path, workspace_writer,
    Engagement, Result, WorkspaceError,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::PoisonError;
use whipplescript_store::branches::write_evidence::WriteEvidenceRef;
use whipplescript_store::branches::{
    BranchRow, BranchStatus, BranchStore, CutRow, OpBranchState, OpRow,
};
use whipplescript_store::content::{ContentBlobs, ContentStore};
use whipplescript_store::vcs::recorded_review::{
    AppliedRecordedSettlement, HistoricalRecordedSettlement, PreparedRecordedMergeReview,
    RecordedMergeOutcome, RecordedMergeReview, RecordedSettlementOutcome,
};
use whipplescript_store::vcs::{NativeWorkspaceVcs, VcsWriteOutcome};
use whipplescript_store::{StoreError, StoreResult};

/// Carriage of an original owner witness, not a filesystem discovery result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct NativeTurnFileWitness {
    pub path: String,
    pub kind: String,
    pub sha256: String,
    pub bytes: u64,
}

/// A selected project-file boundary at the actual recorded original base.
/// Chat-local artifacts/work require their own retained publication boundary;
/// they must never be silently included in a target/mainline candidate.
#[derive(Clone)]
pub struct NativeWitnessedTurnTarget {
    engagement: Engagement,
    base: CutRow,
    base_op: Option<OpRow>,
    original_lineage: Option<BranchRow>,
}

/// Exact native evidence retained for a later product reference commit.
pub struct NativeWitnessedTurn {
    target: NativeWitnessedTurnTarget,
    cut: CutRow,
    op: OpRow,
    files: BTreeMap<String, String>,
    removed: Vec<String>,
    manifest: BTreeMap<String, String>,
    base_manifest: BTreeMap<String, String>,
    result_evidence: Option<TurnResultEvidence>,
}

/// Sealed native review evidence, not permission to publish a result. The
/// embedding must retain and consume its same original product writer.
pub struct NativeReviewedTurn {
    result: NativeWitnessedTurn,
    prepared: PreparedRecordedMergeReview,
    reviewed_target: BranchRow,
    vcs: NativeWorkspaceVcs,
}

/// An actual original native home-line operation. It does not certify
/// filesystem projection, sibling reconciliation, or a product commit.
pub struct NativeSettledTurn {
    result: NativeWitnessedTurn,
    applied: AppliedRecordedSettlement,
    vcs: NativeWorkspaceVcs,
}

/// Exact original historical settlement, not a current applied receipt. It
/// cannot authorize moving current heads or projecting mutable files.
pub struct NativeHistoricalSettledTurn {
    result: NativeWitnessedTurn,
    history: HistoricalRecordedSettlement,
    vcs: NativeWorkspaceVcs,
}

struct TurnResultEvidence {
    reference: WriteEvidenceRef,
    root_body: Vec<u8>,
    descriptor: String,
    descriptor_body: Vec<u8>,
    local_files: BTreeMap<String, NativeTurnFileWitness>,
}

fn refused(message: &str) -> WorkspaceError {
    WorkspaceError::msg(message)
}

impl Engagement {
    /// Capture only native recorded history. A new/inherited branch receives
    /// an empty-diff anchor under the original check, never a filesystem import.
    pub fn witnessed_turn_start_guarded(
        &self,
        actor: &str,
        command: &str,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<NativeWitnessedTurnTarget> {
        check()?;
        if actor.is_empty() || command.is_empty() {
            return Err(refused("original native startup meaning unavailable"));
        }
        let writer = workspace_writer(&self.store_root, &self.branch);
        let _writing = writer.lock().unwrap_or_else(PoisonError::into_inner);
        let observed = NativeWorkspaceVcs::open_read_only(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )?;
        let branch = observed
            .get_branch(&self.branch)?
            .filter(|row| row.status == BranchStatus::Active)
            .ok_or_else(|| refused("original native startup branch unavailable"))?;
        match (&branch.head_cut_id, &branch.head_manifest_hash) {
            (Some(id), Some(hash)) => {
                let cut = observed
                    .get_cut(id)?
                    .ok_or_else(|| refused("original native startup head unavailable"))?;
                if cut.manifest_hash != *hash || observed.cut_manifest(id)?.is_none() {
                    return Err(refused("original native startup head differs"));
                }
                if cut.branch_id == self.branch {
                    let target = self.witnessed_turn_target_at(id)?;
                    check()?;
                    return Ok(target);
                }
            }
            (None, None) => {}
            _ => return Err(refused("original native startup head is incomplete")),
        }
        let meaning = serde_json::to_vec(&(
            "gaugedesk-native-startup-base-v1",
            &self.branch,
            actor,
            command,
            &branch.head_cut_id,
            &branch.head_manifest_hash,
        ))
        .map_err(|_| refused("original native startup meaning unavailable"))?;
        let id = format!(
            "witnessed-turn-base-{}",
            hex::encode(Sha256::digest(meaning))
        );
        if observed.get_cut(&id)?.is_some() || observed.get_op(&format!("op-{id}"))?.is_some() {
            return Err(refused("original native startup anchor lost its head"));
        }
        let mut vcs = NativeWorkspaceVcs::from_parts(
            BranchStore::open(self.store_root.join("branches.sqlite"))?,
            ContentStore::open_existing(self.store_root.join("content.sqlite"))?,
        );
        vcs.set_actor(Some(actor.into()));
        vcs.set_intent(Some(command.into()));
        let mut native_check = || {
            check().map_err(|_| {
                StoreError::Conflict("original native startup authority ended".into())
            })?;
            if observed.get_branch(&self.branch)?.as_ref() != Some(&branch) {
                return Err(StoreError::Conflict(
                    "original native startup branch changed".into(),
                ));
            }
            Ok(())
        };
        if !matches!(
            vcs.import_diff_guarded(
                &self.branch,
                &BTreeMap::new(),
                &[],
                &id,
                &super::now_at(),
                &mut native_check
            )?,
            VcsWriteOutcome::Written { .. }
        ) {
            return Err(refused("original native startup anchor refused"));
        }
        let target = self.witnessed_turn_target_at(&id)?;
        let op = target
            .base_op
            .as_ref()
            .ok_or_else(|| refused("original native startup operation unavailable"))?;
        let expected = match branch.head_cut_id.as_deref() {
            Some(id) => observed
                .cut_manifest(id)?
                .ok_or_else(|| refused("original native startup tree unavailable"))?,
            None => BTreeMap::new(),
        };
        let before = OpBranchState::of(&branch);
        let after = OpBranchState {
            head_cut_id: Some(id.clone()),
            head_manifest_hash: Some(target.base.manifest_hash.clone()),
            ..before.clone()
        };
        if target.base.parent_cut_id != branch.head_cut_id
            || target.base.actor.as_deref() != Some(actor)
            || target.base.intent.as_deref() != Some(command)
            || target.base.origin.as_deref() != Some("import")
            || target.base.change_id != id
            || op.kind != "import"
            || op.origin.as_deref() != Some("import")
            || op.deltas.len() != 1
            || op.deltas[0].branch_id != self.branch
            || op.deltas[0].before.as_ref() != Some(&before)
            || op.deltas[0].after != after
            || vcs.cut_manifest(&id)?.as_ref() != Some(&expected)
        {
            return Err(refused("original native startup anchor differs"));
        }
        check()?;
        Ok(target)
    }

    pub fn witnessed_turn_target_at(&self, base_cut: &str) -> Result<NativeWitnessedTurnTarget> {
        let vcs = NativeWorkspaceVcs::open_read_only(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )?;
        let base = vcs
            .get_cut(base_cut)?
            .ok_or_else(|| refused("original native turn base unavailable"))?;
        if base.branch_id != self.branch {
            return Err(refused(
                "original native turn base belongs to another branch",
            ));
        }
        let base_op = if base.cut_id.starts_with("witnessed-turn-base-") {
            let op = vcs
                .get_op(&format!("op-{}", base.cut_id))?
                .ok_or_else(|| refused("original native startup operation unavailable"))?;
            let parent_hash = match base.parent_cut_id.as_deref() {
                Some(id) => Some(
                    vcs.get_cut(id)?
                        .ok_or_else(|| refused("original native startup parent unavailable"))?
                        .manifest_hash,
                ),
                None => None,
            };
            if base.origin.as_deref() != Some("import")
                || base.change_id != base.cut_id
                || op.kind != "import"
                || op.origin.as_deref() != Some("import")
                || op.deltas.len() != 1
                || !op.deltas.first().is_some_and(|delta| {
                    delta.branch_id == self.branch
                        && delta.before.as_ref().is_some_and(|before| {
                            before.status == BranchStatus::Active
                                && before.head_cut_id == base.parent_cut_id
                                && before.head_manifest_hash == parent_hash
                                && before.branch_point_cut_id == delta.after.branch_point_cut_id
                                && before.branch_point_manifest_hash
                                    == delta.after.branch_point_manifest_hash
                        })
                        && delta.after.status == BranchStatus::Active
                        && delta.after.head_cut_id.as_deref() == Some(base.cut_id.as_str())
                        && delta.after.head_manifest_hash.as_deref()
                            == Some(base.manifest_hash.as_str())
                })
            {
                return Err(refused(
                    "original native startup operation is not its anchor",
                ));
            }
            Some(op)
        } else {
            None
        };
        let target = NativeWitnessedTurnTarget {
            engagement: self.clone(),
            base,
            base_op,
            original_lineage: None,
        };
        target.observe()?;
        Ok(target)
    }
}

impl NativeWitnessedTurnTarget {
    /// Capture topology only while the original base is still the live head.
    /// Startup publication must also exclude a race with this read.
    pub fn capture_original_lineage(self) -> Result<Self> {
        let observed = self.observe()?;
        let row = observed
            .get_branch(&self.engagement.branch)?
            .ok_or_else(|| refused("original native lineage unavailable"))?;
        self.with_retained_lineage(row)
    }

    /// Original sealed startup carriage, never a grant or a live-topology repair.
    pub fn with_retained_lineage(mut self, row: BranchRow) -> Result<Self> {
        self.original_lineage = Some(row);
        self.observe()?;
        Ok(self)
    }

    pub fn original_lineage(&self) -> Result<&BranchRow> {
        self.original_lineage
            .as_ref()
            .ok_or_else(|| refused("original native lineage unavailable"))
    }

    /// Publish initial topology while both native writers hold the exact row.
    pub fn publish_startup_lineage_retained<T>(
        &self,
        publish: impl FnOnce() -> StoreResult<T>,
    ) -> StoreResult<T> {
        let lineage = self
            .original_lineage
            .as_ref()
            .ok_or_else(|| StoreError::Conflict("original native lineage unavailable".into()))?;
        self.publish_base_retained(|| {
            let current = self.observe()?;
            if current.get_branch(&self.engagement.branch)?.as_ref() != Some(lineage) {
                return Err(StoreError::Conflict(
                    "original native startup lineage changed".into(),
                ));
            }
            publish()
        })
    }

    pub fn base_cut(&self) -> &str {
        &self.base.cut_id
    }

    /// Retain the complete original base while its startup reference commits.
    /// This grants no permission and never refreshes the original check.
    pub fn publish_base_retained<T>(
        &self,
        publish: impl FnOnce() -> StoreResult<T>,
    ) -> StoreResult<T> {
        let observed = NativeWorkspaceVcs::open_for_recorded_review(
            self.engagement.store_root.join("branches.sqlite"),
            self.engagement.store_root.join("content.sqlite"),
        )?;
        self.observe_at(&observed)?;
        let manifest = observed.cut_manifest(&self.base.cut_id)?.ok_or_else(|| {
            StoreError::Conflict("original native startup tree unavailable".into())
        })?;
        let mut retained: Vec<_> = manifest.values().cloned().collect();
        retained.push(self.base.manifest_hash.clone());
        if let Some(id) = self
            .original_lineage
            .as_ref()
            .and_then(|row| row.branch_point_cut_id.as_ref())
        {
            let cut = observed.get_cut(id)?.ok_or_else(|| {
                StoreError::Conflict("original divergence cut unavailable".into())
            })?;
            let manifest = observed.cut_manifest(id)?.ok_or_else(|| {
                StoreError::Conflict("original divergence tree unavailable".into())
            })?;
            retained.push(cut.manifest_hash);
            retained.extend(manifest.into_values());
        }
        observed.publish_retained_recorded_observation(&retained, |current| {
            // The owner holds BOTH native writers through the embedding's
            // original commit; cut, operation and active custody cannot race.
            self.observe_at(current)?;
            if current.cut_manifest(&self.base.cut_id)?.as_ref() != Some(&manifest) {
                return Err(StoreError::Conflict(
                    "original native startup tree differs".into(),
                ));
            }
            publish()
        })
    }

    fn observe(&self) -> StoreResult<NativeWorkspaceVcs> {
        let vcs = NativeWorkspaceVcs::open_read_only(
            self.engagement.store_root.join("branches.sqlite"),
            self.engagement.store_root.join("content.sqlite"),
        )?;
        self.observe_at(&vcs)?;
        Ok(vcs)
    }

    fn observe_at(&self, vcs: &NativeWorkspaceVcs) -> StoreResult<()> {
        if !vcs
            .get_branch(&self.engagement.branch)?
            .is_some_and(|branch| branch.status == BranchStatus::Active)
            || vcs.get_cut(&self.base.cut_id)?.as_ref() != Some(&self.base)
            || vcs.cut_manifest(&self.base.cut_id)?.is_none()
        {
            return Err(StoreError::Conflict(
                "original native turn branch or base unavailable".into(),
            ));
        }
        if let Some(row) = &self.original_lineage {
            if row.branch_id != self.engagement.branch
                || row.status != BranchStatus::Active
                || row.head_cut_id.as_deref() != Some(self.base.cut_id.as_str())
                || row.head_manifest_hash.as_deref() != Some(self.base.manifest_hash.as_str())
                || row.parent_branch_id.as_deref().is_none_or(str::is_empty)
                || !vcs
                    .get_branch(row.parent_branch_id.as_deref().unwrap_or_default())?
                    .is_some_and(|parent| parent.status == BranchStatus::Active)
            {
                return Err(StoreError::Conflict(
                    "original native lineage differs".into(),
                ));
            }
            match (&row.branch_point_cut_id, &row.branch_point_manifest_hash) {
                (None, None) => {}
                (Some(id), Some(hash))
                    if vcs
                        .get_cut(id)?
                        .is_some_and(|cut| cut.manifest_hash == *hash)
                        && vcs.cut_manifest(id)?.is_some() => {}
                _ => {
                    return Err(StoreError::Conflict(
                        "original native divergence differs".into(),
                    ))
                }
            }
        }
        if let Some(op) = &self.base_op {
            if vcs.get_op(&op.op_id)?.as_ref() != Some(op) {
                return Err(StoreError::Conflict(
                    "original native startup operation differs".into(),
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn plan(
        &self,
        witness: &[NativeTurnFileWitness],
        runtime_cut: &str,
        actor: &str,
        command: &str,
    ) -> Result<(String, BTreeMap<String, NativeTurnFileWitness>)> {
        self.plan_result(witness, runtime_cut, actor, command, false)
    }

    fn plan_result(
        &self,
        witness: &[NativeTurnFileWitness],
        runtime_cut: &str,
        actor: &str,
        command: &str,
        include_local: bool,
    ) -> Result<(String, BTreeMap<String, NativeTurnFileWitness>)> {
        if runtime_cut.is_empty() || actor.is_empty() || command.is_empty() {
            return Err(refused("original native turn meaning unavailable"));
        }
        let empty = hex::encode(Sha256::digest([]));
        let mut final_files = BTreeMap::new();
        let mut spelling = BTreeMap::new();
        for entry in witness {
            let local = entry.path.starts_with("artifacts/") || entry.path.starts_with("work/");
            let valid_path = valid_native_action_target_path(&entry.path)
                || (include_local
                    && local
                    && !entry.path.contains('\\')
                    && !entry
                        .path
                        .split('/')
                        .any(|part| matches!(part, "" | "." | "..")));
            if !valid_path
                || entry.sha256.len() != 64
                || !entry
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || !matches!(entry.kind.as_str(), "add" | "modify" | "delete")
                || (entry.kind == "delete" && (entry.bytes != 0 || entry.sha256 != empty))
            {
                return Err(refused("invalid original native turn file witness"));
            }
            self.engagement.ensure_selected_path(&entry.path)?;
            if entry.path.chars().any(char::is_control)
                || entry
                    .path
                    .split('/')
                    .any(|part| matches!(part, ".git" | ".gaugedesk-folder"))
            {
                return Err(refused("original native turn file path is reserved"));
            }
            safe_path(&self.engagement.path, &entry.path)?;
            if spelling
                .insert(entry.path.to_lowercase(), entry.path.clone())
                .is_some_and(|previous| previous != entry.path)
            {
                return Err(refused("ambiguous native turn file path"));
            }
            // The owner witness is ordered. Multiple writes to one path are
            // normal; only its final operation describes the resulting bytes.
            final_files.insert(entry.path.clone(), entry.clone());
        }
        let meaning = serde_json::to_vec(&(
            &self.engagement.branch,
            &self.base.cut_id,
            runtime_cut,
            actor,
            command,
            witness,
        ))
        .map_err(|_| refused("original native turn meaning unavailable"))?;
        Ok((
            format!("witnessed-turn-{}", hex::encode(Sha256::digest(meaning))),
            final_files,
        ))
    }

    /// Import only final witnessed project paths against the original base.
    /// No scan, projection, clock renewal, or current-head rebase occurs here.
    pub fn import_guarded(
        self,
        witness: &[NativeTurnFileWitness],
        runtime_cut: &str,
        actor: &str,
        command: &str,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<NativeWitnessedTurn> {
        self.import_checked(witness, runtime_cut, actor, command, check, false)
    }

    /// Admit the complete original owner witness, retaining run-owned outputs
    /// outside target history under the same native cut and original guard.
    pub fn import_result_guarded(
        self,
        witness: &[NativeTurnFileWitness],
        runtime_cut: &str,
        actor: &str,
        command: &str,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<NativeWitnessedTurn> {
        self.import_checked(witness, runtime_cut, actor, command, check, true)
    }

    /// Original saved bodies supplied under the embedding's retained key and
    /// product writer. Never read or project the mutable source workspace.
    #[allow(clippy::too_many_arguments)] // Complete original witness, bytes and borrowed authority.
    pub fn import_saved_result_guarded(
        self,
        witness: &[NativeTurnFileWitness],
        runtime_cut: &str,
        actor: &str,
        command: &str,
        bodies: &BTreeMap<String, Vec<u8>>,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<NativeWitnessedTurn> {
        check()?;
        let (_, final_files) = self.plan_result(witness, runtime_cut, actor, command, true)?;
        let original = self.original_lineage()?.clone();
        if bodies.keys().ne(final_files.keys()) {
            return Err(refused("original saved native payload set differs"));
        }
        let evidence =
            TurnResultEvidence::new(&self, witness, &final_files, runtime_cut, actor, command)?;
        // Observation validates only immutable original coordinates and current
        // custody. The owner performs the atomic isolated reference operation.
        let observed = self.observe()?;
        let base_manifest = observed
            .cut_manifest(&self.base.cut_id)?
            .ok_or_else(|| refused("original native result base unavailable"))?;
        let mut vcs = NativeWorkspaceVcs::from_parts(
            BranchStore::open(self.engagement.store_root.join("branches.sqlite"))?,
            ContentStore::open_existing(self.engagement.store_root.join("content.sqlite"))?,
        );
        vcs.set_actor(Some(actor.into()));
        vcs.set_intent(Some(command.into()));
        for (path, entry) in &final_files {
            check()?;
            let body = &bodies[path];
            if body.len() as u64 != entry.bytes {
                return Err(refused("original saved native payload length differs"));
            }
            let mut digest = Sha256::new();
            for window in body.chunks(64 * 1024) {
                check()?;
                digest.update(window);
            }
            if hex::encode(digest.finalize()) != entry.sha256 {
                return Err(refused("original saved native payload digest differs"));
            }
            if entry.kind != "delete" && vcs.content_store().put(body)? != entry.sha256[..32] {
                return Err(refused("original saved native payload preparation differs"));
            }
            check()?;
        }
        validate_payloads(&vcs, &final_files, check)?;
        evidence.prepare(&vcs, check)?;
        let files: BTreeMap<_, _> = final_files
            .iter()
            .filter(|(_, file)| {
                file.kind != "delete" && valid_native_action_target_path(&file.path)
            })
            .map(|(path, file)| (path.clone(), file.sha256[..32].to_owned()))
            .collect();
        let removed: Vec<_> = final_files
            .iter()
            .filter(|(_, file)| {
                file.kind == "delete" && valid_native_action_target_path(&file.path)
            })
            .map(|(path, _)| path.clone())
            .collect();
        let mut native_check = || {
            check().map_err(|_| {
                StoreError::Conflict("original saved native result authority ended".into())
            })
        };
        let candidate = vcs.import_original_candidate_guarded(
            &original,
            &files,
            &removed,
            &evidence.reference,
            &super::now_at(),
            &mut native_check,
        )?;
        let mut expected = base_manifest.clone();
        expected.extend(files.clone());
        for path in &removed {
            expected.remove(path);
        }
        if vcs.cut_manifest(&candidate.cut.cut_id)?.as_ref() != Some(&expected) {
            return Err(refused("original isolated native result manifest differs"));
        }
        let result = NativeWitnessedTurn {
            target: self,
            cut: candidate.cut,
            op: candidate.operation,
            files,
            removed,
            manifest: expected,
            base_manifest,
            result_evidence: Some(evidence),
        };
        result.observe_at(&vcs)?;
        check()?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)] // One original turn and its complete-result mode.
    fn import_checked(
        self,
        witness: &[NativeTurnFileWitness],
        runtime_cut: &str,
        actor: &str,
        command: &str,
        check: &mut dyn FnMut() -> Result<()>,
        include_local: bool,
    ) -> Result<NativeWitnessedTurn> {
        check()?;
        let (cut_id, final_files) =
            self.plan_result(witness, runtime_cut, actor, command, include_local)?;
        let evidence = if include_local {
            Some(TurnResultEvidence::new(
                &self,
                witness,
                &final_files,
                runtime_cut,
                actor,
                command,
            )?)
        } else {
            None
        };
        let writer = workspace_writer(&self.engagement.store_root, &self.engagement.branch);
        let _writing = writer.lock().unwrap_or_else(PoisonError::into_inner);
        let observed = self.observe()?;
        let files: BTreeMap<String, String> = final_files
            .iter()
            .filter(|(_, entry)| {
                entry.kind != "delete" && valid_native_action_target_path(&entry.path)
            })
            .map(|(path, entry)| (path.clone(), entry.sha256[..32].to_owned()))
            .collect();
        let removed: Vec<String> = final_files
            .iter()
            .filter(|(_, entry)| {
                entry.kind == "delete" && valid_native_action_target_path(&entry.path)
            })
            .map(|(path, _)| path.clone())
            .collect();
        // Recover the exact original receipt before looking at any live file.
        if let Some(cut) = observed.get_cut(&cut_id)? {
            let result = self.recorded(&observed, cut, actor, command, files, removed, evidence)?;
            result.validate_payloads(&observed, &final_files, check)?;
            check()?;
            return Ok(result);
        }
        let branch = observed
            .get_branch(&self.engagement.branch)?
            .ok_or_else(|| refused("native turn branch unavailable"))?;
        if branch.head_cut_id.as_deref() != Some(self.base.cut_id.as_str())
            || branch.head_manifest_hash.as_deref() != Some(self.base.manifest_hash.as_str())
        {
            return Err(refused("native turn branch moved from its original base"));
        }
        self.engagement.ensure_projection()?;
        let root = &self.engagement.store_root;
        let mut vcs = NativeWorkspaceVcs::from_parts(
            BranchStore::open(root.join("branches.sqlite"))?,
            ContentStore::open_existing(root.join("content.sqlite"))?,
        );
        vcs.set_actor(Some(actor.into()));
        vcs.set_intent(Some(command.into()));
        for entry in final_files.values() {
            check()?;
            if entry.kind == "delete" {
                let path = safe_manage_path(&self.engagement.path, &entry.path)?;
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(refused("witnessed native deletion is not absent")),
                }
                continue;
            }
            // Read one authorized opened inode into a private snapshot. The
            // native blob preparer never reopens a mutable workspace path.
            safe_manage_path(&self.engagement.path, &entry.path)?;
            let mut input = safe_read_file(&self.engagement.path, &entry.path)?;
            if input.metadata().map_err(WorkspaceError::io)?.len() != entry.bytes {
                return Err(refused("witnessed native turn bytes changed"));
            }
            let mut snapshot = tempfile::NamedTempFile::new().map_err(WorkspaceError::io)?;
            let mut digest = Sha256::new();
            let mut count = 0u64;
            let mut window = [0u8; 64 * 1024];
            loop {
                check()?;
                let n = input.read(&mut window).map_err(WorkspaceError::io)?;
                if n == 0 {
                    break;
                }
                count = count
                    .checked_add(n as u64)
                    .ok_or_else(|| refused("witnessed native turn bytes changed"))?;
                if count > entry.bytes {
                    return Err(refused("witnessed native turn bytes changed"));
                }
                digest.update(&window[..n]);
                check()?;
                snapshot
                    .write_all(&window[..n])
                    .map_err(WorkspaceError::io)?;
            }
            if count != entry.bytes || hex::encode(digest.finalize()) != entry.sha256 {
                return Err(refused("witnessed native turn bytes changed"));
            }
            snapshot.as_file().sync_all().map_err(WorkspaceError::io)?;
            check()?;
            let snapshot = snapshot.into_temp_path();
            let hash = vcs.content_store().put_file(&snapshot)?;
            check()?;
            if hash != entry.sha256[..32] {
                return Err(refused("witnessed native turn preparation changed"));
            }
        }
        // Check the actual stored payloads, including an existing cached blob.
        validate_payloads(&vcs, &final_files, check)?;
        if let Some(evidence) = &evidence {
            evidence.prepare(&vcs, check)?;
        }
        let mut native_check = || {
            check()
                .map_err(|_| StoreError::Conflict("original native turn authority ended".into()))?;
            // Another native process does not share the projection mutex. Read
            // the committed basis again while the real branch writer is held;
            // its uncommitted import cannot turn a newer basis into this one.
            if !observed
                .get_branch(&self.engagement.branch)?
                .is_some_and(|branch| {
                    branch.status == BranchStatus::Active
                        && branch.head_cut_id.as_deref() == Some(self.base.cut_id.as_str())
                        && branch.head_manifest_hash.as_deref()
                            == Some(self.base.manifest_hash.as_str())
                })
            {
                return Err(StoreError::Conflict(
                    "original native turn base changed before commit".into(),
                ));
            }
            Ok(())
        };
        let outcome = if let Some(evidence) = &evidence {
            vcs.import_diff_guarded_with_evidence(
                &self.engagement.branch,
                &files,
                &removed,
                &cut_id,
                &super::now_at(),
                &evidence.reference,
                &mut native_check,
            )?
        } else {
            vcs.import_diff_guarded(
                &self.engagement.branch,
                &files,
                &removed,
                &cut_id,
                &super::now_at(),
                &mut native_check,
            )?
        };
        match outcome {
            VcsWriteOutcome::Written { .. } => {}
            _ => return Err(refused("native witnessed turn import refused")),
        }
        let cut = vcs
            .get_cut(&cut_id)?
            .ok_or_else(|| refused("native witnessed turn cut unavailable"))?;
        let result = self.recorded(&vcs, cut, actor, command, files, removed, evidence)?;
        check()?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)] // Exact original native receipt and its expected result evidence.
    fn recorded(
        self,
        vcs: &NativeWorkspaceVcs,
        cut: CutRow,
        actor: &str,
        command: &str,
        files: BTreeMap<String, String>,
        removed: Vec<String>,
        result_evidence: Option<TurnResultEvidence>,
    ) -> Result<NativeWitnessedTurn> {
        if vcs.write_evidence(&cut.cut_id)?.as_ref()
            != result_evidence.as_ref().map(|e| &e.reference)
        {
            return Err(refused(
                "native witnessed turn original result evidence differs",
            ));
        }
        if let Some(evidence) = &result_evidence {
            evidence.observe(vcs)?;
        }
        let op = vcs
            .get_op(&format!("op-{}", cut.cut_id))?
            .ok_or_else(|| refused("native witnessed turn operation unavailable"))?;
        let mut expected = vcs
            .cut_manifest(&self.base.cut_id)?
            .ok_or_else(|| refused("original native turn manifest unavailable"))?;
        let base_manifest = expected.clone();
        expected.extend(files.clone());
        for path in &removed {
            expected.remove(path);
        }
        let delta = op.deltas.first();
        if cut.branch_id != self.engagement.branch
            || cut.change_id != cut.cut_id
            || cut.parent_cut_id.as_deref() != Some(self.base.cut_id.as_str())
            || cut.origin.as_deref() != Some("import")
            || cut.actor.as_deref() != Some(actor)
            || cut.intent.as_deref() != Some(command)
            || op.kind != "import"
            || op.origin.as_deref() != Some("import")
            || op.deltas.len() != 1
            || !delta.is_some_and(|delta| {
                delta.branch_id == self.engagement.branch
                    && delta.before.as_ref().is_some_and(|before| {
                        before.head_cut_id.as_deref() == Some(self.base.cut_id.as_str())
                            && before.head_manifest_hash.as_deref()
                                == Some(self.base.manifest_hash.as_str())
                            && before.status == BranchStatus::Active
                            && delta.after.status == BranchStatus::Active
                            && before.branch_point_cut_id == delta.after.branch_point_cut_id
                            && before.branch_point_manifest_hash
                                == delta.after.branch_point_manifest_hash
                    })
                    && delta.after.head_cut_id.as_deref() == Some(cut.cut_id.as_str())
                    && delta.after.head_manifest_hash.as_deref() == Some(cut.manifest_hash.as_str())
            })
            || vcs.cut_manifest(&cut.cut_id)?.as_ref() != Some(&expected)
        {
            return Err(refused("native witnessed turn evidence differs"));
        }
        Ok(NativeWitnessedTurn {
            target: self,
            cut,
            op,
            files,
            removed,
            manifest: expected,
            base_manifest,
            result_evidence,
        })
    }
}

fn validate_payloads(
    vcs: &NativeWorkspaceVcs,
    final_files: &BTreeMap<String, NativeTurnFileWitness>,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    for entry in final_files.values().filter(|entry| entry.kind != "delete") {
        check()?;
        let body = vcs
            .content_store()
            .get(&entry.sha256[..32])?
            .ok_or_else(|| refused("original native turn payload unavailable"))?;
        if body.len() as u64 != entry.bytes {
            return Err(refused("original native turn payload differs"));
        }
        let mut digest = Sha256::new();
        for window in body.chunks(64 * 1024) {
            check()?;
            digest.update(window);
        }
        if hex::encode(digest.finalize()) != entry.sha256 {
            return Err(refused("original native turn payload differs"));
        }
        check()?;
    }
    Ok(())
}

impl NativeWitnessedTurn {
    fn destination(&self) -> &str {
        if self.cut.branch_id != self.target.engagement.branch {
            self.target
                .original_lineage
                .as_ref()
                .and_then(|row| row.parent_branch_id.as_deref())
                .expect("isolated original candidate has a sealed parent")
        } else {
            &self.target.engagement.target
        }
    }
    pub fn cut(&self) -> &str {
        &self.cut.cut_id
    }
    pub fn files(&self) -> &BTreeMap<String, String> {
        &self.files
    }
    pub fn removed(&self) -> &[String] {
        &self.removed
    }
    pub fn result_evidence(&self) -> Option<&WriteEvidenceRef> {
        self.result_evidence.as_ref().map(|e| &e.reference)
    }
    pub fn local_files(&self) -> BTreeMap<String, String> {
        self.result_evidence
            .as_ref()
            .map(|e| {
                e.local_files
                    .iter()
                    .filter(|(_, entry)| entry.kind != "delete")
                    .map(|(path, entry)| (path.clone(), entry.sha256[..32].to_owned()))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn local_removed(&self) -> Vec<String> {
        self.result_evidence
            .as_ref()
            .map(|e| {
                e.local_files
                    .values()
                    .filter(|entry| entry.kind == "delete")
                    .map(|entry| entry.path.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Prepare only recorded history under the original borrowed product
    /// check. Never import the mutable target or mint merge candidate bytes.
    pub fn prepare_recorded_review_guarded(
        self,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<NativeReviewedTurn> {
        check()?;
        if self.result_evidence.is_none() {
            return Err(refused("complete original native result unavailable"));
        }
        let vcs = NativeWorkspaceVcs::open_for_recorded_review(
            self.target.engagement.store_root.join("branches.sqlite"),
            self.target.engagement.store_root.join("content.sqlite"),
        )?;
        self.observe_at(&vcs)?;
        let mut native_check =
            || check().map_err(|_| StoreError::Conflict("original result authority ended".into()));
        let prepared = vcs.prepare_recorded_merge_review(
            &self.cut.branch_id,
            &self.cut.cut_id,
            &self.retained(),
            &mut native_check,
        )?;
        if prepared.review().target_branch_id != self.destination() {
            return Err(refused("original native result target changed"));
        }
        // Capture the complete reviewed destination while the owner's
        // original review fence proves its rows, not from a later loose read.
        let reviewed_target =
            vcs.publish_prepared_recorded_merge_review(&prepared, |review, vcs| {
                native_check()?;
                vcs.get_branch(&review.target_branch_id)?.ok_or_else(|| {
                    StoreError::Conflict("original reviewed native destination unavailable".into())
                })
            })?;
        check()?;
        Ok(NativeReviewedTurn {
            result: self,
            prepared,
            reviewed_target,
            vcs,
        })
    }

    fn settlement_id(&self) -> Result<String> {
        let actor = self.cut.actor.as_deref().filter(|v| !v.is_empty());
        let command = self.cut.intent.as_deref().filter(|v| !v.is_empty());
        if actor.is_none() || command.is_none() || self.result_evidence.is_none() {
            return Err(refused("original native settlement meaning unavailable"));
        }
        let meaning = serde_json::to_vec(&(
            "gaugedesk-original-native-settlement-v1",
            &self.cut.branch_id,
            &self.destination(),
            &self.cut,
            &self.op,
        ))
        .map_err(|_| refused("original native settlement meaning unavailable"))?;
        Ok(format!(
            "office-settlement-{}",
            hex::encode(Sha256::digest(meaning))
        ))
    }

    /// Recover before preparing a new review: a committed native merge has
    /// moved the source head. Recovery never reads or imports mutable files.
    pub fn recover_settlement_guarded(
        self,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<std::result::Result<NativeSettledTurn, Self>> {
        check()?;
        let id = self.settlement_id()?;
        let vcs = NativeWorkspaceVcs::open_for_recorded_review(
            self.target.engagement.store_root.join("branches.sqlite"),
            self.target.engagement.store_root.join("content.sqlite"),
        )?;
        self.observe_at(&vcs)?;
        if vcs.get_cut(&id)?.is_none() && vcs.get_op(&format!("op-{id}"))?.is_none() {
            check()?;
            return Ok(Err(self));
        }
        let mut native_check = || {
            check().map_err(|_| {
                StoreError::Conflict("original native settlement authority ended".into())
            })
        };
        let applied = vcs.recover_recorded_settlement(
            &self.cut.branch_id,
            &self.cut.cut_id,
            &self.retained(),
            &id,
            self.cut.actor.as_deref().expect("qualified actor"),
            self.cut.intent.as_deref().expect("qualified command"),
            &mut native_check,
        )?;
        check()?;
        Ok(Ok(NativeSettledTurn {
            result: self,
            applied,
            vcs,
        }))
    }

    /// Recover immutable original history after later legitimate collaboration.
    /// The original check is still required; no current-head authority escapes.
    pub fn recover_historical_settlement_guarded(
        self,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<std::result::Result<NativeHistoricalSettledTurn, Self>> {
        check()?;
        let id = self.settlement_id()?;
        let vcs = NativeWorkspaceVcs::open_for_recorded_review(
            self.target.engagement.store_root.join("branches.sqlite"),
            self.target.engagement.store_root.join("content.sqlite"),
        )?;
        self.observe_at(&vcs)?;
        if vcs.get_cut(&id)?.is_none() && vcs.get_op(&format!("op-{id}"))?.is_none() {
            check()?;
            return Ok(Err(self));
        }
        let mut native_check = || {
            check().map_err(|_| {
                StoreError::Conflict("original native settlement authority ended".into())
            })
        };
        let history = vcs.recover_historical_recorded_settlement(
            &self.cut.branch_id,
            &self.cut.cut_id,
            &self.retained(),
            &id,
            self.cut.actor.as_deref().expect("qualified actor"),
            self.cut.intent.as_deref().expect("qualified command"),
            &mut native_check,
        )?;
        check()?;
        Ok(Ok(NativeHistoricalSettledTurn {
            result: self,
            history,
            vcs,
        }))
    }

    fn retained(&self) -> Vec<String> {
        let mut retained: Vec<String> = self.manifest.values().cloned().collect();
        retained.extend(self.base_manifest.values().cloned());
        retained.push(self.cut.manifest_hash.clone());
        retained.push(self.target.base.manifest_hash.clone());
        if let Some(evidence) = &self.result_evidence {
            retained.push(evidence.reference.content_hash.clone());
            retained.push(evidence.descriptor.clone());
            retained.extend(
                evidence
                    .local_files
                    .values()
                    .filter(|entry| entry.kind != "delete")
                    .map(|entry| entry.sha256[..32].to_owned()),
            );
        }
        retained
    }

    fn observe_at(&self, vcs: &NativeWorkspaceVcs) -> StoreResult<()> {
        self.target.observe_at(vcs)?;
        if vcs.cut_manifest(&self.target.base.cut_id)?.as_ref() != Some(&self.base_manifest)
            || vcs.cut_manifest(&self.cut.cut_id)?.as_ref() != Some(&self.manifest)
            || vcs.get_cut(&self.cut.cut_id)?.as_ref() != Some(&self.cut)
            || vcs.get_op(&self.op.op_id)?.as_ref() != Some(&self.op)
        {
            return Err(StoreError::Conflict(
                "native witnessed turn evidence changed before publication".into(),
            ));
        }
        if vcs.write_evidence(&self.cut.cut_id)?.as_ref()
            != self.result_evidence.as_ref().map(|e| &e.reference)
        {
            return Err(StoreError::Conflict(
                "native witnessed turn original result evidence changed".into(),
            ));
        }
        if let Some(evidence) = &self.result_evidence {
            evidence.observe(vcs).map_err(|_| {
                StoreError::Conflict("native witnessed turn retained result unavailable".into())
            })?;
        }
        Ok(())
    }

    fn validate_payloads(
        &self,
        vcs: &NativeWorkspaceVcs,
        final_files: &BTreeMap<String, NativeTurnFileWitness>,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        validate_payloads(vcs, final_files, check)
    }

    /// Retain the complete exact result and its original base across the
    /// caller's product writer commit. No native mutation belongs in publish.
    pub fn publish_retained<T>(&self, publish: impl FnOnce() -> StoreResult<T>) -> StoreResult<T> {
        if self.cut.branch_id != self.target.engagement.branch {
            // An isolated creation receipt is not the current candidate custody
            // supplied by the existing recorded review/settlement publishers.
            return Err(StoreError::Conflict(
                "isolated original result requires recorded publication custody".into(),
            ));
        }
        let content = ContentStore::open_for_retained_publication(
            self.target.engagement.store_root.join("content.sqlite"),
        )?;
        // A cut names its whole immutable tree, including unchanged files.
        // Both sides of the original native operation must be available at
        // the product reference commit, not only the newly written subset.
        content.publish_retained(&self.retained(), || {
            let vcs = self.target.observe()?;
            self.observe_at(&vcs)?;
            publish()
        })
    }
}

impl NativeSettledTurn {
    pub fn review_diff(&self) -> Result<String> {
        let cut = self.applied.cut();
        let base = match &cut.parent_cut_id {
            Some(parent) => self
                .vcs
                .cut_manifest(parent)?
                .ok_or_else(|| refused("original settlement parent tree unavailable"))?,
            None => BTreeMap::new(),
        };
        let manifest = self
            .vcs
            .cut_manifest(&cut.cut_id)?
            .ok_or_else(|| refused("original settlement tree unavailable"))?;
        let diff = whipplescript_store::diff::diff_manifests(
            &base,
            &manifest,
            self.vcs.content_store(),
            3,
        )?;
        Ok(super::render_diff(&diff))
    }

    pub fn cut(&self) -> &CutRow {
        self.applied.cut()
    }

    pub fn operation(&self) -> &OpRow {
        self.applied.operation()
    }

    /// Consume the SAME original embedding writer in this callback, including
    /// its final check. No native mutation or new payload preparation belongs
    /// in the callback. Original result provenance remains a distinct cut.
    pub fn publish_retained<T>(
        &self,
        publish: impl FnOnce(&NativeWitnessedTurn, &CutRow, &OpRow) -> StoreResult<T>,
    ) -> StoreResult<T> {
        self.vcs
            .publish_recorded_settlement(&self.applied, |applied, vcs| {
                self.result.observe_at(vcs)?;
                if applied.cut().branch_id != self.result.destination() {
                    return Err(StoreError::Conflict(
                        "original native settlement target differs".into(),
                    ));
                }
                publish(&self.result, applied.cut(), applied.operation())
            })
    }
}

impl NativeHistoricalSettledTurn {
    pub fn review_diff(&self) -> Result<String> {
        let cut = self.history.cut();
        let base = match &cut.parent_cut_id {
            Some(parent) => self
                .vcs
                .cut_manifest(parent)?
                .ok_or_else(|| refused("original settlement parent tree unavailable"))?,
            None => BTreeMap::new(),
        };
        let manifest = self
            .vcs
            .cut_manifest(&cut.cut_id)?
            .ok_or_else(|| refused("original settlement tree unavailable"))?;
        let diff = whipplescript_store::diff::diff_manifests(
            &base,
            &manifest,
            self.vcs.content_store(),
            3,
        )?;
        Ok(super::render_diff(&diff))
    }

    pub fn cut(&self) -> &CutRow {
        self.history.cut()
    }

    pub fn operation(&self) -> &OpRow {
        self.history.operation()
    }

    /// Consume the SAME original embedding writer in this callback, including
    /// its final check. No native mutation or new payload preparation belongs
    /// in the callback. Original result provenance remains a distinct cut.
    pub fn publish_retained<T>(
        &self,
        publish: impl FnOnce(&NativeWitnessedTurn, &CutRow, &OpRow) -> StoreResult<T>,
    ) -> StoreResult<T> {
        self.vcs
            .publish_historical_recorded_settlement(&self.history, |history, vcs| {
                self.result.observe_at(vcs)?;
                if history.cut().branch_id != self.result.destination() {
                    return Err(StoreError::Conflict(
                        "original native settlement target differs".into(),
                    ));
                }
                publish(&self.result, history.cut(), history.operation())
            })
    }
}

impl NativeReviewedTurn {
    /// Apply the reviewed recorded candidate using the existing home-line
    /// gate and original check. Does not project or scan any filesystem.
    pub fn settle_guarded(
        self,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<NativeSettledTurn> {
        check()?;
        if matches!(
            self.review().outcome,
            RecordedMergeOutcome::Conflicted { .. }
        ) {
            return Err(refused("original native settlement candidate conflicts"));
        }
        let id = self.result.settlement_id()?;
        let review = self.review();
        let mut prepare_check = || {
            check().map_err(|_| {
                StoreError::Conflict("original native settlement authority ended".into())
            })?;
            let target = self.vcs.get_branch(&review.target_branch_id)?;
            if target.as_ref() != Some(&self.reviewed_target) {
                return Err(StoreError::Conflict(
                    "original reviewed native destination changed".into(),
                ));
            }
            Ok(())
        };
        let prepared = self.vcs.prepare_recorded_settlement(
            &self.result.cut.branch_id,
            &self.result.cut.cut_id,
            &self.result.retained(),
            &id,
            self.result.cut.actor.as_deref().expect("qualified actor"),
            self.result
                .cut
                .intent
                .as_deref()
                .expect("qualified command"),
            &self.result.cut.recorded_at,
            &mut prepare_check,
        )?;
        let mut native_check = || {
            check().map_err(|_| {
                StoreError::Conflict("original native settlement authority ended".into())
            })
        };
        let applied = match self.vcs.apply_prepared_recorded_settlement(
            &prepared,
            &mut native_check,
            &mut super::GaugeDeskMainlineGate,
        )? {
            RecordedSettlementOutcome::Applied(applied) => *applied,
            RecordedSettlementOutcome::GateRefused(_) => {
                return Err(refused("original native settlement gate refused"))
            }
            RecordedSettlementOutcome::GateStale { .. } => {
                return Err(refused("original native settlement gate stale"))
            }
        };
        check()?;
        Ok(NativeSettledTurn {
            result: self.result,
            applied,
            vcs: self.vcs,
        })
    }

    pub fn review_diff(&self) -> String {
        super::render_diff(&self.review().diff)
    }

    pub fn review(&self) -> &RecordedMergeReview {
        self.prepared.review()
    }

    /// Both native writers exclude cut/operation changes and content erasure
    /// through publication. The callback consumes the SAME original product
    /// writer, including its final authority check and task receipt. A product
    /// commit is not rolled back if closing a native fence subsequently fails.
    pub fn publish_retained<T>(
        &self,
        publish: impl FnOnce(&RecordedMergeReview, &NativeWitnessedTurn) -> StoreResult<T>,
    ) -> StoreResult<T> {
        self.vcs
            .publish_prepared_recorded_merge_review(&self.prepared, |review, vcs| {
                self.result.observe_at(vcs)?;
                if review.target_branch_id != self.result.destination() {
                    return Err(StoreError::Conflict(
                        "original native result target changed".into(),
                    ));
                }
                publish(review, &self.result)
            })
    }
}

impl TurnResultEvidence {
    fn new(
        target: &NativeWitnessedTurnTarget,
        witness: &[NativeTurnFileWitness],
        final_files: &BTreeMap<String, NativeTurnFileWitness>,
        runtime_cut: &str,
        actor: &str,
        command: &str,
    ) -> Result<Self> {
        let descriptor_body = serde_json::to_vec(&(
            "gaugedesk-witnessed-turn-result-v1",
            &target.engagement.branch,
            &target.base.cut_id,
            runtime_cut,
            actor,
            command,
            witness,
        ))
        .map_err(|_| refused("original turn result descriptor unavailable"))?;
        let descriptor = hex::encode(Sha256::digest(&descriptor_body))[..32].to_owned();
        let local_files: BTreeMap<_, _> = final_files
            .iter()
            .filter(|(_, entry)| {
                entry.path.starts_with("artifacts/") || entry.path.starts_with("work/")
            })
            .map(|(path, entry)| (path.clone(), entry.clone()))
            .collect();
        let mut root = BTreeMap::from([("original-descriptor".to_owned(), descriptor.clone())]);
        root.extend(
            local_files
                .iter()
                .filter(|(_, entry)| entry.kind != "delete")
                .map(|(path, entry)| (format!("payload:{path}"), entry.sha256[..32].to_owned())),
        );
        let root_body = serde_json::to_vec(&root)
            .map_err(|_| refused("original turn result root unavailable"))?;
        let reference = WriteEvidenceRef {
            schema_ref: "gaugedesk-witnessed-turn-result/v1".into(),
            label_ref: descriptor.clone(),
            content_hash: hex::encode(Sha256::digest(&root_body))[..32].to_owned(),
        };
        Ok(Self {
            reference,
            root_body,
            descriptor,
            descriptor_body,
            local_files,
        })
    }

    fn prepare(
        &self,
        vcs: &NativeWorkspaceVcs,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        if vcs.content_store().put(&self.descriptor_body)? != self.descriptor
            || vcs.content_store().put(&self.root_body)? != self.reference.content_hash
        {
            return Err(refused("original turn result preparation differs"));
        }
        check()?;
        self.observe(vcs)
    }

    fn observe(&self, vcs: &NativeWorkspaceVcs) -> Result<()> {
        if vcs
            .content_store()
            .get(&self.reference.content_hash)?
            .as_ref()
            != Some(&self.root_body)
            || vcs.content_store().get(&self.descriptor)?.as_ref() != Some(&self.descriptor_body)
        {
            return Err(refused("original turn result descriptor unavailable"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, kind: &str, bytes: &[u8]) -> NativeTurnFileWitness {
        NativeTurnFileWitness {
            path: path.into(),
            kind: kind.into(),
            sha256: hex::encode(Sha256::digest(bytes)),
            bytes: bytes.len() as u64,
        }
    }
    fn observed(eng: &Engagement) -> NativeWorkspaceVcs {
        NativeWorkspaceVcs::open_read_only(
            eng.store_root.join("branches.sqlite"),
            eng.store_root.join("content.sqlite"),
        )
        .unwrap()
    }
    fn setup() -> (tempfile::TempDir, Engagement, String) {
        let (root, instance) = crate::tests::instance();
        let eng = instance.create_engagement("witnessed-turn").unwrap();
        eng.write_file("preserved.txt", "recorded").unwrap();
        eng.write_file("removed.txt", "original deletion base")
            .unwrap();
        let base = eng.commit_turn("base").unwrap().unwrap().0;
        (root, eng, base)
    }

    #[test]
    fn isolated_saved_result_keeps_whole_original_branch_and_later_work() {
        let (_root, eng, base) = setup();
        let target = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .capture_original_lineage()
            .unwrap();
        let original = target.original_lineage().unwrap().clone();
        let parent = original.parent_branch_id.as_deref().unwrap();
        let witness = vec![
            file("result.txt", "add", b"first"),
            file("result.txt", "modify", b"saved final"),
            file("removed.txt", "delete", b""),
            file("artifacts/result.bin", "add", b"saved local\0\xff"),
        ];
        let bodies = BTreeMap::from([
            ("result.txt".into(), b"saved final".to_vec()),
            ("removed.txt".into(), vec![]),
            ("artifacts/result.bin".into(), b"saved local\0\xff".to_vec()),
        ]);
        eng.write_file("result.txt", "unsubmitted replacement")
            .unwrap();
        eng.write_file("pending.txt", "unsubmitted unrelated edit")
            .unwrap();
        let mut vcs = NativeWorkspaceVcs::open_for_recorded_review(
            eng.store_root.join("branches.sqlite"),
            eng.store_root.join("content.sqlite"),
        )
        .unwrap();
        vcs.create_branch("later-parent", None, parent, "later-parent")
            .unwrap();
        vcs.retarget(eng.branch(), "later-parent", "later-retarget")
            .unwrap();
        vcs.write(
            eng.branch(),
            "later.txt",
            Some("later source work"),
            "later-source",
            "later-source",
        )
        .unwrap();
        vcs.write(
            parent,
            "home-later.txt",
            Some("independent Home work"),
            "later-home",
            "later-home",
        )
        .unwrap();
        let before = vcs.get_branch(eng.branch()).unwrap();
        let import = || {
            target
                .clone()
                .import_saved_result_guarded(
                    &witness,
                    "original-runtime",
                    "original-staff",
                    "original-command",
                    &bodies,
                    &mut || Ok(()),
                )
                .unwrap()
        };
        let result = import();
        assert!(result
            .publish_retained::<()>(|| {
                panic!("isolated creation receipt reached unreviewed publication")
            })
            .is_err());
        assert_ne!(result.cut.branch_id, eng.branch());
        assert_eq!(result.destination(), parent);
        assert_eq!(
            result.manifest.get("preserved.txt"),
            result.base_manifest.get("preserved.txt")
        );
        assert!(!result.manifest.contains_key("removed.txt"));
        assert!(!result.manifest.contains_key("later.txt"));
        assert!(!result.manifest.contains_key("pending.txt"));
        assert!(!result.manifest.contains_key("artifacts/result.bin"));
        assert_eq!(
            result.local_files()["artifacts/result.bin"],
            witness[3].sha256[..32]
        );
        let cut = result.cut.clone();
        let op = result.op.clone();
        let candidate = result.cut.branch_id.clone();
        let reviewed = result
            .prepare_recorded_review_guarded(&mut || Ok(()))
            .unwrap();
        assert_eq!(reviewed.review().target_branch_id, parent);
        let settled = reviewed.settle_guarded(&mut || Ok(())).unwrap();
        settled
            .publish_retained(|native, _, _| {
                assert_eq!(native.cut, cut);
                Ok(())
            })
            .unwrap();
        assert_eq!(vcs.get_branch(eng.branch()).unwrap(), before);
        assert_eq!(
            vcs.read(parent, "preserved.txt").unwrap().as_deref(),
            Some("recorded")
        );
        assert_eq!(
            vcs.read(parent, "result.txt").unwrap().as_deref(),
            Some("saved final")
        );
        assert_eq!(
            vcs.read(parent, "home-later.txt").unwrap().as_deref(),
            Some("independent Home work")
        );
        assert!(vcs.read(parent, "later.txt").unwrap().is_none());
        assert!(vcs.read(parent, "removed.txt").unwrap().is_none());
        assert_eq!(
            eng.read_file("removed.txt").unwrap(),
            "original deletion base"
        );
        assert_eq!(
            eng.read_file("result.txt").unwrap(),
            "unsubmitted replacement"
        );
        assert_eq!(
            eng.read_file("pending.txt").unwrap(),
            "unsubmitted unrelated edit"
        );
        // Existing owner history may be reopened after later legitimate work.
        vcs.write(
            parent,
            "home-after.txt",
            Some("Home after settlement"),
            "home-after",
            "home-after",
        )
        .unwrap();
        vcs.write(
            &candidate,
            "candidate-after.txt",
            Some("candidate after settlement"),
            "candidate-after",
            "candidate-after",
        )
        .unwrap();
        let home_after = vcs.get_branch(parent).unwrap();
        let candidate_after = vcs.get_branch(&candidate).unwrap();
        drop(vcs);
        let retried = import();
        assert_eq!(retried.cut, cut);
        assert_eq!(retried.op, op);
        let history = match retried
            .recover_historical_settlement_guarded(&mut || Ok(()))
            .unwrap()
        {
            Ok(history) => history,
            Err(_) => panic!("original isolated settlement history missing"),
        };
        history.publish_retained(|_, _, _| Ok(())).unwrap();
        let reopened = observed(&eng);
        assert_eq!(reopened.get_branch(eng.branch()).unwrap(), before);
        assert_eq!(reopened.get_branch(parent).unwrap(), home_after);
        assert_eq!(reopened.get_branch(&candidate).unwrap(), candidate_after);
    }

    #[test]
    fn isolated_saved_result_refuses_changed_or_missing_bytes_and_meaning() {
        for case in [
            "missing",
            "extra",
            "length",
            "digest",
            "authority-ended",
            "changed-meaning",
        ] {
            let (_root, eng, base) = setup();
            let target = eng
                .witnessed_turn_target_at(&base)
                .unwrap()
                .capture_original_lineage()
                .unwrap();
            let mut witness = vec![
                file("result.txt", "add", b"earlier"),
                file("result.txt", "modify", b"original"),
            ];
            let mut bodies = BTreeMap::from([("result.txt".into(), b"original".to_vec())]);
            // A matching live file may never repair missing or changed saved bytes.
            eng.write_file("result.txt", "original").unwrap();
            if case == "changed-meaning" {
                target
                    .clone()
                    .import_saved_result_guarded(
                        &witness,
                        "original-runtime",
                        "original-staff",
                        "original-command",
                        &bodies,
                        &mut || Ok(()),
                    )
                    .unwrap();
                witness[0] = file("result.txt", "add", b"changed earlier witness");
            }
            let before = observed(&eng);
            let branches = before.list_branches(None).unwrap();
            let ops = before.list_ops(100).unwrap();
            let db = rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
            let cuts: i64 = db
                .query_row("SELECT COUNT(*) FROM cuts", [], |row| row.get(0))
                .unwrap();
            match case {
                "missing" => {
                    bodies.clear();
                }
                "extra" => {
                    bodies.insert("unwitnessed.txt".into(), b"extra".to_vec());
                }
                "length" => {
                    bodies.insert("result.txt".into(), b"longer body".to_vec());
                }
                "digest" => {
                    bodies.insert("result.txt".into(), b"changed!".to_vec());
                }
                _ => {}
            }
            let mut calls = 0;
            let result = target.import_saved_result_guarded(
                &witness,
                "original-runtime",
                "original-staff",
                "original-command",
                &bodies,
                &mut || {
                    calls += 1;
                    if case == "authority-ended" && calls >= 3 {
                        Err(refused("original task ended"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err(), "{case}");
            let after = observed(&eng);
            assert_eq!(after.list_branches(None).unwrap(), branches, "{case}");
            assert_eq!(after.list_ops(100).unwrap(), ops, "{case}");
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM cuts", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                cuts,
                "{case}"
            );
            assert_eq!(eng.read_file("result.txt").unwrap(), "original");
        }
    }

    #[test]
    fn original_lineage_retains_exact_topology_after_later_work_and_retarget() {
        let (_root, eng, base) = setup();
        let target = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .capture_original_lineage()
            .unwrap();
        let original = target.original_lineage().unwrap().clone();
        target
            .publish_startup_lineage_retained(|| {
                let db =
                    rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
                db.busy_timeout(std::time::Duration::ZERO).unwrap();
                let error = db
                    .execute(
                        "UPDATE branches SET updated_at='racing-update' WHERE branch_id=?1",
                        [eng.branch()],
                    )
                    .unwrap_err();
                assert_eq!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                );
                Ok(())
            })
            .unwrap();
        let mut vcs = NativeWorkspaceVcs::open_for_recorded_review(
            eng.store_root.join("branches.sqlite"),
            eng.store_root.join("content.sqlite"),
        )
        .unwrap();
        vcs.create_branch(
            "later-parent",
            None,
            original.parent_branch_id.as_deref().unwrap(),
            "later-parent-time",
        )
        .unwrap();
        vcs.retarget(eng.branch(), "later-parent", "later-retarget-time")
            .unwrap();
        vcs.write(
            eng.branch(),
            "later.txt",
            Some("later independently admitted work"),
            "later-work",
            "later-work-time",
        )
        .unwrap();
        let before = observed(&eng).get_branch(eng.branch()).unwrap().unwrap();
        assert_ne!(before.parent_branch_id, original.parent_branch_id);
        assert_ne!(before.head_cut_id, original.head_cut_id);
        assert!(eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .capture_original_lineage()
            .is_err());
        assert!(target.publish_startup_lineage_retained(|| Ok(())).is_err());
        let reopened = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .with_retained_lineage(original.clone())
            .unwrap();
        assert_eq!(reopened.original_lineage().unwrap(), &original);
        reopened.publish_base_retained(|| Ok(())).unwrap();
        assert_eq!(
            observed(&eng).get_branch(eng.branch()).unwrap().unwrap(),
            before
        );
        for case in ["source", "head", "hash", "parent", "divergence"] {
            let mut changed = original.clone();
            match case {
                "source" => changed.branch_id = "other-source".into(),
                "head" => changed.head_cut_id = before.head_cut_id.clone(),
                "hash" => changed.head_manifest_hash = Some("changed".into()),
                "parent" => changed.parent_branch_id = None,
                "divergence" => changed.branch_point_manifest_hash = Some("changed".into()),
                _ => unreachable!(),
            }
            assert!(
                eng.witnessed_turn_target_at(&base)
                    .unwrap()
                    .with_retained_lineage(changed)
                    .is_err(),
                "{case}"
            );
        }
    }

    fn original_result(eng: &Engagement, base: &str) -> NativeWitnessedTurn {
        eng.write_file("result.txt", "original result").unwrap();
        eng.write_file("artifacts/report.txt", "original local result")
            .unwrap();
        eng.witnessed_turn_target_at(base)
            .unwrap()
            .import_result_guarded(
                &[
                    file("result.txt", "add", b"original result"),
                    file("artifacts/report.txt", "add", b"original local result"),
                ],
                "owner-cut",
                "human:alice",
                "original-command",
                &mut || Ok(()),
            )
            .unwrap()
    }

    fn retry_original_result(eng: &Engagement, base: &str) -> NativeWitnessedTurn {
        eng.witnessed_turn_target_at(base)
            .unwrap()
            .import_result_guarded(
                &[
                    file("result.txt", "add", b"original result"),
                    file("artifacts/report.txt", "add", b"original local result"),
                ],
                "owner-cut",
                "human:alice",
                "original-command",
                &mut || Ok(()),
            )
            .unwrap()
    }

    #[test]
    fn historical_settlement_consumer_retains_original_evidence_after_later_native_work() {
        let (_root, eng, base) = setup();
        let settled = original_result(&eng, &base)
            .prepare_recorded_review_guarded(&mut || Ok(()))
            .unwrap()
            .settle_guarded(&mut || Ok(()))
            .unwrap();
        let original_cut = settled.cut().clone();
        let original_operation = settled.operation().clone();
        let original_result_cut = settled.result.cut().to_owned();
        assert_ne!(original_result_cut, original_cut.cut_id);
        let mut vcs = NativeWorkspaceVcs::open_for_recorded_review(
            eng.store_root.join("branches.sqlite"),
            eng.store_root.join("content.sqlite"),
        )
        .unwrap();
        vcs.write(
            eng.branch(),
            "later-source.txt",
            Some("later source collaboration"),
            "later-source",
            "later1",
        )
        .unwrap();
        vcs.write(
            eng.target.as_str(),
            "later-main.txt",
            Some("later shared collaboration"),
            "later-main",
            "later2",
        )
        .unwrap();
        eng.write_file("result.txt", "unsubmitted replacement")
            .unwrap();
        eng.write_file("artifacts/report.txt", "unsubmitted local replacement")
            .unwrap();
        assert!(retry_original_result(&eng, &base)
            .recover_settlement_guarded(&mut || Ok(()))
            .is_err());
        assert!(retry_original_result(&eng, &base)
            .recover_historical_settlement_guarded(&mut || Err(refused("original access expired")),)
            .is_err());
        let history = match retry_original_result(&eng, &base)
            .recover_historical_settlement_guarded(&mut || Ok(()))
            .unwrap()
        {
            Ok(history) => history,
            Err(_) => panic!("original settlement history not recovered"),
        };
        assert_eq!(history.cut(), &original_cut);
        assert_eq!(history.operation(), &original_operation);
        assert!(history.review_diff().unwrap().contains("original result"));
        assert!(!history
            .review_diff()
            .unwrap()
            .contains("unsubmitted replacement"));
        // More work after recovery must also remain intact through publication.
        vcs.write(
            eng.target.as_str(),
            "later-again.txt",
            Some("newer shared collaboration"),
            "later-again",
            "later3",
        )
        .unwrap();
        let heads = [
            vcs.get_branch(eng.branch()).unwrap(),
            vcs.get_branch(eng.target.as_str()).unwrap(),
        ];
        let branches = rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        let content = rusqlite::Connection::open(eng.store_root.join("content.sqlite")).unwrap();
        branches.busy_timeout(std::time::Duration::ZERO).unwrap();
        content.busy_timeout(std::time::Duration::ZERO).unwrap();
        history
            .publish_retained(|result, cut, operation| {
                assert_eq!(result.cut(), original_result_cut);
                assert_eq!(cut, &original_cut);
                assert_eq!(operation, &original_operation);
                assert!(branches.execute_batch("BEGIN IMMEDIATE").is_err());
                assert!(content.execute_batch("BEGIN IMMEDIATE").is_err());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            [
                vcs.get_branch(eng.branch()).unwrap(),
                vcs.get_branch(eng.target.as_str()).unwrap()
            ],
            heads
        );
        assert_eq!(
            eng.read_file("result.txt").unwrap(),
            "unsubmitted replacement"
        );
        assert_eq!(
            eng.read_file("artifacts/report.txt").unwrap(),
            "unsubmitted local replacement"
        );
        // Actual original authority loss inside both native writers refuses recovery.
        assert!(retry_original_result(&eng, &base)
            .recover_historical_settlement_guarded(&mut || {
                if branches.execute_batch("BEGIN IMMEDIATE").is_err() {
                    assert!(content.execute_batch("BEGIN IMMEDIATE").is_err());
                    return Err(refused(
                        "original access ended inside historical publication",
                    ));
                }
                branches.execute_batch("ROLLBACK").unwrap();
                Ok(())
            })
            .is_err());
        assert_eq!(
            [
                vcs.get_branch(eng.branch()).unwrap(),
                vcs.get_branch(eng.target.as_str()).unwrap()
            ],
            heads
        );
        branches
            .execute("DELETE FROM ops WHERE op_id=?1", [&history.result.op.op_id])
            .unwrap();
        assert!(history
            .publish_retained::<()>(|_, _, _| {
                panic!("missing original result operation published as history")
            })
            .is_err());
    }

    #[test]
    fn original_settlement_keeps_provenance_pending_files_and_both_native_fences() {
        let (_root, eng, base) = setup();
        let result = original_result(&eng, &base);
        let original = result.cut().to_owned();
        eng.write_file("pending.txt", "never submitted").unwrap();
        let settled = result
            .prepare_recorded_review_guarded(&mut || Ok(()))
            .unwrap()
            .settle_guarded(&mut || Ok(()))
            .unwrap();
        let cut = settled.cut().cut_id.clone();
        assert_ne!(cut, original);
        assert_eq!(settled.cut().actor.as_deref(), Some("human:alice"));
        assert_eq!(settled.cut().intent.as_deref(), Some("original-command"));
        assert_eq!(settled.operation().kind, "merge-keep");
        let vcs = observed(&eng);
        for branch in [eng.branch(), eng.target.as_str()] {
            assert_eq!(
                vcs.get_branch(branch)
                    .unwrap()
                    .unwrap()
                    .head_cut_id
                    .as_deref(),
                Some(cut.as_str())
            );
        }
        let manifest = vcs.cut_manifest(&cut).unwrap().unwrap();
        assert!(manifest.contains_key("result.txt"));
        assert!(!manifest.contains_key("pending.txt"));
        assert!(!manifest.contains_key("artifacts/report.txt"));
        assert_eq!(eng.read_file("pending.txt").unwrap(), "never submitted");
        let branches = rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        let content = rusqlite::Connection::open(eng.store_root.join("content.sqlite")).unwrap();
        branches.busy_timeout(std::time::Duration::ZERO).unwrap();
        content.busy_timeout(std::time::Duration::ZERO).unwrap();
        settled
            .publish_retained(|result, recorded, op| {
                assert_eq!(result.cut(), original);
                assert_eq!(recorded.cut_id, cut);
                assert_eq!(op.op_id, format!("op-{cut}"));
                assert!(branches.execute_batch("BEGIN IMMEDIATE").is_err());
                assert!(content.execute_batch("BEGIN IMMEDIATE").is_err());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn original_settlement_recovery_never_reimports_or_reapplies_and_requires_authority() {
        let (_root, eng, base) = setup();
        let settled = original_result(&eng, &base)
            .prepare_recorded_review_guarded(&mut || Ok(()))
            .unwrap()
            .settle_guarded(&mut || Ok(()))
            .unwrap();
        let before = settled.operation().clone();
        // A native commit survives an embedding refusal. Retry uses retained
        // original bytes even after both result and local output have changed.
        assert!(settled
            .publish_retained::<()>(|_, _, _| Err(StoreError::Conflict("embedding refused".into())))
            .is_err());
        eng.write_file("result.txt", "new unsubmitted edit")
            .unwrap();
        eng.write_file("artifacts/report.txt", "new local edit")
            .unwrap();
        let recovered = match retry_original_result(&eng, &base)
            .recover_settlement_guarded(&mut || Ok(()))
            .unwrap()
        {
            Ok(settled) => settled,
            Err(_) => panic!("original native settlement not recovered"),
        };
        assert_eq!(recovered.operation(), &before);
        assert_eq!(eng.read_file("result.txt").unwrap(), "new unsubmitted edit");
        assert!(retry_original_result(&eng, &base)
            .recover_settlement_guarded(&mut || Err(refused("original authority ended")))
            .is_err());
        assert_eq!(
            observed(&eng).get_op(&before.op_id).unwrap().as_ref(),
            Some(&before)
        );
    }

    #[test]
    fn original_settlement_refuses_changed_reviewed_destination_without_moving_source() {
        let (_root, eng, base) = setup();
        let result = original_result(&eng, &base);
        let source = observed(&eng).get_branch(eng.branch()).unwrap();
        let reviewed = result
            .prepare_recorded_review_guarded(&mut || Ok(()))
            .unwrap();
        let conn = rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        conn.execute(
            "UPDATE branches SET updated_at = 'changed reviewed row' WHERE branch_id = ?1",
            [&eng.target],
        )
        .unwrap();
        assert!(reviewed.settle_guarded(&mut || Ok(())).is_err());
        assert_eq!(observed(&eng).get_branch(eng.branch()).unwrap(), source);
    }

    #[test]
    fn recorded_result_review_holds_both_native_writers_without_importing_pending_work() {
        let (_root, eng, base) = setup();
        let result = original_result(&eng, &base);
        eng.write_file("pending.txt", "never submitted").unwrap();
        let branches = rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        let content = rusqlite::Connection::open(eng.store_root.join("content.sqlite")).unwrap();
        branches.busy_timeout(std::time::Duration::ZERO).unwrap();
        content.busy_timeout(std::time::Duration::ZERO).unwrap();
        let reviewed = result
            .prepare_recorded_review_guarded(&mut || Ok(()))
            .unwrap();
        let before = observed(&eng).get_branch(eng.branch()).unwrap();
        reviewed
            .publish_retained(|review, original| {
                assert!(branches.execute_batch("BEGIN IMMEDIATE").is_err());
                assert!(content.execute_batch("BEGIN IMMEDIATE").is_err());
                assert_eq!(review.head_cut_id, original.cut());
                assert_eq!(review.target_branch_id, eng.target());
                assert!(review.diff.iter().any(|entry| entry.path == "result.txt"));
                assert!(!review.diff.iter().any(
                    |entry| entry.path == "pending.txt" || entry.path.starts_with("artifacts/")
                ));
                assert!(original.local_files().contains_key("artifacts/report.txt"));
                Ok(())
            })
            .unwrap();
        assert_eq!(observed(&eng).get_branch(eng.branch()).unwrap(), before);
        assert_eq!(eng.read_file("pending.txt").unwrap(), "never submitted");
        assert!(!observed(&eng)
            .cut_manifest(reviewed.review().head_cut_id.as_str())
            .unwrap()
            .unwrap()
            .contains_key("pending.txt"));
        branches.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
        content.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
    }

    #[test]
    fn prepared_result_review_refuses_changed_original_evidence_and_target() {
        for case in [
            "operation",
            "result-reference",
            "local-payload",
            "unchanged-base",
            "retarget",
            "head",
        ] {
            let (_root, eng, base) = setup();
            let result = original_result(&eng, &base);
            let reviewed = result
                .prepare_recorded_review_guarded(&mut || Ok(()))
                .unwrap();
            let branches =
                rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
            let content =
                ContentStore::open_existing(eng.store_root.join("content.sqlite")).unwrap();
            match case {
                "operation" => {
                    branches
                        .execute(
                            "DELETE FROM ops WHERE op_id=?1",
                            [&reviewed.result.op.op_id],
                        )
                        .unwrap();
                }
                "result-reference" => {
                    branches
                        .execute(
                            "DELETE FROM cut_evidence WHERE cut_id=?1",
                            [reviewed.result.cut()],
                        )
                        .unwrap();
                }
                "local-payload" => {
                    content
                        .erase(
                            &reviewed.result.local_files()["artifacts/report.txt"],
                            "now",
                        )
                        .unwrap();
                }
                "unchanged-base" => {
                    content
                        .erase(&reviewed.result.base_manifest["preserved.txt"], "now")
                        .unwrap();
                }
                "retarget" => {
                    branches.execute("UPDATE branches SET parent_branch_id='another-target' WHERE branch_id=?1", [eng.branch()]).unwrap();
                }
                "head" => {
                    eng.write_file("later.txt", "later turn").unwrap();
                    eng.commit_turn("later").unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                reviewed
                    .publish_retained::<()>(|_, _| panic!(
                        "changed original result published: {case}"
                    ))
                    .is_err(),
                "{case}"
            );
        }
    }

    #[test]
    fn recorded_result_preparation_requires_complete_evidence_and_original_guard() {
        let (_root, eng, base) = setup();
        let result = original_result(&eng, &base);
        assert!(result
            .prepare_recorded_review_guarded(&mut || Err(refused("original authority ended")))
            .is_err());
        let (_root, eng, base) = setup();
        eng.write_file("result.txt", "original result").unwrap();
        let result = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(
                &[file("result.txt", "add", b"original result")],
                "owner-cut",
                "human:alice",
                "original-command",
                &mut || Ok(()),
            )
            .unwrap();
        assert!(result
            .prepare_recorded_review_guarded(&mut || Ok(()))
            .is_err());
    }

    #[test]
    fn native_startup_empty_base_never_imports_or_rewrites_pending_files() {
        let (_root, instance) = crate::tests::instance();
        let eng = instance.create_engagement("startup-empty").unwrap();
        let before = observed(&eng).get_branch(eng.branch()).unwrap().unwrap();
        assert!(before.head_cut_id.is_none());
        eng.write_file("pending.txt", "unrecorded edit").unwrap();
        eng.write_file("artifacts/report.txt", "unrecorded artifact")
            .unwrap();
        let target = eng
            .witnessed_turn_start_guarded("human:alice", "original-command", &mut || Ok(()))
            .unwrap();
        assert!(target.base_cut().starts_with("witnessed-turn-base-"));
        assert!(observed(&eng)
            .cut_manifest(target.base_cut())
            .unwrap()
            .unwrap()
            .is_empty());
        assert_eq!(target.base.parent_cut_id, None);
        assert_eq!(target.base.actor.as_deref(), Some("human:alice"));
        assert_eq!(target.base.intent.as_deref(), Some("original-command"));
        assert!(target.base_op.is_some());
        assert_eq!(eng.read_file("pending.txt").unwrap(), "unrecorded edit");
        assert_eq!(
            eng.read_file("artifacts/report.txt").unwrap(),
            "unrecorded artifact"
        );
        let head = observed(&eng).get_branch(eng.branch()).unwrap().unwrap();
        let again = eng
            .witnessed_turn_start_guarded("human:alice", "original-command", &mut || Ok(()))
            .unwrap();
        assert_eq!(again.base, target.base);
        assert_eq!(
            observed(&eng).get_branch(eng.branch()).unwrap().unwrap(),
            head
        );
        target
            .publish_base_retained(|| {
                for name in ["content.sqlite", "branches.sqlite"] {
                    let competitor = rusqlite::Connection::open(eng.store_root.join(name)).unwrap();
                    competitor.busy_timeout(std::time::Duration::ZERO).unwrap();
                    assert!(
                        competitor.execute_batch("BEGIN IMMEDIATE").is_err(),
                        "{name} escaped original startup publication"
                    );
                }
                Ok(())
            })
            .unwrap();
        eng.write_file("result.txt", "original model result")
            .unwrap();
        let result = target
            .import_result_guarded(
                &[file("result.txt", "add", b"original model result")],
                "owner-cut",
                "human:alice",
                "original-command",
                &mut || Ok(()),
            )
            .unwrap();
        let manifest = observed(&eng).cut_manifest(result.cut()).unwrap().unwrap();
        assert_eq!(manifest.len(), 1);
        assert!(manifest.contains_key("result.txt"));
        assert_eq!(eng.read_file("pending.txt").unwrap(), "unrecorded edit");
    }

    #[test]
    fn native_startup_anchors_inherited_tree_and_preserves_owned_recorded_base() {
        let (_root, instance) = crate::tests::instance();
        let source = instance.create_engagement("source").unwrap();
        source
            .write_file("recorded.txt", "original recorded bytes")
            .unwrap();
        let source_cut = source.commit_turn("source base").unwrap().unwrap().0;
        let eng = instance
            .fork_engagement_at(
                "startup-inherited",
                source.branch(),
                source.target(),
                &source_cut,
            )
            .unwrap();
        let inherited = observed(&eng).get_branch(eng.branch()).unwrap().unwrap();
        assert_eq!(inherited.head_cut_id.as_deref(), Some(source_cut.as_str()));
        eng.write_file("recorded.txt", "pending changed bytes")
            .unwrap();
        eng.write_file("unrelated.txt", "unsubmitted addition")
            .unwrap();
        let target = eng
            .witnessed_turn_start_guarded("human:alice", "command", &mut || Ok(()))
            .unwrap();
        assert_eq!(
            target.base.parent_cut_id.as_deref(),
            Some(source_cut.as_str())
        );
        assert_eq!(
            observed(&eng).cut_manifest(target.base_cut()).unwrap(),
            observed(&eng).cut_manifest(&source_cut).unwrap()
        );
        assert_eq!(
            eng.read_file("recorded.txt").unwrap(),
            "pending changed bytes"
        );
        target.publish_base_retained(|| Ok(())).unwrap();
        let cut = target.base.cut_id.clone();
        let captured = eng
            .witnessed_turn_start_guarded("human:bob", "fresh-command", &mut || Ok(()))
            .unwrap();
        assert_eq!(captured.base.cut_id, cut);
        assert_eq!(captured.base_op, target.base_op);
    }

    #[test]
    fn native_startup_final_guard_is_inside_writer_and_refuses_without_anchor() {
        let (_root, instance) = crate::tests::instance();
        let eng = instance.create_engagement("startup-guard").unwrap();
        let before = observed(&eng).get_branch(eng.branch()).unwrap();
        let competitor =
            rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        competitor.busy_timeout(std::time::Duration::ZERO).unwrap();
        let mut inside = false;
        let result = eng.witnessed_turn_start_guarded("human:alice", "command", &mut || {
            if competitor.execute_batch("BEGIN IMMEDIATE").is_err() {
                inside = true;
                return Err(refused("original access ended at startup native commit"));
            }
            competitor.execute_batch("ROLLBACK").unwrap();
            Ok(())
        });
        assert!(result.is_err());
        assert!(inside);
        assert_eq!(observed(&eng).get_branch(eng.branch()).unwrap(), before);
        let db = rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM cuts WHERE cut_id LIKE 'witnessed-turn-base-%'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM ops WHERE op_id LIKE 'op-witnessed-turn-base-%'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn native_startup_refuses_another_process_moving_its_original_branch() {
        let (_root, instance) = crate::tests::instance();
        let eng = instance.create_engagement("startup-racing").unwrap();
        let mut competitor = NativeWorkspaceVcs::from_parts(
            BranchStore::open(eng.store_root.join("branches.sqlite")).unwrap(),
            ContentStore::open_existing(eng.store_root.join("content.sqlite")).unwrap(),
        );
        let mut calls = 0;
        assert!(eng
            .witnessed_turn_start_guarded("human:alice", "command", &mut || {
                calls += 1;
                if calls == 2 {
                    competitor
                        .import_diff(
                            eng.branch(),
                            &BTreeMap::new(),
                            &[],
                            "independent-native-cut",
                            &super::super::now_at(),
                        )
                        .unwrap();
                }
                Ok(())
            })
            .is_err());
        assert!(calls >= 2);
        assert_eq!(
            observed(&eng)
                .get_branch(eng.branch())
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("independent-native-cut")
        );
        let db = rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM cuts WHERE cut_id LIKE 'witnessed-turn-base-%'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn native_startup_base_publication_refuses_erased_payload_or_missing_original_anchor_operation()
    {
        for missing in ["payload", "operation", "manifest", "operation-shape"] {
            let (_root, instance) = crate::tests::instance();
            let source = instance.create_engagement("source").unwrap();
            source
                .write_file("recorded.txt", "original recorded bytes")
                .unwrap();
            let source_cut = source.commit_turn("source base").unwrap().unwrap().0;
            let eng = instance
                .fork_engagement_at(
                    "startup-inherited",
                    source.branch(),
                    source.target(),
                    &source_cut,
                )
                .unwrap();
            let target = eng
                .witnessed_turn_start_guarded("human:alice", "command", &mut || Ok(()))
                .unwrap();
            let manifest = observed(&eng)
                .cut_manifest(target.base_cut())
                .unwrap()
                .unwrap();
            match missing {
                "payload" => {
                    ContentStore::open_existing(eng.store_root.join("content.sqlite"))
                        .unwrap()
                        .erase(&manifest["recorded.txt"], "now")
                        .unwrap();
                }
                "manifest" => {
                    ContentStore::open_existing(eng.store_root.join("content.sqlite"))
                        .unwrap()
                        .erase(&target.base.manifest_hash, "now")
                        .unwrap();
                }
                "operation-shape" => {
                    rusqlite::Connection::open(eng.store_root.join("branches.sqlite"))
                        .unwrap()
                        .execute(
                            "UPDATE ops SET kind='different' WHERE op_id=?1",
                            [&target.base_op.as_ref().unwrap().op_id],
                        )
                        .unwrap();
                }
                "operation" => {
                    rusqlite::Connection::open(eng.store_root.join("branches.sqlite"))
                        .unwrap()
                        .execute(
                            "DELETE FROM ops WHERE op_id=?1",
                            [&target.base_op.as_ref().unwrap().op_id],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let before = observed(&eng).get_branch(eng.branch()).unwrap();
            assert!(
                target
                    .publish_base_retained::<()>(|| panic!(
                        "incomplete original startup base published: {missing}"
                    ))
                    .is_err(),
                "{missing}"
            );
            assert_eq!(observed(&eng).get_branch(eng.branch()).unwrap(), before);
            if matches!(missing, "operation" | "operation-shape") {
                assert!(eng
                    .witnessed_turn_start_guarded("human:alice", "command", &mut || Ok(()))
                    .is_err());
            }
        }
    }

    #[test]
    fn another_native_process_cannot_replace_the_original_base_during_preparation() {
        let (_root, eng, base) = setup();
        eng.write_file("later.txt", "later recorded work").unwrap();
        let later = eng.commit_turn("later work").unwrap().unwrap().0;
        let later_cut = observed(&eng).get_cut(&later).unwrap().unwrap();
        let base_cut = observed(&eng).get_cut(&base).unwrap().unwrap();
        let db = rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        db.execute(
            "UPDATE branches SET head_cut_id=?1, head_manifest_hash=?2 WHERE branch_id=?3",
            [&base, &base_cut.manifest_hash, eng.branch()],
        )
        .unwrap();
        eng.write_file("artifacts/report.txt", "original result")
            .unwrap();
        let witness = [file("artifacts/report.txt", "add", b"original result")];
        let target = eng.witnessed_turn_target_at(&base).unwrap();
        let planned = target
            .plan_result(&witness, "owner-cut", "human:alice", "command", true)
            .unwrap()
            .0;
        let mut calls = 0;
        let result = target.import_result_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
            calls += 1;
            if calls == 3 {
                db.execute("UPDATE branches SET head_cut_id=?1, head_manifest_hash=?2 WHERE branch_id=?3",
                    [&later, &later_cut.manifest_hash, eng.branch()]).unwrap();
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(calls >= 3);
        let vcs = observed(&eng);
        assert_eq!(
            vcs.get_branch(eng.branch())
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some(later.as_str())
        );
        assert!(vcs.get_cut(&planned).unwrap().is_none());
        assert!(vcs.get_op(&format!("op-{planned}")).unwrap().is_none());
        assert!(vcs.write_evidence(&planned).unwrap().is_none());
    }

    #[test]
    fn complete_original_results_survive_collection_and_replay_without_live_files() {
        let (_root, eng, base) = setup();
        let binary = vec![0xfe; 9 * 1024 * 1024];
        std::fs::create_dir_all(eng.path.join("artifacts")).unwrap();
        std::fs::write(eng.path.join("artifacts/report.bin"), &binary).unwrap();
        eng.write_file("work/analysis.txt", "original analysis")
            .unwrap();
        eng.write_file("project.txt", "project result").unwrap();
        let witness = [
            file("artifacts/report.bin", "add", b"intermediate"),
            file("artifacts/report.bin", "modify", &binary),
            file("work/analysis.txt", "add", b"original analysis"),
            file("work/deleted.txt", "delete", b""),
            file("project.txt", "add", b"project result"),
        ];
        let result = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_result_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                Ok(())
            })
            .unwrap();
        let reference = result.result_evidence().unwrap().clone();
        assert_eq!(result.files().len(), 1);
        assert_eq!(result.local_files().len(), 2);
        assert_eq!(result.local_removed(), ["work/deleted.txt"]);
        let mut vcs = NativeWorkspaceVcs::from_parts(
            BranchStore::open(eng.store_root.join("branches.sqlite")).unwrap(),
            ContentStore::open_existing(eng.store_root.join("content.sqlite")).unwrap(),
        );
        let manifest = vcs.cut_manifest(result.cut()).unwrap().unwrap();
        assert!(manifest.keys().all(|p| valid_native_action_target_path(p)));
        let orphan = vcs
            .content_store()
            .put(b"unrooted synthetic bytes")
            .unwrap();
        vcs.purge_unreachable(&super::super::now_at()).unwrap();
        assert!(vcs.content_store().get(&orphan).unwrap().is_none());
        assert_eq!(
            vcs.write_evidence(result.cut()).unwrap(),
            Some(reference.clone())
        );
        assert_eq!(
            vcs.content_store()
                .get(&result.local_files()["artifacts/report.bin"])
                .unwrap()
                .unwrap(),
            binary
        );
        let competitor = rusqlite::Connection::open(eng.store_root.join("content.sqlite")).unwrap();
        competitor.busy_timeout(std::time::Duration::ZERO).unwrap();
        result
            .publish_retained(|| {
                assert!(competitor.execute_batch("BEGIN IMMEDIATE").is_err());
                Ok(())
            })
            .unwrap();
        eng.write_file("artifacts/report.bin", "later artifact")
            .unwrap();
        eng.write_file("project.txt", "later project work").unwrap();
        eng.commit_turn("later authorized work").unwrap();
        let later = observed(&eng).get_branch(eng.branch()).unwrap().unwrap();
        std::fs::remove_dir_all(&eng.path).unwrap();
        let retry = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_result_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                Ok(())
            })
            .unwrap();
        assert_eq!(retry.cut, result.cut);
        assert_eq!(retry.op, result.op);
        assert_eq!(retry.result_evidence(), Some(&reference));
        retry.publish_retained(|| Ok(())).unwrap();
        assert_eq!(
            observed(&eng).get_branch(eng.branch()).unwrap().unwrap(),
            later
        );
        assert!(!eng.path.exists());
    }

    #[test]
    fn artifact_only_results_bind_empty_project_diff_and_cannot_change_original_meaning() {
        let (_root, eng, base) = setup();
        eng.write_file("artifacts/report.txt", "original result")
            .unwrap();
        let witness = [file("artifacts/report.txt", "add", b"original result")];
        let result = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_result_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                Ok(())
            })
            .unwrap();
        assert!(result.files().is_empty());
        assert_eq!(
            observed(&eng).cut_manifest(result.cut()).unwrap(),
            observed(&eng).cut_manifest(&base).unwrap()
        );
        let before = observed(&eng).get_branch(eng.branch()).unwrap();
        for (runtime, actor, command) in [
            ("different-owner", "human:alice", "command"),
            ("owner-cut", "human:bob", "command"),
            ("owner-cut", "human:alice", "different-command"),
        ] {
            assert!(eng
                .witnessed_turn_target_at(&base)
                .unwrap()
                .import_result_guarded(&witness, runtime, actor, command, &mut || Ok(()))
                .is_err());
        }
        assert!(eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut || Ok(
                ()
            ))
            .is_err());
        assert_eq!(observed(&eng).get_branch(eng.branch()).unwrap(), before);
    }

    #[test]
    fn missing_or_changed_original_result_evidence_never_publishes_or_reconstructs() {
        for case in [
            "label",
            "schema",
            "reference",
            "row",
            "root",
            "descriptor",
            "payload",
        ] {
            let (_root, eng, base) = setup();
            eng.write_file("artifacts/report.txt", "original result")
                .unwrap();
            let witness = [file("artifacts/report.txt", "add", b"original result")];
            let result = eng
                .witnessed_turn_target_at(&base)
                .unwrap()
                .import_result_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                    Ok(())
                })
                .unwrap();
            let evidence = result.result_evidence.as_ref().unwrap();
            let db = rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
            let content =
                ContentStore::open_existing(eng.store_root.join("content.sqlite")).unwrap();
            match case {
                "label" => {
                    db.execute(
                        "UPDATE cut_evidence SET label_ref='different' WHERE cut_id=?1",
                        [result.cut()],
                    )
                    .unwrap();
                }
                "schema" => {
                    db.execute(
                        "UPDATE cut_evidence SET schema_ref='different' WHERE cut_id=?1",
                        [result.cut()],
                    )
                    .unwrap();
                }
                "reference" => {
                    db.execute(
                        "UPDATE cut_evidence SET content_hash='different' WHERE cut_id=?1",
                        [result.cut()],
                    )
                    .unwrap();
                }
                "row" => {
                    db.execute("DELETE FROM cut_evidence WHERE cut_id=?1", [result.cut()])
                        .unwrap();
                }
                "root" => {
                    content
                        .erase(&evidence.reference.content_hash, "now")
                        .unwrap();
                }
                "descriptor" => {
                    content.erase(&evidence.descriptor, "now").unwrap();
                }
                "payload" => {
                    content
                        .erase(&result.local_files()["artifacts/report.txt"], "now")
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let before = observed(&eng).get_branch(eng.branch()).unwrap();
            assert!(
                result
                    .publish_retained::<()>(|| panic!(
                        "incomplete original result published: {case}"
                    ))
                    .is_err(),
                "{case}"
            );
            assert!(
                eng.witnessed_turn_target_at(&base)
                    .unwrap()
                    .import_result_guarded(
                        &witness,
                        "owner-cut",
                        "human:alice",
                        "command",
                        &mut || Ok(())
                    )
                    .is_err(),
                "{case}"
            );
            assert_eq!(
                observed(&eng).get_branch(eng.branch()).unwrap(),
                before,
                "{case}"
            );
            assert_eq!(
                eng.read_file("artifacts/report.txt").unwrap(),
                "original result"
            );
        }
    }

    #[test]
    fn complete_result_guard_refuses_inside_native_writer_without_rooting_preparation() {
        let (_root, eng, base) = setup();
        eng.write_file("artifacts/report.txt", "original result")
            .unwrap();
        let witness = [file("artifacts/report.txt", "add", b"original result")];
        let target = eng.witnessed_turn_target_at(&base).unwrap();
        let planned = target
            .plan_result(&witness, "owner-cut", "human:alice", "command", true)
            .unwrap()
            .0;
        let competitor =
            rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        competitor.busy_timeout(std::time::Duration::ZERO).unwrap();
        let mut inside = false;
        let result = target.import_result_guarded(
            &witness,
            "owner-cut",
            "human:alice",
            "command",
            &mut || {
                if competitor.execute_batch("BEGIN IMMEDIATE").is_err() {
                    inside = true;
                    return Err(refused("original access ended"));
                }
                competitor.execute_batch("ROLLBACK").unwrap();
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(inside);
        let mut vcs = NativeWorkspaceVcs::from_parts(
            BranchStore::open(eng.store_root.join("branches.sqlite")).unwrap(),
            ContentStore::open_existing(eng.store_root.join("content.sqlite")).unwrap(),
        );
        assert_eq!(
            vcs.get_branch(eng.branch())
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some(base.as_str())
        );
        assert!(vcs.get_cut(&planned).unwrap().is_none());
        assert!(vcs.get_op(&format!("op-{planned}")).unwrap().is_none());
        assert!(vcs.write_evidence(&planned).unwrap().is_none());
        vcs.purge_unreachable(&super::super::now_at()).unwrap();
        assert!(vcs
            .content_store()
            .get(&witness[0].sha256[..32])
            .unwrap()
            .is_none());
    }

    #[test]
    fn unrooted_local_result_descriptors_are_not_durable_native_versions() {
        let (_root, eng, base) = setup();
        let content = ContentStore::open_existing(eng.store_root.join("content.sqlite")).unwrap();
        let artifact = content.put(b"synthetic original artifact").unwrap();
        let descriptor = content
            .put(
                serde_json::to_string(&BTreeMap::from([(
                    "artifacts/report.txt",
                    artifact.clone(),
                )]))
                .unwrap()
                .as_bytes(),
            )
            .unwrap();
        eng.write_file("artifacts/report.txt", "later synthetic artifact")
            .unwrap();
        let mut vcs = NativeWorkspaceVcs::from_parts(
            BranchStore::open(eng.store_root.join("branches.sqlite")).unwrap(),
            ContentStore::open_existing(eng.store_root.join("content.sqlite")).unwrap(),
        );
        assert!(vcs.content_store().get(&descriptor).unwrap().is_some());
        assert!(vcs.content_store().get(&artifact).unwrap().is_some());
        vcs.purge_unreachable(&super::super::now_at()).unwrap();
        assert!(vcs.content_store().get(&descriptor).unwrap().is_none());
        assert!(vcs.content_store().get(&artifact).unwrap().is_none());
        assert_eq!(
            eng.read_file("artifacts/report.txt").unwrap(),
            "later synthetic artifact"
        );
        assert!(vcs.get_cut(&base).unwrap().is_some());
        assert!(vcs
            .cut_manifest(&base)
            .unwrap()
            .unwrap()
            .contains_key("preserved.txt"));
    }

    #[test]
    fn whole_witness_import_keeps_original_base_and_unrelated_pending_files() {
        let (_root, eng, base) = setup();
        eng.write_file("preserved.txt", "unrelated pending edit")
            .unwrap();
        eng.write_file("unrelated.txt", "unrelated pending addition")
            .unwrap();
        let bytes = vec![0xff; 9 * 1024 * 1024];
        std::fs::write(eng.path.join("result.bin"), &bytes).unwrap();
        eng.write_file("result.txt", "final synthetic result")
            .unwrap();
        std::fs::remove_file(eng.path.join("removed.txt")).unwrap();
        let witness = vec![
            file("result.txt", "add", b"intermediate"),
            file("result.txt", "modify", b"final synthetic result"),
            file("result.bin", "add", &bytes),
            file("removed.txt", "delete", b""),
        ];
        let result = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(
                &witness,
                "original-owner-witness",
                "human:alice",
                "original-command",
                &mut || Ok(()),
            )
            .unwrap();
        let vcs = observed(&eng);
        let manifest = vcs.cut_manifest(result.cut()).unwrap().unwrap();
        assert_eq!(
            manifest["preserved.txt"],
            whipplescript_store::stable_hash_hex("recorded")
        );
        assert!(!manifest.contains_key("unrelated.txt"));
        assert!(!manifest.contains_key("removed.txt"));
        assert_eq!(result.files().len(), 2);
        assert_eq!(result.removed(), &["removed.txt"]);
        assert_eq!(
            vcs.content_store()
                .get(&manifest["result.bin"])
                .unwrap()
                .unwrap(),
            bytes
        );
        assert_eq!(result.cut.parent_cut_id.as_deref(), Some(base.as_str()));
        assert_eq!(result.cut.actor.as_deref(), Some("human:alice"));
        assert_eq!(result.cut.intent.as_deref(), Some("original-command"));
        assert_eq!(
            std::fs::read(eng.path.join("preserved.txt")).unwrap(),
            b"unrelated pending edit"
        );
        eng.write_file("result.txt", "later work").unwrap();
        eng.commit_turn("later independently authorized work")
            .unwrap();
        let later = observed(&eng).get_branch(eng.branch()).unwrap().unwrap();
        let retry = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(
                &witness,
                "original-owner-witness",
                "human:alice",
                "original-command",
                &mut || Ok(()),
            )
            .unwrap();
        assert_eq!(retry.cut, result.cut);
        assert_eq!(retry.op, result.op);
        assert_eq!(
            observed(&eng).get_branch(eng.branch()).unwrap().unwrap(),
            later
        );
        assert_eq!(
            std::fs::read(eng.path.join("result.txt")).unwrap(),
            b"later work"
        );
        assert_eq!(
            vcs.content_store()
                .get(&result.files()["result.txt"])
                .unwrap()
                .unwrap(),
            b"final synthetic result"
        );
    }

    #[test]
    fn recorded_retry_does_not_require_the_live_projection() {
        let (_root, eng, base) = setup();
        eng.write_file("result.txt", "synthetic result").unwrap();
        let witness = [file("result.txt", "add", b"synthetic result")];
        let result = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                Ok(())
            })
            .unwrap();
        let before = observed(&eng).get_branch(eng.branch()).unwrap().unwrap();
        std::fs::remove_dir_all(&eng.path).unwrap();
        let retry = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                Ok(())
            })
            .unwrap();
        assert_eq!(retry.cut, result.cut);
        assert_eq!(retry.op, result.op);
        assert_eq!(
            observed(&eng).get_branch(eng.branch()).unwrap().unwrap(),
            before
        );
        assert!(!eng.path.exists());
        assert!(eng
            .witnessed_turn_target_at(result.cut())
            .unwrap()
            .import_guarded(
                &witness,
                "new-owner-cut",
                "human:alice",
                "new-command",
                &mut || Ok(())
            )
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn recorded_retry_does_not_follow_a_replaced_live_file() {
        let (root, eng, base) = setup();
        eng.write_file("result.txt", "synthetic result").unwrap();
        let witness = [file("result.txt", "add", b"synthetic result")];
        let result = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                Ok(())
            })
            .unwrap();
        let outside = root.path().join("outside.txt");
        std::fs::write(&outside, "outside synthetic bytes").unwrap();
        std::fs::remove_file(eng.path.join("result.txt")).unwrap();
        std::os::unix::fs::symlink(&outside, eng.path.join("result.txt")).unwrap();
        let retry = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                Ok(())
            })
            .unwrap();
        assert_eq!(retry.cut, result.cut);
        assert_eq!(retry.op, result.op);
        let fresh = [file("result.txt", "modify", b"outside synthetic bytes")];
        assert!(eng
            .witnessed_turn_target_at(result.cut())
            .unwrap()
            .import_guarded(
                &fresh,
                "new-owner-cut",
                "human:alice",
                "new-command",
                &mut || Ok(())
            )
            .is_err());
        assert_eq!(std::fs::read(outside).unwrap(), b"outside synthetic bytes");
    }

    #[test]
    fn late_guard_runs_inside_actual_native_branch_writer_and_rolls_back() {
        let (_root, eng, base) = setup();
        eng.write_file("result.txt", "synthetic result").unwrap();
        let witness = [file("result.txt", "add", b"synthetic result")];
        let competitor =
            rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        competitor.busy_timeout(std::time::Duration::ZERO).unwrap();
        let mut inside_writer = false;
        let mut check = || {
            if competitor.execute_batch("BEGIN IMMEDIATE").is_err() {
                inside_writer = true;
                return Err(refused("original authority ended at native commit"));
            }
            competitor.execute_batch("ROLLBACK").unwrap();
            Ok(())
        };
        let target = eng.witnessed_turn_target_at(&base).unwrap();
        let planned = target
            .plan(&witness, "owner-cut", "human:alice", "command")
            .unwrap()
            .0;
        assert!(target
            .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut check)
            .is_err());
        assert!(inside_writer);
        let vcs = observed(&eng);
        assert_eq!(
            vcs.get_branch(eng.branch())
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some(base.as_str())
        );
        assert!(vcs.get_cut(&planned).unwrap().is_none());
        assert!(vcs.get_op(&format!("op-{planned}")).unwrap().is_none());
    }

    #[test]
    fn wrong_bytes_lengths_deletions_scopes_and_stale_bases_never_advance() {
        for case in [
            "hash", "length", "deletion", "path", "local", "scope", "spelling", "base",
        ] {
            let (_root, mut eng, base) = setup();
            eng.write_file("result.txt", "actual bytes").unwrap();
            let mut witness = vec![file("result.txt", "add", b"actual bytes")];
            match case {
                "hash" => witness[0].sha256 = hex::encode(Sha256::digest(b"other bytes")),
                "length" => witness[0].bytes += 1,
                "deletion" => witness = vec![file("result.txt", "delete", b"")],
                "path" => witness[0].path = "../outside.txt".into(),
                "local" => witness[0].path = "artifacts/report.txt".into(),
                "scope" => {
                    eng.sparse_roots = Some(std::collections::BTreeSet::from(["selected".into()]))
                }
                "spelling" => witness.push(file("RESULT.txt", "add", b"actual bytes")),
                "base" => {
                    eng.write_file("later.txt", "later").unwrap();
                    eng.commit_turn("later").unwrap();
                }
                _ => unreachable!(),
            }
            let before = observed(&eng).get_branch(eng.branch()).unwrap().unwrap();
            let target = eng.witnessed_turn_target_at(&base).unwrap();
            let planned = target
                .plan(&witness, "owner-cut", "human:alice", "command")
                .ok()
                .map(|p| p.0);
            assert!(
                target
                    .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut || Ok(
                        ()
                    ))
                    .is_err(),
                "{case}"
            );
            assert_eq!(
                observed(&eng).get_branch(eng.branch()).unwrap().unwrap(),
                before,
                "{case}"
            );
            if let Some(planned) = planned {
                assert!(
                    observed(&eng).get_cut(&planned).unwrap().is_none(),
                    "{case}"
                );
            }
        }
    }

    #[test]
    fn authority_ending_during_bounded_snapshot_never_imports_a_partial_file() {
        let (_root, eng, base) = setup();
        let bytes = vec![0xff; 2 * 1024 * 1024];
        std::fs::write(eng.path.join("result.bin"), &bytes).unwrap();
        let mut calls = 0;
        let result = eng.witnessed_turn_target_at(&base).unwrap().import_guarded(
            &[file("result.bin", "add", &bytes)],
            "owner-cut",
            "human:alice",
            "command",
            &mut || {
                calls += 1;
                if calls >= 8 {
                    Err(refused("authority ended"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err());
        assert_eq!(calls, 8);
        assert_eq!(
            observed(&eng)
                .get_branch(eng.branch())
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some(base.as_str())
        );
    }

    #[test]
    fn complete_result_retention_excludes_erasure_and_refuses_missing_receipts_and_payloads() {
        let (_root, eng, base) = setup();
        eng.write_file("one.txt", "one").unwrap();
        eng.write_file("two.txt", "two").unwrap();
        let witness = [
            file("one.txt", "add", b"one"),
            file("two.txt", "add", b"two"),
        ];
        let result = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                Ok(())
            })
            .unwrap();
        let competitor = rusqlite::Connection::open(eng.store_root.join("content.sqlite")).unwrap();
        competitor.busy_timeout(std::time::Duration::ZERO).unwrap();
        result
            .publish_retained(|| {
                assert!(competitor.execute_batch("BEGIN IMMEDIATE").is_err());
                Ok(())
            })
            .unwrap();
        let branch_connection =
            rusqlite::Connection::open(eng.store_root.join("branches.sqlite")).unwrap();
        branch_connection
            .execute("DELETE FROM ops WHERE op_id=?1", [&result.op.op_id])
            .unwrap();
        assert!(result
            .publish_retained::<()>(|| panic!("missing native receipt published"))
            .is_err());
        let (_root, eng, base) = setup();
        eng.write_file("one.txt", "one").unwrap();
        eng.write_file("two.txt", "two").unwrap();
        let result = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                Ok(())
            })
            .unwrap();
        ContentStore::open_existing(eng.store_root.join("content.sqlite"))
            .unwrap()
            .erase(&result.files()["one.txt"], "now")
            .unwrap();
        assert!(result
            .publish_retained::<()>(|| panic!("incomplete native result published"))
            .is_err());
        assert!(eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut || Ok(
                ()
            ))
            .is_err());
        let (_root, eng, base) = setup();
        eng.write_file("one.txt", "one").unwrap();
        eng.write_file("two.txt", "two").unwrap();
        let result = eng
            .witnessed_turn_target_at(&base)
            .unwrap()
            .import_guarded(&witness, "owner-cut", "human:alice", "command", &mut || {
                Ok(())
            })
            .unwrap();
        ContentStore::open_existing(eng.store_root.join("content.sqlite"))
            .unwrap()
            .erase(&result.base_manifest["preserved.txt"], "now")
            .unwrap();
        assert!(result
            .publish_retained::<()>(|| panic!("missing unchanged native base published"))
            .is_err());
    }
}
