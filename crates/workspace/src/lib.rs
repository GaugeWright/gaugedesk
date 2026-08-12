//! GaugeDesk adapter for WhippleScript's versioned workspace (`WorkspaceVcs`).
//!
//! GaugeDesk owns lifecycle policy: when a turn cuts, which line a chat
//! targets, and when a clean proposal is admitted. WhippleScript owns the
//! content-addressed cuts, lineage, merge verdicts, restore, and the
//! text-merge engine that make those decisions real.
//!
//! Shape of the adapter: every branch a human or agent touches keeps a REAL
//! worktree on disk (the agent harness needs genuine inodes), and this crate
//! moves state across that boundary with whip's materialize/import-back
//! projection — `sync_in` scans the worktree against a persisted stat cache
//! and commits the diff as one cut; `sync_out` projects a branch head back
//! into its worktree (pruning files the manifest no longer names). Lines:
//! whip's mainline `main` is the instance repo, `engagement/<id>` is a chat
//! (kept open across merges via `merge_keeping`), `workstream/<id>/main` is
//! a stream line.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use whipplescript_store::branches::{CreateBranchOutcome, RetargetOutcome, MAINLINE_BRANCH_ID};
use whipplescript_store::content::ContentBlobs;
use whipplescript_store::diff::DiffEntry;
use whipplescript_store::materialize::MaterializedScratch;
use whipplescript_store::stat_cache::{CachedEntry, StatCache};
use whipplescript_store::vcs::{
    MergeProbeOutcome, NativeWorkspaceVcs, ReconcileOutcome, RestoreOutcome, VcsMergeOutcome,
    VcsWriteOutcome,
};

mod external;
pub use external::{ExternalTargetKind, ExternalWorkspace};

/// Host-owned per-chat materializations are never target history. The runtime
/// mount contains the selected archetype discipline; it is recreated from the
/// immutable archetype version and layered read-only by the sandbox.
const CHAT_LOCAL_PATHS: &[&str] = &[".gaugedesk-runtime"];

fn is_chat_local_path(path: &str) -> bool {
    CHAT_LOCAL_PATHS
        .iter()
        .any(|root| path == *root || path.starts_with(&format!("{root}/")))
}

/// Same-provider export envelope: raw snapshots of the two store files.
/// Full fidelity (every branch, cut, op, and blob travels), version-stamped.
pub const EXPORT_FORMAT: &str = "whipplescript-vcs-export-v1";
const EXPORT_MAGIC: &[u8; 8] = b"WSVCSEX1";

#[derive(Debug)]
pub struct WorkspaceError {
    pub message: String,
}

impl WorkspaceError {
    pub(crate) fn io(error: std::io::Error) -> Self {
        Self {
            message: error.to_string(),
        }
    }
    pub(crate) fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl From<whipplescript_store::StoreError> for WorkspaceError {
    fn from(error: whipplescript_store::StoreError) -> Self {
        Self {
            message: format!("{error:?}"),
        }
    }
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for WorkspaceError {}

type Result<T> = std::result::Result<T, WorkspaceError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub is_dir: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    Clean,
    Conflict,
}

/// Whip's merge-piece surface, re-exported so consumers (the fold UI's
/// JSON) speak the engine's own vocabulary — provenance-tagged merged
/// spans, three-slice conflict regions, and settled region resolutions
/// (the region-memory currency).
pub use whipplescript_store::text_merge::{MergePiece, Provenance, RegionResolution};

/// The editor's base for a save: the cut id it loaded (the §12 shape) or,
/// from a pre-cut client, the content it loaded (resolved to a recorded
/// cut when one matches).
#[derive(Clone, Copy, Debug)]
pub enum SaveBase<'a> {
    Cut(&'a str),
    Content(&'a str),
}

/// Outcome of a base-carrying editor save (SUB-6). Every accepting
/// outcome names the cut it minted, so the editor's next save can carry
/// it as the base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SaveFileOutcome {
    /// The file hadn't moved since the editor's base: a plain write.
    Written { cut: String },
    /// Concurrent changes composed cleanly; `content` is the merged body
    /// now on disk, `pieces` its provenance for the review affordance.
    Merged {
        cut: String,
        content: String,
        pieces: Vec<MergePiece>,
    },
    /// Real divergence: nothing written; `current` is the file as it
    /// stands and `current_cut` its cut — together the re-save base —
    /// and `pieces` the fold payload.
    Conflicted {
        current: String,
        current_cut: Option<String>,
        pieces: Vec<MergePiece>,
    },
}

/// A read-only look at what a save would do (the live fold's twin):
/// `clean` means the draft would compose with the file as it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergePreview {
    pub current_cut: Option<String>,
    pub clean: bool,
    pub merged: Option<String>,
    pub pieces: Vec<MergePiece>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevisionId(pub String);

impl std::fmt::Display for RevisionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub struct WorkspaceExport(pub Vec<u8>);

/// Opaque same-provider lineage source. It contains only the local native store
/// location; callers cannot derive workspace semantics from it.
pub struct PeerSource(pub(crate) PathBuf);

// ---------------------------------------------------------------------------
// ids and time: cut ids are caller-minted in whip's vcs; recorded_at is an
// opaque ordered string. Nanos + a process counter keep both unique.

static CUT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn now_nanos() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as i128)
        .unwrap_or(0)
}

fn now_at() -> String {
    now_nanos().to_string()
}

fn fresh_cut_id(kind: &str) -> String {
    format!(
        "cut-{kind}-{:x}-{:x}",
        now_nanos(),
        CUT_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

pub struct Instance {
    repo: PathBuf,
    worktrees: PathBuf,
    store_root: PathBuf,
}

impl Instance {
    pub fn init(repo: impl Into<PathBuf>, worktrees: impl Into<PathBuf>) -> Result<Self> {
        let repo = repo.into();
        let worktrees = worktrees.into();
        let store_root = store_root_for(&repo);
        std::fs::create_dir_all(&repo).map_err(WorkspaceError::io)?;
        std::fs::create_dir_all(&worktrees).map_err(WorkspaceError::io)?;
        let instance = Self {
            repo,
            worktrees,
            store_root,
        };
        let _ = instance.store()?;
        write_substrate_stamp(&instance.store_root)?;
        Ok(instance)
    }

    pub fn open(repo: impl Into<PathBuf>, worktrees: impl Into<PathBuf>) -> Self {
        let repo = repo.into();
        let store_root = store_root_for(&repo);
        Self {
            repo,
            worktrees: worktrees.into(),
            store_root,
        }
    }

    pub fn init_at(dir: impl AsRef<Path>) -> Result<Self> {
        Self::init(dir.as_ref().join("repo"), dir.as_ref().join("worktrees"))
    }

    pub fn open_at(dir: impl AsRef<Path>) -> Self {
        Self::open(dir.as_ref().join("repo"), dir.as_ref().join("worktrees"))
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    /// Open the native store. Pre-target/legacy layouts are rejected: this is
    /// a pre-user hard cutover and silently reseeding them would manufacture a
    /// second authority for files whose ownership is unknown.
    fn store(&self) -> Result<NativeWorkspaceVcs> {
        let fresh = !self.store_root.join("branches.sqlite").exists();
        if fresh
            && (self.store_root.join("workspace.sqlite3").exists()
                || self.repo.join(".git").exists())
        {
            return Err(WorkspaceError::msg(
                "pre-target workspace layout is unsupported; reset this pre-release state root",
            ));
        }
        let mut vcs = NativeWorkspaceVcs::open(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )?;
        vcs.init(&now_at())?;
        Ok(vcs)
    }

    pub fn export(&self) -> Result<WorkspaceExport> {
        let _ = self.store()?;
        let branches = snapshot_sqlite(&self.store_root.join("branches.sqlite"))?;
        let content = snapshot_sqlite(&self.store_root.join("content.sqlite"))?;
        let mut bytes = Vec::with_capacity(16 + 16 + branches.len() + content.len());
        bytes.extend_from_slice(EXPORT_MAGIC);
        bytes.extend_from_slice(&(branches.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&branches);
        bytes.extend_from_slice(&(content.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&content);
        Ok(WorkspaceExport(bytes))
    }

    pub fn export_format(&self) -> &'static str {
        EXPORT_FORMAT
    }

    pub fn from_export_at(dir: impl AsRef<Path>, export: &[u8]) -> Result<Self> {
        let (branches, content) = parse_export(export)?;
        let dir = dir.as_ref();
        let repo = dir.join("repo");
        let worktrees = dir.join("worktrees");
        let store_root = store_root_for(&repo);
        std::fs::create_dir_all(&repo).map_err(WorkspaceError::io)?;
        std::fs::create_dir_all(&worktrees).map_err(WorkspaceError::io)?;
        std::fs::create_dir_all(&store_root).map_err(WorkspaceError::io)?;
        std::fs::write(store_root.join("branches.sqlite"), branches).map_err(WorkspaceError::io)?;
        std::fs::write(store_root.join("content.sqlite"), content).map_err(WorkspaceError::io)?;
        write_substrate_stamp(&store_root)?;
        let instance = Self {
            repo,
            worktrees,
            store_root,
        };
        let mut vcs = instance.store()?;
        sync_out(
            &mut vcs,
            &instance.store_root,
            MAINLINE_BRANCH_ID,
            &instance.repo,
        )?;
        let _ = instance.reconcile_engagements()?;
        Ok(instance)
    }

    pub fn peer_source(&self) -> PeerSource {
        PeerSource(self.store_root.clone())
    }

    pub fn fork_from_at(dir: impl AsRef<Path>, source: &PeerSource) -> Result<Self> {
        let branches = snapshot_sqlite(&source.0.join("branches.sqlite"))?;
        let content = snapshot_sqlite(&source.0.join("content.sqlite"))?;
        let mut export = Vec::new();
        export.extend_from_slice(EXPORT_MAGIC);
        export.extend_from_slice(&(branches.len() as u64).to_le_bytes());
        export.extend_from_slice(&branches);
        export.extend_from_slice(&(content.len() as u64).to_le_bytes());
        export.extend_from_slice(&content);
        Self::from_export_at(dir, &export)
    }

    /// Fold the peer's mainline into ours. Lineage-aware three-way: the
    /// base is the newest LOCAL main cut the peer also carries (fork and
    /// export share cut history by construction), so both sides' own
    /// advances survive and genuine both-touched divergence escalates.
    /// A peer with no shared history is refused honestly.
    pub fn pull_from(&self, source: &PeerSource) -> Result<MergeOutcome> {
        let peer = NativeWorkspaceVcs::open(
            source.0.join("branches.sqlite"),
            source.0.join("content.sqlite"),
        )?;
        let Some(bundle) = peer.export_bundle(MAINLINE_BRANCH_ID)? else {
            return Err(WorkspaceError::msg("peer store has no mainline"));
        };
        let mut vcs = self.store()?;
        let local_main = vcs
            .get_branch(MAINLINE_BRANCH_ID)?
            .ok_or_else(|| WorkspaceError::msg("no local mainline"))?;
        let peer_cuts: BTreeSet<&str> = bundle.cuts.iter().map(|cut| cut.cut_id.as_str()).collect();
        let base_cut = vcs
            .list_cuts(MAINLINE_BRANCH_ID, 100_000)?
            .into_iter()
            .find(|cut| peer_cuts.contains(cut.cut_id.as_str()));
        if base_cut.is_none() && local_main.head_cut_id.is_some() {
            return Err(WorkspaceError::msg(
                "peer workspace shares no history with this one; refusing a blind overwrite",
            ));
        }
        // Land the peer's blobs (verified content addresses, like bundle
        // import), then a transport line forked at the shared base whose
        // head is the peer's state — a real three-way against mainline.
        for blob in &bundle.blobs {
            if let Some(chunk_ids) = &blob.chunk_ids {
                vcs.content_store()
                    .put_chunk_root(&blob.id, chunk_ids, blob.byte_len)?;
                continue;
            }
            if let Some(body) = &blob.body {
                let stored = vcs.content_store().put(body)?;
                if stored != blob.id {
                    return Err(WorkspaceError::msg(format!(
                        "peer blob `{}` does not match its content (hashes to `{stored}`)",
                        blob.id
                    )));
                }
            }
        }
        let transport = format!("peer-pull/{:x}", now_nanos());
        let created = vcs.fork_with_lineage(
            &transport,
            None,
            MAINLINE_BRANCH_ID,
            base_cut.as_ref().map(|cut| cut.cut_id.as_str()),
            &now_at(),
        )?;
        if !matches!(created, CreateBranchOutcome::Created(_)) {
            return Err(WorkspaceError::msg(format!(
                "could not create pull transport line: {created:?}"
            )));
        }
        let base_manifest = match &base_cut {
            Some(cut) => vcs.cut_manifest(&cut.cut_id)?.unwrap_or_default(),
            None => BTreeMap::new(),
        };
        let mut changed = BTreeMap::new();
        for (path, hash) in &bundle.manifest {
            if base_manifest.get(path) != Some(hash) {
                changed.insert(path.clone(), hash.clone());
            }
        }
        let removed: Vec<String> = base_manifest
            .keys()
            .filter(|path| !bundle.manifest.contains_key(*path))
            .cloned()
            .collect();
        if !changed.is_empty() || !removed.is_empty() {
            let outcome = vcs.import_diff(
                &transport,
                &changed,
                &removed,
                &fresh_cut_id("pull"),
                &now_at(),
            )?;
            if !matches!(outcome, VcsWriteOutcome::Written { .. }) {
                return Err(WorkspaceError::msg(format!(
                    "pull transport import refused: {outcome:?}"
                )));
            }
        }
        // The transport line is disposable: a plain adopting merge.
        match vcs.merge(&transport, &fresh_cut_id("pull-merge"), &now_at())? {
            VcsMergeOutcome::Adopted { .. } | VcsMergeOutcome::Landed { .. } => {
                sync_out(&mut vcs, &self.store_root, MAINLINE_BRANCH_ID, &self.repo)?;
                Ok(MergeOutcome::Clean)
            }
            VcsMergeOutcome::Conflicted { .. } => {
                let _ = vcs.discard_branch(&transport, &now_at())?;
                Ok(MergeOutcome::Conflict)
            }
            other => Err(WorkspaceError::msg(format!(
                "pull merge refused: {other:?}"
            ))),
        }
    }

    pub fn updates_available_from(&self, source_repo: &Path) -> bool {
        let source_root = store_root_for(source_repo);
        let Ok(source) = NativeWorkspaceVcs::open(
            source_root.join("branches.sqlite"),
            source_root.join("content.sqlite"),
        ) else {
            return false;
        };
        let Ok(local) = self.store() else {
            return false;
        };
        match (
            source.get_branch(MAINLINE_BRANCH_ID),
            local.get_branch(MAINLINE_BRANCH_ID),
        ) {
            (Ok(Some(source)), Ok(Some(local))) => {
                source.head_manifest_hash != local.head_manifest_hash
            }
            _ => false,
        }
    }

    pub fn seed_main(&self, files: &[(&str, &str)]) -> Result<()> {
        for (relative, content) in files {
            let path = safe_path(&self.repo, relative)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(WorkspaceError::io)?;
            }
            std::fs::write(path, content).map_err(WorkspaceError::io)?;
        }
        let mut vcs = self.store()?;
        sync_in(&mut vcs, &self.store_root, MAINLINE_BRANCH_ID, &self.repo)?;
        Ok(())
    }

    pub fn create_engagement(&self, id: &str) -> Result<Engagement> {
        self.create_engagement_on(id, MAINLINE_BRANCH_ID)
    }

    pub fn create_engagement_on(&self, id: &str, target: &str) -> Result<Engagement> {
        let mut vcs = self.store()?;
        let branch = engagement_line(id);
        match vcs.create_branch(&branch, None, target, &now_at())? {
            CreateBranchOutcome::Created(_) | CreateBranchOutcome::Existing(_) => {}
            other => {
                return Err(WorkspaceError::msg(format!(
                    "could not create engagement line `{branch}` on `{target}`: {other:?}"
                )))
            }
        }
        let path = self.worktrees.join(id);
        sync_out(&mut vcs, &self.store_root, &branch, &path)?;
        Ok(Engagement {
            store_root: self.store_root.clone(),
            repo: self.repo.clone(),
            path,
            branch,
            target: target.into(),
        })
    }

    /// Create an engagement with WhippleScript lineage pinned to an exact
    /// durable cut of another engagement branch.
    pub fn fork_engagement_at(
        &self,
        id: &str,
        source_branch: &str,
        target: &str,
        cut_id: &str,
    ) -> Result<Engagement> {
        let mut vcs = self.store()?;
        let branch = engagement_line(id);
        match vcs.fork_with_lineage(&branch, None, source_branch, Some(cut_id), &now_at())? {
            CreateBranchOutcome::Created(_) | CreateBranchOutcome::Existing(_) => {}
            other => {
                return Err(WorkspaceError::msg(format!(
                    "could not fork engagement line `{branch}` at `{cut_id}`: {other:?}"
                )))
            }
        }
        let path = self.worktrees.join(id);
        sync_out(&mut vcs, &self.store_root, &branch, &path)?;
        Ok(Engagement {
            store_root: self.store_root.clone(),
            repo: self.repo.clone(),
            path,
            branch,
            target: target.into(),
        })
    }

    pub fn remove_engagement(&self, id: &str) -> Result<()> {
        let mut vcs = self.store()?;
        let _ = vcs.discard_branch(&engagement_line(id), &now_at())?;
        let _ = std::fs::remove_file(scratch_cache_path(&self.store_root, &engagement_line(id)));
        Ok(())
    }

    /// Reclaim orphaned content (whip's conservative GC sweep): the
    /// residue of superseded saves and refused imports. Everything any
    /// recorded cut, branch pointer, resolution memory, or conflict row
    /// can name survives; per-blob erasure stays the honesty path for
    /// payloads that must actually go.
    pub fn purge_unreachable_objects(&self) -> Result<()> {
        let _ = self.store()?.purge_unreachable()?;
        Ok(())
    }

    pub fn reconcile_engagements(&self) -> Result<Vec<(String, Engagement)>> {
        let mut vcs = self.store()?;
        let mut result = Vec::new();
        for row in vcs.list_branches(Some(whipplescript_store::branches::BranchStatus::Active))? {
            let Some(id) = row.branch_id.strip_prefix("engagement/") else {
                continue;
            };
            let id = id.to_string();
            let path = self.worktrees.join(&id);
            if !path.is_dir() {
                // A missing checkout (fresh import, relocated device) is
                // re-materialized; an existing one is left exactly as it
                // sits — it may hold work from an interrupted turn.
                sync_out(&mut vcs, &self.store_root, &row.branch_id, &path)?;
            }
            result.push((
                id,
                Engagement {
                    store_root: self.store_root.clone(),
                    repo: self.repo.clone(),
                    path,
                    branch: row.branch_id.clone(),
                    target: row
                        .parent_branch_id
                        .clone()
                        .unwrap_or_else(|| MAINLINE_BRANCH_ID.to_owned()),
                },
            ));
        }
        result.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(result)
    }

    pub fn workstream_ref(id: &str) -> String {
        format!("workstream/{id}/main")
    }

    pub fn create_workstream(&self, id: &str) -> Result<()> {
        let mut vcs = self.store()?;
        let line = Self::workstream_ref(id);
        match vcs.create_branch(&line, None, MAINLINE_BRANCH_ID, &now_at())? {
            CreateBranchOutcome::Created(_) | CreateBranchOutcome::Existing(_) => Ok(()),
            other => Err(WorkspaceError::msg(format!(
                "could not create workstream line `{line}`: {other:?}"
            ))),
        }
    }

    pub fn promote_workstream_to_main(&self, id: &str) -> Result<MergeOutcome> {
        let mut vcs = self.store()?;
        sync_in(&mut vcs, &self.store_root, MAINLINE_BRANCH_ID, &self.repo)?;
        match vcs.merge_keeping(
            &Self::workstream_ref(id),
            &fresh_cut_id("promote"),
            &now_at(),
        )? {
            VcsMergeOutcome::Landed { .. } | VcsMergeOutcome::Adopted { .. } => {
                sync_out(&mut vcs, &self.store_root, MAINLINE_BRANCH_ID, &self.repo)?;
                Ok(MergeOutcome::Clean)
            }
            VcsMergeOutcome::Conflicted { .. } => Ok(MergeOutcome::Conflict),
            other => Err(WorkspaceError::msg(format!(
                "workstream promotion refused: {other:?}"
            ))),
        }
    }
}

#[derive(Clone)]
pub struct Engagement {
    store_root: PathBuf,
    repo: PathBuf,
    path: PathBuf,
    branch: String,
    target: String,
}

impl Engagement {
    fn store(&self) -> Result<NativeWorkspaceVcs> {
        let mut vcs = NativeWorkspaceVcs::open(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )?;
        vcs.init(&now_at())?;
        Ok(vcs)
    }

    /// Import the worktree (and mainline's repo, when it is the target's
    /// disk tree) so store-level verbs see what's actually on disk.
    fn import_sides(&self, vcs: &mut NativeWorkspaceVcs) -> Result<()> {
        sync_in(vcs, &self.store_root, &self.branch, &self.path)?;
        if self.target == MAINLINE_BRANCH_ID {
            sync_in(vcs, &self.store_root, MAINLINE_BRANCH_ID, &self.repo)?;
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn branch(&self) -> &str {
        &self.branch
    }
    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn set_target(&mut self, target: impl Into<String>) -> Result<()> {
        let target = target.into();
        let mut vcs = self.store()?;
        match vcs.retarget(&self.branch, &target, &now_at())? {
            RetargetOutcome::Retargeted(_) => {
                self.target = target;
                Ok(())
            }
            other => Err(WorkspaceError::msg(format!(
                "could not retarget `{}` onto `{target}`: {other:?}",
                self.branch
            ))),
        }
    }

    /// Move a settled chat to another shared line in the same workspace root.
    ///
    /// This is deliberately stronger than [`set_target`]. A re-home is refused while
    /// the chat differs from its current target, then the engagement branch is restored
    /// to the destination cut and its worktree is rematerialized. The transcript lives
    /// outside this provider and therefore survives; file history from the old line does
    /// not become a candidate against the new line.
    pub fn rehome(&mut self, target: impl Into<String>) -> Result<()> {
        let target = target.into();
        if target == self.target {
            return Ok(());
        }

        let mut vcs = self.store()?;
        self.import_sides(&mut vcs)?;
        let pending = vcs
            .diff_against(&self.branch, Some(&self.target), 1)?
            .ok_or_else(|| WorkspaceError::msg(format!("no branch `{}`", self.branch)))?;
        if pending.iter().any(|entry| !is_chat_local_path(&entry.path)) {
            return Err(WorkspaceError::msg(
                "chat has unsettled workspace changes; settle or discard them before moving",
            ));
        }
        let local_overlays = snapshot_local_files(&self.path)?;

        let destination = vcs
            .get_branch(&target)?
            .ok_or_else(|| WorkspaceError::msg(format!("no target line `{target}`")))?;
        let previous = self.target.clone();
        match vcs.retarget(&self.branch, &target, &now_at())? {
            RetargetOutcome::Retargeted(_) => {}
            other => {
                return Err(WorkspaceError::msg(format!(
                    "could not retarget `{}` onto `{target}`: {other:?}",
                    self.branch
                )))
            }
        }

        let restored = match destination.head_cut_id {
            Some(head_cut) => {
                match vcs.restore(&self.branch, &head_cut, &fresh_cut_id("rehome"), &now_at())? {
                    RestoreOutcome::Restored { .. } | RestoreOutcome::AlreadyThere => Ok(()),
                    other => Err(WorkspaceError::msg(format!(
                        "rehome restore refused: {other:?}"
                    ))),
                }
            }
            None => {
                clear_worktree(&self.path)?;
                sync_in(&mut vcs, &self.store_root, &self.branch, &self.path).map(|_| ())
            }
        };
        if let Err(error) = restored {
            let _ = vcs.retarget(&self.branch, &previous, &now_at());
            return Err(error);
        }

        sync_out(&mut vcs, &self.store_root, &self.branch, &self.path)?;
        for (path, body) in local_overlays {
            self.write_file(&path, &body)?;
        }
        self.target = target;
        Ok(())
    }

    pub fn commit_turn(&self, _message: &str) -> Result<Option<RevisionId>> {
        let mut vcs = self.store()?;
        if let Some(cut) = sync_in(&mut vcs, &self.store_root, &self.branch, &self.path)? {
            return Ok(Some(RevisionId(cut)));
        }
        let cut_id = fresh_cut_id("turn-boundary");
        let cut = vcs
            .cut_at_quiescence(&self.branch, &cut_id, &now_at())?
            .ok_or_else(|| WorkspaceError::msg(format!("no branch `{}`", self.branch)))?;
        Ok(Some(RevisionId(cut.cut_id)))
    }

    /// Ensure the current worktree state has a durable address even before a
    /// turn starts. This is the pre-user half of point-fork semantics.
    pub fn boundary_cut(&self) -> Result<RevisionId> {
        self.commit_turn("turn boundary")?
            .ok_or_else(|| WorkspaceError::msg("turn boundary did not produce a cut"))
    }

    pub fn diff_against_main(&self) -> Result<String> {
        let mut vcs = self.store()?;
        self.import_sides(&mut vcs)?;
        let entries = vcs
            .diff_against(&self.branch, Some(&self.target), 3)?
            .ok_or_else(|| WorkspaceError::msg(format!("no branch `{}`", self.branch)))?;
        Ok(render_diff(&entries))
    }

    pub fn revert_to_main(&self) -> Result<()> {
        let mut vcs = self.store()?;
        let target = vcs
            .get_branch(&self.target)?
            .ok_or_else(|| WorkspaceError::msg(format!("no target line `{}`", self.target)))?;
        match target.head_cut_id {
            Some(head_cut) => {
                match vcs.restore(&self.branch, &head_cut, &fresh_cut_id("revert"), &now_at())? {
                    RestoreOutcome::Restored { .. } | RestoreOutcome::AlreadyThere => {}
                    other => return Err(WorkspaceError::msg(format!("revert refused: {other:?}"))),
                }
            }
            None => {
                // Virgin target: revert means "empty tree" — import the
                // cleared worktree as this branch's own cut.
                clear_worktree(&self.path)?;
                sync_in(&mut vcs, &self.store_root, &self.branch, &self.path)?;
            }
        }
        sync_out(&mut vcs, &self.store_root, &self.branch, &self.path)
    }

    pub fn merge_probe(&self) -> Result<MergeOutcome> {
        let mut vcs = self.store()?;
        self.import_sides(&mut vcs)?;
        match vcs.merge_probe(&self.branch)? {
            MergeProbeOutcome::UpToDate | MergeProbeOutcome::Clean { .. } => {
                Ok(MergeOutcome::Clean)
            }
            MergeProbeOutcome::Conflicted { .. } => Ok(MergeOutcome::Conflict),
            other => Err(WorkspaceError::msg(format!(
                "merge probe refused: {other:?}"
            ))),
        }
    }

    /// Land this line's delta on its target. The line stays OPEN
    /// (`merge_keeping`): a chat merges every clean turn for its whole
    /// life. Both disk trees refresh — the target's (mainline's repo)
    /// because it adopted the content, ours because the line rebased onto
    /// the merge cut (folding anything the target had that we lacked).
    pub fn merge_into_main(&self) -> Result<MergeOutcome> {
        let mut vcs = self.store()?;
        self.import_sides(&mut vcs)?;
        match vcs.merge_keeping(&self.branch, &fresh_cut_id("keep"), &now_at())? {
            VcsMergeOutcome::Landed { .. } | VcsMergeOutcome::Adopted { .. } => {
                if self.target == MAINLINE_BRANCH_ID {
                    sync_out(&mut vcs, &self.store_root, MAINLINE_BRANCH_ID, &self.repo)?;
                }
                sync_out(&mut vcs, &self.store_root, &self.branch, &self.path)?;
                Ok(MergeOutcome::Clean)
            }
            VcsMergeOutcome::Conflicted { .. } => Ok(MergeOutcome::Conflict),
            other => Err(WorkspaceError::msg(format!("merge refused: {other:?}"))),
        }
    }

    /// Fold the target's advance into this line (whip's rebase-down
    /// reconcile at quiescence), then refresh the worktree.
    pub fn sync_from_main(&self) -> Result<MergeOutcome> {
        let mut vcs = self.store()?;
        self.import_sides(&mut vcs)?;
        match vcs.reconcile_branch(&self.branch, true, &fresh_cut_id("sync"), &now_at())? {
            ReconcileOutcome::Rebased { .. } | ReconcileOutcome::UpToDate => {
                sync_out(&mut vcs, &self.store_root, &self.branch, &self.path)?;
                Ok(MergeOutcome::Clean)
            }
            ReconcileOutcome::Conflicts { .. } => Ok(MergeOutcome::Conflict),
            other => Err(WorkspaceError::msg(format!("sync refused: {other:?}"))),
        }
    }

    pub fn ingest(&self, source: &Path) -> Result<usize> {
        if source.is_file() {
            let name = source.file_name().ok_or_else(|| {
                WorkspaceError::msg(format!(
                    "ingest {}: context path has no file name",
                    source.display()
                ))
            })?;
            std::fs::copy(source, self.path.join(name)).map_err(WorkspaceError::io)?;
            Ok(1)
        } else {
            copy_dir(source, &self.path)
        }
    }

    pub fn ingest_upload(&self, files: &[(String, String)]) -> Result<usize> {
        for (name, content) in files {
            let base = Path::new(name)
                .file_name()
                .ok_or_else(|| {
                    WorkspaceError::msg(format!(
                        "ingest upload: uploaded file has no name: {name:?}"
                    ))
                })?
                .to_string_lossy();
            self.write_file(&base, content)?;
        }
        Ok(files.len())
    }

    pub fn tree(&self) -> Result<Vec<FileEntry>> {
        let mut result = Vec::new();
        walk_tree(&self.path, &self.path, &mut result).map_err(WorkspaceError::io)?;
        result.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(result)
    }

    pub fn read_file(&self, relative: &str) -> Result<String> {
        std::fs::read_to_string(safe_path(&self.path, relative)?).map_err(WorkspaceError::io)
    }

    pub fn read_file_capped(&self, relative: &str, max_bytes: usize) -> Result<Option<String>> {
        use std::io::Read;
        let file =
            std::fs::File::open(safe_path(&self.path, relative)?).map_err(WorkspaceError::io)?;
        let mut bytes = Vec::new();
        file.take(max_bytes as u64)
            .read_to_end(&mut bytes)
            .map_err(WorkspaceError::io)?;
        if bytes.contains(&0) {
            Ok(None)
        } else {
            Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
        }
    }

    pub fn write_file(&self, relative: &str, content: &str) -> Result<()> {
        let path = safe_path(&self.path, relative)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(WorkspaceError::io)?;
        }
        std::fs::write(path, content).map_err(WorkspaceError::io)
    }

    /// The branch's head cut after folding the worktree in — the
    /// addressable base a reader carries into its next save (cut-on-read,
    /// spec §12: the state you saw is always a recorded cut).
    pub fn current_cut(&self) -> Result<Option<String>> {
        let mut vcs = self.store()?;
        sync_in(&mut vcs, &self.store_root, &self.branch, &self.path)?;
        Ok(vcs
            .get_branch(&self.branch)?
            .and_then(|row| row.head_cut_id))
    }

    /// Base-carrying editor save (SUB-6, text-merge spec §12.1): the
    /// whole verb — base check, region-memory apply, token merge, region
    /// resolution minting — is whip's `save_with_base`; this crate only
    /// folds the worktree in first and writes accepted bodies back out.
    /// A clean composition writes and returns provenance pieces; a real
    /// divergence writes NOTHING and returns the regions for the editor's
    /// fold. `resolutions` are the regions the user just settled in that
    /// fold: recorded as memory BEFORE the merge, so they both apply now
    /// and pay forward to every later merge that meets the same regions.
    pub fn save_file_with_base(
        &self,
        relative: &str,
        draft: &str,
        base: SaveBase<'_>,
        resolutions: &[RegionResolution],
    ) -> Result<SaveFileOutcome> {
        use whipplescript_store::vcs::SaveWithBaseOutcome;
        let mut vcs = self.store()?;
        sync_in(&mut vcs, &self.store_root, &self.branch, &self.path)?;
        let base_cut = match base {
            SaveBase::Cut(cut) => Some(cut.to_owned()),
            SaveBase::Content(body) => {
                // A pre-cut client names its base by content: find the
                // newest recorded cut that bound this path to exactly that
                // body (an empty base also matches a cut without the
                // path — the "file didn't exist yet" base).
                let id = vcs.content_store().put(body)?;
                let matching_cut = vcs
                    .list_cuts(&self.branch, 200)?
                    .into_iter()
                    .find(|cut| {
                        vcs.cut_manifest(&cut.cut_id)
                            .ok()
                            .flatten()
                            .is_some_and(|manifest| match manifest.get(relative) {
                                Some(bound) => *bound == id,
                                None => body.is_empty(),
                            })
                    })
                    .map(|cut| cut.cut_id);
                if matching_cut.is_some() {
                    matching_cut
                } else if self.read_file(relative).ok().as_deref() == Some(body) {
                    // A freshly materialized target basis can predate the
                    // branch's bounded content lookup. `sync_in` above made the
                    // exact bytes the current addressable head, so an unchanged
                    // editor base safely names that head without weakening the
                    // stale-base comparison.
                    vcs.get_branch(&self.branch)?
                        .and_then(|branch| branch.head_cut_id)
                } else {
                    None
                }
            }
        };
        let Some(base_cut) = base_cut else {
            return Err(WorkspaceError::msg(format!(
                "save of {relative}: the base the editor loaded matches no recorded state; \
                 reload the file and reapply the edit"
            )));
        };
        match vcs.save_with_base(
            &self.branch,
            relative,
            draft,
            &base_cut,
            resolutions,
            &fresh_cut_id("save"),
            &now_at(),
        )? {
            SaveWithBaseOutcome::Written { cut_id } => {
                self.write_file(relative, draft)?;
                Ok(SaveFileOutcome::Written { cut: cut_id })
            }
            SaveWithBaseOutcome::Merged {
                cut_id,
                merged,
                pieces,
            } => {
                self.write_file(relative, &merged)?;
                Ok(SaveFileOutcome::Merged {
                    cut: cut_id,
                    content: merged,
                    pieces,
                })
            }
            SaveWithBaseOutcome::Conflicted {
                head_cut_id,
                pieces,
            } => {
                let current = match std::fs::read_to_string(safe_path(&self.path, relative)?) {
                    Ok(body) => body,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(error) => return Err(WorkspaceError::io(error)),
                };
                Ok(SaveFileOutcome::Conflicted {
                    current,
                    current_cut: head_cut_id,
                    pieces,
                })
            }
            SaveWithBaseOutcome::UnknownBaseCut => Err(WorkspaceError::msg(format!(
                "save of {relative}: base cut `{base_cut}` is not a recorded state of this chat"
            ))),
            other => Err(WorkspaceError::msg(format!("save refused: {other:?}"))),
        }
    }

    /// Read-only twin of `save_file_with_base` (the live fold, §12.3):
    /// what WOULD the draft do against the file as it stands right now?
    /// Region memory applies exactly as it would on the save. `None` =
    /// the base cut isn't recorded here (reload).
    pub fn merge_preview(
        &self,
        relative: &str,
        draft: &str,
        base_cut: &str,
    ) -> Result<Option<MergePreview>> {
        let mut vcs = self.store()?;
        sync_in(&mut vcs, &self.store_root, &self.branch, &self.path)?;
        let Some(preview) = vcs.merge_preview(&self.branch, relative, draft, base_cut)? else {
            return Ok(None);
        };
        let merged = preview.clean.then(|| {
            preview
                .pieces
                .iter()
                .filter_map(|piece| match piece {
                    MergePiece::Merged { text, .. } => Some(text.as_str()),
                    MergePiece::Conflict { .. } => None,
                })
                .collect::<String>()
        });
        Ok(Some(MergePreview {
            current_cut: preview.head_cut_id,
            clean: preview.clean,
            merged,
            pieces: preview.pieces,
        }))
    }
}

// ---------------------------------------------------------------------------
// Worktree <-> branch projection (whip's materialize/import-back seam).

fn scratch_cache_path(store_root: &Path, branch: &str) -> PathBuf {
    store_root
        .join("scratch")
        .join(format!("{}.json", branch.replace('/', "__")))
}

/// The scratch handle for a persistent worktree: the persisted stat cache
/// when one survives, else a cache SEEDED FROM THE BRANCH MANIFEST whose
/// entries can never be trusted by fingerprint (impossible size) — every
/// file re-hashes once, unchanged content drops out by content id, and a
/// manifest path missing on disk still reports as removed. Lost caches
/// degrade to a slower scan, never to a wrong diff.
fn load_scratch(vcs: &NativeWorkspaceVcs, store_root: &Path, branch: &str) -> MaterializedScratch {
    if let Ok(body) = std::fs::read_to_string(scratch_cache_path(store_root, branch)) {
        if let Ok(cache) = StatCache::from_json(&body) {
            return MaterializedScratch {
                cache,
                key_of: BTreeMap::new(),
            };
        }
    }
    let manifest = vcs.manifest(branch).ok().flatten().unwrap_or_default();
    let entries = manifest
        .into_iter()
        .map(|(path, content_hash)| {
            (
                path,
                CachedEntry {
                    size: u64::MAX,
                    mtime_unix_nanos: 0,
                    content_hash,
                },
            )
        })
        .collect();
    MaterializedScratch {
        cache: StatCache {
            stamp_unix_nanos: now_nanos(),
            entries,
        },
        key_of: BTreeMap::new(),
    }
}

fn persist_scratch(store_root: &Path, branch: &str, cache: &StatCache) -> Result<()> {
    let path = scratch_cache_path(store_root, branch);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(WorkspaceError::io)?;
    }
    std::fs::write(path, cache.to_json()).map_err(WorkspaceError::io)
}

/// Scan the worktree and commit what changed as ONE cut on the branch.
/// `None` = nothing changed (no cut minted). A missing worktree directory
/// imports nothing — it means "not checked out here", never "everything
/// was deleted".
fn sync_in(
    vcs: &mut NativeWorkspaceVcs,
    store_root: &Path,
    branch: &str,
    root: &Path,
) -> Result<Option<String>> {
    if !root.is_dir() {
        return Ok(None);
    }
    let scratch = load_scratch(vcs, store_root, branch);
    let import = whipplescript_store::materialize::import_scratch(
        root,
        &scratch,
        vcs.content_store(),
        now_nanos(),
    )?;
    let manifest = vcs.manifest(branch)?.unwrap_or_default();
    let mut changed = import.changed;
    changed.retain(|path, hash| !is_chat_local_path(path) && manifest.get(path) != Some(hash));
    let removed: Vec<String> = import
        .removed
        .into_iter()
        .filter(|path| !is_chat_local_path(path) && manifest.contains_key(path))
        .collect();
    if changed.is_empty() && removed.is_empty() {
        persist_scratch(store_root, branch, &import.cache)?;
        return Ok(None);
    }
    let cut_id = fresh_cut_id("turn");
    match vcs.import_diff(branch, &changed, &removed, &cut_id, &now_at())? {
        VcsWriteOutcome::Written { cut_id, .. } => {
            persist_scratch(store_root, branch, &import.cache)?;
            Ok(Some(cut_id))
        }
        other => Err(WorkspaceError::msg(format!(
            "worktree import on `{branch}` refused: {other:?}"
        ))),
    }
}

/// Project the branch head into its worktree: clear files the manifest no
/// longer names, materialize the rest, persist the fresh stat cache.
///
/// A file the manifest does not name is not necessarily settled history — it
/// may be un-synced user or agent work (a file dropped into the worktree while
/// the host was down, or a failed import). So clearing never destroys bytes
/// (DR-0054 Phase A): unmanifested files move into the chat-local quarantine,
/// which cuts, diffs, and future syncs all ignore, and stay recoverable there.
fn sync_out(
    vcs: &mut NativeWorkspaceVcs,
    store_root: &Path,
    branch: &str,
    root: &Path,
) -> Result<()> {
    let manifest = vcs
        .manifest(branch)?
        .ok_or_else(|| WorkspaceError::msg(format!("no line `{branch}` to materialize")))?;
    std::fs::create_dir_all(root).map_err(WorkspaceError::io)?;
    let mut on_disk = Vec::new();
    walk_tree(root, root, &mut on_disk).map_err(WorkspaceError::io)?;
    let unmanifested: Vec<&FileEntry> = on_disk
        .iter()
        .filter(|entry| {
            !entry.is_dir && !manifest.contains_key(&entry.path) && !is_chat_local_path(&entry.path)
        })
        .collect();
    if !unmanifested.is_empty() {
        let quarantine = root
            .join(".gaugedesk-runtime")
            .join("quarantine")
            .join(now_nanos().to_string());
        for entry in unmanifested {
            let destination = quarantine.join(&entry.path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).map_err(WorkspaceError::io)?;
            }
            std::fs::rename(root.join(&entry.path), &destination).map_err(WorkspaceError::io)?;
        }
    }
    for entry in on_disk
        .iter()
        .rev()
        .filter(|entry| entry.is_dir && !is_chat_local_path(&entry.path))
    {
        // Bottom-up best-effort prune; non-empty directories refuse.
        let _ = std::fs::remove_dir(root.join(&entry.path));
    }
    let scratch = vcs
        .materialize_branch(branch, root, now_nanos())?
        .ok_or_else(|| WorkspaceError::msg(format!("no line `{branch}` to materialize")))?;
    persist_scratch(store_root, branch, &scratch.cache)
}

fn clear_worktree(root: &Path) -> Result<()> {
    if !root.is_dir() {
        return Ok(());
    }
    let mut on_disk = Vec::new();
    walk_tree(root, root, &mut on_disk).map_err(WorkspaceError::io)?;
    for entry in on_disk.iter().filter(|entry| !entry.is_dir) {
        std::fs::remove_file(root.join(&entry.path)).map_err(WorkspaceError::io)?;
    }
    for entry in on_disk.iter().rev().filter(|entry| entry.is_dir) {
        let _ = std::fs::remove_dir(root.join(&entry.path));
    }
    Ok(())
}

fn snapshot_local_files(root: &Path) -> Result<Vec<(String, String)>> {
    let mut tree = Vec::new();
    walk_tree(root, root, &mut tree).map_err(WorkspaceError::io)?;
    tree.into_iter()
        .filter(|entry| !entry.is_dir && is_chat_local_path(&entry.path))
        .map(|entry| {
            std::fs::read_to_string(root.join(&entry.path))
                .map(|body| (entry.path, body))
                .map_err(WorkspaceError::io)
        })
        .collect()
}

/// Unified-diff text for the reviewer surface: whip's own rendering per
/// entry, under the `diff --git` segment header both the engine's no-op
/// rule and the web client's changed-files parser key on.
fn render_diff(entries: &[DiffEntry]) -> String {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&format!(
            "diff --git a/{path} b/{path}\n",
            path = entry.path
        ));
        out.push_str(&entry.to_unified());
    }
    out
}

// ---------------------------------------------------------------------------
/// A consistent point-in-time copy of one sqlite file (WAL-safe: VACUUM
/// INTO serializes through the connection, not the filesystem).
fn snapshot_sqlite(path: &Path) -> Result<Vec<u8>> {
    if !path.exists() {
        return Err(WorkspaceError::msg(format!(
            "no store file at {}",
            path.display()
        )));
    }
    let connection =
        rusqlite::Connection::open(path).map_err(|error| WorkspaceError::msg(error.to_string()))?;
    let target = path.with_extension(format!("snapshot-{:x}", now_nanos()));
    let _ = std::fs::remove_file(&target);
    connection
        .execute("VACUUM INTO ?1", [target.to_string_lossy().as_ref()])
        .map_err(|error| WorkspaceError::msg(error.to_string()))?;
    let bytes = std::fs::read(&target).map_err(WorkspaceError::io);
    let _ = std::fs::remove_file(&target);
    bytes
}

fn parse_export(export: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let need = |condition: bool| {
        if condition {
            Ok(())
        } else {
            Err(WorkspaceError::msg("malformed workspace export"))
        }
    };
    need(export.len() >= 16 && &export[..8] == EXPORT_MAGIC)?;
    let mut offset = 8;
    let mut take = |bytes: &[u8]| -> Result<Vec<u8>> {
        need(bytes.len() >= offset + 8)?;
        let len =
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("8 bytes")) as usize;
        offset += 8;
        need(bytes.len() >= offset + len)?;
        let body = bytes[offset..offset + len].to_vec();
        offset += len;
        Ok(body)
    };
    let branches = take(export)?;
    let content = take(export)?;
    Ok((branches, content))
}

// ---------------------------------------------------------------------------
// Trait surface (dyn dispatch for the app's provider registry).

pub trait Workspace: Send {
    fn mainline(&self) -> &str;
    fn workstream_ref(&self, ws_id: &str) -> String;
    fn workstream_id_of(&self, target: &str) -> Option<String>;
    fn create_engagement(&self, id: &str) -> Result<Box<dyn ChatWorkspace>>;
    fn create_engagement_on(&self, id: &str, target: &str) -> Result<Box<dyn ChatWorkspace>>;
    fn fork_engagement_at(
        &self,
        id: &str,
        source_branch: &str,
        target: &str,
        cut_id: &str,
    ) -> Result<Box<dyn ChatWorkspace>>;
    fn remove_engagement(&self, id: &str) -> Result<()>;
    fn purge_unreachable_objects(&self) -> Result<()>;
    fn reconcile_engagements(&self) -> Result<Vec<(String, Box<dyn ChatWorkspace>)>>;
    fn create_workstream(&self, ws_id: &str) -> Result<()>;
    fn promote_workstream_to_main(&self, ws_id: &str) -> Result<MergeOutcome>;
    fn seed_main(&self, files: &[(&str, &str)]) -> Result<()>;
    fn export(&self) -> Result<WorkspaceExport>;
    fn export_format(&self) -> &'static str;
    fn peer_source(&self) -> PeerSource;
    fn pull_from(&self, src: &PeerSource) -> Result<MergeOutcome>;
}

pub trait ChatWorkspace: Send {
    /// An owned copy of this handle.
    ///
    /// A chat workspace is a *locator* — roots, a path, a branch, a target — and
    /// every operation opens its backing store on demand. So a copy is cheap, and
    /// it is what lets a long agent turn hold its workspace without holding the
    /// workbench lock that owns the engagement map for the turn's whole duration.
    fn boxed_clone(&self) -> Box<dyn ChatWorkspace>;
    fn path(&self) -> &Path;
    fn branch(&self) -> &str;
    fn target(&self) -> &str;
    fn set_target(&mut self, target: &str) -> Result<()>;
    fn rehome(&mut self, target: &str) -> Result<()>;
    fn commit_turn(&self, message: &str) -> Result<Option<RevisionId>>;
    fn boundary_cut(&self) -> Result<RevisionId>;
    /// Exact revision/fingerprint currently held by the target authority.
    fn standing_revision(&self) -> Result<RevisionId>;
    /// Adapter-specific publication (for example `git push`). It is never
    /// implied by apply and must be invoked through a separately admitted act.
    fn publish(&self) -> Result<RevisionId> {
        Err(WorkspaceError::msg(
            "this workspace adapter has no publisher",
        ))
    }
    fn diff_against_main(&self) -> Result<String>;
    fn revert_to_main(&self) -> Result<()>;
    fn sync_from_main(&self) -> Result<MergeOutcome>;
    fn merge_probe(&self) -> Result<MergeOutcome>;
    fn merge_into_main(&self) -> Result<MergeOutcome>;
    fn ingest(&self, source: &Path) -> Result<usize>;
    fn ingest_upload(&self, files: &[(String, String)]) -> Result<usize>;
    fn tree(&self) -> Result<Vec<FileEntry>>;
    fn read_file(&self, rel: &str) -> Result<String>;
    fn read_file_capped(&self, rel: &str, max_bytes: usize) -> Result<Option<String>>;
    fn write_file(&self, rel: &str, content: &str) -> Result<()>;
    fn current_cut(&self) -> Result<Option<String>>;
    fn save_file_with_base(
        &self,
        rel: &str,
        draft: &str,
        base: SaveBase<'_>,
        resolutions: &[RegionResolution],
    ) -> Result<SaveFileOutcome>;
    fn merge_preview(&self, rel: &str, draft: &str, base_cut: &str)
        -> Result<Option<MergePreview>>;
}

impl Workspace for Instance {
    fn mainline(&self) -> &str {
        MAINLINE_BRANCH_ID
    }
    fn workstream_ref(&self, id: &str) -> String {
        Self::workstream_ref(id)
    }
    fn workstream_id_of(&self, target: &str) -> Option<String> {
        target
            .strip_prefix("workstream/")
            .and_then(|value| value.strip_suffix("/main"))
            .map(str::to_string)
    }
    fn create_engagement(&self, id: &str) -> Result<Box<dyn ChatWorkspace>> {
        Ok(Box::new(Self::create_engagement(self, id)?))
    }
    fn create_engagement_on(&self, id: &str, target: &str) -> Result<Box<dyn ChatWorkspace>> {
        Ok(Box::new(Self::create_engagement_on(self, id, target)?))
    }
    fn fork_engagement_at(
        &self,
        id: &str,
        source_branch: &str,
        target: &str,
        cut_id: &str,
    ) -> Result<Box<dyn ChatWorkspace>> {
        Ok(Box::new(Self::fork_engagement_at(
            self,
            id,
            source_branch,
            target,
            cut_id,
        )?))
    }
    fn remove_engagement(&self, id: &str) -> Result<()> {
        Self::remove_engagement(self, id)
    }
    fn purge_unreachable_objects(&self) -> Result<()> {
        Self::purge_unreachable_objects(self)
    }
    fn reconcile_engagements(&self) -> Result<Vec<(String, Box<dyn ChatWorkspace>)>> {
        Ok(Self::reconcile_engagements(self)?
            .into_iter()
            .map(|(id, chat)| (id, Box::new(chat) as Box<dyn ChatWorkspace>))
            .collect())
    }
    fn create_workstream(&self, id: &str) -> Result<()> {
        Self::create_workstream(self, id)
    }
    fn promote_workstream_to_main(&self, id: &str) -> Result<MergeOutcome> {
        Self::promote_workstream_to_main(self, id)
    }
    fn seed_main(&self, files: &[(&str, &str)]) -> Result<()> {
        Self::seed_main(self, files)
    }
    fn export(&self) -> Result<WorkspaceExport> {
        Self::export(self)
    }
    fn export_format(&self) -> &'static str {
        Self::export_format(self)
    }
    fn peer_source(&self) -> PeerSource {
        Self::peer_source(self)
    }
    fn pull_from(&self, source: &PeerSource) -> Result<MergeOutcome> {
        Self::pull_from(self, source)
    }
}

impl ChatWorkspace for Engagement {
    fn boxed_clone(&self) -> Box<dyn ChatWorkspace> {
        Box::new(self.clone())
    }
    fn path(&self) -> &Path {
        self.path()
    }
    fn branch(&self) -> &str {
        self.branch()
    }
    fn target(&self) -> &str {
        self.target()
    }
    fn set_target(&mut self, target: &str) -> Result<()> {
        self.set_target(target)
    }
    fn rehome(&mut self, target: &str) -> Result<()> {
        self.rehome(target)
    }
    fn commit_turn(&self, message: &str) -> Result<Option<RevisionId>> {
        self.commit_turn(message)
    }
    fn boundary_cut(&self) -> Result<RevisionId> {
        self.boundary_cut()
    }
    fn standing_revision(&self) -> Result<RevisionId> {
        self.boundary_cut()
    }
    fn diff_against_main(&self) -> Result<String> {
        self.diff_against_main()
    }
    fn revert_to_main(&self) -> Result<()> {
        self.revert_to_main()
    }
    fn sync_from_main(&self) -> Result<MergeOutcome> {
        self.sync_from_main()
    }
    fn merge_probe(&self) -> Result<MergeOutcome> {
        self.merge_probe()
    }
    fn merge_into_main(&self) -> Result<MergeOutcome> {
        self.merge_into_main()
    }
    fn ingest(&self, source: &Path) -> Result<usize> {
        self.ingest(source)
    }
    fn ingest_upload(&self, files: &[(String, String)]) -> Result<usize> {
        self.ingest_upload(files)
    }
    fn tree(&self) -> Result<Vec<FileEntry>> {
        self.tree()
    }
    fn read_file(&self, relative: &str) -> Result<String> {
        self.read_file(relative)
    }
    fn read_file_capped(&self, relative: &str, max_bytes: usize) -> Result<Option<String>> {
        self.read_file_capped(relative, max_bytes)
    }
    fn write_file(&self, relative: &str, content: &str) -> Result<()> {
        self.write_file(relative, content)
    }
    fn current_cut(&self) -> Result<Option<String>> {
        self.current_cut()
    }
    fn save_file_with_base(
        &self,
        relative: &str,
        draft: &str,
        base: SaveBase<'_>,
        resolutions: &[RegionResolution],
    ) -> Result<SaveFileOutcome> {
        self.save_file_with_base(relative, draft, base, resolutions)
    }
    fn merge_preview(
        &self,
        relative: &str,
        draft: &str,
        base_cut: &str,
    ) -> Result<Option<MergePreview>> {
        self.merge_preview(relative, draft, base_cut)
    }
}

pub trait WorkspaceProvider: Send + Sync {
    fn export_format(&self) -> &'static str;
    fn init_at(&self, dir: &Path) -> Result<Box<dyn Workspace>>;
    fn open_at(&self, dir: &Path) -> Box<dyn Workspace>;
    #[allow(clippy::wrong_self_convention)]
    fn from_export_at(&self, dir: &Path, export: &[u8]) -> Result<Box<dyn Workspace>>;
    fn fork_from_at(&self, dir: &Path, source: &PeerSource) -> Result<Box<dyn Workspace>>;
}

pub struct WhippleWorkspaceProvider;

impl WorkspaceProvider for WhippleWorkspaceProvider {
    fn export_format(&self) -> &'static str {
        EXPORT_FORMAT
    }
    fn init_at(&self, dir: &Path) -> Result<Box<dyn Workspace>> {
        Ok(Box::new(Instance::init_at(dir)?))
    }
    fn open_at(&self, dir: &Path) -> Box<dyn Workspace> {
        Box::new(Instance::open_at(dir))
    }
    fn from_export_at(&self, dir: &Path, export: &[u8]) -> Result<Box<dyn Workspace>> {
        Ok(Box::new(Instance::from_export_at(dir, export)?))
    }
    fn fork_from_at(&self, dir: &Path, source: &PeerSource) -> Result<Box<dyn Workspace>> {
        Ok(Box::new(Instance::fork_from_at(dir, source)?))
    }
}

const _: fn(&dyn Workspace, &dyn ChatWorkspace, &dyn WorkspaceProvider) = |_, _, _| {};

fn engagement_line(id: &str) -> String {
    format!("engagement/{id}")
}
fn store_root_for(repo: &Path) -> PathBuf {
    let name = repo
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("workspace");
    repo.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{name}.whipplescript"))
}

fn write_substrate_stamp(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root).map_err(WorkspaceError::io)?;
    std::fs::write(
        root.join("substrate.json"),
        format!("{{\"substrate\":\"whipplescript\",\"format\":\"{EXPORT_FORMAT}\"}}\n"),
    )
    .map_err(WorkspaceError::io)
}

fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(WorkspaceError::msg(format!(
            "path {relative} escapes the worktree"
        )));
    }
    Ok(root.join(path))
}

fn walk_tree(root: &Path, directory: &Path, result: &mut Vec<FileEntry>) -> std::io::Result<()> {
    if !directory.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name() == ".git" {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            continue;
        }
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        result.push(FileEntry {
            path: relative,
            is_dir: kind.is_dir(),
        });
        if kind.is_dir() {
            walk_tree(root, &path, result)?;
        }
    }
    Ok(())
}

fn copy_dir(source: &Path, target: &Path) -> Result<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir(source).map_err(WorkspaceError::io)? {
        let entry = entry.map_err(WorkspaceError::io)?;
        if entry.file_name() == ".git" {
            continue;
        }
        let kind = entry.file_type().map_err(WorkspaceError::io)?;
        if kind.is_symlink() {
            continue;
        }
        let destination = target.join(entry.file_name());
        if kind.is_dir() {
            std::fs::create_dir_all(&destination).map_err(WorkspaceError::io)?;
            count += copy_dir(&entry.path(), &destination)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), destination).map_err(WorkspaceError::io)?;
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance() -> (tempfile::TempDir, Instance) {
        let directory = tempfile::tempdir().expect("temp");
        let instance = Instance::init(
            directory.path().join("repo"),
            directory.path().join("worktrees"),
        )
        .expect("init");
        (directory, instance)
    }

    /// SUB-6 save contract: an unmoved file writes plain; a concurrent
    /// disjoint edit MERGES through whip's token-level engine (both
    /// sides' words survive); overlapping rewrites write NOTHING and
    /// return three-slice regions for the fold.
    #[test]
    fn save_with_base_merges_disjoint_and_folds_conflicts() {
        let (_directory, instance) = instance();
        let eng = instance.create_engagement("edit").expect("engagement");
        let base = "The quick brown fox jumps over the lazy dog tonight.";
        eng.write_file("notes.md", base).expect("seed");
        // Fast path: nothing moved. A content-named base (pre-cut client)
        // resolves to its recorded cut.
        let outcome = eng
            .save_file_with_base(
                "notes.md",
                "The swift brown fox jumps over the lazy dog tonight.",
                SaveBase::Content(base),
                &[],
            )
            .expect("save");
        assert!(
            matches!(outcome, SaveFileOutcome::Written { .. }),
            "expected plain write, got {outcome:?}"
        );
        // An agent turn moves the file while the editor holds a draft
        // based on the earlier content: edits six words apart compose.
        let agent = "The swift grey fox jumps over the lazy dog tonight.";
        eng.write_file("notes.md", agent).expect("agent write");
        let outcome = eng
            .save_file_with_base(
                "notes.md",
                "The swift brown fox jumps over the lazy dog today.",
                SaveBase::Content("The swift brown fox jumps over the lazy dog tonight."),
                &[],
            )
            .expect("save");
        let SaveFileOutcome::Merged { content, .. } = &outcome else {
            panic!("expected merge, got {outcome:?}");
        };
        assert_eq!(content, "The swift grey fox jumps over the lazy dog today.");
        assert_eq!(eng.read_file("notes.md").expect("read"), *content);
        // Overlapping rewrites: nothing written, regions returned, and the
        // cut-carrying base (the §12 shape) round-trips.
        let head_cut = eng.current_cut().expect("cut").expect("recorded");
        eng.write_file(
            "notes.md",
            "The swift brown fox jumps over the lazy tiger today.",
        )
        .expect("agent write 2");
        let outcome = eng
            .save_file_with_base(
                "notes.md",
                "The swift brown fox jumps over the lazy lion today.",
                SaveBase::Cut(&head_cut),
                &[],
            )
            .expect("save");
        let SaveFileOutcome::Conflicted {
            current,
            current_cut,
            pieces,
        } = &outcome
        else {
            panic!("expected conflict, got {outcome:?}");
        };
        assert_eq!(
            current,
            "The swift brown fox jumps over the lazy tiger today."
        );
        assert!(current_cut.is_some(), "the re-save base is addressable");
        assert!(pieces
            .iter()
            .any(|piece| matches!(piece, MergePiece::Conflict { .. })));
        assert_eq!(
            eng.read_file("notes.md").expect("read"),
            "The swift brown fox jumps over the lazy tiger today.",
            "a conflicted save writes nothing"
        );
    }

    /// Region memory end-to-end at the editor surface: a fold resolution
    /// travels with the re-save, applies immediately (the same regions
    /// compose via memory), and PAYS FORWARD — the identical divergence
    /// in a different file later auto-applies with `resolved` provenance,
    /// never re-asking.
    #[test]
    fn region_resolution_applies_and_pays_forward_across_files() {
        let (_directory, instance) = instance();
        let eng = instance.create_engagement("mem").expect("engagement");
        let base = "Alpha beta gamma delta epsilon zeta eta theta.";
        let agent = "Alpha beta AGENT-GAMMA delta epsilon zeta eta theta.";
        let draft = "Alpha beta EDITOR-GAMMA delta epsilon zeta eta theta.";

        eng.write_file("one.md", base).expect("seed");
        let base_cut = eng.current_cut().expect("cut").expect("recorded");
        eng.write_file("one.md", agent).expect("agent write");
        let outcome = eng
            .save_file_with_base("one.md", draft, SaveBase::Cut(&base_cut), &[])
            .expect("save");
        let SaveFileOutcome::Conflicted {
            current_cut,
            pieces,
            ..
        } = outcome
        else {
            panic!("expected the first divergence to conflict, got {outcome:?}");
        };
        // The user settles the region by hand in the fold; the re-save
        // carries the settled triple.
        let resolution = pieces
            .iter()
            .find_map(|piece| match piece {
                MergePiece::Conflict {
                    base_text,
                    ours_text,
                    theirs_text,
                } => Some(RegionResolution {
                    base_text: base_text.clone(),
                    ours_text: ours_text.clone(),
                    theirs_text: theirs_text.clone(),
                    resolution_text: "SETTLED-GAMMA".to_owned(),
                }),
                MergePiece::Merged { .. } => None,
            })
            .expect("a conflict region");
        // The fold composes the resolved document (merged spans + the
        // settled text) and re-saves it against the file's current cut —
        // a plain write that CARRIES the settled triples into memory.
        let resolved: String = pieces
            .iter()
            .map(|piece| match piece {
                MergePiece::Merged { text, .. } => text.as_str(),
                MergePiece::Conflict { .. } => "SETTLED-GAMMA",
            })
            .collect();
        let outcome = eng
            .save_file_with_base(
                "one.md",
                &resolved,
                SaveBase::Cut(current_cut.as_deref().expect("re-save base")),
                std::slice::from_ref(&resolution),
            )
            .expect("resolved save");
        assert!(
            matches!(outcome, SaveFileOutcome::Written { .. }),
            "the race-checked re-save lands plain: {outcome:?}"
        );
        assert!(
            eng.read_file("one.md")
                .expect("read")
                .contains("SETTLED-GAMMA"),
            "the settled text landed"
        );

        // Pay-forward: the SAME divergence in a different file composes
        // through memory — resolved provenance, no fold.
        eng.write_file("two.md", base).expect("seed two");
        let base_cut = eng.current_cut().expect("cut").expect("recorded");
        eng.write_file("two.md", agent).expect("agent write two");
        let outcome = eng
            .save_file_with_base("two.md", draft, SaveBase::Cut(&base_cut), &[])
            .expect("save two");
        let SaveFileOutcome::Merged {
            content, pieces, ..
        } = &outcome
        else {
            panic!("expected memory to auto-apply, got {outcome:?}");
        };
        assert!(
            content.contains("SETTLED-GAMMA"),
            "memory replayed the settled text: {content}"
        );
        assert!(
            pieces.iter().any(|piece| matches!(
                piece,
                MergePiece::Merged {
                    provenance: Provenance::Resolved,
                    ..
                }
            )),
            "the replayed region is honestly tagged as remembered"
        );
    }

    #[test]
    fn engagement_isolated_until_kept_and_conflicts_do_not_mutate_main() {
        let (_directory, instance) = instance();
        instance.seed_main(&[("same.txt", "base")]).expect("seed");
        let a = instance.create_engagement("a").expect("a");
        let b = instance.create_engagement("b").expect("b");
        a.write_file("a.txt", "a").expect("write");
        a.commit_turn("a").expect("cut");
        assert!(!instance.repo().join("a.txt").exists());
        assert_eq!(a.merge_into_main().expect("merge"), MergeOutcome::Clean);
        assert_eq!(
            std::fs::read_to_string(instance.repo().join("a.txt")).expect("main"),
            "a"
        );
        a.write_file("same.txt", "from a").expect("write a");
        b.write_file("same.txt", "from b").expect("write b");
        a.commit_turn("a2").expect("cut a");
        b.commit_turn("b2").expect("cut b");
        assert_eq!(a.merge_into_main().expect("merge a2"), MergeOutcome::Clean);
        assert_eq!(
            b.merge_into_main().expect("merge b"),
            MergeOutcome::Conflict
        );
        assert_eq!(
            std::fs::read_to_string(instance.repo().join("same.txt")).expect("unchanged"),
            "from a"
        );
    }

    #[test]
    fn export_fork_workstream_restore_and_erasure_round_trip() {
        let (_directory, instance) = instance();
        instance.seed_main(&[("base.txt", "base")]).expect("seed");
        instance.create_workstream("team").expect("workstream");
        let chat = instance
            .create_engagement_on("chat", "workstream/team/main")
            .expect("chat");
        chat.write_file("work.txt", "work").expect("write");
        chat.commit_turn("turn").expect("cut");
        assert_eq!(
            chat.merge_into_main().expect("stream merge"),
            MergeOutcome::Clean
        );
        assert_eq!(
            instance
                .promote_workstream_to_main("team")
                .expect("promote"),
            MergeOutcome::Clean
        );
        chat.revert_to_main().expect("restore");
        let export = instance.export().expect("export");
        assert_eq!(instance.export_format(), EXPORT_FORMAT);
        let target = tempfile::tempdir().expect("target");
        let imported = Instance::from_export_at(target.path(), &export.0).expect("import");
        assert!(imported.repo().join("work.txt").exists());
        let fork = tempfile::tempdir().expect("fork");
        let forked = Instance::fork_from_at(fork.path(), &instance.peer_source()).expect("fork");
        assert!(forked.repo().join("work.txt").exists());
    }

    #[test]
    fn no_op_cut_and_file_facets_remain_compatible() {
        let (_directory, instance) = instance();
        let chat = instance.create_engagement("chat").expect("chat");
        assert!(chat.commit_turn("nothing").expect("noop").is_some());
        chat.ingest_upload(&[("../safe.txt".into(), "safe".into())])
            .expect("upload");
        assert_eq!(chat.read_file("safe.txt").expect("read"), "safe");
        assert!(chat.write_file("../escape", "no").is_err());
        assert!(chat
            .tree()
            .expect("tree")
            .iter()
            .any(|entry| entry.path == "safe.txt"));
        assert!(chat.diff_against_main().expect("diff").contains("safe.txt"));
        // The GC sweep is safe to run on a live instance: everything the
        // chat can still read survives it.
        instance.purge_unreachable_objects().expect("purge");
        assert_eq!(chat.read_file("safe.txt").expect("read"), "safe");
        assert!(chat.diff_against_main().expect("diff").contains("safe.txt"));
    }

    #[test]
    fn engagement_fork_pins_an_earlier_durable_cut() {
        let (_directory, instance) = instance();
        let chat = instance.create_engagement("source").expect("source");
        chat.write_file("answer.txt", "one").expect("write one");
        let first = chat.commit_turn("one").expect("first").expect("cut");
        chat.write_file("answer.txt", "two").expect("write two");
        chat.commit_turn("two").expect("second").expect("cut");

        let fork = instance
            .fork_engagement_at("fork", chat.branch(), chat.target(), &first.0)
            .expect("fork at first");
        assert_eq!(fork.read_file("answer.txt").expect("fork body"), "one");
        assert_eq!(chat.read_file("answer.txt").expect("source body"), "two");
    }

    #[test]
    fn workstream_member_promotion_materializes_into_a_sibling() {
        let (_directory, instance) = instance();
        let mut a = instance.create_engagement("a").expect("a");
        let mut b = instance.create_engagement("b").expect("b");
        instance.create_workstream("team").expect("workstream");
        instance
            .create_workstream("team")
            .expect("idempotent ensure");
        a.set_target("workstream/team/main").expect("home a");
        b.set_target("workstream/team/main").expect("home b");
        a.write_file("shared.txt", "from a").expect("write");
        a.commit_turn("turn").expect("cut");
        assert_eq!(a.merge_into_main().expect("promote"), MergeOutcome::Clean);
        assert_eq!(b.sync_from_main().expect("sync"), MergeOutcome::Clean);
        assert_eq!(b.read_file("shared.txt").expect("materialized"), "from a");
    }

    #[test]
    fn settled_rehome_materializes_destination_without_carrying_old_line() {
        let (_directory, instance) = instance();
        instance.create_workstream("one").expect("one");
        instance.create_workstream("two").expect("two");

        let one = instance
            .create_engagement_on("one-writer", "workstream/one/main")
            .expect("one writer");
        one.write_file("one.txt", "only one").expect("write one");
        one.commit_turn("one").expect("cut one");
        assert_eq!(
            one.merge_into_main().expect("land one"),
            MergeOutcome::Clean
        );

        let two = instance
            .create_engagement_on("two-writer", "workstream/two/main")
            .expect("two writer");
        two.write_file("two.txt", "only two").expect("write two");
        two.commit_turn("two").expect("cut two");
        assert_eq!(
            two.merge_into_main().expect("land two"),
            MergeOutcome::Clean
        );

        let mut chat = instance
            .create_engagement_on("moving", "workstream/one/main")
            .expect("moving");
        assert_eq!(chat.read_file("one.txt").expect("old line"), "only one");
        chat.rehome("workstream/two/main").expect("rehome");
        assert_eq!(chat.target(), "workstream/two/main");
        assert_eq!(chat.read_file("two.txt").expect("new line"), "only two");
        assert!(
            chat.read_file("one.txt").is_err(),
            "old line must not travel"
        );
        assert!(chat.diff_against_main().expect("settled diff").is_empty());
    }

    #[test]
    fn rehome_preserves_the_ephemeral_discipline_mount() {
        let (_directory, instance) = instance();
        instance.create_workstream("team").expect("team");
        let mut chat = instance.create_engagement("moving").expect("chat");
        chat.write_file(".gaugedesk-runtime/discipline/checks/review.sh", "exit 0\n")
            .expect("runtime mount");

        chat.rehome("workstream/team/main").expect("rehome");
        assert_eq!(
            chat.read_file(".gaugedesk-runtime/discipline/checks/review.sh")
                .expect("preserved runtime mount"),
            "exit 0\n"
        );
        assert!(chat.diff_against_main().expect("target diff").is_empty());
        assert_eq!(chat.target(), "workstream/team/main");
    }

    #[test]
    fn rehome_refuses_an_unsettled_candidate() {
        let (_directory, instance) = instance();
        instance.create_workstream("one").expect("one");
        instance.create_workstream("two").expect("two");
        let mut chat = instance
            .create_engagement_on("moving", "workstream/one/main")
            .expect("moving");
        chat.write_file("candidate.txt", "keep me")
            .expect("candidate");
        chat.commit_turn("candidate").expect("cut");

        let error = chat.rehome("workstream/two/main").expect_err("must refuse");
        assert!(error.to_string().contains("unsettled workspace changes"));
        assert_eq!(chat.target(), "workstream/one/main");
        assert_eq!(
            chat.read_file("candidate.txt").expect("preserved"),
            "keep me"
        );
    }

    /// Peer federation over the vcs substrate: a fork shares cut history,
    /// so a later pull three-ways against the shared base — the puller's
    /// own advance survives alongside the peer's.
    #[test]
    fn fork_then_pull_folds_peer_advance_without_losing_local_work() {
        let (_directory, instance) = instance();
        instance.seed_main(&[("shared.txt", "base")]).expect("seed");
        let fork_dir = tempfile::tempdir().expect("fork");
        let forked =
            Instance::fork_from_at(fork_dir.path(), &instance.peer_source()).expect("fork");
        // Peer advances one file; we advance another.
        forked
            .seed_main(&[("peer.txt", "peer work")])
            .expect("peer");
        instance
            .seed_main(&[("local.txt", "local work")])
            .expect("local");
        assert!(instance.updates_available_from(forked.repo()));
        assert_eq!(
            instance.pull_from(&forked.peer_source()).expect("pull"),
            MergeOutcome::Clean
        );
        assert_eq!(
            std::fs::read_to_string(instance.repo().join("peer.txt")).expect("peer file"),
            "peer work"
        );
        assert_eq!(
            std::fs::read_to_string(instance.repo().join("local.txt")).expect("local file"),
            "local work"
        );
    }

    /// DR-0054 Phase A: worktree projection never destroys bytes. A file the
    /// branch manifest does not name (dropped into the worktree without a
    /// sync-in — an interrupted agent, a user copy while the host was down) is
    /// quarantined under the chat-local runtime area, not deleted.
    #[test]
    fn sync_out_quarantines_unmanifested_files_instead_of_destroying_them() {
        let (_directory, instance) = instance();
        instance
            .seed_main(&[("tracked.txt", "tracked")])
            .expect("seed");
        let chat = instance.create_engagement("keeper").expect("chat");

        // Dropped in behind the store's back: on disk, in no manifest.
        std::fs::write(chat.path().join("dropped.txt"), "irreplaceable bytes").expect("drop");

        // revert_to_main restores the target head and re-projects the
        // worktree — the sync_out path that used to delete the file.
        chat.revert_to_main().expect("revert");

        assert!(
            !chat.path().join("dropped.txt").exists(),
            "sync semantics stay clean: the unmanifested file leaves the tree"
        );
        let quarantine = chat.path().join(".gaugedesk-runtime").join("quarantine");
        let stamp = std::fs::read_dir(&quarantine)
            .expect("quarantine directory exists")
            .next()
            .expect("one quarantine sweep")
            .expect("readable entry")
            .path();
        assert_eq!(
            std::fs::read_to_string(stamp.join("dropped.txt")).expect("preserved bytes"),
            "irreplaceable bytes",
            "the bytes stay recoverable in the chat-local quarantine"
        );
    }

    #[test]
    fn opening_a_pre_target_layout_is_rejected_without_migration() {
        let directory = tempfile::tempdir().expect("temp");
        let repo = directory.path().join("repo");
        let worktrees = directory.path().join("worktrees");
        std::fs::create_dir_all(repo.join(".git")).expect("legacy metadata");
        std::fs::write(repo.join("main.txt"), "main").expect("main snapshot");
        std::fs::create_dir_all(worktrees.join("chat")).expect("legacy chat");
        std::fs::write(worktrees.join("chat/.git"), "gitdir: elsewhere")
            .expect("worktree metadata");
        std::fs::write(worktrees.join("chat/draft.txt"), "draft").expect("draft snapshot");

        let instance = Instance::open(&repo, &worktrees);
        let error = instance
            .reconcile_engagements()
            .err()
            .expect("pre-target layout must fail");
        assert!(error.to_string().contains("pre-target workspace layout"));
        assert!(
            repo.join(".git").exists(),
            "rejection must not mutate old state"
        );
        assert!(worktrees.join("chat/.git").exists());
    }
}

#[cfg(test)]
mod workspace_store_contention {
    use whipplescript_store::vcs::NativeWorkspaceVcs;

    /// The workspace store is opened afresh on **every** operation
    /// ([`Workspace::store`]), so a single turn is many short-lived connections
    /// rather than one long-lived handle. Each open re-runs
    /// `PRAGMA journal_mode = WAL` *before* `PRAGMA busy_timeout`, which means
    /// the prelude runs with a timeout of zero.
    ///
    /// That ordering looks like the cause of the `SQLITE_BUSY` seen on a task
    /// that follows a stop (`CMP-17`), and it is not: `journal_mode` on a
    /// database already in WAL is a read, and neither plain concurrency nor a
    /// held write lock makes an open fail. This test exists to keep that answer
    /// from having to be re-derived, and to catch the day the prelude does start
    /// needing a lock.
    /// Why `busy_timeout` does not save the write above, shown on raw SQLite.
    ///
    /// A **deferred** transaction takes SHARED on its first read and then tries
    /// to upgrade on its first write. If another connection already holds the
    /// write lock, SQLite returns `SQLITE_BUSY` *immediately* and deliberately
    /// does not invoke the busy handler — waiting while holding SHARED is how
    /// two connections deadlock. An **immediate** transaction takes the write
    /// lock up front, with no SHARED to deadlock against, so the handler applies
    /// and it waits.
    ///
    /// `whipplescript-store`'s `branches.rs` uses `connection.transaction()`,
    /// which is rusqlite's deferred default. GaugeDesk's own store uses
    /// `TransactionBehavior::Immediate` at every one of its transaction sites.
    #[test]
    fn deferred_upgrades_fail_instantly_where_immediate_waits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe.sqlite");
        let setup = rusqlite::Connection::open(&path).unwrap();
        setup
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE rows (id INTEGER PRIMARY KEY, v TEXT);
                 INSERT INTO rows (id, v) VALUES (1, 'seed');",
            )
            .unwrap();

        let attempt = |behaviour: rusqlite::TransactionBehavior| {
            let holder = rusqlite::Connection::open(&path).unwrap();
            holder
                .execute_batch("BEGIN IMMEDIATE; INSERT INTO rows (v) VALUES ('held');")
                .unwrap();

            let writer = rusqlite::Connection::open(&path).unwrap();
            // The same 5 s the dependency asks for.
            writer
                .busy_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            let started = std::time::Instant::now();
            let begin = match behaviour {
                rusqlite::TransactionBehavior::Immediate => "BEGIN IMMEDIATE",
                _ => "BEGIN DEFERRED",
            };
            let outcome = (|| -> rusqlite::Result<()> {
                writer.execute_batch(begin)?;
                // A read first, which is what makes a deferred transaction take
                // SHARED and then have to upgrade.
                let _: i64 = writer.query_row("SELECT count(*) FROM rows", [], |row| row.get(0))?;
                writer.execute("INSERT INTO rows (v) VALUES ('writer')", [])?;
                writer.execute_batch("COMMIT")
            })();
            let _ = writer.execute_batch("ROLLBACK");
            let waited = started.elapsed().as_millis();
            holder.execute_batch("ROLLBACK").unwrap();
            (outcome.is_err(), waited)
        };

        let (deferred_failed, deferred_ms) = attempt(rusqlite::TransactionBehavior::Deferred);
        assert!(
            deferred_failed && deferred_ms < 500,
            "expected a deferred upgrade to be refused at once; failed={deferred_failed} after {deferred_ms}ms",
        );

        let (immediate_failed, immediate_ms) = attempt(rusqlite::TransactionBehavior::Immediate);
        assert!(
            immediate_failed && immediate_ms >= 4_000,
            "expected an immediate transaction to wait out busy_timeout; failed={immediate_failed} after {immediate_ms}ms",
        );
    }

    /// The decisive CMP-17 experiment: does `busy_timeout` apply to a **write**
    /// through this API, as opposed to an open?
    ///
    /// A second connection holds the write lock for 1.5 s. If the handler is in
    /// force, the write waits and then succeeds. If it is not, the write fails
    /// immediately — which is what the reproduction shows in the engine, where
    /// six concurrent commits into one target fail about 20 ms after they begin
    /// rather than after the 5 s the pragma asks for.
    /// Fixed upstream in whipplescript-src#91, which opens every write
    /// transaction in `branches.rs` and `workstreams.rs` `Immediate`, and
    /// released as `whipplescript-store` 0.4.2 — a single-crate backport off
    /// 0.4.1, because `main` has since moved rusqlite 0.32 → 0.40 and
    /// `libsqlite3-sys` declares `links = "sqlite3"`, so this repository could
    /// not have resolved a store built against 0.40 at all.
    ///
    /// This is the durable guard that the fix is present: it fails after ~1 ms
    /// against a store without it, and waits out the full hold with it. Keep it
    /// running rather than ignored — a dependency bump that silently reverted the
    /// behaviour would otherwise be invisible until it reached a user.
    #[test]
    fn a_write_waits_for_a_held_lock_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        let branches = dir.path().join("branches.sqlite");
        let content = dir.path().join("content.sqlite");
        let mut vcs = NativeWorkspaceVcs::open(branches.clone(), content.clone()).unwrap();
        vcs.init(&crate::now_at()).unwrap();

        let holding = std::sync::Arc::new(std::sync::Barrier::new(2));
        let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let holder = {
            let (branches, holding, released) = (
                branches.clone(),
                std::sync::Arc::clone(&holding),
                std::sync::Arc::clone(&released),
            );
            std::thread::spawn(move || {
                let conn = rusqlite::Connection::open(&branches).unwrap();
                conn.execute_batch("BEGIN IMMEDIATE").unwrap();
                holding.wait();
                std::thread::sleep(std::time::Duration::from_millis(1500));
                released.store(true, std::sync::atomic::Ordering::SeqCst);
                conn.execute_batch("COMMIT").unwrap();
            })
        };

        holding.wait();
        let started = std::time::Instant::now();
        let mut changed = std::collections::BTreeMap::new();
        changed.insert("probe.txt".to_string(), "hash-probe".to_string());
        let outcome = vcs.import_diff(
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            &changed,
            &[],
            "cut-probe",
            &crate::now_at(),
        );
        let waited = started.elapsed();
        let saw_release = released.load(std::sync::atomic::Ordering::SeqCst);
        holder.join().unwrap();

        assert!(
            outcome.is_ok(),
            "the write failed after {}ms (lock released first: {saw_release}) — busy_timeout is \
             not in force for this statement: {:?}",
            waited.as_millis(),
            outcome.err(),
        );
    }

    #[test]
    fn opening_the_store_survives_concurrency_and_a_held_write_lock() {
        let dir = tempfile::tempdir().unwrap();
        let branches = dir.path().join("branches.sqlite");
        let content = dir.path().join("content.sqlite");
        drop(NativeWorkspaceVcs::open(branches.clone(), content.clone()).unwrap());

        let stop = std::sync::atomic::AtomicBool::new(false);
        let mut failures: Vec<String> = Vec::new();
        std::thread::scope(|scope| {
            // Behaves like a turn committing: take the write lock, hold it
            // briefly, release, repeat.
            let writer = scope.spawn(|| {
                let conn = rusqlite::Connection::open(&branches).unwrap();
                conn.busy_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if conn.execute_batch("BEGIN IMMEDIATE").is_ok() {
                        std::thread::sleep(std::time::Duration::from_millis(15));
                        let _ = conn.execute_batch("COMMIT");
                    }
                }
            });

            let handles: Vec<_> = (0..6)
                .map(|_| {
                    let (b, c) = (branches.clone(), content.clone());
                    scope.spawn(move || {
                        let mut seen = Vec::new();
                        for _ in 0..60 {
                            if let Err(error) = NativeWorkspaceVcs::open(b.clone(), c.clone()) {
                                seen.push(format!("{error:?}"));
                            }
                        }
                        seen
                    })
                })
                .collect();
            for handle in handles {
                failures.extend(handle.join().unwrap());
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            writer.join().unwrap();
        });
        assert!(
            failures.is_empty(),
            "{} of 360 opens failed under a concurrent writer; first: {}",
            failures.len(),
            failures.first().unwrap()
        );
    }
}
