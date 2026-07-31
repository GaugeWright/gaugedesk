use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    ChatWorkspace, FileEntry, MergeOutcome, MergePreview, PeerSource, RegionResolution, Result,
    RevisionId, SaveBase, SaveFileOutcome, Workspace, WorkspaceError, WorkspaceExport,
};

const METADATA_FILE: &str = "candidate.json";
const EXTERNAL_EXPORT_FORMAT: &str = "gaugedesk-external-target-v1";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalTargetKind {
    Git,
    Folder,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CandidateMetadata {
    id: String,
    kind: ExternalTargetKind,
    basis: String,
}

/// An adapter-owned external target. The source path is protected control
/// state; runs receive only isolated candidate directories under `state_root`.
pub struct ExternalWorkspace {
    source: PathBuf,
    state_root: PathBuf,
    kind: ExternalTargetKind,
}

impl ExternalWorkspace {
    pub fn open(
        source: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        kind: ExternalTargetKind,
    ) -> Result<Self> {
        let source = source.into();
        let state_root = state_root.into();
        if !source.is_dir() {
            return Err(WorkspaceError::msg(
                "external target source is not a directory",
            ));
        }
        reject_symlinks(&source)?;
        if kind == ExternalTargetKind::Git {
            git(&source, &["rev-parse", "--is-inside-work-tree"])?;
            if !git(&source, &["status", "--porcelain"])?.is_empty() {
                return Err(WorkspaceError::msg(
                    "external Git target must be clean when attached",
                ));
            }
            if source.join(".gitmodules").is_file() {
                return Err(WorkspaceError::msg(
                    "Git submodules are not supported by this target adapter",
                ));
            }
        }
        std::fs::create_dir_all(state_root.join("candidates")).map_err(WorkspaceError::io)?;
        std::fs::create_dir_all(state_root.join("bases")).map_err(WorkspaceError::io)?;
        Ok(Self {
            source,
            state_root,
            kind,
        })
    }

    pub fn exact_basis(&self) -> Result<String> {
        exact_basis(&self.source, self.kind)
    }

    pub fn can_publish(&self) -> bool {
        self.kind == ExternalTargetKind::Git
            && git(
                &self.source,
                &[
                    "rev-parse",
                    "--abbrev-ref",
                    "--symbolic-full-name",
                    "@{upstream}",
                ],
            )
            .is_ok()
    }

    fn candidate_path(&self, id: &str) -> PathBuf {
        self.state_root.join("candidates").join(id)
    }

    fn base_path(&self, id: &str) -> PathBuf {
        self.state_root.join("bases").join(id)
    }

    fn metadata_path(&self, id: &str) -> PathBuf {
        self.state_root
            .join("metadata")
            .join(id)
            .join(METADATA_FILE)
    }

    fn materialize(&self, id: &str) -> Result<ExternalCandidate> {
        let basis = self.exact_basis()?;
        let candidate = self.candidate_path(id);
        let base = self.base_path(id);
        if candidate.exists() || base.exists() {
            return Err(WorkspaceError::msg("external candidate already exists"));
        }
        match self.kind {
            ExternalTargetKind::Git => {
                run(
                    Command::new("git")
                        .arg("clone")
                        .arg("--no-hardlinks")
                        .arg("--quiet")
                        .arg(&self.source)
                        .arg(&candidate),
                    "clone external Git target",
                )?;
                git(&candidate, &["checkout", "--quiet", "--detach", &basis])?;
                std::fs::write(candidate.join(".git/info/exclude"), ".gaugedesk-runtime/\n")
                    .map_err(WorkspaceError::io)?;
            }
            ExternalTargetKind::Folder => copy_tree(&self.source, &candidate)?,
        }
        copy_tree(&candidate, &base)?;
        let metadata = CandidateMetadata {
            id: id.to_owned(),
            kind: self.kind,
            basis: basis.clone(),
        };
        write_metadata(&self.metadata_path(id), &metadata)?;
        Ok(ExternalCandidate {
            source: self.source.clone(),
            candidate,
            base_snapshot: base,
            metadata,
            branch: format!("candidate/{id}"),
        })
    }

    fn load_candidate(&self, id: &str) -> Result<ExternalCandidate> {
        let metadata = read_metadata(&self.metadata_path(id))?;
        Ok(ExternalCandidate {
            source: self.source.clone(),
            candidate: self.candidate_path(id),
            base_snapshot: self.base_path(id),
            metadata,
            branch: format!("candidate/{id}"),
        })
    }
}

impl Workspace for ExternalWorkspace {
    fn mainline(&self) -> &str {
        "external-authority"
    }

    fn workstream_ref(&self, ws_id: &str) -> String {
        format!("unsupported/{ws_id}")
    }

    fn workstream_id_of(&self, _target: &str) -> Option<String> {
        None
    }

    fn create_engagement(&self, id: &str) -> Result<Box<dyn ChatWorkspace>> {
        Ok(Box::new(self.materialize(id)?))
    }

    fn create_engagement_on(&self, id: &str, _target: &str) -> Result<Box<dyn ChatWorkspace>> {
        self.create_engagement(id)
    }

    fn fork_engagement_at(
        &self,
        _id: &str,
        _source_branch: &str,
        _target: &str,
        _cut_id: &str,
    ) -> Result<Box<dyn ChatWorkspace>> {
        Err(WorkspaceError::msg(
            "external candidates must be proposed from a fresh exact basis",
        ))
    }

    fn remove_engagement(&self, id: &str) -> Result<()> {
        remove_if_exists(&self.candidate_path(id))?;
        remove_if_exists(&self.base_path(id))?;
        remove_if_exists(self.metadata_path(id).parent().expect("metadata parent"))
    }

    fn purge_unreachable_objects(&self) -> Result<()> {
        Ok(())
    }

    fn reconcile_engagements(&self) -> Result<Vec<(String, Box<dyn ChatWorkspace>)>> {
        let root = self.state_root.join("metadata");
        if !root.is_dir() {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        for entry in std::fs::read_dir(root).map_err(WorkspaceError::io)? {
            let entry = entry.map_err(WorkspaceError::io)?;
            if entry.file_type().map_err(WorkspaceError::io)?.is_dir() {
                let id = entry.file_name().to_string_lossy().to_string();
                result.push((
                    id.clone(),
                    Box::new(self.load_candidate(&id)?) as Box<dyn ChatWorkspace>,
                ));
            }
        }
        result.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(result)
    }

    fn create_workstream(&self, _ws_id: &str) -> Result<()> {
        Err(WorkspaceError::msg(
            "external targets do not have GaugeDesk-owned shared lines",
        ))
    }

    fn promote_workstream_to_main(&self, _ws_id: &str) -> Result<MergeOutcome> {
        Err(WorkspaceError::msg(
            "external targets require their adapter-specific apply act",
        ))
    }

    fn seed_main(&self, _files: &[(&str, &str)]) -> Result<()> {
        Err(WorkspaceError::msg(
            "an external target is seeded by its authority",
        ))
    }

    fn export(&self) -> Result<WorkspaceExport> {
        Err(WorkspaceError::msg(
            "external target bytes are not owned by GaugeDesk relocation",
        ))
    }

    fn export_format(&self) -> &'static str {
        EXTERNAL_EXPORT_FORMAT
    }

    fn peer_source(&self) -> PeerSource {
        PeerSource(self.state_root.clone())
    }

    fn pull_from(&self, _src: &PeerSource) -> Result<MergeOutcome> {
        Err(WorkspaceError::msg(
            "external target authority cannot be replaced by a GaugeDesk pull",
        ))
    }
}

#[derive(Clone)]
struct ExternalCandidate {
    source: PathBuf,
    candidate: PathBuf,
    base_snapshot: PathBuf,
    metadata: CandidateMetadata,
    branch: String,
}

impl ExternalCandidate {
    fn candidate_revision(&self) -> Result<String> {
        exact_basis(&self.candidate, self.metadata.kind)
    }

    fn source_is_at_basis(&self) -> Result<bool> {
        Ok(exact_basis(&self.source, self.metadata.kind)? == self.metadata.basis)
    }

    fn commit_git(&self, message: &str) -> Result<Option<RevisionId>> {
        git(&self.candidate, &["add", "-A"])?;
        let changed = !git(&self.candidate, &["status", "--porcelain"])?.is_empty();
        if !changed {
            return Ok(None);
        }
        run(
            Command::new("git")
                .current_dir(&self.candidate)
                .env("GIT_AUTHOR_NAME", "GaugeDesk Candidate")
                .env("GIT_AUTHOR_EMAIL", "candidate@gaugedesk.invalid")
                .env("GIT_COMMITTER_NAME", "GaugeDesk Candidate")
                .env("GIT_COMMITTER_EMAIL", "candidate@gaugedesk.invalid")
                .arg("commit")
                .arg("--quiet")
                .arg("-m")
                .arg(message),
            "commit external Git candidate",
        )?;
        Ok(Some(RevisionId(self.candidate_revision()?)))
    }

    fn apply_git(&self) -> Result<MergeOutcome> {
        if !self.source_is_at_basis()? || !git(&self.source, &["status", "--porcelain"])?.is_empty()
        {
            return Ok(MergeOutcome::Conflict);
        }
        let head = self.candidate_revision()?;
        if head == self.metadata.basis {
            return Ok(MergeOutcome::Clean);
        }
        let range = format!("{}..{head}", self.metadata.basis);
        let commits = git(&self.candidate, &["rev-list", "--reverse", &range])?;
        for commit in commits.lines() {
            let patch = run_output(
                Command::new("git")
                    .current_dir(&self.candidate)
                    .arg("format-patch")
                    .arg("--stdout")
                    .arg("-1")
                    .arg(commit),
                "render external Git commit",
            )?;
            let mut child = Command::new("git")
                .current_dir(&self.source)
                .env("GIT_COMMITTER_NAME", "GaugeDesk Apply")
                .env("GIT_COMMITTER_EMAIL", "apply@gaugedesk.invalid")
                .arg("am")
                .arg("--quiet")
                .arg("--3way")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .map_err(WorkspaceError::io)?;
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .expect("piped stdin")
                .write_all(&patch)
                .map_err(WorkspaceError::io)?;
            let status = child.wait().map_err(WorkspaceError::io)?;
            if !status.success() {
                let _ = git(&self.source, &["am", "--abort"]);
                return Ok(MergeOutcome::Conflict);
            }
        }
        Ok(MergeOutcome::Clean)
    }

    fn apply_folder(&self) -> Result<MergeOutcome> {
        if !self.source_is_at_basis()? {
            return Ok(MergeOutcome::Conflict);
        }
        sync_tree(&self.candidate, &self.source)?;
        Ok(MergeOutcome::Clean)
    }
}

impl ChatWorkspace for ExternalCandidate {
    fn boxed_clone(&self) -> Box<dyn ChatWorkspace> {
        Box::new(self.clone())
    }
    fn path(&self) -> &Path {
        &self.candidate
    }

    fn branch(&self) -> &str {
        &self.branch
    }

    fn target(&self) -> &str {
        "external-authority"
    }

    fn set_target(&mut self, _target: &str) -> Result<()> {
        Err(WorkspaceError::msg(
            "external candidates cannot be retargeted",
        ))
    }

    fn rehome(&mut self, _target: &str) -> Result<()> {
        Err(WorkspaceError::msg(
            "external candidates cannot join managed lines",
        ))
    }

    fn commit_turn(&self, message: &str) -> Result<Option<RevisionId>> {
        match self.metadata.kind {
            ExternalTargetKind::Git => self.commit_git(message),
            ExternalTargetKind::Folder => {
                let revision = self.candidate_revision()?;
                let base_candidate = exact_basis(&self.base_snapshot, ExternalTargetKind::Folder)?;
                Ok((revision != base_candidate).then_some(RevisionId(revision)))
            }
        }
    }

    fn boundary_cut(&self) -> Result<RevisionId> {
        Ok(RevisionId(self.metadata.basis.clone()))
    }

    fn standing_revision(&self) -> Result<RevisionId> {
        Ok(RevisionId(exact_basis(&self.source, self.metadata.kind)?))
    }

    fn publish(&self) -> Result<RevisionId> {
        if self.metadata.kind != ExternalTargetKind::Git {
            return Err(WorkspaceError::msg(
                "unversioned folders have no native publisher",
            ));
        }
        git(&self.source, &["push"])?;
        self.standing_revision()
    }

    fn diff_against_main(&self) -> Result<String> {
        match self.metadata.kind {
            ExternalTargetKind::Git => git(
                &self.candidate,
                &[
                    "diff",
                    "--no-ext-diff",
                    "--binary",
                    &self.metadata.basis,
                    "HEAD",
                ],
            ),
            ExternalTargetKind::Folder => folder_diff(&self.base_snapshot, &self.candidate),
        }
    }

    fn revert_to_main(&self) -> Result<()> {
        match self.metadata.kind {
            ExternalTargetKind::Git => {
                git(&self.candidate, &["reset", "--hard", &self.metadata.basis])?;
                git(
                    &self.candidate,
                    &["clean", "-fd", "-e", ".gaugedesk-runtime/"],
                )?;
                Ok(())
            }
            ExternalTargetKind::Folder => {
                remove_if_exists(&self.candidate)?;
                copy_tree(&self.base_snapshot, &self.candidate)
            }
        }
    }

    fn sync_from_main(&self) -> Result<MergeOutcome> {
        if self.source_is_at_basis()? {
            Ok(MergeOutcome::Clean)
        } else {
            Ok(MergeOutcome::Conflict)
        }
    }

    fn merge_probe(&self) -> Result<MergeOutcome> {
        self.sync_from_main()
    }

    fn merge_into_main(&self) -> Result<MergeOutcome> {
        match self.metadata.kind {
            ExternalTargetKind::Git => self.apply_git(),
            ExternalTargetKind::Folder => self.apply_folder(),
        }
    }

    fn ingest(&self, source: &Path) -> Result<usize> {
        let before = file_map(&self.candidate)?.len();
        copy_tree(source, &self.candidate)?;
        Ok(file_map(&self.candidate)?.len().saturating_sub(before))
    }

    fn ingest_upload(&self, files: &[(String, String)]) -> Result<usize> {
        for (path, body) in files {
            self.write_file(path, body)?;
        }
        Ok(files.len())
    }

    fn tree(&self) -> Result<Vec<FileEntry>> {
        let mut entries = Vec::new();
        walk(&self.candidate, &self.candidate, &mut entries)?;
        Ok(entries)
    }

    fn read_file(&self, rel: &str) -> Result<String> {
        std::fs::read_to_string(safe_path(&self.candidate, rel)?).map_err(WorkspaceError::io)
    }

    fn read_file_capped(&self, rel: &str, max_bytes: usize) -> Result<Option<String>> {
        let bytes = std::fs::read(safe_path(&self.candidate, rel)?).map_err(WorkspaceError::io)?;
        Ok((bytes.len() <= max_bytes).then(|| String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn write_file(&self, rel: &str, content: &str) -> Result<()> {
        let path = safe_path(&self.candidate, rel)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(WorkspaceError::io)?;
        }
        std::fs::write(path, content).map_err(WorkspaceError::io)
    }

    fn current_cut(&self) -> Result<Option<String>> {
        Ok(Some(self.candidate_revision()?))
    }

    fn save_file_with_base(
        &self,
        rel: &str,
        draft: &str,
        base: SaveBase<'_>,
        _resolutions: &[RegionResolution],
    ) -> Result<SaveFileOutcome> {
        let current = self.read_file(rel).unwrap_or_default();
        let matches = match base {
            SaveBase::Cut(cut) => self.current_cut()?.as_deref() == Some(cut),
            SaveBase::Content(content) => current == content,
        };
        if !matches {
            return Ok(SaveFileOutcome::Conflicted {
                current,
                current_cut: self.current_cut()?,
                pieces: Vec::new(),
            });
        }
        self.write_file(rel, draft)?;
        let cut = self
            .commit_turn(&format!("edit {rel}"))?
            .map(|revision| revision.0)
            .unwrap_or(self.candidate_revision()?);
        Ok(SaveFileOutcome::Written { cut })
    }

    fn merge_preview(
        &self,
        _rel: &str,
        _draft: &str,
        base_cut: &str,
    ) -> Result<Option<MergePreview>> {
        let current = self.current_cut()?;
        Ok(Some(MergePreview {
            clean: current.as_deref() == Some(base_cut),
            current_cut: current,
            merged: None,
            pieces: Vec::new(),
        }))
    }
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let mut command = Command::new("git");
    command.current_dir(root).args(args);
    let output = run_output(&mut command, "run Git target adapter")?;
    Ok(String::from_utf8_lossy(&output).trim().to_owned())
}

fn run(command: &mut Command, operation: &str) -> Result<()> {
    let status = command.status().map_err(WorkspaceError::io)?;
    if status.success() {
        Ok(())
    } else {
        Err(WorkspaceError::msg(format!("{operation} failed: {status}")))
    }
}

fn run_output(command: &mut Command, operation: &str) -> Result<Vec<u8>> {
    let output = command.output().map_err(WorkspaceError::io)?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(WorkspaceError::msg(format!(
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn exact_basis(root: &Path, kind: ExternalTargetKind) -> Result<String> {
    match kind {
        ExternalTargetKind::Git => git(root, &["rev-parse", "HEAD"]),
        ExternalTargetKind::Folder => fingerprint(root),
    }
}

fn fingerprint(root: &Path) -> Result<String> {
    let files = file_map(root)?;
    let mut digest = Sha256::new();
    for (path, body) in files {
        digest.update((path.len() as u64).to_be_bytes());
        digest.update(path.as_bytes());
        digest.update((body.len() as u64).to_be_bytes());
        digest.update(&body);
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn file_map(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut entries = Vec::new();
    walk(root, root, &mut entries)?;
    entries
        .into_iter()
        .filter(|entry| !entry.is_dir && !runtime_path(&entry.path))
        .map(|entry| {
            std::fs::read(root.join(&entry.path))
                .map(|body| (entry.path, body))
                .map_err(WorkspaceError::io)
        })
        .collect()
}

fn folder_diff(base: &Path, candidate: &Path) -> Result<String> {
    let before = file_map(base)?;
    let after = file_map(candidate)?;
    let mut paths = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    let mut diff = String::new();
    for path in paths {
        if before.get(&path) == after.get(&path) {
            continue;
        }
        diff.push_str(&format!("diff --git a/{path} b/{path}\n"));
        diff.push_str(&format!("--- a/{path}\n+++ b/{path}\n"));
        let old = before
            .get(&path)
            .map(|body| String::from_utf8_lossy(body))
            .unwrap_or_default();
        let new = after
            .get(&path)
            .map(|body| String::from_utf8_lossy(body))
            .unwrap_or_default();
        for line in old.lines() {
            diff.push('-');
            diff.push_str(line);
            diff.push('\n');
        }
        for line in new.lines() {
            diff.push('+');
            diff.push_str(line);
            diff.push('\n');
        }
    }
    Ok(diff)
}

fn sync_tree(source: &Path, destination: &Path) -> Result<()> {
    let source_files = file_map(source)?;
    let destination_files = file_map(destination)?;
    for path in destination_files.keys() {
        if !source_files.contains_key(path) {
            std::fs::remove_file(destination.join(path)).map_err(WorkspaceError::io)?;
        }
    }
    for (path, body) in source_files {
        let target = destination.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(WorkspaceError::io)?;
        }
        std::fs::write(target, body).map_err(WorkspaceError::io)?;
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination).map_err(WorkspaceError::io)?;
    for entry in std::fs::read_dir(source).map_err(WorkspaceError::io)? {
        let entry = entry.map_err(WorkspaceError::io)?;
        let name = entry.file_name();
        if name == ".git" || name == ".gaugedesk-runtime" {
            continue;
        }
        let kind = entry.file_type().map_err(WorkspaceError::io)?;
        if kind.is_symlink() {
            continue;
        }
        let target = destination.join(name);
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), target).map_err(WorkspaceError::io)?;
        }
    }
    Ok(())
}

fn walk(root: &Path, directory: &Path, result: &mut Vec<FileEntry>) -> Result<()> {
    for entry in std::fs::read_dir(directory).map_err(WorkspaceError::io)? {
        let entry = entry.map_err(WorkspaceError::io)?;
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let kind = entry.file_type().map_err(WorkspaceError::io)?;
        if kind.is_symlink() {
            continue;
        }
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .expect("walk root")
            .to_string_lossy()
            .replace('\\', "/");
        result.push(FileEntry {
            path: relative,
            is_dir: kind.is_dir(),
        });
        if kind.is_dir() {
            walk(root, &path, result)?;
        }
    }
    Ok(())
}

fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(WorkspaceError::msg("path escapes the target candidate"));
    }
    Ok(root.join(path))
}

fn runtime_path(path: &str) -> bool {
    path == ".gaugedesk-runtime" || path.starts_with(".gaugedesk-runtime/")
}

fn reject_symlinks(root: &Path) -> Result<()> {
    for entry in std::fs::read_dir(root).map_err(WorkspaceError::io)? {
        let entry = entry.map_err(WorkspaceError::io)?;
        if entry.file_name() == ".git" {
            continue;
        }
        let kind = entry.file_type().map_err(WorkspaceError::io)?;
        if kind.is_symlink() {
            return Err(WorkspaceError::msg(format!(
                "external target contains unsupported symlink {}",
                entry.path().display()
            )));
        }
        if kind.is_dir() {
            reject_symlinks(&entry.path())?;
        }
    }
    Ok(())
}

fn write_metadata(path: &Path, metadata: &CandidateMetadata) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(WorkspaceError::io)?;
    }
    std::fs::write(
        path,
        serde_json::to_vec(metadata).map_err(|error| WorkspaceError::msg(error.to_string()))?,
    )
    .map_err(WorkspaceError::io)
}

fn read_metadata(path: &Path) -> Result<CandidateMetadata> {
    let body = std::fs::read(path).map_err(WorkspaceError::io)?;
    serde_json::from_slice(&body).map_err(|error| WorkspaceError::msg(error.to_string()))
}

fn remove_if_exists(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_dir_all(path).map_err(WorkspaceError::io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_candidate_is_isolated_and_rejects_a_stale_apply() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("a.txt"), "one\n").unwrap();
        let state = tempfile::tempdir().unwrap();
        let workspace =
            ExternalWorkspace::open(source.path(), state.path(), ExternalTargetKind::Folder)
                .unwrap();
        let candidate = workspace.create_engagement("chat").unwrap();
        candidate.write_file("a.txt", "candidate\n").unwrap();
        candidate.commit_turn("change").unwrap();
        assert_eq!(
            std::fs::read_to_string(source.path().join("a.txt")).unwrap(),
            "one\n"
        );
        std::fs::write(source.path().join("a.txt"), "concurrent\n").unwrap();
        assert_eq!(candidate.merge_probe().unwrap(), MergeOutcome::Conflict);
        assert_eq!(candidate.merge_into_main().unwrap(), MergeOutcome::Conflict);
        assert_eq!(
            std::fs::read_to_string(source.path().join("a.txt")).unwrap(),
            "concurrent\n"
        );
    }

    #[test]
    fn git_candidate_keeps_native_history_and_applies_only_on_exact_head() {
        let source = tempfile::tempdir().unwrap();
        git(source.path(), &["init", "--quiet"]).unwrap();
        std::fs::write(source.path().join("a.txt"), "one\n").unwrap();
        git(source.path(), &["add", "a.txt"]).unwrap();
        run(
            Command::new("git")
                .current_dir(source.path())
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
                .arg("commit")
                .arg("--quiet")
                .arg("-m")
                .arg("base"),
            "commit fixture",
        )
        .unwrap();
        let state = tempfile::tempdir().unwrap();
        let workspace =
            ExternalWorkspace::open(source.path(), state.path(), ExternalTargetKind::Git).unwrap();
        let candidate = workspace.create_engagement("chat").unwrap();
        candidate.write_file("a.txt", "candidate\n").unwrap();
        candidate.commit_turn("candidate").unwrap();
        assert!(candidate.diff_against_main().unwrap().contains("candidate"));
        assert_eq!(candidate.merge_into_main().unwrap(), MergeOutcome::Clean);
        assert_eq!(
            std::fs::read_to_string(source.path().join("a.txt")).unwrap(),
            "candidate\n"
        );
        assert_eq!(
            git(source.path(), &["rev-list", "--count", "HEAD"]).unwrap(),
            "2"
        );
    }

    #[test]
    fn git_publish_is_explicit_and_pushes_an_applied_revision() {
        let remote = tempfile::tempdir().unwrap();
        git(remote.path(), &["init", "--bare", "--quiet"]).unwrap();
        let source = tempfile::tempdir().unwrap();
        git(source.path(), &["init", "--quiet"]).unwrap();
        std::fs::write(source.path().join("a.txt"), "one\n").unwrap();
        git(source.path(), &["add", "a.txt"]).unwrap();
        run(
            Command::new("git")
                .current_dir(source.path())
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
                .arg("commit")
                .arg("--quiet")
                .arg("-m")
                .arg("base"),
            "commit fixture",
        )
        .unwrap();
        git(
            source.path(),
            &["remote", "add", "origin", remote.path().to_str().unwrap()],
        )
        .unwrap();
        git(source.path(), &["push", "--quiet", "-u", "origin", "HEAD"]).unwrap();

        let state = tempfile::tempdir().unwrap();
        let workspace =
            ExternalWorkspace::open(source.path(), state.path(), ExternalTargetKind::Git).unwrap();
        assert!(workspace.can_publish());
        let candidate = workspace.create_engagement("chat").unwrap();
        candidate.write_file("a.txt", "published\n").unwrap();
        candidate.commit_turn("candidate").unwrap();
        assert_eq!(candidate.merge_into_main().unwrap(), MergeOutcome::Clean);
        let applied = candidate.standing_revision().unwrap();
        assert_eq!(candidate.publish().unwrap(), applied);
        assert_eq!(
            git(remote.path(), &["rev-parse", "HEAD"]).unwrap(),
            applied.0
        );
    }
}
