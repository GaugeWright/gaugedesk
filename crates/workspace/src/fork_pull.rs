//! Immutable fork-preview data and the existing Main publication fence.
use super::{Instance, NativeWorkspaceVcs, Result, WorkspaceError};
use std::collections::BTreeMap;
use whipplescript_store::vcs::{GateCommit, GateVerdict, MainlineGate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainSnapshot {
    cut: Option<String>,
    files: BTreeMap<String, String>,
}

impl MainSnapshot {
    pub fn cut(&self) -> Option<&str> {
        self.cut.as_deref()
    }
    pub fn files(&self) -> &BTreeMap<String, String> {
        &self.files
    }
}

impl Instance {
    /// Head and immutable manifest agree even if Main moves during the read.
    pub fn main_snapshot(&self) -> Result<MainSnapshot> {
        let vcs = NativeWorkspaceVcs::open_read_only(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )?;
        let cut = vcs
            .get_branch(super::MAINLINE_BRANCH_ID)?
            .ok_or_else(|| WorkspaceError::msg("Main is unavailable"))?
            .head_cut_id;
        let files = match &cut {
            None => BTreeMap::new(),
            Some(cut) => vcs
                .cut_manifest(cut)?
                .ok_or_else(|| WorkspaceError::msg("preview cut is unavailable"))?,
        };
        Ok(MainSnapshot { cut, files })
    }

    /// Bytes from the exact observed cut, including chunked and binary content.
    pub fn read_snapshot_file(
        &self,
        snapshot: &MainSnapshot,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        let Some(id) = snapshot.files.get(path) else {
            return Ok(None);
        };
        let vcs = NativeWorkspaceVcs::open_read_only(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )?;
        vcs.content_store().get(id).map_err(Into::into)
    }
}

pub(super) struct PreviewMainlineGate<'a> {
    pub expected: Option<Option<&'a str>>,
}

impl MainlineGate for PreviewMainlineGate<'_> {
    fn prepare(
        &mut self,
        base: Option<&str>,
        _proposed: &str,
        _artifacts: &whipplescript_store::norm_commands::NormArtifactCapture<'_>,
    ) -> whipplescript_store::StoreResult<GateVerdict> {
        if let Some(expected) = self.expected {
            if base != expected {
                return Err(whipplescript_store::StoreError::Conflict(
                    "fork Main changed after preview; preview again".into(),
                ));
            }
        }
        Ok(GateVerdict::Admit)
    }
    fn commit(
        &mut self,
        advance: &mut dyn FnMut() -> whipplescript_store::StoreResult<()>,
    ) -> whipplescript_store::StoreResult<GateCommit> {
        advance()?;
        Ok(GateCommit::Committed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_binary_snapshot_and_expected_parent_survive_real_main_movement() {
        let directory = tempfile::tempdir().expect("owned workspace");
        let workspace = Instance::init_at(directory.path()).expect("initialize");
        let first = workspace.create_engagement("first").expect("first line");
        first
            .write_file_bytes("image.bin", &[0, 255, 128])
            .expect("binary");
        first.commit_turn("first").expect("cut");
        first.merge_into_main().expect("publish");
        let snapshot = workspace.main_snapshot().expect("snapshot");
        let incoming = workspace
            .fork_engagement_at(
                "incoming",
                "main",
                "main",
                snapshot.cut().expect("recorded cut"),
            )
            .expect("pinned incoming");
        incoming
            .write_file("other.txt", "incoming")
            .expect("incoming file");
        incoming.commit_turn("incoming").expect("incoming cut");
        let later = workspace.create_engagement("later").expect("later line");
        later
            .write_file_bytes("image.bin", &[1, 2, 3])
            .expect("later binary");
        later.commit_turn("later").expect("later cut");
        later.merge_into_main().expect("later publish");
        let current = workspace.main_snapshot().expect("current");
        assert_eq!(
            workspace
                .read_snapshot_file(&snapshot, "image.bin")
                .expect("immutable bytes"),
            Some(vec![0, 255, 128])
        );
        assert!(
            incoming.merge_into_main_at(snapshot.cut()).is_err(),
            "a clean merge cannot bypass the expected parent"
        );
        assert_eq!(workspace.main_snapshot().expect("unchanged Main"), current);
    }
    #[test]
    fn empty_parent_and_same_content_publication_are_fenced() {
        let directory = tempfile::tempdir().expect("owned workspace");
        let workspace = Instance::init_at(directory.path()).expect("initialize");
        let empty = workspace.main_snapshot().expect("empty snapshot");
        assert_eq!(empty.cut(), None);
        let pending = workspace
            .create_engagement("pending")
            .expect("empty pending line");
        let later = workspace.create_engagement("later").expect("later line");
        later.write_file("new.txt", "later").expect("later file");
        later.commit_turn("later").expect("cut");
        later.merge_into_main().expect("publish");
        let current = workspace.main_snapshot().expect("current");
        assert!(
            pending.merge_into_main_at(None).is_err(),
            "empty preview is a guarded revision"
        );
        assert_eq!(workspace.main_snapshot().expect("unchanged Main"), current);
        let no_op = workspace
            .create_engagement("no-op")
            .expect("same-content line");
        assert_eq!(
            no_op
                .merge_into_main_at(current.cut())
                .expect("fresh same-content publish"),
            super::super::MergeOutcome::Clean
        );
        let next = workspace.main_snapshot().expect("next");
        assert_eq!(next.files(), current.files());
        assert_ne!(next.cut(), current.cut());
        let fresh = tempfile::tempdir().expect("fresh workspace");
        let workspace = Instance::init_at(fresh.path()).expect("initialize");
        let no_op = workspace
            .create_engagement("empty-no-op")
            .expect("empty line");
        assert_eq!(
            no_op.merge_into_main_at(None).expect("fresh empty publish"),
            super::super::MergeOutcome::Clean
        );
        assert!(workspace
            .main_snapshot()
            .expect("certified empty Main")
            .cut()
            .is_some());
    }
}
