//! Exact saved workflow source from an admitted native work target. A source
//! snapshot is data, not an access grant. No disk edits are imported by reading.

use super::{Instance, NativeWorkspaceVcs, Result, WorkspaceError, MAINLINE_BRANCH_ID};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowSource {
    pub cut: String,
    pub content_hash: String,
    pub content: String,
}

impl Instance {
    /// Read an exact retained revision on this target's Main ancestry. The host
    /// admits the actual target/path before this read, then retains the returned
    /// bytes with its invocation before reporting successful launch.
    pub fn workflow_source(
        &self,
        path: &str,
        cut: &str,
        byte_limit: usize,
    ) -> Result<WorkflowSource> {
        if !super::valid_native_action_target_path(path) || cut.is_empty() {
            return Err(WorkspaceError::msg(
                "workflow source has invalid coordinates",
            ));
        }
        let vcs = NativeWorkspaceVcs::open_read_only(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )?;
        let head = vcs
            .get_branch(MAINLINE_BRANCH_ID)?
            .and_then(|branch| branch.head_cut_id)
            .ok_or_else(|| {
                WorkspaceError::msg("workflow source target has no saved Main revision")
            })?;
        if vcs.cut_chain(&head, cut)?.is_none() {
            return Err(WorkspaceError::msg(
                "workflow source revision is outside the target Main ancestry",
            ));
        }
        let content = vcs
            .read_at_cut(cut, path)?
            .ok_or_else(|| WorkspaceError::msg("saved workflow source is unavailable"))?;
        if content.len() > byte_limit {
            return Err(WorkspaceError::msg(
                "workflow source exceeds its admitted byte budget",
            ));
        }
        Ok(WorkflowSource {
            cut: cut.into(),
            content_hash: whipplescript_store::stable_hash_hex(&content),
            content,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_reads_exact_saved_revision_without_importing_disk_edits() {
        let directory = tempfile::tempdir().unwrap();
        let workspace = Instance::init_at(directory.path()).unwrap();
        workspace
            .seed_main(&[("tutorials/basics.whip", "original source")])
            .unwrap();
        let cut = workspace.current_main_cut().unwrap().unwrap();
        std::fs::write(
            workspace.repo().join("tutorials/basics.whip"),
            "uncommitted changes",
        )
        .unwrap();
        let source = workspace
            .workflow_source("tutorials/basics.whip", &cut, 4096)
            .unwrap();
        assert_eq!(source.content, "original source");
        assert_eq!(
            source.content_hash,
            whipplescript_store::stable_hash_hex("original source")
        );
        assert_eq!(
            workspace.current_main_cut().unwrap().as_deref(),
            Some(cut.as_str())
        );
        assert!(workspace
            .workflow_source("tutorials/basics.whip", &cut, 2)
            .is_err());
        assert!(workspace
            .workflow_source("../outside.whip", &cut, 4096)
            .is_err());
        assert!(workspace
            .workflow_source("missing.whip", &cut, 4096)
            .is_err());
        assert!(workspace
            .workflow_source("tutorials/basics.whip", "foreign-cut", 4096)
            .is_err());
    }

    #[test]
    fn saved_source_survives_rename_edit_and_reopen_without_following_latest() {
        let directory = tempfile::tempdir().unwrap();
        let workspace = Instance::init_at(directory.path()).unwrap();
        workspace
            .seed_main(&[("tutorials/basics.whip", "original source")])
            .unwrap();
        let original = workspace.current_main_cut().unwrap().unwrap();
        std::fs::rename(
            workspace.repo().join("tutorials/basics.whip"),
            workspace.repo().join("tutorials/renamed.whip"),
        )
        .unwrap();
        workspace
            .seed_main(&[("tutorials/renamed.whip", "edited source")])
            .unwrap();
        let latest = workspace.current_main_cut().unwrap().unwrap();
        assert_ne!(latest, original);
        drop(workspace);
        let workspace = Instance::open_at(directory.path());
        assert_eq!(
            workspace
                .workflow_source("tutorials/basics.whip", &original, 4096)
                .unwrap()
                .content,
            "original source"
        );
        assert!(workspace
            .workflow_source("tutorials/basics.whip", &latest, 4096)
            .is_err());
        assert!(workspace
            .workflow_source("tutorials/renamed.whip", &original, 4096)
            .is_err());
        assert_eq!(
            workspace
                .workflow_source("tutorials/renamed.whip", &latest, 4096)
                .unwrap()
                .content,
            "edited source"
        );
    }

    #[test]
    fn another_target_revision_and_unavailable_store_cannot_supply_source() {
        let first_dir = tempfile::tempdir().unwrap();
        let second_dir = tempfile::tempdir().unwrap();
        let first = Instance::init_at(first_dir.path()).unwrap();
        let second = Instance::init_at(second_dir.path()).unwrap();
        first.seed_main(&[("basics.whip", "first source")]).unwrap();
        second
            .seed_main(&[("basics.whip", "second source")])
            .unwrap();
        let first_cut = first.current_main_cut().unwrap().unwrap();
        assert!(second
            .workflow_source("basics.whip", &first_cut, 4096)
            .is_err());

        // A read must not initialize missing authority or import the disk copy.
        let content_store = first.store_root.join("content.sqlite");
        std::fs::remove_file(&content_store).unwrap();
        assert!(first
            .workflow_source("basics.whip", &first_cut, 4096)
            .is_err());
        assert!(!content_store.exists());
        assert_eq!(
            std::fs::read_to_string(first.repo().join("basics.whip")).unwrap(),
            "first source"
        );
    }
}
