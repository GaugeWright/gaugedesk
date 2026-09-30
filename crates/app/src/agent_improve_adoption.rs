//! Candidate definition snapshots and stale-safe adoption into an Agent's
//! versioned authoring target. The campaign selector owns when to offer this;
//! this module owns which bytes can be written and the exact-mainline fence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use gaugedesk_workspace::{MergeOutcome, Workspace};
use sha2::{Digest, Sha256};

const MAX_DEFINITION_FILES: usize = 512;
const MAX_DEFINITION_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentDefinitionSnapshot {
    files: BTreeMap<String, String>,
    pub identity: String,
}

impl AgentDefinitionSnapshot {
    /// Read the full authoring surface that can affect a package or its
    /// discipline. A file outside these roots remains outside this candidate.
    pub(crate) fn capture(root: &Path) -> Result<Self, String> {
        fn visit(
            root: &Path,
            dir: &Path,
            files: &mut BTreeMap<String, String>,
        ) -> Result<(), String> {
            let entries = std::fs::read_dir(dir).map_err(|error| error.to_string())?;
            for entry in entries {
                let entry = entry.map_err(|error| error.to_string())?;
                let kind = entry.file_type().map_err(|error| error.to_string())?;
                if kind.is_dir() {
                    visit(root, &entry.path(), files)?;
                } else if kind.is_file() {
                    let path = entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|error| error.to_string())?
                        .to_str()
                        .ok_or("Agent definition path is not UTF-8")?
                        .replace('\\', "/");
                    if !admitted_path(&path) {
                        return Err(format!("Agent definition path `{path}` is not admitted"));
                    }
                    let bytes = std::fs::read(entry.path()).map_err(|error| error.to_string())?;
                    let body = String::from_utf8(bytes)
                        .map_err(|_| format!("Agent definition file `{path}` is not UTF-8"))?;
                    files.insert(path, body);
                } else {
                    return Err("Agent definition contains a symlink or special file".to_owned());
                }
            }
            Ok(())
        }

        let mut files = BTreeMap::new();
        for subtree in [
            "agent",
            gaugedesk_boundary::definition::DRAFT_ROOT,
            crate::discipline::DISCIPLINE_DRAFT_ROOT,
        ] {
            visit(root, &root.join(subtree), &mut files)?;
        }
        Self::from_files(files)
    }

    /// Read the authority's retained Main cut, without relying on its mutable
    /// disk projection or creating a chat branch to inspect it.
    pub(crate) fn from_main(workspace: &dyn Workspace) -> Result<Self, String> {
        let mut files = BTreeMap::new();
        for entry in workspace.main_tree().map_err(|error| error.to_string())? {
            if entry.is_dir || !admitted_path(&entry.path) {
                continue;
            }
            let body = workspace
                .read_main_file(&entry.path)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("Main lost Agent definition file `{}`", entry.path))?;
            files.insert(entry.path, body);
        }
        Self::from_files(files)
    }

    fn from_files(files: BTreeMap<String, String>) -> Result<Self, String> {
        if files.len() > MAX_DEFINITION_FILES {
            return Err("Agent definition has too many editable files".to_owned());
        }
        let mut bytes = 0usize;
        let mut digest = Sha256::new();
        for (path, body) in &files {
            if !admitted_path(path) {
                return Err(format!("Agent definition path `{path}` is not admitted"));
            }
            bytes = bytes.saturating_add(path.len()).saturating_add(body.len());
            if bytes > MAX_DEFINITION_BYTES {
                return Err("Agent definition exceeds the editable context budget".to_owned());
            }
            digest.update((path.len() as u64).to_be_bytes());
            digest.update(path.as_bytes());
            digest.update((body.len() as u64).to_be_bytes());
            digest.update(body.as_bytes());
        }
        Ok(Self {
            files,
            identity: format!("agent-definition:sha256:{}", hex::encode(digest.finalize())),
        })
    }

    pub(crate) fn changed_paths(&self, candidate: &Self) -> Vec<String> {
        self.files
            .keys()
            .chain(candidate.files.keys())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|path| self.files.get(*path) != candidate.files.get(*path))
            .cloned()
            .collect()
    }

    pub(crate) fn package_refs(&self) -> Result<(String, String), String> {
        let scratch = tempfile::tempdir().map_err(|error| error.to_string())?;
        self.materialize(scratch.path())?;
        let package = crate::agent_release::snapshot_authored_package(
            scratch.path(),
            &scratch.path().join("evaluated-package"),
        )
        .map_err(|error| error.to_string())?;
        let discipline = crate::agent_release::snapshot_authored_discipline(
            scratch.path(),
            &scratch.path().join("evaluated-discipline"),
            &package,
        )
        .map_err(|error| error.to_string())?;
        Ok((package.version_ref().to_owned(), discipline.reference))
    }

    pub(crate) fn materialize(&self, root: &Path) -> Result<(), String> {
        for (path, body) in &self.files {
            let destination = root.join(path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            std::fs::write(destination, body).map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

fn admitted_path(path: &str) -> bool {
    let normal = Path::new(path)
        .components()
        .all(|component| matches!(component, Component::Normal(_)));
    normal
        && ["agent/", ".whipple/draft/", ".whipple/discipline/draft/"]
            .iter()
            .any(|root| path.starts_with(root))
}

/// Adopt an already selected candidate. An exact cut comparison is repeated
/// inside the workspace's two-writer merge lock, so even an unrelated Main
/// edit between this read and the merge refuses the entire candidate.
pub(crate) fn adopt_candidate(
    workspace: &dyn Workspace,
    expected_cut: &str,
    baseline: &AgentDefinitionSnapshot,
    candidate: &AgentDefinitionSnapshot,
    evaluated_package_ref: &str,
    evaluated_discipline_ref: &str,
) -> Result<Vec<String>, String> {
    let changed = baseline.changed_paths(candidate);
    if changed.is_empty() {
        return Err("candidate changes no Agent definition file".to_owned());
    }
    let refs = candidate.package_refs()?;
    if refs.0 != evaluated_package_ref || refs.1 != evaluated_discipline_ref {
        return Err(
            "candidate definition no longer matches evaluated package and discipline".to_owned(),
        );
    }
    if workspace
        .current_main_cut()
        .map_err(|error| error.to_string())?
        .as_deref()
        != Some(expected_cut)
        || AgentDefinitionSnapshot::from_main(workspace)? != *baseline
    {
        return Err("Agent draft changed since the baseline was evaluated".to_owned());
    }
    let engagement_id = crate::library::gen_id("agent-improve-adopt");
    let engagement = workspace
        .create_engagement(&engagement_id)
        .map_err(|error| error.to_string())?;
    let result = (|| {
        for path in &changed {
            match candidate.files.get(path) {
                Some(body) => engagement
                    .write_file(path, body)
                    .map_err(|error| error.to_string())?,
                None => engagement
                    .delete_entry(path)
                    .map_err(|error| error.to_string())?,
            }
        }
        engagement
            .commit_turn("adopt Agent improvement candidate")
            .map_err(|error| error.to_string())?;
        match engagement
            .merge_into_main_if_target_cut(expected_cut)
            .map_err(|error| error.to_string())?
        {
            MergeOutcome::Clean => Ok(changed),
            MergeOutcome::Conflict => Err("Agent improvement adoption conflicted".to_owned()),
        }
    })();
    let cleanup = workspace.remove_engagement(&engagement_id);
    match (result, cleanup) {
        (Ok(changed), Ok(())) => Ok(changed),
        (Ok(_), Err(error)) => Err(format!(
            "Agent improvement landed but temporary branch cleanup failed: {error}"
        )),
        (Err(error), _) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_support::LockUnpoisoned;

    #[test]
    fn adoption_refuses_stale_main_and_preserves_published_version() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let guard = workbench.lock_unpoisoned();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let published = guard.library.agents[crate::DEFAULT_AGENT].versions[&1]
            .package_ref
            .clone();
        let baseline = AgentDefinitionSnapshot::from_main(workspace.as_ref()).unwrap();
        let baseline_cut = workspace.current_main_cut().unwrap().unwrap();
        let mut candidate_files = baseline.files.clone();
        candidate_files.insert("agent/AGENTS.md".to_owned(), "improved method\n".to_owned());
        let candidate = AgentDefinitionSnapshot::from_files(candidate_files).unwrap();
        let (package_ref, discipline_ref) = candidate.package_refs().unwrap();
        assert_ne!(baseline.identity, candidate.identity);

        let other_id = crate::library::gen_id("other-authoring-edit");
        let other = workspace.create_engagement(&other_id).unwrap();
        other.write_file("notes.md", "human edit").unwrap();
        other.commit_turn("human edit").unwrap();
        assert_eq!(other.merge_into_main().unwrap(), MergeOutcome::Clean);
        workspace.remove_engagement(&other_id).unwrap();
        assert!(adopt_candidate(
            workspace.as_ref(),
            &baseline_cut,
            &baseline,
            &candidate,
            &package_ref,
            &discipline_ref,
        )
        .unwrap_err()
        .contains("draft changed"));
        assert_eq!(
            workspace.read_main_file("agent/AGENTS.md").unwrap(),
            baseline.files.get("agent/AGENTS.md").cloned()
        );

        let fresh = AgentDefinitionSnapshot::from_main(workspace.as_ref()).unwrap();
        let fresh_cut = workspace.current_main_cut().unwrap().unwrap();
        let mut fresh_files = fresh.files.clone();
        fresh_files.insert("agent/AGENTS.md".to_owned(), "improved method\n".to_owned());
        fresh_files.insert("agent/guide.md".to_owned(), "new context\n".to_owned());
        let fresh_candidate = AgentDefinitionSnapshot::from_files(fresh_files).unwrap();
        let (fresh_package, fresh_discipline) = fresh_candidate.package_refs().unwrap();
        let changed = adopt_candidate(
            workspace.as_ref(),
            &fresh_cut,
            &fresh,
            &fresh_candidate,
            &fresh_package,
            &fresh_discipline,
        )
        .unwrap();
        assert_eq!(changed, vec!["agent/AGENTS.md", "agent/guide.md"]);
        assert_eq!(
            workspace
                .read_main_file("agent/AGENTS.md")
                .unwrap()
                .as_deref(),
            Some("improved method\n")
        );
        assert_eq!(
            guard.library.agents[crate::DEFAULT_AGENT].versions[&1].package_ref,
            published,
            "draft adoption cannot repin a published version"
        );

        let next = AgentDefinitionSnapshot::from_main(workspace.as_ref()).unwrap();
        let next_cut = workspace.current_main_cut().unwrap().unwrap();
        let mut without_guide = next.files.clone();
        without_guide.remove("agent/guide.md");
        let removal = AgentDefinitionSnapshot::from_files(without_guide).unwrap();
        let (removal_package, removal_discipline) = removal.package_refs().unwrap();
        assert_eq!(
            adopt_candidate(
                workspace.as_ref(),
                &next_cut,
                &next,
                &removal,
                &removal_package,
                &removal_discipline,
            )
            .unwrap(),
            vec!["agent/guide.md"]
        );
        assert_eq!(workspace.read_main_file("agent/guide.md").unwrap(), None);
    }

    #[test]
    fn adoption_refuses_bytes_other_than_the_evaluated_candidate() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let guard = workbench.lock_unpoisoned();
        let target_id = crate::library_state::authoring_target_id(crate::DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let baseline = AgentDefinitionSnapshot::from_main(workspace.as_ref()).unwrap();
        let cut = workspace.current_main_cut().unwrap().unwrap();
        let mut files = baseline.files.clone();
        files.insert(
            "agent/SYSTEM.md".to_owned(),
            "candidate system\n".to_owned(),
        );
        let candidate = AgentDefinitionSnapshot::from_files(files).unwrap();
        let (package_ref, discipline_ref) = baseline.package_refs().unwrap();
        assert!(adopt_candidate(
            workspace.as_ref(),
            &cut,
            &baseline,
            &candidate,
            &package_ref,
            &discipline_ref,
        )
        .unwrap_err()
        .contains("no longer matches evaluated"));
        assert_eq!(
            AgentDefinitionSnapshot::from_main(workspace.as_ref()).unwrap(),
            baseline
        );
    }
}
