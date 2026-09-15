//! Exact receiving-workspace retry before product admission commits. A receipt
//! proves local carriage only; it is neither Home authority nor an overwrite grant.
use super::{Instance, Result, WorkflowProtection, WorkspaceError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(super) const FILE: &str = "import.json";
const PROTOCOL: &str = "gaugedesk.workspace-import.v1";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    protocol: String,
    export: String,
    stores: Vec<String>,
    binding: Option<String>,
    substrate: String,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn refusal() -> WorkspaceError {
    WorkspaceError::msg("workspace import cannot reuse missing or changed receiving evidence")
}

/// Compare normalized SQLite snapshots, including WAL history, rather than
/// mutable database headers or a main file that may not contain committed WAL.
/// Snapshot acquisition uses the same input-before-target order as export.
fn capture(instance: &Instance, export: &[u8], workflow: bool) -> Result<Receipt> {
    let root = &instance.store_root;
    let workflow_root = root.join("workflow");
    if workflow_root.exists() != workflow {
        return Err(refusal());
    }
    let vcs = [
        root.join("branches.sqlite"),
        root.join("content.sqlite"),
        root.join("workstreams.sqlite"),
    ];
    let (stores, binding) = if workflow {
        let [branches, content, workstreams] = vcs;
        let input = workflow_root.join("inputs.sqlite");
        let snapshots = super::snapshot::snapshot_stores_with_input(
            [
                branches,
                content,
                workstreams,
                workflow_root.join("runtime.sqlite"),
                workflow_root.join("coord.sqlite"),
                workflow_root.join("items.sqlite"),
                input.clone(),
            ],
            &input,
        )?;
        let binding =
            std::fs::read(workflow_root.join("workspace.json")).map_err(WorkspaceError::io)?;
        (
            snapshots.iter().map(|bytes| digest(bytes)).collect(),
            Some(digest(&binding)),
        )
    } else {
        (
            super::snapshot::snapshot_stores(vcs)?
                .iter()
                .map(|bytes| digest(bytes))
                .collect(),
            None,
        )
    };
    let substrate = std::fs::read(root.join("substrate.json")).map_err(WorkspaceError::io)?;
    Ok(Receipt {
        protocol: PROTOCOL.into(),
        export: digest(export),
        stores,
        binding,
        substrate: digest(&substrate),
    })
}

/// The containing store set is still staged. Its owner syncs this file and
/// publishes it in the same directory rename as all received authority.
pub(super) fn write(instance: &Instance, export: &[u8], workflow: bool) -> Result<()> {
    let receipt = capture(instance, export, workflow)?;
    let bytes = serde_json::to_vec(&receipt).map_err(|_| refusal())?;
    std::fs::write(instance.store_root.join(FILE), bytes).map_err(WorkspaceError::io)
}

/// A retry reuses only the exact installed store set. It does not rematerialize
/// files, rewind later history, migrate stores, or initialize missing authority.
pub(super) fn resume(
    instance: &Instance,
    export: &[u8],
    workflow: Option<&super::workflow_storage::WorkflowSnapshot>,
    protection: Option<&WorkflowProtection>,
) -> Result<()> {
    let bytes = std::fs::read(instance.store_root.join(FILE)).map_err(WorkspaceError::io)?;
    let retained: Receipt = serde_json::from_slice(&bytes).map_err(|_| refusal())?;
    if retained.protocol != PROTOCOL || retained.export != digest(export) {
        return Err(refusal());
    }
    // A matching ciphertext receipt cannot stand in for current key custody.
    if let Some(workflow) = workflow {
        let storage = instance.native_workflow_storage();
        let stores = match protection {
            Some(protection) => storage.open_existing_protected(protection)?,
            None => storage.open_existing(&workflow.binding.workspace_id)?,
        };
        drop(stores);
    }
    if capture(instance, export, workflow.is_some())? != retained {
        return Err(refusal());
    }
    // Publication may have succeeded before its final directory sync failed.
    sync_directory(&instance.store_root)?;
    sync_directory(instance.store_root.parent().ok_or_else(refusal)?)
}

pub(super) fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(path)
        .map_err(WorkspaceError::io)?
        .sync_all()
        .map_err(WorkspaceError::io)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_import_retry_preserves_unimported_files_and_refuses_later_authority() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = Instance::init_at(source_dir.path()).unwrap();
        source
            .seed_main(&[("source.txt", "received content")])
            .unwrap();
        let export = source.export().unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        let imported = Instance::from_export_at(target_dir.path(), &export.0).unwrap();
        std::fs::write(imported.repo().join("source.txt"), "unsaved local edit").unwrap();
        drop(imported);
        let reopened = Instance::from_export_at(target_dir.path(), &export.0).unwrap();
        assert_eq!(
            std::fs::read_to_string(reopened.repo().join("source.txt")).unwrap(),
            "unsaved local edit"
        );
        // The existing authority changes in WAL. An old receive receipt cannot
        // erase the new chat, even when the offered export is byte-for-byte equal.
        let chat = reopened.create_engagement("later-chat").unwrap();
        assert!(Instance::from_export_at(target_dir.path(), &export.0).is_err());
        assert!(reopened
            .reconcile_engagements()
            .unwrap()
            .iter()
            .any(|(id, _)| id == "later-chat"));
        assert!(chat.path().exists());
    }

    #[test]
    fn import_retry_requires_original_receipt_and_every_installed_store() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = Instance::init_at(source_dir.path()).unwrap();
        source
            .seed_main(&[("source.txt", "received content")])
            .unwrap();
        let export = source.export().unwrap();
        for missing in [
            FILE,
            "branches.sqlite",
            "content.sqlite",
            "workstreams.sqlite",
            "substrate.json",
        ] {
            let target = tempfile::tempdir().unwrap();
            let imported = Instance::from_export_at(target.path(), &export.0).unwrap();
            let path = imported.store_root.join(missing);
            std::fs::remove_file(&path).unwrap();
            assert!(
                Instance::from_export_at(target.path(), &export.0).is_err(),
                "missing {missing}"
            );
            assert!(!path.exists(), "retry recreated {missing}");
        }
        let target = tempfile::tempdir().unwrap();
        let imported = Instance::from_export_at(target.path(), &export.0).unwrap();
        source
            .seed_main(&[("other.txt", "different export")])
            .unwrap();
        assert!(Instance::from_export_at(target.path(), &source.export().unwrap().0).is_err());
        assert!(Instance::from_export_at(target.path(), &export.0).is_ok());
        std::fs::write(imported.store_root.join(FILE), b"{}").unwrap();
        assert!(Instance::from_export_at(target.path(), &export.0).is_err());
    }
}
