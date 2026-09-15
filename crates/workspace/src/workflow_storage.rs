//! Workspace-owned workflow state. Locators and prepared content protection
//! grant no product authority. VCS forks never copy this plane.

use super::{Instance, Result, WorkspaceError};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use whipplescript_store::{
    content::ContentStore,
    coordination::CoordinationStore,
    items::WorkItemStore,
    native_stores::NativeStores,
    payload_protection::{PayloadCodec, PayloadProtection},
    SqliteStore, StoreError,
};

const DIRECTORY: &str = "workflow";
const BINDING_FILE: &str = "workspace.json";
const PROTOCOL: &str = "gaugedesk.workspace-workflow-storage.v1";
const PROTECTED_PROTOCOL: &str = "gaugedesk.workspace-workflow-storage.v2";
const KEY_CHECK: &[u8] = b"gaugedesk.workspace-workflow-key.v1";
const STORES: [&str; 4] = [
    "runtime.sqlite",
    "coord.sqlite",
    "items.sqlite",
    "inputs.sqlite",
];

/// Prepared host custody, bound to one collaboration workspace. Construct this
/// before product/store transactions. The codec must support nested retention;
/// neither construction nor possession grants product authority.
pub struct WorkflowProtection {
    workspace_id: String,
    payload: PayloadProtection,
    codec: Arc<dyn PayloadCodec>,
}

impl WorkflowProtection {
    pub fn new(workspace_id: &str, codec: Arc<dyn PayloadCodec>) -> Result<Self> {
        valid_workspace(workspace_id)?;
        Ok(Self {
            workspace_id: workspace_id.into(),
            payload: PayloadProtection::new(
                format!("gaugedesk.workspace-workflow.v1:{workspace_id}"),
                codec.clone(),
            )?,
            codec,
        })
    }

    fn associated_data(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "gaugedesk.workspace-key-binding.v1",
            &self.workspace_id,
            self.payload.domain(),
        ))
        .expect("string tuple serializes")
    }

    /// Retain the host key around atomic workspace publication, including final
    /// directory rename. Preserve the callback's refusal and require one call.
    pub(super) fn retain<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut operation = Some(operation);
        let mut result = None;
        let mut calls = 0;
        self.codec.retain(&mut || {
            calls += 1;
            let operation = operation.take().ok_or_else(|| {
                StoreError::fault("workflow protection", "codec repeated retained operation")
            })?;
            result = Some(operation().map_err(|error| StoreError::Conflict(error.message))?);
            Ok(())
        })?;
        if calls != 1 {
            return Err(refused(
                "codec changed retained workspace operation cardinality",
            ));
        }
        result.ok_or_else(|| refused("codec omitted retained workspace operation"))
    }
}

/// A validated storage-mode hint, not proof of key custody or product authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkflowProtectionMode {
    Plain,
    Protected,
}

pub struct NativeWorkflowStorage {
    root: PathBuf,
}

/// Runtime/tracker/coordination and retained inputs have independent authorities;
/// VCS collection never owns input roots.
pub struct NativeWorkflowStores {
    pub runtime: NativeStores,
    pub inputs: ContentStore,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    protocol: String,
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protected: Option<ProtectedBinding>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedBinding {
    domain: String,
    key_check: Vec<u8>,
}

impl Binding {
    pub(super) fn plain(workspace_id: String) -> Self {
        Self {
            protocol: PROTOCOL.into(),
            workspace_id,
            protected: None,
        }
    }
    pub(super) fn is_protected(&self) -> bool {
        self.protected.is_some()
    }
    pub(super) fn validate(&self) -> Result<()> {
        valid_workspace(&self.workspace_id)?;
        if !matches!(
            (self.protocol.as_str(), self.protected.is_some()),
            (PROTOCOL, false) | (PROTECTED_PROTOCOL, true)
        ) {
            return Err(refused(
                "workflow workspace binding has an unsupported protocol",
            ));
        }
        Ok(())
    }
    fn create(workspace_id: &str, protection: Option<&WorkflowProtection>) -> Result<Self> {
        let mut binding = Self::plain(workspace_id.into());
        if let Some(protection) = protection {
            if protection.workspace_id != workspace_id {
                return Err(refused("workflow protection belongs to another workspace"));
            }
            binding.protocol = PROTECTED_PROTOCOL.into();
            binding.protected = Some(ProtectedBinding {
                domain: protection.payload.domain().into(),
                key_check: protection
                    .codec
                    .seal(&protection.associated_data(), KEY_CHECK)?,
            });
        }
        Ok(binding)
    }
    fn verify(&self, workspace_id: &str, protection: Option<&WorkflowProtection>) -> Result<()> {
        self.validate()?;
        if self.workspace_id != workspace_id {
            return Err(refused("workflow storage belongs to another workspace"));
        }
        match (&self.protected, protection) {
            (None, None) => Ok(()),
            (Some(binding), Some(protection)) => {
                if protection.workspace_id != workspace_id
                    || binding.domain != protection.payload.domain()
                {
                    return Err(refused("workflow protection belongs to another workspace"));
                }
                if protection
                    .codec
                    .open(&protection.associated_data(), &binding.key_check)?
                    != KEY_CHECK
                {
                    return Err(refused("workflow content-key binding is invalid"));
                }
                Ok(())
            }
            _ => Err(refused("workflow storage protection mode does not match")),
        }
    }
}

pub(super) struct WorkflowSnapshot {
    pub binding: Binding,
    pub stores: [Vec<u8>; 4],
}
fn refused(message: &str) -> WorkspaceError {
    WorkspaceError::msg(message)
}
fn valid_workspace(workspace_id: &str) -> Result<()> {
    if workspace_id.trim().is_empty() {
        return Err(refused("workflow storage requires a workspace identity"));
    }
    Ok(())
}
fn paths(root: &Path) -> [PathBuf; 4] {
    STORES.map(|name| root.join(name))
}
fn open_stores(
    root: &Path,
    protection: Option<&WorkflowProtection>,
    create: bool,
) -> Result<NativeWorkflowStores> {
    let [runtime, coord, items, inputs] = paths(root);
    if let Some(protection) = protection {
        let p = &protection.payload;
        return Ok(NativeWorkflowStores {
            runtime: NativeStores {
                runtime: if create {
                    SqliteStore::create_protected(runtime, p.clone())?
                } else {
                    SqliteStore::open_existing_protected(runtime, p.clone())?
                },
                coord: if create {
                    CoordinationStore::create_protected(coord, p.clone())?
                } else {
                    CoordinationStore::open_existing_protected(coord, p.clone())?
                },
                items: if create {
                    WorkItemStore::create_protected(items, p.clone())?
                } else {
                    WorkItemStore::open_existing_protected(items, p.clone())?
                },
                frontier: None,
            },
            inputs: if create {
                ContentStore::create_protected(inputs, p.clone())?
            } else {
                ContentStore::open_existing_protected(inputs, p.clone())?
            },
        });
    }
    Ok(NativeWorkflowStores {
        runtime: if create {
            NativeStores::open(runtime, coord, items)?
        } else {
            NativeStores::open_existing(runtime, coord, items)?
        },
        inputs: if create {
            ContentStore::open(inputs)?
        } else {
            ContentStore::open_existing(inputs)?
        },
    })
}
impl Instance {
    pub fn native_workflow_storage(&self) -> NativeWorkflowStorage {
        NativeWorkflowStorage {
            root: self.store_root.join(DIRECTORY),
        }
    }
}
impl NativeWorkflowStorage {
    /// Read the owner-maintained binding before preparing host key custody.
    /// Absence is distinct from malformed/incomplete state. A protected opener
    /// must still authenticate the binding with the actual prepared key.
    pub fn protection_mode(&self, workspace_id: &str) -> Result<Option<WorkflowProtectionMode>> {
        valid_workspace(workspace_id)?;
        match std::fs::symlink_metadata(&self.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(WorkspaceError::io(error)),
            Ok(metadata) if !metadata.is_dir() => {
                return Err(refused("workflow storage is not an owned directory"))
            }
            Ok(_) => {}
        }
        let binding = self.retained_binding()?;
        if binding.workspace_id != workspace_id {
            return Err(refused("workflow storage belongs to another workspace"));
        }
        self.require_stores()?;
        Ok(Some(if binding.is_protected() {
            WorkflowProtectionMode::Protected
        } else {
            WorkflowProtectionMode::Plain
        }))
    }

    /// Plain compatibility/qualification state. Never upgrades existing stores.
    pub fn initialize(&self, workspace_id: &str) -> Result<NativeWorkflowStores> {
        self.initialize_inner(workspace_id, None)
    }
    pub fn initialize_protected(
        &self,
        protection: &WorkflowProtection,
    ) -> Result<NativeWorkflowStores> {
        protection.retain(|| self.initialize_inner(&protection.workspace_id, Some(protection)))
    }
    fn initialize_inner(
        &self,
        workspace_id: &str,
        protection: Option<&WorkflowProtection>,
    ) -> Result<NativeWorkflowStores> {
        valid_workspace(workspace_id)?;
        if self.root.exists() {
            return self.open_inner(workspace_id, protection);
        }
        let parent = self
            .root
            .parent()
            .ok_or_else(|| refused("workflow storage has no parent"))?;
        std::fs::create_dir_all(parent).map_err(WorkspaceError::io)?;
        let staging = tempfile::Builder::new()
            .prefix(".workflow-init-")
            .tempdir_in(parent)
            .map_err(WorkspaceError::io)?;
        // Close WAL connections before directory publication.
        drop(open_stores(staging.path(), protection, true)?);
        write_binding(staging.path(), &Binding::create(workspace_id, protection)?)?;
        sync_stores(staging.path())?;
        match std::fs::rename(staging.path(), &self.root) {
            Ok(()) => {
                sync_directory(parent)?;
                self.open_inner(workspace_id, protection)
            }
            Err(_) if self.root.exists() => self.open_inner(workspace_id, protection),
            Err(error) => Err(WorkspaceError::io(error)),
        }
    }
    pub fn open_existing(&self, workspace_id: &str) -> Result<NativeWorkflowStores> {
        self.open_inner(workspace_id, None)
    }
    pub fn open_existing_protected(
        &self,
        protection: &WorkflowProtection,
    ) -> Result<NativeWorkflowStores> {
        protection.retain(|| self.open_inner(&protection.workspace_id, Some(protection)))
    }
    fn open_inner(
        &self,
        workspace_id: &str,
        protection: Option<&WorkflowProtection>,
    ) -> Result<NativeWorkflowStores> {
        self.retained_binding()?.verify(workspace_id, protection)?;
        self.require_stores()?;
        open_stores(&self.root, protection, false)
    }
    fn retained_binding(&self) -> Result<Binding> {
        let bytes = std::fs::read(self.root.join(BINDING_FILE)).map_err(WorkspaceError::io)?;
        let binding: Binding = serde_json::from_slice(&bytes)
            .map_err(|_| refused("workflow workspace binding is malformed"))?;
        binding.validate()?;
        Ok(binding)
    }
    fn require_stores(&self) -> Result<[PathBuf; 4]> {
        let paths = paths(&self.root);
        if paths.iter().any(|path| !path.is_file()) {
            return Err(refused(
                "workflow workspace is missing an authoritative store",
            ));
        }
        Ok(paths)
    }
    /// Caller retains prepared protection through the whole workspace export.
    pub(super) fn snapshot_with_vcs(
        &self,
        vcs: [PathBuf; 3],
        protection: Option<&WorkflowProtection>,
    ) -> Result<([Vec<u8>; 3], Option<WorkflowSnapshot>)> {
        if !self.root.exists() {
            if protection.is_some() {
                return Err(refused("protected workflow storage is missing"));
            }
            return Ok((super::snapshot::snapshot_stores(vcs)?, None));
        }
        let binding = self.retained_binding()?;
        drop(self.open_inner(&binding.workspace_id, protection)?);
        let [runtime, coord, items, inputs] = self.require_stores()?;
        let [branches, content, workstreams] = vcs;
        let [branches, content, workstreams, runtime, coord, items, inputs] =
            super::snapshot::snapshot_stores_with_input(
                [
                    branches,
                    content,
                    workstreams,
                    runtime,
                    coord,
                    items,
                    inputs.clone(),
                ],
                &inputs,
            )?;
        Ok((
            [branches, content, workstreams],
            Some(WorkflowSnapshot {
                binding,
                stores: [runtime, coord, items, inputs],
            }),
        ))
    }
    /// Staged import only; the caller retains protection until publishing the
    /// entire workspace, not merely this nested directory.
    pub(super) fn restore(
        &self,
        snapshot: WorkflowSnapshot,
        protection: Option<&WorkflowProtection>,
    ) -> Result<()> {
        snapshot
            .binding
            .verify(&snapshot.binding.workspace_id, protection)?;
        if self.root.exists() {
            return Err(refused(
                "workflow relocation cannot overwrite existing authority",
            ));
        }
        let parent = self
            .root
            .parent()
            .ok_or_else(|| refused("workflow storage has no parent"))?;
        std::fs::create_dir_all(parent).map_err(WorkspaceError::io)?;
        let staging = tempfile::Builder::new()
            .prefix(".workflow-import-")
            .tempdir_in(parent)
            .map_err(WorkspaceError::io)?;
        for (path, bytes) in paths(staging.path()).into_iter().zip(snapshot.stores) {
            std::fs::write(path, bytes).map_err(WorkspaceError::io)?;
        }
        write_binding(staging.path(), &snapshot.binding)?;
        drop(open_stores(staging.path(), protection, false)?);
        sync_stores(staging.path())?;
        std::fs::rename(staging.path(), &self.root).map_err(WorkspaceError::io)?;
        sync_directory(parent)
    }
}
fn write_binding(root: &Path, binding: &Binding) -> Result<()> {
    let bytes = serde_json::to_vec(binding)
        .map_err(|_| refused("workflow workspace binding cannot be encoded"))?;
    std::fs::write(root.join(BINDING_FILE), bytes).map_err(WorkspaceError::io)
}
fn sync_stores(root: &Path) -> Result<()> {
    for path in paths(root).into_iter().chain([root.join(BINDING_FILE)]) {
        // Windows FlushFileBuffers requires a writable file handle.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(WorkspaceError::io)?
            .sync_all()
            .map_err(WorkspaceError::io)?;
    }
    sync_directory(root)
}
fn sync_directory(root: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(root)
        .map_err(WorkspaceError::io)?
        .sync_all()
        .map_err(WorkspaceError::io)?;
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use whipplescript_store::{
        log_append::LogAppend,
        tracker_filing::{TrackerFiling, TrackerFilings},
        tracker_result::closing_conformance,
        RuntimeStore,
    };

    #[test]
    fn protection_mode_distinguishes_absence_and_refuses_incomplete_or_foreign_state() {
        let source = tempfile::tempdir().unwrap();
        let workspace = Instance::init_at(source.path()).unwrap();
        let storage = workspace.native_workflow_storage();
        assert_eq!(storage.protection_mode("workspace").unwrap(), None);
        assert!(!storage.root.exists());
        drop(storage.initialize("workspace").unwrap());
        assert_eq!(
            storage.protection_mode("workspace").unwrap(),
            Some(WorkflowProtectionMode::Plain)
        );
        assert!(storage.protection_mode("foreign").is_err());
        let missing = storage.root.join(STORES[0]);
        std::fs::remove_file(&missing).unwrap();
        assert!(storage.protection_mode("workspace").is_err());
        assert!(!missing.exists());
        std::fs::remove_file(storage.root.join(BINDING_FILE)).unwrap();
        assert!(storage.protection_mode("workspace").is_err());
    }

    #[test]
    fn retained_workspace_operation_requires_one_codec_callback() {
        struct CallbackCount(usize);
        impl PayloadCodec for CallbackCount {
            fn seal(&self, _: &[u8], _: &[u8]) -> whipplescript_store::StoreResult<Vec<u8>> {
                Err(StoreError::fault("fixture", "payloads are not exercised"))
            }
            fn open(&self, _: &[u8], _: &[u8]) -> whipplescript_store::StoreResult<Vec<u8>> {
                Err(StoreError::fault("fixture", "payloads are not exercised"))
            }
            fn retain(
                &self,
                operation: &mut dyn FnMut() -> whipplescript_store::StoreResult<()>,
            ) -> whipplescript_store::StoreResult<()> {
                for _ in 0..self.0 {
                    let _ = operation();
                }
                Ok(())
            }
        }
        for count in [0, 1, 2] {
            let protection =
                WorkflowProtection::new("workspace", Arc::new(CallbackCount(count))).unwrap();
            let effects = std::cell::Cell::new(0);
            let result = protection.retain(|| {
                effects.set(effects.get() + 1);
                Ok(17)
            });
            assert_eq!(effects.get(), usize::from(count > 0));
            if count == 1 {
                assert_eq!(result.unwrap(), 17);
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn workflow_storage_export_preserves_history_receipts_coordination_and_inputs() {
        let source = tempfile::tempdir().unwrap();
        let workspace = Instance::init_at(source.path()).unwrap();
        workspace
            .seed_main(&[("tutorials/basics.whip", "ordinary source")])
            .unwrap();
        let mut stores = workspace
            .native_workflow_storage()
            .initialize("personal:one")
            .unwrap();
        let delivery = closing_conformance::setup(&mut stores.runtime, "lease_expired");
        let instance = delivery.closure.instance_id;
        let events = stores.runtime.list_events(&instance).unwrap();
        let runs = stores.runtime.list_runs(&instance).unwrap();
        let head = stores.runtime.chain_head(&instance).unwrap();
        let filing = TrackerFiling {
            operation_id: "filing:one".into(),
            instance_id: instance.clone(),
            effect_id: "effect:filing".into(),
            actor: "person:one".into(),
            queue: "tutorials".into(),
            title: "Create a Personal chat".into(),
            body: "Use the normal chat action".into(),
            labels: vec![],
            metadata: json!({}),
            assigned_to: Some("person:one".into()),
        };
        let receipt = stores.runtime.items.file_issue_once(&filing).unwrap();
        stores
            .runtime
            .coord
            .append_for_owner(
                "personal:one",
                "progress",
                "tutorial",
                "{\"started\":true}",
                "person:one",
                0,
            )
            .unwrap();
        let entries = stores.runtime.coord.list_entries(None, None).unwrap();
        let input_hash = stores.inputs.put_text("retained typed input").unwrap();
        // Export with live WAL connections, not only cleanly closed databases.
        let export = workspace.export().unwrap();
        let target = tempfile::tempdir().unwrap();
        let imported = Instance::from_export_at(target.path(), &export.0).unwrap();
        assert_eq!(
            std::fs::read_to_string(imported.repo().join("tutorials/basics.whip")).unwrap(),
            "ordinary source"
        );
        let mut relocated = imported
            .native_workflow_storage()
            .open_existing("personal:one")
            .unwrap();
        assert_eq!(relocated.runtime.list_events(&instance).unwrap(), events);
        assert_eq!(relocated.runtime.list_runs(&instance).unwrap(), runs);
        assert_eq!(relocated.runtime.chain_head(&instance).unwrap(), head);
        assert_eq!(
            relocated.runtime.items.file_issue_once(&filing).unwrap(),
            receipt
        );
        assert_eq!(
            relocated.runtime.coord.list_entries(None, None).unwrap(),
            entries
        );
        assert_eq!(
            relocated
                .inputs
                .get_text(&input_hash)
                .unwrap()
                .text()
                .as_deref(),
            Some("retained typed input")
        );
        assert!(imported
            .native_workflow_storage()
            .open_existing("another-project")
            .is_err());
        drop(relocated);
        let reopened = Instance::open_at(target.path());
        let reopened_stores = reopened
            .native_workflow_storage()
            .open_existing("personal:one")
            .unwrap();
        assert_eq!(reopened_stores.runtime.chain_head(&instance).unwrap(), head);
        // An exact retry reuses unchanged authority. A later input write in WAL
        // makes that old installation receipt stale; import cannot rewind it.
        assert!(Instance::from_export_at(target.path(), &export.0).is_ok());
        let later = reopened_stores
            .inputs
            .put_text("input after receiving")
            .unwrap();
        assert!(Instance::from_export_at(target.path(), &export.0).is_err());
        assert_eq!(
            reopened_stores
                .inputs
                .get_text(&later)
                .unwrap()
                .text()
                .as_deref(),
            Some("input after receiving")
        );
        assert_eq!(reopened_stores.runtime.chain_head(&instance).unwrap(), head);
        drop(reopened_stores);
        // A VCS fork starts without workflow state even when the source has it.
        let fork = tempfile::tempdir().unwrap();
        let forked = Instance::fork_from_at(fork.path(), &workspace.peer_source()).unwrap();
        assert!(!forked.native_workflow_storage().root.exists());
        let fresh = forked
            .native_workflow_storage()
            .initialize("project:fork")
            .unwrap();
        assert!(fresh.runtime.list_events(&instance).unwrap().is_empty());
        assert!(fresh
            .runtime
            .items
            .get_item(&receipt.item_id)
            .unwrap()
            .is_none());
        assert!(matches!(
            fresh.inputs.get_text(&input_hash).unwrap(),
            whipplescript_store::content::TextBlob::Missing
        ));
    }

    #[test]
    fn workflow_storage_refuses_missing_replaced_and_foreign_stores() {
        for failure in ["missing", "empty", "wrong-kind"] {
            for index in 0..4 {
                let source = tempfile::tempdir().unwrap();
                let workspace = Instance::init_at(source.path()).unwrap();
                let storage = workspace.native_workflow_storage();
                drop(storage.initialize("project:one").unwrap());
                let stores = paths(&storage.root);
                match failure {
                    "missing" => std::fs::remove_file(&stores[index]).unwrap(),
                    "empty" => std::fs::write(&stores[index], []).unwrap(),
                    "wrong-kind" => {
                        std::fs::copy(&stores[(index + 1) % 4], &stores[index]).unwrap();
                    }
                    _ => unreachable!(),
                }
                assert!(
                    storage.initialize("project:one").is_err(),
                    "{failure} {index}"
                );
                assert!(
                    storage.open_existing("project:one").is_err(),
                    "{failure} {index}"
                );
                if failure == "missing" {
                    assert!(!stores[index].exists());
                }
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let workspace = Instance::init_at(directory.path()).unwrap();
        let storage = workspace.native_workflow_storage();
        assert!(storage.initialize(" ").is_err());
        assert!(!storage.root.exists());
        drop(storage.initialize("project:one").unwrap());
        assert!(storage.initialize("project:two").is_err());
    }

    #[test]
    fn workflow_storage_invalid_import_does_not_publish_partial_authority() {
        let source = tempfile::tempdir().unwrap();
        let workspace = Instance::init_at(source.path()).unwrap();
        drop(
            workspace
                .native_workflow_storage()
                .initialize("project:one")
                .unwrap(),
        );
        let export = workspace.export().unwrap();
        for index in 0..4 {
            let mut decoded = super::super::parse_export(&export.0).unwrap();
            decoded.workflow.as_mut().unwrap().stores[index] = vec![];
            let altered = super::super::encode_export(
                &decoded.branches,
                &decoded.content,
                decoded.workstreams.as_deref().unwrap(),
                decoded.workflow.as_ref(),
            );
            let target = tempfile::tempdir().unwrap();
            assert!(Instance::from_export_at(target.path(), &altered).is_err());
            assert!(!super::super::store_root_for(&target.path().join("repo")).exists());
            // A corrected delivery can still install the full authoritative set.
            Instance::from_export_at(target.path(), &export.0).unwrap();
        }
    }

    #[test]
    fn workflow_storage_export_codec_rejects_truncation_overflow_and_trailing_bytes() {
        let valid = super::super::encode_export(b"branches", b"content", b"workstreams", None);
        for end in 0..valid.len() {
            assert!(
                super::super::parse_export(&valid[..end]).is_err(),
                "accepted truncation {end}"
            );
        }
        let mut overflow = valid.clone();
        overflow[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(super::super::parse_export(&overflow).is_err());
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(super::super::parse_export(&trailing).is_err());
        for (magic, stores) in [
            (super::super::LEGACY_EXPORT_MAGIC, 2),
            (super::super::V2_EXPORT_MAGIC, 3),
        ] {
            let mut legacy = magic.to_vec();
            for bytes in [b"branches".as_slice(), b"content", b"workstreams"]
                .into_iter()
                .take(stores)
            {
                legacy.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                legacy.extend_from_slice(bytes);
            }
            let parsed = super::super::parse_export(&legacy).unwrap();
            assert!(parsed.workflow.is_none());
            assert_eq!(parsed.workstreams.is_some(), stores == 3);
        }
    }
}
