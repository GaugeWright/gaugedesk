//! Home-owned native action infrastructure. Startup configuration supplies
//! limits; action requests supply neither storage locations nor runtime grants.

use super::*;
use gaugedesk_whip_runtime::host_actions::{
    facade::GovernedHostFacade, register_native_file_package, register_native_recording_package,
    NativeStores,
};
use std::path::PathBuf;
use whipplescript_kernel::file_lease::FileLeasePolicy;
use whipplescript_store::{StoreError, StoreResult};

/// Trusted host configuration. A rollout must choose its measured byte budget;
/// this boundary supplies no product default or caller-provided lease clock.
#[derive(Clone, Copy)]
pub struct NativeActionStorageConfig {
    pub input_byte_limit: usize,
    pub file_lease: FileLeasePolicy,
}

/// Storage opened only from a Workbench's actual Home. Multiple connections use
/// the same input authority and therefore the same publication exclusion.
pub struct NativeActionStorage {
    home_root: PathBuf,
    home_id: gaugedesk_core::ids::HomeId,
    inputs: NativeActionInputCustody,
    file_lease: FileLeasePolicy,
}

impl NativeActionStorage {
    /// Trusted custody for separately authenticated preparation and execution.
    pub fn inputs(&self) -> &NativeActionInputCustody {
        &self.inputs
    }

    pub(super) fn require_home(&self, wb: &Workbench) -> Result<(), String> {
        if &self.home_id != wb.home_id()
            || self.home_root != wb.root_path().canonicalize().map_err(|e| e.to_string())?
        {
            return Err("native action storage belongs to a different Home".into());
        }
        Ok(())
    }
}

/// An I/O-free locator from the actual Home, used only under current read
/// authority. Observation needs neither input custody nor coordination stores.
pub(in crate::file_action_factory) struct NativeActionObservationSource {
    home_root: PathBuf,
}
impl NativeActionObservationSource {
    pub(in crate::file_action_factory) fn open(
        &self,
    ) -> StoreResult<whipplescript_store::SqliteStore> {
        let root = self.home_root.canonicalize()?;
        whipplescript_store::SqliteStore::open_read_only(root.join("actions/native/runtime.sqlite"))
    }
}

/// Metadata-writing locator for an already admitted reconciliation. This is
/// distinct from the read-only observation source and conveys no authorization.
pub(in crate::file_action_factory) struct NativeActionReconciliationSource {
    home_root: PathBuf,
}
impl NativeActionReconciliationSource {
    pub(in crate::file_action_factory) fn open(
        &self,
    ) -> StoreResult<(PathBuf, whipplescript_store::SqliteStore)> {
        let root = self.home_root.canonicalize()?;
        let path = root.join("actions/native/runtime.sqlite");
        if !path.is_file() {
            return Err(StoreError::Conflict(
                "original correction runtime is unavailable".into(),
            ));
        }
        Ok((root, whipplescript_store::SqliteStore::open(path)?))
    }
}

impl Workbench {
    pub(in crate::file_action_factory) fn native_action_reconciliation_source(
        &self,
    ) -> Result<NativeActionReconciliationSource, String> {
        if self.root_path().as_os_str().is_empty() {
            return Err("native reconciliation requires an initialized Home root".into());
        }
        Ok(NativeActionReconciliationSource {
            home_root: self.root_path().to_path_buf(),
        })
    }

    pub(in crate::file_action_factory) fn native_action_observation_source(
        &self,
    ) -> Result<NativeActionObservationSource, String> {
        if self.root_path().as_os_str().is_empty() {
            return Err("native observation requires an initialized Home root".into());
        }
        Ok(NativeActionObservationSource {
            home_root: self.root_path().to_path_buf(),
        })
    }

    /// Internal host startup only. Creates no product command or action grant.
    pub fn open_native_action_storage(
        &self,
        config: NativeActionStorageConfig,
    ) -> Result<NativeActionStorage, String> {
        if self.root_path().as_os_str().is_empty() {
            return Err("native action storage requires an initialized Home root".into());
        }
        let home_root = self.root_path().canonicalize().map_err(|e| e.to_string())?;
        let path = home_root.join("actions");
        std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        let inputs = NativeActionInputCustody::open(
            path.join("inputs.sqlite"),
            self.home_id().as_str(),
            config.input_byte_limit,
        )
        .map_err(|e| format!("{e:?}"))?;
        Ok(NativeActionStorage {
            home_root,
            home_id: self.home_id().clone(),
            inputs,
            file_lease: config.file_lease,
        })
    }

    /// Open the Home runtime for an exact currently authorized editor command.
    /// Does not resolve content, deliver, acquire ownership or advance rules.
    pub fn open_editor_file_save_runtime(
        &mut self,
        context: &AuthenticatedActionContext,
        storage: &NativeActionStorage,
        command: &HostActionCommand,
    ) -> Result<GovernedHostFacade<NativeStores>, String> {
        storage.require_home(self)?;
        let prepared =
            self.prepare_native_editor_action(context, storage.inputs(), command, &command.policy)?;
        self.open_native_command_runtime(
            storage,
            command,
            prepared.key,
            prepared.basis,
            NativeActionKind::FileSave,
        )
    }

    /// Open the Home runtime for an exact currently authorized correction.
    /// Initialization reads no correction body and acquires no action ownership.
    pub fn open_editor_corrections_runtime(
        &mut self,
        context: &AuthenticatedActionContext,
        storage: &NativeActionStorage,
        command: &HostActionCommand,
    ) -> Result<GovernedHostFacade<NativeStores>, String> {
        storage.require_home(self)?;
        let prepared =
            self.prepare_native_corrections(context, storage.inputs(), command, &command.policy)?;
        self.open_native_command_runtime(
            storage,
            command,
            prepared.key,
            prepared.basis,
            NativeActionKind::RecordCorrections,
        )
    }

    // Only the purpose-specific current-authority preparation above reaches this
    // shared Home location. Package selection is internal, never caller intent.
    fn open_native_command_runtime(
        &mut self,
        storage: &NativeActionStorage,
        command: &HostActionCommand,
        key: SigningKey,
        basis: gaugedesk_store::command_dispatch::DispatchReadBasis,
        kind: NativeActionKind,
    ) -> Result<GovernedHostFacade<NativeStores>, String> {
        let register: fn(&whipplescript_store::SqliteStore) -> StoreResult<()> = match kind {
            NativeActionKind::FileSave => register_native_file_package,
            NativeActionKind::RecordCorrections => register_native_recording_package,
            NativeActionKind::InspectCorrections => {
                return Err("inspection cannot initialize a writable runtime".into())
            }
        };
        let root = GovernanceRootVerifier::new(self.authority().clone(), key.public_key());
        let policy = crate::action_policy::load_action_policy(
            self.store_ref(),
            &ActionPolicyIdentity {
                issuer: command.issuer.clone(),
                scope: command.scope.clone(),
                request_id: command.request_id.clone(),
            },
            &command.policy,
            &root,
        )?;
        let path = storage.home_root.join("actions/native");
        self.store_mut()
            .with_dispatch_basis(&basis, || -> StoreResult<_> {
                std::fs::create_dir_all(&path)?;
                let stores = NativeStores::open(
                    path.join("runtime.sqlite"),
                    path.join("coord.sqlite"),
                    path.join("items.sqlite"),
                )?;
                register(&stores.runtime)?;
                let mut runtime = GovernedHostFacade::from_signed_store_with_verifier(
                    stores,
                    command.policy.epoch,
                    policy.signed_envelope(),
                    &root,
                )
                .map_err(|e| {
                    StoreError::Conflict(format!("editor runtime policy refused: {e:?}"))
                })?;
                runtime
                    .kernel_mut()
                    .set_file_lease_policy(storage.file_lease);
                Ok(runtime)
            })
            .map_err(|e| format!("{e:?}"))?
            .map_err(|e| format!("{e:?}"))
    }
}

#[cfg(test)]
#[path = "file_action_storage_tests.rs"]
mod tests;
