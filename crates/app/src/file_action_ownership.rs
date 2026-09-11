//! An explicitly acquired native runtime ownership fence. Observing the latest
//! epoch is never a substitute for retaining the epoch this owner acquired.
use super::*;
use gaugedesk_whip_runtime::host_actions::{facade::GovernedHostFacade, LogAppend, NativeStores};
use whipplescript_store::{StoreError, StoreResult};

/// Owns the actual facade and its acquired fence. It conveys no current product
/// authorization: each use must independently recheck the actor and admission.
pub struct NativeEditorActionRuntime {
    pub(super) runtime: GovernedHostFacade<NativeStores>,
    pub(super) admission: ActionAdmissionReceipt,
    pub(super) epoch: i64,
}

impl NativeEditorActionRuntime {
    /// The facade can be used for separately authorized evidence inspection.
    pub fn runtime(&self) -> &GovernedHostFacade<NativeStores> {
        &self.runtime
    }

    pub(super) fn require_current(&self, admission: &ActionAdmissionReceipt) -> StoreResult<()> {
        if admission != &self.admission
            || self
                .runtime
                .kernel()
                .store()
                .instance_owner_epoch(&admission.instance_ref)?
                != self.epoch
        {
            return Err(StoreError::Conflict(
                "native editor runtime ownership is stale or mismatched".into(),
            ));
        }
        Ok(())
    }
}

/// Called inside the same product writer fence used by every native takeover.
pub(super) fn require_epoch(
    runtime: &GovernedHostFacade<NativeStores>,
    admission: &ActionAdmissionReceipt,
    epoch: Option<i64>,
) -> StoreResult<()> {
    if let Some(expected) = epoch {
        if runtime
            .kernel()
            .store()
            .instance_owner_epoch(&admission.instance_ref)?
            != expected
        {
            return Err(StoreError::Conflict(
                "native editor runtime ownership is stale".into(),
            ));
        }
    }
    Ok(())
}

impl Workbench {
    /// Explicit recovery takeover of this actual runtime. This does not cancel
    /// an issued attempt, settle its outcome, advance rules or retry a target.
    pub fn claim_editor_file_save_runtime(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        mut runtime: GovernedHostFacade<NativeStores>,
    ) -> Result<NativeEditorActionRuntime, String> {
        let prepared =
            self.prepare_native_editor_action(context, inputs, command, runtime.policy_ref())?;
        let epoch = self
            .store_mut()
            .with_dispatch_basis(&prepared.basis, || {
                super::execution::read_evidence(&runtime, command, admission, &prepared.key)?;
                runtime
                    .kernel_mut()
                    .store_mut()
                    .claim_instance_ownership(&admission.instance_ref)
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))?;
        Ok(NativeEditorActionRuntime {
            runtime,
            admission: admission.clone(),
            epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{admitted_fixture, editor_runtime};
    use crate::LockUnpoisoned;
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;

    #[test]
    fn explicit_native_takeover_retains_its_epoch_and_requires_current_authority() {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command, inputs, token) = admitted_fixture(dir.path());
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        let admission = wb
            .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
            .unwrap()
            .receipt;
        let before = runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap();
        let first = wb
            .claim_editor_file_save_runtime(&context, &inputs, &command, &admission, runtime)
            .unwrap();
        first.require_current(&admission).unwrap();
        let replacement = editor_runtime(&wb, &command, dir.path());
        let second = wb
            .claim_editor_file_save_runtime(&context, &inputs, &command, &admission, replacement)
            .unwrap();
        second.require_current(&admission).unwrap();
        assert_eq!(second.epoch, first.epoch + 1);
        assert!(first.require_current(&admission).is_err());
        let mut changed = admission.clone();
        changed.fingerprint.push_str("-other");
        assert!(second.require_current(&changed).is_err());
        let replacement = editor_runtime(&wb, &command, dir.path());
        wb.revoke_account_session(&token);
        assert!(wb
            .claim_editor_file_save_runtime(&context, &inputs, &command, &admission, replacement)
            .is_err());
        second.require_current(&admission).unwrap();
        assert_eq!(
            second
                .runtime()
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap(),
            before
        );
    }
}
