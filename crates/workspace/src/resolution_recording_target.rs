//! Native correction targets bind the actual store and admitted namespace.
//! The caller holds current Home authority; these locators grant no access.
use super::{Engagement, NativeWorkspaceVcs, Result, WorkspaceError};
use whipplescript_store::{
    branches::BranchStore,
    content::ContentStore,
    vcs::resolution_scope::ResolutionMemoryScope,
    vcs_resolution_recording::{BoundResolutionRecording, ResolutionRecordingBinding},
    StoreError, StoreResult,
};

struct Coordinates {
    store_root: std::path::PathBuf,
    path: String,
    scope: ResolutionMemoryScope,
}
impl Coordinates {
    fn check_binding(&self, binding: &ResolutionRecordingBinding) -> StoreResult<()> {
        if binding.scope() != &self.scope {
            return Err(StoreError::Conflict(
                "native recording binding differs from its admitted target scope".into(),
            ));
        }
        Ok(())
    }
    fn observe(&self) -> StoreResult<NativeWorkspaceVcs> {
        NativeWorkspaceVcs::open_read_only(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )
    }
}

/// A confined native write target, built from the actual selected workspace.
/// No file base or caller-selected store path participates in construction.
pub struct NativeResolutionRecordingTarget {
    coordinates: Coordinates,
    branch: String,
}
impl NativeResolutionRecordingTarget {
    pub fn path(&self) -> &str {
        &self.coordinates.path
    }
    pub fn scope(&self) -> &ResolutionMemoryScope {
        &self.coordinates.scope
    }

    /// Prepare the owner's bound handler; recording happens only when the
    /// governed runtime invokes it after retaining dispatch evidence. Current
    /// input custody, target mapping and IFC checks remain host obligations.
    pub fn open_recording(
        &self,
        binding: ResolutionRecordingBinding,
        input_json: &str,
    ) -> StoreResult<BoundResolutionRecording<BranchStore, ContentStore>> {
        self.coordinates.check_binding(&binding)?;
        // Refuse an unavailable workspace instead of treating lost target
        // history as a new empty store. This needs no file content or base cut.
        if self
            .coordinates
            .observe()?
            .get_branch(&self.branch)?
            .is_none()
        {
            return Err(StoreError::Conflict(
                "native recording workspace is unavailable".into(),
            ));
        }
        let workspace = NativeWorkspaceVcs::open(
            self.coordinates.store_root.join("branches.sqlite"),
            self.coordinates.store_root.join("content.sqlite"),
        )?;
        BoundResolutionRecording::new(workspace, binding, input_json)
    }
}

/// Read-only access to the original target for an independently authorized
/// investigator. The owner reads its historical batch, not current knowledge
/// or erased correction bodies. There is no write adapter on this type.
pub struct NativeResolutionRecordingEvidenceTarget {
    coordinates: Coordinates,
}
impl NativeResolutionRecordingEvidenceTarget {
    pub fn path(&self) -> &str {
        &self.coordinates.path
    }
    pub fn scope(&self) -> &ResolutionMemoryScope {
        &self.coordinates.scope
    }

    /// Call the governed runtime's recovery reader against the actual target.
    /// The callback checks current read authority before reading the receipt.
    pub fn observe<T>(
        &self,
        binding: &ResolutionRecordingBinding,
        inspect: impl FnOnce(&NativeWorkspaceVcs) -> StoreResult<T>,
    ) -> StoreResult<T> {
        self.coordinates.check_binding(binding)?;
        inspect(&self.coordinates.observe()?)
    }
}

impl Engagement {
    fn native_resolution_coordinates(
        &self,
        path: &str,
        scope: ResolutionMemoryScope,
    ) -> Result<Coordinates> {
        if !super::valid_native_action_target_path(path) {
            return Err(WorkspaceError::msg(
                "recording requires a normalized native target path",
            ));
        }
        self.ensure_selected_path(path)?;
        Ok(Coordinates {
            store_root: self.store_root.clone(),
            path: path.into(),
            scope,
        })
    }
    pub fn native_resolution_recording_target(
        &self,
        path: &str,
        scope: ResolutionMemoryScope,
    ) -> Result<NativeResolutionRecordingTarget> {
        Ok(NativeResolutionRecordingTarget {
            coordinates: self.native_resolution_coordinates(path, scope)?,
            branch: self.branch.clone(),
        })
    }
    pub fn native_resolution_recording_evidence_target(
        &self,
        path: &str,
        scope: ResolutionMemoryScope,
    ) -> Result<NativeResolutionRecordingEvidenceTarget> {
        Ok(NativeResolutionRecordingEvidenceTarget {
            coordinates: self.native_resolution_coordinates(path, scope)?,
        })
    }
}

#[cfg(test)]
#[path = "resolution_recording_target_tests.rs"]
mod tests;
