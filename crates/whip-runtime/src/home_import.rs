//! Exact native runtime evidence for a project Home's chat import pointer
//! (DR-0250, WS-159).
//!
//! This read establishes one target operation, not current package meaning or
//! Home-wide coverage. The Home separately owns pending registration, epoch
//! revalidation, product acknowledgment and the retained-use fence.

use std::path::Path;

use whipplescript_kernel::host_facade::require_home_store_incarnation;
use whipplescript_store::payload_protection::PayloadProtection;
use whipplescript_store::program_imports::{ProgramImportOperationKind, ProgramImportWitness};
use whipplescript_store::{ProgramVersionView, SqliteStore};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HomeChatImportEvidence {
    pub target_store_incarnation: String,
    pub operation_id: String,
    pub version_id: String,
    pub witness_digest: String,
    /// Exact target witness, read and digest-checked by WhippleScript's store.
    /// The product still checks its meaning against the registered Home basis.
    pub witness: ProgramImportWitness,
    pub program_version: ProgramVersionView,
}

/// Independently read one immutable checked operation from the existing target.
/// A replacement at the same path, a reused version with another operation, or
/// an unwitnessed/legacy admission cannot complete the Home pointer.
pub fn readback_home_chat_import(
    path: &Path,
    protection: Option<PayloadProtection>,
    expected_incarnation: &str,
    operation_id: &str,
    version_id: &str,
    witness_digest: &str,
) -> Result<HomeChatImportEvidence, String> {
    if !path.is_file() {
        return Err("Home chat target runtime is missing".into());
    }
    let store = match protection {
        Some(protection) => SqliteStore::open_read_only_protected(path, protection),
        None => SqliteStore::open_read_only(path),
    }
    .map_err(|error| format!("Home chat target runtime is unreadable: {error:?}"))?;
    let incarnation = require_home_store_incarnation(&store)
        .map_err(|error| format!("Home chat target identity is invalid: {error}"))?;
    if incarnation != expected_incarnation {
        return Err("Home chat target store incarnation changed".into());
    }
    let operation = store
        .program_import_operation(operation_id)
        .map_err(|error| format!("Home chat target operation is unreadable: {error:?}"))?
        .ok_or("Home chat target operation is missing")?;
    if operation.kind != ProgramImportOperationKind::Checked
        || operation.version_id != version_id
        || operation.witness_digest.as_deref() != Some(witness_digest)
    {
        return Err("Home chat target operation differs from its registered evidence".into());
    }
    let witness = store
        .program_import_witness(version_id, witness_digest)
        .map_err(|error| format!("Home chat target witness is unreadable: {error:?}"))?
        .ok_or("Home chat target import witness is missing")?;
    let program_version = store
        .get_program_version(version_id)
        .map_err(|error| format!("Home chat target version is unreadable: {error:?}"))?
        .ok_or("Home chat target version is missing")?;
    Ok(HomeChatImportEvidence {
        target_store_incarnation: incarnation,
        operation_id: operation.operation_id,
        version_id: operation.version_id,
        witness_digest: witness_digest.to_owned(),
        witness,
        program_version,
    })
}
