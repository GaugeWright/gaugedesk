//! Exact native runtime evidence for a project Home's chat import pointer
//! (DR-0250, WS-159).
//!
//! This read establishes one target operation, not current package meaning or
//! Home-wide coverage. The Home separately owns pending registration, epoch
//! revalidation, product acknowledgment and the retained-use fence.

use std::path::Path;

use whipplescript_kernel::host_facade::require_home_store_incarnation;
use whipplescript_store::payload_protection::PayloadProtection;
use whipplescript_store::program_imports::ProgramImportOperationKind;
use whipplescript_store::SqliteStore;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HomeChatImportEvidence {
    pub target_store_incarnation: String,
    pub operation_id: String,
    pub version_id: String,
    pub witness_digest: String,
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
    store
        .program_import_witness(version_id, witness_digest)
        .map_err(|error| format!("Home chat target witness is unreadable: {error:?}"))?
        .ok_or("Home chat target import witness is missing")?;
    Ok(HomeChatImportEvidence {
        target_store_incarnation: incarnation,
        operation_id: operation.operation_id,
        version_id: operation.version_id,
        witness_digest: witness_digest.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use whipplescript_store::program_imports::ProgramImportWitness;
    use whipplescript_store::NewProgramVersion;

    fn digest(value: &str) -> String {
        hex::encode(Sha256::digest(value.as_bytes()))
    }

    #[test]
    fn exact_operation_survives_retry_but_a_replaced_store_cannot_inherit_it() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("runtime.sqlite");
        let mut store = SqliteStore::open(&path).unwrap();
        let source_hash = digest("checked source");
        let ir_hash = digest("checked IR");
        let version = NewProgramVersion {
            program_name: "Method",
            source_hash: &source_hash,
            ir_hash: &ir_hash,
            compiler_version: "whipplescript.host.v1",
            ir_snapshot: None,
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: "{}",
            generated_artifacts_json: "[]",
            artifact_root: None,
        };
        let witness = ProgramImportWitness {
            program_source_digest: source_hash.clone(),
            version_source_digest: None,
            lock_digest: digest("lock"),
            compiler_artifact_digest: digest("compiler"),
            examined: Vec::new(),
            edges: Vec::new(),
            edge_digest: digest("[]"),
            constructs: None,
            declarations: None,
            package_calls: None,
            provider_bindings: None,
            resource_fields: None,
        };
        let operation_id = "imp_11111111111111111111111111111111";
        let first = store
            .create_program_version_with_import_witness_at_id(version, &witness, operation_id)
            .unwrap();
        let retry = store
            .create_program_version_with_import_witness_at_id(version, &witness, operation_id)
            .unwrap();
        assert_eq!(first, retry);
        let incarnation = store.store_incarnation().unwrap().unwrap();
        drop(store);

        let exact = readback_home_chat_import(
            &path,
            None,
            &incarnation,
            operation_id,
            &first.version_id,
            &first.witness_digest,
        )
        .unwrap();
        assert_eq!(exact.operation_id, operation_id);
        assert!(readback_home_chat_import(
            &path,
            None,
            &incarnation,
            operation_id,
            "another version",
            &first.witness_digest,
        )
        .is_err());
        assert!(readback_home_chat_import(
            &path,
            None,
            &incarnation,
            operation_id,
            &first.version_id,
            &digest("another witness"),
        )
        .is_err());

        std::fs::rename(&path, root.path().join("retained.sqlite")).unwrap();
        drop(SqliteStore::open(&path).unwrap());
        assert!(readback_home_chat_import(
            &path,
            None,
            &incarnation,
            operation_id,
            &first.version_id,
            &first.witness_digest,
        )
        .is_err());
    }
}
