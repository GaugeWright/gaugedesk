//! Compose the Home journal with independently read chat runtime evidence.
//!
//! The product app owns the operation journal. The WhippleScript runtime
//! adapter supplies an exact target read without depending on product storage.

use std::path::Path;

use gaugedesk_store::home_reference_journal::{
    HomeReferenceJournal, JournalError, ReferenceCompletion, ReferenceEvidence, ReferenceOperation,
};
use gaugedesk_whip_runtime::home_import::{readback_home_chat_import, HomeChatImportEvidence};
use whipplescript_store::payload_protection::PayloadProtection;

pub struct HomeChatImportCompletion<'a> {
    pub home_id: &'a str,
    pub target_store: &'a str,
    pub target_path: &'a Path,
    pub protection: Option<PayloadProtection>,
    pub home_operation_id: &'a str,
    pub target_operation_id: &'a str,
    pub version_id: &'a str,
    pub witness_digest: &'a str,
}

/// Complete the Home's already registered pointer only after independently
/// reading the exact checked target operation and independently checking its
/// source, lock, compiler and policy meaning against the registered basis.
/// A seal that won before this read leaves the pointer pending for current-basis
/// revalidation; the target's historical witness cannot supply that basis.
pub fn complete_home_chat_import<F>(
    journal: &mut HomeReferenceJournal,
    completion: HomeChatImportCompletion<'_>,
    verify_registered_basis: F,
) -> Result<ReferenceCompletion, JournalError>
where
    F: FnOnce(&ReferenceOperation, &HomeChatImportEvidence) -> Result<(), String>,
{
    journal.complete_reference_operation(
        completion.home_id,
        completion.home_operation_id,
        |registered| {
            verify_home_target(registered, completion.target_store)?;
            let incarnation = registered
                .target_store_incarnation
                .as_deref()
                .ok_or("Home operation has no target store incarnation")?;
            let evidence = readback_home_chat_import(
                completion.target_path,
                completion.protection,
                incarnation,
                completion.target_operation_id,
                completion.version_id,
                completion.witness_digest,
            )?;
            verify_registered_basis(registered, &evidence)?;
            Ok(ReferenceEvidence {
                target_store_incarnation: evidence.target_store_incarnation,
                evidence_ref: evidence.operation_id,
                witness_digest: evidence.witness_digest,
            })
        },
    )
}

fn verify_home_target(registered: &ReferenceOperation, target_store: &str) -> Result<(), String> {
    if registered.target_store != target_store || registered.kind != "checked-program" {
        return Err("Home operation names another target or accepting kind".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_store::home_reference_journal::NewReferenceOperation;
    use sha2::{Digest, Sha256};
    use whipplescript_store::program_imports::ProgramImportWitness;
    use whipplescript_store::{NewProgramVersion, SqliteStore};

    fn digest(value: &str) -> String {
        hex::encode(Sha256::digest(value.as_bytes()))
    }

    const TARGET_OPERATION: &str = "imp_11111111111111111111111111111111";

    fn write_checked_target(store: &mut SqliteStore, operation_id: &str) -> (String, String) {
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
        let first = store
            .create_program_version_with_import_witness_at_id(version, &witness, operation_id)
            .unwrap();
        let retry = store
            .create_program_version_with_import_witness_at_id(version, &witness, operation_id)
            .unwrap();
        assert_eq!(first, retry);
        (first.version_id, first.witness_digest)
    }

    #[test]
    fn exact_operation_survives_retry_but_a_replaced_store_cannot_inherit_it() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("runtime.sqlite");
        let mut store = SqliteStore::open(&path).unwrap();
        let (version_id, witness_digest) = write_checked_target(&mut store, TARGET_OPERATION);
        let incarnation = store.store_incarnation().unwrap().unwrap();
        drop(store);

        let exact = readback_home_chat_import(
            &path,
            None,
            &incarnation,
            TARGET_OPERATION,
            &version_id,
            &witness_digest,
        )
        .unwrap();
        assert_eq!(exact.operation_id, TARGET_OPERATION);
        assert!(readback_home_chat_import(
            &path,
            None,
            &incarnation,
            TARGET_OPERATION,
            "another version",
            &witness_digest,
        )
        .is_err());
        assert!(readback_home_chat_import(
            &path,
            None,
            &incarnation,
            TARGET_OPERATION,
            &version_id,
            &digest("another witness"),
        )
        .is_err());

        std::fs::rename(&path, root.path().join("retained.sqlite")).unwrap();
        drop(SqliteStore::open(&path).unwrap());
        assert!(readback_home_chat_import(
            &path,
            None,
            &incarnation,
            TARGET_OPERATION,
            &version_id,
            &witness_digest,
        )
        .is_err());
    }

    #[test]
    fn home_completion_requires_exact_target_and_preserves_a_postseal_pending_operation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("chat.sqlite");
        let mut target = SqliteStore::open(&path).unwrap();
        let incarnation = target.store_incarnation().unwrap().unwrap();
        let mut product = gaugedesk_store::Store::open_in_memory().unwrap();
        let mut journal = product
            .initialize_home_journal(root.path(), "project:one", "home:one")
            .unwrap();
        let registered = journal
            .register_reference_operation(
                "home:one",
                &NewReferenceOperation {
                    operation_id: "home-op:one",
                    target_store: "chats/one.sqlite",
                    target_store_incarnation: &incarnation,
                    kind: "checked-program",
                    basis_digest: "exact-source-lock-compiler-policy",
                },
            )
            .unwrap();
        assert!(registered.completed_epoch.is_none());
        let (version_id, witness_digest) = write_checked_target(&mut target, TARGET_OPERATION);
        drop(target);

        assert!(complete_home_chat_import(
            &mut journal,
            HomeChatImportCompletion {
                home_id: "home:one",
                target_store: "chats/other.sqlite",
                target_path: &path,
                protection: None,
                home_operation_id: "home-op:one",
                target_operation_id: TARGET_OPERATION,
                version_id: &version_id,
                witness_digest: &witness_digest,
            },
            |_, _| Ok(()),
        )
        .is_err());
        assert!(complete_home_chat_import(
            &mut journal,
            HomeChatImportCompletion {
                home_id: "home:one",
                target_store: "chats/one.sqlite",
                target_path: &path,
                protection: None,
                home_operation_id: "home-op:one",
                target_operation_id: TARGET_OPERATION,
                version_id: &version_id,
                witness_digest: &witness_digest,
            },
            |_, _| Err("source basis no longer matches".into()),
        )
        .is_err());
        assert!(journal
            .reference_operation("home-op:one")
            .unwrap()
            .unwrap()
            .completed_epoch
            .is_none());
        let seal = journal
            .seal_reference_epoch("home:one", "registry", "policy", "structure")
            .unwrap();
        assert!(seal.operations.is_empty());
        assert!(matches!(
            complete_home_chat_import(
                &mut journal,
                HomeChatImportCompletion {
                    home_id: "home:one",
                    target_store: "chats/one.sqlite",
                    target_path: &path,
                    protection: None,
                    home_operation_id: "home-op:one",
                    target_operation_id: TARGET_OPERATION,
                    version_id: &version_id,
                    witness_digest: &witness_digest,
                },
                |_, _| Ok(()),
            ),
            Ok(ReferenceCompletion::NeedsRevalidation { .. })
        ));
        assert!(journal
            .reference_operation("home-op:one")
            .unwrap()
            .unwrap()
            .completed_epoch
            .is_none());

        journal
            .register_reference_operation(
                "home:one",
                &NewReferenceOperation {
                    operation_id: "home-op:two",
                    target_store: "chats/one.sqlite",
                    target_store_incarnation: &incarnation,
                    kind: "checked-program",
                    basis_digest: "exact-current-source-lock-compiler-policy",
                },
            )
            .unwrap();
        let new_target_operation = "imp_22222222222222222222222222222222";
        let (new_version, new_witness) =
            write_checked_target(&mut SqliteStore::open(&path).unwrap(), new_target_operation);
        let completed = complete_home_chat_import(
            &mut journal,
            HomeChatImportCompletion {
                home_id: "home:one",
                target_store: "chats/one.sqlite",
                target_path: &path,
                protection: None,
                home_operation_id: "home-op:two",
                target_operation_id: new_target_operation,
                version_id: &new_version,
                witness_digest: &new_witness,
            },
            |registered, evidence| {
                (registered.basis_digest == "exact-current-source-lock-compiler-policy"
                    && evidence.witness.program_source_digest == digest("checked source")
                    && evidence.witness.lock_digest == digest("lock")
                    && evidence.witness.compiler_artifact_digest == digest("compiler")
                    && evidence.program_version.ir_hash == digest("checked IR"))
                .then_some(())
                .ok_or_else(|| "Home basis changed".to_owned())
            },
        )
        .unwrap();
        assert!(matches!(completed, ReferenceCompletion::Completed(_)));
    }
}
