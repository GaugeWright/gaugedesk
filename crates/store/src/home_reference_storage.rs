//! Dedicated per-project Home journal storage (DR-0318).
//!
//! The legacy product-store migrations remain the single schema source. This
//! database applies only their journal steps, never the product schema. The
//! private Store is a connection holder for the existing operation protocol;
//! no product record/command interface is exposed.

use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::home_reference_journal::*;
use crate::Store;

const JOURNAL_SCHEMA_VERSION: i64 = 8;

/// Coordinates retained by the authenticated Home outside the journal. A
/// caller's descriptor is not a grant of authority or a coverage certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeJournalBinding {
    pub project_id: String,
    pub home_id: String,
    pub incarnation: String,
}

/// One independent writer and immutable storage binding for one project Home.
/// Opening it does not establish accepting-path completeness or product consent.
pub struct HomeReferenceJournal {
    inner: Store,
    binding: HomeJournalBinding,
}

fn validate_binding(binding: &HomeJournalBinding) -> Result<(), JournalError> {
    if binding.project_id.trim().is_empty() || binding.home_id.trim().is_empty() {
        return Err(JournalError::Conflict(
            "project Home journal identity is empty",
        ));
    }
    if binding.incarnation.len() != 32
        || !binding
            .incarnation
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(JournalError::Conflict(
            "Home journal incarnation is invalid",
        ));
    }
    Ok(())
}

fn durable_connection(conn: &Connection) -> Result<(), JournalError> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA foreign_keys=ON;",
    )?;
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let sync: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    if mode != "wal" || sync != 2 {
        return Err(JournalError::Conflict(
            "Home journal requires durable WAL/FULL storage",
        ));
    }
    conn.set_prepared_statement_cache_capacity(crate::STATEMENT_CACHE_CAPACITY);
    Ok(())
}

impl HomeReferenceJournal {
    /// Explicit first creation. Never opens, replaces or adopts an existing
    /// file. An interrupted creation is refused on reopen until recovered by
    /// the owning Home; it cannot turn into an empty authoritative population.
    pub fn create(path: &Path, binding: HomeJournalBinding) -> Result<Self, JournalError> {
        validate_binding(&binding)?;
        let path_string = path
            .to_str()
            .ok_or(JournalError::Conflict("Home journal path is not UTF-8"))?
            .to_owned();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(JournalError::Storage)?;
        drop(file);
        let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        durable_connection(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for migration in crate::MIGRATIONS
            .iter()
            .filter(|migration| (3..=JOURNAL_SCHEMA_VERSION).contains(&migration.version))
        {
            tx.execute_batch(migration.sql)?;
        }
        tx.execute_batch(
            "CREATE TABLE home_reference_storage (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                project_id TEXT NOT NULL CHECK (length(project_id) > 0),
                home_id TEXT NOT NULL CHECK (length(home_id) > 0),
                incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
                schema_version INTEGER NOT NULL
            );
            CREATE TRIGGER home_reference_storage_no_update BEFORE UPDATE ON home_reference_storage
                BEGIN SELECT RAISE(ABORT, 'Home journal binding is immutable'); END;
            CREATE TRIGGER home_reference_storage_no_delete BEFORE DELETE ON home_reference_storage
                BEGIN SELECT RAISE(ABORT, 'Home journal binding is immutable'); END;
            CREATE TRIGGER home_reference_storage_no_replace BEFORE INSERT ON home_reference_storage
                WHEN EXISTS (SELECT 1 FROM home_reference_storage)
                BEGIN SELECT RAISE(ABORT, 'Home journal binding is immutable'); END;",
        )?;
        tx.execute(
            "INSERT INTO home_reference_storage VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                binding.project_id,
                binding.home_id,
                binding.incarnation,
                JOURNAL_SCHEMA_VERSION
            ],
        )?;
        tx.execute(
            "UPDATE home_reference_state SET home_id = ?1 WHERE id = 1",
            [&binding.home_id],
        )?;
        tx.execute_batch(
            "CREATE TRIGGER home_reference_state_home_immutable
            BEFORE UPDATE OF home_id ON home_reference_state
            WHEN NEW.home_id IS NOT OLD.home_id
            BEGIN SELECT RAISE(ABORT, 'Home journal authority is immutable'); END;",
        )?;
        tx.commit()?;
        Ok(Self::from_connection(conn, path_string, binding))
    }

    /// Existing storage must match coordinates independently retained by the
    /// Home. No CREATE flag, initialization, migration or identity inference.
    pub fn open_existing(path: &Path, expected: &HomeJournalBinding) -> Result<Self, JournalError> {
        validate_binding(expected)?;
        let path_string = path
            .to_str()
            .ok_or(JournalError::Conflict("Home journal path is not UTF-8"))?
            .to_owned();
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let (found, version) = conn.query_row(
            "SELECT project_id, home_id, incarnation, schema_version FROM home_reference_storage WHERE id = 1", [],
            |row| Ok((HomeJournalBinding {project_id: row.get(0)?, home_id: row.get(1)?, incarnation: row.get(2)?}, row.get::<_, i64>(3)?)))?;
        let authority: String = conn.query_row(
            "SELECT home_id FROM home_reference_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        if &found != expected || authority != expected.home_id || version != JOURNAL_SCHEMA_VERSION
        {
            return Err(JournalError::Conflict(
                "Home journal binding or schema does not match the retained Home",
            ));
        }
        durable_connection(&conn)?;
        Ok(Self::from_connection(conn, path_string, found))
    }

    fn from_connection(conn: Connection, path: String, binding: HomeJournalBinding) -> Self {
        Self {
            inner: Store {
                conn,
                codec: None,
                path,
                scratch: None,
                home_product: None,
                remembered: Default::default(),
            },
            binding,
        }
    }

    pub fn binding(&self) -> &HomeJournalBinding {
        &self.binding
    }

    pub fn register_checked_program_request(
        &mut self,
        home_id: &str,
        target_store: &str,
        target_store_incarnation: &str,
        request_key: &str,
        basis_digest: &str,
    ) -> Result<ReferenceOperation, JournalError> {
        self.inner.register_checked_program_request(
            home_id,
            target_store,
            target_store_incarnation,
            request_key,
            basis_digest,
        )
    }

    pub fn register_reference_operation(
        &mut self,
        home_id: &str,
        new: &NewReferenceOperation<'_>,
    ) -> Result<ReferenceOperation, JournalError> {
        self.inner.register_reference_operation(home_id, new)
    }

    pub fn complete_reference_operation<F>(
        &mut self,
        home_id: &str,
        operation_id: &str,
        verify: F,
    ) -> Result<ReferenceCompletion, JournalError>
    where
        F: FnOnce(&ReferenceOperation) -> Result<ReferenceEvidence, String>,
    {
        self.inner
            .complete_reference_operation(home_id, operation_id, verify)
    }

    pub fn complete_revalidated_reference_operation<F>(
        &mut self,
        home_id: &str,
        operation_id: &str,
        verify: F,
    ) -> Result<ReferenceCompletion, JournalError>
    where
        F: FnOnce(&ReferenceOperation, i64) -> Result<RevalidatedReferenceEvidence, String>,
    {
        self.inner
            .complete_revalidated_reference_operation(home_id, operation_id, verify)
    }

    pub fn refuse_reference_operation(
        &mut self,
        home_id: &str,
        operation_id: &str,
        reason_code: &str,
    ) -> Result<ReferenceOperation, JournalError> {
        self.inner
            .refuse_reference_operation(home_id, operation_id, reason_code)
    }

    pub fn reference_operations_for_target(
        &self,
        home_id: &str,
        target_store: &str,
    ) -> Result<Vec<ReferenceOperation>, JournalError> {
        self.inner
            .reference_operations_for_target(home_id, target_store)
    }

    pub fn reference_use_pins_for_target(
        &self,
        home_id: &str,
        target_store: &str,
    ) -> Result<Vec<ReferenceUsePin>, JournalError> {
        self.inner
            .reference_use_pins_for_target(home_id, target_store)
    }

    pub fn bind_exact_reference_use<F>(
        &mut self,
        home_id: &str,
        target_store: &str,
        use_key: &str,
        version_id: &str,
        operation_id: &str,
        verify: F,
    ) -> Result<ReferenceUsePin, JournalError>
    where
        F: FnOnce(&ReferenceOperation) -> Result<ReferenceUseEvidence, String>,
    {
        self.inner.bind_exact_reference_use(
            home_id,
            target_store,
            use_key,
            version_id,
            operation_id,
            verify,
        )
    }

    pub fn seal_reference_epoch(
        &mut self,
        home_id: &str,
        registry_basis: &str,
        policy_basis: &str,
        structural_basis: &str,
    ) -> Result<ReferenceSeal, JournalError> {
        self.inner
            .seal_reference_epoch(home_id, registry_basis, policy_basis, structural_basis)
    }

    pub fn finalize_reference_seal(&mut self, epoch: i64) -> Result<ReferenceSeal, JournalError> {
        self.inner.finalize_reference_seal(epoch)
    }

    pub fn unfinished_reference_seal_epochs(
        &self,
        home_id: &str,
    ) -> Result<Vec<i64>, JournalError> {
        self.inner.unfinished_reference_seal_epochs(home_id)
    }

    pub fn sealed_reference_epoch(
        &self,
        epoch: i64,
    ) -> Result<Option<ReferenceSeal>, JournalError> {
        self.inner.sealed_reference_epoch(epoch)
    }

    pub fn reference_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ReferenceOperation>, JournalError> {
        self.inner.reference_operation(operation_id)
    }

    pub fn reference_use_pin(
        &self,
        home_id: &str,
        target_store: &str,
        use_key: &str,
    ) -> Result<Option<ReferenceUsePin>, JournalError> {
        self.inner.reference_use_pin(home_id, target_store, use_key)
    }

    pub fn classify_legacy_reference_use_unknown(
        &mut self,
        home_id: &str,
        target_store: &str,
        use_key: &str,
        version_id: &str,
    ) -> Result<ReferenceUsePin, JournalError> {
        self.inner
            .classify_legacy_reference_use_unknown(home_id, target_store, use_key, version_id)
    }

    pub fn exact_reference_origin_for_version(
        &self,
        home_id: &str,
        target_store: &str,
        version_id: &str,
    ) -> Result<Option<String>, JournalError> {
        self.inner
            .exact_reference_origin_for_version(home_id, target_store, version_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "0123456789abcdef0123456789abcdef";

    fn binding(project: &str, home: &str, incarnation: &str) -> HomeJournalBinding {
        HomeJournalBinding {
            project_id: project.into(),
            home_id: home.into(),
            incarnation: incarnation.into(),
        }
    }

    fn one() -> HomeJournalBinding {
        binding("project:one", "home:one", TARGET)
    }

    fn operation<'a>(id: &'a str) -> NewReferenceOperation<'a> {
        NewReferenceOperation {
            operation_id: id,
            target_store: "runtime:one",
            target_store_incarnation: TARGET,
            kind: "checked-program",
            basis_digest: "basis:one",
        }
    }

    fn evidence(_: &ReferenceOperation) -> Result<ReferenceEvidence, String> {
        Ok(ReferenceEvidence {
            target_store_incarnation: TARGET.into(),
            evidence_ref: "operation:one".into(),
            witness_digest: "witness:one".into(),
        })
    }

    #[test]
    fn separate_writer_keeps_pending_and_seal_durable_through_product_rollback() {
        let root = tempfile::tempdir().unwrap();
        let mut product =
            Store::open(root.path().join("product.sqlite").to_str().unwrap()).unwrap();
        let product_writer = product
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        product_writer
            .execute(
                "INSERT INTO store_meta(key, value) VALUES ('uncommitted', 'value')",
                [],
            )
            .unwrap();
        let path = root.path().join("journal.sqlite");
        let mut journal = HomeReferenceJournal::create(&path, one()).unwrap();
        journal.inner.conn.busy_timeout(Duration::ZERO).unwrap();
        journal
            .register_reference_operation("home:one", &operation("pending"))
            .unwrap();
        journal
            .register_reference_operation("home:one", &operation("completed"))
            .unwrap();
        journal
            .complete_reference_operation("home:one", "completed", evidence)
            .unwrap();
        let seal = journal
            .seal_reference_epoch("home:one", "registry", "policy", "structure")
            .unwrap();
        assert_eq!(seal.operations.len(), 1);
        assert!(!seal.inventory_complete);
        product_writer.rollback().unwrap();
        drop(journal);
        let reopened = HomeReferenceJournal::open_existing(&path, &one()).unwrap();
        assert_eq!(
            reopened
                .reference_operation("pending")
                .unwrap()
                .unwrap()
                .completed_epoch,
            None
        );
        assert_eq!(
            reopened
                .reference_operation("completed")
                .unwrap()
                .unwrap()
                .completed_epoch,
            Some(0)
        );
        assert_eq!(reopened.sealed_reference_epoch(0).unwrap(), Some(seal));
        assert_eq!(
            product
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM store_meta WHERE key = 'uncommitted'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        // The dedicated file contains no product-command or record schema.
        assert_eq!(reopened.inner.conn.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('commands', 'records', 'log', 'store_meta')", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }

    #[test]
    fn each_project_home_has_an_independent_roster_and_epoch() {
        let root = tempfile::tempdir().unwrap();
        let other = binding(
            "project:two",
            "home:two",
            "fedcba9876543210fedcba9876543210",
        );
        let mut first =
            HomeReferenceJournal::create(&root.path().join("one.sqlite"), one()).unwrap();
        let mut second =
            HomeReferenceJournal::create(&root.path().join("two.sqlite"), other).unwrap();
        first
            .register_reference_operation("home:one", &operation("same-id"))
            .unwrap();
        second
            .register_reference_operation("home:two", &operation("same-id"))
            .unwrap();
        first
            .complete_reference_operation("home:one", "same-id", evidence)
            .unwrap();
        let first_cut = first
            .seal_reference_epoch("home:one", "r", "p", "s")
            .unwrap();
        let second_cut = second
            .seal_reference_epoch("home:two", "r", "p", "s")
            .unwrap();
        assert_eq!(first_cut.operations.len(), 1);
        assert!(second_cut.operations.is_empty());
        assert_eq!(
            second
                .reference_operation("same-id")
                .unwrap()
                .unwrap()
                .completed_epoch,
            None
        );
        assert!(first
            .register_reference_operation("home:two", &operation("foreign"))
            .is_err());
        assert!(first
            .seal_reference_epoch("home:two", "r", "p", "s")
            .is_err());
    }

    #[test]
    fn reopen_rejects_every_changed_binding_coordinate_and_replaced_storage() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal.sqlite");
        let journal = HomeReferenceJournal::create(&path, one()).unwrap();
        drop(journal);
        let mut wrong_project = one();
        wrong_project.project_id = "project:other".into();
        let mut wrong_home = one();
        wrong_home.home_id = "home:other".into();
        let mut wrong_incarnation = one();
        wrong_incarnation.incarnation = "fedcba9876543210fedcba9876543210".into();
        for wrong in [&wrong_project, &wrong_home, &wrong_incarnation] {
            assert!(HomeReferenceJournal::open_existing(&path, wrong).is_err());
        }
        assert_eq!(
            HomeReferenceJournal::open_existing(&path, &one())
                .unwrap()
                .binding(),
            &one()
        );
        // A physical replacement retaining project and Home but changing its
        // incarnation is refused against the independently retained descriptor.
        let replacement = root.path().join("replacement.sqlite");
        drop(HomeReferenceJournal::create(&replacement, wrong_incarnation).unwrap());
        std::fs::copy(&replacement, &path).unwrap();
        assert!(HomeReferenceJournal::open_existing(&path, &one()).is_err());
    }

    #[test]
    fn missing_empty_legacy_and_interrupted_storage_never_initialize_on_reopen() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing.sqlite");
        assert!(HomeReferenceJournal::open_existing(&missing, &one()).is_err());
        assert!(!missing.exists());
        let empty = root.path().join("interrupted.sqlite");
        std::fs::write(&empty, []).unwrap();
        assert!(HomeReferenceJournal::open_existing(&empty, &one()).is_err());
        assert_eq!(std::fs::metadata(&empty).unwrap().len(), 0);
        assert!(HomeReferenceJournal::create(&empty, one()).is_err());
        let legacy = root.path().join("prototype.sqlite");
        let mut prototype = Store::open(legacy.to_str().unwrap()).unwrap();
        prototype
            .register_reference_operation("home:one", &operation("old-pending"))
            .unwrap();
        drop(prototype);
        assert!(HomeReferenceJournal::open_existing(&legacy, &one()).is_err());
        let prototype = Store::open(legacy.to_str().unwrap()).unwrap();
        assert!(prototype
            .reference_operation("old-pending")
            .unwrap()
            .is_some());
    }

    #[test]
    fn durable_policy_is_reestablished_on_every_connection() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal.sqlite");
        let journal = HomeReferenceJournal::create(&path, one()).unwrap();
        assert_eq!(journal.inner.synchronous().unwrap(), 2);
        drop(journal);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=OFF;")
            .unwrap();
        drop(conn);
        let first = HomeReferenceJournal::open_existing(&path, &one()).unwrap();
        let second = HomeReferenceJournal::open_existing(&path, &one()).unwrap();
        for journal in [&first, &second] {
            assert_eq!(journal.inner.synchronous().unwrap(), 2);
            assert_eq!(
                journal
                    .inner
                    .conn
                    .query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
                    .unwrap(),
                "wal"
            );
        }
    }

    #[test]
    fn home_and_storage_identity_cannot_be_rebound_in_place() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal.sqlite");
        let journal = HomeReferenceJournal::create(&path, one()).unwrap();
        for mutation in [
            "UPDATE home_reference_storage SET project_id = 'another'",
            "DELETE FROM home_reference_storage",
            "INSERT OR REPLACE INTO home_reference_storage VALUES (1, 'other', 'other', '0123456789abcdef0123456789abcdef', 8)",
            "UPDATE home_reference_state SET home_id = 'another'",
        ] { assert!(journal.inner.conn.execute_batch(mutation).is_err(), "{mutation}"); }
        assert!(HomeReferenceJournal::create(&path, one()).is_err());
        drop(journal);
        assert!(HomeReferenceJournal::open_existing(&path, &one()).is_ok());
    }

    #[test]
    fn incompatible_or_corrupt_authority_storage_refuses_without_repair() {
        let root = tempfile::tempdir().unwrap();
        for corruption in [
            "DROP TRIGGER home_reference_storage_no_update; UPDATE home_reference_storage SET schema_version = 9",
            "DROP TRIGGER home_reference_state_home_immutable; UPDATE home_reference_state SET home_id = 'other'",
        ] {
            let path = root.path().join(if corruption.contains("schema_version") {"future.sqlite"} else {"corrupt.sqlite"});
            let journal = HomeReferenceJournal::create(&path, one()).unwrap();
            journal.inner.conn.execute_batch(corruption).unwrap();
            drop(journal);
            assert!(HomeReferenceJournal::open_existing(&path, &one()).is_err());
        }
    }
    // Invoked by the parent test in a separate process so exit leaves SQLite
    // connections and transactions undropped. Normal suite invocation is inert.
    #[test]
    fn interrupted_writer_child() {
        let Some(root) = std::env::var_os("GAUGEDESK_JOURNAL_CRASH_FIXTURE") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let phase = std::env::var("GAUGEDESK_JOURNAL_CRASH_PHASE").unwrap();
        let mut product = Store::open(root.join("product.sqlite").to_str().unwrap()).unwrap();
        let tx = product
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "INSERT INTO store_meta(key, value) VALUES ('product-ack', 'uncommitted')",
            [],
        )
        .unwrap();
        let mut journal =
            HomeReferenceJournal::create(&root.join("journal.sqlite"), one()).unwrap();
        journal
            .register_reference_operation("home:one", &operation("interrupted"))
            .unwrap();
        if phase != "pending" {
            let target = Connection::open(root.join("target.sqlite")).unwrap();
            target
                .execute_batch(
                    "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
                CREATE TABLE operation(id TEXT PRIMARY KEY, witness TEXT NOT NULL);
                INSERT INTO operation VALUES ('operation:one', 'witness:one');",
                )
                .unwrap();
            if phase == "completed" {
                journal
                    .complete_reference_operation("home:one", "interrupted", evidence)
                    .unwrap();
            }
        }
        std::process::exit(77);
    }

    #[test]
    fn process_interruption_retains_pending_or_completed_without_product_ack() {
        for phase in ["pending", "target", "completed"] {
            let root = tempfile::tempdir().unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "home_reference_storage::tests::interrupted_writer_child",
                    "--nocapture",
                ])
                .env("GAUGEDESK_JOURNAL_CRASH_FIXTURE", root.path())
                .env("GAUGEDESK_JOURNAL_CRASH_PHASE", phase)
                .output()
                .unwrap();
            assert_eq!(
                status.status.code(),
                Some(77),
                "{}",
                String::from_utf8_lossy(&status.stderr)
            );
            let mut journal =
                HomeReferenceJournal::open_existing(&root.path().join("journal.sqlite"), &one())
                    .unwrap();
            let retained = journal.reference_operation("interrupted").unwrap().unwrap();
            assert_eq!(
                retained.completed_epoch,
                if phase == "completed" { Some(0) } else { None }
            );
            let product =
                Store::open(root.path().join("product.sqlite").to_str().unwrap()).unwrap();
            assert_eq!(
                product
                    .conn
                    .query_row(
                        "SELECT COUNT(*) FROM store_meta WHERE key = 'product-ack'",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                0
            );
            if phase == "target" {
                // Recover the exact target after the interruption, not an
                // inferred version or a newly created replacement operation.
                let target = Connection::open_with_flags(
                    root.path().join("target.sqlite"),
                    OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .unwrap();
                journal
                    .complete_reference_operation("home:one", "interrupted", |_| {
                        target
                            .query_row(
                                "SELECT id, witness FROM operation WHERE id = 'operation:one'",
                                [],
                                |r| {
                                    Ok(ReferenceEvidence {
                                        target_store_incarnation: TARGET.into(),
                                        evidence_ref: r.get(0)?,
                                        witness_digest: r.get(1)?,
                                    })
                                },
                            )
                            .map_err(|error| error.to_string())
                    })
                    .unwrap();
            }
            let seal = journal
                .seal_reference_epoch("home:one", "r", "p", "s")
                .unwrap();
            assert_eq!(seal.operations.len(), usize::from(phase != "pending"));
            assert!(!seal.inventory_complete);
        }
    }
}
