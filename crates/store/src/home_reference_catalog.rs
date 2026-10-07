//! Product-side durable bindings for separate Home journals (DR-0318).
//!
//! The authenticated Home registers a binding before journal creation, then
//! retains an immutable readiness receipt after the exact file opens. Runtime
//! accepting paths only reopen ready bindings. These are storage coordinates,
//! not membership, methodology standing or a coverage certificate.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};

use crate::home_reference_journal::{
    HomeJournalBinding, HomeReferenceJournal, JournalError, ReferenceUseClassification,
    ReferenceUsePin,
};
use crate::Store;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeJournalRegistration {
    pub binding: HomeJournalBinding,
    pub ready: bool,
}

/// Product-owned location beneath one state root. Hash the full opaque project
/// id rather than a display-name slug, and never include the incarnation: losing
/// a catalog must not let a new identity create a second empty journal beside
/// an existing project file. A root path is trusted host configuration.
pub fn home_reference_journal_path(root: &Path, project_id: &str) -> PathBuf {
    root.join("homes")
        .join(hex::encode(Sha256::digest(project_id.as_bytes())))
        .join("reference-operations.sqlite")
}

fn registration(
    conn: &Connection,
    project_id: &str,
) -> Result<Option<HomeJournalRegistration>, JournalError> {
    let descriptor = conn.query_row(
        "SELECT project_id, home_id, incarnation FROM home_reference_journal_bindings WHERE project_id = ?1", [project_id],
        |row| Ok(HomeJournalBinding {project_id: row.get(0)?, home_id: row.get(1)?, incarnation: row.get(2)?})).optional()?;
    let Some(binding) = descriptor else {
        return Ok(None);
    };
    let ready = conn
        .query_row(
            "SELECT home_id, incarnation FROM home_reference_journal_ready WHERE project_id = ?1",
            [project_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if ready.as_ref().is_some_and(|(home, incarnation)| {
        home != &binding.home_id || incarnation != &binding.incarnation
    }) {
        return Err(JournalError::Conflict(
            "Home journal readiness differs from its registration",
        ));
    }
    Ok(Some(HomeJournalRegistration {
        binding,
        ready: ready.is_some(),
    }))
}

// Catalog durability is independent of the product's ordinary NORMAL setting.
// Do this before target/product writer entry, never inside an existing writer.
// Restore the connection policy after success or refusal; a panic can only leave
// the stronger setting, not permit a target write on an uncommitted binding.
fn durable_catalog_write<T>(
    conn: &mut Connection,
    write: impl FnOnce(&Transaction<'_>) -> Result<T, JournalError>,
) -> Result<T, JournalError> {
    crate::durable_registry::write(
        conn,
        JournalError::Conflict("Home journal creation must precede the product writer"),
        write,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeReferenceUseAcknowledgment {
    pub binding: HomeJournalBinding,
    pub pin: ReferenceUsePin,
    pub evidence_ref: String,
    pub witness_digest: String,
}

fn acknowledgment(
    conn: &Connection,
    project_id: &str,
    target_store: &str,
    use_key: &str,
) -> Result<Option<HomeReferenceUseAcknowledgment>, JournalError> {
    Ok(conn.query_row("SELECT home_id, journal_incarnation, target_store_incarnation, version_id, operation_id, bound_epoch, evidence_ref, witness_digest FROM home_reference_use_acknowledgments WHERE project_id = ?1 AND target_store = ?2 AND use_key = ?3", params![project_id, target_store, use_key], |row| {
        let home_id: String = row.get(0)?;
        Ok(HomeReferenceUseAcknowledgment {
            binding: HomeJournalBinding {project_id: project_id.into(), home_id: home_id.clone(), incarnation: row.get(1)?},
            pin: ReferenceUsePin {home_id, target_store: target_store.into(), target_store_incarnation: Some(row.get(2)?), use_key: use_key.into(), version_id: row.get(3)?, operation_id: Some(row.get(4)?), classification: ReferenceUseClassification::Exact, bound_epoch: row.get(5)?},
            evidence_ref: row.get(6)?, witness_digest: row.get(7)?,
        })
    }).optional()?)
}

impl Store {
    pub fn home_reference_use_acknowledgment(
        &self,
        project_id: &str,
        target_store: &str,
        use_key: &str,
    ) -> Result<Option<HomeReferenceUseAcknowledgment>, JournalError> {
        acknowledgment(&self.conn, project_id, target_store, use_key)
    }

    /// Commit the product's acknowledgment after independently verified journal
    /// completion and an exact use pin. Only the returned committed receipt can
    /// satisfy this storage half of the use door; current policy and target
    /// verification remain the accepting path's obligations on every use.
    pub fn acknowledge_home_reference_use(
        &mut self,
        journal: &HomeReferenceJournal,
        target_store: &str,
        use_key: &str,
    ) -> Result<HomeReferenceUseAcknowledgment, JournalError> {
        let binding = journal.binding();
        let pin = journal
            .reference_use_pin(&binding.home_id, target_store, use_key)?
            .ok_or(JournalError::Conflict(
                "Home product acknowledgment has no exact use pin",
            ))?;
        if pin.classification != ReferenceUseClassification::Exact {
            return Err(JournalError::Conflict(
                "legacy use cannot acquire a product acknowledgment",
            ));
        }
        let operation_id = pin.operation_id.clone().ok_or(JournalError::Conflict(
            "Home use pin has no exact operation",
        ))?;
        let operation = journal
            .reference_operation(&operation_id)?
            .ok_or(JournalError::Conflict("Home use operation is missing"))?;
        if operation.home_id != binding.home_id
            || operation.target_store != target_store
            || operation.completed_epoch.is_none()
            || operation.refusal.is_some()
            || operation.target_store_incarnation.is_none()
            || operation.target_store_incarnation != pin.target_store_incarnation
        {
            return Err(JournalError::Conflict(
                "Home use pin does not match a completed exact target",
            ));
        }
        let expected = HomeReferenceUseAcknowledgment {
            binding: binding.clone(),
            pin,
            evidence_ref: operation
                .evidence_ref
                .ok_or(JournalError::Conflict("Home completion has no evidence"))?,
            witness_digest: operation
                .witness_digest
                .ok_or(JournalError::Conflict("Home completion has no witness"))?,
        };
        durable_catalog_write(&mut self.conn, |tx| {
            let current = registration(tx, &binding.project_id)?.ok_or(JournalError::Conflict(
                "Home product acknowledgment has no journal registration",
            ))?;
            if !current.ready || current.binding != *binding {
                return Err(JournalError::Conflict(
                    "Home product acknowledgment has a different journal binding",
                ));
            }
            if let Some(found) = acknowledgment(tx, &binding.project_id, target_store, use_key)? {
                if found != expected {
                    return Err(JournalError::Conflict(
                        "Home product acknowledgment has different meaning",
                    ));
                }
                return Ok(found);
            }
            tx.execute("INSERT INTO home_reference_use_acknowledgments VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)", params![binding.project_id, binding.home_id, binding.incarnation, target_store, expected.pin.target_store_incarnation, use_key, expected.pin.version_id, operation_id, expected.pin.bound_epoch, expected.evidence_ref, expected.witness_digest])?;
            Ok(expected)
        })
    }
    /// Inspect independently retained storage coordinates. Does not discover,
    /// create, adopt or certify a Home from a directory or runtime roster.
    pub fn home_journal_registration(
        &self,
        project_id: &str,
    ) -> Result<Option<HomeJournalRegistration>, JournalError> {
        registration(&self.conn, project_id)
    }

    /// Called by the authenticated Home's explicit creation/recovery path before
    /// target admission. One project and one Home retain exactly one binding;
    /// retries reuse its incarnation and changed identities refuse.
    pub fn register_home_journal(
        &mut self,
        project_id: &str,
        home_id: &str,
    ) -> Result<HomeJournalRegistration, JournalError> {
        if project_id.trim().is_empty() || home_id.trim().is_empty() {
            return Err(JournalError::Conflict(
                "project Home journal identity is empty",
            ));
        }
        durable_catalog_write(&mut self.conn, |tx| {
            crate::home_product::check_product_identity(tx, project_id, home_id)?;
            if let Some(found) = registration(tx, project_id)? {
                if found.binding.home_id != home_id {
                    return Err(JournalError::Conflict(
                        "project journal belongs to a different Home",
                    ));
                }
                return Ok(found);
            }
            let existing_home = tx
                .query_row(
                    "SELECT project_id FROM home_reference_journal_bindings WHERE home_id = ?1",
                    [home_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()?;
            if existing_home.is_some() {
                return Err(JournalError::Conflict(
                    "Home journal already belongs to another project",
                ));
            }
            tx.execute("INSERT INTO home_reference_journal_bindings(project_id, home_id, incarnation) VALUES (?1, ?2, lower(hex(randomblob(16))))", params![project_id, home_id])?;
            registration(tx, project_id)?.ok_or(JournalError::Conflict(
                "Home journal registration disappeared",
            ))
        })
    }

    /// Creation may resume an exact, fully initialized file after interruption
    /// before the product readiness receipt. A partial or foreign file refuses;
    /// it is never erased. A ready registration uses only no-create reopening.
    pub fn initialize_home_journal(
        &mut self,
        root: &Path,
        project_id: &str,
        home_id: &str,
    ) -> Result<HomeReferenceJournal, JournalError> {
        let registered = self.register_home_journal(project_id, home_id)?;
        let path = home_reference_journal_path(root, project_id);
        if registered.ready {
            return HomeReferenceJournal::open_existing(&path, &registered.binding);
        }
        let journal = if path.exists() {
            HomeReferenceJournal::open_existing(&path, &registered.binding)?
        } else {
            std::fs::create_dir_all(
                path.parent()
                    .ok_or(JournalError::Conflict("Home journal root is absent"))?,
            )
            .map_err(JournalError::Storage)?;
            HomeReferenceJournal::create(&path, registered.binding.clone())?
        };
        durable_catalog_write(&mut self.conn, |tx| {
            let current = registration(tx, project_id)?.ok_or(JournalError::Conflict(
                "Home journal registration disappeared",
            ))?;
            if current.binding != registered.binding {
                return Err(JournalError::Conflict(
                    "Home journal registration changed during creation",
                ));
            }
            if !current.ready {
                tx.execute("INSERT INTO home_reference_journal_ready(project_id, home_id, incarnation) VALUES (?1, ?2, ?3)", params![registered.binding.project_id, registered.binding.home_id, registered.binding.incarnation])?;
            }
            Ok(())
        })?;
        Ok(journal)
    }

    /// The accepting path's door: an existing ready binding, an exact Home, and
    /// no filesystem initialization. Missing or mismatched journal state refuses
    /// before the caller can register or write a target operation.
    pub fn open_home_journal(
        &self,
        root: &Path,
        project_id: &str,
        home_id: &str,
    ) -> Result<HomeReferenceJournal, JournalError> {
        let registered = registration(&self.conn, project_id)?.ok_or(JournalError::Conflict(
            "project Home journal has not been registered",
        ))?;
        if !registered.ready || registered.binding.home_id != home_id {
            return Err(JournalError::Conflict(
                "project Home journal is not ready for this authority",
            ));
        }
        HomeReferenceJournal::open_existing(
            &home_reference_journal_path(root, project_id),
            &registered.binding,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::home_reference_journal::NewReferenceOperation;
    use rusqlite::TransactionBehavior;

    const TARGET: &str = "0123456789abcdef0123456789abcdef";

    fn pending() -> NewReferenceOperation<'static> {
        NewReferenceOperation {
            operation_id: "pending:one",
            target_store: "runtime:one",
            target_store_incarnation: TARGET,
            kind: "checked-program",
            basis_digest: "basis:one",
        }
    }

    #[test]
    fn registered_home_reopens_one_exact_journal_before_and_during_product_writer() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("product.sqlite");
        let mut product = Store::open(path.to_str().unwrap()).unwrap();
        let original_sync = product.synchronous().unwrap();
        let journal = product
            .initialize_home_journal(root.path(), "project:one", "home:one")
            .unwrap();
        let expected = journal.binding().clone();
        let registered = product
            .home_journal_registration("project:one")
            .unwrap()
            .unwrap();
        assert!(registered.ready);
        assert_eq!(registered.binding, expected);
        assert_eq!(product.synchronous().unwrap(), original_sync);
        let catalog_reader = product.sibling().unwrap();
        let writer = product
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        writer
            .execute(
                "INSERT INTO store_meta(key, value) VALUES ('uncommitted', 'yes')",
                [],
            )
            .unwrap();
        let mut reopened = catalog_reader
            .open_home_journal(root.path(), "project:one", "home:one")
            .unwrap();
        assert_eq!(reopened.binding(), &expected);
        reopened
            .register_reference_operation("home:one", &pending())
            .unwrap();
        let seal = reopened
            .seal_reference_epoch("home:one", "r", "p", "s")
            .unwrap();
        assert!(seal.operations.is_empty());
        assert!(!seal.inventory_complete);
        writer.rollback().unwrap();
        drop(journal);
        drop(reopened);
        drop(product);
        let mut product = Store::open(path.to_str().unwrap()).unwrap();
        let recovered = product
            .initialize_home_journal(root.path(), "project:one", "home:one")
            .unwrap();
        assert_eq!(recovered.binding(), &expected);
        assert!(recovered
            .reference_operation("pending:one")
            .unwrap()
            .is_some());
        assert_eq!(
            product
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM home_reference_journal_bindings",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn one_project_home_never_shares_or_changes_its_registered_binding() {
        let root = tempfile::tempdir().unwrap();
        let mut product = Store::open_in_memory().unwrap();
        let first = product
            .initialize_home_journal(root.path(), "project.one", "home:one")
            .unwrap();
        let second = product
            .initialize_home_journal(root.path(), "project-one", "home:two")
            .unwrap();
        assert_ne!(first.binding().incarnation, second.binding().incarnation);
        assert_ne!(
            home_reference_journal_path(root.path(), "project.one"),
            home_reference_journal_path(root.path(), "project-one")
        );
        assert!(product
            .register_home_journal("project.one", "home:two")
            .is_err());
        assert!(product
            .register_home_journal("project:other", "home:one")
            .is_err());
        assert!(product
            .open_home_journal(root.path(), "project.one", "home:two")
            .is_err());
        assert!(product
            .open_home_journal(root.path(), "project:other", "home:one")
            .is_err());
        assert_eq!(
            product
                .home_journal_registration("project.one")
                .unwrap()
                .unwrap()
                .binding,
            *first.binding()
        );
        assert_eq!(
            product
                .home_journal_registration("project-one")
                .unwrap()
                .unwrap()
                .binding,
            *second.binding()
        );
    }

    #[test]
    fn ready_journal_loss_cannot_be_initialized_again_and_replacement_refuses() {
        let root = tempfile::tempdir().unwrap();
        let mut product = Store::open_in_memory().unwrap();
        let journal = product
            .initialize_home_journal(root.path(), "project", "home")
            .unwrap();
        let original = journal.binding().clone();
        drop(journal);
        let path = home_reference_journal_path(root.path(), "project");
        std::fs::remove_file(&path).unwrap();
        assert!(product
            .open_home_journal(root.path(), "project", "home")
            .is_err());
        assert!(product
            .initialize_home_journal(root.path(), "project", "home")
            .is_err());
        assert!(!path.exists());
        let mut replaced = original.clone();
        replaced.incarnation = TARGET.into();
        drop(HomeReferenceJournal::create(&path, replaced).unwrap());
        assert!(product
            .open_home_journal(root.path(), "project", "home")
            .is_err());
        assert!(product
            .initialize_home_journal(root.path(), "project", "home")
            .is_err());
        assert_eq!(
            product
                .home_journal_registration("project")
                .unwrap()
                .unwrap()
                .binding,
            original
        );
    }

    #[test]
    fn missing_catalog_and_partial_creation_preserve_unknown_existing_storage() {
        let root = tempfile::tempdir().unwrap();
        let mut original = Store::open_in_memory().unwrap();
        let mut journal = original
            .initialize_home_journal(root.path(), "project", "home")
            .unwrap();
        journal
            .register_reference_operation("home", &pending())
            .unwrap();
        let old = journal.binding().clone();
        drop(journal);
        let mut lost_catalog = Store::open_in_memory().unwrap();
        assert!(lost_catalog
            .open_home_journal(root.path(), "project", "home")
            .is_err());
        assert!(lost_catalog
            .initialize_home_journal(root.path(), "project", "home")
            .is_err());
        assert!(HomeReferenceJournal::open_existing(
            &home_reference_journal_path(root.path(), "project"),
            &old
        )
        .unwrap()
        .reference_operation("pending:one")
        .unwrap()
        .is_some());
        assert!(
            !lost_catalog
                .home_journal_registration("project")
                .unwrap()
                .unwrap()
                .ready
        );
        let root = tempfile::tempdir().unwrap();
        let mut product = Store::open_in_memory().unwrap();
        let binding = product
            .register_home_journal("partial", "home:partial")
            .unwrap()
            .binding;
        let path = home_reference_journal_path(root.path(), "partial");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, []).unwrap();
        assert!(product
            .initialize_home_journal(root.path(), "partial", "home:partial")
            .is_err());
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
        assert_eq!(
            product
                .home_journal_registration("partial")
                .unwrap()
                .unwrap(),
            HomeJournalRegistration {
                binding,
                ready: false
            }
        );
    }

    #[test]
    fn immutable_catalog_and_exact_readiness_hold_even_without_foreign_keys() {
        let root = tempfile::tempdir().unwrap();
        let mut product = Store::open_in_memory().unwrap();
        product
            .initialize_home_journal(root.path(), "project", "home")
            .unwrap();
        product
            .conn
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();
        for mutation in [
            "UPDATE home_reference_journal_bindings SET home_id = 'other'",
            "DELETE FROM home_reference_journal_bindings",
            "INSERT OR REPLACE INTO home_reference_journal_bindings VALUES ('project', 'home', '0123456789abcdef0123456789abcdef')",
            "UPDATE home_reference_journal_ready SET incarnation = '0123456789abcdef0123456789abcdef'",
            "DELETE FROM home_reference_journal_ready",
            "INSERT INTO home_reference_journal_ready VALUES ('unknown', 'unknown', '0123456789abcdef0123456789abcdef')",
            "INSERT OR REPLACE INTO home_reference_journal_ready SELECT * FROM home_reference_journal_bindings",
        ] {assert!(product.conn.execute_batch(mutation).is_err(), "{mutation}");}
        assert!(product
            .open_home_journal(root.path(), "project", "home")
            .is_ok());
    }

    #[test]
    fn concurrent_registration_reuses_one_identity_and_restores_connection_policy() {
        let mut first = Store::open_in_memory().unwrap();
        let mut second = first.sibling().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let other = barrier.clone();
        let worker = std::thread::spawn(move || {
            other.wait();
            let before = second.synchronous().unwrap();
            let found = second.register_home_journal("project", "home").unwrap();
            assert_eq!(second.synchronous().unwrap(), before);
            found
        });
        barrier.wait();
        let found = first.register_home_journal("project", "home").unwrap();
        assert_eq!(found, worker.join().unwrap());
        let before = first.synchronous().unwrap();
        assert!(first
            .register_home_journal("project", "other-home")
            .is_err());
        assert_eq!(first.synchronous().unwrap(), before);
    }

    #[test]
    fn durable_catalog_write_uses_wal_full_or_rollback_extra_and_restores_policy() {
        for (mode, required) in [("WAL", 2), ("DELETE", 3)] {
            let mut product = Store::open_in_memory().unwrap();
            product
                .conn
                .execute_batch(&format!(
                    "PRAGMA journal_mode={mode}; PRAGMA synchronous=OFF; PRAGMA fullfsync=OFF;"
                ))
                .unwrap();
            durable_catalog_write(&mut product.conn, |tx| {
                assert_eq!(
                    tx.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))
                        .unwrap(),
                    required
                );
                assert_eq!(
                    tx.query_row("PRAGMA fullfsync", [], |r| r.get::<_, i64>(0))
                        .unwrap(),
                    1
                );
                Ok(())
            })
            .unwrap();
            assert_eq!(product.synchronous().unwrap(), 0);
            assert_eq!(
                product
                    .conn
                    .query_row("PRAGMA fullfsync", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn journal_completion_stays_unacknowledged_when_product_commit_cannot_run() {
        use crate::home_reference_journal::{ReferenceEvidence, ReferenceUseEvidence};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("product.sqlite");
        let mut product = Store::open(path.to_str().unwrap()).unwrap();
        let mut journal = product
            .initialize_home_journal(root.path(), "project", "home")
            .unwrap();
        journal
            .register_reference_operation("home", &pending())
            .unwrap();
        journal
            .complete_reference_operation("home", "pending:one", |_| {
                Ok(ReferenceEvidence {
                    target_store_incarnation: TARGET.into(),
                    evidence_ref: "target-operation".into(),
                    witness_digest: "witness".into(),
                })
            })
            .unwrap();
        let pin = journal
            .bind_exact_reference_use(
                "home",
                "runtime:one",
                "item",
                "version",
                "pending:one",
                |_| {
                    Ok(ReferenceUseEvidence {
                        target_store_incarnation: TARGET.into(),
                        version_id: "version".into(),
                        evidence_ref: "target-operation".into(),
                        witness_digest: "witness".into(),
                    })
                },
            )
            .unwrap();
        assert!(product
            .home_reference_use_acknowledgment("project", "runtime:one", "item")
            .unwrap()
            .is_none());
        let mut sibling = product.sibling().unwrap();
        sibling
            .conn
            .busy_timeout(std::time::Duration::ZERO)
            .unwrap();
        let writer = product
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(sibling
            .acknowledge_home_reference_use(&journal, "runtime:one", "item")
            .is_err());
        assert!(sibling
            .home_reference_use_acknowledgment("project", "runtime:one", "item")
            .unwrap()
            .is_none());
        writer.rollback().unwrap();
        assert!(journal
            .reference_operation("pending:one")
            .unwrap()
            .unwrap()
            .completed_epoch
            .is_some());
        let acknowledged = product
            .acknowledge_home_reference_use(&journal, "runtime:one", "item")
            .unwrap();
        assert_eq!(acknowledged.pin, pin);
        assert_eq!(
            product
                .acknowledge_home_reference_use(&journal, "runtime:one", "item")
                .unwrap(),
            acknowledged
        );
        for mutation in ["DELETE FROM home_reference_use_acknowledgments", "UPDATE home_reference_use_acknowledgments SET witness_digest = 'other'", "INSERT OR REPLACE INTO home_reference_use_acknowledgments SELECT * FROM home_reference_use_acknowledgments"] {
            assert!(product.conn.execute_batch(mutation).is_err());
        }
        drop(product);
        drop(journal);
        let mut product = Store::open(path.to_str().unwrap()).unwrap();
        let journal = product
            .open_home_journal(root.path(), "project", "home")
            .unwrap();
        assert_eq!(
            product
                .acknowledge_home_reference_use(&journal, "runtime:one", "item")
                .unwrap(),
            acknowledged
        );
        product.conn.execute_batch("DROP TRIGGER home_reference_ack_no_update; UPDATE home_reference_use_acknowledgments SET witness_digest = 'other';").unwrap();
        assert!(product
            .acknowledge_home_reference_use(&journal, "runtime:one", "item")
            .is_err());
    }

    #[test]
    fn catalog_crash_child() {
        let Some(root) = std::env::var_os("GAUGEDESK_HOME_CATALOG_CRASH_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        let phase = std::env::var("GAUGEDESK_HOME_CATALOG_CRASH_PHASE").unwrap();
        let mut product = Store::open(root.join("product.sqlite").to_str().unwrap()).unwrap();
        let reserved = product.register_home_journal("project", "home").unwrap();
        if phase == "created" {
            let path = home_reference_journal_path(&root, "project");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let _journal = HomeReferenceJournal::create(&path, reserved.binding).unwrap();
            std::process::exit(77);
        } else if phase == "ready" {
            let mut journal = product
                .initialize_home_journal(&root, "project", "home")
                .unwrap();
            journal
                .register_reference_operation("home", &pending())
                .unwrap();
            std::process::exit(77);
        }
        std::process::exit(77);
    }

    #[test]
    fn explicit_creation_recovers_catalog_file_and_readiness_crash_boundaries() {
        for phase in ["registered", "created", "ready"] {
            let root = tempfile::tempdir().unwrap();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "home_reference_catalog::tests::catalog_crash_child",
                    "--nocapture",
                ])
                .env("GAUGEDESK_HOME_CATALOG_CRASH_FIXTURE", root.path())
                .env("GAUGEDESK_HOME_CATALOG_CRASH_PHASE", phase)
                .output()
                .unwrap();
            assert_eq!(
                child.status.code(),
                Some(77),
                "{}",
                String::from_utf8_lossy(&child.stderr)
            );
            let mut product =
                Store::open(root.path().join("product.sqlite").to_str().unwrap()).unwrap();
            let before = product
                .home_journal_registration("project")
                .unwrap()
                .unwrap();
            assert_eq!(before.ready, phase == "ready");
            if !before.ready {
                assert!(product
                    .open_home_journal(root.path(), "project", "home")
                    .is_err());
            }
            let recovered = product
                .initialize_home_journal(root.path(), "project", "home")
                .unwrap();
            assert_eq!(recovered.binding(), &before.binding);
            assert_eq!(
                recovered
                    .reference_operation("pending:one")
                    .unwrap()
                    .is_some(),
                phase == "ready"
            );
            assert!(
                product
                    .home_journal_registration("project")
                    .unwrap()
                    .unwrap()
                    .ready
            );
            assert_eq!(
                product
                    .conn
                    .query_row(
                        "SELECT COUNT(*) FROM home_reference_journal_bindings",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                1
            );
        }
    }
}
