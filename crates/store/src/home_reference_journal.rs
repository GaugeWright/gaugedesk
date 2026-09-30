//! The Home-owned accepting-operation roster and short epoch seal (DR-0250).
//!
//! This is the storage protocol, not a coverage certificate. The migration
//! deliberately leaves the accepting-path inventory unknown until every Home
//! door and its use fence is wired and proved. A local runtime store cannot
//! make that claim on behalf of this journal.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::Store;

#[derive(Debug)]
pub enum JournalError {
    Database(rusqlite::Error),
    Conflict(&'static str),
    Verification(String),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => error.fmt(f),
            Self::Conflict(message) => f.write_str(message),
            Self::Verification(message) => write!(f, "reference evidence refused: {message}"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<rusqlite::Error> for JournalError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewReferenceOperation<'a> {
    pub operation_id: &'a str,
    pub target_store: &'a str,
    pub kind: &'a str,
    /// Digest of the exact source, dependency, policy and structural input
    /// basis. Its meaning is supplied and verified by the accepting host.
    pub basis_digest: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReferenceOperation {
    pub operation_id: String,
    pub home_id: String,
    pub target_store: String,
    pub kind: String,
    pub basis_digest: String,
    pub registered_epoch: i64,
    pub completed_epoch: Option<i64>,
    pub evidence_ref: Option<String>,
    pub witness_digest: Option<String>,
    /// Present only when a pre-seal target write was checked against a later
    /// epoch before completion. The original registration basis remains intact.
    pub revalidated_basis_digest: Option<String>,
    /// A terminal refusal accounts for a registration without making its
    /// target evidence usable or adding it to an accepted seal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Box<ReferenceRefusal>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReferenceRefusal {
    pub epoch: i64,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceEvidence {
    /// Immutable identity in the target runtime store, not a moving version row.
    pub evidence_ref: String,
    pub witness_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevalidatedReferenceEvidence {
    pub evidence: ReferenceEvidence,
    /// Exact current source, dependency, policy and structural basis.
    pub current_basis_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferenceCompletion {
    Completed(Box<ReferenceOperation>),
    /// The seal won. The old target write remains registered but cannot be
    /// completed or used until a next-epoch revalidation path is supplied.
    NeedsRevalidation {
        registered_epoch: i64,
        current_epoch: i64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceSeal {
    pub home_id: String,
    pub epoch: i64,
    pub registry_basis: String,
    pub policy_basis: String,
    pub structural_basis: String,
    pub roster_digest: String,
    pub operations: Vec<ReferenceOperation>,
    /// Always false until the complete path inventory and use door are proved.
    /// A sealed exact subset is not yet a Home-wide coverage certificate.
    pub inventory_complete: bool,
}

fn required(value: &str) -> Result<(), JournalError> {
    if value.is_empty() {
        Err(JournalError::Conflict(
            "reference journal identity or basis is empty",
        ))
    } else {
        Ok(())
    }
}

fn state(conn: &Connection) -> Result<(Option<String>, i64, bool), JournalError> {
    Ok(conn.query_row(
        "SELECT home_id, current_epoch, inventory_complete \
         FROM home_reference_state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? != 0)),
    )?)
}

fn bind_home(conn: &Connection, home_id: &str) -> Result<i64, JournalError> {
    required(home_id)?;
    let (bound, epoch, _) = state(conn)?;
    if bound.as_deref().is_some_and(|bound| bound != home_id) {
        return Err(JournalError::Conflict(
            "reference journal belongs to a different Home",
        ));
    }
    if bound.is_none() {
        conn.execute(
            "UPDATE home_reference_state SET home_id = ?1 WHERE id = 1 AND home_id IS NULL",
            [home_id],
        )?;
    }
    Ok(epoch)
}

fn operation(
    conn: &Connection,
    operation_id: &str,
) -> Result<Option<ReferenceOperation>, JournalError> {
    Ok(conn
        .query_row(
            "SELECT operations.operation_id, operations.home_id, target_store, kind, basis_digest, \
                    registered_epoch, completed_epoch, evidence_ref, witness_digest, \
                    revalidated_basis_digest, refusals.refused_epoch, refusals.reason_code, \
                    refusals.home_id \
             FROM home_reference_operations AS operations \
             LEFT JOIN home_reference_refusals AS refusals \
               ON refusals.operation_id = operations.operation_id \
             WHERE operations.operation_id = ?1",
            [operation_id],
            |row| {
                let home_id: String = row.get(1)?;
                let refusal_home: Option<String> = row.get(12)?;
                if refusal_home.as_deref().is_some_and(|refusal_home| refusal_home != home_id) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(ReferenceOperation {
                    operation_id: row.get(0)?,
                    home_id,
                    target_store: row.get(2)?,
                    kind: row.get(3)?,
                    basis_digest: row.get(4)?,
                    registered_epoch: row.get(5)?,
                    completed_epoch: row.get(6)?,
                    evidence_ref: row.get(7)?,
                    witness_digest: row.get(8)?,
                    revalidated_basis_digest: row.get(9)?,
                    refusal: match (row.get(10)?, row.get(11)?) {
                        (Some(epoch), Some(reason)) => {
                            Some(Box::new(ReferenceRefusal { epoch, reason }))
                        }
                        (None, None) => None,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    },
                })
            },
        )
        .optional()?)
}

fn completed_in_epoch(
    conn: &Connection,
    epoch: i64,
) -> Result<Vec<ReferenceOperation>, JournalError> {
    let mut stmt = conn.prepare_cached(
        "SELECT operation_id FROM home_reference_operations \
         WHERE completed_epoch = ?1 ORDER BY operation_id",
    )?;
    let ids = stmt
        .query_map([epoch], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    ids.into_iter()
        .map(|id| {
            operation(conn, &id)?.ok_or(JournalError::Conflict(
                "sealed reference operation disappeared",
            ))
        })
        .collect()
}

fn digest(operations: &[ReferenceOperation]) -> Result<String, JournalError> {
    let encoded = serde_json::to_vec(operations)
        .map_err(|error| JournalError::Verification(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

impl Store {
    /// Register before the target runtime store writes. An exact retry returns
    /// the same row; an identity reused for different meaning is refused.
    pub fn register_reference_operation(
        &mut self,
        home_id: &str,
        new: &NewReferenceOperation<'_>,
    ) -> Result<ReferenceOperation, JournalError> {
        for value in [
            new.operation_id,
            new.target_store,
            new.kind,
            new.basis_digest,
        ] {
            required(value)?;
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let epoch = bind_home(&tx, home_id)?;
        if let Some(existing) = operation(&tx, new.operation_id)? {
            if existing.home_id != home_id
                || existing.target_store != new.target_store
                || existing.kind != new.kind
                || existing.basis_digest != new.basis_digest
            {
                return Err(JournalError::Conflict(
                    "reference operation identity has different meaning",
                ));
            }
            tx.commit()?;
            return Ok(existing);
        }
        tx.execute(
            "INSERT INTO home_reference_operations \
             (operation_id, home_id, target_store, kind, basis_digest, \
              registered_epoch, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')",
            params![
                new.operation_id,
                home_id,
                new.target_store,
                new.kind,
                new.basis_digest,
                epoch
            ],
        )?;
        let registered = operation(&tx, new.operation_id)?.ok_or(JournalError::Conflict(
            "registered reference operation disappeared",
        ))?;
        tx.commit()?;
        Ok(registered)
    }

    /// Complete only after the caller verifies immutable target evidence. The
    /// verifier runs outside the Home write transaction; the transaction then
    /// fences a seal that may have won during verification. The caller must not
    /// acknowledge or expose the target operation unless this returns Completed.
    pub fn complete_reference_operation<F>(
        &mut self,
        home_id: &str,
        operation_id: &str,
        verify: F,
    ) -> Result<ReferenceCompletion, JournalError>
    where
        F: FnOnce(&ReferenceOperation) -> Result<ReferenceEvidence, String>,
    {
        required(home_id)?;
        required(operation_id)?;
        let before = operation(&self.conn, operation_id)?.ok_or(JournalError::Conflict(
            "reference operation was not registered",
        ))?;
        if before.home_id != home_id {
            return Err(JournalError::Conflict(
                "reference operation belongs to a different Home",
            ));
        }
        if before.refusal.is_some() {
            return Err(JournalError::Conflict(
                "terminally refused reference operation cannot complete",
            ));
        }
        if before.completed_epoch.is_some() {
            return Ok(ReferenceCompletion::Completed(Box::new(before)));
        }
        let evidence = verify(&before).map_err(JournalError::Verification)?;
        required(&evidence.evidence_ref)?;
        required(&evidence.witness_digest)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_epoch = bind_home(&tx, home_id)?;
        let now = operation(&tx, operation_id)?.ok_or(JournalError::Conflict(
            "reference operation disappeared during verification",
        ))?;
        if now.refusal.is_some() {
            return Err(JournalError::Conflict(
                "reference operation was refused during verification",
            ));
        }
        if now.completed_epoch.is_some() {
            if now.evidence_ref.as_deref() != Some(&evidence.evidence_ref)
                || now.witness_digest.as_deref() != Some(&evidence.witness_digest)
            {
                return Err(JournalError::Conflict(
                    "concurrent reference completion has different evidence",
                ));
            }
            tx.commit()?;
            return Ok(ReferenceCompletion::Completed(Box::new(now)));
        }
        if now.registered_epoch != current_epoch {
            tx.commit()?;
            return Ok(ReferenceCompletion::NeedsRevalidation {
                registered_epoch: now.registered_epoch,
                current_epoch,
            });
        }
        tx.execute(
            "UPDATE home_reference_operations \
             SET status = 'completed', completed_epoch = ?2, \
                 evidence_ref = ?3, witness_digest = ?4 \
             WHERE operation_id = ?1 AND status = 'pending'",
            params![
                operation_id,
                current_epoch,
                evidence.evidence_ref,
                evidence.witness_digest
            ],
        )?;
        let completed = operation(&tx, operation_id)?.ok_or(JournalError::Conflict(
            "completed reference operation disappeared",
        ))?;
        tx.commit()?;
        Ok(ReferenceCompletion::Completed(Box::new(completed)))
    }

    /// Finish a registration whose seal won before its target write could be
    /// exposed. The accepting host verifies the target evidence and its full
    /// current basis, and names the epoch it checked. A seal during that work
    /// returns NeedsRevalidation again, preserving the pending obligation.
    pub fn complete_revalidated_reference_operation<F>(
        &mut self,
        home_id: &str,
        operation_id: &str,
        verify: F,
    ) -> Result<ReferenceCompletion, JournalError>
    where
        F: FnOnce(&ReferenceOperation, i64) -> Result<RevalidatedReferenceEvidence, String>,
    {
        required(home_id)?;
        required(operation_id)?;
        let before = operation(&self.conn, operation_id)?.ok_or(JournalError::Conflict(
            "reference operation was not registered",
        ))?;
        if before.home_id != home_id {
            return Err(JournalError::Conflict(
                "reference operation belongs to a different Home",
            ));
        }
        if before.refusal.is_some() {
            return Err(JournalError::Conflict(
                "terminally refused reference operation cannot revalidate",
            ));
        }
        if before.completed_epoch.is_some() {
            return Ok(ReferenceCompletion::Completed(Box::new(before)));
        }
        let (_, checked_epoch, _) = state(&self.conn)?;
        if checked_epoch == before.registered_epoch {
            return Err(JournalError::Conflict(
                "reference operation has not crossed a seal",
            ));
        }
        let checked = verify(&before, checked_epoch).map_err(JournalError::Verification)?;
        required(&checked.evidence.evidence_ref)?;
        required(&checked.evidence.witness_digest)?;
        required(&checked.current_basis_digest)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_epoch = bind_home(&tx, home_id)?;
        let now = operation(&tx, operation_id)?.ok_or(JournalError::Conflict(
            "reference operation disappeared during revalidation",
        ))?;
        if now.refusal.is_some() {
            return Err(JournalError::Conflict(
                "reference operation was refused during revalidation",
            ));
        }
        if now.completed_epoch.is_some() {
            if now.evidence_ref.as_deref() != Some(&checked.evidence.evidence_ref)
                || now.witness_digest.as_deref() != Some(&checked.evidence.witness_digest)
                || now.revalidated_basis_digest.as_deref() != Some(&checked.current_basis_digest)
            {
                return Err(JournalError::Conflict(
                    "concurrent reference completion has different revalidated evidence",
                ));
            }
            tx.commit()?;
            return Ok(ReferenceCompletion::Completed(Box::new(now)));
        }
        if current_epoch != checked_epoch {
            tx.commit()?;
            return Ok(ReferenceCompletion::NeedsRevalidation {
                registered_epoch: now.registered_epoch,
                current_epoch,
            });
        }
        tx.execute(
            "UPDATE home_reference_operations \
             SET status = 'completed', completed_epoch = ?2, \
                 evidence_ref = ?3, witness_digest = ?4, \
                 revalidated_basis_digest = ?5 \
             WHERE operation_id = ?1 AND status = 'pending'",
            params![
                operation_id,
                current_epoch,
                checked.evidence.evidence_ref,
                checked.evidence.witness_digest,
                checked.current_basis_digest
            ],
        )?;
        let completed = operation(&tx, operation_id)?.ok_or(JournalError::Conflict(
            "revalidated reference operation disappeared",
        ))?;
        tx.commit()?;
        Ok(ReferenceCompletion::Completed(Box::new(completed)))
    }

    /// Close a registered attempt that cannot become an acceptance. The row
    /// remains queryable by exact identity, including after a seal or crash,
    /// while the completed-operation roster excludes it. A caller must not
    /// use target evidence after choosing this disposition.
    pub fn refuse_reference_operation(
        &mut self,
        home_id: &str,
        operation_id: &str,
        reason_code: &str,
    ) -> Result<ReferenceOperation, JournalError> {
        for value in [home_id, operation_id, reason_code] {
            required(value)?;
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let epoch = bind_home(&tx, home_id)?;
        let before = operation(&tx, operation_id)?.ok_or(JournalError::Conflict(
            "reference operation was not registered",
        ))?;
        if before.home_id != home_id {
            return Err(JournalError::Conflict(
                "reference operation belongs to a different Home",
            ));
        }
        if before.completed_epoch.is_some() {
            return Err(JournalError::Conflict(
                "completed reference operation cannot be refused",
            ));
        }
        if let Some(existing) = &before.refusal {
            if existing.reason != reason_code {
                return Err(JournalError::Conflict(
                    "reference operation has a different terminal refusal",
                ));
            }
            tx.commit()?;
            return Ok(before);
        }
        tx.execute(
            "INSERT INTO home_reference_refusals \
             (operation_id, home_id, refused_epoch, reason_code) \
             VALUES (?1, ?2, ?3, ?4)",
            params![operation_id, home_id, epoch, reason_code],
        )?;
        let refused = operation(&tx, operation_id)?.ok_or(JournalError::Conflict(
            "refused reference operation disappeared",
        ))?;
        tx.commit()?;
        Ok(refused)
    }

    /// Atomically freeze the completed roster and advance admission to the
    /// next epoch. Pending rows remain owed. The seal is an exact cut, but it
    /// cannot claim completeness until the accepting-path inventory is proved.
    pub fn seal_reference_epoch(
        &mut self,
        home_id: &str,
        registry_basis: &str,
        policy_basis: &str,
        structural_basis: &str,
    ) -> Result<ReferenceSeal, JournalError> {
        for value in [home_id, registry_basis, policy_basis, structural_basis] {
            required(value)?;
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let epoch = bind_home(&tx, home_id)?;
        let operations = completed_in_epoch(&tx, epoch)?;
        let roster_digest = digest(&operations)?;
        tx.execute(
            "INSERT INTO home_reference_seals \
             (epoch, home_id, registry_basis, policy_basis, structural_basis, \
              roster_digest, operation_count) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                epoch,
                home_id,
                registry_basis,
                policy_basis,
                structural_basis,
                roster_digest,
                operations.len() as i64
            ],
        )?;
        tx.execute(
            "UPDATE home_reference_state SET current_epoch = ?1 WHERE id = 1",
            [epoch + 1],
        )?;
        tx.commit()?;
        Ok(ReferenceSeal {
            home_id: home_id.to_owned(),
            epoch,
            registry_basis: registry_basis.to_owned(),
            policy_basis: policy_basis.to_owned(),
            structural_basis: structural_basis.to_owned(),
            roster_digest,
            operations,
            inventory_complete: false,
        })
    }

    /// Read back and verify a frozen cut. Later admissions do not change its
    /// digest; missing or altered members refuse instead of shrinking it.
    pub fn sealed_reference_epoch(
        &self,
        epoch: i64,
    ) -> Result<Option<ReferenceSeal>, JournalError> {
        let seal: Option<(String, String, String, String, String, i64)> = self
            .conn
            .query_row(
                "SELECT home_id, registry_basis, policy_basis, structural_basis, \
                        roster_digest, operation_count \
                 FROM home_reference_seals WHERE epoch = ?1",
                [epoch],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((home_id, registry_basis, policy_basis, structural_basis, roster_digest, count)) =
            seal
        else {
            return Ok(None);
        };
        let operations = completed_in_epoch(&self.conn, epoch)?;
        if operations.len() as i64 != count || digest(&operations)? != roster_digest {
            return Err(JournalError::Conflict(
                "sealed reference roster differs from its durable cut",
            ));
        }
        Ok(Some(ReferenceSeal {
            home_id,
            epoch,
            registry_basis,
            policy_basis,
            structural_basis,
            roster_digest,
            operations,
            inventory_complete: false,
        }))
    }

    pub fn reference_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ReferenceOperation>, JournalError> {
        operation(&self.conn, operation_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(id: &'a str) -> NewReferenceOperation<'a> {
        NewReferenceOperation {
            operation_id: id,
            target_store: "chats/one.sqlite",
            kind: "checked-program",
            basis_digest: "source+lock+compiler+policy:one",
        }
    }

    fn evidence(_: &ReferenceOperation) -> Result<ReferenceEvidence, String> {
        Ok(ReferenceEvidence {
            evidence_ref: "operation:one".into(),
            witness_digest: "witness:one".into(),
        })
    }

    #[test]
    fn seal_freezes_completed_work_and_retains_pending_obligations() {
        let mut store = Store::open_in_memory().unwrap();
        let first = store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        assert_eq!(first.registered_epoch, 0);
        assert_eq!(
            store
                .register_reference_operation("home:one", &input("one"))
                .unwrap(),
            first,
        );
        store
            .complete_reference_operation("home:one", "one", evidence)
            .unwrap();
        store
            .register_reference_operation("home:one", &input("pending"))
            .unwrap();
        let seal = store
            .seal_reference_epoch("home:one", "registry:1", "policy:1", "tree:1")
            .unwrap();
        assert_eq!(seal.epoch, 0);
        assert_eq!(seal.operations.len(), 1);
        assert_eq!(seal.operations[0].operation_id, "one");
        assert!(!seal.inventory_complete);
        assert_eq!(store.sealed_reference_epoch(0).unwrap(), Some(seal.clone()));
        assert_eq!(
            store
                .complete_reference_operation("home:one", "pending", evidence)
                .unwrap(),
            ReferenceCompletion::NeedsRevalidation {
                registered_epoch: 0,
                current_epoch: 1,
            }
        );
        assert!(store
            .reference_operation("pending")
            .unwrap()
            .unwrap()
            .completed_epoch
            .is_none());
        store
            .register_reference_operation("home:one", &input("next"))
            .unwrap();
        store
            .complete_reference_operation("home:one", "next", evidence)
            .unwrap();
        assert_eq!(store.sealed_reference_epoch(0).unwrap(), Some(seal));
    }

    #[test]
    fn exact_retries_survive_reopen_and_identity_reuse_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("home.db");
        let path = path.to_str().unwrap();
        let mut store = Store::open(path).unwrap();
        store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        drop(store);
        let mut store = Store::open(path).unwrap();
        assert!(store.reference_operation("one").unwrap().is_some());
        let completed = store
            .complete_reference_operation("home:one", "one", evidence)
            .unwrap();
        assert!(matches!(completed, ReferenceCompletion::Completed(_)));
        assert_eq!(
            store
                .complete_reference_operation("home:one", "one", |_| panic!(
                    "retry must not rewrite evidence"
                ))
                .unwrap(),
            completed
        );
        let changed = NewReferenceOperation {
            basis_digest: "changed",
            ..input("one")
        };
        assert!(matches!(
            store.register_reference_operation("home:one", &changed),
            Err(JournalError::Conflict(_))
        ));
        assert!(matches!(
            store.register_reference_operation("home:other", &input("other")),
            Err(JournalError::Conflict(_))
        ));
        let sealed = store
            .seal_reference_epoch("home:one", "registry:1", "policy:1", "tree:1")
            .unwrap();
        drop(store);
        let reopened = Store::open(path).unwrap();
        assert_eq!(reopened.sealed_reference_epoch(0).unwrap(), Some(sealed));
    }

    #[test]
    fn failed_verification_keeps_pending_and_cannot_enter_seal() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        assert!(matches!(
            store.complete_reference_operation("home:one", "one", |_| Err("target missing".into())),
            Err(JournalError::Verification(_))
        ));
        let seal = store
            .seal_reference_epoch("home:one", "registry:1", "policy:1", "tree:1")
            .unwrap();
        assert!(seal.operations.is_empty());
        assert!(!seal.inventory_complete);
        assert!(store
            .reference_operation("one")
            .unwrap()
            .unwrap()
            .completed_epoch
            .is_none());
    }

    #[test]
    fn terminal_refusal_accounts_for_work_without_admitting_target_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("home.db");
        let path = path.to_str().unwrap();
        let mut store = Store::open(path).unwrap();
        store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        store
            .seal_reference_epoch("home:one", "registry:1", "policy:1", "tree:1")
            .unwrap();
        let refused = store
            .refuse_reference_operation("home:one", "one", "unresolved-import")
            .unwrap();
        assert_eq!(refused.registered_epoch, 0);
        assert_eq!(
            refused.refusal.as_ref().map(|refusal| refusal.epoch),
            Some(1)
        );
        assert_eq!(
            refused
                .refusal
                .as_ref()
                .map(|refusal| refusal.reason.as_str()),
            Some("unresolved-import")
        );
        assert!(refused.completed_epoch.is_none());
        assert_eq!(
            store
                .refuse_reference_operation("home:one", "one", "unresolved-import")
                .unwrap(),
            refused,
        );
        assert!(store
            .complete_reference_operation("home:one", "one", evidence)
            .is_err());
        assert!(store
            .complete_revalidated_reference_operation("home:one", "one", |_, _| {
                panic!("a refused operation must not revalidate")
            })
            .is_err());
        assert!(store
            .refuse_reference_operation("home:one", "one", "different-reason")
            .is_err());
        assert!(store
            .seal_reference_epoch("home:one", "registry:2", "policy:2", "tree:2")
            .unwrap()
            .operations
            .is_empty());
        drop(store);
        let mut reopened = Store::open(path).unwrap();
        assert_eq!(
            reopened.reference_operation("one").unwrap(),
            Some(refused.clone())
        );
        assert_eq!(
            reopened
                .register_reference_operation("home:one", &input("one"))
                .unwrap(),
            refused,
        );
    }

    #[test]
    fn completed_operation_cannot_be_rewritten_as_refused() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        let completed = store
            .complete_reference_operation("home:one", "one", evidence)
            .unwrap();
        assert!(store
            .refuse_reference_operation("home:one", "one", "no-longer-needed")
            .is_err());
        assert_eq!(
            store.reference_operation("one").unwrap(),
            Some(match completed {
                ReferenceCompletion::Completed(operation) => *operation,
                ReferenceCompletion::NeedsRevalidation { .. } => panic!("same epoch"),
            })
        );
    }

    #[test]
    fn upgrading_a_v3_seal_keeps_its_exact_roster_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("home.db");
        let path = path.to_str().unwrap();
        let mut store = Store::open(path).unwrap();
        store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        store
            .complete_reference_operation("home:one", "one", evidence)
            .unwrap();
        let sealed = store
            .seal_reference_epoch("home:one", "registry:1", "policy:1", "tree:1")
            .unwrap();
        assert!(!serde_json::to_string(&sealed.operations[0])
            .unwrap()
            .contains("refusal"));
        drop(store);
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(
            "DROP TABLE home_reference_refusals; \
             DELETE FROM schema_migrations WHERE version = 4;",
        )
        .unwrap();
        drop(conn);
        let upgraded = Store::open(path).unwrap();
        assert_eq!(upgraded.sealed_reference_epoch(0).unwrap(), Some(sealed));
        assert_eq!(upgraded.schema_version().unwrap(), 4);
    }

    #[test]
    fn deferred_target_is_revalidated_into_the_next_epoch() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        store
            .seal_reference_epoch("home:one", "registry:1", "policy:1", "tree:1")
            .unwrap();
        let completed = store
            .complete_revalidated_reference_operation("home:one", "one", |old, epoch| {
                assert_eq!(old.registered_epoch, 0);
                assert_eq!(epoch, 1);
                Ok(RevalidatedReferenceEvidence {
                    evidence: evidence(old)?,
                    current_basis_digest: "source+lock+compiler+policy:two".into(),
                })
            })
            .unwrap();
        let ReferenceCompletion::Completed(operation) = completed else {
            panic!("not completed")
        };
        assert_eq!(operation.completed_epoch, Some(1));
        assert_eq!(operation.registered_epoch, 0);
        assert_eq!(
            operation.revalidated_basis_digest.as_deref(),
            Some("source+lock+compiler+policy:two")
        );
        let next = store
            .seal_reference_epoch("home:one", "registry:2", "policy:2", "tree:2")
            .unwrap();
        assert_eq!(next.operations, vec![*operation]);
    }

    #[test]
    fn seal_during_revalidation_does_not_lose_pending_work() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        store
            .seal_reference_epoch("home:one", "registry:1", "policy:1", "tree:1")
            .unwrap();
        let mut concurrent = store.sibling().unwrap();
        let outcome = store
            .complete_revalidated_reference_operation("home:one", "one", |old, epoch| {
                assert_eq!(epoch, 1);
                concurrent
                    .seal_reference_epoch("home:one", "registry:2", "policy:2", "tree:2")
                    .unwrap();
                Ok(RevalidatedReferenceEvidence {
                    evidence: evidence(old)?,
                    current_basis_digest: "basis:1".into(),
                })
            })
            .unwrap();
        assert_eq!(
            outcome,
            ReferenceCompletion::NeedsRevalidation {
                registered_epoch: 0,
                current_epoch: 2,
            }
        );
        assert!(store
            .reference_operation("one")
            .unwrap()
            .unwrap()
            .completed_epoch
            .is_none());
    }
}
