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
pub enum ReferenceUseClassification {
    Exact,
    LegacyUnknown,
}

/// One immutable item-to-admission binding. A retained version alone cannot
/// choose among several accepting operations for the same version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceUsePin {
    pub home_id: String,
    pub target_store: String,
    pub use_key: String,
    pub version_id: String,
    pub operation_id: Option<String>,
    pub classification: ReferenceUseClassification,
    pub bound_epoch: i64,
}

/// The target store's read of the exact immutable operation and witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceUseEvidence {
    pub version_id: String,
    pub evidence_ref: String,
    pub witness_digest: String,
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

fn use_pin(
    conn: &Connection,
    home_id: &str,
    target_store: &str,
    use_key: &str,
) -> Result<Option<ReferenceUsePin>, JournalError> {
    let row: Option<(String, String, Option<String>, i64)> = conn
        .query_row(
            "SELECT version_id, classification, operation_id, bound_epoch \
             FROM home_reference_use_pins \
             WHERE home_id = ?1 AND target_store = ?2 AND use_key = ?3",
            params![home_id, target_store, use_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((version_id, classification, operation_id, bound_epoch)) = row else {
        return Ok(None);
    };
    let classification = match (classification.as_str(), operation_id.as_deref()) {
        ("exact", Some(id)) => {
            let operation = operation(conn, id)?.ok_or(JournalError::Conflict(
                "exact reference use pin has no target operation",
            ))?;
            if operation.home_id != home_id
                || operation.target_store != target_store
                || operation.completed_epoch.is_none()
                || operation.refusal.is_some()
            {
                return Err(JournalError::Conflict(
                    "exact reference use pin has no completed Home operation",
                ));
            }
            ReferenceUseClassification::Exact
        }
        ("legacy_unknown", None) => ReferenceUseClassification::LegacyUnknown,
        _ => return Err(JournalError::Conflict("malformed reference use pin")),
    };
    Ok(Some(ReferenceUsePin {
        home_id: home_id.to_owned(),
        target_store: target_store.to_owned(),
        use_key: use_key.to_owned(),
        version_id,
        operation_id,
        classification,
        bound_epoch,
    }))
}

fn completed_through_epoch(
    conn: &Connection,
    epoch: i64,
) -> Result<Vec<ReferenceOperation>, JournalError> {
    let mut stmt = conn.prepare_cached(
        "SELECT operation_id FROM home_reference_operations \
         WHERE completed_epoch <= ?1 ORDER BY operation_id",
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct SealMetadata {
    home_id: String,
    registry_basis: String,
    policy_basis: String,
    structural_basis: String,
    roster_digest: String,
    operation_count: i64,
    roster_scope: String,
    seal_status: String,
}

fn seal_metadata(conn: &Connection, epoch: i64) -> Result<Option<SealMetadata>, JournalError> {
    Ok(conn
        .query_row(
            "SELECT home_id, registry_basis, policy_basis, structural_basis, \
                    roster_digest, operation_count, roster_scope, seal_status \
             FROM home_reference_seals WHERE epoch = ?1",
            [epoch],
            |row| {
                Ok(SealMetadata {
                    home_id: row.get(0)?,
                    registry_basis: row.get(1)?,
                    policy_basis: row.get(2)?,
                    structural_basis: row.get(3)?,
                    roster_digest: row.get(4)?,
                    operation_count: row.get(5)?,
                    roster_scope: row.get(6)?,
                    seal_status: row.get(7)?,
                })
            },
        )
        .optional()?)
}

fn validate_seal_frontier(
    conn: &Connection,
    epoch: i64,
    home_id: &str,
) -> Result<(), JournalError> {
    let (bound, current_epoch, _) = state(conn)?;
    if bound.as_deref() != Some(home_id) || current_epoch <= epoch {
        return Err(JournalError::Conflict(
            "reference seal has no matching advanced Home frontier",
        ));
    }
    Ok(())
}

impl Store {
    /// Give one logical checked-program request a recoverable target operation
    /// identity. The request key is chosen and retained by the authenticated
    /// Home, not by the runtime store. It deliberately excludes the basis:
    /// retrying the same request after a source or policy change must conflict
    /// with its original registration instead of silently creating a second
    /// operation. A changed target is a different request and needs explicit
    /// disposition of the first one.
    pub fn register_checked_program_request(
        &mut self,
        home_id: &str,
        target_store: &str,
        request_key: &str,
        basis_digest: &str,
    ) -> Result<ReferenceOperation, JournalError> {
        for value in [home_id, target_store, request_key, basis_digest] {
            required(value)?;
        }
        let identity = serde_json::to_vec(&(
            "gaugedesk.checked-program-request.v1",
            home_id,
            target_store,
            request_key,
        ))
        .map_err(|error| JournalError::Verification(error.to_string()))?;
        let hash = Sha256::digest(identity);
        let operation_id = format!("imp_{}", hex::encode(&hash[..16]));
        self.register_reference_operation(
            home_id,
            &NewReferenceOperation {
                operation_id: &operation_id,
                target_store,
                kind: "checked-program",
                basis_digest,
            },
        )
    }

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
        let evidence = verify(&before).map_err(JournalError::Verification)?;
        required(&evidence.evidence_ref)?;
        required(&evidence.witness_digest)?;
        if before.completed_epoch.is_some() {
            if before.evidence_ref.as_deref() != Some(&evidence.evidence_ref)
                || before.witness_digest.as_deref() != Some(&evidence.witness_digest)
            {
                return Err(JournalError::Conflict(
                    "completed reference operation differs from current target evidence",
                ));
            }
            return Ok(ReferenceCompletion::Completed(Box::new(before)));
        }
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
        let (_, checked_epoch, _) = state(&self.conn)?;
        if before.completed_epoch.is_none() && checked_epoch == before.registered_epoch {
            return Err(JournalError::Conflict(
                "reference operation has not crossed a seal",
            ));
        }
        let checked = verify(&before, checked_epoch).map_err(JournalError::Verification)?;
        required(&checked.evidence.evidence_ref)?;
        required(&checked.evidence.witness_digest)?;
        required(&checked.current_basis_digest)?;
        if before.completed_epoch.is_some() {
            if before.evidence_ref.as_deref() != Some(&checked.evidence.evidence_ref)
                || before.witness_digest.as_deref() != Some(&checked.evidence.witness_digest)
            {
                return Err(JournalError::Conflict(
                    "completed revalidated reference operation differs from current target evidence",
                ));
            }
            // The recorded epoch and basis remain historical facts. A later
            // basis belongs to the use door, not a rewrite of this completion.
            return Ok(ReferenceCompletion::Completed(Box::new(before)));
        }
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

    /// Bind one item to its exact completed admission before runtime arrival
    /// or effects. The caller reads immutable target evidence outside the Home
    /// write transaction; this transaction then checks the Home pointer and
    /// keeps a competing admission from replacing an existing item pin.
    #[allow(clippy::too_many_arguments)]
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
        for value in [home_id, target_store, use_key, version_id, operation_id] {
            required(value)?;
        }
        let before = operation(&self.conn, operation_id)?.ok_or(JournalError::Conflict(
            "reference use operation was not registered",
        ))?;
        if before.home_id != home_id || before.target_store != target_store {
            return Err(JournalError::Conflict(
                "reference use operation belongs to another Home or target",
            ));
        }
        if before.completed_epoch.is_none() || before.refusal.is_some() {
            return Err(JournalError::Conflict(
                "reference use operation is not completed",
            ));
        }
        let evidence = verify(&before).map_err(JournalError::Verification)?;
        for value in [
            &evidence.version_id,
            &evidence.evidence_ref,
            &evidence.witness_digest,
        ] {
            required(value)?;
        }
        if evidence.version_id != version_id
            || before.evidence_ref.as_deref() != Some(&evidence.evidence_ref)
            || before.witness_digest.as_deref() != Some(&evidence.witness_digest)
        {
            return Err(JournalError::Conflict(
                "reference use target evidence differs from its Home pointer",
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let epoch = bind_home(&tx, home_id)?;
        let now = operation(&tx, operation_id)?.ok_or(JournalError::Conflict(
            "reference use operation disappeared during target verification",
        ))?;
        if now != before {
            return Err(JournalError::Conflict(
                "reference use operation changed during target verification",
            ));
        }
        if let Some(existing) = use_pin(&tx, home_id, target_store, use_key)? {
            if existing.classification != ReferenceUseClassification::Exact
                || existing.operation_id.as_deref() != Some(operation_id)
                || existing.version_id != version_id
            {
                return Err(JournalError::Conflict(
                    "reference use already has a different immutable pin",
                ));
            }
            tx.commit()?;
            return Ok(existing);
        }
        tx.execute(
            "INSERT INTO home_reference_use_pins \
             (home_id, target_store, use_key, version_id, classification, \
              operation_id, bound_epoch) VALUES (?1, ?2, ?3, ?4, 'exact', ?5, ?6)",
            params![
                home_id,
                target_store,
                use_key,
                version_id,
                operation_id,
                epoch
            ],
        )?;
        let pinned = use_pin(&tx, home_id, target_store, use_key)?
            .ok_or(JournalError::Conflict("new reference use pin disappeared"))?;
        tx.commit()?;
        Ok(pinned)
    }

    /// Commit the cut and its bases under brief admission exclusion, then
    /// materialize the immutable roster without holding the writer. A crash
    /// between those steps leaves a pending seal that cannot certify a gate.
    /// Pending operations remain owed in the next epoch.
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
        tx.execute(
            "INSERT INTO home_reference_seals \
             (epoch, home_id, registry_basis, policy_basis, structural_basis, \
              roster_digest, operation_count, roster_scope, seal_status) \
             VALUES (?1, ?2, ?3, ?4, ?5, '', 0, 'through_epoch', 'pending')",
            params![
                epoch,
                home_id,
                registry_basis,
                policy_basis,
                structural_basis
            ],
        )?;
        tx.execute(
            "UPDATE home_reference_state SET current_epoch = ?1 WHERE id = 1",
            [epoch + 1],
        )?;
        tx.commit()?;
        self.finalize_reference_seal(epoch)
    }

    /// Resume a cut whose frontier was durably advanced before a crash. The
    /// completed rows through that epoch cannot change through this journal
    /// API, so later admissions do not enter its roster.
    pub fn finalize_reference_seal(&mut self, epoch: i64) -> Result<ReferenceSeal, JournalError> {
        let before = seal_metadata(&self.conn, epoch)?
            .ok_or(JournalError::Conflict("reference seal does not exist"))?;
        validate_seal_frontier(&self.conn, epoch, &before.home_id)?;
        if before.roster_scope != "through_epoch" {
            return Err(JournalError::Conflict(
                "legacy reference seal cannot be finalized again",
            ));
        }
        let operations = completed_through_epoch(&self.conn, epoch)?;
        let roster_digest = digest(&operations)?;
        let operation_count = i64::try_from(operations.len())
            .map_err(|_| JournalError::Conflict("reference roster exceeds seal capacity"))?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = seal_metadata(&tx, epoch)?
            .ok_or(JournalError::Conflict("reference seal disappeared"))?;
        if now != before {
            return Err(JournalError::Conflict(
                "reference seal changed during finalization",
            ));
        }
        validate_seal_frontier(&tx, epoch, &now.home_id)?;
        match now.seal_status.as_str() {
            "pending" => {
                tx.execute(
                    "UPDATE home_reference_seals \
                     SET roster_digest = ?2, operation_count = ?3, seal_status = 'final' \
                     WHERE epoch = ?1 AND seal_status = 'pending'",
                    params![epoch, roster_digest, operation_count],
                )?;
            }
            "final"
                if now.roster_digest == roster_digest && now.operation_count == operation_count => {
            }
            "final" => {
                return Err(JournalError::Conflict(
                    "sealed reference roster differs from its durable cut",
                ));
            }
            _ => return Err(JournalError::Conflict("unknown reference seal status")),
        }
        tx.commit()?;
        Ok(ReferenceSeal {
            home_id: now.home_id,
            epoch,
            registry_basis: now.registry_basis,
            policy_basis: now.policy_basis,
            structural_basis: now.structural_basis,
            roster_digest,
            operations,
            inventory_complete: false,
        })
    }

    /// List durable cuts that advanced admission but have not yet finished
    /// roster materialization. Recovery finalizes these exact epochs before
    /// offering their certificates; it never infers them from current work.
    pub fn unfinished_reference_seal_epochs(
        &self,
        home_id: &str,
    ) -> Result<Vec<i64>, JournalError> {
        required(home_id)?;
        let (bound, _, _) = state(&self.conn)?;
        if bound.as_deref().is_some_and(|bound| bound != home_id) {
            return Err(JournalError::Conflict(
                "reference journal belongs to a different Home",
            ));
        }
        let mut statement = self.conn.prepare_cached(
            "SELECT epoch FROM home_reference_seals \
             WHERE home_id = ?1 AND seal_status = 'pending' ORDER BY epoch",
        )?;
        let epochs = statement
            .query_map([home_id], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(epochs)
    }

    /// Read back and verify a frozen cut. Later admissions do not change its
    /// digest; missing or altered members refuse instead of shrinking it.
    pub fn sealed_reference_epoch(
        &self,
        epoch: i64,
    ) -> Result<Option<ReferenceSeal>, JournalError> {
        let Some(seal) = seal_metadata(&self.conn, epoch)? else {
            return Ok(None);
        };
        validate_seal_frontier(&self.conn, epoch, &seal.home_id)?;
        if seal.seal_status != "final" {
            return Err(JournalError::Conflict(
                "reference seal has not finished materializing",
            ));
        }
        let operations = match seal.roster_scope.as_str() {
            "epoch" => completed_in_epoch(&self.conn, epoch)?,
            "through_epoch" => completed_through_epoch(&self.conn, epoch)?,
            _ => {
                return Err(JournalError::Conflict(
                    "unknown reference seal roster scope",
                ))
            }
        };
        if i64::try_from(operations.len()).ok() != Some(seal.operation_count)
            || digest(&operations)? != seal.roster_digest
        {
            return Err(JournalError::Conflict(
                "sealed reference roster differs from its durable cut",
            ));
        }
        Ok(Some(ReferenceSeal {
            home_id: seal.home_id,
            epoch,
            registry_basis: seal.registry_basis,
            policy_basis: seal.policy_basis,
            structural_basis: seal.structural_basis,
            roster_digest: seal.roster_digest,
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

    pub fn reference_use_pin(
        &self,
        home_id: &str,
        target_store: &str,
        use_key: &str,
    ) -> Result<Option<ReferenceUsePin>, JournalError> {
        use_pin(&self.conn, home_id, target_store, use_key)
    }

    /// Preserve a pre-journal item's unresolved lineage without inventing an
    /// accepting operation. It remains unusable until its lifecycle is chosen
    /// explicitly; an exact retry cannot silently upgrade this classification.
    pub fn classify_legacy_reference_use_unknown(
        &mut self,
        home_id: &str,
        target_store: &str,
        use_key: &str,
        version_id: &str,
    ) -> Result<ReferenceUsePin, JournalError> {
        for value in [home_id, target_store, use_key, version_id] {
            required(value)?;
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let epoch = bind_home(&tx, home_id)?;
        if let Some(existing) = use_pin(&tx, home_id, target_store, use_key)? {
            if existing.version_id != version_id
                || existing.classification != ReferenceUseClassification::LegacyUnknown
            {
                return Err(JournalError::Conflict(
                    "legacy reference use already has a different immutable pin",
                ));
            }
            tx.commit()?;
            return Ok(existing);
        }
        tx.execute(
            "INSERT INTO home_reference_use_pins \
             (home_id, target_store, use_key, version_id, classification, bound_epoch) \
             VALUES (?1, ?2, ?3, ?4, 'legacy_unknown', ?5)",
            params![home_id, target_store, use_key, version_id, epoch],
        )?;
        let pinned = use_pin(&tx, home_id, target_store, use_key)?.ok_or(
            JournalError::Conflict("legacy reference use pin disappeared"),
        )?;
        tx.commit()?;
        Ok(pinned)
    }

    /// Recover the one Home operation already used by this retained version.
    /// A version row alone is insufficient: separate checked imports may have
    /// produced the same version. Never choose one by ordering or by a target
    /// store's local roster.
    pub fn exact_reference_origin_for_version(
        &self,
        home_id: &str,
        target_store: &str,
        version_id: &str,
    ) -> Result<Option<String>, JournalError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT DISTINCT operation_id FROM home_reference_use_pins \
             WHERE home_id = ?1 AND target_store = ?2 AND version_id = ?3 \
               AND classification = 'exact' ORDER BY operation_id LIMIT 2",
        )?;
        let ids = stmt
            .query_map(params![home_id, target_store, version_id], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() > 1 {
            return Err(JournalError::Conflict(
                "retained version has multiple Home admission origins",
            ));
        }
        let Some(id) = ids.into_iter().next() else {
            return Ok(None);
        };
        let origin = operation(&self.conn, &id)?.ok_or(JournalError::Conflict(
            "retained version Home admission origin disappeared",
        ))?;
        if origin.home_id != home_id
            || origin.target_store != target_store
            || origin.completed_epoch.is_none()
            || origin.refusal.is_some()
        {
            return Err(JournalError::Conflict(
                "retained version Home admission origin is not completed",
            ));
        }
        Ok(Some(id))
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

    fn exact_use_evidence(_: &ReferenceOperation) -> Result<ReferenceUseEvidence, String> {
        Ok(ReferenceUseEvidence {
            version_id: "version:one".into(),
            evidence_ref: "operation:one".into(),
            witness_digest: "witness:one".into(),
        })
    }

    #[test]
    fn checked_program_request_recovers_one_operation_and_refuses_changed_meaning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("home.db");
        let path = path.to_str().unwrap();
        let mut store = Store::open(path).unwrap();
        let first = store
            .register_checked_program_request(
                "home:one",
                "gates/project:one/runtime.sqlite",
                "item:one:first-admission",
                "source+lock+compiler+policy:one",
            )
            .unwrap();
        assert!(first.operation_id.starts_with("imp_"));
        assert_eq!(first.operation_id.len(), 36);
        assert_eq!(first.registered_epoch, 0);
        drop(store);

        let mut reopened = Store::open(path).unwrap();
        let retry = reopened
            .register_checked_program_request(
                "home:one",
                "gates/project:one/runtime.sqlite",
                "item:one:first-admission",
                "source+lock+compiler+policy:one",
            )
            .unwrap();
        assert_eq!(retry, first);
        assert!(matches!(
            reopened.register_checked_program_request(
                "home:one",
                "gates/project:one/runtime.sqlite",
                "item:one:first-admission",
                "source+lock+compiler+policy:two",
            ),
            Err(JournalError::Conflict(_))
        ));
        let other = reopened
            .register_checked_program_request(
                "home:one",
                "gates/project:one/runtime.sqlite",
                "item:two:first-admission",
                "source+lock+compiler+policy:one",
            )
            .unwrap();
        assert_ne!(other.operation_id, first.operation_id);
        assert_eq!(
            reopened.reference_operation(&first.operation_id).unwrap(),
            Some(first)
        );
    }

    #[test]
    fn exact_item_pin_requires_completed_target_and_survives_seal_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("home.db");
        let path = path.to_str().unwrap();
        let mut store = Store::open(path).unwrap();
        store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        assert!(store
            .bind_exact_reference_use(
                "home:one",
                "chats/one.sqlite",
                "item:one",
                "version:one",
                "one",
                |_| panic!("a pending Home pointer cannot verify a use"),
            )
            .is_err());
        store
            .complete_reference_operation("home:one", "one", evidence)
            .unwrap();
        let pinned = store
            .bind_exact_reference_use(
                "home:one",
                "chats/one.sqlite",
                "item:one",
                "version:one",
                "one",
                exact_use_evidence,
            )
            .unwrap();
        assert_eq!(pinned.classification, ReferenceUseClassification::Exact);
        assert_eq!(pinned.operation_id.as_deref(), Some("one"));
        assert_eq!(pinned.bound_epoch, 0);
        assert_eq!(
            store
                .reference_use_pin("home:one", "chats/one.sqlite", "item:one")
                .unwrap(),
            Some(pinned.clone()),
        );
        store
            .seal_reference_epoch("home:one", "registry:1", "policy:1", "tree:1")
            .unwrap();
        drop(store);
        let mut reopened = Store::open(path).unwrap();
        assert_eq!(
            reopened
                .bind_exact_reference_use(
                    "home:one",
                    "chats/one.sqlite",
                    "item:one",
                    "version:one",
                    "one",
                    exact_use_evidence,
                )
                .unwrap(),
            pinned,
        );
        assert!(reopened
            .bind_exact_reference_use(
                "home:one",
                "chats/one.sqlite",
                "item:one",
                "version:changed",
                "one",
                exact_use_evidence,
            )
            .is_err());
    }

    #[test]
    fn competing_or_corrupt_item_pins_cannot_switch_target_operations() {
        let mut store = Store::open_in_memory().unwrap();
        for id in ["one", "two"] {
            store
                .register_reference_operation("home:one", &input(id))
                .unwrap();
            store
                .complete_reference_operation("home:one", id, evidence)
                .unwrap();
        }
        store
            .bind_exact_reference_use(
                "home:one",
                "chats/one.sqlite",
                "item:one",
                "version:one",
                "one",
                exact_use_evidence,
            )
            .unwrap();
        assert!(store
            .bind_exact_reference_use(
                "home:one",
                "chats/one.sqlite",
                "item:one",
                "version:one",
                "two",
                exact_use_evidence,
            )
            .is_err());
        assert_eq!(
            store
                .reference_use_pin("home:one", "chats/one.sqlite", "item:one")
                .unwrap()
                .unwrap()
                .operation_id
                .as_deref(),
            Some("one"),
        );
        store
            .conn
            .execute(
                "UPDATE home_reference_use_pins SET operation_id = 'two' \
                 WHERE use_key = 'item:one'",
                [],
            )
            .unwrap();
        assert!(store
            .bind_exact_reference_use(
                "home:one",
                "chats/one.sqlite",
                "item:one",
                "version:one",
                "one",
                exact_use_evidence,
            )
            .is_err());
    }

    #[test]
    fn retained_version_origin_requires_one_exact_home_pin() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(
            store
                .exact_reference_origin_for_version("home:one", "chats/one.sqlite", "version:one")
                .unwrap(),
            None
        );
        for id in ["one", "two"] {
            store
                .register_reference_operation("home:one", &input(id))
                .unwrap();
            store
                .complete_reference_operation("home:one", id, evidence)
                .unwrap();
        }
        store
            .bind_exact_reference_use(
                "home:one",
                "chats/one.sqlite",
                "item:one",
                "version:one",
                "one",
                exact_use_evidence,
            )
            .unwrap();
        assert_eq!(
            store
                .exact_reference_origin_for_version("home:one", "chats/one.sqlite", "version:one")
                .unwrap(),
            Some("one".into())
        );
        store
            .bind_exact_reference_use(
                "home:one",
                "chats/one.sqlite",
                "item:two",
                "version:one",
                "two",
                exact_use_evidence,
            )
            .unwrap();
        assert!(store
            .exact_reference_origin_for_version("home:one", "chats/one.sqlite", "version:one")
            .is_err());
    }

    #[test]
    fn legacy_unknown_is_durable_and_cannot_be_upgraded_by_retry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("home.db");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        let unknown = store
            .classify_legacy_reference_use_unknown(
                "home:one",
                "chats/one.sqlite",
                "old-item",
                "version:one",
            )
            .unwrap();
        assert_eq!(
            unknown.classification,
            ReferenceUseClassification::LegacyUnknown
        );
        drop(store);
        let mut reopened = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            reopened
                .classify_legacy_reference_use_unknown(
                    "home:one",
                    "chats/one.sqlite",
                    "old-item",
                    "version:one",
                )
                .unwrap(),
            unknown
        );
        reopened
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        reopened
            .complete_reference_operation("home:one", "one", evidence)
            .unwrap();
        assert!(reopened
            .bind_exact_reference_use(
                "home:one",
                "chats/one.sqlite",
                "old-item",
                "version:one",
                "one",
                exact_use_evidence,
            )
            .is_err());
    }

    #[test]
    fn a_legacy_unknown_pin_cannot_become_an_exact_pin_by_retry() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        store
            .complete_reference_operation("home:one", "one", evidence)
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO home_reference_use_pins \
                 (home_id, target_store, use_key, version_id, classification, bound_epoch) \
                 VALUES ('home:one', 'chats/one.sqlite', 'old-item', 'old-version', \
                         'legacy_unknown', 0)",
                [],
            )
            .unwrap();
        let legacy = store
            .reference_use_pin("home:one", "chats/one.sqlite", "old-item")
            .unwrap()
            .unwrap();
        assert_eq!(
            legacy.classification,
            ReferenceUseClassification::LegacyUnknown
        );
        assert!(legacy.operation_id.is_none());
        assert!(store
            .bind_exact_reference_use(
                "home:one",
                "chats/one.sqlite",
                "old-item",
                "version:one",
                "one",
                exact_use_evidence,
            )
            .is_err());
        assert!(
            !store
                .seal_reference_epoch("home:one", "registry:1", "policy:1", "tree:1")
                .unwrap()
                .inventory_complete
        );
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
    fn unfinished_seal_survives_restart_and_excludes_later_admissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("home.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        store
            .register_reference_operation("home:one", &input("one"))
            .unwrap();
        store
            .complete_reference_operation("home:one", "one", evidence)
            .unwrap();
        store
            .register_reference_operation("home:one", &input("pending"))
            .unwrap();
        assert!(store
            .conn
            .execute(
                "UPDATE home_reference_operations SET witness_digest = 'changed' \
                 WHERE operation_id = 'one'",
                [],
            )
            .is_err());
        assert!(store
            .conn
            .execute(
                "INSERT OR REPLACE INTO home_reference_operations \
                 (operation_id, home_id, target_store, kind, basis_digest, \
                  registered_epoch, status) \
                 VALUES ('one', 'home:one', 'other', 'other', 'other', 0, 'pending')",
                [],
            )
            .is_err());

        // Crash immediately after the short frontier transaction commits.
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "INSERT INTO home_reference_seals \
             (epoch, home_id, registry_basis, policy_basis, structural_basis, \
              roster_digest, operation_count, roster_scope, seal_status) \
             VALUES (0, 'home:one', 'registry:1', 'policy:1', 'tree:1', \
                     '', 0, 'through_epoch', 'pending')",
            [],
        )
        .unwrap();
        tx.execute(
            "UPDATE home_reference_state SET current_epoch = 1 WHERE id = 1",
            [],
        )
        .unwrap();
        tx.commit().unwrap();
        drop(store);

        let mut reopened = Store::open(path.to_str().unwrap()).unwrap();
        assert!(reopened.sealed_reference_epoch(0).is_err());
        assert_eq!(
            reopened
                .unfinished_reference_seal_epochs("home:one")
                .unwrap(),
            vec![0]
        );
        assert!(reopened
            .conn
            .execute(
                "UPDATE home_reference_operations \
                 SET status = 'completed', completed_epoch = 0, \
                     evidence_ref = 'late', witness_digest = 'late' \
                 WHERE operation_id = 'pending'",
                [],
            )
            .is_err());
        reopened
            .register_reference_operation("home:one", &input("two"))
            .unwrap();
        reopened
            .complete_reference_operation("home:one", "two", evidence)
            .unwrap();
        let recovered = reopened.finalize_reference_seal(0).unwrap();
        assert!(reopened
            .unfinished_reference_seal_epochs("home:one")
            .unwrap()
            .is_empty());
        assert_eq!(recovered.operations.len(), 1);
        assert_eq!(recovered.operations[0].operation_id, "one");
        assert_eq!(reopened.finalize_reference_seal(0).unwrap(), recovered);
        assert_eq!(reopened.sealed_reference_epoch(0).unwrap(), Some(recovered));
        reopened
            .conn
            .execute(
                "UPDATE home_reference_state SET current_epoch = 0 WHERE id = 1",
                [],
            )
            .unwrap();
        assert!(reopened.sealed_reference_epoch(0).is_err());
        reopened
            .conn
            .execute(
                "UPDATE home_reference_state SET current_epoch = 1 WHERE id = 1",
                [],
            )
            .unwrap();
        assert_eq!(
            reopened
                .seal_reference_epoch("home:one", "registry:2", "policy:2", "tree:2")
                .unwrap()
                .operations
                .len(),
            2
        );
    }

    #[test]
    fn later_seal_retains_every_earlier_completed_operation() {
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
        let first = store
            .seal_reference_epoch("home:one", "registry:1", "policy:1", "tree:1")
            .unwrap();
        store
            .register_reference_operation("home:one", &input("two"))
            .unwrap();
        store
            .complete_reference_operation("home:one", "two", evidence)
            .unwrap();
        let second = store
            .seal_reference_epoch("home:one", "registry:2", "policy:2", "tree:2")
            .unwrap();
        let ids: Vec<_> = second
            .operations
            .iter()
            .map(|operation| operation.operation_id.as_str())
            .collect();
        assert_eq!(ids, ["one", "two"]);
        assert_ne!(first.roster_digest, second.roster_digest);
        drop(store);
        let reopened = Store::open(path).unwrap();
        assert_eq!(reopened.sealed_reference_epoch(0).unwrap(), Some(first));
        assert_eq!(reopened.sealed_reference_epoch(1).unwrap(), Some(second));
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
                .complete_reference_operation("home:one", "one", evidence)
                .unwrap(),
            completed
        );
        assert!(matches!(
            store.complete_reference_operation("home:one", "one", |_| {
                Err("target operation or witness is missing".into())
            }),
            Err(JournalError::Verification(_))
        ));
        assert!(matches!(
            store.complete_reference_operation("home:one", "one", |_| {
                Ok(ReferenceEvidence {
                    evidence_ref: "operation:one".into(),
                    witness_digest: "witness:changed".into(),
                })
            }),
            Err(JournalError::Conflict(_))
        ));
        assert_eq!(
            store.reference_operation("one").unwrap(),
            match completed {
                ReferenceCompletion::Completed(operation) => Some(*operation),
                ReferenceCompletion::NeedsRevalidation { .. } => unreachable!(),
            }
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
            "DROP TABLE home_reference_use_pins; \
             DROP TABLE home_reference_refusals; \
             ALTER TABLE home_reference_seals DROP COLUMN roster_scope; \
             DELETE FROM schema_migrations WHERE version IN (4, 5, 6);",
        )
        .unwrap();
        drop(conn);
        let mut upgraded = Store::open(path).unwrap();
        assert_eq!(upgraded.sealed_reference_epoch(0).unwrap(), Some(sealed));
        assert_eq!(
            upgraded.schema_version().unwrap(),
            crate::SUPPORTED_SCHEMA_VERSION
        );
        upgraded
            .register_reference_operation("home:one", &input("two"))
            .unwrap();
        upgraded
            .complete_reference_operation("home:one", "two", evidence)
            .unwrap();
        let next = upgraded
            .seal_reference_epoch("home:one", "registry:2", "policy:2", "tree:2")
            .unwrap();
        let ids: Vec<_> = next
            .operations
            .iter()
            .map(|operation| operation.operation_id.as_str())
            .collect();
        assert_eq!(ids, ["one", "two"]);
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
        assert_eq!(
            store
                .complete_revalidated_reference_operation("home:one", "one", |old, epoch| {
                    assert_eq!(epoch, 1);
                    Ok(RevalidatedReferenceEvidence {
                        evidence: evidence(old)?,
                        current_basis_digest: "source+lock+compiler+policy:two".into(),
                    })
                })
                .unwrap(),
            ReferenceCompletion::Completed(operation.clone()),
        );
        assert!(matches!(
            store.complete_revalidated_reference_operation("home:one", "one", |_, _| {
                Err("target operation or witness is missing".into())
            }),
            Err(JournalError::Verification(_))
        ));
        let next = store
            .seal_reference_epoch("home:one", "registry:2", "policy:2", "tree:2")
            .unwrap();
        assert_eq!(
            store
                .complete_revalidated_reference_operation("home:one", "one", |old, epoch| {
                    assert_eq!(epoch, 2);
                    Ok(RevalidatedReferenceEvidence {
                        evidence: evidence(old)?,
                        current_basis_digest: "source+lock+compiler+policy:changed".into(),
                    })
                })
                .unwrap(),
            ReferenceCompletion::Completed(operation.clone()),
        );
        assert!(matches!(
            store.complete_revalidated_reference_operation("home:one", "one", |old, _| {
                let mut changed = evidence(old)?;
                changed.witness_digest = "witness:changed".into();
                Ok(RevalidatedReferenceEvidence {
                    evidence: changed,
                    current_basis_digest: "source+lock+compiler+policy:changed".into(),
                })
            }),
            Err(JournalError::Conflict(_))
        ));
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
