//! The shared record-fact commit, used by ordinary and retained publication.
use super::*;

pub(crate) fn encode_facts(
    codec: Option<&Arc<dyn ContentCodec>>,
    facts: &[CommandRecordFact],
) -> Result<Vec<CommandRecordFact>, AdmitError> {
    facts
        .iter()
        .map(|fact| {
            let payload = match codec {
                Some(codec) => codec
                    .encode(&fact.scope_id, &fact.kind, &fact.payload)
                    .map_err(AdmitError::Codec)?,
                None => fact.payload.clone(),
            };
            Ok(CommandRecordFact {
                scope_id: fact.scope_id.clone(),
                kind: fact.kind.clone(),
                payload,
            })
        })
        .collect()
}

pub(crate) fn commit(
    tx: rusqlite::Transaction<'_>,
    codec: Option<Arc<dyn ContentCodec>>,
    command_scope: &str,
    idempotency_key: &str,
    snapshot_json: &str,
    stored: Vec<CommandRecordFact>,
    chained: Option<ChainedRecordFact<'_>>,
) -> Result<MaterializedRecordAdmission, AdmitError> {
    let command_id = format!(
        "record-command:{}:{command_scope}{idempotency_key}",
        command_scope.len()
    );
    tx.execute(
        "INSERT OR IGNORE INTO commands
             (command_id, scope_id, idempotency_key, status, snapshot_json)
             VALUES (?1, ?2, ?3, 'received', ?4)",
        params![command_id, command_scope, idempotency_key, snapshot_json],
    )?;
    let record = tx
        .query_row(
            "SELECT command_id, scope_id, idempotency_key, status, snapshot_json
                 FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2",
            params![command_scope, idempotency_key],
            command_record_from_row,
        )
        .optional()?
        .ok_or_else(|| AdmitError::Db(rusqlite::Error::QueryReturnedNoRows))?;
    if record.snapshot_json != snapshot_json {
        return Err(AdmitError::Rejected(Rejection {
            reason: "idempotency key reused with different command",
        }));
    }
    if tx
        .query_row(
            "SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
            params![command_scope, idempotency_key],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        tx.execute(
            "UPDATE commands SET status = 'applied', updated_at = CURRENT_TIMESTAMP
                 WHERE command_id = ?1",
            params![record.command_id],
        )?;
        tx.commit()?;
        return Ok(MaterializedRecordAdmission {
            positions: Vec::new(),
            replayed: true,
            chained_payload: None,
        });
    }
    if record.status != "received" {
        let reason = match record.status.as_str() {
            "processing" => "command is already processing",
            "rejected" => "command already rejected; submit with a new key",
            "expired" => "idempotency key expired; submit with a new key",
            "applied" => "applied command is missing its durable receipt",
            _ => "command could not be claimed",
        };
        return Err(AdmitError::Rejected(Rejection { reason }));
    }
    tx.execute(
        "UPDATE commands SET status = 'processing', updated_at = CURRENT_TIMESTAMP
             WHERE command_id = ?1 AND status = 'received'",
        params![record.command_id],
    )?;

    let mut positions = Vec::with_capacity(stored.len());
    for fact in stored {
        let position: i64 = tx.query_row(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            params![fact.scope_id],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            params![fact.scope_id, position, fact.kind, fact.payload],
        )?;
        positions.push(position);
    }
    // Resolve the chain link against the head visible to *this* transaction and
    // append it here. Reading the head outside the transaction would let two
    // concurrent governed actions link to the same predecessor and fork the
    // chain — the defect this method exists to make unrepresentable.
    let mut chained_payload = None;
    if let Some(chained) = chained {
        let previous = tx_chain_head(&tx, codec.as_ref(), chained.scope_id, chained.kind)?;
        let payload = (chained.link)(previous.as_deref());
        let encoded = match &codec {
            Some(codec) => codec
                .encode(chained.scope_id, chained.kind, &payload)
                .map_err(AdmitError::Codec)?,
            None => payload.clone(),
        };
        let position: i64 = tx.query_row(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            params![chained.scope_id],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            params![chained.scope_id, position, chained.kind, encoded],
        )?;
        positions.push(position);
        chained_payload = Some(payload);
    }
    let applied_at = positions.first().copied().unwrap_or(0);
    tx.execute(
        "INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)",
        params![command_scope, idempotency_key, applied_at],
    )?;
    tx.execute(
        "UPDATE commands SET status = 'applied', updated_at = CURRENT_TIMESTAMP
             WHERE command_id = ?1",
        params![record.command_id],
    )?;
    tx.commit()?;
    Ok(MaterializedRecordAdmission {
        positions,
        replayed: false,
        chained_payload,
    })
}
