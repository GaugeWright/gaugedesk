//! The shared record-fact commit, used by ordinary and retained publication.
use super::*;

pub(crate) fn pending_command_matches(
    conn: &rusqlite::Connection,
    command_id: &str,
    scope_id: &str,
    idempotency_key: &str,
    snapshot_json: &str,
) -> Result<bool, AdmitError> {
    Ok(conn
        .prepare_cached(
            "SELECT 1 FROM commands c WHERE c.command_id = ?1 AND c.scope_id = ?2
             AND c.idempotency_key = ?3 AND c.snapshot_json = ?4 AND c.status = 'processing'
             AND NOT EXISTS (SELECT 1 FROM command_receipts r
               WHERE r.scope_id = c.scope_id AND r.command_key = c.idempotency_key)",
        )?
        .query_row(
            params![command_id, scope_id, idempotency_key, snapshot_json],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(crate) fn validate_snapshot(
    command_scope: &str,
    idempotency_key: &str,
    id: Option<String>,
    snapshot: Option<String>,
) -> Result<String, AdmitError> {
    let expected = format!(
        "record-command:{}:{command_scope}{idempotency_key}",
        command_scope.len()
    );
    if id.as_deref() != Some(expected.as_str()) {
        return Err(AdmitError::Rejected(Rejection {
            reason: "record receipt has no matching original command",
        }));
    }
    snapshot.ok_or(AdmitError::Rejected(Rejection {
        reason: "record receipt has no matching original command",
    }))
}

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

#[allow(clippy::too_many_arguments)] // The final process check accompanies the held publication transaction.
pub(crate) fn commit(
    tx: rusqlite::Transaction<'_>,
    codec: Option<Arc<dyn ContentCodec>>,
    command_scope: &str,
    idempotency_key: &str,
    snapshot_json: &str,
    stored: Vec<CommandRecordFact>,
    chained: Option<ChainedRecordFact<'_>>,
    claimed_command: Option<&str>,
    final_check: impl FnOnce() -> Result<(), AdmitError>,
) -> Result<MaterializedRecordAdmission, AdmitError> {
    commit_staged(
        tx,
        codec,
        command_scope,
        idempotency_key,
        snapshot_json,
        stored,
        chained,
        claimed_command,
        |_| Ok(Vec::new()),
        final_check,
    )
}

/// Apply lifecycle decisions only after checking the exact pending original
/// command. The shared receipt path skips staging on an already committed retry.
#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_lifecycle<L: Lifecycle>(
    tx: rusqlite::Transaction<'_>,
    codec: Option<Arc<dyn ContentCodec>>,
    command_id: &str,
    command_scope: &str,
    idempotency_key: &str,
    snapshot_json: &str,
    batch: crate::command_dispatch::LifecycleBatch<L>,
    stored: Vec<CommandRecordFact>,
    final_check: impl FnOnce() -> Result<(), AdmitError>,
) -> Result<MaterializedRecordAdmission, AdmitError> {
    if batch.scope.trim().is_empty()
        || batch.commands.is_empty()
        || stored
            .iter()
            .any(|fact| fact.scope_id == batch.scope && fact.kind == L::KIND)
    {
        return Err(AdmitError::Rejected(Rejection {
            reason: "invalid claimed lifecycle batch",
        }));
    }
    commit_staged(
        tx,
        codec,
        command_scope,
        idempotency_key,
        snapshot_json,
        stored,
        None,
        Some(command_id),
        |tx| stage_lifecycle::<L>(tx, batch),
        final_check,
    )
}

#[allow(clippy::too_many_arguments)] // One original claim and two typed batches.
pub(crate) fn commit_lifecycle_pair<L: Lifecycle, M: Lifecycle>(
    tx: rusqlite::Transaction<'_>,
    codec: Option<Arc<dyn ContentCodec>>,
    command_id: &str,
    command_scope: &str,
    key: &str,
    snapshot: &str,
    first: crate::command_dispatch::LifecycleBatch<L>,
    second: crate::command_dispatch::LifecycleBatch<M>,
    facts: impl FnOnce(i64) -> Result<Vec<CommandRecordFact>, AdmitError>,
    final_check: impl FnOnce() -> Result<(), AdmitError>,
) -> Result<MaterializedRecordAdmission, AdmitError> {
    if first.scope.trim().is_empty()
        || first.scope != second.scope
        || first.commands.is_empty()
        || second.commands.is_empty()
        || L::KIND == M::KIND
    {
        return Err(AdmitError::Rejected(Rejection {
            reason: "invalid claimed lifecycle pair",
        }));
    }
    let phase_codec = codec.clone();
    commit_staged(
        tx,
        codec,
        command_scope,
        key,
        snapshot,
        Vec::new(),
        None,
        Some(command_id),
        |tx| {
            let scope = first.scope.clone();
            let mut positions = stage_lifecycle::<L>(tx, first)?;
            positions.extend(stage_lifecycle::<M>(tx, second)?);
            let next = tx
                .prepare_cached(
                    "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id=?1",
                )?
                .query_row(params![scope], |row| row.get::<_, i64>(0))?;
            let prepared = facts(next)?;
            if prepared
                .iter()
                .any(|fact| fact.scope_id != scope || fact.kind == L::KIND || fact.kind == M::KIND)
            {
                return Err(AdmitError::Rejected(Rejection {
                    reason: "lifecycle pair facts cross scope or inject typed events",
                }));
            }
            let stored = encode_facts(phase_codec.as_ref(), &prepared)?;
            positions.extend(append_facts(tx, &stored)?);
            Ok(positions)
        },
        final_check,
    )
}

pub(crate) fn stage_lifecycle<L: Lifecycle>(
    tx: &rusqlite::Transaction<'_>,
    batch: crate::command_dispatch::LifecycleBatch<L>,
) -> Result<Vec<i64>, AdmitError> {
    let mut state = L::State::default();
    let mut statement = tx.prepare_cached(
        "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 ORDER BY position",
    )?;
    for row in statement.query_map(params![batch.scope, L::KIND], |row| row.get::<_, String>(0))? {
        state = L::evolve(&state, serde_json::from_str(&row?)?);
    }
    let mut position: i64 = tx
        .prepare_cached("SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1")?
        .query_row(params![batch.scope], |row| row.get(0))?;
    let mut positions = Vec::new();
    for command in batch.commands {
        let events = L::decide(&state, command).map_err(AdmitError::Rejected)?;
        for event in events {
            tx.prepare_cached(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![
                batch.scope,
                position,
                L::KIND,
                serde_json::to_string(&event)?
            ])?;
            state = L::evolve(&state, event);
            positions.push(position);
            position += 1;
        }
    }
    Ok(positions)
}

pub(crate) fn append_facts(
    tx: &rusqlite::Transaction<'_>,
    stored: &[CommandRecordFact],
) -> Result<Vec<i64>, AdmitError> {
    let mut positions = Vec::with_capacity(stored.len());
    for fact in stored {
        let position: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            )?
            .query_row(params![fact.scope_id], |row| row.get(0))?;
        tx.prepare_cached(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
        )?
        .execute(params![fact.scope_id, position, fact.kind, fact.payload])?;
        positions.push(position);
    }
    Ok(positions)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_staged(
    tx: rusqlite::Transaction<'_>,
    codec: Option<Arc<dyn ContentCodec>>,
    command_scope: &str,
    idempotency_key: &str,
    snapshot_json: &str,
    stored: Vec<CommandRecordFact>,
    chained: Option<ChainedRecordFact<'_>>,
    claimed_command: Option<&str>,
    stage: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<Vec<i64>, AdmitError>,
    final_check: impl FnOnce() -> Result<(), AdmitError>,
) -> Result<MaterializedRecordAdmission, AdmitError> {
    let command_id = claimed_command.map(str::to_owned).unwrap_or_else(|| {
        format!(
            "record-command:{}:{command_scope}{idempotency_key}",
            command_scope.len()
        )
    });
    if claimed_command.is_none() {
        tx.prepare_cached(
            "INSERT OR IGNORE INTO commands
             (command_id, scope_id, idempotency_key, status, snapshot_json)
             VALUES (?1, ?2, ?3, 'received', ?4)",
        )?
        .execute(params![
            command_id,
            command_scope,
            idempotency_key,
            snapshot_json
        ])?;
    }
    let record = tx
        .prepare_cached(
            "SELECT command_id, scope_id, idempotency_key, status, snapshot_json
                 FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2",
        )?
        .query_row(
            params![command_scope, idempotency_key],
            command_record_from_row,
        )
        .optional()?
        .ok_or_else(|| AdmitError::Db(rusqlite::Error::QueryReturnedNoRows))?;
    if record.command_id != command_id {
        return Err(AdmitError::Rejected(Rejection {
            reason: "record receipt has no matching original command",
        }));
    }
    if record.snapshot_json != snapshot_json {
        return Err(AdmitError::Rejected(Rejection {
            reason: "idempotency key reused with different command",
        }));
    }
    if tx
        .prepare_cached("SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2")?
        .query_row(params![command_scope, idempotency_key], |_| Ok(()))
        .optional()?
        .is_some()
    {
        tx.prepare_cached(
            "UPDATE commands SET status = 'applied', updated_at = CURRENT_TIMESTAMP
                 WHERE command_id = ?1",
        )?
        .execute(params![record.command_id])?;
        final_check()?;
        tx.commit()?;
        return Ok(MaterializedRecordAdmission {
            positions: Vec::new(),
            replayed: true,
            chained_payload: None,
        });
    }
    let expected_status = if claimed_command.is_some() {
        "processing"
    } else {
        "received"
    };
    if record.status != expected_status {
        let reason = match record.status.as_str() {
            "processing" => "command is already processing",
            "rejected" => "command already rejected; submit with a new key",
            "expired" => "idempotency key expired; submit with a new key",
            "applied" => "applied command is missing its durable receipt",
            _ => "command could not be claimed",
        };
        return Err(AdmitError::Rejected(Rejection { reason }));
    }
    tx.prepare_cached(
        "UPDATE commands SET status = 'processing', updated_at = CURRENT_TIMESTAMP
             WHERE command_id = ?1 AND status = 'received'",
    )?
    .execute(params![record.command_id])?;

    let mut positions = stage(&tx)?;
    positions.extend(append_facts(&tx, &stored)?);
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
        let position: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            )?
            .query_row(params![chained.scope_id], |row| row.get(0))?;
        tx.prepare_cached(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
        )?
        .execute(params![chained.scope_id, position, chained.kind, encoded])?;
        positions.push(position);
        chained_payload = Some(payload);
    }
    let applied_at = positions.first().copied().unwrap_or(0);
    tx.prepare_cached(
        "INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)",
    )?
    .execute(params![command_scope, idempotency_key, applied_at])?;
    tx.prepare_cached(
        "UPDATE commands SET status = 'applied', updated_at = CURRENT_TIMESTAMP
             WHERE command_id = ?1",
    )?
    .execute(params![record.command_id])?;
    final_check()?;
    tx.commit()?;
    Ok(MaterializedRecordAdmission {
        positions,
        replayed: false,
        chained_payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::command_dispatch::LifecycleBatch;
    use gaugedesk_core::run::{RunCommand, RunPhase, RunState};

    fn completion(commands: Vec<RunCommand>) -> LifecycleBatch<RunState> {
        LifecycleBatch {
            scope: "chat".into(),
            commands,
        }
    }
    fn running(store: &mut Store) {
        for command in [
            RunCommand::RequestRun,
            RunCommand::AdmitRun,
            RunCommand::StartRun,
        ] {
            store.admit::<RunState>("chat", command).unwrap();
        }
    }
    fn result_fact() -> Vec<CommandRecordFact> {
        vec![CommandRecordFact {
            scope_id: "chat".into(),
            kind: "workspace_result".into(),
            payload: "original-retained-cut".into(),
        }]
    }
    fn pending(store: &mut Store) {
        running(store);
        store
            .claim_command("original", "task", "key", "original-input")
            .unwrap();
    }
    fn unchanged_pending(store: &Store, events: &[(i64, String, String)]) {
        assert_eq!(store.retained_events("chat").unwrap(), events);
        assert_eq!(
            store.fold::<RunState>("chat").unwrap().phase,
            RunPhase::Running
        );
        assert_eq!(
            store.command("original").unwrap().unwrap().status,
            "processing"
        );
        assert!(store
            .conn
            .query_row(
                "SELECT 1 FROM command_receipts WHERE scope_id='task' AND command_key='key'",
                [],
                |_| Ok(())
            )
            .optional()
            .unwrap()
            .is_none());
    }

    #[test]
    fn claimed_pair_assigns_result_positions_under_writer_and_replays_without_builder() {
        use gaugedesk_core::merge::{MergeCommand, MergePhase, MergeState};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("product.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        pending(&mut store);
        let basis = store
            .read_for_dispatch(&["chat", "authority"], |_| Ok(()))
            .unwrap()
            .1;
        let result = store
            .with_dispatch_record_admission(&basis, |writer| {
                writer.commit_claimed_lifecycle_pair(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    completion(vec![RunCommand::RecordObservation, RunCommand::CompleteRun]),
                    crate::command_dispatch::LifecycleBatch::<MergeState> {
                        scope: "chat".into(),
                        commands: vec![MergeCommand::StartMerge, MergeCommand::WorkspaceClean],
                    },
                    |next| {
                        assert_eq!(next, 7);
                        Ok(vec![
                            CommandRecordFact {
                                scope_id: "chat".into(),
                                kind: "transcript".into(),
                                payload: "original answer".into(),
                            },
                            CommandRecordFact {
                                scope_id: "chat".into(),
                                kind: "boundary".into(),
                                payload: next.to_string(),
                            },
                        ])
                    },
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(result.positions, [3, 4, 5, 6, 7, 8]);
        assert_eq!(
            store.fold::<RunState>("chat").unwrap().phase,
            RunPhase::Completed
        );
        assert_eq!(
            store.fold::<MergeState>("chat").unwrap().phase,
            MergePhase::Clean
        );
        assert_eq!(store.records("chat", "boundary").unwrap(), ["7"]);
        assert_eq!(
            store
                .retained_events("chat")
                .unwrap()
                .iter()
                .find(|r| r.0 == 7)
                .unwrap()
                .2,
            "original answer"
        );
        drop(store);
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        let before = store.retained_events("chat").unwrap();
        let basis = store
            .read_for_dispatch(&["chat", "authority"], |_| Ok(()))
            .unwrap()
            .1;
        let replay = store
            .with_dispatch_record_admission(&basis, |writer| {
                writer.commit_claimed_lifecycle_pair(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    completion(vec![RunCommand::CompleteRun]),
                    crate::command_dispatch::LifecycleBatch::<MergeState> {
                        scope: "chat".into(),
                        commands: vec![MergeCommand::StartMerge],
                    },
                    |_| panic!("committed result must not rebuild later position references"),
                )
            })
            .unwrap()
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(store.retained_events("chat").unwrap(), before);
    }

    #[test]
    fn claimed_pair_rolls_back_both_lifecycles_facts_and_receipt_at_each_failure() {
        use gaugedesk_core::merge::{MergeCommand, MergePhase, MergeState};
        use std::sync::atomic::{AtomicBool, Ordering};
        for failure in [
            "second-decision",
            "builder",
            "injected-run",
            "injected-merge",
            "other-scope",
            "final-authority",
        ] {
            let mut store = Store::open_in_memory().unwrap();
            pending(&mut store);
            let before = store.retained_events("chat").unwrap();
            let current = Arc::new(AtomicBool::new(true));
            let observed = current.clone();
            let basis = store
                .read_for_dispatch(&["chat", "authority"], |_| Ok(()))
                .unwrap()
                .1
                .with_process_guard(move || observed.load(Ordering::Acquire));
            let result = store
                .with_dispatch_record_admission(&basis, |writer| {
                    writer.commit_claimed_lifecycle_pair(
                        "original",
                        "task",
                        "key",
                        "original-input",
                        completion(vec![RunCommand::CompleteRun]),
                        crate::command_dispatch::LifecycleBatch::<MergeState> {
                            scope: "chat".into(),
                            commands: if failure == "second-decision" {
                                vec![MergeCommand::WorkspaceClean]
                            } else {
                                vec![MergeCommand::StartMerge, MergeCommand::WorkspaceClean]
                            },
                        },
                        |next| {
                            if failure == "builder" {
                                return Err(AdmitError::Rejected(Rejection {
                                    reason: "result unavailable",
                                }));
                            }
                            if failure == "final-authority" {
                                current.store(false, Ordering::Release);
                            }
                            Ok(vec![CommandRecordFact {
                                scope_id: if failure == "other-scope" {
                                    "other"
                                } else {
                                    "chat"
                                }
                                .into(),
                                kind: match failure {
                                    "injected-run" => <RunState as gaugedesk_core::Lifecycle>::KIND,
                                    "injected-merge" => {
                                        <MergeState as gaugedesk_core::Lifecycle>::KIND
                                    }
                                    _ => "boundary",
                                }
                                .into(),
                                payload: next.to_string(),
                            }])
                        },
                    )
                })
                .unwrap();
            assert!(result.is_err(), "{failure}");
            unchanged_pending(&store, &before);
            assert_eq!(
                store.fold::<MergeState>("chat").unwrap().phase,
                MergePhase::Idle
            );
            assert!(store.retained_events("other").unwrap().is_empty());
        }
    }

    #[test]
    fn claimed_lifecycle_completion_and_result_share_original_receipt_after_reopen() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        pending(&mut store);
        let (_, basis) = store
            .read_for_dispatch(&["authority", "chat"], |_| Ok(()))
            .unwrap();
        let result = store
            .with_dispatch_record_admission(&basis, |writer| {
                writer.commit_claimed_lifecycle(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    completion(vec![RunCommand::RecordObservation, RunCommand::CompleteRun]),
                    &result_fact(),
                )
            })
            .unwrap()
            .unwrap();
        assert!(!result.replayed);
        assert_eq!(result.positions, vec![3, 4, 5]);
        assert_eq!(
            store.fold::<RunState>("chat").unwrap().phase,
            RunPhase::Completed
        );
        assert_eq!(
            store.records("chat", "workspace_result").unwrap(),
            vec!["original-retained-cut"]
        );
        assert_eq!(
            store.command("original").unwrap().unwrap().status,
            "applied"
        );
        drop(store);
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        for command in [
            RunCommand::RetryRun,
            RunCommand::AdmitRun,
            RunCommand::StartRun,
        ] {
            store.admit::<RunState>("chat", command).unwrap();
        }
        let before = store.retained_events("chat").unwrap();
        let (_, basis) = store
            .read_for_dispatch(&["authority", "chat"], |_| Ok(()))
            .unwrap();
        let replay = store
            .with_dispatch_record_admission(&basis, |writer| {
                writer.commit_claimed_lifecycle(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    completion(vec![RunCommand::CompleteRun]),
                    &result_fact(),
                )
            })
            .unwrap()
            .unwrap();
        assert!(replay.replayed);
        assert!(replay.positions.is_empty());
        assert_eq!(store.retained_events("chat").unwrap(), before);
        assert_eq!(
            store.fold::<RunState>("chat").unwrap().phase,
            RunPhase::Running
        );
    }

    #[test]
    fn claimed_lifecycle_late_rejection_rolls_back_prior_decisions_and_result() {
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        let before = store.retained_events("chat").unwrap();
        assert!(store
            .with_record_admission(|writer| {
                writer.commit_claimed_lifecycle(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    completion(vec![
                        RunCommand::RecordObservation,
                        RunCommand::CompleteRun,
                        RunCommand::StartRun,
                    ]),
                    &result_fact(),
                )
            })
            .unwrap()
            .is_err());
        unchanged_pending(&store, &before);
    }

    #[test]
    fn claimed_lifecycle_requires_exact_original_and_typed_events() {
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        let before = store.retained_events("chat").unwrap();
        for (id, snapshot) in [
            ("substituted", "original-input"),
            ("original", "substituted-input"),
        ] {
            assert!(store
                .with_record_admission(|writer| {
                    writer.commit_claimed_lifecycle(
                        id,
                        "task",
                        "key",
                        snapshot,
                        completion(vec![RunCommand::CompleteRun]),
                        &result_fact(),
                    )
                })
                .unwrap()
                .is_err());
            unchanged_pending(&store, &before);
        }
        let injected = vec![CommandRecordFact {
            scope_id: "chat".into(),
            kind: "run".into(),
            payload: "\"RunCompleted\"".into(),
        }];
        assert!(store
            .with_record_admission(|writer| {
                writer.commit_claimed_lifecycle(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    completion(vec![RunCommand::CompleteRun]),
                    &injected,
                )
            })
            .unwrap()
            .is_err());
        unchanged_pending(&store, &before);
    }

    #[test]
    fn claimed_lifecycle_receipt_failure_rolls_back_completion_and_result() {
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        let before = store.retained_events("chat").unwrap();
        store.conn.execute_batch("CREATE TRIGGER refuse_completion_receipt BEFORE INSERT ON command_receipts BEGIN SELECT RAISE(ABORT, 'receipt unavailable'); END;").unwrap();
        assert!(store
            .with_record_admission(|writer| {
                writer.commit_claimed_lifecycle(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    completion(vec![RunCommand::CompleteRun]),
                    &result_fact(),
                )
            })
            .unwrap()
            .is_err());
        unchanged_pending(&store, &before);
    }

    #[test]
    fn claimed_lifecycle_public_writer_rechecks_original_authority_at_final_commit() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        let before = store.retained_events("chat").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let captured = calls.clone();
        let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
        // Fault injection: standing survives writer entry and method entry,
        // then ends at the final commit after decisions, facts and receipt.
        let basis = basis.with_process_guard(move || captured.fetch_add(1, Ordering::SeqCst) < 2);
        assert!(store
            .with_dispatch_record_admission(&basis, |writer| {
                writer.commit_claimed_lifecycle(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    completion(vec![RunCommand::RecordObservation, RunCommand::CompleteRun]),
                    &result_fact(),
                )
            })
            .unwrap()
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        unchanged_pending(&store, &before);
    }

    #[test]
    fn claimed_lifecycle_final_authority_failure_rolls_back_staged_result_and_receipt() {
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        let before = store.retained_events("chat").unwrap();
        let mut final_called = false;
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(commit_lifecycle(
            tx,
            None,
            "original",
            "task",
            "key",
            "original-input",
            completion(vec![RunCommand::RecordObservation, RunCommand::CompleteRun]),
            result_fact(),
            || {
                final_called = true;
                Err(AdmitError::Rejected(Rejection {
                    reason: "original authority ended at commit",
                }))
            }
        )
        .is_err());
        assert!(final_called);
        unchanged_pending(&store, &before);
    }

    #[test]
    fn response_failure_cannot_rewrite_committed_original_receipt() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .claim_command("original", "upload", "key", "input")
            .unwrap();
        store
            .with_record_admission(|writer| {
                writer.commit_claimed("original", "upload", "key", "input", &[])
            })
            .unwrap()
            .unwrap();
        assert!(!store
            .set_unreceipted_command_failure("original", "rejected")
            .unwrap());
        assert!(!store
            .set_unreceipted_command_failure("original", "expired")
            .unwrap());
        assert_eq!(
            store.command("original").unwrap().unwrap().status,
            "applied"
        );
        // Recovery can observe a status lagging its receipt. Receipt presence
        // still prevents a failure response from inventing a rejection.
        store.set_command_status("original", "processing").unwrap();
        assert!(!store
            .set_unreceipted_command_failure("original", "rejected")
            .unwrap());
        assert_eq!(
            store.command("original").unwrap().unwrap().status,
            "processing"
        );
        store
            .claim_command("unfinished", "other", "key", "input")
            .unwrap();
        assert!(store
            .set_unreceipted_command_failure("unfinished", "expired")
            .unwrap());
        assert_eq!(
            store.command("unfinished").unwrap().unwrap().status,
            "expired"
        );
        assert!(!store
            .set_unreceipted_command_failure("unfinished", "rejected")
            .unwrap());
        assert!(store
            .set_unreceipted_command_failure("original", "applied")
            .is_err());
    }

    #[test]
    fn claimed_publication_requires_exact_claim_and_rolls_back_late_receipt_failure() {
        let mut store = Store::open_in_memory().unwrap();
        let facts = vec![
            CommandRecordFact {
                scope_id: "chat".into(),
                kind: "resource".into(),
                payload: "metadata".into(),
            },
            CommandRecordFact {
                scope_id: "access".into(),
                kind: "access".into(),
                payload: "grant".into(),
            },
        ];
        store
            .claim_command("original", "upload", "key", "exact-input")
            .unwrap();
        for (id, snapshot) in [
            ("substituted", "exact-input"),
            ("original", "different-input"),
        ] {
            assert!(store
                .with_record_admission(
                    |writer| writer.commit_claimed(id, "upload", "key", snapshot, &facts)
                )
                .unwrap()
                .is_err());
        }
        store.set_command_status("original", "rejected").unwrap();
        assert!(store
            .with_record_admission(|writer| writer.commit_claimed(
                "original",
                "upload",
                "key",
                "exact-input",
                &facts
            ))
            .unwrap()
            .is_err());
        store.set_command_status("original", "processing").unwrap();
        // Refuse after both fact inserts, at durable receipt publication.
        store.conn.execute_batch("CREATE TRIGGER refuse_upload_receipt BEFORE INSERT ON command_receipts BEGIN SELECT RAISE(ABORT, 'receipt unavailable'); END;").unwrap();
        assert!(store
            .with_record_admission(|writer| writer.commit_claimed(
                "original",
                "upload",
                "key",
                "exact-input",
                &facts
            ))
            .unwrap()
            .is_err());
        assert!(store.records("chat", "resource").unwrap().is_empty());
        assert!(store.records("access", "access").unwrap().is_empty());
        assert_eq!(
            store
                .command_for_key("upload", "key")
                .unwrap()
                .unwrap()
                .status,
            "processing"
        );
        store
            .conn
            .execute_batch("DROP TRIGGER refuse_upload_receipt")
            .unwrap();
        let publication = store
            .with_record_admission(|writer| {
                writer.commit_claimed("original", "upload", "key", "exact-input", &facts)
            })
            .unwrap()
            .unwrap();
        assert!(!publication.replayed);
        assert_eq!(publication.positions.len(), 2);
        assert_eq!(
            store
                .command_for_key("upload", "key")
                .unwrap()
                .unwrap()
                .command_id,
            "original"
        );
        assert_eq!(
            store
                .command_for_key("upload", "key")
                .unwrap()
                .unwrap()
                .status,
            "applied"
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT COUNT(*) FROM commands", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let replay = store
            .with_record_admission(|writer| {
                writer.commit_claimed("original", "upload", "key", "exact-input", &facts)
            })
            .unwrap()
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(store.records("chat", "resource").unwrap().len(), 1);
    }

    #[test]
    fn final_record_refusal_rolls_back_the_whole_batch_and_receipt_repair() {
        let mut store = Store::open_in_memory().unwrap();
        let facts = vec![
            CommandRecordFact {
                scope_id: "resource".into(),
                kind: "resource".into(),
                payload: "metadata".into(),
            },
            CommandRecordFact {
                scope_id: "binding".into(),
                kind: "binding".into(),
                payload: "exact file".into(),
            },
        ];
        let refuse = || {
            Err(AdmitError::Rejected(Rejection {
                reason: "final standing ended",
            }))
        };
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(commit(
            tx,
            None,
            "publication",
            "key",
            "snapshot",
            facts.clone(),
            None,
            None,
            refuse
        )
        .is_err());
        assert!(store.records("resource", "resource").unwrap().is_empty());
        assert!(store.records("binding", "binding").unwrap().is_empty());
        assert!(store
            .command_for_key("publication", "key")
            .unwrap()
            .is_none());
        assert!(store
            .committed_record_snapshot("publication", "key")
            .unwrap()
            .is_none());
        store
            .with_record_admission(|writer| writer.commit("publication", "key", "snapshot", &facts))
            .unwrap()
            .unwrap();
        let original = store
            .command_for_key("publication", "key")
            .unwrap()
            .unwrap();
        store
            .set_command_status(&original.command_id, "processing")
            .unwrap();
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(commit(
            tx,
            None,
            "publication",
            "key",
            "snapshot",
            facts,
            None,
            None,
            refuse
        )
        .is_err());
        assert_eq!(
            store
                .command_for_key("publication", "key")
                .unwrap()
                .unwrap()
                .status,
            "processing"
        );
        assert_eq!(
            store.records("resource", "resource").unwrap(),
            vec!["metadata"]
        );
        assert_eq!(
            store.records("binding", "binding").unwrap(),
            vec!["exact file"]
        );
    }
}
