//! A receipted phase subordinate to an exact pending original command.
//! It keeps the parent pending and conveys no authority for subsequent work.
use crate::command_dispatch::{LifecycleBatch, MaterializedCommandPrefix};
use crate::{AdmitError, CommandRecordFact, ContentCodec};
use gaugedesk_core::{Lifecycle, Rejection};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const KIND: &str = "command_prefix_result_v1";
const KEY: &str = "prefix";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefixResult {
    revision: String,
    meaning_sha256: String,
    events: Vec<PrefixEvent>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefixEvent {
    scope: String,
    position: i64,
    kind: String,
    sha256: String,
    encoded: bool,
}

fn refused() -> AdmitError {
    AdmitError::Rejected(Rejection {
        reason: "command prefix has no exact retained pending parent or original phase",
    })
}
fn digest(body: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(body.as_ref()))
}
pub(crate) fn prefix_scope(command_id: &str, phase: &str) -> String {
    format!("command-prefix:{}:{command_id}{phase}", command_id.len())
}

/// Presence is an observation only. Publication still verifies exact original
/// phase meaning and its retained rows under the pending command writer.
pub(crate) fn recorded(
    store: &crate::Store,
    command_id: &str,
    phase: &str,
) -> Result<bool, AdmitError> {
    if command_id.trim().is_empty() || phase.trim().is_empty() {
        return Err(refused());
    }
    let scope = prefix_scope(command_id, phase);
    let markers: i64 = store.conn.query_row(
        "SELECT COUNT(*) FROM events WHERE scope_id=?1 AND kind=?2",
        params![scope, KIND],
        |row| row.get(0),
    )?;
    let receipts: i64 = store.conn.query_row(
        "SELECT COUNT(*) FROM command_receipts WHERE scope_id=?1 AND command_key=?2",
        params![scope, KEY],
        |row| row.get(0),
    )?;
    match (markers, receipts) {
        (0, 0) => Ok(false),
        (1, 1) => Ok(true),
        _ => Err(refused()),
    }
}

/// Shared immutable phase inspection. No repair or lifecycle staging occurs.
#[allow(clippy::too_many_arguments)] // One original parent and exact phase meaning.
fn inspect_pending<L: Lifecycle>(
    tx: &Transaction<'_>,
    codec: Option<&Arc<dyn ContentCodec>>,
    command_id: &str,
    command_scope: &str,
    key: &str,
    snapshot: &str,
    phase: &str,
    batch: &LifecycleBatch<L>,
    facts: &[CommandRecordFact],
) -> Result<(String, String, Option<Vec<i64>>), AdmitError>
where
    L::Command: Serialize,
{
    // The parent stays pending, including on a phase replay. Status alone is
    // insufficient: a lagging projection cannot revive a receipted parent.
    if !crate::record_admission::pending_command_matches(
        tx,
        command_id,
        command_scope,
        key,
        snapshot,
    )? {
        return Err(refused());
    }
    inspect_phase(
        tx,
        codec,
        command_id,
        command_scope,
        key,
        snapshot,
        phase,
        batch,
        facts,
    )
}

// Called only after the caller has verified the corresponding pending or
// recorded parent under this same transaction. Never stages or repairs rows.
#[allow(clippy::too_many_arguments)]
fn inspect_phase<L: Lifecycle>(
    tx: &Transaction<'_>,
    codec: Option<&Arc<dyn ContentCodec>>,
    command_id: &str,
    command_scope: &str,
    key: &str,
    snapshot: &str,
    phase: &str,
    batch: &LifecycleBatch<L>,
    facts: &[CommandRecordFact],
) -> Result<(String, String, Option<Vec<i64>>), AdmitError>
where
    L::Command: Serialize,
{
    let scope = prefix_scope(command_id, phase);
    if phase.trim().is_empty()
        || batch.scope.trim().is_empty()
        || batch.scope == scope
        || (batch.commands.is_empty() && facts.is_empty())
        || facts.iter().any(|fact| {
            fact.scope_id == scope || (fact.scope_id == batch.scope && fact.kind == L::KIND)
        })
    {
        return Err(refused());
    }
    let raw_facts: Vec<_> = facts
        .iter()
        .map(|f| (&f.scope_id, &f.kind, &f.payload))
        .collect();
    let meaning = digest(serde_json::to_vec(&(
        "claimed-lifecycle-prefix/v1",
        command_id,
        command_scope,
        key,
        snapshot,
        phase,
        &batch.scope,
        L::KIND,
        &batch.commands,
        raw_facts,
    ))?);
    let has_receipt = tx
        .prepare_cached("SELECT 1 FROM command_receipts WHERE scope_id=?1 AND command_key=?2")?
        .query_row(params![scope, KEY], |_| Ok(()))
        .optional()?
        .is_some();
    let mut statement = tx.prepare_cached(
        "SELECT payload FROM events WHERE scope_id=?1 AND kind=?2 ORDER BY position",
    )?;
    let markers = statement
        .query_map(params![scope, KIND], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    // Never reconstruct an incomplete original phase from current state.
    if markers.len() != usize::from(has_receipt) {
        return Err(refused());
    }
    let phase_command: Option<(String, String)> = tx
        .prepare_cached("SELECT command_id, snapshot_json FROM commands WHERE scope_id=?1 AND idempotency_key=?2")?
        .query_row(params![scope, KEY], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    let expected_command = format!("record-command:{}:{scope}{KEY}", scope.len());
    match (has_receipt, phase_command) {
        (true, Some((id, snapshot))) if id == expected_command && snapshot == meaning => {}
        (false, None) => {}
        _ => return Err(refused()),
    }
    let recovered = if let Some(marker) = markers.first() {
        let body = decode(codec, &scope, KIND, marker)?;
        let result: PrefixResult = serde_json::from_str(&body)?;
        if result.revision != "claimed-lifecycle-prefix/v1"
            || result.meaning_sha256 != meaning
            || result.events.len() < facts.len()
        {
            return Err(refused());
        }
        let typed_count = result.events.len() - facts.len();
        if batch.commands.is_empty() && typed_count != 0 {
            return Err(refused());
        }
        for event in &result.events[..typed_count] {
            if event.scope != batch.scope || event.kind != L::KIND || event.encoded {
                return Err(refused());
            }
        }
        for (event, fact) in result.events[typed_count..].iter().zip(facts) {
            if event.scope != fact.scope_id
                || event.kind != fact.kind
                || event.sha256 != digest(&fact.payload)
                || !event.encoded
            {
                return Err(refused());
            }
        }
        let mut positions = Vec::with_capacity(result.events.len());
        for event in result.events {
            let row: Option<(String, String)> = tx
                .prepare_cached(
                    "SELECT kind, payload FROM events WHERE scope_id=?1 AND position=?2",
                )?
                .query_row(params![event.scope, event.position], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let (kind, body) = row.ok_or_else(refused)?;
            let body = if event.encoded {
                decode(codec, &event.scope, &kind, &body)?
            } else {
                body
            };
            if kind != event.kind || digest(body) != event.sha256 {
                return Err(refused());
            }
            positions.push(event.position);
        }
        Some(positions)
    } else {
        None
    };
    Ok((scope, meaning, recovered))
}

#[allow(clippy::too_many_arguments)] // Borrow the same held original writer and phase.
pub(crate) fn verify<L: Lifecycle>(
    tx: &Transaction<'_>,
    codec: Option<&Arc<dyn ContentCodec>>,
    command_id: &str,
    command_scope: &str,
    key: &str,
    snapshot: &str,
    phase: &str,
    batch: &LifecycleBatch<L>,
    facts: &[CommandRecordFact],
) -> Result<Vec<i64>, AdmitError>
where
    L::Command: Serialize,
{
    let (_, _, recovered) = inspect_pending(
        tx,
        codec,
        command_id,
        command_scope,
        key,
        snapshot,
        phase,
        batch,
        facts,
    )?;
    recovered.ok_or_else(refused)
}

/// Historical phase evidence under an independently admitted current reader.
/// The exact recorded pair is reverified here, never accepted as a cached grant.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_recorded<P: Lifecycle, L: Lifecycle, M: Lifecycle>(
    tx: &Transaction<'_>,
    codec: Option<&Arc<dyn ContentCodec>>,
    command_id: &str,
    command_scope: &str,
    key: &str,
    snapshot: &str,
    phase: &str,
    batch: &LifecycleBatch<P>,
    facts: &[CommandRecordFact],
) -> Result<Vec<i64>, AdmitError>
where
    P::Command: Serialize,
{
    let original = crate::record_admission_pair::verify::<L, M>(
        tx,
        codec,
        command_id,
        command_scope,
        key,
        snapshot,
        &batch.scope,
    )?;
    let first_result = original.positions().first().ok_or_else(refused)?;
    if facts.iter().any(|fact| fact.scope_id != batch.scope) {
        return Err(refused());
    }
    let (_, _, recovered) = inspect_phase(
        tx,
        codec,
        command_id,
        command_scope,
        key,
        snapshot,
        phase,
        batch,
        facts,
    )?;
    let positions = recovered.ok_or_else(refused)?;
    if positions.is_empty()
        || positions
            .iter()
            .any(|position| position < &0 || position >= first_result)
        || positions.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(refused());
    }
    Ok(positions)
}

#[allow(clippy::too_many_arguments)] // Exact original parent, named phase and typed intent.
pub(crate) fn commit<L: Lifecycle>(
    tx: Transaction<'_>,
    codec: Option<Arc<dyn ContentCodec>>,
    command_id: &str,
    command_scope: &str,
    key: &str,
    snapshot: &str,
    phase: &str,
    batch: LifecycleBatch<L>,
    facts: &[CommandRecordFact],
    final_check: impl FnOnce() -> Result<(), AdmitError>,
) -> Result<MaterializedCommandPrefix, AdmitError>
where
    L::Command: Serialize,
{
    let (scope, meaning, recovered) = inspect_pending(
        &tx,
        codec.as_ref(),
        command_id,
        command_scope,
        key,
        snapshot,
        phase,
        &batch,
        facts,
    )?;
    let stored = crate::record_admission::encode_facts(codec.as_ref(), facts)?;
    let phase_scope = scope.clone();
    let phase_meaning = meaning.clone();
    let phase_codec = codec.clone();
    let result = crate::record_admission::commit_staged(
        tx,
        codec,
        &scope,
        KEY,
        &meaning,
        Vec::new(),
        None,
        None,
        |tx| {
            let target = batch.scope.clone();
            let mut positions = crate::record_admission::stage_lifecycle::<L>(tx, batch)?;
            let mut events = Vec::with_capacity(positions.len() + facts.len());
            for position in &positions {
                let payload: String = tx
                    .prepare_cached("SELECT payload FROM events WHERE scope_id=?1 AND position=?2")?
                    .query_row(params![target, position], |r| r.get(0))?;
                events.push(PrefixEvent {
                    scope: target.clone(),
                    position: *position,
                    kind: L::KIND.into(),
                    sha256: digest(payload),
                    encoded: false,
                });
            }
            let fact_positions = crate::record_admission::append_facts(tx, &stored)?;
            for (position, fact) in fact_positions.iter().zip(facts) {
                events.push(PrefixEvent {
                    scope: fact.scope_id.clone(),
                    position: *position,
                    kind: fact.kind.clone(),
                    sha256: digest(&fact.payload),
                    encoded: true,
                });
            }
            positions.extend(fact_positions);
            let marker = CommandRecordFact {
                scope_id: phase_scope,
                kind: KIND.into(),
                payload: serde_json::to_string(&PrefixResult {
                    revision: "claimed-lifecycle-prefix/v1".into(),
                    meaning_sha256: phase_meaning,
                    events,
                })?,
            };
            let stored_marker =
                crate::record_admission::encode_facts(phase_codec.as_ref(), &[marker])?;
            crate::record_admission::append_facts(tx, &stored_marker)?;
            Ok(positions)
        },
        final_check,
    )?;
    if result.replayed != recovered.is_some() {
        return Err(refused());
    }
    Ok(MaterializedCommandPrefix {
        positions: recovered.unwrap_or(result.positions),
        replayed: result.replayed,
    })
}

fn decode(
    codec: Option<&Arc<dyn ContentCodec>>,
    scope: &str,
    kind: &str,
    body: &str,
) -> Result<String, AdmitError> {
    match codec {
        Some(codec) => codec.decode(scope, kind, body).ok_or_else(refused),
        None => Ok(body.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{command_dispatch::DispatchReadBasis, Store};
    use gaugedesk_core::run::{RunCommand, RunPhase, RunState};

    fn batch() -> LifecycleBatch<RunState> {
        LifecycleBatch {
            scope: "chat".into(),
            commands: vec![
                RunCommand::RequestRun,
                RunCommand::AdmitRun,
                RunCommand::StartRun,
            ],
        }
    }
    fn facts() -> Vec<CommandRecordFact> {
        vec![CommandRecordFact {
            scope_id: "chat".into(),
            kind: "transcript".into(),
            payload: "synthetic original input".into(),
        }]
    }
    fn basis(store: &Store) -> DispatchReadBasis {
        store
            .read_for_dispatch(&["authority"], |_| Ok(()))
            .unwrap()
            .1
    }
    fn pending(store: &mut Store) {
        store
            .claim_command("original", "http-task", "original-key", "original-snapshot")
            .unwrap();
    }
    fn prefix(store: &mut Store) -> Result<MaterializedCommandPrefix, AdmitError> {
        let observed = basis(store);
        store
            .with_dispatch_record_admission(&observed, |writer| {
                writer.commit_claimed_lifecycle_prefix(
                    "original",
                    "http-task",
                    "original-key",
                    "original-snapshot",
                    "startup",
                    batch(),
                    &facts(),
                )
            })
            .unwrap()
    }
    fn assert_pending(store: &Store) {
        assert!(store
            .pending_command_matches("original", "http-task", "original-key", "original-snapshot")
            .unwrap());
        assert!(store
            .committed_record_snapshot("http-task", "original-key")
            .unwrap()
            .is_none());
    }

    #[test]
    fn phase_presence_requires_both_original_marker_and_receipt() {
        for missing in ["marker", "receipt"] {
            let mut store = Store::open_in_memory().unwrap();
            pending(&mut store);
            assert!(!store
                .claimed_lifecycle_prefix_recorded("original", "startup")
                .unwrap());
            prefix(&mut store).unwrap();
            assert!(store
                .claimed_lifecycle_prefix_recorded("original", "startup")
                .unwrap());
            assert_pending(&store);
            let scope = Store::claimed_lifecycle_prefix_scope("original", "startup");
            let sql = if missing == "marker" {
                "DELETE FROM events WHERE scope_id=?1"
            } else {
                "DELETE FROM command_receipts WHERE scope_id=?1"
            };
            store.conn.execute(sql, [&scope]).unwrap();
            assert!(store
                .claimed_lifecycle_prefix_recorded("original", "startup")
                .is_err());
        }
    }

    #[test]
    fn fact_only_phase_preserves_run_and_replays_exact_original_positions() {
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        prefix(&mut store).unwrap();
        let original_run = store.fold::<RunState>("chat").unwrap();
        let mut positions = Vec::new();
        for replay in [false, true] {
            let observed = basis(&store);
            let admitted = store
                .with_dispatch_record_admission(&observed, |writer| {
                    writer.commit_claimed_lifecycle_prefix(
                        "original",
                        "http-task",
                        "original-key",
                        "original-snapshot",
                        "process-declaration",
                        LifecycleBatch::<RunState> {
                            scope: "chat".into(),
                            commands: Vec::new(),
                        },
                        &facts(),
                    )
                })
                .unwrap()
                .unwrap();
            assert_eq!(admitted.replayed, replay);
            assert_eq!(store.fold::<RunState>("chat").unwrap(), original_run);
            assert_pending(&store);
            if replay {
                assert_eq!(admitted.positions, positions);
            }
            positions = admitted.positions;
            assert_eq!(positions.len(), 1);
        }
        let before = store.retained_events("chat").unwrap();
        let observed = basis(&store);
        assert!(store
            .with_dispatch_record_admission(&observed, |writer| {
                writer.commit_claimed_lifecycle_prefix(
                    "original",
                    "http-task",
                    "original-key",
                    "original-snapshot",
                    "empty-phase",
                    LifecycleBatch::<RunState> {
                        scope: "chat".into(),
                        commands: Vec::new(),
                    },
                    &[],
                )
            })
            .unwrap()
            .is_err());
        assert_eq!(store.retained_events("chat").unwrap(), before);
    }

    #[test]
    fn prefix_keeps_parent_pending_and_replays_original_positions_after_reopen_and_later_state() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        pending(&mut store);
        let first = prefix(&mut store).unwrap();
        assert!(!first.replayed);
        assert_eq!(first.positions, [0, 1, 2, 3]);
        assert_eq!(
            store.fold::<RunState>("chat").unwrap().phase,
            RunPhase::Running
        );
        assert_pending(&store);
        drop(store);
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        store
            .admit::<RunState>("chat", RunCommand::CompleteRun)
            .unwrap();
        store
            .admit::<RunState>("chat", RunCommand::RetryRun)
            .unwrap();
        let before = store.retained_events("chat").unwrap();
        let replay = prefix(&mut store).unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.positions, first.positions);
        assert_eq!(store.retained_events("chat").unwrap(), before);
        assert_eq!(
            store.fold::<RunState>("chat").unwrap().phase,
            RunPhase::Requested
        );
        assert_pending(&store);
    }

    #[test]
    fn prefix_refuses_substituted_or_settled_parent_and_changed_phase_meaning() {
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        let before = store.retained_events("chat").unwrap();
        for (id, scope, key, snapshot) in [
            (
                "different",
                "http-task",
                "original-key",
                "original-snapshot",
            ),
            ("original", "different", "original-key", "original-snapshot"),
            ("original", "http-task", "different", "original-snapshot"),
            ("original", "http-task", "original-key", "different"),
        ] {
            assert!(store
                .with_record_admission(|writer| writer.commit_claimed_lifecycle_prefix(
                    id,
                    scope,
                    key,
                    snapshot,
                    "startup",
                    batch(),
                    &facts(),
                ))
                .unwrap()
                .is_err());
            assert_eq!(store.retained_events("chat").unwrap(), before);
        }
        prefix(&mut store).unwrap();
        let before = store.retained_events("chat").unwrap();
        let mut changed = facts();
        changed[0].payload = "changed input".into();
        assert!(store
            .with_record_admission(|writer| writer.commit_claimed_lifecycle_prefix(
                "original",
                "http-task",
                "original-key",
                "original-snapshot",
                "startup",
                batch(),
                &changed,
            ))
            .unwrap()
            .is_err());
        let changed_batch = LifecycleBatch::<RunState> {
            scope: "chat".into(),
            commands: vec![RunCommand::RecordObservation],
        };
        assert!(store
            .with_record_admission(|writer| writer.commit_claimed_lifecycle_prefix(
                "original",
                "http-task",
                "original-key",
                "original-snapshot",
                "startup",
                changed_batch,
                &facts(),
            ))
            .unwrap()
            .is_err());
        assert_eq!(store.retained_events("chat").unwrap(), before);
        for status in ["rejected", "expired", "applied"] {
            store.set_command_status("original", status).unwrap();
            assert!(prefix(&mut store).is_err());
        }
        store.set_command_status("original", "processing").unwrap();
        store
            .with_record_admission(|writer| {
                writer.commit_claimed(
                    "original",
                    "http-task",
                    "original-key",
                    "original-snapshot",
                    &[],
                )
            })
            .unwrap()
            .unwrap();
        // The durable parent receipt wins even when mutable status lags it.
        store.set_command_status("original", "processing").unwrap();
        assert!(prefix(&mut store).is_err());
        assert_eq!(store.retained_events("chat").unwrap(), before);
    }

    #[test]
    fn prefix_receipt_or_final_authority_failure_rolls_back_all_started_state() {
        for late in [false, true] {
            let mut store = Store::open_in_memory().unwrap();
            pending(&mut store);
            if !late {
                store.conn.execute_batch("CREATE TRIGGER refuse_prefix_receipt BEFORE INSERT ON command_receipts BEGIN SELECT RAISE(ABORT, 'receipt unavailable'); END;").unwrap();
            }
            let observed = basis(&store);
            let mut observed_final = false;
            let result = if late {
                let tx = store
                    .conn
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
                commit(
                    tx,
                    None,
                    "original",
                    "http-task",
                    "original-key",
                    "original-snapshot",
                    "startup",
                    batch(),
                    &facts(),
                    || {
                        observed_final = true;
                        Err(refused())
                    },
                )
            } else {
                store
                    .with_dispatch_record_admission(&observed, |writer| {
                        writer.commit_claimed_lifecycle_prefix(
                            "original",
                            "http-task",
                            "original-key",
                            "original-snapshot",
                            "startup",
                            batch(),
                            &facts(),
                        )
                    })
                    .unwrap()
            };
            assert!(result.is_err());
            assert_eq!(observed_final, late);
            assert!(store.retained_events("chat").unwrap().is_empty());
            assert!(store
                .retained_events(&prefix_scope("original", "startup"))
                .unwrap()
                .is_empty());
            assert!(store
                .command_for_key(&prefix_scope("original", "startup"), KEY)
                .unwrap()
                .is_none());
            assert_eq!(
                store.fold::<RunState>("chat").unwrap().phase,
                RunPhase::Init
            );
            assert_pending(&store);
        }
    }

    #[test]
    fn prefix_public_writer_checks_original_clock_after_staging() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        let calls = Arc::new(AtomicUsize::new(0));
        let proof = calls.clone();
        let observed =
            basis(&store).with_process_guard(move || proof.fetch_add(1, Ordering::SeqCst) < 2);
        assert!(store
            .with_dispatch_record_admission(&observed, |writer| writer
                .commit_claimed_lifecycle_prefix(
                    "original",
                    "http-task",
                    "original-key",
                    "original-snapshot",
                    "startup",
                    batch(),
                    &facts(),
                ))
            .unwrap()
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(store.retained_events("chat").unwrap().is_empty());
        assert_pending(&store);
    }

    #[test]
    fn phase_recovery_refuses_missing_or_changed_original_rows_and_injected_lifecycle_facts() {
        for case in [
            "marker",
            "typed",
            "input",
            "changed-marker",
            "changed-input",
        ] {
            let mut store = Store::open_in_memory().unwrap();
            pending(&mut store);
            prefix(&mut store).unwrap();
            match case {
                "marker" => {
                    store
                        .conn
                        .execute(
                            "DELETE FROM events WHERE scope_id=?1",
                            [prefix_scope("original", "startup")],
                        )
                        .unwrap();
                }
                "typed" => {
                    store
                        .conn
                        .execute(
                            "DELETE FROM events WHERE scope_id='chat' AND position=1",
                            [],
                        )
                        .unwrap();
                }
                "input" => {
                    store
                        .conn
                        .execute(
                            "DELETE FROM events WHERE scope_id='chat' AND position=3",
                            [],
                        )
                        .unwrap();
                }
                "changed-marker" => {
                    store
                        .conn
                        .execute(
                            "UPDATE events SET payload='{}' WHERE scope_id=?1",
                            [prefix_scope("original", "startup")],
                        )
                        .unwrap();
                }
                "changed-input" => {
                    store.conn.execute("UPDATE events SET payload='other' WHERE scope_id='chat' AND position=3", []).unwrap();
                }
                _ => unreachable!(),
            }
            let before = store.retained_events("chat").unwrap();
            assert!(prefix(&mut store).is_err(), "{case}");
            assert_eq!(store.retained_events("chat").unwrap(), before, "{case}");
            assert_pending(&store);
        }
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        let injected = vec![CommandRecordFact {
            scope_id: "chat".into(),
            kind: "run".into(),
            payload: "\"RunCompleted\"".into(),
        }];
        assert!(store
            .with_record_admission(|writer| writer.commit_claimed_lifecycle_prefix(
                "original",
                "http-task",
                "original-key",
                "original-snapshot",
                "startup",
                batch(),
                &injected,
            ))
            .unwrap()
            .is_err());
        assert!(store.retained_events("chat").unwrap().is_empty());
    }

    #[test]
    fn pending_intent_refusal_ends_writer_before_native_work_even_when_a_later_claim_matches() {
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        let observed = basis(&store);
        store
            .with_dispatch_record_admission(&observed, |writer| {
                assert!(writer
                    .require_pending_claim(
                        "other",
                        "http-task",
                        "original-key",
                        "original-snapshot"
                    )
                    .is_err());
                assert!(writer
                    .require_pending_claim(
                        "original",
                        "http-task",
                        "original-key",
                        "original-snapshot"
                    )
                    .is_err());
                assert!(writer
                    .with_native_check(|_| panic!("ended original intent reached a native effect"))
                    .is_err());
            })
            .unwrap();
        assert_pending(&store);
        store
            .with_record_admission(|writer| {
                writer.commit_claimed(
                    "original",
                    "http-task",
                    "original-key",
                    "original-snapshot",
                    &[],
                )
            })
            .unwrap()
            .unwrap();
        store.set_command_status("original", "processing").unwrap();
        let observed = basis(&store);
        store
            .with_dispatch_record_admission(&observed, |writer| {
                assert!(writer
                    .require_pending_claim(
                        "original",
                        "http-task",
                        "original-key",
                        "original-snapshot"
                    )
                    .is_err());
                assert!(writer
                    .with_native_check(|_| panic!("receipted parent reached native work"))
                    .is_err());
            })
            .unwrap();
    }

    #[test]
    fn encrypted_prefix_recovery_requires_original_plaintext_not_fresh_ciphertext() {
        struct Codec(std::sync::atomic::AtomicUsize);
        impl ContentCodec for Codec {
            fn encode(&self, _: &str, _: &str, body: &str) -> Result<String, String> {
                Ok(format!(
                    "{}:{body}",
                    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                ))
            }
            fn decode(&self, _: &str, _: &str, body: &str) -> Option<String> {
                body.split_once(':').map(|(_, body)| body.into())
            }
        }
        let mut store = Store::open_in_memory().unwrap();
        store.codec = Some(Arc::new(Codec(std::sync::atomic::AtomicUsize::new(0))));
        pending(&mut store);
        let first = prefix(&mut store).unwrap();
        let replay = prefix(&mut store).unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.positions, first.positions);
        assert_eq!(
            store.records("chat", "transcript").unwrap(),
            ["synthetic original input"]
        );
        assert_pending(&store);
    }
    #[test]
    fn held_phase_verifier_keeps_one_writer_through_multiple_phases_and_completion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held-phases.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        pending(&mut store);
        let startup = prefix(&mut store).unwrap();
        let file_facts = vec![CommandRecordFact {
            scope_id: "chat".into(),
            kind: "file".into(),
            payload: "synthetic saved file".into(),
        }];
        let file_batch = LifecycleBatch::<RunState> {
            scope: "chat".into(),
            commands: vec![],
        };
        let observed = basis(&store);
        let file = store
            .with_dispatch_record_admission(&observed, |writer| {
                writer.commit_claimed_lifecycle_prefix(
                    "original",
                    "http-task",
                    "original-key",
                    "original-snapshot",
                    "file",
                    file_batch,
                    &file_facts,
                )
            })
            .unwrap()
            .unwrap();
        let rival = rusqlite::Connection::open(&path).unwrap();
        rival.busy_timeout(std::time::Duration::ZERO).unwrap();
        let before_events = store.retained_events("chat").unwrap();
        let before_startup = store
            .retained_events(&prefix_scope("original", "startup"))
            .unwrap();
        let before_file = store
            .retained_events(&prefix_scope("original", "file"))
            .unwrap();
        let observed = basis(&store);
        let completed = store.with_dispatch_record_admission(&observed, |writer| {
            assert_eq!(writer.require_claimed_lifecycle_prefix("original", "http-task", "original-key", "original-snapshot", "startup", &batch(), &facts()).unwrap(), startup.positions);
            assert_eq!(writer.require_claimed_lifecycle_prefix("original", "http-task", "original-key", "original-snapshot", "file", &LifecycleBatch::<RunState> { scope: "chat".into(), commands: vec![] }, &file_facts).unwrap(), file.positions);
            assert!(matches!(rival.execute_batch("BEGIN IMMEDIATE"), Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::DatabaseBusy));
            writer.with_native_check(|check| check.check_current()).unwrap().unwrap();
            writer.commit_claimed_lifecycle("original", "http-task", "original-key", "original-snapshot", LifecycleBatch::<RunState> { scope: "chat".into(), commands: vec![RunCommand::CompleteRun] }, &[])
        }).unwrap().unwrap();
        assert!(!completed.replayed);
        assert_eq!(
            store.fold::<RunState>("chat").unwrap().phase,
            RunPhase::Completed
        );
        assert_eq!(
            store
                .retained_events(&prefix_scope("original", "startup"))
                .unwrap(),
            before_startup
        );
        assert_eq!(
            store
                .retained_events(&prefix_scope("original", "file"))
                .unwrap(),
            before_file
        );
        assert_eq!(
            &store.retained_events("chat").unwrap()[..before_events.len()],
            before_events.as_slice()
        );
        assert_eq!(
            store.retained_events("chat").unwrap().len(),
            before_events.len() + 1
        );
    }

    #[test]
    fn held_phase_verifier_refuses_missing_changed_and_orphan_evidence_without_repair() {
        for case in [
            "command",
            "command-id",
            "command-meaning",
            "receipt",
            "marker",
            "event",
            "event-body",
            "duplicate-marker",
            "new-phase",
            "changed-fact",
            "changed-batch",
            "rejected-parent",
            "expired-parent",
            "completed-parent",
        ] {
            let mut store = Store::open_in_memory().unwrap();
            pending(&mut store);
            prefix(&mut store).unwrap();
            let phase_scope = prefix_scope("original", "startup");
            let mut supplied = facts();
            let mut supplied_batch = batch();
            match case {
                "command" => {
                    store
                        .conn
                        .execute("DELETE FROM commands WHERE scope_id=?1", [&phase_scope])
                        .unwrap();
                }
                "command-id" => {
                    store
                        .conn
                        .execute(
                            "UPDATE commands SET command_id='wrong' WHERE scope_id=?1",
                            [&phase_scope],
                        )
                        .unwrap();
                }
                "command-meaning" => {
                    store
                        .conn
                        .execute(
                            "UPDATE commands SET snapshot_json='wrong' WHERE scope_id=?1",
                            [&phase_scope],
                        )
                        .unwrap();
                }
                "receipt" => {
                    store
                        .conn
                        .execute(
                            "DELETE FROM command_receipts WHERE scope_id=?1",
                            [&phase_scope],
                        )
                        .unwrap();
                }
                "marker" => {
                    store
                        .conn
                        .execute("DELETE FROM events WHERE scope_id=?1", [&phase_scope])
                        .unwrap();
                }
                "event" => {
                    store
                        .conn
                        .execute(
                            "DELETE FROM events WHERE scope_id='chat' AND kind='transcript'",
                            [],
                        )
                        .unwrap();
                }
                "event-body" => {
                    store.conn.execute("UPDATE events SET payload='changed' WHERE scope_id='chat' AND kind='transcript'", []).unwrap();
                }
                "duplicate-marker" => {
                    store
                        .append_record(&phase_scope, KIND, "duplicate")
                        .unwrap();
                }
                "changed-fact" => supplied[0].payload = "changed".into(),
                "changed-batch" => supplied_batch.commands.pop().map(|_| ()).unwrap(),
                "rejected-parent" => {
                    store.set_command_status("original", "rejected").unwrap();
                }
                "expired-parent" => {
                    store.set_command_status("original", "expired").unwrap();
                }
                "completed-parent" => {
                    store
                        .with_record_admission(|writer| {
                            writer.commit_claimed(
                                "original",
                                "http-task",
                                "original-key",
                                "original-snapshot",
                                &[],
                            )
                        })
                        .unwrap()
                        .unwrap();
                    store.set_command_status("original", "processing").unwrap();
                }
                _ => {}
            }
            let before = store.retained_events("chat").unwrap();
            let before_phase = store.retained_events(&phase_scope).unwrap();
            let before_command = store.command_for_key(&phase_scope, KEY).unwrap();
            let observed = basis(&store);
            store
                .with_dispatch_record_admission(&observed, |writer| {
                    let phase = if case == "new-phase" {
                        "never-created"
                    } else {
                        "startup"
                    };
                    assert!(
                        writer
                            .require_claimed_lifecycle_prefix(
                                "original",
                                "http-task",
                                "original-key",
                                "original-snapshot",
                                phase,
                                &supplied_batch,
                                &supplied
                            )
                            .is_err(),
                        "{case}"
                    );
                    // A phase failure remains terminal even after a later input would match.
                    assert!(writer
                        .with_native_check(|_| panic!("failed phase revived native work: {case}"))
                        .is_err());
                    assert!(writer
                        .commit_claimed(
                            "original",
                            "http-task",
                            "original-key",
                            "original-snapshot",
                            &[]
                        )
                        .is_err());
                })
                .unwrap();
            assert_eq!(store.retained_events("chat").unwrap(), before, "{case}");
            assert_eq!(
                store.retained_events(&phase_scope).unwrap(),
                before_phase,
                "{case}"
            );
            assert_eq!(
                store.command_for_key(&phase_scope, KEY).unwrap(),
                before_command,
                "{case}"
            );
            if matches!(case, "command" | "command-id" | "command-meaning") {
                assert!(prefix(&mut store).is_err(), "replay must not repair {case}");
                assert_eq!(
                    store.command_for_key(&phase_scope, KEY).unwrap(),
                    before_command
                );
            }
        }
    }

    #[test]
    fn held_phase_verifier_rechecks_current_authority_before_release_and_latches_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Codec {
            live: Arc<AtomicBool>,
            interrupt: Arc<AtomicBool>,
        }
        impl ContentCodec for Codec {
            fn encode(&self, _: &str, _: &str, body: &str) -> Result<String, String> {
                Ok(body.into())
            }
            fn decode(&self, _: &str, kind: &str, body: &str) -> Option<String> {
                if kind == KIND && self.interrupt.load(Ordering::SeqCst) {
                    self.live.store(false, Ordering::SeqCst);
                }
                Some(body.into())
            }
        }
        let live = Arc::new(AtomicBool::new(true));
        let interrupt = Arc::new(AtomicBool::new(false));
        let mut store = Store::open_in_memory().unwrap().with_codec(Arc::new(Codec {
            live: live.clone(),
            interrupt: interrupt.clone(),
        }));
        pending(&mut store);
        prefix(&mut store).unwrap();
        let before = store.retained_events("chat").unwrap();
        let guard = live.clone();
        let observed = basis(&store).with_process_guard(move || guard.load(Ordering::SeqCst));
        interrupt.store(true, Ordering::SeqCst);
        store
            .with_dispatch_record_admission(&observed, |writer| {
                assert!(writer
                    .require_claimed_lifecycle_prefix(
                        "original",
                        "http-task",
                        "original-key",
                        "original-snapshot",
                        "startup",
                        &batch(),
                        &facts()
                    )
                    .is_err());
                assert!(!live.load(Ordering::SeqCst));
                live.store(true, Ordering::SeqCst);
                assert!(writer
                    .with_native_check(|_| panic!("restored access revived failed verifier"))
                    .is_err());
                assert!(writer
                    .commit_claimed(
                        "original",
                        "http-task",
                        "original-key",
                        "original-snapshot",
                        &[]
                    )
                    .is_err());
            })
            .unwrap();
        assert_eq!(store.retained_events("chat").unwrap(), before);
        assert_pending(&store);
    }
    #[test]
    fn held_phase_verifier_decodes_original_content_without_encoding_and_refuses_erasure() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        struct Codec {
            encodes: Arc<AtomicUsize>,
            readable: Arc<AtomicBool>,
        }
        impl ContentCodec for Codec {
            fn encode(&self, _: &str, _: &str, body: &str) -> Result<String, String> {
                Ok(format!(
                    "{}:{body}",
                    self.encodes.fetch_add(1, Ordering::SeqCst)
                ))
            }
            fn decode(&self, _: &str, _: &str, body: &str) -> Option<String> {
                if !self.readable.load(Ordering::SeqCst) {
                    return None;
                }
                body.split_once(':').map(|(_, body)| body.into())
            }
        }
        let encodes = Arc::new(AtomicUsize::new(0));
        let readable = Arc::new(AtomicBool::new(true));
        let mut store = Store::open_in_memory().unwrap().with_codec(Arc::new(Codec {
            encodes: encodes.clone(),
            readable: readable.clone(),
        }));
        pending(&mut store);
        let original = prefix(&mut store).unwrap();
        let before_encodes = encodes.load(Ordering::SeqCst);
        for erased in [false, true] {
            readable.store(!erased, Ordering::SeqCst);
            let observed = basis(&store);
            store
                .with_dispatch_record_admission(&observed, |writer| {
                    let result = writer.require_claimed_lifecycle_prefix(
                        "original",
                        "http-task",
                        "original-key",
                        "original-snapshot",
                        "startup",
                        &batch(),
                        &facts(),
                    );
                    if erased {
                        assert!(result.is_err());
                        readable.store(true, Ordering::SeqCst);
                        assert!(writer
                            .with_native_check(|_| panic!(
                                "restored decoding revived ended phase verifier"
                            ))
                            .is_err());
                    } else {
                        assert_eq!(result.unwrap(), original.positions);
                    }
                })
                .unwrap();
            assert_eq!(encodes.load(Ordering::SeqCst), before_encodes);
        }
        assert_pending(&store);
    }
    fn complete_recorded(store: &mut Store) {
        use gaugedesk_core::merge::{MergeCommand, MergeState};
        let observed = basis(store);
        store
            .with_dispatch_record_admission(&observed, |writer| {
                writer.commit_recorded_claimed_lifecycle_pair(
                    "original",
                    "http-task",
                    "original-key",
                    "original-snapshot",
                    LifecycleBatch::<RunState> {
                        scope: "chat".into(),
                        commands: vec![RunCommand::RecordObservation, RunCommand::CompleteRun],
                    },
                    LifecycleBatch::<MergeState> {
                        scope: "chat".into(),
                        commands: vec![MergeCommand::StartMerge, MergeCommand::WorkspaceClean],
                    },
                    |_| {
                        Ok(vec![CommandRecordFact {
                            scope_id: "chat".into(),
                            kind: "workspace_result".into(),
                            payload: "synthetic original native cut".into(),
                        }])
                    },
                )
            })
            .unwrap()
            .unwrap();
    }
    fn historical(
        writer: &crate::command_dispatch::DispatchRecordAdmission<'_>,
        phase: &str,
        supplied_batch: &LifecycleBatch<RunState>,
        supplied_facts: &[CommandRecordFact],
    ) -> Result<Vec<i64>, AdmitError> {
        use gaugedesk_core::merge::MergeState;
        writer.require_recorded_lifecycle_prefix::<RunState, RunState, MergeState>(
            "original",
            "http-task",
            "original-key",
            "original-snapshot",
            phase,
            supplied_batch,
            supplied_facts,
        )
    }
    #[test]
    fn historical_phases_survive_reopen_later_work_and_status_lag_without_task_revival() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("historical.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        pending(&mut store);
        let startup = prefix(&mut store).unwrap();
        let file_facts = [CommandRecordFact {
            scope_id: "chat".into(),
            kind: "file".into(),
            payload: "synthetic original file".into(),
        }];
        let file_batch = LifecycleBatch::<RunState> {
            scope: "chat".into(),
            commands: vec![],
        };
        let observed = basis(&store);
        let file = store
            .with_dispatch_record_admission(&observed, |writer| {
                writer.commit_claimed_lifecycle_prefix(
                    "original",
                    "http-task",
                    "original-key",
                    "original-snapshot",
                    "file",
                    file_batch,
                    &file_facts,
                )
            })
            .unwrap()
            .unwrap();
        complete_recorded(&mut store);
        drop(store);
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        store
            .admit::<RunState>("chat", RunCommand::RetryRun)
            .unwrap();
        store
            .admit::<RunState>("chat", RunCommand::AdmitRun)
            .unwrap();
        let later = store.fold::<RunState>("chat").unwrap();
        let rival = rusqlite::Connection::open(&path).unwrap();
        rival.busy_timeout(std::time::Duration::ZERO).unwrap();
        for lagging in [false, true] {
            if lagging {
                store.set_command_status("original", "processing").unwrap();
            }
            let before = store.retained_events("chat").unwrap();
            let changes = store.conn.total_changes();
            let observed = basis(&store);
            store.with_dispatch_record_admission(&observed, |writer| {
                assert_eq!(historical(&writer, "startup", &batch(), &facts()).unwrap(), startup.positions);
                assert_eq!(historical(&writer, "file", &LifecycleBatch::<RunState> {
                    scope: "chat".into(), commands: vec![],
                }, &file_facts).unwrap(), file.positions);
                assert!(matches!(rival.execute_batch("BEGIN IMMEDIATE"), Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::DatabaseBusy));
                writer.with_native_check(|check| check.check_current()).unwrap().unwrap();
            }).unwrap();
            assert_eq!(store.conn.total_changes(), changes);
            assert_eq!(store.retained_events("chat").unwrap(), before);
            assert_eq!(store.fold::<RunState>("chat").unwrap(), later);
            assert!(!store
                .pending_command_matches(
                    "original",
                    "http-task",
                    "original-key",
                    "original-snapshot"
                )
                .unwrap());
            let observed = basis(&store);
            store
                .with_dispatch_record_admission(&observed, |writer| {
                    assert!(writer
                        .require_claimed_lifecycle_prefix(
                            "original",
                            "http-task",
                            "original-key",
                            "original-snapshot",
                            "startup",
                            &batch(),
                            &facts(),
                        )
                        .is_err());
                })
                .unwrap();
        }
    }
    #[test]
    fn historical_phase_refusals_never_repair_or_revive_current_reader() {
        for case in [
            "pending",
            "legacy",
            "pair-binding",
            "phase-command",
            "phase-receipt",
            "phase-marker",
            "duplicate-marker",
            "phase-event",
            "changed-event",
            "changed-intent",
            "changed-fact",
            "missing-phase",
            "post-result-row",
            "cross-scope-fact",
        ] {
            let mut store = Store::open_in_memory().unwrap();
            pending(&mut store);
            let mut supplied = facts();
            if case == "cross-scope-fact" {
                supplied[0].scope_id = "other-chat".into();
                let observed = basis(&store);
                store
                    .with_dispatch_record_admission(&observed, |writer| {
                        writer.commit_claimed_lifecycle_prefix(
                            "original",
                            "http-task",
                            "original-key",
                            "original-snapshot",
                            "startup",
                            batch(),
                            &supplied,
                        )
                    })
                    .unwrap()
                    .unwrap();
            } else {
                prefix(&mut store).unwrap();
            }
            if case == "legacy" {
                let observed = basis(&store);
                store
                    .with_dispatch_record_admission(&observed, |writer| {
                        writer.commit_claimed(
                            "original",
                            "http-task",
                            "original-key",
                            "original-snapshot",
                            &[],
                        )
                    })
                    .unwrap()
                    .unwrap();
            } else if case != "pending" {
                complete_recorded(&mut store);
            }
            let scope = prefix_scope("original", "startup");
            let mut supplied_batch = batch();
            match case {
                "pair-binding" => {
                    store
                        .conn
                        .execute("DELETE FROM command_pair_results", [])
                        .unwrap();
                }
                "phase-command" => {
                    store
                        .conn
                        .execute(
                            "UPDATE commands SET snapshot_json='changed' WHERE scope_id=?1",
                            [&scope],
                        )
                        .unwrap();
                }
                "phase-receipt" => {
                    store
                        .conn
                        .execute("DELETE FROM command_receipts WHERE scope_id=?1", [&scope])
                        .unwrap();
                }
                "phase-marker" => {
                    store
                        .conn
                        .execute("DELETE FROM events WHERE scope_id=?1", [&scope])
                        .unwrap();
                }
                "duplicate-marker" => {
                    store.append_record(&scope, KIND, "duplicate").unwrap();
                }
                "phase-event" => {
                    store
                        .conn
                        .execute(
                            "DELETE FROM events WHERE scope_id='chat' AND kind='transcript'",
                            [],
                        )
                        .unwrap();
                }
                "changed-event" => {
                    store.conn.execute("UPDATE events SET payload='changed' WHERE scope_id='chat' AND kind='transcript'", []).unwrap();
                }
                "changed-intent" => {
                    supplied_batch.commands.pop();
                }
                "changed-fact" => {
                    supplied[0].payload = "changed".into();
                }
                "post-result-row" => {
                    // All phase meaning and bytes still match; only the retained
                    // fact position is transplanted to after the result.
                    let position = store
                        .append_record("chat", "transcript", &supplied[0].payload)
                        .unwrap();
                    let body: String = store
                        .conn
                        .query_row(
                            "SELECT payload FROM events WHERE scope_id=?1 AND kind=?2",
                            params![scope, KIND],
                            |r| r.get(0),
                        )
                        .unwrap();
                    let mut marker: PrefixResult = serde_json::from_str(&body).unwrap();
                    marker.events.last_mut().unwrap().position = position;
                    store
                        .conn
                        .execute(
                            "UPDATE events SET payload=?1 WHERE scope_id=?2 AND kind=?3",
                            params![serde_json::to_string(&marker).unwrap(), scope, KIND],
                        )
                        .unwrap();
                }
                _ => {}
            }
            let before = store.retained_events("chat").unwrap();
            let before_phase = store.retained_events(&scope).unwrap();
            let changes = store.conn.total_changes();
            let observed = basis(&store);
            store
                .with_dispatch_record_admission(&observed, |writer| {
                    let phase = if case == "missing-phase" {
                        "missing"
                    } else {
                        "startup"
                    };
                    assert!(
                        historical(&writer, phase, &supplied_batch, &supplied).is_err(),
                        "{case}"
                    );
                    assert!(writer
                        .with_native_check(|_| panic!("revived failed historical read: {case}"))
                        .is_err());
                    assert!(writer
                        .commit_claimed(
                            "original",
                            "http-task",
                            "original-key",
                            "original-snapshot",
                            &[]
                        )
                        .is_err());
                })
                .unwrap();
            assert_eq!(store.conn.total_changes(), changes, "{case}");
            assert_eq!(store.retained_events("chat").unwrap(), before, "{case}");
            assert_eq!(
                store.retained_events(&scope).unwrap(),
                before_phase,
                "{case}"
            );
        }
    }
    #[test]
    fn historical_phase_checks_current_reader_after_decoding_and_never_encodes() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        struct Codec {
            live: Arc<AtomicBool>,
            interrupt: Arc<AtomicBool>,
            readable: Arc<AtomicBool>,
            encodes: Arc<AtomicUsize>,
        }
        impl ContentCodec for Codec {
            fn encode(&self, _: &str, _: &str, body: &str) -> Result<String, String> {
                self.encodes.fetch_add(1, Ordering::SeqCst);
                Ok(body.into())
            }
            fn decode(&self, _: &str, kind: &str, body: &str) -> Option<String> {
                if kind == KIND {
                    if self.interrupt.load(Ordering::SeqCst) {
                        self.live.store(false, Ordering::SeqCst);
                    }
                    if !self.readable.load(Ordering::SeqCst) {
                        return None;
                    }
                }
                Some(body.into())
            }
        }
        for erasure in [false, true] {
            let live = Arc::new(AtomicBool::new(true));
            let interrupt = Arc::new(AtomicBool::new(false));
            let readable = Arc::new(AtomicBool::new(true));
            let encodes = Arc::new(AtomicUsize::new(0));
            let mut store = Store::open_in_memory().unwrap().with_codec(Arc::new(Codec {
                live: live.clone(),
                interrupt: interrupt.clone(),
                readable: readable.clone(),
                encodes: encodes.clone(),
            }));
            pending(&mut store);
            prefix(&mut store).unwrap();
            complete_recorded(&mut store);
            let count = encodes.load(Ordering::SeqCst);
            let observed = basis(&store);
            store
                .with_dispatch_record_admission(&observed, |writer| {
                    assert!(historical(&writer, "startup", &batch(), &facts()).is_ok());
                })
                .unwrap();
            let guard = live.clone();
            let observed = basis(&store).with_process_guard(move || guard.load(Ordering::SeqCst));
            if erasure {
                readable.store(false, Ordering::SeqCst);
            } else {
                interrupt.store(true, Ordering::SeqCst);
            }
            let before = store.retained_events("chat").unwrap();
            let changes = store.conn.total_changes();
            store
                .with_dispatch_record_admission(&observed, |writer| {
                    assert!(historical(&writer, "startup", &batch(), &facts()).is_err());
                    live.store(true, Ordering::SeqCst);
                    readable.store(true, Ordering::SeqCst);
                    interrupt.store(false, Ordering::SeqCst);
                    assert!(writer
                        .with_native_check(|_| panic!("restored access revived ended reader"))
                        .is_err());
                    assert!(writer
                        .commit_claimed(
                            "original",
                            "http-task",
                            "original-key",
                            "original-snapshot",
                            &[]
                        )
                        .is_err());
                })
                .unwrap();
            assert_eq!(store.conn.total_changes(), changes);
            assert_eq!(store.retained_events("chat").unwrap(), before);
            assert_eq!(encodes.load(Ordering::SeqCst), count);
        }
    }
}
