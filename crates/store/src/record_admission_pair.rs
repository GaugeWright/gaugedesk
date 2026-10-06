//! Immutable paired publication provenance; never pending execution authority.
use crate::command_dispatch::LifecycleBatch;
use crate::{AdmitError, CommandRecordFact, ContentCodec, MaterializedRecordAdmission};
use gaugedesk_core::{Lifecycle, Rejection};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const KIND: &str = "command_pair_result_v1";
const REVISION: &str = "claimed-lifecycle-pair-result/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    revision: String,
    command: String,
    command_scope: String,
    key: String,
    snapshot_digest: String,
    result_scope: String,
    first_kind: String,
    second_kind: String,
    intent_digest: String,
    rows: Vec<Row>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    position: i64,
    class: String,
    kind: String,
    digest: String,
}

/// Verified original typed events and facts, carrying no current permission.
/// Constructible only by the owner's read-only verifier under a held writer.
pub struct RecordedLifecyclePair<L: Lifecycle, M: Lifecycle> {
    first: Vec<L::Event>,
    second: Vec<M::Event>,
    facts: Vec<CommandRecordFact>,
    positions: Vec<i64>,
    intent_digest: String,
}
impl<L: Lifecycle, M: Lifecycle> RecordedLifecyclePair<L, M> {
    pub fn first_events(&self) -> &[L::Event] {
        &self.first
    }
    pub fn second_events(&self) -> &[M::Event] {
        &self.second
    }
    pub fn facts(&self) -> &[CommandRecordFact] {
        &self.facts
    }
    pub fn positions(&self) -> &[i64] {
        &self.positions
    }
    pub fn intent_digest(&self) -> &str {
        &self.intent_digest
    }
}
fn refused() -> AdmitError {
    AdmitError::Rejected(Rejection {
        reason: "recorded pair has no exact retained committed origin",
    })
}
fn digest(body: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(body.as_ref()))
}
fn decode(
    codec: Option<&Arc<dyn ContentCodec>>,
    scope: &str,
    kind: &str,
    raw: &str,
) -> Result<String, AdmitError> {
    match codec {
        Some(codec) => codec.decode(scope, kind, raw).ok_or_else(refused),
        None => Ok(raw.into()),
    }
}
fn intent<L: Lifecycle, M: Lifecycle>(
    first: &LifecycleBatch<L>,
    second: &LifecycleBatch<M>,
) -> Result<String, AdmitError>
where
    L::Command: Serialize,
    M::Command: Serialize,
{
    Ok(digest(serde_json::to_vec(&(
        REVISION,
        &first.scope,
        L::KIND,
        &first.commands,
        M::KIND,
        &second.commands,
    ))?))
}

#[allow(clippy::too_many_arguments)] // Complete original parent and exact result scope.
pub(crate) fn verify<L: Lifecycle, M: Lifecycle>(
    tx: &Transaction<'_>,
    codec: Option<&Arc<dyn ContentCodec>>,
    command: &str,
    command_scope: &str,
    key: &str,
    snapshot: &str,
    result_scope: &str,
) -> Result<RecordedLifecyclePair<L, M>, AdmitError> {
    if [command, command_scope, key, result_scope]
        .iter()
        .any(|s| s.trim().is_empty())
        || L::KIND == M::KIND
    {
        return Err(refused());
    }
    let receipt: Option<(String, String, String, i64)> = tx.query_row(
        "SELECT c.command_id,c.snapshot_json,c.status,r.applied_at FROM commands c JOIN command_receipts r ON r.scope_id=c.scope_id AND r.command_key=c.idempotency_key WHERE c.scope_id=?1 AND c.idempotency_key=?2",
        params![command_scope,key], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).optional()?;
    let Some((id, retained_snapshot, status, applied_at)) = receipt else {
        return Err(refused());
    };
    if id != command
        || retained_snapshot != snapshot
        || !matches!(status.as_str(), "applied" | "processing")
    {
        return Err(refused());
    }
    let mut stmt = tx.prepare_cached(
        "SELECT position,payload FROM events WHERE scope_id=?1 AND kind=?2 ORDER BY position",
    )?;
    let markers = stmt
        .query_map(params![result_scope, KIND], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut selected = Vec::new();
    for (position, raw) in markers {
        let body = decode(codec, result_scope, KIND, &raw)?;
        let marker: Marker = serde_json::from_str(&body)?;
        if marker.command == command {
            selected.push((position, marker, body));
        }
    }
    let [(marker_position, marker, marker_body)] = selected.as_slice() else {
        return Err(refused());
    };
    if marker.revision != REVISION
        || marker.command_scope != command_scope
        || marker.key != key
        || marker.snapshot_digest != digest(snapshot)
        || marker.result_scope != result_scope
        || marker.first_kind != L::KIND
        || marker.second_kind != M::KIND
        || marker.intent_digest.len() != 64
        || !marker
            .intent_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || marker.rows.first().is_none_or(|r| r.position != applied_at)
    {
        return Err(refused());
    }
    let binding: Option<(String,String,String,i64,String)> = tx.query_row(
        "SELECT command_scope,command_key,result_scope,marker_position,marker_sha256 FROM command_pair_results WHERE command_id=?1",
        [command], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    if binding
        != Some((
            command_scope.into(),
            key.into(),
            result_scope.into(),
            *marker_position,
            digest(marker_body),
        ))
    {
        return Err(refused());
    }
    let mut first = Vec::new();
    let mut second = Vec::new();
    let mut facts = Vec::new();
    let mut positions = Vec::new();
    let mut stage = 0;
    for row in &marker.rows {
        if row.position < 0
            || row.position >= *marker_position
            || positions
                .last()
                .is_some_and(|last| row.position != last + 1)
        {
            return Err(refused());
        }
        let retained: Option<(String, String)> = tx
            .query_row(
                "SELECT kind,payload FROM events WHERE scope_id=?1 AND position=?2",
                params![result_scope, row.position],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (kind, raw) = retained.ok_or_else(refused)?;
        if kind != row.kind {
            return Err(refused());
        }
        let body = if row.class == "fact" {
            decode(codec, result_scope, &kind, &raw)?
        } else {
            raw
        };
        if digest(&body) != row.digest {
            return Err(refused());
        }
        match row.class.as_str() {
            "first" if stage == 0 && kind == L::KIND => first.push(serde_json::from_str(&body)?),
            "second" if stage <= 1 && kind == M::KIND => {
                stage = 1;
                second.push(serde_json::from_str(&body)?);
            }
            "fact" if stage >= 1 && kind != L::KIND && kind != M::KIND && kind != KIND => {
                stage = 2;
                facts.push(CommandRecordFact {
                    scope_id: result_scope.into(),
                    kind,
                    payload: body,
                });
            }
            _ => return Err(refused()),
        }
        positions.push(row.position);
    }
    if first.is_empty()
        || second.is_empty()
        || positions.last().is_none_or(|p| p + 1 != *marker_position)
    {
        return Err(refused());
    }
    Ok(RecordedLifecyclePair {
        first,
        second,
        facts,
        positions,
        intent_digest: marker.intent_digest.clone(),
    })
}

#[allow(clippy::too_many_arguments)] // One original claim, two typed intents and retained publication.
pub(crate) fn commit<L: Lifecycle, M: Lifecycle>(
    tx: Transaction<'_>,
    codec: Option<Arc<dyn ContentCodec>>,
    command: &str,
    command_scope: &str,
    key: &str,
    snapshot: &str,
    first: LifecycleBatch<L>,
    second: LifecycleBatch<M>,
    facts: impl FnOnce(i64) -> Result<Vec<CommandRecordFact>, AdmitError>,
    final_check: impl FnOnce() -> Result<(), AdmitError>,
) -> Result<MaterializedRecordAdmission, AdmitError>
where
    L::Command: Serialize,
    M::Command: Serialize,
{
    if first.scope.trim().is_empty()
        || first.scope != second.scope
        || first.commands.is_empty()
        || second.commands.is_empty()
        || L::KIND == M::KIND
    {
        return Err(refused());
    }
    let meaning = intent(&first, &second)?;
    let has_receipt = tx
        .query_row(
            "SELECT 1 FROM command_receipts WHERE scope_id=?1 AND command_key=?2",
            params![command_scope, key],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if has_receipt {
        let original = verify::<L, M>(
            &tx,
            codec.as_ref(),
            command,
            command_scope,
            key,
            snapshot,
            &first.scope,
        )?;
        if original.intent_digest != meaning {
            return Err(refused());
        }
    }
    if !has_receipt {
        let mut statement =
            tx.prepare_cached("SELECT payload FROM events WHERE scope_id=?1 AND kind=?2")?;
        let raw = statement
            .query_map(params![first.scope, KIND], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for raw in raw {
            let marker: Marker =
                serde_json::from_str(&decode(codec.as_ref(), &first.scope, KIND, &raw)?)?;
            if marker.command == command {
                return Err(refused());
            }
        }
    }
    let scope = first.scope.clone();
    let phase_codec = codec.clone();
    crate::record_admission::commit_staged(
        tx,
        codec,
        command_scope,
        key,
        snapshot,
        Vec::new(),
        None,
        Some(command),
        |tx| {
            let first_positions = crate::record_admission::stage_lifecycle::<L>(tx, first)?;
            let second_positions = crate::record_admission::stage_lifecycle::<M>(tx, second)?;
            if first_positions.is_empty() || second_positions.is_empty() {
                return Err(refused());
            }
            let mut positions = first_positions.clone();
            positions.extend(&second_positions);
            let next: i64 = tx.query_row(
                "SELECT COALESCE(MAX(position),-1)+1 FROM events WHERE scope_id=?1",
                [&scope],
                |r| r.get(0),
            )?;
            let prepared = facts(next)?;
            if prepared.iter().any(|f| {
                f.scope_id != scope || f.kind == L::KIND || f.kind == M::KIND || f.kind == KIND
            }) {
                return Err(refused());
            }
            let stored = crate::record_admission::encode_facts(phase_codec.as_ref(), &prepared)?;
            let fact_positions = crate::record_admission::append_facts(tx, &stored)?;
            let mut rows = Vec::new();
            for (class, typed_positions) in
                [("first", &first_positions), ("second", &second_positions)]
            {
                for position in typed_positions {
                    let (kind, body): (String, String) = tx.query_row(
                        "SELECT kind,payload FROM events WHERE scope_id=?1 AND position=?2",
                        params![scope, position],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )?;
                    rows.push(Row {
                        position: *position,
                        class: class.into(),
                        kind,
                        digest: digest(body),
                    });
                }
            }
            for (position, fact) in fact_positions.iter().zip(&prepared) {
                rows.push(Row {
                    position: *position,
                    class: "fact".into(),
                    kind: fact.kind.clone(),
                    digest: digest(&fact.payload),
                });
            }
            positions.extend(fact_positions);
            let marker = Marker {
                revision: REVISION.into(),
                command: command.into(),
                command_scope: command_scope.into(),
                key: key.into(),
                snapshot_digest: digest(snapshot),
                result_scope: scope.clone(),
                first_kind: L::KIND.into(),
                second_kind: M::KIND.into(),
                intent_digest: meaning,
                rows,
            };
            let marker_body = serde_json::to_string(&marker)?;
            let marker_facts = crate::record_admission::encode_facts(
                phase_codec.as_ref(),
                &[CommandRecordFact {
                    scope_id: scope.clone(),
                    kind: KIND.into(),
                    payload: marker_body.clone(),
                }],
            )?;
            // Marker positions are internal evidence; preserve caller fact positions.
            let marker_positions = crate::record_admission::append_facts(tx, &marker_facts)?;
            tx.execute("INSERT INTO command_pair_results (command_id,command_scope,command_key,result_scope,marker_position,marker_sha256) VALUES (?1,?2,?3,?4,?5,?6)",
                params![command,command_scope,key,scope,marker_positions[0],digest(marker_body)])?;
            Ok(positions)
        },
        final_check,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{command_dispatch::DispatchReadBasis, Store};
    use gaugedesk_core::{
        merge::{MergeCommand, MergeState},
        run::{RunCommand, RunEvent, RunState},
    };

    fn pending(store: &mut Store) {
        for c in [
            RunCommand::RequestRun,
            RunCommand::AdmitRun,
            RunCommand::StartRun,
        ] {
            store.admit::<RunState>("chat", c).unwrap();
        }
        store
            .claim_command("original", "task", "key", "original-input")
            .unwrap();
    }
    fn basis(store: &Store) -> DispatchReadBasis {
        store
            .read_for_dispatch(&["chat", "task", "authority"], |_| Ok(()))
            .unwrap()
            .1
    }
    fn batches() -> (LifecycleBatch<RunState>, LifecycleBatch<MergeState>) {
        (
            LifecycleBatch {
                scope: "chat".into(),
                commands: vec![RunCommand::RecordObservation, RunCommand::CompleteRun],
            },
            LifecycleBatch {
                scope: "chat".into(),
                commands: vec![MergeCommand::StartMerge, MergeCommand::WorkspaceClean],
            },
        )
    }
    fn publish(store: &mut Store) -> Result<MaterializedRecordAdmission, AdmitError> {
        let observed_basis = basis(store);
        let (first, second) = batches();
        store.with_dispatch_record_admission(&observed_basis, |writer| {
            writer.commit_recorded_claimed_lifecycle_pair(
                "original",
                "task",
                "key",
                "original-input",
                first,
                second,
                |next| {
                    Ok(vec![
                        CommandRecordFact {
                            scope_id: "chat".into(),
                            kind: "workspace_result".into(),
                            payload: "original-native-cut".into(),
                        },
                        CommandRecordFact {
                            scope_id: "chat".into(),
                            kind: "transcript".into(),
                            payload: format!("original synthetic result at {next}"),
                        },
                    ])
                },
            )
        })?
    }
    fn original(
        store: &mut Store,
    ) -> Result<RecordedLifecyclePair<RunState, MergeState>, AdmitError> {
        let observed_basis = basis(store);
        store.with_dispatch_record_admission(&observed_basis, |writer| {
            writer.require_recorded_claimed_lifecycle_pair(
                "original",
                "task",
                "key",
                "original-input",
                "chat",
            )
        })?
    }
    fn marker(store: &Store) -> (i64, String) {
        store
            .conn
            .query_row(
                "SELECT position,payload FROM events WHERE scope_id='chat' AND kind=?1",
                [KIND],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    }

    #[test]
    fn recorded_pair_survives_reopen_and_later_work_without_replay_or_task_revival() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("result.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        pending(&mut store);
        let published = publish(&mut store).unwrap();
        assert_eq!(published.positions.len(), 6);
        assert!(matches!(
            original(&mut store).unwrap().first_events().last(),
            Some(RunEvent::RunCompleted)
        ));
        let before = store.retained_events("chat").unwrap();
        let (first, second) = batches();
        let observed_basis = basis(&store);
        let replay = store
            .with_dispatch_record_admission(&observed_basis, |writer| {
                writer.commit_recorded_claimed_lifecycle_pair(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    first,
                    second,
                    |_| panic!("replay rebuilt facts"),
                )
            })
            .unwrap()
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(store.retained_events("chat").unwrap(), before);
        store
            .append_record("chat", "transcript", "later synthetic result")
            .unwrap();
        store.set_command_status("original", "processing").unwrap();
        drop(store);
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        let original = original(&mut store).unwrap();
        assert_eq!(original.positions(), published.positions);
        assert_eq!(original.facts()[0].payload, "original-native-cut");
        assert!(!original.facts()[1].payload.contains("later"));
        assert_eq!(
            store.command("original").unwrap().unwrap().status,
            "processing"
        );
        let observed_basis = basis(&store);
        assert!(store
            .with_dispatch_record_admission(&observed_basis, |writer| writer.require_pending_claim(
                "original",
                "task",
                "key",
                "original-input"
            ))
            .unwrap()
            .is_err());
    }

    #[test]
    fn recorded_pair_refuses_damaged_parent_marker_receipt_and_original_rows_without_repair() {
        for case in [
            "missing-parent",
            "snapshot",
            "rejected-parent",
            "missing-receipt",
            "missing-marker",
            "duplicate-marker",
            "typed-missing",
            "typed-changed",
            "fact-missing",
            "fact-changed",
            "marker-changed",
            "marker-spelling",
            "receipt-position",
            "missing-binding",
            "binding-scope",
        ] {
            let mut store = Store::open_in_memory().unwrap();
            pending(&mut store);
            let publication = publish(&mut store).unwrap();
            let (position, body) = marker(&store);
            match case {
                "missing-parent" => {
                    // Deliberately corrupt the fixture outside normal FK protection.
                    store
                        .conn
                        .pragma_update(None, "foreign_keys", "OFF")
                        .unwrap();
                    store
                        .conn
                        .execute("DELETE FROM commands WHERE command_id='original'", [])
                        .unwrap();
                }
                "snapshot" => {
                    store.conn.execute("UPDATE commands SET snapshot_json='changed' WHERE command_id='original'",[]).unwrap();
                }
                "rejected-parent" => {
                    store.set_command_status("original", "rejected").unwrap();
                }
                "missing-receipt" => {
                    store
                        .conn
                        .execute("DELETE FROM command_receipts WHERE scope_id='task'", [])
                        .unwrap();
                }
                "missing-marker" => {
                    store
                        .conn
                        .execute(
                            "DELETE FROM events WHERE scope_id='chat' AND position=?1",
                            [position],
                        )
                        .unwrap();
                }
                "duplicate-marker" => {
                    store.append_record("chat", KIND, &body).unwrap();
                }
                "typed-missing" | "fact-missing" => {
                    let p = if case == "typed-missing" {
                        publication.positions[0]
                    } else {
                        publication.positions[4]
                    };
                    store
                        .conn
                        .execute(
                            "DELETE FROM events WHERE scope_id='chat' AND position=?1",
                            [p],
                        )
                        .unwrap();
                }
                "typed-changed" | "fact-changed" => {
                    let p = if case == "typed-changed" {
                        publication.positions[0]
                    } else {
                        publication.positions[4]
                    };
                    store.conn.execute("UPDATE events SET payload='substituted' WHERE scope_id='chat' AND position=?1",[p]).unwrap();
                }
                "marker-changed" => {
                    let mut m: serde_json::Value = serde_json::from_str(&body).unwrap();
                    m["snapshot_digest"] = "changed".into();
                    store
                        .conn
                        .execute(
                            "UPDATE events SET payload=?1 WHERE scope_id='chat' AND position=?2",
                            params![m.to_string(), position],
                        )
                        .unwrap();
                }
                "marker-spelling" => {
                    let marker: serde_json::Value = serde_json::from_str(&body).unwrap();
                    store
                        .conn
                        .execute(
                            "UPDATE events SET payload=?1 WHERE scope_id='chat' AND position=?2",
                            params![serde_json::to_string_pretty(&marker).unwrap(), position],
                        )
                        .unwrap();
                }
                "missing-binding" => {
                    store
                        .conn
                        .execute("DELETE FROM command_pair_results", [])
                        .unwrap();
                }
                "binding-scope" => {
                    store
                        .conn
                        .execute("UPDATE command_pair_results SET result_scope='other'", [])
                        .unwrap();
                }
                "receipt-position" => {
                    store
                        .conn
                        .execute(
                            "UPDATE command_receipts SET applied_at=?1 WHERE scope_id='task'",
                            [position],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let before = store.conn.total_changes();
            let observed_basis = basis(&store);
            store
                .with_dispatch_record_admission(&observed_basis, |writer| {
                    assert!(
                        writer
                            .require_recorded_claimed_lifecycle_pair::<RunState, MergeState>(
                                "original",
                                "task",
                                "key",
                                "original-input",
                                "chat"
                            )
                            .is_err(),
                        "{case}"
                    );
                    assert!(writer
                        .with_native_check(|_| panic!("ended verifier revived work: {case}"))
                        .is_err());
                })
                .unwrap();
            assert_eq!(store.conn.total_changes(), before, "{case}");
        }
    }

    #[test]
    fn recorded_pair_refuses_changed_replay_and_posthoc_marker_for_legacy_receipt() {
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        publish(&mut store).unwrap();
        let before = store.retained_events("chat").unwrap();
        let (mut first, second) = batches();
        first.commands = vec![RunCommand::FailRun];
        let observed_basis = basis(&store);
        assert!(store
            .with_dispatch_record_admission(&observed_basis, |writer| writer
                .commit_recorded_claimed_lifecycle_pair(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    first,
                    second,
                    |_| panic!("changed replay rebuilt")
                ))
            .unwrap()
            .is_err());
        assert_eq!(store.retained_events("chat").unwrap(), before);
        let mut legacy = Store::open_in_memory().unwrap();
        pending(&mut legacy);
        let (first, second) = batches();
        let observed_basis = basis(&legacy);
        legacy
            .with_dispatch_record_admission(&observed_basis, |writer| {
                writer.commit_claimed_lifecycle_pair(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    first,
                    second,
                    |_| {
                        Ok(vec![CommandRecordFact {
                            scope_id: "chat".into(),
                            kind: "workspace_result".into(),
                            payload: "legacy".into(),
                        }])
                    },
                )
            })
            .unwrap()
            .unwrap();
        // A later append cannot change what the original atomic receipt named.
        let (_, raw) = marker(&store);
        legacy.append_record("chat", KIND, &raw).unwrap();
        assert!(original(&mut legacy).is_err());
        let (first, second) = batches();
        let observed_basis = basis(&legacy);
        assert!(legacy
            .with_dispatch_record_admission(&observed_basis, |writer| writer
                .commit_recorded_claimed_lifecycle_pair(
                    "original",
                    "task",
                    "key",
                    "original-input",
                    first,
                    second,
                    |_| panic!("legacy replay rebuilt")
                ))
            .unwrap()
            .is_err());
    }

    #[test]
    fn recorded_pair_cannot_copy_original_rows_into_a_different_result_scope() {
        let mut store = Store::open_in_memory().unwrap();
        pending(&mut store);
        publish(&mut store).unwrap();
        let (position, raw) = marker(&store);
        store.conn.execute("INSERT INTO events (scope_id,position,kind,payload) SELECT 'other-chat',position,kind,payload FROM events WHERE scope_id='chat'",[]).unwrap();
        let mut marker: serde_json::Value = serde_json::from_str(&raw).unwrap();
        marker["result_scope"] = "other-chat".into();
        store
            .conn
            .execute(
                "UPDATE events SET payload=?1 WHERE scope_id='other-chat' AND position=?2",
                params![marker.to_string(), position],
            )
            .unwrap();
        let observed_basis = basis(&store);
        store
            .with_dispatch_record_admission(&observed_basis, |writer| {
                assert!(writer
                    .require_recorded_claimed_lifecycle_pair::<RunState, MergeState>(
                        "original",
                        "task",
                        "key",
                        "original-input",
                        "other-chat"
                    )
                    .is_err());
            })
            .unwrap();
        assert!(original(&mut store).is_ok());
    }

    #[test]
    fn recorded_pair_rolls_back_both_lifecycles_facts_marker_and_receipt() {
        for point in ["marker", "binding", "receipt"] {
            let mut store = Store::open_in_memory().unwrap();
            pending(&mut store);
            let before = store.retained_events("chat").unwrap();
            let trigger = if point == "marker" {
                "CREATE TRIGGER fail_pair BEFORE INSERT ON events WHEN NEW.kind='command_pair_result_v1' BEGIN SELECT RAISE(ABORT,'marker unavailable'); END;"
            } else if point == "binding" {
                "CREATE TRIGGER fail_pair BEFORE INSERT ON command_pair_results BEGIN SELECT RAISE(ABORT,'binding unavailable'); END;"
            } else {
                "CREATE TRIGGER fail_pair BEFORE INSERT ON command_receipts BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END;"
            };
            store.conn.execute_batch(trigger).unwrap();
            assert!(publish(&mut store).is_err(), "{point}");
            assert_eq!(store.retained_events("chat").unwrap(), before);
            assert_eq!(
                store.command("original").unwrap().unwrap().status,
                "processing"
            );
            assert!(store
                .committed_record_snapshot("task", "key")
                .unwrap()
                .is_none());
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT COUNT(*) FROM command_pair_results", [], |row| row
                        .get::<_, i64>(
                        0
                    ))
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn recorded_pair_reader_excludes_writers_and_refuses_key_loss_and_ended_authority() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        struct Codec {
            readable: Arc<AtomicBool>,
            live: Arc<AtomicBool>,
            interrupt: Arc<AtomicBool>,
            encodes: Arc<AtomicUsize>,
        }
        impl ContentCodec for Codec {
            fn encode(&self, scope: &str, kind: &str, body: &str) -> Result<String, String> {
                self.encodes.fetch_add(1, Ordering::SeqCst);
                Ok(serde_json::to_string(&(scope, kind, body)).unwrap())
            }
            fn decode(&self, scope: &str, kind: &str, body: &str) -> Option<String> {
                if !self.readable.load(Ordering::SeqCst) {
                    return None;
                }
                if kind == KIND && self.interrupt.load(Ordering::SeqCst) {
                    self.live.store(false, Ordering::SeqCst);
                }
                let (s, k, p): (String, String, String) = serde_json::from_str(body).ok()?;
                (s == scope && k == kind).then_some(p)
            }
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("pair.sqlite");
        let readable = Arc::new(AtomicBool::new(true));
        let live = Arc::new(AtomicBool::new(true));
        let interrupt = Arc::new(AtomicBool::new(false));
        let encodes = Arc::new(AtomicUsize::new(0));
        let mut store = Store::open(path.to_str().unwrap())
            .unwrap()
            .with_codec(Arc::new(Codec {
                readable: readable.clone(),
                live: live.clone(),
                interrupt: interrupt.clone(),
                encodes: encodes.clone(),
            }));
        pending(&mut store);
        publish(&mut store).unwrap();
        let writes = encodes.load(Ordering::SeqCst);
        let other = rusqlite::Connection::open(path).unwrap();
        other.busy_timeout(std::time::Duration::ZERO).unwrap();
        let observed_basis = basis(&store);
        store
            .with_dispatch_record_admission(&observed_basis, |writer| {
                let origin = writer
                    .require_recorded_claimed_lifecycle_pair::<RunState, MergeState>(
                        "original",
                        "task",
                        "key",
                        "original-input",
                        "chat",
                    )
                    .unwrap();
                assert_eq!(origin.facts()[0].payload, "original-native-cut");
                assert!(other.execute_batch("BEGIN IMMEDIATE").is_err());
            })
            .unwrap();
        readable.store(false, Ordering::SeqCst);
        assert!(original(&mut store).is_err());
        readable.store(true, Ordering::SeqCst);
        interrupt.store(true, Ordering::SeqCst);
        let alive = live.clone();
        let observed_basis = basis(&store).with_process_guard(move || alive.load(Ordering::SeqCst));
        store
            .with_dispatch_record_admission(&observed_basis, |writer| {
                assert!(writer
                    .require_recorded_claimed_lifecycle_pair::<RunState, MergeState>(
                        "original",
                        "task",
                        "key",
                        "original-input",
                        "chat"
                    )
                    .is_err());
                live.store(true, Ordering::SeqCst);
                interrupt.store(false, Ordering::SeqCst);
                assert!(writer
                    .with_native_check(|_| panic!("restored source revived refused reader"))
                    .is_err());
            })
            .unwrap();
        assert_eq!(encodes.load(Ordering::SeqCst), writes);
    }
}
