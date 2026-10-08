//! Exact original task input plus its sole derived HTTP-attempt companion.
//! Separate recipe; the ordinary prefix implementation is unchanged.
//! It keeps the parent pending and conveys no authority for subsequent work.
use crate::command_dispatch::{LifecycleBatch, MaterializedCommandPrefix, TaskInputLink};
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
use crate::record_admission_prefix::prefix_scope;

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
    link: &TaskInputLink,
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
        link,
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
    link: &TaskInputLink,
) -> Result<(String, String, Option<Vec<i64>>), AdmitError>
where
    L::Command: Serialize,
{
    let scope = prefix_scope(command_id, phase);
    validate_input(command_id, key, snapshot, phase, batch, facts, link)?;
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
        "claimed-task-input-prefix/v1",
        command_id,
        command_scope,
        key,
        snapshot,
        phase,
        &batch.scope,
        L::KIND,
        &batch.commands,
        raw_facts,
        &link.body_digest,
    ))?);
    let has_receipt = tx
        .prepare_cached("SELECT 1 FROM command_receipts WHERE scope_id=?1 AND command_key=?2")?
        .query_row(params![scope, KEY], |_| Ok(()))
        .optional()?
        .is_some();
    let linked_rows: i64 = tx.query_row(
        "SELECT COUNT(*) FROM events WHERE scope_id=?1 AND kind='task_correlation_attempt'",
        [format!("http-task-attempt::{command_id}")],
        |row| row.get(0),
    )?;
    if linked_rows != i64::from(has_receipt) {
        return Err(refused());
    }
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
        if !matches!(result.revision.as_str(), "claimed-task-input-prefix/v1")
            || result.meaning_sha256 != meaning
            || result.events.len() < facts.len() + 1
        {
            return Err(refused());
        }
        let typed_count = result.events.len() - facts.len() - 1;
        if batch.commands.is_empty() && typed_count != 0 {
            return Err(refused());
        }
        for event in &result.events[..typed_count] {
            if event.scope != batch.scope || event.kind != L::KIND || !event.encoded {
                return Err(refused());
            }
        }
        for (event, fact) in result.events[typed_count..typed_count + facts.len()]
            .iter()
            .zip(facts)
        {
            if event.scope != fact.scope_id
                || event.kind != fact.kind
                || event.sha256 != digest(&fact.payload)
                || !event.encoded
            {
                return Err(refused());
            }
        }
        let user_position = result.events[typed_count + facts.len() - 1].position;
        let expected_link = companion(command_id, &batch.scope, user_position, link)?;
        let linked = result.events.last().ok_or_else(refused)?;
        if linked.scope != expected_link.scope_id
            || linked.kind != expected_link.kind
            || linked.sha256 != digest(&expected_link.payload)
            || !linked.encoded
        {
            return Err(refused());
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
            let body = decode(codec, &event.scope, &kind, &body)?;
            if kind != event.kind || digest(body) != event.sha256 {
                return Err(refused());
            }
            positions.push(event.position);
        }
        if positions.iter().any(|position| *position < 0)
            || positions[..positions.len() - 1]
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(refused());
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
    link: &TaskInputLink,
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
        link,
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
    link: &TaskInputLink,
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
        link,
    )?;
    let positions = recovered.ok_or_else(refused)?;
    if positions.is_empty()
        || positions
            .iter()
            .take(positions.len() - 1)
            .any(|position| position < &0 || position >= first_result)
        || positions[..positions.len() - 1]
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
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
    link: &TaskInputLink,
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
        link,
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
            let mut positions =
                crate::record_admission::stage_lifecycle::<L>(tx, phase_codec.as_ref(), batch)?;
            let mut events = Vec::with_capacity(positions.len() + facts.len());
            for position in &positions {
                let payload: String = tx
                    .prepare_cached("SELECT payload FROM events WHERE scope_id=?1 AND position=?2")?
                    .query_row(params![target, position], |r| r.get(0))?;
                events.push(PrefixEvent {
                    scope: target.clone(),
                    position: *position,
                    kind: L::KIND.into(),
                    sha256: digest(decode(phase_codec.as_ref(), &target, L::KIND, &payload)?),
                    encoded: true,
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
            let user_position = *fact_positions.last().ok_or_else(refused)?;
            let linked = companion(command_id, &target, user_position, link)?;
            let stored_link = crate::record_admission::encode_facts(
                phase_codec.as_ref(),
                std::slice::from_ref(&linked),
            )?;
            let linked_positions = crate::record_admission::append_facts(tx, &stored_link)?;
            let linked_position = *linked_positions.first().ok_or_else(refused)?;
            events.push(PrefixEvent {
                scope: linked.scope_id,
                position: linked_position,
                kind: linked.kind,
                sha256: digest(&linked.payload),
                encoded: true,
            });
            positions.extend(fact_positions);
            positions.extend(linked_positions);
            let marker = CommandRecordFact {
                scope_id: phase_scope,
                kind: KIND.into(),
                payload: serde_json::to_string(&PrefixResult {
                    revision: "claimed-task-input-prefix/v1".into(),
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

fn validate_input<L: Lifecycle>(
    command_id: &str,
    key: &str,
    snapshot: &str,
    phase: &str,
    batch: &LifecycleBatch<L>,
    facts: &[CommandRecordFact],
    link: &TaskInputLink,
) -> Result<(), AdmitError> {
    let last = facts.last().ok_or_else(refused)?;
    let user: serde_json::Value = serde_json::from_str(&last.payload)?;
    let original: serde_json::Value = serde_json::from_str(snapshot)?;
    let raw_key = user["client_request_id"].as_str().ok_or_else(refused)?;
    let linked_scope = format!("http-task-attempt::{command_id}");
    if facts.iter().any(|fact| fact.scope_id != batch.scope)
        || last.kind != "transcript"
        || user["type"] != "user"
        || user["chat_id"] != batch.scope
        || format!("office-http:v1:{}", digest(raw_key.as_bytes())) != key
        || !user["text"].is_string()
        || ["home_id", "actor_id"].iter().any(|field| {
            user[*field]
                .as_str()
                .is_none_or(|value| value.trim().is_empty())
        })
        || link.body_digest.len() != 64
        || !link
            .body_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || original["body_sha256"] != link.body_digest
        || linked_scope == batch.scope
        || linked_scope == prefix_scope(command_id, phase)
    {
        return Err(refused());
    }
    Ok(())
}
fn companion(
    command_id: &str,
    chat: &str,
    user_position: i64,
    link: &TaskInputLink,
) -> Result<CommandRecordFact, AdmitError> {
    if user_position < 0 {
        return Err(refused());
    }
    Ok(CommandRecordFact {
        scope_id: format!("http-task-attempt::{command_id}"),
        kind: "task_correlation_attempt".into(),
        payload: serde_json::to_string(
            &serde_json::json!({"chat_id":chat,"user_entry_id":user_position,"command_id":command_id,"body_digest":link.body_digest}),
        )?,
    })
}

#[cfg(test)]
mod tests;
