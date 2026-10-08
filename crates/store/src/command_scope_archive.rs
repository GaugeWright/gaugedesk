//! Exact product command-scope carriage. This is retained evidence, not an
//! admission grant. The authenticated caller selects scopes and authorizes
//! relocation before exporting or importing. Current execution is independent.

use super::*;
use serde::{Deserialize, Serialize};

const PROTOCOL: &str = "gaugedesk.command-scope-archive.v2";
const LEGACY_PROTOCOL: &str = "gaugedesk.command-scope-archive.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandScopeArchive {
    protocol: String,
    scopes: Vec<Scope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    id: String,
    events: Vec<(i64, String, String)>,
    commands: Vec<Command>,
    receipts: Vec<(String, i64)>,
    #[serde(default)]
    fact_sets: Vec<(String, i64)>,
    #[serde(default)]
    fact_refs: Vec<(String, i64, String, i64)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    id: String,
    key: String,
    status: String,
    snapshot: String,
    updated_at: String,
}

fn refused(reason: &'static str) -> AdmitError {
    AdmitError::Rejected(Rejection { reason })
}

impl CommandScopeArchive {
    pub fn scope_ids(&self) -> impl Iterator<Item = &str> {
        self.scopes.iter().map(|scope| scope.id.as_str())
    }

    /// The decoded event sequence is supplied for comparison with an existing
    /// relocation envelope. Positions remain in this archive, not reallocated
    /// by appending those envelope rows again.
    pub fn events(&self) -> impl Iterator<Item = (&str, i64, &str, &str)> {
        self.scopes.iter().flat_map(|scope| {
            scope.events.iter().map(move |(position, kind, payload)| {
                (
                    scope.id.as_str(),
                    *position,
                    kind.as_str(),
                    payload.as_str(),
                )
            })
        })
    }

    fn validate(&self, allowed: impl Fn(&str) -> bool) -> Result<(), AdmitError> {
        if self.protocol != PROTOCOL && self.protocol != LEGACY_PROTOCOL {
            return Err(refused("unsupported command scope archive"));
        }
        if self.protocol == LEGACY_PROTOCOL
            && self
                .scopes
                .iter()
                .any(|scope| !scope.fact_sets.is_empty() || !scope.fact_refs.is_empty())
        {
            return Err(refused(
                "legacy command archive carries newer fact coordinates",
            ));
        }
        let mut previous: Option<&str> = None;
        for scope in &self.scopes {
            if scope.id.trim().is_empty()
                || !allowed(&scope.id)
                || previous.is_some_and(|id| id >= scope.id.as_str())
            {
                return Err(refused("command archive has unselected or repeated scope"));
            }
            previous = Some(&scope.id);
            let mut position = None;
            for (next, kind, _) in &scope.events {
                if *next < 0 || position.is_some_and(|old| old >= *next) || kind.is_empty() {
                    return Err(refused("command archive has invalid event coordinates"));
                }
                position = Some(*next);
            }
            // Canonical order makes an accepted archive exactly replayable
            // against the store's ordered read, including after deserialization.
            if scope
                .commands
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
                || scope.receipts.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            {
                return Err(refused("command archive has noncanonical command order"));
            }
            let mut keys = std::collections::BTreeSet::new();
            let mut ids = std::collections::BTreeSet::new();
            for command in &scope.commands {
                if command.id.is_empty()
                    || command.key.is_empty()
                    || !keys.insert(&command.key)
                    || !ids.insert(&command.id)
                    || !matches!(
                        command.status.as_str(),
                        "received" | "processing" | "applied" | "rejected" | "expired"
                    )
                {
                    return Err(refused("command archive has invalid command state"));
                }
            }
            let mut receipts = std::collections::BTreeSet::new();
            for (key, at) in &scope.receipts {
                if key.is_empty() || *at < 0 || !receipts.insert(key) {
                    return Err(refused("command archive has invalid receipt"));
                }
            }
            // Legacy lifecycle receipts may have no commands table row. A
            // materialized applied command, however, must have its real receipt.
            for command in &scope.commands {
                if command.status == "applied" && !receipts.contains(&command.key) {
                    return Err(refused("applied command is missing its original receipt"));
                }
            }
            if scope
                .fact_sets
                .windows(2)
                .any(|pair| pair[0].0 >= pair[1].0)
                || scope
                    .fact_refs
                    .windows(2)
                    .any(|pair| (&pair[0].0, pair[0].1) >= (&pair[1].0, pair[1].1))
            {
                return Err(refused("command archive has noncanonical fact coordinates"));
            }
            let sets = scope
                .fact_sets
                .iter()
                .map(|(key, count)| (key.as_str(), *count))
                .collect::<std::collections::BTreeMap<_, _>>();
            for (key, count) in &scope.fact_sets {
                if *count < 0 || !receipts.contains(key) {
                    return Err(refused("command archive has an unreceipted fact set"));
                }
                let refs = scope
                    .fact_refs
                    .iter()
                    .filter(|(candidate, _, _, _)| candidate == key)
                    .collect::<Vec<_>>();
                if refs.len() as i64 != *count
                    || refs
                        .iter()
                        .enumerate()
                        .any(|(index, reference)| reference.1 != index as i64)
                {
                    return Err(refused("command archive has incomplete fact coordinates"));
                }
            }
            if scope
                .fact_refs
                .iter()
                .any(|(key, _, _, _)| !sets.contains_key(key.as_str()))
            {
                return Err(refused("command archive has an orphaned fact coordinate"));
            }
        }
        let events = self
            .scopes
            .iter()
            .flat_map(|scope| {
                scope
                    .events
                    .iter()
                    .map(move |(position, _, _)| (scope.id.as_str(), *position))
            })
            .collect::<std::collections::BTreeSet<_>>();
        let mut linked = std::collections::BTreeSet::new();
        for scope in &self.scopes {
            for (_, _, event_scope, event_position) in &scope.fact_refs {
                if !events.contains(&(event_scope.as_str(), *event_position))
                    || !linked.insert((event_scope.as_str(), *event_position))
                {
                    return Err(refused(
                        "command archive has a missing or repeated fact event",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn read_scope(
    conn: &Connection,
    codec: Option<&Arc<dyn ContentCodec>>,
    id: &str,
) -> Result<Scope, AdmitError> {
    let mut statement = conn.prepare_cached(
        "SELECT position, kind, payload FROM events WHERE scope_id = ?1 ORDER BY position",
    )?;
    let mut events = Vec::new();
    for row in statement.query_map([id], |row| {
        Ok((
            row.get(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (position, kind, raw) = row?;
        let payload = match codec {
            Some(codec) => codec.decode(id, &kind, &raw).ok_or_else(|| {
                AdmitError::Codec("command scope has unavailable retained evidence".into())
            })?,
            None => raw,
        };
        events.push((position, kind, payload));
    }
    let commands = conn
        .prepare_cached(
            "SELECT command_id, idempotency_key, status, snapshot_json, updated_at
         FROM commands WHERE scope_id = ?1 ORDER BY idempotency_key",
        )?
        .query_map([id], |row| {
            Ok(Command {
                id: row.get(0)?,
                key: row.get(1)?,
                status: row.get(2)?,
                snapshot: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let receipts = conn.prepare_cached("SELECT command_key, applied_at FROM command_receipts WHERE scope_id = ?1 ORDER BY command_key",
    )?.query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let fact_sets = conn
        .prepare_cached(
            "SELECT command_key, fact_count FROM record_command_fact_sets
             WHERE command_scope = ?1 ORDER BY command_key",
        )?
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let fact_refs = conn
        .prepare_cached(
            "SELECT command_key, fact_index, event_scope, event_position
             FROM record_command_fact_refs WHERE command_scope = ?1
             ORDER BY command_key, fact_index",
        )?
        .query_map([id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Scope {
        id: id.into(),
        events,
        commands,
        receipts,
        fact_sets,
        fact_refs,
    })
}

impl Store {
    /// Select the complete event/command/receipt plane from one read snapshot.
    /// A command with no event yet is still discovered. Cross-store relocation
    /// additionally holds the product writer exclusion around this read.
    pub fn export_command_scopes(
        &self,
        selected: impl Fn(&str) -> bool,
    ) -> Result<CommandScopeArchive, AdmitError> {
        let tx = self.conn.unchecked_transaction()?;
        let ids = tx
            .prepare_cached(
                "SELECT scope_id FROM events UNION SELECT scope_id FROM commands
             UNION SELECT scope_id FROM command_receipts
             UNION SELECT command_scope FROM record_command_fact_sets
             UNION SELECT command_scope FROM record_command_fact_refs ORDER BY scope_id",
            )?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let scopes = ids
            .into_iter()
            .filter(|id| selected(id))
            .map(|id| read_scope(&tx, self.codec.as_ref(), &id))
            .collect::<Result<Vec<_>, _>>()?;
        let archive = CommandScopeArchive {
            protocol: PROTOCOL.into(),
            scopes,
        };
        archive.validate(selected)?;
        tx.commit()?;
        Ok(archive)
    }

    /// Import only caller-selected scopes, preserving original positions and
    /// receipts. Existing exact state is a replay; any other existing state is
    /// a conflict. The complete set rolls back on conflict or codec/SQL failure.
    /// This neither synthesizes receipts from events nor authorizes execution.
    pub fn import_command_scopes(
        &mut self,
        archive: &CommandScopeArchive,
        allowed: impl Fn(&str) -> bool,
    ) -> Result<(), AdmitError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        import_into(&tx, self.codec.as_ref(), archive, allowed)?;
        tx.commit()?;
        Ok(())
    }
}

/// Stage an exact archive in an already-held product transaction. The caller
/// owns rollback on every error and decides when the whole admission commits.
pub(crate) fn import_into(
    tx: &rusqlite::Transaction<'_>,
    codec: Option<&Arc<dyn ContentCodec>>,
    archive: &CommandScopeArchive,
    allowed: impl Fn(&str) -> bool,
) -> Result<(), AdmitError> {
    archive.validate(allowed)?;
    for scope in &archive.scopes {
        let existing = read_scope(tx, codec, &scope.id)?;
        if existing == *scope {
            continue;
        }
        if !existing.events.is_empty()
            || !existing.commands.is_empty()
            || !existing.receipts.is_empty()
            || !existing.fact_sets.is_empty()
            || !existing.fact_refs.is_empty()
        {
            return Err(refused(
                "command scope import conflicts with existing authority",
            ));
        }
        for (position, kind, payload) in &scope.events {
            let stored = match codec {
                Some(codec) => codec
                    .encode(&scope.id, kind, payload)
                    .map_err(AdmitError::Codec)?,
                None => payload.clone(),
            };
            tx.prepare_cached(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![scope.id, position, kind, stored])?;
        }
        for command in &scope.commands {
            tx.prepare_cached("INSERT INTO commands (command_id, scope_id, idempotency_key, status, snapshot_json, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?.execute(
                params![command.id, scope.id, command.key, command.status, command.snapshot, command.updated_at])?;
        }
        for (key, position) in &scope.receipts {
            tx.prepare_cached("INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)")?.execute(
                params![scope.id, key, position])?;
        }
        for (key, count) in &scope.fact_sets {
            tx.prepare_cached(
                "INSERT INTO record_command_fact_sets (command_scope, command_key, fact_count)
                 VALUES (?1, ?2, ?3)",
            )?
            .execute(params![scope.id, key, count])?;
        }
        for (key, index, event_scope, event_position) in &scope.fact_refs {
            tx.prepare_cached(
                "INSERT INTO record_command_fact_refs
                 (command_scope, command_key, fact_index, event_scope, event_position)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?
            .execute(params![scope.id, key, index, event_scope, event_position])?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "command_scope_archive_tests.rs"]
mod tests;
