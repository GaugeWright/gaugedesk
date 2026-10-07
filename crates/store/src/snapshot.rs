//! Per-scope fold checkpoints (SCALE-1).
//!
//! A lifecycle that returns a [`SnapshotCodec`] from
//! [`Lifecycle::snapshot_codec`] has its folded state checkpointed into
//! `scope_snapshots`, in the same immediate transaction as the append that
//! crossed the interval, so a rolled-back admission leaves no checkpoint. A fold
//! then starts from the newest checkpoint and evolves only the events after it.
//!
//! Events remain the only authority (`INV-8`). A checkpoint is derived and
//! rebuildable, and it is used only when everything about it still holds:
//!
//! * it was written for this lifecycle, codec version and reducer build;
//! * the event it claims to follow is still at its position, with its kind and
//!   the exact stored bytes it was folded from;
//! * the content codec, when one is set, still opens it.
//!
//! Anything else — a missing row, a raised version, a new release, an
//! undecodable state — is a full replay, which is exactly the fold that existed
//! before checkpoints.
//!
//! With a content codec the fold still opens every retained row of the scope,
//! as [`crate::retained_kind_payloads`] does, because unavailable protected
//! history must refuse a lifecycle fold rather than vanish behind a checkpoint.
//! Only the deserialize-and-evolve of the checkpointed prefix is skipped there.

use std::sync::Arc;

use gaugedesk_core::{Lifecycle, SnapshotCodec, SNAPSHOT_REDUCER_BUILD};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::{AdmitError, ContentCodec};

/// A loaded checkpoint: the folded state and the position of the last event of
/// the lifecycle's kind it includes.
struct Checkpoint<S> {
    state: S,
    position: i64,
}

fn anchor(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

fn load<L: Lifecycle>(
    conn: &Connection,
    codec: Option<&Arc<dyn ContentCodec>>,
    scope: &str,
    snapshot: &SnapshotCodec<L::State>,
) -> Result<Option<Checkpoint<L::State>>, AdmitError> {
    let row: Option<(i64, String, String)> = conn
        .prepare_cached(
            "SELECT position, anchor_sha256, state FROM scope_snapshots
             WHERE scope_id = ?1 AND kind = ?2 AND lifecycle = ?3
               AND codec_version = ?4 AND reducer_build = ?5",
        )?
        .query_row(
            params![
                scope,
                L::KIND,
                snapshot.lifecycle,
                snapshot.version,
                SNAPSHOT_REDUCER_BUILD
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((position, expected, stored)) = row else {
        return Ok(None);
    };
    let anchored: Option<(String, String)> = conn
        .prepare_cached("SELECT kind, payload FROM events WHERE scope_id = ?1 AND position = ?2")?
        .query_row(params![scope, position], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()?;
    match anchored {
        Some((kind, raw)) if kind == L::KIND && anchor(&raw) == expected => {}
        _ => return Ok(None),
    }
    let plain = match codec {
        Some(codec) => match codec.decode(scope, L::KIND, &stored) {
            Some(plain) => plain,
            None => return Ok(None),
        },
        None => stored,
    };
    Ok((snapshot.decode)(&plain).map(|state| Checkpoint { state, position }))
}

/// Fold `L` in `scope`, from its newest valid checkpoint when there is one.
pub(crate) fn fold<L: Lifecycle>(
    conn: &Connection,
    codec: Option<&Arc<dyn ContentCodec>>,
    scope: &str,
) -> Result<L::State, AdmitError> {
    let checkpoint = match L::snapshot_codec() {
        Some(snapshot) => load::<L>(conn, codec, scope, &snapshot)?,
        None => None,
    };
    let (mut state, after) = match checkpoint {
        Some(Checkpoint { state, position }) => (state, position),
        None => (L::State::default(), -1),
    };
    match codec {
        // Nothing to authenticate: read only this lifecycle's tail.
        None => {
            let mut statement = conn.prepare_cached(
                "SELECT payload FROM events
                 WHERE scope_id = ?1 AND kind = ?2 AND position > ?3 ORDER BY position",
            )?;
            let rows = statement.query_map(params![scope, L::KIND, after], |row| {
                row.get::<_, String>(0)
            })?;
            for row in rows {
                state = L::evolve(&state, serde_json::from_str(&row?)?);
            }
        }
        // Open the whole retained history, as the full fold always has, and
        // evolve only what the checkpoint does not already hold.
        Some(codec) => {
            let mut statement = conn.prepare_cached(
                "SELECT position, kind, payload FROM events WHERE scope_id = ?1 ORDER BY position",
            )?;
            let rows = statement.query_map([scope], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (position, kind, raw) = row?;
                let plain = codec.decode(scope, &kind, &raw).ok_or_else(|| {
                    AdmitError::Codec("authority history contains an unavailable record".into())
                })?;
                if kind == L::KIND && position > after {
                    state = L::evolve(&state, serde_json::from_str(&plain)?);
                }
            }
        }
    }
    Ok(state)
}

/// Checkpoint `state` — the fold of every `L` event now in `scope` — when the
/// interval has been crossed since the last checkpoint. Call it inside the
/// admission's immediate transaction, after its appends and before commit.
///
/// A state the codec cannot encode is simply not checkpointed: the checkpoint
/// is an optimization and its absence is the full replay.
pub(crate) fn checkpoint<L: Lifecycle>(
    conn: &Connection,
    codec: Option<&Arc<dyn ContentCodec>>,
    scope: &str,
    state: &L::State,
) -> Result<(), AdmitError> {
    let Some(snapshot) = L::snapshot_codec() else {
        return Ok(());
    };
    let previous: i64 = conn
        .prepare_cached(
            "SELECT position FROM scope_snapshots
             WHERE scope_id = ?1 AND kind = ?2 AND lifecycle = ?3
               AND codec_version = ?4 AND reducer_build = ?5",
        )?
        .query_row(
            params![
                scope,
                L::KIND,
                snapshot.lifecycle,
                snapshot.version,
                SNAPSHOT_REDUCER_BUILD
            ],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(-1);
    let (since, head): (i64, Option<i64>) = conn
        .prepare_cached(
            "SELECT COUNT(*), MAX(position) FROM events
             WHERE scope_id = ?1 AND kind = ?2 AND position > ?3",
        )?
        .query_row(params![scope, L::KIND, previous], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    let Some(head) = head else {
        return Ok(());
    };
    if since < i64::from(snapshot.every) {
        return Ok(());
    }
    let raw: String = conn
        .prepare_cached("SELECT payload FROM events WHERE scope_id = ?1 AND position = ?2")?
        .query_row(params![scope, head], |row| row.get(0))?;
    let Some(plain) = (snapshot.encode)(state) else {
        return Ok(());
    };
    let stored = match codec {
        Some(codec) => match codec.encode(scope, L::KIND, &plain) {
            Ok(stored) => stored,
            Err(_) => return Ok(()),
        },
        None => plain,
    };
    // One checkpoint per lifecycle per scope: a raised version or a new build
    // replaces the old one rather than accumulating beside it.
    conn.prepare_cached(
        "DELETE FROM scope_snapshots WHERE scope_id = ?1 AND kind = ?2 AND lifecycle = ?3",
    )?
    .execute(params![scope, L::KIND, snapshot.lifecycle])?;
    conn.prepare_cached(
        "INSERT INTO scope_snapshots
         (scope_id, kind, lifecycle, codec_version, reducer_build, position, anchor_sha256, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?
    .execute(params![
        scope,
        L::KIND,
        snapshot.lifecycle,
        snapshot.version,
        SNAPSHOT_REDUCER_BUILD,
        head,
        anchor(&raw),
        stored
    ])?;
    Ok(())
}
