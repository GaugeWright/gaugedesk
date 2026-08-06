//! gaugewright local store — the SQLite event log + the admission transaction.
//!
//! The imperative shell around the pure `gaugedesk-core` reducers (ADR 0004): it
//! folds a scope's events to current state (`INV-8`), runs `decide`, and appends
//! the resulting events **atomically** at the next position (single-writer per
//! scope, `INV-7`). A rejected command appends nothing (`INV-2`). The
//! fold/append loop is the reusable spine for every lifecycle.
//!
//! Threading (RF-A7): the `Store` is **synchronous** `rusqlite`. fold/append are
//! fast and run directly inside the control-plane's async handlers; the one
//! genuinely long operation — a Pi turn (subprocess + multi-step admission) — is
//! dispatched on `tokio::task::spawn_blocking` (`crates/app/src/lib.rs` `post_task`),
//! so it never blocks an async worker. Per-scope writes serialize through an
//! immediate transaction with a `busy_timeout` (see `open`), so concurrent
//! connections wait rather than fail. A move to an async SQLite driver is a
//! scale-time change behind this same API — not needed for the single-process,
//! single-user shape — and would not alter the admission semantics above.

use std::sync::Arc;
use std::time::Duration;

use gaugedesk_core::{Lifecycle, Rejection};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

/// A transparent at-rest transform applied to record payloads of designated
/// **content** kinds (`SECAUD-9`/`SECAUD-6`). The store crate stays crypto-free: this
/// is the seam an app-side content vault implements to encrypt sensitive content
/// (e.g. `transcript`) under per-scope keys, leaving lifecycle/metadata records
/// untouched. `None` on the [`Store`] = plaintext (the default; zero behavior change).
pub trait ContentCodec: Send + Sync {
    /// Transform a payload for storage. Must be reversible by [`decode`](Self::decode).
    /// A non-content `kind` returns the payload unchanged (pass-through).
    /// Failure aborts the store append before a transaction is opened; protected
    /// content must never be replaced with a lossy placeholder or plaintext.
    fn encode(&self, scope: &str, kind: &str, payload: &str) -> Result<String, String>;
    /// Reverse [`encode`](Self::encode). Returns `None` when the payload is
    /// **unrecoverable** — its per-scope key was crypto-erased — so the caller drops
    /// the row (the content is gone, history intact). Non-content kinds and legacy
    /// plaintext return `Some(payload)`.
    fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String>;
}

pub struct Store {
    conn: Connection,
    codec: Option<Arc<dyn ContentCodec>>,
    /// The database this connection was opened from, so [`Store::sibling`] can open
    /// a second one onto the same data.
    path: String,
    /// Set only for an ephemeral store ([`Store::open_in_memory`]): the temporary
    /// directory removed once every connection to it has dropped.
    scratch: Option<Arc<ScratchHome>>,
}

#[derive(Debug)]
pub enum AdmitError {
    Rejected(Rejection),
    Db(rusqlite::Error),
    Json(serde_json::Error),
    Codec(String),
    /// A persisted record declares a schema version newer than this build
    /// supports (DR-0054 Phase B). Reading it anyway would silently drop the
    /// newer build's data, so the reader fails closed with this diagnosable
    /// error instead of skipping or truncating the record.
    UnsupportedSchema(String),
}

/// One immutable revision in the declarative-record plane (CORE-2). Current
/// state is the greatest revision; tombstones are revisions, never deletes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordRevision {
    pub record_id: String,
    pub scope_id: String,
    pub kind: String,
    pub revision: i64,
    pub tombstone: bool,
    pub payload: String,
}

/// Metadata for protected bytes held outside SQLite. `status` is `live`,
/// `tombstoned`, or `unavailable`; historical rows that cite the handle remain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentMetadata {
    pub handle: String,
    pub resource_id: Option<String>,
    pub sha256: Option<String>,
    pub size_bytes: Option<i64>,
    pub status: String,
}

/// Operational command state. This is retry/recovery data, not lifecycle truth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandRecord {
    pub command_id: String,
    pub scope_id: String,
    pub idempotency_key: String,
    pub status: String,
    pub snapshot_json: String,
}

/// Result of an application command admitted through the materialized command
/// shell. `replayed` means the idempotency receipt already existed, so callers
/// must not repeat non-durable notifications for the original admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedAdmission<S> {
    pub state: S,
    pub replayed: bool,
}

/// One immutable record fact admitted as part of a caller-keyed command.
/// Records may span scopes; the command receipt and every fact commit in one
/// SQLite transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandRecordFact {
    pub scope_id: String,
    pub kind: String,
    pub payload: String,
}

/// A record fact whose payload depends on the committed head of its own scope —
/// a hash-chain link (`SECAUD-2`). The link **must** be computed inside the write
/// transaction that appends it: a caller that reads the head first and appends
/// afterwards leaves a window in which two writers read the same head and fork
/// the chain. The store owns *when* the link is computed; `link` owns *how*.
pub struct ChainedRecordFact<'a> {
    pub scope_id: &'a str,
    pub kind: &'a str,
    /// Given the decoded payload of the scope's current last row of this kind
    /// (`None` when the scope holds none), produce the payload to append.
    pub link: &'a dyn Fn(Option<&str>) -> String,
}

/// Result of atomically admitting ordinary record facts. `replayed` means the
/// exact command snapshot already committed and no fact was appended again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedRecordAdmission {
    pub positions: Vec<i64>,
    pub replayed: bool,
    /// The payload actually appended for a [`ChainedRecordFact`], once its link
    /// was resolved against the committed head. `None` when no chained fact was
    /// supplied, or when the command replayed and nothing was appended.
    pub chained_payload: Option<String>,
}

/// Per-scope projection cursor/version. A dirty or behind row cannot be treated
/// as a current projection until its owner rebuilds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionMeta {
    pub projection: String,
    pub scope_id: String,
    pub version: i64,
    pub high_water: i64,
    pub dirty: bool,
}

/// Runtime/boundary evidence remains operational until an owning scope admits
/// it by attaching an event coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationRecord {
    pub observation_id: String,
    pub run_ref: String,
    pub kind: String,
    pub payload_ref: Option<String>,
    pub admitted_scope: Option<String>,
    pub admitted_position: Option<i64>,
}

impl From<rusqlite::Error> for AdmitError {
    fn from(e: rusqlite::Error) -> Self {
        AdmitError::Db(e)
    }
}
impl From<serde_json::Error> for AdmitError {
    fn from(e: serde_json::Error) -> Self {
        AdmitError::Json(e)
    }
}

/// Map the `GAUGEDESK_SQLITE_SYNCHRONOUS` setting to a SQLite `synchronous` mode
/// (`SCALE-5`): `FULL` (case-insensitive) for a hosted data plane's fsync-per-commit
/// durability, else the desktop default `NORMAL`. Pure, so the policy is unit-testable.
fn synchronous_mode(setting: Option<&str>) -> &'static str {
    match setting {
        Some(s) if s.trim().eq_ignore_ascii_case("full") => "FULL",
        _ => "NORMAL",
    }
}

/// WAL is the local-disk default. A hosted single-writer deployment may opt
/// into the rollback journal when its durable volume is a network filesystem
/// that cannot safely provide SQLite's shared-memory WAL contract.
fn journal_mode(setting: Option<&str>) -> &'static str {
    match setting {
        Some(s) if s.trim().eq_ignore_ascii_case("delete") => "DELETE",
        _ => "WAL",
    }
}

/// The newest store schema version this build understands — the greatest
/// `version` in [`MIGRATIONS`]. `Store::open` applies every pending migration up
/// to this version, and **fails closed** on a database whose `schema_migrations`
/// ledger records a greater version: that database was written by a newer build,
/// and opening it anyway could misread or drop data this build does not know
/// about (DR-0054 Phase B — the downgrade guard).
pub const SUPPORTED_SCHEMA_VERSION: i64 = 2;

/// One numbered, idempotent schema migration (DR-0054 Phase C). Applied in
/// `version` order inside a single immediate transaction and recorded in
/// `schema_migrations`; an already-recorded version is never re-executed, so
/// re-opening a current store is a no-op. Evolution is additive by default —
/// a migration may create tables/indexes/rows but never rewrites or drops
/// admitted data.
struct Migration {
    version: i64,
    /// Diagnostic name (not persisted: the ledger's shape predates it and
    /// stays `(version, applied_at)` so existing databases need no alteration).
    name: &'static str,
    sql: &'static str,
}

/// The migration ledger. Version 1 is the base schema every pre-ledger database
/// already has (its `CREATE TABLE IF NOT EXISTS` batch makes it a no-op there);
/// each later version is an additive, idempotent step.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "base-store-schema",
        // Append-only event log (INV-6). `(scope_id, position)` is the per-scope
        // total order (INV-7). The remaining tables are the logical store profile:
        // immutable record revisions, out-of-line content metadata, operational
        // commands/observations, and rebuildable projection cursors (CORE-2).
        // `command_receipts` discharges INV-19 (AT_MOST_ONCE): a command carrying
        // an idempotency key is admitted at most once per scope — a replay of the
        // same `(scope, command_key)` is a no-op that returns the prior state.
        sql: "CREATE TABLE IF NOT EXISTS events (
                 scope_id TEXT    NOT NULL,
                 position INTEGER NOT NULL,
                 kind     TEXT    NOT NULL,
                 payload  TEXT    NOT NULL,
                 PRIMARY KEY (scope_id, position)
             );
             CREATE TABLE IF NOT EXISTS command_receipts (
                 scope_id    TEXT    NOT NULL,
                 command_key TEXT    NOT NULL,
                 applied_at  INTEGER NOT NULL,
                 PRIMARY KEY (scope_id, command_key)
             );
             CREATE TABLE IF NOT EXISTS scopes (
                 scope_id  TEXT PRIMARY KEY,
                 authority TEXT,
                 lifecycle TEXT,
                 subject_id TEXT
             );
             CREATE TABLE IF NOT EXISTS records (
                 record_id  TEXT    NOT NULL,
                 revision   INTEGER NOT NULL,
                 scope_id   TEXT    NOT NULL,
                 kind       TEXT    NOT NULL,
                 tombstone  INTEGER NOT NULL DEFAULT 0 CHECK (tombstone IN (0, 1)),
                 payload    TEXT    NOT NULL,
                 created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 PRIMARY KEY (record_id, revision)
             );
             CREATE INDEX IF NOT EXISTS records_scope_kind
                 ON records(scope_id, kind, record_id, revision);
             CREATE TABLE IF NOT EXISTS content (
                 handle      TEXT PRIMARY KEY,
                 resource_id TEXT,
                 sha256      TEXT,
                 size_bytes  INTEGER,
                 status      TEXT NOT NULL DEFAULT 'live'
                     CHECK (status IN ('live', 'tombstoned', 'unavailable')),
                 updated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE TABLE IF NOT EXISTS commands (
                 command_id      TEXT PRIMARY KEY,
                 scope_id       TEXT NOT NULL,
                 idempotency_key TEXT NOT NULL,
                 status         TEXT NOT NULL
                     CHECK (status IN ('received', 'processing', 'applied', 'rejected', 'expired')),
                 snapshot_json  TEXT NOT NULL,
                 updated_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 UNIQUE (scope_id, idempotency_key)
             );
             CREATE TABLE IF NOT EXISTS observations (
                 observation_id TEXT PRIMARY KEY,
                 run_ref        TEXT NOT NULL,
                 kind           TEXT NOT NULL,
                 payload_ref    TEXT,
                 admitted_scope TEXT,
                 admitted_position INTEGER,
                 created_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE TABLE IF NOT EXISTS projection_meta (
                 projection TEXT    NOT NULL,
                 scope_id   TEXT    NOT NULL,
                 version    INTEGER NOT NULL,
                 high_water INTEGER NOT NULL,
                 dirty      INTEGER NOT NULL DEFAULT 1 CHECK (dirty IN (0, 1)),
                 updated_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 PRIMARY KEY (projection, scope_id)
             );",
    },
    Migration {
        version: 2,
        name: "store-meta",
        // Additive: a key/value descriptor for the store itself, seeded with the
        // moment this database first reached v2. `INSERT OR IGNORE` keeps the
        // original value on every later re-open, so the step is idempotent.
        sql: "CREATE TABLE IF NOT EXISTS store_meta (
                 key        TEXT PRIMARY KEY,
                 value      TEXT NOT NULL,
                 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             INSERT OR IGNORE INTO store_meta(key, value)
                 VALUES ('created_at', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));",
    },
];

/// The fail-closed downgrade-guard error (DR-0054 Phase B): diagnosable — it
/// names the database, both versions, and the remediation (run the newer
/// build), never "reset the state root".
fn schema_ahead_error(path: &str, found: i64) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
        Some(format!(
            "store {path} records schema version {found}, but this build supports at most \
             {SUPPORTED_SCHEMA_VERSION}: a newer GaugeDesk wrote it. Refusing to open so no \
             data is misread or dropped — run a build at schema version {found} or newer \
             against this state root (do not reset it)."
        )),
    )
}

/// Read the decoded payload of a scope's last row of `kind`, inside an open
/// transaction — the predecessor a [`ChainedRecordFact`] links to. `None` when the
/// scope holds no row of that kind (the chain's genesis).
fn tx_chain_head(
    tx: &rusqlite::Transaction<'_>,
    codec: Option<&Arc<dyn ContentCodec>>,
    scope_id: &str,
    kind: &str,
) -> Result<Option<String>, AdmitError> {
    let raw: Option<String> = tx
        .query_row(
            "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 \
             ORDER BY position DESC LIMIT 1",
            params![scope_id, kind],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match (raw, codec) {
        (Some(raw), Some(codec)) => codec.decode(scope_id, kind, &raw),
        (Some(raw), None) => Some(raw),
        (None, _) => None,
    })
}

/// Process-unique suffixes for the scratch databases [`Store::open_in_memory`] mints.
static SCRATCH_STORES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The directory holding a scratch store's database, removed when the last
/// connection to it — original or [`sibling`](Store::sibling) — drops.
#[derive(Debug)]
struct ScratchHome(std::path::PathBuf);

impl Drop for ScratchHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Store {
    /// An ephemeral store for tests and scratch work: a real SQLite database in a
    /// temporary directory, deleted when the last connection to it drops.
    ///
    /// **Not** `Connection::open_in_memory()`, which gives each connection its own
    /// private database — a [`sibling`](Self::sibling) of one would silently be an
    /// empty store. A *named shared-cache* in-memory database shares data but takes
    /// table-level locks that `busy_timeout` does not retry, so concurrent writers
    /// fail with `SQLITE_LOCKED` instead of waiting. Backing onto a file is the only
    /// shape that gives scratch stores the same concurrency behaviour as production.
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let n = SCRATCH_STORES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("gaugewright-scratch-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|_| rusqlite::Error::InvalidPath(dir.clone()))?;
        let path = dir.join("store.db");
        let mut store = Self::open(
            path.to_str()
                .ok_or_else(|| rusqlite::Error::InvalidPath(path.clone()))?,
        )?;
        store.scratch = Some(Arc::new(ScratchHome(dir)));
        Ok(store)
    }

    /// A second connection to the same database, carrying the same content codec
    /// (`SECAUD-9/6`) so it encodes and decodes identically.
    ///
    /// This is what lets a long operation — an agent turn — hold durable state
    /// access without holding a process-wide lock over everything else. Per-scope
    /// serialization is the store's own job (immediate transactions + WAL +
    /// `busy_timeout`, see [`open`](Self::open)), not the caller's.
    pub fn sibling(&self) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(Duration::from_secs(30))?;
        // The original connection already established the database journal mode
        // and schema. Re-running `PRAGMA journal_mode` and `CREATE TABLE IF NOT
        // EXISTS` here turns every agent turn into an unnecessary schema writer;
        // under a live projection reader SQLite can reject that setup with BUSY
        // before the turn reaches its properly serialized IMMEDIATE transactions.
        // `synchronous` is connection-local, so carry that one setting explicitly.
        let sync = synchronous_mode(gaugedesk_env::var("SQLITE_SYNCHRONOUS").as_deref());
        conn.execute_batch(&format!("PRAGMA synchronous={sync};"))?;
        Ok(Self {
            conn,
            codec: self.codec.clone(),
            path: self.path.clone(),
            // Share the scratch directory's lifetime: an ephemeral database
            // outlives whichever connection drops first.
            scratch: self.scratch.clone(),
        })
    }

    /// The database this store is connected to.
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        // Install the busy timeout before changing journal state, so two
        // connections racing through initialization wait instead of failing
        // SQLITE_BUSY. WAL remains the local-disk default; an explicitly
        // single-writer hosted plane may select DELETE for a network filesystem.
        //
        // SCALE-5: set `synchronous` **explicitly** rather than leaning on SQLite's
        // default. `NORMAL` + WAL is crash-safe against an *application* crash and only
        // risks losing the most-recent commit(s) on an *OS/power* crash mid-checkpoint —
        // the right desktop default (no fsync per commit). A hosted/multi-user data plane
        // sets `GAUGEDESK_SQLITE_SYNCHRONOUS=FULL` for fsync-per-commit durability.
        // WAL auto-recovers (replays the log) on the next open, so no separate sweep.
        let sync = synchronous_mode(gaugedesk_env::var("SQLITE_SYNCHRONOUS").as_deref());
        let journal = journal_mode(gaugedesk_env::var("SQLITE_JOURNAL_MODE").as_deref());
        conn.busy_timeout(Duration::from_secs(30))?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode={journal}; PRAGMA synchronous={sync};"
        ))?;
        Self::init(conn, path.to_string())
    }

    /// The `synchronous` durability level (`SCALE-5`): the desktop default is **NORMAL**;
    /// `GAUGEDESK_SQLITE_SYNCHRONOUS=FULL` (case-insensitive) opts into fsync-per-commit
    /// for a hosted data plane. Any other/absent value → `NORMAL`. The current level is
    /// readable via [`synchronous`](Self::synchronous).
    pub fn synchronous(&self) -> Result<i64, rusqlite::Error> {
        self.conn.query_row("PRAGMA synchronous", [], |r| r.get(0))
    }

    /// Append one immutable declarative record revision. The revision is
    /// allocated under an immediate transaction, so concurrent writers cannot
    /// mint the same next revision. A tombstone is an ordinary revision.
    pub fn append_record_revision(
        &mut self,
        record_id: &str,
        scope_id: &str,
        kind: &str,
        payload: &str,
        tombstone: bool,
    ) -> Result<RecordRevision, AdmitError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision: i64 = tx.query_row(
            "SELECT COALESCE(MAX(revision), 0) + 1 FROM records WHERE record_id = ?1",
            params![record_id],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO records
             (record_id, revision, scope_id, kind, tombstone, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record_id,
                revision,
                scope_id,
                kind,
                i64::from(tombstone),
                payload
            ],
        )?;
        tx.commit()?;
        Ok(RecordRevision {
            record_id: record_id.to_owned(),
            scope_id: scope_id.to_owned(),
            kind: kind.to_owned(),
            revision,
            tombstone,
            payload: payload.to_owned(),
        })
    }

    /// All immutable revisions for a record, oldest first.
    pub fn record_history(&self, record_id: &str) -> Result<Vec<RecordRevision>, AdmitError> {
        let mut stmt = self.conn.prepare(
            "SELECT record_id, scope_id, kind, revision, tombstone, payload
             FROM records WHERE record_id = ?1 ORDER BY revision",
        )?;
        let rows = stmt.query_map(params![record_id], record_revision_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Latest revision, including a tombstone. Consumers decide whether a
    /// tombstoned record is visible; history is never collapsed.
    pub fn current_record(&self, record_id: &str) -> Result<Option<RecordRevision>, AdmitError> {
        self.conn
            .query_row(
                "SELECT record_id, scope_id, kind, revision, tombstone, payload
                 FROM records WHERE record_id = ?1 ORDER BY revision DESC LIMIT 1",
                params![record_id],
                record_revision_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Insert or update metadata for out-of-line protected bytes. This API does
    /// not write the bytes: callers stage and atomically place them first.
    pub fn put_content_metadata(&mut self, content: &ContentMetadata) -> Result<(), AdmitError> {
        self.conn.execute(
            "INSERT INTO content(handle, resource_id, sha256, size_bytes, status)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(handle) DO UPDATE SET
               resource_id = excluded.resource_id,
               sha256 = excluded.sha256,
               size_bytes = excluded.size_bytes,
               status = excluded.status,
               updated_at = CURRENT_TIMESTAMP",
            params![
                content.handle,
                content.resource_id,
                content.sha256,
                content.size_bytes,
                content.status
            ],
        )?;
        Ok(())
    }

    pub fn content_metadata(&self, handle: &str) -> Result<Option<ContentMetadata>, AdmitError> {
        self.conn
            .query_row(
                "SELECT handle, resource_id, sha256, size_bytes, status
                 FROM content WHERE handle = ?1",
                params![handle],
                |row| {
                    Ok(ContentMetadata {
                        handle: row.get(0)?,
                        resource_id: row.get(1)?,
                        sha256: row.get(2)?,
                        size_bytes: row.get(3)?,
                        status: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Create the operational receipt before command execution. Reusing an
    /// idempotency key returns the existing row and never replaces its snapshot.
    pub fn receive_command(
        &mut self,
        command_id: &str,
        scope_id: &str,
        idempotency_key: &str,
        snapshot_json: &str,
    ) -> Result<CommandRecord, AdmitError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO commands
             (command_id, scope_id, idempotency_key, status, snapshot_json)
             VALUES (?1, ?2, ?3, 'received', ?4)",
            params![command_id, scope_id, idempotency_key, snapshot_json],
        )?;
        self.command_by_key(scope_id, idempotency_key)?
            .ok_or_else(|| AdmitError::Db(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Preserve the first snapshot and atomically claim a newly received command
    /// for execution. The immediate transaction plus conditional status update
    /// ensures separate store connections cannot both run the same caller key.
    pub fn claim_command(
        &mut self,
        command_id: &str,
        scope_id: &str,
        idempotency_key: &str,
        snapshot_json: &str,
    ) -> Result<(CommandRecord, bool), AdmitError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO commands
             (command_id, scope_id, idempotency_key, status, snapshot_json)
             VALUES (?1, ?2, ?3, 'received', ?4)",
            params![command_id, scope_id, idempotency_key, snapshot_json],
        )?;
        let mut record = tx
            .query_row(
                "SELECT command_id, scope_id, idempotency_key, status, snapshot_json
                 FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2",
                params![scope_id, idempotency_key],
                command_record_from_row,
            )
            .optional()?
            .ok_or_else(|| AdmitError::Db(rusqlite::Error::QueryReturnedNoRows))?;
        let claimed = if record.snapshot_json == snapshot_json && record.status == "received" {
            tx.execute(
                "UPDATE commands SET status = 'processing', updated_at = CURRENT_TIMESTAMP
                 WHERE command_id = ?1 AND status = 'received'",
                params![record.command_id],
            )? == 1
        } else {
            false
        };
        if claimed {
            record.status = "processing".to_string();
        }
        tx.commit()?;
        Ok((record, claimed))
    }

    pub fn set_command_status(
        &mut self,
        command_id: &str,
        status: &str,
    ) -> Result<bool, AdmitError> {
        let changed = self.conn.execute(
            "UPDATE commands SET status = ?2, updated_at = CURRENT_TIMESTAMP
             WHERE command_id = ?1",
            params![command_id, status],
        )?;
        Ok(changed == 1)
    }

    pub fn command(&self, command_id: &str) -> Result<Option<CommandRecord>, AdmitError> {
        self.conn
            .query_row(
                "SELECT command_id, scope_id, idempotency_key, status, snapshot_json
                 FROM commands WHERE command_id = ?1",
                params![command_id],
                command_record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn command_for_key(
        &self,
        scope_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<CommandRecord>, AdmitError> {
        self.command_by_key(scope_id, idempotency_key)
    }

    fn command_by_key(
        &self,
        scope_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<CommandRecord>, AdmitError> {
        self.conn
            .query_row(
                "SELECT command_id, scope_id, idempotency_key, status, snapshot_json
                 FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2",
                params![scope_id, idempotency_key],
                command_record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Startup recovery for commands interrupted in `received`/`processing`.
    /// A committed idempotency receipt repairs the row to `applied`; without
    /// one, this profile expires it rather than replaying against mutable input.
    pub fn reconcile_commands(&mut self) -> Result<(usize, usize), AdmitError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (applied, expired) = {
            let mut stmt = tx.prepare(
                "SELECT command_id, scope_id, idempotency_key FROM commands
                 WHERE status IN ('received', 'processing')",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let mut applied = 0;
            let mut expired = 0;
            for row in rows {
                let (command_id, scope_id, key) = row?;
                let committed = tx
                    .query_row(
                        "SELECT 1 FROM command_receipts
                         WHERE scope_id = ?1 AND command_key = ?2",
                        params![scope_id, key],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                let status = if committed {
                    applied += 1;
                    "applied"
                } else {
                    expired += 1;
                    "expired"
                };
                tx.execute(
                    "UPDATE commands SET status = ?2, updated_at = CURRENT_TIMESTAMP
                     WHERE command_id = ?1",
                    params![command_id, status],
                )?;
            }
            (applied, expired)
        };
        tx.commit()?;
        Ok((applied, expired))
    }

    /// Application-facing command shell (CORE-2): preserve the first serialized
    /// command under the caller's idempotency key, drive operational status, and
    /// admit through the receipt-protected lifecycle transaction. A replay returns
    /// the current fold with `replayed = true`; reusing a key for different input
    /// fails closed instead of replacing the original materialized decision input.
    pub fn admit_materialized<L: Lifecycle>(
        &mut self,
        scope_id: &str,
        idempotency_key: &str,
        command: L::Command,
    ) -> Result<MaterializedAdmission<L::State>, AdmitError>
    where
        L::Command: serde::Serialize,
    {
        let snapshot = serde_json::to_string(&serde_json::json!({
            "kind": L::KIND,
            "command": &command,
        }))?;
        // Length-prefix the scope so distinct (scope, key) pairs cannot collide
        // in the commands table's globally unique command id.
        let command_id = format!("command:{}:{scope_id}{idempotency_key}", scope_id.len());
        let (receipt, claimed) =
            self.claim_command(&command_id, scope_id, idempotency_key, &snapshot)?;
        if receipt.snapshot_json != snapshot {
            return Err(AdmitError::Rejected(Rejection {
                reason: "idempotency key reused with different command",
            }));
        }
        let replayed = self
            .conn
            .query_row(
                "SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
                params![scope_id, idempotency_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if replayed {
            // Repair a command row whose receipt committed just before a process
            // interruption prevented its final status update.
            self.set_command_status(&command_id, "applied")?;
            return Ok(MaterializedAdmission {
                state: self.fold::<L>(scope_id)?,
                replayed: true,
            });
        }

        if !claimed {
            let reason = match receipt.status.as_str() {
                "rejected" => "command already rejected; submit with a new key",
                "expired" => "idempotency key expired; submit with a new key",
                "processing" => "command is already processing",
                "applied" => "applied command is missing its durable receipt",
                _ => "command could not be claimed",
            };
            return Err(AdmitError::Rejected(Rejection { reason }));
        }
        match self.admit_with_key::<L>(scope_id, idempotency_key, command) {
            Ok(state) => {
                self.set_command_status(&command_id, "applied")?;
                Ok(MaterializedAdmission {
                    state,
                    replayed: false,
                })
            }
            Err(AdmitError::Rejected(rejection)) => {
                self.set_command_status(&command_id, "rejected")?;
                Err(AdmitError::Rejected(rejection))
            }
            Err(error) => {
                // Best effort only: if this update itself fails, startup
                // reconciliation will expire the unreceipted processing row.
                let _ = self.set_command_status(&command_id, "expired");
                Err(error)
            }
        }
    }

    /// Atomically bind an exact caller command snapshot to one or more ordinary
    /// record facts and a durable receipt (`INV-19`). This is the record-plane
    /// sibling of [`admit_materialized`](Self::admit_materialized): retries of
    /// the same key and snapshot return the first receipt, a changed snapshot is
    /// rejected, and no partial prefix of `facts` can become visible.
    pub fn admit_record_facts(
        &mut self,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        facts: &[CommandRecordFact],
    ) -> Result<MaterializedRecordAdmission, AdmitError> {
        self.admit_record_facts_chained(command_scope, idempotency_key, snapshot_json, facts, None)
    }

    /// [`admit_record_facts`](Self::admit_record_facts) plus an optional
    /// [`ChainedRecordFact`] appended last, whose payload is resolved against its
    /// scope's committed head **inside this transaction**. That placement is the
    /// whole point: it closes the read-head-then-append window that would let two
    /// concurrent governed actions link to the same predecessor and fork a
    /// tamper-evident chain (`SECAUD-2`). A replayed command appends nothing and
    /// resolves no link.
    pub fn admit_record_facts_chained(
        &mut self,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        facts: &[CommandRecordFact],
        chained: Option<ChainedRecordFact<'_>>,
    ) -> Result<MaterializedRecordAdmission, AdmitError> {
        let stored: Result<Vec<CommandRecordFact>, AdmitError> = facts
            .iter()
            .map(|fact| {
                let payload = match &self.codec {
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
            .collect();
        let stored = stored?;
        let command_id = format!(
            "record-command:{}:{command_scope}{idempotency_key}",
            command_scope.len()
        );
        let codec = self.codec.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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

    pub fn put_projection_meta(&mut self, meta: &ProjectionMeta) -> Result<(), AdmitError> {
        self.conn.execute(
            "INSERT INTO projection_meta
             (projection, scope_id, version, high_water, dirty)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(projection, scope_id) DO UPDATE SET
               version = excluded.version,
               high_water = excluded.high_water,
               dirty = excluded.dirty,
               updated_at = CURRENT_TIMESTAMP",
            params![
                meta.projection,
                meta.scope_id,
                meta.version,
                meta.high_water,
                i64::from(meta.dirty)
            ],
        )?;
        Ok(())
    }

    pub fn projection_meta(
        &self,
        projection: &str,
        scope_id: &str,
    ) -> Result<Option<ProjectionMeta>, AdmitError> {
        self.conn
            .query_row(
                "SELECT projection, scope_id, version, high_water, dirty
                 FROM projection_meta WHERE projection = ?1 AND scope_id = ?2",
                params![projection, scope_id],
                |row| {
                    Ok(ProjectionMeta {
                        projection: row.get(0)?,
                        scope_id: row.get(1)?,
                        version: row.get(2)?,
                        high_water: row.get(3)?,
                        dirty: row.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Upsert the stable scope descriptor used by operational/profile tables.
    /// Event admission remains source-of-truth even if a legacy scope has no row.
    pub fn put_scope(
        &mut self,
        scope_id: &str,
        authority: Option<&str>,
        lifecycle: Option<&str>,
        subject_id: Option<&str>,
    ) -> Result<(), AdmitError> {
        self.conn.execute(
            "INSERT INTO scopes(scope_id, authority, lifecycle, subject_id)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(scope_id) DO UPDATE SET
               authority = excluded.authority,
               lifecycle = excluded.lifecycle,
               subject_id = excluded.subject_id",
            params![scope_id, authority, lifecycle, subject_id],
        )?;
        Ok(())
    }

    /// Record operational evidence without granting it lifecycle authority.
    /// Reusing the id is idempotent and never swaps the original correlation.
    pub fn record_observation(
        &mut self,
        observation_id: &str,
        run_ref: &str,
        kind: &str,
        payload_ref: Option<&str>,
    ) -> Result<ObservationRecord, AdmitError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO observations
             (observation_id, run_ref, kind, payload_ref)
             VALUES (?1, ?2, ?3, ?4)",
            params![observation_id, run_ref, kind, payload_ref],
        )?;
        self.observation(observation_id)?
            .ok_or_else(|| AdmitError::Db(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Link operational evidence to the already-admitted event that made it
    /// product truth. The event must exist; no event is invented here.
    pub fn admit_observation(
        &mut self,
        observation_id: &str,
        scope_id: &str,
        position: i64,
    ) -> Result<bool, AdmitError> {
        let event_exists = self
            .conn
            .query_row(
                "SELECT 1 FROM events WHERE scope_id = ?1 AND position = ?2",
                params![scope_id, position],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !event_exists {
            return Ok(false);
        }
        let changed = self.conn.execute(
            "UPDATE observations
             SET admitted_scope = ?2, admitted_position = ?3
             WHERE observation_id = ?1
               AND admitted_scope IS NULL AND admitted_position IS NULL",
            params![observation_id, scope_id, position],
        )?;
        Ok(changed == 1)
    }

    pub fn observation(
        &self,
        observation_id: &str,
    ) -> Result<Option<ObservationRecord>, AdmitError> {
        self.conn
            .query_row(
                "SELECT observation_id, run_ref, kind, payload_ref,
                        admitted_scope, admitted_position
                 FROM observations WHERE observation_id = ?1",
                params![observation_id],
                |row| {
                    Ok(ObservationRecord {
                        observation_id: row.get(0)?,
                        run_ref: row.get(1)?,
                        kind: row.get(2)?,
                        payload_ref: row.get(3)?,
                        admitted_scope: row.get(4)?,
                        admitted_position: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// The greatest schema version recorded in this store's `schema_migrations`
    /// ledger — after a successful open, always [`SUPPORTED_SCHEMA_VERSION`]
    /// (open applies every pending migration and refuses a newer database).
    pub fn schema_version(&self) -> Result<i64, rusqlite::Error> {
        self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
    }

    /// Open-time schema handshake (DR-0054 Phase B/C): read the recorded schema
    /// version, refuse a database written by a newer build (the downgrade
    /// guard), then apply every pending migration from [`MIGRATIONS`] in order —
    /// inside one immediate transaction, each recorded in `schema_migrations`,
    /// idempotent on re-run.
    ///
    /// A database with **no** `schema_migrations` table is pre-v1 (the schema
    /// every build has implicitly written since v1): it reads as version 0 and
    /// is brought current by the ledger, not treated as an error — v1's
    /// `CREATE TABLE IF NOT EXISTS` batch is a no-op over its existing tables
    /// and records it as v1.
    fn init(mut conn: Connection, path: String) -> Result<Self, rusqlite::Error> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version    INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );",
        )?;
        let recorded: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?;
        if recorded > SUPPORTED_SCHEMA_VERSION {
            return Err(schema_ahead_error(&path, recorded));
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for migration in MIGRATIONS {
            let applied = tx
                .query_row(
                    "SELECT 1 FROM schema_migrations WHERE version = ?1",
                    [migration.version],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if applied {
                continue;
            }
            tx.execute_batch(migration.sql).map_err(|e| {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                    Some(format!(
                        "store {path} migration v{} ({}) failed: {e}",
                        migration.version, migration.name
                    )),
                )
            })?;
            tx.execute(
                "INSERT INTO schema_migrations(version) VALUES (?1)",
                [migration.version],
            )?;
        }
        tx.commit()?;
        Ok(Self {
            conn,
            codec: None,
            path,
            scratch: None,
        })
    }

    /// Fold a lifecycle's events within a scope into current state (`INV-8`:
    /// state is the fold). Events are filtered by `L::KIND` so distinct
    /// lifecycles (a run, its review, its export) can coexist in one scope.
    pub fn fold<L: Lifecycle>(&self, scope_id: &str) -> Result<L::State, AdmitError> {
        let mut stmt = self.conn.prepare(
            "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 ORDER BY position",
        )?;
        let rows = stmt.query_map(params![scope_id, L::KIND], |r| r.get::<_, String>(0))?;
        let mut state = L::State::default();
        for row in rows {
            let event: L::Event = serde_json::from_str(&row?)?;
            state = L::evolve(&state, event);
        }
        Ok(state)
    }

    /// Append a durable **record** (non-lifecycle admitted evidence — e.g. a
    /// transcript message) at the next position in a scope. Same append-only log,
    /// single-writer per scope (`INV-6`/`INV-7`); these are facts, not reducer events.
    /// Returns the assigned `position` — a monotonic per-scope sequence the library
    /// projection uses for "Recent" ordering and latest-wins tombstones.
    pub fn append_record(
        &mut self,
        scope_id: &str,
        kind: &str,
        payload: &str,
    ) -> Result<i64, AdmitError> {
        // SECAUD-9/6: a configured content codec transparently encrypts content kinds
        // at rest (non-content kinds pass through). `None` ⇒ plaintext (the default).
        let stored = match &self.codec {
            Some(codec) => codec
                .encode(scope_id, kind, payload)
                .map_err(AdmitError::Codec)?,
            None => payload.to_string(),
        };
        // Immediate (sqlite-local-store.md): take the write lock up front so the
        // MAX(position) read and the insert are one atomic write, even if another
        // connection ever shares this file (INV-7 single-writer per scope).
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let position: i64 = tx.query_row(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            params![scope_id],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            params![scope_id, position, kind, stored],
        )?;
        tx.commit()?;
        Ok(position)
    }

    /// Append one [`ChainedRecordFact`] whose payload is resolved against the
    /// scope's committed head **inside** the write transaction that appends it —
    /// the standalone sibling of
    /// [`admit_record_facts_chained`](Self::admit_record_facts_chained), for
    /// governed actions with no domain facts to ride along with. Returns the
    /// appended position and the payload the link produced.
    ///
    /// Computing the link outside this transaction would reopen the fork window
    /// (`SECAUD-2`): two writers reading the same head both link to it, and the
    /// chain silently branches.
    pub fn append_chained_record(
        &mut self,
        scope_id: &str,
        kind: &str,
        link: &dyn Fn(Option<&str>) -> String,
    ) -> Result<(i64, String), AdmitError> {
        let codec = self.codec.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = tx_chain_head(&tx, codec.as_ref(), scope_id, kind)?;
        let payload = link(previous.as_deref());
        let stored = match &codec {
            Some(codec) => codec
                .encode(scope_id, kind, &payload)
                .map_err(AdmitError::Codec)?,
            None => payload.clone(),
        };
        let position: i64 = tx.query_row(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            params![scope_id],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            params![scope_id, position, kind, stored],
        )?;
        tx.commit()?;
        Ok((position, payload))
    }

    /// Append several record facts as one SQLite commit, even when they span
    /// scopes. Used when two projections jointly express one authoritative
    /// transition (for example handoff commit + project Home binding).
    pub fn append_records_atomically(
        &mut self,
        records: &[(&str, &str, &str)],
    ) -> Result<Vec<i64>, AdmitError> {
        let stored: Result<Vec<(&str, &str, String)>, AdmitError> = records
            .iter()
            .map(|(scope, kind, payload)| {
                let payload = match &self.codec {
                    Some(codec) => codec
                        .encode(scope, kind, payload)
                        .map_err(AdmitError::Codec)?,
                    None => (*payload).to_owned(),
                };
                Ok((*scope, *kind, payload))
            })
            .collect();
        let stored = stored?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut positions = Vec::with_capacity(stored.len());
        for (scope, kind, payload) in stored {
            let position: i64 = tx.query_row(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
                params![scope],
                |row| row.get(0),
            )?;
            tx.execute(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
                params![scope, position, kind, payload],
            )?;
            positions.push(position);
        }
        tx.commit()?;
        Ok(positions)
    }

    /// Atomically append one non-lifecycle record under an idempotency key.
    /// The returned tuple is `(position, inserted)`: a replay returns the
    /// original assigned position and `false` without duplicating the pointer.
    pub fn append_record_with_key(
        &mut self,
        scope_id: &str,
        command_key: &str,
        kind: &str,
        payload: &str,
    ) -> Result<(i64, bool), AdmitError> {
        let stored = match &self.codec {
            Some(codec) => codec
                .encode(scope_id, kind, payload)
                .map_err(AdmitError::Codec)?,
            None => payload.to_string(),
        };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(position) = tx
            .query_row(
                "SELECT applied_at FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
                params![scope_id, command_key],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        {
            tx.commit()?;
            return Ok((position, false));
        }
        let position: i64 = tx.query_row(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            params![scope_id],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            params![scope_id, position, kind, stored],
        )?;
        tx.execute(
            "INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)",
            params![scope_id, command_key, position],
        )?;
        tx.commit()?;
        Ok((position, true))
    }

    /// All records of one `kind` in a scope, in order — a durable projection
    /// source (e.g. the transcript snapshot). A content codec (`SECAUD-9/6`) decodes
    /// each row; a crypto-erased row (`decode` ⇒ `None`) is dropped (content gone).
    pub fn records(&self, scope_id: &str, kind: &str) -> Result<Vec<String>, AdmitError> {
        let mut stmt = self.conn.prepare(
            "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 ORDER BY position",
        )?;
        let rows = stmt.query_map(params![scope_id, kind], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let payload = row?;
            match &self.codec {
                Some(codec) => {
                    if let Some(plain) = codec.decode(scope_id, kind, &payload) {
                        out.push(plain);
                    }
                }
                None => out.push(payload),
            }
        }
        Ok(out)
    }

    /// The full event history for a scope, in order — the audit timeline
    /// (`INV-6`: the log is append-only and is the record). Returns
    /// `(position, kind, payload)` rows across all lifecycles in the scope. A content
    /// codec decodes content kinds; a crypto-erased content row is dropped.
    pub fn events(&self, scope_id: &str) -> Result<Vec<(i64, String, String)>, AdmitError> {
        let mut stmt = self.conn.prepare(
            "SELECT position, kind, payload FROM events WHERE scope_id = ?1 ORDER BY position",
        )?;
        let rows = stmt.query_map(params![scope_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (pos, kind, payload) = row?;
            match &self.codec {
                Some(codec) => {
                    if let Some(plain) = codec.decode(scope_id, &kind, &payload) {
                        out.push((pos, kind, plain));
                    }
                }
                None => out.push((pos, kind, payload)),
            }
        }
        Ok(out)
    }

    /// Monotonic high-water cursor for every admitted scope. Migration and
    /// backup verification use this compact projection to prove that no scope
    /// was truncated without reading or exporting content bodies.
    pub fn scope_high_water_marks(
        &self,
    ) -> Result<std::collections::BTreeMap<String, i64>, AdmitError> {
        let mut statement = self.conn.prepare(
            "SELECT scope_id, MAX(position) FROM events GROUP BY scope_id ORDER BY scope_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut cursors = std::collections::BTreeMap::new();
        for row in rows {
            let (scope, position) = row?;
            cursors.insert(scope, position);
        }
        Ok(cursors)
    }

    /// Attach a [`ContentCodec`] (`SECAUD-9/6`) — transparent at-rest encryption of
    /// content kinds under per-scope keys. Builder; without one the store is plaintext.
    pub fn with_codec(mut self, codec: Arc<dyn ContentCodec>) -> Self {
        self.codec = Some(codec);
        self
    }

    /// Every distinct scope id present in the log, ordered. The seam for capturing a
    /// subtree (e.g. a project's owned scopes for relocation) without a separate index.
    pub fn scope_ids(&self) -> Result<Vec<String>, AdmitError> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT scope_id FROM events ORDER BY scope_id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Admit one command into a scope: fold → `decide` → append atomically
    /// (single-writer per scope, `INV-7`; rejection appends nothing, `INV-2`).
    ///
    /// The fold happens **inside** the immediate write transaction (not before
    /// it), so the whole fold→decide→append is one serializable unit per scope:
    /// two connections racing the same scope cannot both `decide` against stale
    /// state and both append (the immediate lock makes the second fold observe
    /// the first's committed events). Within one process the workbench mutex
    /// already serializes admits; this keeps the guarantee true at the store
    /// itself, under genuine multi-connection contention (RF-C7).
    pub fn admit<L: Lifecycle>(
        &mut self,
        scope_id: &str,
        command: L::Command,
    ) -> Result<L::State, AdmitError> {
        // Immediate (sqlite-local-store.md step 3): take the write lock up front so
        // the fold, the position read, and the multi-event append are one atomic,
        // non-interleavable unit per scope (INV-7/INV-22).
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Fold the scope's current state from *committed* events, inside the lock.
        let state = {
            let mut stmt = tx.prepare(
                "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 ORDER BY position",
            )?;
            let rows = stmt.query_map(params![scope_id, L::KIND], |r| r.get::<_, String>(0))?;
            let mut s = L::State::default();
            for row in rows {
                let event: L::Event = serde_json::from_str(&row?)?;
                s = L::evolve(&s, event);
            }
            s
        };
        let events = L::decide(&state, command).map_err(AdmitError::Rejected)?;

        // Next position is global per scope so the per-scope order is total
        // across all lifecycles, even though the fold filters by kind.
        let base: i64 = tx.query_row(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            params![scope_id],
            |r| r.get(0),
        )?;
        let mut new_state = state;
        for (offset, event) in events.into_iter().enumerate() {
            let position = base + offset as i64;
            let payload = serde_json::to_string(&event)?;
            tx.execute(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
                params![scope_id, position, L::KIND, payload],
            )?;
            new_state = L::evolve(&new_state, event);
        }
        tx.commit()?;
        Ok(new_state)
    }

    /// Idempotent admission (`INV-19`, `AT_MOST_ONCE`): admit `command` under a
    /// caller-supplied `command_key` that uniquely names *this* command attempt.
    /// A first attempt applies exactly like [`Self::admit`] and records a receipt;
    /// a **replay** of the same `(scope, command_key)` — a retried request, a
    /// double-submit — is a no-op that returns the scope's current state without
    /// appending again. The receipt check, the fold, the decide, and the append
    /// all happen inside one immediate transaction, so even two connections
    /// racing the same key admit it at most once (the loser sees the committed
    /// receipt and no-ops). Use this for any command reachable via an at-least-once
    /// delivery path (client retries, federated re-delivery); `admit` stays the
    /// path for commands with no natural key.
    pub fn admit_with_key<L: Lifecycle>(
        &mut self,
        scope_id: &str,
        command_key: &str,
        command: L::Command,
    ) -> Result<L::State, AdmitError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Fold inside the lock (same serializability as `admit`, RF-C12).
        let fold = |tx: &rusqlite::Transaction| -> Result<L::State, AdmitError> {
            let mut stmt = tx.prepare(
                "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 ORDER BY position",
            )?;
            let rows = stmt.query_map(params![scope_id, L::KIND], |r| r.get::<_, String>(0))?;
            let mut s = L::State::default();
            for row in rows {
                let event: L::Event = serde_json::from_str(&row?)?;
                s = L::evolve(&s, event);
            }
            Ok(s)
        };

        // Already applied this key? Idempotent no-op: return current state.
        let seen: bool = tx
            .query_row(
                "SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
                params![scope_id, command_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if seen {
            let state = fold(&tx)?;
            tx.commit()?;
            return Ok(state);
        }

        let state = fold(&tx)?;
        let events = L::decide(&state, command).map_err(AdmitError::Rejected)?;
        let base: i64 = tx.query_row(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            params![scope_id],
            |r| r.get(0),
        )?;
        let mut new_state = state;
        for (offset, event) in events.into_iter().enumerate() {
            let position = base + offset as i64;
            let payload = serde_json::to_string(&event)?;
            tx.execute(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
                params![scope_id, position, L::KIND, payload],
            )?;
            new_state = L::evolve(&new_state, event);
        }
        // Record the receipt only on a *successful* (non-rejected) admission, in
        // the same transaction — so a rejected command leaves no receipt and can
        // be legitimately retried, while an accepted one is sealed against replay.
        tx.execute(
            "INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)",
            params![scope_id, command_key, base],
        )?;
        tx.commit()?;
        Ok(new_state)
    }
}

fn record_revision_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RecordRevision> {
    Ok(RecordRevision {
        record_id: row.get(0)?,
        scope_id: row.get(1)?,
        kind: row.get(2)?,
        revision: row.get(3)?,
        tombstone: row.get::<_, i64>(4)? != 0,
        payload: row.get(5)?,
    })
}

fn command_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CommandRecord> {
    Ok(CommandRecord {
        command_id: row.get(0)?,
        scope_id: row.get(1)?,
        idempotency_key: row.get(2)?,
        status: row.get(3)?,
        snapshot_json: row.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::managed_machine_execution::{
        ExecutionCapability, ExecutionPhase, ExecutionProfile, ExecutionRequest,
        ExecutionResourceBounds, ManagedExecutionCommand, ManagedExecutionState,
        WorkspaceAuthorization,
    };
    use gaugedesk_core::resource_export::{ExportCommand, ExportPhase, ExportState};
    use gaugedesk_core::review::{ReviewCommand, ReviewPhase, ReviewState};
    use gaugedesk_core::run::{RunCommand::*, RunPhase, RunState};
    use std::collections::BTreeSet;

    #[test]
    fn synchronous_mode_defaults_to_normal_and_opts_into_full(/* SCALE-5 */) {
        assert_eq!(synchronous_mode(None), "NORMAL");
        assert_eq!(synchronous_mode(Some("")), "NORMAL");
        assert_eq!(synchronous_mode(Some("garbage")), "NORMAL");
        // FULL is the hosted-plane opt-in (case-insensitive, trimmed).
        assert_eq!(synchronous_mode(Some("FULL")), "FULL");
        assert_eq!(synchronous_mode(Some("  full  ")), "FULL");
    }

    #[test]
    fn journal_mode_defaults_to_wal_and_explicitly_allows_single_writer_delete() {
        assert_eq!(journal_mode(None), "WAL");
        assert_eq!(journal_mode(Some("")), "WAL");
        assert_eq!(journal_mode(Some("garbage")), "WAL");
        assert_eq!(journal_mode(Some("DELETE")), "DELETE");
        assert_eq!(journal_mode(Some("  delete  ")), "DELETE");
    }

    #[test]
    fn a_file_store_sets_synchronous_normal_explicitly(/* SCALE-5 */) {
        // The desktop default is NORMAL (1): crash-safe against an app crash, no fsync per
        // commit. (Env-override → FULL is covered by the pure-helper test above, without an
        // env race.) An in-memory store keeps the SQLite default, so this uses a real file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("durability.db");
        let path = path.to_str().unwrap().to_string();
        let store = Store::open(&path).unwrap();
        assert_eq!(store.synchronous().unwrap(), 1, "NORMAL == 1");
    }

    /// DR-0054 Phase C: a fresh store is created *by* the migration ledger —
    /// every migration applied in order, each recorded, and the exercised v2
    /// step's artifact (`store_meta.created_at`) is really there.
    #[test]
    fn open_applies_and_records_every_migration_in_order() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
        let versions: Vec<i64> = store
            .conn
            .prepare("SELECT version FROM schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(versions, vec![1, 2], "each migration recorded exactly once");
        let created_at: String = store
            .conn
            .query_row(
                "SELECT value FROM store_meta WHERE key = 'created_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            created_at.ends_with('Z'),
            "v2 seeded a real created-at timestamp: {created_at}"
        );
    }

    /// DR-0054 Phase C gate: re-opening a current store re-runs the ledger as a
    /// no-op — no duplicate rows, no re-executed step (the v2 seed keeps its
    /// original value), and admitted data is untouched.
    #[test]
    fn reopening_a_current_store_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idempotent.db");
        let path = path.to_str().unwrap().to_string();
        let created_at: String = {
            let mut store = Store::open(&path).unwrap();
            store.append_record("scope", "evt", "kept").unwrap();
            store
                .conn
                .query_row(
                    "SELECT value FROM store_meta WHERE key = 'created_at'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        for _ in 0..2 {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
            let rows: i64 = store
                .conn
                .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
                .unwrap();
            assert_eq!(rows, 2, "no duplicate ledger rows on re-open");
            let still: String = store
                .conn
                .query_row(
                    "SELECT value FROM store_meta WHERE key = 'created_at'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(still, created_at, "the v2 seed is not re-executed");
            assert_eq!(store.records("scope", "evt").unwrap(), vec!["kept"]);
        }
    }

    /// DR-0054 Phase C: a database standing at v1 (the shape every pre-ledger
    /// build wrote) is upgraded additively — v2 applies and is recorded, and
    /// the admitted events are byte-for-byte untouched.
    #[test]
    fn a_v1_database_upgrades_additively_to_current() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.db");
        let path = path.to_str().unwrap().to_string();
        {
            let mut store = Store::open(&path).unwrap();
            store.append_record("scope", "evt", "pre-upgrade").unwrap();
            // Rewind to exactly what a v1 build left behind: ledger at 1, no v2 artifacts.
            store
                .conn
                .execute_batch(
                    "DELETE FROM schema_migrations WHERE version > 1; DROP TABLE store_meta;",
                )
                .unwrap();
            assert_eq!(store.schema_version().unwrap(), 1);
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
        assert_eq!(store.records("scope", "evt").unwrap(), vec!["pre-upgrade"]);
        let seeded: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM store_meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(seeded, 1, "v2 applied on upgrade");
    }

    /// DR-0054 Phase B: a database with **no** `schema_migrations` table but
    /// existing data is pre-v1, not an error — it is recorded as v1 (the schema
    /// it implicitly has) and brought current, with its data preserved.
    #[test]
    fn a_pre_ledger_database_is_recorded_as_v1_and_brought_current() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pre-v1.db");
        let path = path.to_str().unwrap().to_string();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (
                     scope_id TEXT NOT NULL, position INTEGER NOT NULL,
                     kind TEXT NOT NULL, payload TEXT NOT NULL,
                     PRIMARY KEY (scope_id, position)
                 );
                 INSERT INTO events(scope_id, position, kind, payload)
                     VALUES ('scope', 0, 'evt', 'ancient');",
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
        assert_eq!(store.records("scope", "evt").unwrap(), vec!["ancient"]);
        let v1_recorded: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v1_recorded, 1, "the implicit schema is recorded as v1");
    }

    /// DR-0054 Phase B — the downgrade guard: a database recording a schema
    /// version newer than this build fails closed with a diagnosable error that
    /// names both versions and never suggests resetting the state root.
    #[test]
    fn a_newer_schema_database_fails_closed_with_a_diagnosable_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("from-the-future.db");
        let path = path.to_str().unwrap().to_string();
        {
            let mut store = Store::open(&path).unwrap();
            store
                .append_record("scope", "evt", "newer-build-data")
                .unwrap();
            store
                .conn
                .execute("INSERT INTO schema_migrations(version) VALUES (999)", [])
                .unwrap();
        }
        let error = match Store::open(&path) {
            Ok(_) => panic!("a newer schema must refuse to open"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("999") && message.contains(&SUPPORTED_SCHEMA_VERSION.to_string()),
            "the error names both versions: {message}"
        );
        assert!(
            message.contains("Refusing to open") && message.contains("do not reset"),
            "the remediation is the newer build, never a reset: {message}"
        );
        // Failing closed changed nothing: the newer build's database still opens there.
        let conn = Connection::open(&path).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "the refused open wrote nothing");
    }

    #[test]
    fn sibling_reuses_initialized_schema_and_connection_policy() {
        let mut store = Store::open_in_memory().unwrap();
        store.append_record("scope", "seed", "one").unwrap();

        let mut sibling = store.sibling().unwrap();
        assert_eq!(sibling.synchronous().unwrap(), store.synchronous().unwrap());
        assert_eq!(sibling.records("scope", "seed").unwrap().len(), 1);
        sibling.append_record("scope", "seed", "two").unwrap();
        assert_eq!(store.records("scope", "seed").unwrap().len(), 2);
    }

    #[test]
    fn multi_scope_record_append_rolls_back_as_one_unit() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_test_scope BEFORE INSERT ON events
                 WHEN NEW.scope_id = 'reject' BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        let result = store.append_records_atomically(&[
            ("handoff::p", "handoff", "committed"),
            ("reject", "project", "new-home"),
        ]);
        assert!(result.is_err());
        assert!(store.records("handoff::p", "handoff").unwrap().is_empty());
        assert!(store.records("reject", "project").unwrap().is_empty());
    }

    /// RF-C7: per-scope single-writer (INV-7) under REAL contention — many
    /// connections to the same file, all appending into one scope. The
    /// immediate transaction + busy_timeout must serialize them into one
    /// gapless total order, never SQLITE_BUSY, never a duplicate position.
    #[test]
    fn concurrent_appends_from_many_connections_keep_one_total_order() {
        const THREADS: usize = 8;
        const APPENDS: usize = 25;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contended.db");
        let path = path.to_str().unwrap().to_string();
        let _prime = Store::open(&path).unwrap(); // create the schema once

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let p = path.clone();
                std::thread::spawn(move || {
                    let mut store = Store::open(&p).unwrap();
                    let mut positions = Vec::with_capacity(APPENDS);
                    for i in 0..APPENDS {
                        positions.push(
                            store
                                .append_record("scope-contended", "evt", &format!("t{t}-{i}"))
                                .expect("a contended append must wait, not fail"),
                        );
                    }
                    positions
                })
            })
            .collect();
        let mut all_positions: Vec<i64> = Vec::new();
        for h in handles {
            all_positions.extend(h.join().unwrap());
        }

        // One gapless per-scope total order across every writer: positions are
        // exactly 0..N*M with no duplicate and no hole (INV-6/INV-7).
        all_positions.sort_unstable();
        let expected: Vec<i64> = (0..(THREADS * APPENDS) as i64).collect();
        assert_eq!(all_positions, expected);

        let store = Store::open(&path).unwrap();
        let all = store.records("scope-contended", "evt").unwrap();
        assert_eq!(all.len(), THREADS * APPENDS);
    }

    /// A tiny deterministic hash, standing in for the audit chain's SHA-256 so the
    /// store test needs no crypto dependency.
    fn fnv(s: &str) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325_u64;
        for b in s.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// SECAUD-2 under REAL contention: many connections appending chained records
    /// into one scope must produce a single unbroken chain. Resolving the link
    /// *outside* the write transaction — read the head, then append — lets two
    /// writers observe the same predecessor and both link to it, silently forking
    /// the chain. Each row here must name exactly the row before it.
    #[test]
    fn concurrent_chained_appends_never_fork_the_chain() {
        const THREADS: usize = 8;
        const APPENDS: usize = 25;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chained.db");
        let path = path.to_str().unwrap().to_string();
        let _prime = Store::open(&path).unwrap();

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let p = path.clone();
                std::thread::spawn(move || {
                    let mut store = Store::open(&p).unwrap();
                    for i in 0..APPENDS {
                        let tag = format!("t{t}-{i}");
                        let link = |previous: Option<&str>| {
                            format!("{}|{tag}", previous.map(fnv).unwrap_or(0))
                        };
                        store
                            .append_chained_record("chain", "entry", &link)
                            .expect("a contended chained append must wait, not fail");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let store = Store::open(&path).unwrap();
        let rows = store.records("chain", "entry").unwrap();
        assert_eq!(rows.len(), THREADS * APPENDS);

        // Walk the chain in position order: every row's declared predecessor must
        // be the row that actually precedes it. A fork breaks this at the join.
        let mut expected = 0_u64;
        for (i, row) in rows.iter().enumerate() {
            let declared: u64 = row
                .split_once('|')
                .expect("a chained row carries its link")
                .0
                .parse()
                .expect("the link is a hash");
            assert_eq!(
                declared, expected,
                "row {i} links to the wrong predecessor — the chain forked"
            );
            expected = fnv(row);
        }
    }

    /// A sibling reaches the same data — including in memory, which is the whole
    /// reason `open_in_memory` names its database instead of taking the anonymous
    /// one. An anonymous in-memory sibling would silently be an empty store.
    #[test]
    fn a_sibling_connection_shares_the_same_database() {
        let mut store = Store::open_in_memory().unwrap();
        store.append_record("s", "evt", "one").unwrap();

        let mut sibling = store.sibling().unwrap();
        assert_eq!(
            sibling.records("s", "evt").unwrap(),
            vec!["one".to_string()]
        );

        sibling.append_record("s", "evt", "two").unwrap();
        assert_eq!(
            store.records("s", "evt").unwrap(),
            vec!["one".to_string(), "two".to_string()],
            "the original connection sees the sibling's committed write"
        );
    }

    /// Two in-memory stores are still independent: naming the database must not
    /// accidentally pool every test's store into one shared database.
    #[test]
    fn separate_in_memory_stores_stay_isolated() {
        let mut a = Store::open_in_memory().unwrap();
        let b = Store::open_in_memory().unwrap();
        a.append_record("s", "evt", "only-in-a").unwrap();
        assert!(b.records("s", "evt").unwrap().is_empty());
    }

    /// The sibling path under contention: many connections onto one in-memory
    /// database must serialize through the same immediate-transaction spine a file
    /// store uses, never failing on a shared-cache table lock.
    #[test]
    fn concurrent_writes_across_in_memory_siblings_keep_one_total_order() {
        const THREADS: usize = 4;
        const APPENDS: usize = 25;

        let store = Store::open_in_memory().unwrap();
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let mut sibling = store.sibling().unwrap();
                std::thread::spawn(move || {
                    let mut positions = Vec::with_capacity(APPENDS);
                    for i in 0..APPENDS {
                        positions.push(
                            sibling
                                .append_record("contended", "evt", &format!("t{t}-{i}"))
                                .expect("a contended sibling append must wait, not fail"),
                        );
                    }
                    positions
                })
            })
            .collect();

        let mut all: Vec<i64> = Vec::new();
        for h in handles {
            all.extend(h.join().unwrap());
        }
        all.sort_unstable();
        assert_eq!(all, (0..(THREADS * APPENDS) as i64).collect::<Vec<_>>());
        assert_eq!(
            store.records("contended", "evt").unwrap().len(),
            THREADS * APPENDS
        );
    }

    /// RF-C7 (lifecycle path): concurrent `admit` calls race one run lifecycle;
    /// the decide-inside-the-write-lock spine must let exactly ONE RequestRun
    /// through and reject the rest, no matter the interleaving.
    #[test]
    fn concurrent_admits_settle_one_winner_per_lifecycle_step() {
        const THREADS: usize = 8;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admit-race.db");
        let path = path.to_str().unwrap().to_string();
        let _prime = Store::open(&path).unwrap();

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || {
                    let mut store = Store::open(&p).unwrap();
                    store.admit::<RunState>("run-race", RequestRun).is_ok()
                })
            })
            .collect();
        let wins = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|won| *won)
            .count();

        // Exactly one RequestRun was admitted; every loser was REJECTED by
        // decide (a verdict), not failed by the database (an error).
        assert_eq!(wins, 1, "exactly one concurrent RequestRun may win");
        let store = Store::open(&path).unwrap();
        let s = store.fold::<RunState>("run-race").unwrap();
        assert_eq!(s.phase, RunPhase::Requested);
    }

    /// RF-A10 / INV-19: a command admitted under a key applies once; a replay of
    /// the same key is a no-op returning the current state (AT_MOST_ONCE).
    #[test]
    fn admit_with_key_is_idempotent_on_replay() {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "idem-run";

        // First attempt applies RequestRun.
        let s = store
            .admit_with_key::<RunState>(scope, "req-key-1", RequestRun)
            .unwrap();
        assert_eq!(s.phase, RunPhase::Requested);

        // A replay of the SAME key is a no-op — no second event appended, the
        // phase is unchanged, and it does NOT error (it returns the current state).
        let s = store
            .admit_with_key::<RunState>(scope, "req-key-1", RequestRun)
            .unwrap();
        assert_eq!(s.phase, RunPhase::Requested, "replay must not advance");
        assert_eq!(
            store.records(scope, RunState::KIND).unwrap().len(),
            1,
            "replay appended no second event (AT_MOST_ONCE)"
        );

        // A DIFFERENT key for the next legitimate command applies normally.
        let s = store
            .admit_with_key::<RunState>(scope, "admit-key-1", AdmitRun)
            .unwrap();
        assert_eq!(s.phase, RunPhase::Admitted);
    }

    fn workspace_execution_request() -> ExecutionRequest {
        ExecutionRequest {
            home_id: "home-a".into(),
            tenant_id: "tenant-a".into(),
            project_id: "project-a".into(),
            work_target_basis: "basis:abc".into(),
            command_id: "command-a".into(),
            payload_digest: "sha256:payload-a".into(),
            profile: ExecutionProfile::IsolatedWorkspace,
            required_capabilities: [ExecutionCapability::Workspace, ExecutionCapability::Process]
                .into_iter()
                .collect(),
            credential_class: "private-home:openai".into(),
            bounds: ExecutionResourceBounds {
                max_vcpus: 2,
                max_memory_mib: 8_192,
                max_disk_mib: 16_384,
                max_wall_seconds: 1_800,
                max_processes: 256,
                max_output_bytes: 16 * 1024 * 1024,
            },
        }
    }

    #[test]
    fn managed_execution_acknowledgement_is_durable_before_response() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed-execution.db");
        let scope = "home:home-a:command:command-a";

        {
            let mut store = Store::open(path.to_str().unwrap()).unwrap();
            store
                .admit_with_key::<ManagedExecutionState>(
                    scope,
                    "prepare:command-a",
                    ManagedExecutionCommand::Prepare(workspace_execution_request()),
                )
                .unwrap();
            store
                .admit_with_key::<ManagedExecutionState>(
                    scope,
                    "reserve:command-a",
                    ManagedExecutionCommand::AuthorizeWorkspace(WorkspaceAuthorization {
                        reservation_id: "reservation-a".into(),
                        reserved_nanos_usd: 10_000,
                    }),
                )
                .unwrap();
            let acknowledged = store
                .admit_with_key::<ManagedExecutionState>(
                    scope,
                    "ack:command-a",
                    ManagedExecutionCommand::Acknowledge,
                )
                .unwrap();
            assert_eq!(acknowledged.phase, ExecutionPhase::Acknowledged);
            assert!(acknowledged.acknowledged);
        }

        let mut reopened = Store::open(path.to_str().unwrap()).unwrap();
        let recovered = reopened.fold::<ManagedExecutionState>(scope).unwrap();
        assert_eq!(recovered.phase, ExecutionPhase::Acknowledged);
        assert!(recovered.acknowledged);
        assert_eq!(
            recovered.request.as_ref().unwrap().work_target_basis,
            "basis:abc"
        );
        assert!(recovered.reservation_open);

        let event_count = reopened
            .records(scope, ManagedExecutionState::KIND)
            .unwrap()
            .len();
        let replayed = reopened
            .admit_with_key::<ManagedExecutionState>(
                scope,
                "ack:command-a",
                ManagedExecutionCommand::Acknowledge,
            )
            .unwrap();
        assert_eq!(replayed.phase, ExecutionPhase::Acknowledged);
        assert_eq!(
            reopened
                .records(scope, ManagedExecutionState::KIND)
                .unwrap()
                .len(),
            event_count,
            "replayed acknowledgement appends no second fact"
        );
    }

    #[test]
    fn append_record_with_key_returns_the_stable_position_on_replay() {
        let mut store = Store::open_in_memory().unwrap();
        let first = store
            .append_record_with_key("chat-1", "whip:event:4", "runtime_pointer", "pointer-a")
            .unwrap();
        let replay = store
            .append_record_with_key("chat-1", "whip:event:4", "runtime_pointer", "pointer-b")
            .unwrap();
        assert_eq!(first, (0, true));
        assert_eq!(replay, (0, false));
        assert_eq!(
            store.records("chat-1", "runtime_pointer").unwrap(),
            vec!["pointer-a"]
        );
    }

    #[test]
    fn scope_high_water_marks_name_every_scope_without_payloads() {
        let mut store = Store::open_in_memory().unwrap();
        store.append_record("alpha", "event", "secret-a").unwrap();
        store.append_record("alpha", "event", "secret-b").unwrap();
        store.append_record("beta", "event", "secret-c").unwrap();
        assert_eq!(
            store.scope_high_water_marks().unwrap(),
            [("alpha".to_owned(), 1_i64), ("beta".to_owned(), 0_i64)]
                .into_iter()
                .collect()
        );
    }

    /// A rejected keyed command leaves no receipt, so a corrected retry under the
    /// same key can still succeed (only *accepted* commands are sealed).
    #[test]
    fn a_rejected_keyed_command_leaves_no_receipt() {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "idem-reject";
        // AdmitRun from Init is rejected (must RequestRun first).
        assert!(store
            .admit_with_key::<RunState>(scope, "k", AdmitRun)
            .is_err());
        // The same key now carries a valid command — it is NOT blocked by a
        // ghost receipt from the rejected attempt.
        let s = store
            .admit_with_key::<RunState>(scope, "k", RequestRun)
            .unwrap();
        assert_eq!(s.phase, RunPhase::Requested);
    }

    #[test]
    fn materialized_admission_preserves_input_status_and_replays_once(/* CORE-2 */) {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "materialized-run";
        let first = store
            .admit_materialized::<RunState>(scope, "caller-key", RequestRun)
            .unwrap();
        assert!(!first.replayed);
        assert_eq!(first.state.phase, RunPhase::Requested);

        let replay = store
            .admit_materialized::<RunState>(scope, "caller-key", RequestRun)
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(store.records(scope, RunState::KIND).unwrap().len(), 1);
        let receipt = store.command_for_key(scope, "caller-key").unwrap().unwrap();
        assert_eq!(receipt.status, "applied");
        assert!(receipt.snapshot_json.contains(r#""kind":"run""#));
        assert!(receipt.snapshot_json.contains("RequestRun"));

        let mismatch = store.admit_materialized::<RunState>(scope, "caller-key", AdmitRun);
        assert!(matches!(mismatch, Err(AdmitError::Rejected(_))));
        assert_eq!(
            store
                .command_for_key(scope, "caller-key")
                .unwrap()
                .unwrap()
                .snapshot_json,
            receipt.snapshot_json,
            "a reused key never replaces the first materialized input"
        );
    }

    #[test]
    fn record_fact_admission_is_atomic_replayable_and_snapshot_bound() {
        let mut store = Store::open_in_memory().unwrap();
        let facts = vec![
            CommandRecordFact {
                scope_id: "org::acme".into(),
                kind: "membership".into(),
                payload: r#"{"id":"alice"}"#.into(),
            },
            CommandRecordFact {
                scope_id: "audit".into(),
                kind: "audit".into(),
                payload: r#"{"action":"member.invite"}"#.into(),
            },
        ];
        let first = store
            .admit_record_facts(
                "environment:administration:acme",
                "intent-1",
                r#"{"v":1}"#,
                &facts,
            )
            .unwrap();
        assert_eq!(first.positions, vec![0, 0]);
        assert!(!first.replayed);

        let replay = store
            .admit_record_facts(
                "environment:administration:acme",
                "intent-1",
                r#"{"v":1}"#,
                &facts,
            )
            .unwrap();
        assert!(replay.replayed);
        assert!(replay.positions.is_empty());
        assert_eq!(store.records("org::acme", "membership").unwrap().len(), 1);
        assert_eq!(store.records("audit", "audit").unwrap().len(), 1);
        assert_eq!(
            store
                .command_for_key("environment:administration:acme", "intent-1")
                .unwrap()
                .unwrap()
                .status,
            "applied"
        );

        let mismatch = store.admit_record_facts(
            "environment:administration:acme",
            "intent-1",
            r#"{"v":2}"#,
            &facts,
        );
        assert!(matches!(mismatch, Err(AdmitError::Rejected(_))));
        assert_eq!(store.records("org::acme", "membership").unwrap().len(), 1);
    }

    #[test]
    fn concurrent_record_fact_retry_has_one_effect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record-command.sqlite");
        let mut first = Store::open(path.to_str().unwrap()).unwrap();
        let mut second = Store::open(path.to_str().unwrap()).unwrap();
        let fact = CommandRecordFact {
            scope_id: "org".into(),
            kind: "org".into(),
            payload: r#"{"display_name":"Acme"}"#.into(),
        };
        assert!(
            !first
                .admit_record_facts(
                    "environment:administration:org",
                    "same",
                    "snapshot",
                    std::slice::from_ref(&fact)
                )
                .unwrap()
                .replayed
        );
        assert!(
            second
                .admit_record_facts(
                    "environment:administration:org",
                    "same",
                    "snapshot",
                    &[fact]
                )
                .unwrap()
                .replayed
        );
        assert_eq!(second.records("org", "org").unwrap().len(), 1);
    }

    #[test]
    fn materialized_rejection_is_observable_and_correction_uses_a_new_key(/* CORE-2 */) {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "materialized-reject";
        assert!(store
            .admit_materialized::<RunState>(scope, "bad-attempt", StartRun)
            .is_err());
        assert_eq!(
            store
                .command_for_key(scope, "bad-attempt")
                .unwrap()
                .unwrap()
                .status,
            "rejected"
        );
        let replay = store
            .admit_materialized::<RunState>(scope, "bad-attempt", StartRun)
            .unwrap_err();
        assert!(matches!(
            replay,
            AdmitError::Rejected(Rejection {
                reason: "command already rejected; submit with a new key"
            })
        ));
        assert!(store
            .admit_materialized::<RunState>(scope, "bad-attempt", RequestRun)
            .is_err());
        let corrected = store
            .admit_materialized::<RunState>(scope, "corrected-attempt", RequestRun)
            .unwrap();
        assert_eq!(corrected.state.phase, RunPhase::Requested);
    }

    #[test]
    fn command_claim_runs_a_caller_key_once(/* CORE-2 */) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commands.sqlite");
        let mut first_connection = Store::open(path.to_str().unwrap()).unwrap();
        let mut second_connection = Store::open(path.to_str().unwrap()).unwrap();
        let (first, claimed) = first_connection
            .claim_command("command-1", "scope", "caller-key", r#"{"input":1}"#)
            .unwrap();
        assert!(claimed);
        assert_eq!(first.status, "processing");

        let (replay, claimed_again) = second_connection
            .claim_command("command-1", "scope", "caller-key", r#"{"input":1}"#)
            .unwrap();
        assert!(!claimed_again);
        assert_eq!(replay.status, "processing");

        let (mismatch, mismatch_claimed) = second_connection
            .claim_command("command-1", "scope", "caller-key", r#"{"input":2}"#)
            .unwrap();
        assert!(!mismatch_claimed);
        assert_eq!(mismatch.snapshot_json, r#"{"input":1}"#);
    }

    #[test]
    fn admits_and_rebuilds_a_run_from_the_log() {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "run-1";
        store.admit::<RunState>(scope, RequestRun).unwrap();
        store.admit::<RunState>(scope, AdmitRun).unwrap();
        let s = store.admit::<RunState>(scope, StartRun).unwrap();
        assert_eq!(s.phase, RunPhase::Running);
        // INV-8: the event log alone rebuilds the same state.
        assert_eq!(
            store.fold::<RunState>(scope).unwrap().phase,
            RunPhase::Running
        );
    }

    #[test]
    fn rejected_command_appends_no_event() {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "run-2";
        store.admit::<RunState>(scope, RequestRun).unwrap();
        let err = store.admit::<RunState>(scope, StartRun); // INV-11: not admitted
        assert!(matches!(err, Err(AdmitError::Rejected(_))));
        // INV-2: a rejected command is not a fact — the log is unchanged.
        assert_eq!(
            store.fold::<RunState>(scope).unwrap().phase,
            RunPhase::Requested
        );
    }

    #[test]
    fn events_returns_the_ordered_audit_timeline() {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "audit-1";
        store.admit::<RunState>(scope, RequestRun).unwrap();
        store.admit::<RunState>(scope, AdmitRun).unwrap();
        store.admit::<RunState>(scope, StartRun).unwrap();
        let events = store.events(scope).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events.iter().map(|(p, ..)| *p).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(events.iter().all(|(_, kind, _)| kind == "run"));
        assert!(events[0].2.contains("RunRequested"));
    }

    #[test]
    fn admission_is_atomic_all_events_or_none() {
        // INV-22: a `decide` that yields several events commits as one unit. A
        // multi-event command lands a contiguous position block with no partial
        // prefix visible — and a later rejection leaves that block intact.
        let mut store = Store::open_in_memory().unwrap();
        let scope = "atomic-1";
        // RequestRun → AdmitRun each yield one event; drive to Running (3 events).
        store.admit::<RunState>(scope, RequestRun).unwrap();
        store.admit::<RunState>(scope, AdmitRun).unwrap();
        store.admit::<RunState>(scope, StartRun).unwrap();
        let before = store.events(scope).unwrap();
        assert_eq!(before.len(), 3, "three admitted events");
        // A rejected command must not append a partial event.
        assert!(store.admit::<RunState>(scope, StartRun).is_err());
        assert_eq!(
            store.events(scope).unwrap().len(),
            3,
            "rejection left the log atomic"
        );
    }

    #[test]
    fn scopes_are_isolated_no_cross_scope_bleed() {
        // INV-7: each scope is its own total order; one scope's events and records
        // never appear when folding/reading another.
        let mut store = Store::open_in_memory().unwrap();
        store.admit::<RunState>("scope-a", RequestRun).unwrap();
        store
            .append_record("scope-a", "transcript", "a-note")
            .unwrap();
        // scope-b starts empty and its own positions begin at 0.
        assert_eq!(
            store.fold::<RunState>("scope-b").unwrap().phase,
            RunPhase::Init
        );
        assert!(store.records("scope-b", "transcript").unwrap().is_empty());
        assert!(store.events("scope-b").unwrap().is_empty());
        let p = store
            .append_record("scope-b", "transcript", "b-note")
            .unwrap();
        assert_eq!(p, 0, "scope-b's position sequence is independent");
        assert_eq!(
            store.records("scope-a", "transcript").unwrap(),
            vec!["a-note"]
        );
    }

    /// The Phase-1 gate end-to-end through the shell: a run produces a tainted
    /// output → review (conjunctive consent auto-clears) → export, all in one
    /// scope, each lifecycle admitted and folded independently by `KIND`.
    #[test]
    fn run_to_review_to_export_all_gated() {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "engagement-1";
        let owners: BTreeSet<_> = ["A", "B"].iter().map(|s| (*s).into()).collect();

        // run reaches Running
        store.admit::<RunState>(scope, RequestRun).unwrap();
        store.admit::<RunState>(scope, AdmitRun).unwrap();
        store.admit::<RunState>(scope, StartRun).unwrap();

        // review of the tainted output: not released until every owner consents
        store
            .admit::<ReviewState>(
                scope,
                ReviewCommand::Propose {
                    required: owners.clone(),
                },
            )
            .unwrap();
        store
            .admit::<ReviewState>(scope, ReviewCommand::Consent("A".into()))
            .unwrap();
        let r = store
            .admit::<ReviewState>(scope, ReviewCommand::Consent("B".into()))
            .unwrap();
        assert_eq!(
            r.phase,
            ReviewPhase::Cleared,
            "auto-clears once both consent"
        );
        let r = store
            .admit::<ReviewState>(scope, ReviewCommand::Release)
            .unwrap();
        assert_eq!(r.phase, ReviewPhase::Released);

        // export: requires both source consents AND target admission
        store
            .admit::<ExportState>(
                scope,
                ExportCommand::ProposeExport {
                    source_required: owners,
                },
            )
            .unwrap();
        store
            .admit::<ExportState>(scope, ExportCommand::SourceConsent("A".into()))
            .unwrap();
        store
            .admit::<ExportState>(scope, ExportCommand::SourceConsent("B".into()))
            .unwrap();
        // not yet cleared without the target — export is rejected
        assert!(matches!(
            store.admit::<ExportState>(scope, ExportCommand::Export),
            Err(AdmitError::Rejected(_))
        ));
        store
            .admit::<ExportState>(scope, ExportCommand::TargetAdmit)
            .unwrap();
        let e = store
            .admit::<ExportState>(scope, ExportCommand::Export)
            .unwrap();
        assert_eq!(e.phase, ExportPhase::Exported);

        // the run lifecycle in the same scope is untouched by the others' events
        assert_eq!(
            store.fold::<RunState>(scope).unwrap().phase,
            RunPhase::Running
        );
    }

    /// A test codec: "encrypts" the `secret` kind by reversing the payload (and marks
    /// it), passes every other kind through, and can be told a scope is "erased" so its
    /// `secret` rows decode to `None` (unrecoverable).
    struct RevCodec {
        erased: std::sync::Mutex<std::collections::BTreeSet<String>>,
    }
    impl ContentCodec for RevCodec {
        fn encode(&self, _scope: &str, kind: &str, payload: &str) -> Result<String, String> {
            Ok(if kind == "secret" {
                format!("rev:{}", payload.chars().rev().collect::<String>())
            } else {
                payload.to_string()
            })
        }
        fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String> {
            if kind != "secret" {
                return Some(payload.to_string());
            }
            if self.erased.lock().unwrap().contains(scope) {
                return None; // crypto-erased: unrecoverable
            }
            payload
                .strip_prefix("rev:")
                .map(|p| p.chars().rev().collect())
                .or_else(|| Some(payload.to_string())) // legacy plaintext
        }
    }

    struct FailingCodec;
    impl ContentCodec for FailingCodec {
        fn encode(&self, _scope: &str, _kind: &str, _payload: &str) -> Result<String, String> {
            Err("key service unavailable".to_owned())
        }

        fn decode(&self, _scope: &str, _kind: &str, payload: &str) -> Option<String> {
            Some(payload.to_owned())
        }
    }

    #[test]
    fn content_codec_failure_appends_nothing() {
        let mut store = Store::open_in_memory()
            .unwrap()
            .with_codec(std::sync::Arc::new(FailingCodec));

        assert!(matches!(
            store.append_record("eng-1", "secret", "must-not-leak"),
            Err(AdmitError::Codec(message)) if message == "key service unavailable"
        ));
        assert!(store.records("eng-1", "secret").unwrap().is_empty());
    }

    #[test]
    fn content_codec_encrypts_content_kinds_at_rest_and_passes_others_through() {
        // SECAUD-9: a content kind is stored transformed (the raw column is not the
        // plaintext) yet reads back transparently; a non-content kind is untouched.
        let codec = std::sync::Arc::new(RevCodec {
            erased: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        });
        let mut store = Store::open_in_memory().unwrap().with_codec(codec);
        store
            .append_record("eng-1", "secret", "hello-transcript")
            .unwrap();
        store.append_record("eng-1", "meta", "not-secret").unwrap();

        // Reads decode transparently.
        assert_eq!(
            store.records("eng-1", "secret").unwrap(),
            vec!["hello-transcript"]
        );
        assert_eq!(store.records("eng-1", "meta").unwrap(), vec!["not-secret"]);

        // A plaintext store over the same rows sees the content kind is NOT plaintext...
        let raw = Store::open_in_memory().unwrap();
        // (re-insert the at-rest bytes a codec'd store would have written)
        let mut raw = raw;
        raw.append_record("eng-1", "secret", "rev:tpircsnart-olleh")
            .unwrap();
        assert_ne!(
            raw.records("eng-1", "secret").unwrap(),
            vec!["hello-transcript"]
        );
    }

    #[test]
    fn content_codec_crypto_erase_makes_content_unrecoverable_history_intact() {
        // SECAUD-6: once a scope's key is erased, its content rows decode to None and are
        // dropped from reads — gone — while the underlying append-only rows remain.
        let codec = std::sync::Arc::new(RevCodec {
            erased: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        });
        let mut store = Store::open_in_memory().unwrap().with_codec(codec.clone());
        store
            .append_record("eng-1", "secret", "client-data")
            .unwrap();
        store
            .append_record("eng-2", "secret", "other-data")
            .unwrap();
        assert_eq!(store.records("eng-1", "secret").unwrap().len(), 1);

        // Crypto-erase eng-1: its content is unrecoverable; eng-2 is untouched (per-unit).
        codec.erased.lock().unwrap().insert("eng-1".into());
        assert!(
            store.records("eng-1", "secret").unwrap().is_empty(),
            "erased content is gone"
        );
        assert_eq!(
            store.records("eng-2", "secret").unwrap(),
            vec!["other-data"],
            "other unit intact"
        );
        // The decoded history also drops the unrecoverable row (the raw append-only row is
        // never deleted — INV-6 — only the key is gone, so the ciphertext can't be opened).
        assert_eq!(
            store.events("eng-1").unwrap().len(),
            0,
            "decoded history drops the erased row"
        );
    }

    #[test]
    fn record_revisions_are_append_only_and_tombstones_keep_history(/* CORE-2 */) {
        let mut store = Store::open_in_memory().unwrap();
        let first = store
            .append_record_revision("project:1", "library", "project", r#"{"name":"A"}"#, false)
            .unwrap();
        let second = store
            .append_record_revision("project:1", "library", "project", r#"{"name":"B"}"#, false)
            .unwrap();
        let tombstone = store
            .append_record_revision("project:1", "library", "project", "{}", true)
            .unwrap();
        assert_eq!(
            (first.revision, second.revision, tombstone.revision),
            (1, 2, 3)
        );
        assert_eq!(store.record_history("project:1").unwrap().len(), 3);
        assert_eq!(store.current_record("project:1").unwrap(), Some(tombstone));
    }

    #[test]
    fn content_metadata_tombstones_without_deleting_the_handle(/* CORE-2 */) {
        let mut store = Store::open_in_memory().unwrap();
        let mut metadata = ContentMetadata {
            handle: "sha256:abc".into(),
            resource_id: Some("resource:1".into()),
            sha256: Some("abc".into()),
            size_bytes: Some(42),
            status: "live".into(),
        };
        store.put_content_metadata(&metadata).unwrap();
        metadata.status = "tombstoned".into();
        store.put_content_metadata(&metadata).unwrap();
        assert_eq!(
            store.content_metadata("sha256:abc").unwrap(),
            Some(metadata)
        );
    }

    #[test]
    fn command_recovery_repairs_committed_and_expires_uncommitted(/* CORE-2 */) {
        let mut store = Store::open_in_memory().unwrap();
        store
            .receive_command("command:applied", "scope:1", "key:applied", r#"{"v":1}"#)
            .unwrap();
        store
            .set_command_status("command:applied", "processing")
            .unwrap();
        store
            .append_record_with_key("scope:1", "key:applied", "record", "{}")
            .unwrap();
        store
            .receive_command("command:expired", "scope:1", "key:expired", r#"{"v":2}"#)
            .unwrap();
        let (applied, expired) = store.reconcile_commands().unwrap();
        assert_eq!((applied, expired), (1, 1));
        assert_eq!(
            store.command("command:applied").unwrap().unwrap().status,
            "applied"
        );
        assert_eq!(
            store.command("command:expired").unwrap().unwrap().status,
            "expired"
        );
    }

    #[test]
    fn command_idempotency_keeps_the_first_materialized_snapshot(/* CORE-2 */) {
        let mut store = Store::open_in_memory().unwrap();
        let first = store
            .receive_command("command:1", "scope:1", "same-key", r#"{"before":1}"#)
            .unwrap();
        let replay = store
            .receive_command("command:2", "scope:1", "same-key", r#"{"before":999}"#)
            .unwrap();
        assert_eq!(replay, first);
        assert_eq!(replay.command_id, "command:1");
        assert_eq!(replay.snapshot_json, r#"{"before":1}"#);
    }

    #[test]
    fn projection_meta_carries_version_cursor_and_dirty_state(/* CORE-2 */) {
        let mut store = Store::open_in_memory().unwrap();
        let dirty = ProjectionMeta {
            projection: "workspace".into(),
            scope_id: "scope:1".into(),
            version: 2,
            high_water: 9,
            dirty: true,
        };
        store.put_projection_meta(&dirty).unwrap();
        assert_eq!(
            store.projection_meta("workspace", "scope:1").unwrap(),
            Some(dirty)
        );
        let clean = ProjectionMeta {
            dirty: false,
            high_water: 12,
            ..store
                .projection_meta("workspace", "scope:1")
                .unwrap()
                .unwrap()
        };
        store.put_projection_meta(&clean).unwrap();
        assert_eq!(
            store.projection_meta("workspace", "scope:1").unwrap(),
            Some(clean)
        );
    }

    #[test]
    fn observations_gain_authority_only_by_linking_an_existing_event(/* CORE-2 */) {
        let mut store = Store::open_in_memory().unwrap();
        let raw = store
            .record_observation("obs:1", "run:1", "model.delta", Some("evidence:1"))
            .unwrap();
        assert_eq!(raw.admitted_scope, None);
        assert!(!store.admit_observation("obs:1", "scope:1", 0).unwrap());
        let position = store
            .append_record("scope:1", "runtime_pointer", "{}")
            .unwrap();
        assert!(store
            .admit_observation("obs:1", "scope:1", position)
            .unwrap());
        let admitted = store.observation("obs:1").unwrap().unwrap();
        assert_eq!(admitted.admitted_scope.as_deref(), Some("scope:1"));
        assert_eq!(admitted.admitted_position, Some(position));
    }

    #[test]
    fn opening_a_legacy_event_store_applies_additive_profile_migration(/* CORE-2 */) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (
                scope_id TEXT NOT NULL, position INTEGER NOT NULL,
                kind TEXT NOT NULL, payload TEXT NOT NULL,
                PRIMARY KEY(scope_id, position));
             CREATE TABLE command_receipts (
                scope_id TEXT NOT NULL, command_key TEXT NOT NULL,
                applied_at INTEGER NOT NULL,
                PRIMARY KEY(scope_id, command_key));
             INSERT INTO events VALUES ('scope:legacy', 0, 'record', '{\"kept\":true}');",
        )
        .unwrap();
        drop(conn);

        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            store.records("scope:legacy", "record").unwrap(),
            vec![r#"{"kept":true}"#]
        );
        let revision = store
            .append_record_revision("record:1", "scope:legacy", "project", "{}", false)
            .unwrap();
        assert_eq!(revision.revision, 1);
        store
            .put_projection_meta(&ProjectionMeta {
                projection: "workspace".into(),
                scope_id: "scope:legacy".into(),
                version: 1,
                high_water: 0,
                dirty: false,
            })
            .unwrap();
    }
}
