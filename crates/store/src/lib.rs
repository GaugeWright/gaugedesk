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
//! genuinely long operation — a runtime turn (subprocess + multi-step admission) — is
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

pub mod command_dispatch;
pub mod command_scope_archive;
mod durable_registry;
pub mod home_product;
mod home_reference_catalog;
pub mod home_reference_journal;
mod home_reference_storage;
pub mod migration_inventory;
pub mod project_authority;
mod record_admission;
mod record_admission_pair;
pub use record_admission_pair::RecordedLifecyclePair;
mod record_admission_prefix;
#[cfg(test)]
mod record_claim_tests;
mod request_admission;
mod snapshot;
#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
mod typed_codec_tests;

/// A transparent at-rest transform applied to record payloads of designated
/// **content** kinds (`SECAUD-9`/`SECAUD-6`). The store crate stays crypto-free: this
/// is the seam an app-side content vault implements to encrypt sensitive content
/// (e.g. `transcript`) under per-scope keys, including designated lifecycle events; other kinds pass through. `None` on the [`Store`] = plaintext (the default; zero behavior change).
pub trait ContentCodec: Send + Sync {
    /// Transform a payload for storage. Must be reversible by [`decode`](Self::decode).
    /// A non-content `kind` returns the payload unchanged (pass-through).
    /// Failure aborts the store append before protected bytes are written; protected
    /// content must never be replaced with a lossy placeholder or plaintext.
    fn encode(&self, scope: &str, kind: &str, payload: &str) -> Result<String, String>;
    /// Reverse [`encode`](Self::encode). Returns `None` when the payload is
    /// unavailable, for example after key erasure or failed authentication.
    /// Informational content views may omit it; authority and typed lifecycle
    /// folds must refuse. Pass-through and legacy plaintext depend on the codec's
    /// policy; a strict deployment need not accept legacy plaintext.
    fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String>;
    /// [`decode`](Self::decode) every `(kind, payload)` row of one scope, in
    /// order, answered as of one instant. The answers must be exactly those
    /// `decode` would give each row at that instant; a codec that resolves a
    /// key per scope overrides this to resolve it once per read rather than
    /// once per row, which on the Hub was most of the cost of every fold of an
    /// encrypted scope.
    fn decode_scope(&self, scope: &str, rows: &[(&str, &str)]) -> Vec<Option<String>> {
        rows.iter()
            .map(|(kind, payload)| self.decode(scope, kind, payload))
            .collect()
    }
    /// A value that moves whenever [`decode`](Self::decode) may answer a row
    /// of `scope` differently than it has: a key erased or fenced, a key that
    /// could not be resolved. `None`, the default, says the codec cannot tell,
    /// and nothing decoded from `scope` may be remembered (see
    /// [`Store::read_stamp`]).
    fn epoch(&self, scope: &str) -> Option<u64> {
        let _ = scope;
        None
    }
}

/// What a read of some scopes answered from (see [`Store::read_stamp`]). Two
/// equal stamps of the same scopes mean every read of those scopes between
/// them would have answered the same.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadStamp {
    heads: Vec<Option<i64>>,
    codec_epoch: u64,
}

/// The least string greater than every string that starts with `prefix`, in
/// code-point order (which is SQLite's binary order for UTF-8 text): the
/// prefix with its last character advanced, past any that cannot advance.
/// `None` when no string bounds it, as for the empty prefix.
fn prefix_successor(prefix: &str) -> Option<String> {
    let mut chars: Vec<char> = prefix.chars().collect();
    while let Some(last) = chars.pop() {
        let next = match last as u32 {
            0xD7FF => Some('\u{E000}'),
            0x10FFFF => None,
            point => char::from_u32(point + 1),
        };
        if let Some(next) = next {
            chars.push(next);
            return Some(chars.into_iter().collect());
        }
    }
    None
}

/// [`ContentCodec::decode_scope`], held to one answer per row: a codec that
/// answers a different number of rows has answered none of them, so every row
/// reads as unavailable rather than the read silently losing some.
fn decode_scope(
    codec: &dyn ContentCodec,
    scope: &str,
    rows: &[(&str, &str)],
) -> Vec<Option<String>> {
    let decoded = codec.decode_scope(scope, rows);
    if decoded.len() == rows.len() {
        decoded
    } else {
        vec![None; rows.len()]
    }
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
    /// Independently retained coordinates for a dedicated Home product store.
    home_product: Option<home_product::HomeProductBinding>,
    /// Folds remembered on this connection (see [`Store::remember`]).
    remembered: std::sync::Mutex<Remembered>,
}

/// How long [`Store::remember`] answers a fold at all, however still the store
/// has been. The read stamp already moves with every event appended to the
/// scope and every change in how the codec opens it; this bounds what a stamp
/// cannot see, such as another process erasing a key file.
pub const REMEMBERED_FOR: Duration = Duration::from_secs(5);

/// At most this many folds are remembered per connection; past it the memory
/// starts over.
const FOLDS_REMEMBERED: usize = 512;

#[derive(Default)]
struct Remembered {
    folds: std::collections::HashMap<(&'static str, String), RememberedFold>,
}

struct RememberedFold {
    stamp: ReadStamp,
    at: std::time::Instant,
    value: Box<dyn std::any::Any + Send>,
}

/// An additional exact-input identity claimed atomically with record facts.
/// A reviewed external effect uses this to bind BOTH the caller's review key
/// and the proposal's single approval identity before contacting its authority.
pub struct RecordCommandClaim<'a> {
    pub key: &'a str,
    pub snapshot: &'a str,
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

/// Immutable record snapshot backed by its receipt. `first_fact_position`
/// belongs to the first fact's scope (which the owning caller knows), not
/// necessarily the command scope; an admission without facts records zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedRecordSnapshot {
    pub idempotency_key: String,
    pub snapshot_json: String,
    pub first_fact_position: i64,
}

/// Result of an application command admitted through the materialized command
/// shell. `replayed` means the idempotency receipt already existed, so callers
/// must not repeat non-durable notifications for the original admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedAdmission<S> {
    pub state: S,
    pub replayed: bool,
}

/// Durable result of an exact request admitted through [`Store::admit_request`].
/// This is operational recovery evidence, not lifecycle state. In particular,
/// `Rejected` means the exact request key and intent were atomically fenced
/// without appending an effect; an absent or mismatched record proves nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestAdmissionStatus {
    Applied,
    Rejected,
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
/// How many prepared statements a connection keeps compiled. See `Store::init`.
const STATEMENT_CACHE_CAPACITY: usize = 128;

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
pub const SUPPORTED_SCHEMA_VERSION: i64 = 14;

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
    Migration {
        version: 3,
        name: "home-reference-journal",
        // A Home-wide roster must live with the Home command authority, not
        // inside one chat, gate, or action runtime store (DR-0250). Migration
        // cannot establish coverage of older operations or of doors that are
        // not wired yet: inventory_complete deliberately starts false.
        sql: "CREATE TABLE IF NOT EXISTS home_reference_state (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 home_id TEXT,
                 current_epoch INTEGER NOT NULL CHECK (current_epoch >= 0),
                 inventory_complete INTEGER NOT NULL DEFAULT 0
                     CHECK (inventory_complete = 0)
             );
             INSERT OR IGNORE INTO home_reference_state
                 (id, home_id, current_epoch, inventory_complete)
                 VALUES (1, NULL, 0, 0);
             CREATE TABLE IF NOT EXISTS home_reference_operations (
                 operation_id TEXT PRIMARY KEY,
                 home_id TEXT NOT NULL,
                 target_store TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 basis_digest TEXT NOT NULL,
                 registered_epoch INTEGER NOT NULL,
                 completed_epoch INTEGER,
                 status TEXT NOT NULL CHECK (status IN ('pending', 'completed')),
                 evidence_ref TEXT,
                 witness_digest TEXT,
                 revalidated_basis_digest TEXT,
                 CHECK (
                     (status = 'pending' AND completed_epoch IS NULL
                      AND evidence_ref IS NULL AND witness_digest IS NULL
                      AND revalidated_basis_digest IS NULL)
                     OR
                     (status = 'completed' AND completed_epoch IS NOT NULL
                      AND evidence_ref IS NOT NULL AND witness_digest IS NOT NULL)
                 )
             );
             CREATE INDEX IF NOT EXISTS home_reference_operations_epoch
                 ON home_reference_operations(completed_epoch, operation_id);
             CREATE TABLE IF NOT EXISTS home_reference_seals (
                 epoch INTEGER PRIMARY KEY,
                 home_id TEXT NOT NULL,
                 registry_basis TEXT NOT NULL,
                 policy_basis TEXT NOT NULL,
                 structural_basis TEXT NOT NULL,
                 roster_digest TEXT NOT NULL,
                 operation_count INTEGER NOT NULL CHECK (operation_count >= 0)
             );",
    },
    Migration {
        version: 4,
        name: "home-reference-terminal-refusals",
        // Keep the v3 operation rows and sealed-roster encoding intact. A
        // refused registration remains in the Home's durable account of work
        // without entering the completed-operation cut (DR-0250).
        sql: "CREATE TABLE IF NOT EXISTS home_reference_refusals (
                 operation_id TEXT PRIMARY KEY
                     REFERENCES home_reference_operations(operation_id),
                 home_id TEXT NOT NULL,
                 refused_epoch INTEGER NOT NULL CHECK (refused_epoch >= 0),
                 reason_code TEXT NOT NULL CHECK (length(reason_code) > 0)
             );",
    },
    Migration {
        version: 5,
        name: "home-reference-use-pins",
        // A retained runtime version is insufficient to identify the exact
        // accepting operation when a version has multiple admissions. Keep
        // the item's Home binding immutable and distinguish historical gaps.
        sql: "CREATE TABLE IF NOT EXISTS home_reference_use_pins (
                 home_id TEXT NOT NULL CHECK (length(home_id) > 0),
                 target_store TEXT NOT NULL CHECK (length(target_store) > 0),
                 use_key TEXT NOT NULL CHECK (length(use_key) > 0),
                 version_id TEXT NOT NULL CHECK (length(version_id) > 0),
                 classification TEXT NOT NULL
                     CHECK (classification IN ('exact', 'legacy_unknown')),
                 operation_id TEXT REFERENCES home_reference_operations(operation_id),
                 bound_epoch INTEGER NOT NULL CHECK (bound_epoch >= 0),
                 PRIMARY KEY (home_id, target_store, use_key),
                 CHECK (
                     (classification = 'exact' AND operation_id IS NOT NULL) OR
                     (classification = 'legacy_unknown' AND operation_id IS NULL)
                 )
             );
             CREATE INDEX IF NOT EXISTS home_reference_use_pins_operation
                 ON home_reference_use_pins(operation_id);",
    },
    Migration {
        version: 6,
        name: "home-reference-cumulative-seals",
        // Existing seals retain their exact v3-v5 epoch-local rosters. New
        // seals include every completed operation through the cut, so a later
        // candidate cannot silently omit a still-admitted earlier operation.
        sql: "ALTER TABLE home_reference_seals ADD COLUMN roster_scope TEXT NOT NULL
                 DEFAULT 'epoch' CHECK (roster_scope IN ('epoch', 'through_epoch'));",
    },
    Migration {
        version: 7,
        name: "home-reference-seal-finalization",
        // The epoch and its authority bases commit under a short writer lock.
        // A crash before the roster is materialized leaves an explicit pending
        // seal, which can be resumed but cannot certify a gate candidate.
        sql:
            "ALTER TABLE home_reference_seals ADD COLUMN seal_status TEXT NOT NULL
                 DEFAULT 'final' CHECK (seal_status IN ('pending', 'final'));
             CREATE TRIGGER home_reference_completed_no_update
                 BEFORE UPDATE ON home_reference_operations
                 WHEN OLD.status = 'completed'
                 BEGIN SELECT RAISE(ABORT, 'completed reference operation is immutable'); END;
             CREATE TRIGGER home_reference_completed_no_delete
                 BEFORE DELETE ON home_reference_operations
                 WHEN OLD.status = 'completed'
                 BEGIN SELECT RAISE(ABORT, 'completed reference operation is immutable'); END;
             CREATE TRIGGER home_reference_completed_no_replace
                 BEFORE INSERT ON home_reference_operations
                 WHEN EXISTS (SELECT 1 FROM home_reference_operations
                              WHERE operation_id = NEW.operation_id AND status = 'completed')
                 BEGIN SELECT RAISE(ABORT, 'completed reference operation is immutable'); END;
             CREATE TRIGGER home_reference_insert_current_epoch
                 BEFORE INSERT ON home_reference_operations
                 WHEN NEW.status != 'pending'
                   OR NEW.registered_epoch != (SELECT current_epoch FROM home_reference_state WHERE id = 1)
                 BEGIN SELECT RAISE(ABORT, 'reference registration must be pending in current epoch'); END;
             CREATE TRIGGER home_reference_complete_current_epoch
                 BEFORE UPDATE ON home_reference_operations
                 WHEN OLD.status = 'pending' AND
                     (NEW.status != 'completed'
                      OR NEW.completed_epoch != (SELECT current_epoch FROM home_reference_state WHERE id = 1))
                 BEGIN SELECT RAISE(ABORT, 'reference completion must use current epoch'); END;
             CREATE TRIGGER home_reference_completed_no_refusal
                 BEFORE INSERT ON home_reference_refusals
                 WHEN EXISTS (SELECT 1 FROM home_reference_operations
                              WHERE operation_id = NEW.operation_id AND status = 'completed')
                 BEGIN SELECT RAISE(ABORT, 'completed reference operation cannot be refused'); END;
             CREATE TRIGGER home_reference_completed_no_refusal_update
                 BEFORE UPDATE ON home_reference_refusals
                 WHEN EXISTS (SELECT 1 FROM home_reference_operations
                              WHERE operation_id = NEW.operation_id AND status = 'completed')
                 BEGIN SELECT RAISE(ABORT, 'completed reference operation cannot be refused'); END;",
    },
    Migration {
        version: 8,
        name: "home-reference-target-store-incarnation",
        // Existing operations cannot acquire an incarnation from a path or a
        // newly opened store. They remain unknown until explicitly readmitted.
        sql: "ALTER TABLE home_reference_operations
                  ADD COLUMN target_store_incarnation TEXT
                  CHECK (target_store_incarnation IS NULL OR
                         length(target_store_incarnation) = 32);
              CREATE TRIGGER home_reference_insert_requires_incarnation
                  BEFORE INSERT ON home_reference_operations
                  WHEN NEW.target_store_incarnation IS NULL OR
                       length(NEW.target_store_incarnation) != 32 OR
                       NEW.target_store_incarnation GLOB '*[^0-9a-f]*'
                  BEGIN SELECT RAISE(ABORT, 'reference target incarnation is required'); END;
              CREATE TRIGGER home_reference_pending_identity_immutable
                  BEFORE UPDATE ON home_reference_operations
                  WHEN OLD.status = 'pending' AND (
                      NEW.operation_id IS NOT OLD.operation_id OR
                      NEW.home_id IS NOT OLD.home_id OR
                      NEW.target_store IS NOT OLD.target_store OR
                      NEW.target_store_incarnation IS NOT OLD.target_store_incarnation OR
                      NEW.kind IS NOT OLD.kind OR
                      NEW.basis_digest IS NOT OLD.basis_digest OR
                      NEW.registered_epoch IS NOT OLD.registered_epoch
                  )
                  BEGIN SELECT RAISE(ABORT, 'pending reference identity is immutable'); END;",
    },
    Migration {
        version: 9,
        name: "project-home-journal-catalog",
        // Independently retain the exact journal identity before creating its
        // file. A ready receipt never permits missing-file reinitialization.
        sql: "CREATE TABLE IF NOT EXISTS home_reference_journal_bindings (
                  project_id TEXT PRIMARY KEY CHECK (length(project_id) > 0),
                  home_id TEXT NOT NULL UNIQUE CHECK (length(home_id) > 0),
                  incarnation TEXT NOT NULL UNIQUE CHECK (length(incarnation) = 32
                      AND incarnation NOT GLOB '*[^0-9a-f]*'),
                  UNIQUE (project_id, home_id, incarnation)
              );
              CREATE TABLE IF NOT EXISTS home_reference_journal_ready (
                  project_id TEXT PRIMARY KEY,
                  home_id TEXT NOT NULL UNIQUE,
                  incarnation TEXT NOT NULL UNIQUE,
                  FOREIGN KEY (project_id, home_id, incarnation)
                      REFERENCES home_reference_journal_bindings(project_id, home_id, incarnation)
              );
              CREATE TABLE IF NOT EXISTS home_reference_use_acknowledgments (
                  project_id TEXT NOT NULL,
                  home_id TEXT NOT NULL,
                  journal_incarnation TEXT NOT NULL,
                  target_store TEXT NOT NULL,
                  target_store_incarnation TEXT NOT NULL,
                  use_key TEXT NOT NULL,
                  version_id TEXT NOT NULL,
                  operation_id TEXT NOT NULL,
                  bound_epoch INTEGER NOT NULL,
                  evidence_ref TEXT NOT NULL,
                  witness_digest TEXT NOT NULL,
                  PRIMARY KEY (project_id, target_store, use_key)
              );
              CREATE TRIGGER IF NOT EXISTS home_reference_ack_requires_ready
                  BEFORE INSERT ON home_reference_use_acknowledgments
                  WHEN NOT EXISTS (SELECT 1 FROM home_reference_journal_ready
                      WHERE project_id = NEW.project_id AND home_id = NEW.home_id
                        AND incarnation = NEW.journal_incarnation)
                  BEGIN SELECT RAISE(ABORT, 'Home use acknowledgment requires ready storage'); END;
              CREATE TRIGGER IF NOT EXISTS home_reference_ack_no_update
                  BEFORE UPDATE ON home_reference_use_acknowledgments
                  BEGIN SELECT RAISE(ABORT, 'Home use acknowledgment is immutable'); END;
              CREATE TRIGGER IF NOT EXISTS home_reference_ack_no_delete
                  BEFORE DELETE ON home_reference_use_acknowledgments
                  BEGIN SELECT RAISE(ABORT, 'Home use acknowledgment is immutable'); END;
              CREATE TRIGGER IF NOT EXISTS home_reference_ack_no_replace
                  BEFORE INSERT ON home_reference_use_acknowledgments
                  WHEN EXISTS (SELECT 1 FROM home_reference_use_acknowledgments
                      WHERE project_id = NEW.project_id AND target_store = NEW.target_store
                        AND use_key = NEW.use_key)
                  BEGIN SELECT RAISE(ABORT, 'Home use acknowledgment is immutable'); END;
              CREATE TRIGGER IF NOT EXISTS home_reference_binding_no_update
                  BEFORE UPDATE ON home_reference_journal_bindings
                  BEGIN SELECT RAISE(ABORT, 'Home journal registration is immutable'); END;
              CREATE TRIGGER IF NOT EXISTS home_reference_binding_no_delete
                  BEFORE DELETE ON home_reference_journal_bindings
                  BEGIN SELECT RAISE(ABORT, 'Home journal registration is immutable'); END;
              CREATE TRIGGER IF NOT EXISTS home_reference_binding_no_replace
                  BEFORE INSERT ON home_reference_journal_bindings
                  WHEN EXISTS (SELECT 1 FROM home_reference_journal_bindings
                      WHERE project_id = NEW.project_id OR home_id = NEW.home_id OR incarnation = NEW.incarnation)
                  BEGIN SELECT RAISE(ABORT, 'Home journal registration is immutable'); END;
              CREATE TRIGGER IF NOT EXISTS home_reference_ready_requires_binding
                  BEFORE INSERT ON home_reference_journal_ready
                  WHEN NOT EXISTS (SELECT 1 FROM home_reference_journal_bindings
                      WHERE project_id = NEW.project_id AND home_id = NEW.home_id AND incarnation = NEW.incarnation)
                  BEGIN SELECT RAISE(ABORT, 'Home journal readiness requires its exact registration'); END;
              CREATE TRIGGER IF NOT EXISTS home_reference_ready_no_update
                  BEFORE UPDATE ON home_reference_journal_ready
                  BEGIN SELECT RAISE(ABORT, 'Home journal readiness is immutable'); END;
              CREATE TRIGGER IF NOT EXISTS home_reference_ready_no_delete
                  BEFORE DELETE ON home_reference_journal_ready
                  BEGIN SELECT RAISE(ABORT, 'Home journal readiness is immutable'); END;
              CREATE TRIGGER IF NOT EXISTS home_reference_ready_no_replace
                  BEFORE INSERT ON home_reference_journal_ready
                  WHEN EXISTS (SELECT 1 FROM home_reference_journal_ready
                      WHERE project_id = NEW.project_id OR home_id = NEW.home_id OR incarnation = NEW.incarnation)
                  BEGIN SELECT RAISE(ABORT, 'Home journal readiness is immutable'); END;",
    },

    Migration {
        version: 10,
        name: "project-authority-keys",
        sql: "CREATE TABLE IF NOT EXISTS project_authority_keys (
                  project_id TEXT PRIMARY KEY CHECK(length(project_id) > 0),
                  authority_id TEXT NOT NULL UNIQUE CHECK(length(authority_id) > 0),
                  public_key TEXT NOT NULL UNIQUE CHECK(length(public_key) = 130
                      AND substr(public_key, 1, 2) = '04'
                      AND public_key NOT GLOB '*[^0-9a-f]*'),
                  custody TEXT NOT NULL CHECK(custody IN ('project-v1', 'incoming-project-v1', 'loopback-v1')),
                  wrapped_seed BLOB NOT NULL CHECK(length(wrapped_seed) > 0)
              );
              CREATE TRIGGER IF NOT EXISTS project_authority_no_update
                  BEFORE UPDATE ON project_authority_keys
                  BEGIN SELECT RAISE(ABORT, 'project authority key is immutable'); END;
              CREATE TRIGGER IF NOT EXISTS project_authority_no_delete
                  BEFORE DELETE ON project_authority_keys
                  BEGIN SELECT RAISE(ABORT, 'project authority key is immutable'); END;
              CREATE TRIGGER IF NOT EXISTS project_authority_no_replace
                  BEFORE INSERT ON project_authority_keys
                  WHEN EXISTS (SELECT 1 FROM project_authority_keys
                      WHERE project_id = NEW.project_id OR authority_id = NEW.authority_id
                        OR public_key = NEW.public_key)
                  BEGIN SELECT RAISE(ABORT, 'project authority key is immutable'); END;",
    },
    Migration {
        version: 11,
        name: "recorded-pair-provenance",
        // Only selected atomic publication creates this binding. A later event
        // append cannot retrofit provenance onto an older command receipt.
        sql: "CREATE TABLE IF NOT EXISTS command_pair_results (
                 command_id TEXT PRIMARY KEY REFERENCES commands(command_id),
                 command_scope TEXT NOT NULL,
                 command_key TEXT NOT NULL,
                 result_scope TEXT NOT NULL,
                 marker_position INTEGER NOT NULL CHECK (marker_position >= 0),
                 marker_sha256 TEXT NOT NULL CHECK (length(marker_sha256) = 64),
                 UNIQUE (command_scope, command_key)
             );",
    },
    Migration {
        version: 12,
        name: "scope-fold-checkpoints",
        // SCALE-1: derived, rebuildable checkpoints of a lifecycle's fold. One
        // row per (scope, kind, lifecycle); the codec version and reducer build
        // are in the key so a changed reducer never resumes an old fold. The
        // anchor is the SHA-256 of the stored bytes of the event at `position`,
        // so a checkpoint whose history moved underneath it is ignored.
        sql: "CREATE TABLE IF NOT EXISTS scope_snapshots (
                 scope_id      TEXT    NOT NULL,
                 kind          TEXT    NOT NULL,
                 lifecycle     TEXT    NOT NULL,
                 codec_version INTEGER NOT NULL,
                 reducer_build TEXT    NOT NULL,
                 position      INTEGER NOT NULL CHECK (position >= 0),
                 anchor_sha256 TEXT    NOT NULL CHECK (length(anchor_sha256) = 64),
                 state         TEXT    NOT NULL,
                 PRIMARY KEY (scope_id, kind, lifecycle, codec_version, reducer_build)
             );",
    },
    Migration {
        version: 13,
        name: "home-product-bindings",
        sql: home_product::CATALOG_SCHEMA,
    },
    Migration {
        version: 14,
        name: "record-command-fact-provenance",
        sql: "CREATE TABLE IF NOT EXISTS record_command_fact_sets (
                 command_scope TEXT NOT NULL,
                 command_key TEXT NOT NULL,
                 fact_count INTEGER NOT NULL CHECK (fact_count >= 0),
                 PRIMARY KEY (command_scope, command_key)
             );
             CREATE TABLE IF NOT EXISTS record_command_fact_refs (
                 command_scope TEXT NOT NULL,
                 command_key TEXT NOT NULL,
                 fact_index INTEGER NOT NULL CHECK (fact_index >= 0),
                 event_scope TEXT NOT NULL,
                 event_position INTEGER NOT NULL,
                 PRIMARY KEY (command_scope, command_key, fact_index),
                 UNIQUE (event_scope, event_position)
             );",
    },
];

/// The fail-closed downgrade-guard refusal (DR-0054 Phase B): diagnosable — it
/// names the database, both versions, and the remediation (run the newer
/// build), never "reset the state root". Typed, so a caller that has to tell a
/// person what happened can recognise it rather than show them SQLite's text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaAhead {
    pub path: String,
    /// The version the database records.
    pub found: i64,
    /// The newest version this build reads: [`SUPPORTED_SCHEMA_VERSION`].
    pub supported: i64,
}

impl SchemaAhead {
    /// The refusal behind `error`, if `error` is one, at any depth of its
    /// source chain.
    pub fn of<'a>(error: &'a (dyn std::error::Error + 'static)) -> Option<&'a SchemaAhead> {
        let mut current = Some(error);
        while let Some(error) = current {
            if let Some(ahead) = error.downcast_ref::<SchemaAhead>() {
                return Some(ahead);
            }
            current = error.source();
        }
        None
    }
}

impl std::fmt::Display for SchemaAhead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            path,
            found,
            supported,
        } = self;
        write!(
            f,
            "store {path} records schema version {found}, but this build supports at most \
             {supported}: a newer GaugeDesk wrote it. Refusing to open so no \
             data is misread or dropped — run a build at schema version {found} or newer \
             against this state root (do not reset it)."
        )
    }
}

impl std::error::Error for SchemaAhead {}

/// rusqlite has no variant for an error of the caller's own. This one boxes
/// any error, displays it unchanged and returns it as its `source()`, so the
/// message is what it always was and [`SchemaAhead::of`] can recover it.
fn schema_ahead_error(path: &str, found: i64) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(SchemaAhead {
        path: path.to_owned(),
        found,
        supported: SUPPORTED_SCHEMA_VERSION,
    }))
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
        .prepare_cached(
            "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 \
             ORDER BY position DESC LIMIT 1",
        )?
        .query_row(params![scope_id, kind], |row| row.get(0))
        .optional()?;
    Ok(match (raw, codec) {
        (Some(raw), Some(codec)) => codec.decode(scope_id, kind, &raw),
        (Some(raw), None) => Some(raw),
        (None, _) => None,
    })
}

/// Authenticate complete retained history before projecting a kind. Unavailable
/// protected facts must not disappear from a lifecycle or receipt check.
fn retained_kind_payloads(
    conn: &Connection,
    codec: Option<&Arc<dyn ContentCodec>>,
    scope: &str,
    selected: &str,
) -> Result<Vec<String>, AdmitError> {
    let mut statement = conn
        .prepare_cached("SELECT kind, payload FROM events WHERE scope_id = ?1 ORDER BY position")?;
    let rows = statement.query_map([scope], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut selected_rows = Vec::new();
    for row in rows {
        let (kind, raw) = row?;
        let plain = match codec {
            Some(codec) => codec.decode(scope, &kind, &raw).ok_or_else(|| {
                AdmitError::Codec("authority history contains an unavailable record".into())
            })?,
            None => raw,
        };
        if kind == selected {
            selected_rows.push(plain);
        }
    }
    Ok(selected_rows)
}

/// Fold a lifecycle from its newest valid checkpoint, or from the start
/// (SCALE-1, [`snapshot`]). Unavailable retained history still refuses.
fn fold_retained<L: Lifecycle>(
    conn: &Connection,
    codec: Option<&Arc<dyn ContentCodec>>,
    scope: &str,
) -> Result<L::State, AdmitError> {
    snapshot::fold::<L>(conn, codec, scope)
}

fn encode_payload(
    codec: Option<&Arc<dyn ContentCodec>>,
    scope: &str,
    kind: &str,
    payload: &str,
) -> Result<String, AdmitError> {
    match codec {
        Some(codec) => codec
            .encode(scope, kind, payload)
            .map_err(AdmitError::Codec),
        None => Ok(payload.to_owned()),
    }
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
        if let Some(binding) = &self.home_product {
            return home_product::reopen(self, binding, false)
                .map_err(home_product::as_database_error);
        }
        let conn =
            Connection::open_with_flags(&self.path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        home_product::refuse_unbound_open(&conn)?;
        conn.busy_timeout(Duration::from_secs(30))?;
        // The original connection already established the database journal mode
        // and schema. Re-running `PRAGMA journal_mode` and `CREATE TABLE IF NOT
        // EXISTS` here turns every agent turn into an unnecessary schema writer;
        // under a live projection reader SQLite can reject that setup with BUSY
        // before the turn reaches its properly serialized IMMEDIATE transactions.
        // `synchronous` is connection-local, so carry that one setting explicitly.
        let sync = synchronous_mode(gaugedesk_env::var("SQLITE_SYNCHRONOUS").as_deref());
        conn.execute_batch(&format!("PRAGMA synchronous={sync};"))?;
        conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
        Ok(Self {
            conn,
            codec: self.codec.clone(),
            path: self.path.clone(),
            // Share the scratch directory's lifetime: an ephemeral database
            // outlives whichever connection drops first.
            scratch: self.scratch.clone(),
            home_product: None,
            remembered: Default::default(),
        })
    }

    /// Observe existing committed records with the same codec and scratch
    /// lifetime. Opening this connection neither creates nor migrates storage;
    /// SQLite refuses mutation through it. This supplies no authority fence.
    pub fn read_only_sibling(&self) -> Result<Self, rusqlite::Error> {
        if let Some(binding) = &self.home_product {
            return home_product::reopen(self, binding, true)
                .map_err(home_product::as_database_error);
        }
        let conn =
            Connection::open_with_flags(&self.path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        home_product::refuse_unbound_open(&conn)?;
        conn.busy_timeout(Duration::from_secs(30))?;
        Ok(Self {
            conn,
            codec: self.codec.clone(),
            path: self.path.clone(),
            scratch: self.scratch.clone(),
            home_product: None,
            remembered: Default::default(),
        })
    }

    /// The database this store is connected to.
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        home_product::refuse_unbound_open(&conn)?;
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
        self.conn
            .prepare_cached("PRAGMA synchronous")?
            .query_row([], |r| r.get(0))
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
        let revision: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM records WHERE record_id = ?1",
            )?
            .query_row(params![record_id], |row| row.get(0))?;
        tx.prepare_cached(
            "INSERT INTO records
             (record_id, revision, scope_id, kind, tombstone, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?
        .execute(params![
            record_id,
            revision,
            scope_id,
            kind,
            i64::from(tombstone),
            payload
        ])?;
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
        let mut stmt = self.conn.prepare_cached(
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
            .prepare_cached(
                "SELECT record_id, scope_id, kind, revision, tombstone, payload
                 FROM records WHERE record_id = ?1 ORDER BY revision DESC LIMIT 1",
            )?
            .query_row(params![record_id], record_revision_from_row)
            .optional()
            .map_err(Into::into)
    }

    /// Insert or update metadata for out-of-line protected bytes. This API does
    /// not write the bytes: callers stage and atomically place them first.
    pub fn put_content_metadata(&mut self, content: &ContentMetadata) -> Result<(), AdmitError> {
        self.conn
            .prepare_cached(
                "INSERT INTO content(handle, resource_id, sha256, size_bytes, status)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(handle) DO UPDATE SET
               resource_id = excluded.resource_id,
               sha256 = excluded.sha256,
               size_bytes = excluded.size_bytes,
               status = excluded.status,
               updated_at = CURRENT_TIMESTAMP",
            )?
            .execute(params![
                content.handle,
                content.resource_id,
                content.sha256,
                content.size_bytes,
                content.status
            ])?;
        Ok(())
    }

    pub fn content_metadata(&self, handle: &str) -> Result<Option<ContentMetadata>, AdmitError> {
        self.conn
            .prepare_cached(
                "SELECT handle, resource_id, sha256, size_bytes, status
                 FROM content WHERE handle = ?1",
            )?
            .query_row(params![handle], |row| {
                Ok(ContentMetadata {
                    handle: row.get(0)?,
                    resource_id: row.get(1)?,
                    sha256: row.get(2)?,
                    size_bytes: row.get(3)?,
                    status: row.get(4)?,
                })
            })
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
        self.conn
            .prepare_cached(
                "INSERT OR IGNORE INTO commands
             (command_id, scope_id, idempotency_key, status, snapshot_json)
             VALUES (?1, ?2, ?3, 'received', ?4)",
            )?
            .execute(params![
                command_id,
                scope_id,
                idempotency_key,
                snapshot_json
            ])?;
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
        self.claim_command_with_basis(
            command_id,
            (scope_id, idempotency_key),
            snapshot_json,
            None,
            &[],
        )
    }

    /// Claim exact caller intent under current product and process standing.
    /// This authorizes only the receipt commit, never later native execution.
    pub fn claim_command_against(
        &mut self,
        command_id: &str,
        scope_id: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        basis: &command_dispatch::DispatchReadBasis,
    ) -> Result<(CommandRecord, bool), AdmitError> {
        self.claim_command_with_basis(
            command_id,
            (scope_id, idempotency_key),
            snapshot_json,
            Some(basis),
            &[],
        )
    }

    /// Exclude every earlier receipt coordinate under the same claim writer.
    /// A format change never implicitly restarts recorded work.
    pub fn claim_command_excluding(
        &mut self,
        command_id: &str,
        scope_key: (&str, &str),
        snapshot: &str,
        basis: Option<&command_dispatch::DispatchReadBasis>,
        excluded: &[(&str, &str)],
    ) -> Result<(CommandRecord, bool), AdmitError> {
        self.claim_command_with_basis(command_id, scope_key, snapshot, basis, excluded)
    }

    fn claim_command_with_basis(
        &mut self,
        command_id: &str,
        scope_key: (&str, &str),
        snapshot_json: &str,
        basis: Option<&command_dispatch::DispatchReadBasis>,
        excluded: &[(&str, &str)],
    ) -> Result<(CommandRecord, bool), AdmitError> {
        let (scope_id, idempotency_key) = scope_key;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(basis) = basis {
            command_dispatch::check_dispatch_basis(&tx, &self.path, basis)?;
        }
        for (legacy_scope, legacy_key) in excluded {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM commands WHERE scope_id=?1 AND idempotency_key=?2)",
                params![legacy_scope, legacy_key],
                |row| row.get(0),
            )?;
            if exists {
                return Err(AdmitError::Rejected(gaugedesk_core::Rejection {
                    reason: "legacy command receipt requires explicit resolution",
                }));
            }
        }
        tx.prepare_cached(
            "INSERT OR IGNORE INTO commands
             (command_id, scope_id, idempotency_key, status, snapshot_json)
             VALUES (?1, ?2, ?3, 'received', ?4)",
        )?
        .execute(params![
            command_id,
            scope_id,
            idempotency_key,
            snapshot_json
        ])?;
        let mut record = tx
            .prepare_cached(
                "SELECT command_id, scope_id, idempotency_key, status, snapshot_json
                 FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2",
            )?
            .query_row(params![scope_id, idempotency_key], command_record_from_row)
            .optional()?
            .ok_or_else(|| AdmitError::Db(rusqlite::Error::QueryReturnedNoRows))?;
        let claimed = if record.snapshot_json == snapshot_json && record.status == "received" {
            tx.prepare_cached(
                "UPDATE commands SET status = 'processing', updated_at = CURRENT_TIMESTAMP
                 WHERE command_id = ?1 AND status = 'received'",
            )?
            .execute(params![record.command_id])?
                == 1
        } else {
            false
        };
        if claimed {
            record.status = "processing".to_string();
        }
        if let Some(basis) = basis {
            command_dispatch::check_dispatch_basis(&tx, &self.path, basis)?;
        }
        tx.commit()?;
        Ok((record, claimed))
    }

    /// Record failure only for an unfinished, unreceipted command. A denied
    /// response after publication cannot rewrite the already committed fact.
    pub fn set_unreceipted_command_failure(
        &mut self,
        command_id: &str,
        status: &str,
    ) -> Result<bool, AdmitError> {
        if !matches!(status, "rejected" | "expired") {
            return Err(AdmitError::Rejected(gaugedesk_core::Rejection {
                reason: "command failure requires rejected or expired status",
            }));
        }
        let changed = self
            .conn
            .prepare_cached(
                "UPDATE commands SET status = ?2, updated_at = CURRENT_TIMESTAMP
             WHERE command_id = ?1 AND status IN ('received', 'processing')
             AND NOT EXISTS (SELECT 1 FROM command_receipts r
                 WHERE r.scope_id = commands.scope_id
                   AND r.command_key = commands.idempotency_key)",
            )?
            .execute(params![command_id, status])?;
        Ok(changed == 1)
    }

    pub fn set_command_status(
        &mut self,
        command_id: &str,
        status: &str,
    ) -> Result<bool, AdmitError> {
        let changed = self
            .conn
            .prepare_cached(
                "UPDATE commands SET status = ?2, updated_at = CURRENT_TIMESTAMP
             WHERE command_id = ?1",
            )?
            .execute(params![command_id, status])?;
        Ok(changed == 1)
    }

    pub fn command(&self, command_id: &str) -> Result<Option<CommandRecord>, AdmitError> {
        self.conn
            .prepare_cached(
                "SELECT command_id, scope_id, idempotency_key, status, snapshot_json
                 FROM commands WHERE command_id = ?1",
            )?
            .query_row(params![command_id], command_record_from_row)
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
            .prepare_cached(
                "SELECT command_id, scope_id, idempotency_key, status, snapshot_json
                 FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2",
            )?
            .query_row(params![scope_id, idempotency_key], command_record_from_row)
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
            let mut stmt = tx.prepare_cached(
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
                    .prepare_cached(
                        "SELECT 1 FROM command_receipts
                         WHERE scope_id = ?1 AND command_key = ?2",
                    )?
                    .query_row(params![scope_id, key], |_| Ok(()))
                    .optional()?
                    .is_some();
                let status = if committed {
                    applied += 1;
                    "applied"
                } else {
                    expired += 1;
                    "expired"
                };
                tx.prepare_cached(
                    "UPDATE commands SET status = ?2, updated_at = CURRENT_TIMESTAMP
                     WHERE command_id = ?1",
                )?
                .execute(params![command_id, status])?;
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
            .prepare_cached(
                "SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
            )?
            .query_row(params![scope_id, idempotency_key], |_| Ok(()))
            .optional()?
            .is_some();
        if replayed {
            // Repair a command row whose receipt committed just before a process
            // interruption prevented its final status update.
            let state = self.fold::<L>(scope_id)?;
            self.set_command_status(&command_id, "applied")?;
            return Ok(MaterializedAdmission {
                state,
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

    /// The committed head used as the basis for a staged record mutation.
    /// An empty scope has head `-1`. A caller that releases its lock for a
    /// remote authority call must pass this position back to
    /// [`admit_record_facts_at_scope_head`](Self::admit_record_facts_at_scope_head)
    /// after reauthenticating and replanning; this read grants no write lease.
    pub fn record_scope_head(&self, scope_id: &str) -> Result<i64, AdmitError> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(position), -1) FROM events WHERE scope_id = ?1",
            params![scope_id],
            |row| row.get(0),
        )?)
    }

    /// Atomically admit record facts only when `expected_scope` still has the
    /// exact committed head observed by the caller. An empty scope has head
    /// `-1`. The comparison and every append share one immediate transaction,
    /// so a competing writer either wins before this command or after it, never
    /// between its basis check and effects. Exact retries remain replayable
    /// after the first admission advances the expected scope.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_record_facts_at_scope_head(
        &mut self,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        facts: &[CommandRecordFact],
        expected_scope: &str,
        expected_position: i64,
    ) -> Result<MaterializedRecordAdmission, AdmitError> {
        self.admit_record_facts_internal(
            command_scope,
            idempotency_key,
            snapshot_json,
            facts,
            None,
            &[],
            Some((expected_scope, expected_position)),
        )
    }

    /// Observe an exact uncompleted command claim in one read. A lagging
    /// mutable status cannot make a command with a durable receipt pending.
    /// This is retained intent evidence, never an execution grant.
    pub fn pending_command_matches(
        &self,
        command_id: &str,
        scope_id: &str,
        idempotency_key: &str,
        snapshot_json: &str,
    ) -> Result<bool, AdmitError> {
        crate::record_admission::pending_command_matches(
            &self.conn,
            command_id,
            scope_id,
            idempotency_key,
            snapshot_json,
        )
    }

    /// Read the original record command only when its durable receipt exists.
    /// One query supplies a consistent observation, including inside a caller's
    /// read snapshot. Mutable command status is neither repaired nor trusted.
    /// The owning reader must separately verify the corresponding record facts.
    pub fn committed_record_snapshot(
        &self,
        command_scope: &str,
        idempotency_key: &str,
    ) -> Result<Option<String>, AdmitError> {
        let original: Option<(Option<String>, Option<String>)> = self
            .conn
            .prepare_cached(
                "SELECT commands.command_id, commands.snapshot_json
             FROM command_receipts AS receipts
             LEFT JOIN commands ON commands.scope_id = receipts.scope_id
               AND commands.idempotency_key = receipts.command_key
             WHERE receipts.scope_id = ?1 AND receipts.command_key = ?2",
            )?
            .query_row(params![command_scope, idempotency_key], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?;
        let Some((id, snapshot)) = original else {
            return Ok(None);
        };
        record_admission::validate_snapshot(command_scope, idempotency_key, id, snapshot).map(Some)
    }

    /// Read exactly the events appended by one receipted record command,
    /// including facts in other scopes and its chained audit fact. Legacy
    /// receipts without an event map refuse instead of being matched to a
    /// similar historical payload. An unavailable decoded fact also refuses.
    pub fn committed_record_facts(
        &self,
        command_scope: &str,
        idempotency_key: &str,
    ) -> Result<Option<Vec<CommandRecordFact>>, AdmitError> {
        if self
            .committed_record_snapshot(command_scope, idempotency_key)?
            .is_none()
        {
            return Ok(None);
        }
        let invalid = || {
            AdmitError::Rejected(Rejection {
                reason: "committed command fact provenance is missing or inconsistent",
            })
        };
        let expected: i64 = self
            .conn
            .prepare_cached(
                "SELECT fact_count FROM record_command_fact_sets
                 WHERE command_scope = ?1 AND command_key = ?2",
            )?
            .query_row(params![command_scope, idempotency_key], |row| row.get(0))
            .optional()?
            .ok_or_else(invalid)?;
        let mut query = self.conn.prepare_cached(
            "SELECT refs.fact_index, refs.event_scope, events.kind, events.payload
             FROM record_command_fact_refs AS refs
             LEFT JOIN events ON events.scope_id = refs.event_scope
               AND events.position = refs.event_position
             WHERE refs.command_scope = ?1 AND refs.command_key = ?2
             ORDER BY refs.fact_index",
        )?;
        let rows = query.query_map(params![command_scope, idempotency_key], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        let mut facts = Vec::new();
        for row in rows {
            let (index, scope_id, kind, payload) = row?;
            if index != facts.len() as i64 {
                return Err(invalid());
            }
            let (Some(kind), Some(payload)) = (kind, payload) else {
                return Err(invalid());
            };
            let payload = match &self.codec {
                Some(codec) => codec.decode(&scope_id, &kind, &payload).ok_or_else(|| {
                    AdmitError::Codec("committed command contains an unavailable fact".into())
                })?,
                None => payload,
            };
            facts.push(CommandRecordFact {
                scope_id,
                kind,
                payload,
            });
        }
        if facts.len() as i64 != expected {
            return Err(invalid());
        }
        Ok(Some(facts))
    }

    /// Enumerate receipted record commands in one scope without trusting or
    /// repairing mutable command status. Keys are lexical coordinates, not
    /// causal order. Owning readers must verify matching facts under their
    /// current authority fence; orphaned receipts refuse instead of disappearing.
    pub fn committed_record_snapshots(
        &self,
        command_scope: &str,
    ) -> Result<Vec<CommittedRecordSnapshot>, AdmitError> {
        let mut query = self.conn.prepare_cached("SELECT receipts.command_key, commands.command_id, commands.snapshot_json, receipts.applied_at
             FROM command_receipts AS receipts
             LEFT JOIN commands ON commands.scope_id = receipts.scope_id
               AND commands.idempotency_key = receipts.command_key
             WHERE receipts.scope_id = ?1 ORDER BY receipts.command_key",
        )?;
        let rows = query.query_map([command_scope], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (key, id, snapshot, first_fact_position) = row?;
            let snapshot = record_admission::validate_snapshot(command_scope, &key, id, snapshot)?;
            Ok(CommittedRecordSnapshot {
                idempotency_key: key,
                snapshot_json: snapshot,
                first_fact_position,
            })
        })
        .collect()
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
        self.admit_record_facts_with_claims(
            command_scope,
            idempotency_key,
            snapshot_json,
            facts,
            chained,
            &[],
        )
    }

    /// Atomically claim the ordinary request key and additional unique command
    /// identities. Every requested retry claim must already belong to this
    /// request. A historical receipt cannot retroactively acquire an identity
    /// or borrow another request's claim with an identical application payload.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_record_facts_with_claims(
        &mut self,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        facts: &[CommandRecordFact],
        chained: Option<ChainedRecordFact<'_>>,
        claims: &[RecordCommandClaim<'_>],
    ) -> Result<MaterializedRecordAdmission, AdmitError> {
        self.admit_record_facts_internal(
            command_scope,
            idempotency_key,
            snapshot_json,
            facts,
            chained,
            claims,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_record_facts_internal(
        &mut self,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        facts: &[CommandRecordFact],
        chained: Option<ChainedRecordFact<'_>>,
        claims: &[RecordCommandClaim<'_>],
        expected_head: Option<(&str, i64)>,
    ) -> Result<MaterializedRecordAdmission, AdmitError> {
        let mut claim_keys = std::collections::BTreeSet::new();
        if claims.len() > 16
            || claims.iter().any(|claim| {
                claim.key.is_empty()
                    || claim.key == idempotency_key
                    || !claim_keys.insert(claim.key)
            })
        {
            return Err(AdmitError::Rejected(Rejection {
                reason: "invalid additional command claims",
            }));
        }
        let stored = record_admission::encode_facts(self.codec.as_ref(), facts)?;
        let command_id = format!(
            "record-command:{}:{command_scope}{idempotency_key}",
            command_scope.len()
        );
        let codec = self.codec.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        if record.snapshot_json != snapshot_json {
            return Err(AdmitError::Rejected(Rejection {
                reason: "idempotency key reused with different command",
            }));
        }
        let replayed = tx
            .prepare_cached(
                "SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
            )?
            .query_row(params![command_scope, idempotency_key], |_| Ok(()))
            .optional()?
            .is_some();
        for claim in claims {
            let expected_claim = serde_json::to_string(&(
                "record-command-claim-v1",
                command_scope,
                idempotency_key,
                claim.snapshot,
            ))?;
            let claimed = tx.prepare_cached("SELECT snapshot_json FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2")?.query_row(
                params![command_scope, claim.key], |row| row.get::<_, String>(0),
            ).optional()?;
            match claimed {
                Some(snapshot) if snapshot != expected_claim || !replayed => {
                    return Err(AdmitError::Rejected(Rejection {
                        reason: "additional command identity is already claimed",
                    }))
                }
                Some(_) => {
                    let receipted = tx.prepare_cached("SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2")?.query_row( params![command_scope, claim.key], |_| Ok(())).optional()?.is_some();
                    if !receipted {
                        return Err(AdmitError::Rejected(Rejection {
                            reason: "additional command claim has no receipt",
                        }));
                    }
                }
                None if replayed => {
                    return Err(AdmitError::Rejected(Rejection {
                        reason: "original receipt does not own additional command claim",
                    }))
                }
                None => {}
            }
        }
        if replayed {
            tx.prepare_cached(
                "UPDATE commands SET status = 'applied', updated_at = CURRENT_TIMESTAMP
                 WHERE command_id = ?1",
            )?
            .execute(params![record.command_id])?;
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
        if let Some((expected_scope, expected_position)) = expected_head {
            let actual_position: i64 = tx
                .prepare_cached(
                    "SELECT COALESCE(MAX(position), -1) FROM events WHERE scope_id = ?1",
                )?
                .query_row(params![expected_scope], |row| row.get(0))?;
            if actual_position != expected_position {
                return Err(AdmitError::Rejected(Rejection {
                    reason: "scope head changed before record admission",
                }));
            }
        }
        tx.prepare_cached(
            "UPDATE commands SET status = 'processing', updated_at = CURRENT_TIMESTAMP
             WHERE command_id = ?1 AND status = 'received'",
        )?
        .execute(params![record.command_id])?;

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
            tx.prepare_cached(
                "INSERT INTO record_command_fact_refs
                 (command_scope, command_key, fact_index, event_scope, event_position)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?
            .execute(params![
                command_scope,
                idempotency_key,
                positions.len() as i64,
                fact.scope_id,
                position,
            ])?;
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
            let position: i64 = tx
                .prepare_cached(
                    "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
                )?
                .query_row(params![chained.scope_id], |row| row.get(0))?;
            tx.prepare_cached(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![chained.scope_id, position, chained.kind, encoded])?;
            tx.prepare_cached(
                "INSERT INTO record_command_fact_refs
                 (command_scope, command_key, fact_index, event_scope, event_position)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?
            .execute(params![
                command_scope,
                idempotency_key,
                positions.len() as i64,
                chained.scope_id,
                position,
            ])?;
            positions.push(position);
            chained_payload = Some(payload);
        }
        let applied_at = positions.first().copied().unwrap_or(0);
        tx.prepare_cached(
            "INSERT INTO record_command_fact_sets (command_scope, command_key, fact_count)
             VALUES (?1, ?2, ?3)",
        )?
        .execute(params![
            command_scope,
            idempotency_key,
            positions.len() as i64
        ])?;
        tx.prepare_cached(
            "INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)",
        )?
        .execute(params![command_scope, idempotency_key, applied_at])?;
        tx.prepare_cached(
            "UPDATE commands SET status = 'applied', updated_at = CURRENT_TIMESTAMP
             WHERE command_id = ?1",
        )?
        .execute(params![record.command_id])?;
        for claim in claims {
            let claim_id = format!(
                "record-command:{}:{command_scope}{}",
                command_scope.len(),
                claim.key
            );
            let claim_snapshot = serde_json::to_string(&(
                "record-command-claim-v1",
                command_scope,
                idempotency_key,
                claim.snapshot,
            ))?;
            tx.prepare_cached("INSERT INTO commands (command_id, scope_id, idempotency_key, status, snapshot_json) VALUES (?1, ?2, ?3, 'applied', ?4)")?.execute( params![claim_id, command_scope, claim.key, claim_snapshot])?;
            tx.prepare_cached("INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)")?.execute( params![command_scope, claim.key, applied_at])?;
        }
        tx.commit()?;
        Ok(MaterializedRecordAdmission {
            positions,
            replayed: false,
            chained_payload,
        })
    }

    pub fn put_projection_meta(&mut self, meta: &ProjectionMeta) -> Result<(), AdmitError> {
        self.conn
            .prepare_cached(
                "INSERT INTO projection_meta
             (projection, scope_id, version, high_water, dirty)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(projection, scope_id) DO UPDATE SET
               version = excluded.version,
               high_water = excluded.high_water,
               dirty = excluded.dirty,
               updated_at = CURRENT_TIMESTAMP",
            )?
            .execute(params![
                meta.projection,
                meta.scope_id,
                meta.version,
                meta.high_water,
                i64::from(meta.dirty)
            ])?;
        Ok(())
    }

    pub fn projection_meta(
        &self,
        projection: &str,
        scope_id: &str,
    ) -> Result<Option<ProjectionMeta>, AdmitError> {
        self.conn
            .prepare_cached(
                "SELECT projection, scope_id, version, high_water, dirty
                 FROM projection_meta WHERE projection = ?1 AND scope_id = ?2",
            )?
            .query_row(params![projection, scope_id], |row| {
                Ok(ProjectionMeta {
                    projection: row.get(0)?,
                    scope_id: row.get(1)?,
                    version: row.get(2)?,
                    high_water: row.get(3)?,
                    dirty: row.get::<_, i64>(4)? != 0,
                })
            })
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
        self.conn
            .prepare_cached(
                "INSERT INTO scopes(scope_id, authority, lifecycle, subject_id)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(scope_id) DO UPDATE SET
               authority = excluded.authority,
               lifecycle = excluded.lifecycle,
               subject_id = excluded.subject_id",
            )?
            .execute(params![scope_id, authority, lifecycle, subject_id])?;
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
        self.conn
            .prepare_cached(
                "INSERT OR IGNORE INTO observations
             (observation_id, run_ref, kind, payload_ref)
             VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![observation_id, run_ref, kind, payload_ref])?;
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
            .prepare_cached("SELECT 1 FROM events WHERE scope_id = ?1 AND position = ?2")?
            .query_row(params![scope_id, position], |_| Ok(()))
            .optional()?
            .is_some();
        if !event_exists {
            return Ok(false);
        }
        let changed = self
            .conn
            .prepare_cached(
                "UPDATE observations
             SET admitted_scope = ?2, admitted_position = ?3
             WHERE observation_id = ?1
               AND admitted_scope IS NULL AND admitted_position IS NULL",
            )?
            .execute(params![observation_id, scope_id, position])?;
        Ok(changed == 1)
    }

    pub fn observation(
        &self,
        observation_id: &str,
    ) -> Result<Option<ObservationRecord>, AdmitError> {
        self.conn
            .prepare_cached(
                "SELECT observation_id, run_ref, kind, payload_ref,
                        admitted_scope, admitted_position
                 FROM observations WHERE observation_id = ?1",
            )?
            .query_row(params![observation_id], |row| {
                Ok(ObservationRecord {
                    observation_id: row.get(0)?,
                    run_ref: row.get(1)?,
                    kind: row.get(2)?,
                    payload_ref: row.get(3)?,
                    admitted_scope: row.get(4)?,
                    admitted_position: row.get(5)?,
                })
            })
            .optional()
            .map_err(Into::into)
    }

    /// The greatest schema version recorded in this store's `schema_migrations`
    /// ledger — after a successful open, always [`SUPPORTED_SCHEMA_VERSION`]
    /// (open applies every pending migration and refuses a newer database).
    pub fn schema_version(&self) -> Result<i64, rusqlite::Error> {
        self.conn
            .prepare_cached("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")?
            .query_row([], |row| row.get(0))
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
        // Every statement this store runs is a constant, and every read and
        // write prepares its statement through the connection's cache, so a
        // statement is compiled once per connection rather than once per call.
        // The store has about sixty distinct statements; rusqlite's default
        // cache of sixteen would evict them against each other.
        conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version    INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );",
        )?;
        let recorded: i64 = conn
            .prepare_cached("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")?
            .query_row([], |row| row.get(0))?;
        if recorded > SUPPORTED_SCHEMA_VERSION {
            return Err(schema_ahead_error(&path, recorded));
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for migration in MIGRATIONS {
            let applied = tx
                .prepare_cached("SELECT 1 FROM schema_migrations WHERE version = ?1")?
                .query_row([migration.version], |_| Ok(()))
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
            tx.prepare_cached("INSERT INTO schema_migrations(version) VALUES (?1)")?
                .execute([migration.version])?;
        }
        tx.commit()?;
        Ok(Self {
            conn,
            codec: None,
            path,
            scratch: None,
            home_product: None,
            remembered: Default::default(),
        })
    }

    /// Fold a lifecycle's events within a scope into current state (`INV-8`:
    /// state is the fold). Events are filtered by `L::KIND` so distinct
    /// lifecycles (a run, its review, its export) can coexist in one scope.
    pub fn fold<L: Lifecycle>(&self, scope_id: &str) -> Result<L::State, AdmitError> {
        fold_retained::<L>(&self.conn, self.codec.as_ref(), scope_id)
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
        let position: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            )?
            .query_row(params![scope_id], |r| r.get(0))?;
        tx.prepare_cached(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
        )?
        .execute(params![scope_id, position, kind, stored])?;
        tx.commit()?;
        Ok(position)
    }

    /// Append one owning record and a position-linked companion in another
    /// scope as one commit. The link receives the actual owning position under
    /// the SQLite write lock; any encode/link/write failure rolls both back.
    pub fn append_record_with_linked_record(
        &mut self,
        scope: &str,
        kind: &str,
        payload: &str,
        companion_scope: &str,
        companion_kind: &str,
        link: impl FnOnce(i64) -> Result<String, AdmitError>,
    ) -> Result<i64, AdmitError> {
        let codec = self.codec.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let position: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            )?
            .query_row(params![scope], |row| row.get(0))?;
        let companion = link(position)?;
        for (record_scope, record_kind, record_payload) in [
            (scope, kind, payload),
            (companion_scope, companion_kind, companion.as_str()),
        ] {
            let stored = match &codec {
                Some(codec) => codec
                    .encode(record_scope, record_kind, record_payload)
                    .map_err(AdmitError::Codec)?,
                None => record_payload.to_owned(),
            };
            let assigned: i64 = tx
                .prepare_cached(
                    "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
                )?
                .query_row(params![record_scope], |row| row.get(0))?;
            tx.prepare_cached(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![record_scope, assigned, record_kind, stored])?;
        }
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
        let position: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            )?
            .query_row(params![scope_id], |r| r.get(0))?;
        tx.prepare_cached(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
        )?
        .execute(params![scope_id, position, kind, stored])?;
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
            let position: i64 = tx
                .prepare_cached(
                    "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
                )?
                .query_row(params![scope], |row| row.get(0))?;
            tx.prepare_cached(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![scope, position, kind, payload])?;
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
        // Bound before the `if let`: a scrutinee's cached statement would
        // otherwise live through the block that commits, and moves, the
        // transaction it borrows.
        let already_applied = tx
            .prepare_cached(
                "SELECT applied_at FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
            )?
            .query_row(params![scope_id, command_key], |row| row.get::<_, i64>(0))
            .optional()?;
        if let Some(position) = already_applied {
            tx.commit()?;
            return Ok((position, false));
        }
        let position: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            )?
            .query_row(params![scope_id], |row| row.get(0))?;
        tx.prepare_cached(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
        )?
        .execute(params![scope_id, position, kind, stored])?;
        tx.prepare_cached(
            "INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)",
        )?
        .execute(params![scope_id, command_key, position])?;
        tx.commit()?;
        Ok((position, true))
    }

    /// A stamp that changes whenever a read of `scopes` may answer
    /// differently: an event appended to one of them, through any connection,
    /// or the codec changing how it opens one of them. A projection folded
    /// from those scopes alone may be remembered while the stamp is unchanged.
    ///
    /// A scope's head is its greatest position. Events are only ever appended,
    /// so the head moves with every change to the scope and with nothing
    /// else: a write to another scope leaves the stamp, and whatever was
    /// remembered against it, alone. Dispatch authorization rests on the same
    /// heads.
    ///
    /// `None` when nothing may be remembered: a transaction is open on this
    /// connection, whose reads see writes that may yet roll back, or the codec
    /// cannot say when its answers for one of the scopes change.
    pub fn read_stamp(&self, scopes: &[&str]) -> Option<ReadStamp> {
        if !self.conn.is_autocommit() {
            return None;
        }
        let mut codec_epoch = 0_u64;
        if let Some(codec) = &self.codec {
            for scope in scopes {
                codec_epoch = codec_epoch.wrapping_add(codec.epoch(scope)?);
            }
        }
        let mut statement = self
            .conn
            .prepare_cached("SELECT MAX(position) FROM events WHERE scope_id = ?1")
            .ok()?;
        let heads = scopes
            .iter()
            .map(|scope| statement.query_row(params![scope], |row| row.get::<_, Option<i64>>(0)))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        Some(ReadStamp { heads, codec_epoch })
    }

    /// `fold` of `scope`, answered from this connection's memory while
    /// nothing a read of `scope` could answer differently has changed (see
    /// [`read_stamp`](Self::read_stamp)), and for at most [`REMEMBERED_FOR`].
    /// `name` names the fold, so two folds of one scope are remembered apart.
    ///
    /// `fold` must read nothing but `scope`: a change to any other scope does
    /// not move the stamp it is remembered against. An error is never
    /// remembered, and nothing is remembered inside a transaction or through
    /// a codec that cannot say when its answers change.
    ///
    /// The Hub folds the same organization and account scopes on almost every
    /// request, under the Workbench lock, and between two writes the answer is
    /// the same each time (WS-1010).
    pub fn remember<T: Clone + Send + 'static>(
        &self,
        name: &'static str,
        scope: &str,
        fold: impl FnOnce(&Store) -> Result<T, AdmitError>,
    ) -> Result<T, AdmitError> {
        let Some(stamp) = self.read_stamp(&[scope]) else {
            return fold(self);
        };
        let key = (name, scope.to_owned());
        {
            let remembered = self
                .remembered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(value) = remembered
                .folds
                .get(&key)
                .filter(|found| found.stamp == stamp && found.at.elapsed() < REMEMBERED_FOR)
                .and_then(|found| found.value.downcast_ref::<T>())
            {
                return Ok(value.clone());
            }
        }
        // The stamp was taken before the fold, so a change during it leaves
        // the answer remembered under a stamp no later read will match.
        let value = fold(self)?;
        let mut remembered = self
            .remembered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        remembered
            .folds
            .retain(|_, found| found.at.elapsed() < REMEMBERED_FOR);
        if remembered.folds.len() >= FOLDS_REMEMBERED {
            remembered.folds.clear();
        }
        remembered.folds.insert(
            key,
            RememberedFold {
                stamp,
                at: std::time::Instant::now(),
                value: Box::new(value.clone()),
            },
        );
        Ok(value)
    }

    /// All records of one `kind` in a scope, in order — a durable projection
    /// source (e.g. the transcript snapshot). A content codec (`SECAUD-9/6`) decodes
    /// each row; a crypto-erased row (`decode` ⇒ `None`) is dropped (content gone).
    pub fn records(&self, scope_id: &str, kind: &str) -> Result<Vec<String>, AdmitError> {
        let payloads = self.kind_payloads(scope_id, kind)?;
        Ok(self
            .decode_kind(scope_id, kind, payloads)
            .into_iter()
            .flatten()
            .collect())
    }

    fn kind_payloads(&self, scope_id: &str, kind: &str) -> Result<Vec<String>, AdmitError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 ORDER BY position",
        )?;
        let rows = stmt.query_map(params![scope_id, kind], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Decode payloads of one kind in one scope with one codec read, so a
    /// codec that resolves its scope key does so once rather than per row.
    fn decode_kind(
        &self,
        scope_id: &str,
        kind: &str,
        payloads: Vec<String>,
    ) -> Vec<Option<String>> {
        match &self.codec {
            Some(codec) => {
                let rows: Vec<(&str, &str)> = payloads
                    .iter()
                    .map(|payload| (kind, payload.as_str()))
                    .collect();
                decode_scope(codec.as_ref(), scope_id, &rows)
            }
            None => payloads.into_iter().map(Some).collect(),
        }
    }

    /// The decoded records of one `kind` for an authority fold. Like
    /// [`Self::retained_events`], an unavailable record refuses the read instead
    /// of disappearing, but only the named kind is read and decoded.
    pub fn retained_records(&self, scope_id: &str, kind: &str) -> Result<Vec<String>, AdmitError> {
        let payloads = self.kind_payloads(scope_id, kind)?;
        self.decode_kind(scope_id, kind, payloads)
            .into_iter()
            .map(|plain| {
                plain.ok_or_else(|| {
                    AdmitError::Codec("authority history contains an unavailable record".into())
                })
            })
            .collect()
    }

    /// All decoded records of one `kind`, paired with the exact scope that owns
    /// each row. This is deliberately narrower than a general event scan: it is
    /// used by erasure cascades that must discover independently keyed child
    /// content before destroying an account or tenant key.
    ///
    /// Crypto-erased rows are omitted exactly as they are from [`Self::records`].
    /// Callers still have to authorize and filter the returned domain records;
    /// this is an internal storage primitive, not a projection API.
    pub fn records_across_scopes(&self, kind: &str) -> Result<Vec<(String, String)>, AdmitError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT scope_id, payload FROM events WHERE kind = ?1 ORDER BY scope_id, position",
        )?;
        let rows = stmt.query_map(params![kind], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        let mut out = Vec::new();
        // Rows arrive grouped by scope; each scope's run is decoded together.
        let mut start = 0;
        while start < rows.len() {
            let scope = rows[start].0.clone();
            let end = rows[start..]
                .iter()
                .position(|(other, _)| *other != scope)
                .map_or(rows.len(), |offset| start + offset);
            let payloads = rows[start..end]
                .iter()
                .map(|(_, payload)| payload.clone())
                .collect();
            for plain in self
                .decode_kind(&scope, kind, payloads)
                .into_iter()
                .flatten()
            {
                out.push((scope.clone(), plain));
            }
            start = end;
        }
        Ok(out)
    }

    /// The full event history for a scope, in order — the audit timeline
    /// (`INV-6`: the log is append-only and is the record). Returns
    /// `(position, kind, payload)` rows across all lifecycles in the scope. A content
    /// codec decodes content kinds; a crypto-erased content row is dropped.
    pub fn events(&self, scope_id: &str) -> Result<Vec<(i64, String, String)>, AdmitError> {
        self.read_events(scope_id, false)
    }

    /// Full history for an authority fold. Unavailable records refuse the read
    /// instead of disappearing and potentially undoing a retained revocation.
    pub fn retained_events(
        &self,
        scope_id: &str,
    ) -> Result<Vec<(i64, String, String)>, AdmitError> {
        self.read_events(scope_id, true)
    }

    fn read_events(
        &self,
        scope_id: &str,
        require_retained: bool,
    ) -> Result<Vec<(i64, String, String)>, AdmitError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT position, kind, payload FROM events WHERE scope_id = ?1 ORDER BY position",
        )?;
        let rows = stmt.query_map(params![scope_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        let Some(codec) = &self.codec else {
            return Ok(rows);
        };
        let pairs: Vec<(&str, &str)> = rows
            .iter()
            .map(|(_, kind, payload)| (kind.as_str(), payload.as_str()))
            .collect();
        let decoded = decode_scope(codec.as_ref(), scope_id, &pairs);
        let mut out = Vec::with_capacity(rows.len());
        for ((pos, kind, _), plain) in rows.into_iter().zip(decoded) {
            match plain {
                Some(plain) => out.push((pos, kind, plain)),
                None if require_retained => {
                    return Err(AdmitError::Codec(
                        "authority history contains an unavailable record".into(),
                    ))
                }
                None => {}
            }
        }
        Ok(out)
    }

    /// Every scope whose id starts with `prefix`, in order. It reads only the
    /// scope index's range for the prefix, where
    /// [`scope_high_water_marks`](Self::scope_high_water_marks) aggregates
    /// every event the store holds: a project's tracker discovery ran that
    /// over a Home's whole history on every task-bar read (WS-926).
    pub fn scopes_with_prefix(&self, prefix: &str) -> Result<Vec<String>, AdmitError> {
        // Every id with the prefix sorts at or after it and before its
        // successor; the equality filter keeps the answer exact regardless.
        let rows = match prefix_successor(prefix) {
            Some(successor) => self
                .conn
                .prepare_cached(
                    "SELECT DISTINCT scope_id FROM events \
                     WHERE scope_id >= ?1 AND scope_id < ?2 \
                     AND substr(scope_id, 1, length(?1)) = ?1 ORDER BY scope_id",
                )?
                .query_map(params![prefix, successor], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?,
            None => self
                .conn
                .prepare_cached(
                    "SELECT DISTINCT scope_id FROM events \
                     WHERE scope_id >= ?1 \
                     AND substr(scope_id, 1, length(?1)) = ?1 ORDER BY scope_id",
                )?
                .query_map(params![prefix], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?,
        };
        Ok(rows)
    }

    /// Monotonic high-water cursor for every admitted scope. Migration and
    /// backup verification use this compact projection to prove that no scope
    /// was truncated without reading or exporting content bodies.
    pub fn scope_high_water_marks(
        &self,
    ) -> Result<std::collections::BTreeMap<String, i64>, AdmitError> {
        let mut statement = self.conn.prepare_cached(
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
        self.remembered = Default::default();
        self
    }

    /// Every distinct scope id present in the log, ordered. The seam for capturing a
    /// subtree (e.g. a project's owned scopes for relocation) without a separate index.
    pub fn scope_ids(&self) -> Result<Vec<String>, AdmitError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT DISTINCT scope_id FROM events ORDER BY scope_id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Page scope identifiers containing an event kind, without decoding any
    /// payload. The lexical cursor orders discovery only; it is not causal order
    /// or a consistent cross-page snapshot. A new discovery pass finds appends
    /// before an earlier cursor. The limit bounds returned rows, not scan cost.
    pub fn scope_ids_with_kind(
        &self,
        kind: &str,
        after: Option<&str>,
        limit: std::num::NonZeroUsize,
    ) -> Result<Vec<String>, AdmitError> {
        let limit = i64::try_from(limit.get()).map_err(|_| {
            AdmitError::Rejected(Rejection {
                reason: "scope discovery page size is out of range",
            })
        })?;
        let mut stmt = self.conn.prepare_cached(
            "SELECT DISTINCT scope_id FROM events
             WHERE kind = ?1 AND (?2 IS NULL OR scope_id > ?2)
             ORDER BY scope_id LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![kind, after, limit], |row| row.get(0))?;
        rows.collect::<Result<Vec<String>, _>>().map_err(Into::into)
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
        let state = fold_retained::<L>(&tx, self.codec.as_ref(), scope_id)?;
        let events = L::decide(&state, command).map_err(AdmitError::Rejected)?;

        // Next position is global per scope so the per-scope order is total
        // across all lifecycles, even though the fold filters by kind.
        let base: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            )?
            .query_row(params![scope_id], |r| r.get(0))?;
        let mut new_state = state;
        for (offset, event) in events.into_iter().enumerate() {
            let position = base + offset as i64;
            let payload = encode_payload(
                self.codec.as_ref(),
                scope_id,
                L::KIND,
                &serde_json::to_string(&event)?,
            )?;
            tx.prepare_cached(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![scope_id, position, L::KIND, payload])?;
            new_state = L::evolve(&new_state, event);
        }
        snapshot::checkpoint::<L>(&tx, self.codec.as_ref(), scope_id, &new_state)?;
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
        let fold =
            |tx: &rusqlite::Transaction| fold_retained::<L>(tx, self.codec.as_ref(), scope_id);

        // Already applied this key? Idempotent no-op: return current state.
        let seen: bool = tx
            .prepare_cached(
                "SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
            )?
            .query_row(params![scope_id, command_key], |_| Ok(()))
            .optional()?
            .is_some();
        if seen {
            let state = fold(&tx)?;
            tx.commit()?;
            return Ok(state);
        }

        let state = fold(&tx)?;
        let events = L::decide(&state, command).map_err(AdmitError::Rejected)?;
        let base: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            )?
            .query_row(params![scope_id], |r| r.get(0))?;
        let mut new_state = state;
        for (offset, event) in events.into_iter().enumerate() {
            let position = base + offset as i64;
            let payload = encode_payload(
                self.codec.as_ref(),
                scope_id,
                L::KIND,
                &serde_json::to_string(&event)?,
            )?;
            tx.prepare_cached(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![scope_id, position, L::KIND, payload])?;
            new_state = L::evolve(&new_state, event);
        }
        // Record the receipt only on a *successful* (non-rejected) admission, in
        // the same transaction — so a rejected command leaves no receipt and can
        // be legitimately retried, while an accepted one is sealed against replay.
        tx.prepare_cached(
            "INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)",
        )?
        .execute(params![scope_id, command_key, base])?;
        snapshot::checkpoint::<L>(&tx, self.codec.as_ref(), scope_id, &new_state)?;
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
    #[test]
    fn changed_command_scope_excludes_every_prior_coordinate() {
        let excluded = [
            ("old-raw-path", "raw-key"),
            ("old-opaque-key-path", "opaque-key"),
        ];
        for (scope, key) in excluded {
            let mut store = Store::open_in_memory().unwrap();
            store
                .claim_command("old", scope, key, "old snapshot")
                .unwrap();
            assert!(store
                .claim_command_excluding(
                    "new",
                    ("opaque-path", "opaque-key"),
                    "new snapshot",
                    None,
                    &excluded,
                )
                .is_err());
            assert!(store
                .command_for_key("opaque-path", "opaque-key")
                .unwrap()
                .is_none());
            assert_eq!(
                store
                    .command_for_key(scope, key)
                    .unwrap()
                    .unwrap()
                    .snapshot_json,
                "old snapshot"
            );
        }
        let mut store = Store::open_in_memory().unwrap();
        assert!(
            store
                .claim_command_excluding(
                    "new",
                    ("opaque-path", "opaque-key"),
                    "new snapshot",
                    None,
                    &excluded,
                )
                .unwrap()
                .1
        );
        assert!(
            !store
                .claim_command_excluding(
                    "new",
                    ("opaque-path", "opaque-key"),
                    "new snapshot",
                    None,
                    &excluded,
                )
                .unwrap()
                .1
        );
    }

    #[test]
    fn opaque_command_claim_never_restarts_a_legacy_receipt() {
        for status in ["received", "processing", "applied", "rejected", "expired"] {
            let mut store = Store::open_in_memory().unwrap();
            store
                .claim_command("legacy", "scope", "raw-key", "original")
                .unwrap();
            store.set_command_status("legacy", status).unwrap();
            assert!(
                store
                    .claim_command_excluding(
                        "opaque",
                        ("scope", "opaque-key"),
                        "original",
                        None,
                        &[("scope", "raw-key")],
                    )
                    .is_err(),
                "{status}"
            );
            assert!(store
                .command_for_key("scope", "opaque-key")
                .unwrap()
                .is_none());
            assert_eq!(
                store
                    .command_for_key("scope", "raw-key")
                    .unwrap()
                    .unwrap()
                    .status,
                status
            );
        }
        let mut store = Store::open_in_memory().unwrap();
        let (_, claimed) = store
            .claim_command_excluding(
                "opaque",
                ("scope", "opaque-key"),
                "original",
                None,
                &[("scope", "raw-key")],
            )
            .unwrap();
        assert!(claimed);
        let (record, claimed) = store
            .claim_command_excluding(
                "opaque",
                ("scope", "opaque-key"),
                "original",
                None,
                &[("scope", "raw-key")],
            )
            .unwrap();
        assert!(!claimed);
        assert_eq!(record.snapshot_json, "original");
    }

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

    #[test]
    fn main_v10_upgrades_to_recorded_pairs_without_replacing_existing_authorities() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("main-v10.sqlite");
        let original = {
            let store = Store::open(path.to_str().unwrap()).unwrap();
            store.conn.execute_batch("DROP TABLE command_pair_results; DROP TABLE scope_snapshots; DELETE FROM schema_migrations WHERE version>=11;").unwrap();
            store.conn.execute("INSERT INTO home_reference_journal_bindings(project_id,home_id,incarnation) VALUES ('original-project','original-home',?1)", ["a".repeat(32)]).unwrap();
            store.conn.execute("INSERT INTO project_authority_keys(project_id,authority_id,public_key,custody,wrapped_seed) VALUES ('original-project','original-authority',?1,'project-v1',?2)", rusqlite::params![format!("04{}", "a".repeat(128)), vec![42_u8; 32]]).unwrap();
            let created: String = store
                .conn
                .query_row(
                    "SELECT value FROM store_meta WHERE key='created_at'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(store.schema_version().unwrap(), 10);
            created
        };
        for _ in 0..2 {
            let store = Store::open(path.to_str().unwrap()).unwrap();
            assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
            let created: String = store
                .conn
                .query_row(
                    "SELECT value FROM store_meta WHERE key='created_at'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(created, original);
            assert_eq!(store.conn.query_row("SELECT home_id FROM home_reference_journal_bindings WHERE project_id='original-project'", [], |row| row.get::<_, String>(0)).unwrap(), "original-home");
            let key = store
                .project_authority_key("original-project")
                .unwrap()
                .unwrap();
            assert_eq!(key.authority_id, "original-authority");
            assert_eq!(key.wrapped_seed, vec![42_u8; 32]);
            let rows: i64 = store
                .conn
                .query_row("SELECT COUNT(*) FROM command_pair_results", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "upgrade cannot retrofit origin evidence");
        }
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
        assert_eq!(
            versions,
            (1..=SUPPORTED_SCHEMA_VERSION).collect::<Vec<_>>(),
            "each migration recorded exactly once"
        );
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
            assert_eq!(
                rows, SUPPORTED_SCHEMA_VERSION,
                "no duplicate ledger rows on re-open"
            );
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
                    "DELETE FROM schema_migrations WHERE version > 1; \
                     DROP TABLE store_meta; \
                     DROP TABLE home_reference_use_pins; \
                     DROP TABLE home_reference_refusals; \
                     DROP TABLE home_reference_seals; \
                     DROP TABLE home_reference_operations; \
                     DROP TABLE home_reference_state;",
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
        assert_eq!(
            SchemaAhead::of(&error),
            Some(&SchemaAhead {
                path: path.clone(),
                found: 999,
                supported: SUPPORTED_SCHEMA_VERSION
            }),
            "the refusal is recognisable without reading its text"
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

    #[test]
    fn read_only_sibling_preserves_codec_live_commits_and_scratch_lifetime() {
        let mut store = Store::open_in_memory().unwrap();
        let codec = Arc::new(RevCodec {
            erased: Default::default(),
        });
        store.codec = Some(codec.clone());
        store.append_record("s", "secret", "original").unwrap();
        let mut observer = store.read_only_sibling().unwrap();
        assert_eq!(observer.records("s", "secret").unwrap(), ["original"]);
        store.append_record("s", "secret", "later").unwrap();
        assert_eq!(
            observer.records("s", "secret").unwrap(),
            ["original", "later"]
        );
        assert!(observer.append_record("s", "secret", "forbidden").is_err());
        assert!(observer
            .conn
            .execute_batch("CREATE TABLE forbidden (id INTEGER)")
            .is_err());
        let path = std::path::PathBuf::from(store.path());
        drop(store);
        assert!(path.exists());
        assert_eq!(
            observer.records("s", "secret").unwrap(),
            ["original", "later"]
        );
        codec.erased.lock().unwrap().insert("s".into());
        assert!(observer.records("s", "secret").unwrap().is_empty());
        drop(observer);
        assert!(!path.exists());
    }

    #[test]
    fn read_only_sibling_never_recreates_missing_storage_or_initializes_empty_schema() {
        let store = Store::open_in_memory().unwrap();
        let path = std::path::PathBuf::from(store.path());
        std::fs::remove_file(&path).unwrap();
        assert!(store.read_only_sibling().is_err());
        assert!(!path.exists());
        let empty = Connection::open(&path).unwrap();
        drop(empty);
        let observer = store.read_only_sibling().unwrap();
        assert!(observer.records("s", "evt").is_err());
        let tables: i64 = observer
            .conn
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))
            .unwrap();
        assert_eq!(tables, 0);
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
    fn scope_head_bound_record_admission_is_atomic_and_replayable() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(store.record_scope_head("account-auth").unwrap(), -1);
        store
            .append_record("account-auth", "legacy", r#"{"id":"alice"}"#)
            .unwrap();
        assert_eq!(store.record_scope_head("account-auth").unwrap(), 0);
        let facts = vec![
            CommandRecordFact {
                scope_id: "account-auth".into(),
                kind: "account-auth-custody".into(),
                payload: r#"{"state":"copying"}"#.into(),
            },
            CommandRecordFact {
                scope_id: "account-auth::alice".into(),
                kind: "account_auth_email".into(),
                payload: r#"{"email":"alice@example.com"}"#.into(),
            },
        ];

        let first = store
            .admit_record_facts_at_scope_head(
                "account-auth",
                "migrate-alice",
                r#"{"account_id":"alice","source_position":0}"#,
                &facts,
                "account-auth",
                0,
            )
            .unwrap();
        assert_eq!(first.positions, vec![1, 0]);
        assert!(!first.replayed);
        assert_eq!(store.record_scope_head("account-auth").unwrap(), 1);

        let replay = store
            .admit_record_facts_at_scope_head(
                "account-auth",
                "migrate-alice",
                r#"{"account_id":"alice","source_position":0}"#,
                &facts,
                "account-auth",
                0,
            )
            .unwrap();
        assert!(
            replay.replayed,
            "the advanced head does not defeat an exact retry"
        );
        assert!(replay.positions.is_empty());
        assert_eq!(
            store
                .records("account-auth", "account-auth-custody")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .records("account-auth::alice", "account_auth_email")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn committed_command_facts_name_only_their_exact_cross_scope_events() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .append_record("org::tenant", "org", r#"{"op":"tombstone","id":"older"}"#)
            .unwrap();
        let facts = vec![
            CommandRecordFact {
                scope_id: "org::tenant".into(),
                kind: "org".into(),
                payload: r#"{"op":"tombstone","id":"current"}"#.into(),
            },
            CommandRecordFact {
                scope_id: "command:closure".into(),
                kind: "member-denial".into(),
                payload: r#"{"member":"person:one"}"#.into(),
            },
        ];
        assert!(store
            .committed_record_facts("command:closure", "close-one")
            .unwrap()
            .is_none());
        store
            .admit_record_facts("command:closure", "close-one", "closure snapshot", &facts)
            .unwrap();
        store
            .append_record("org::tenant", "org", r#"{"op":"upsert","id":"later"}"#)
            .unwrap();
        assert_eq!(
            store
                .committed_record_facts("command:closure", "close-one")
                .unwrap(),
            Some(facts)
        );
        store
            .conn
            .execute(
                "DELETE FROM record_command_fact_refs WHERE command_scope = ?1 AND command_key = ?2 AND fact_index = 0",
                params!["command:closure", "close-one"],
            )
            .unwrap();
        assert!(matches!(
            store.committed_record_facts("command:closure", "close-one"),
            Err(AdmitError::Rejected(_))
        ));
    }

    #[test]
    fn stale_scope_head_refuses_without_a_command_or_fact() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .append_record("account-auth", "legacy", r#"{"id":"alice"}"#)
            .unwrap();
        let fact = CommandRecordFact {
            scope_id: "account-auth::alice".into(),
            kind: "account_auth_email".into(),
            payload: r#"{"email":"alice@example.com"}"#.into(),
        };

        let result = store.admit_record_facts_at_scope_head(
            "account-auth",
            "stale-copy",
            r#"{"account_id":"alice","source_position":-1}"#,
            &[fact],
            "account-auth",
            -1,
        );
        assert!(matches!(
            result,
            Err(AdmitError::Rejected(Rejection {
                reason: "scope head changed before record admission"
            }))
        ));
        assert!(store
            .command_for_key("account-auth", "stale-copy")
            .unwrap()
            .is_none());
        assert!(store
            .records("account-auth::alice", "account_auth_email")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn competing_scope_head_bound_admissions_have_one_winner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scope-head-command.sqlite");
        let mut first = Store::open(path.to_str().unwrap()).unwrap();
        let mut second = Store::open(path.to_str().unwrap()).unwrap();
        let first_fact = CommandRecordFact {
            scope_id: "account-auth".into(),
            kind: "migration".into(),
            payload: r#"{"account_id":"alice"}"#.into(),
        };
        let second_fact = CommandRecordFact {
            scope_id: "account-auth".into(),
            kind: "migration".into(),
            payload: r#"{"account_id":"bob"}"#.into(),
        };

        first
            .admit_record_facts_at_scope_head(
                "account-auth",
                "copy-alice",
                r#"{"account_id":"alice"}"#,
                &[first_fact],
                "account-auth",
                -1,
            )
            .unwrap();
        let loser = second.admit_record_facts_at_scope_head(
            "account-auth",
            "copy-bob",
            r#"{"account_id":"bob"}"#,
            &[second_fact],
            "account-auth",
            -1,
        );
        assert!(matches!(loser, Err(AdmitError::Rejected(_))));
        assert!(second
            .command_for_key("account-auth", "copy-bob")
            .unwrap()
            .is_none());
        assert_eq!(
            second.records("account-auth", "migration").unwrap().len(),
            1
        );
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
    fn command_claim_refuses_stale_expired_revoked_and_foreign_authority_without_writes() {
        for change in ["stale", "expired", "revoked", "foreign"] {
            let mut store = Store::open_in_memory().unwrap();
            let (_, mut basis) = store.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
            let active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let observed = active.clone();
            basis = basis
                .with_process_guard(move || observed.load(std::sync::atomic::Ordering::Acquire));
            // A replay is also an authority-bearing disclosure, and a retained
            // received row cannot be promoted after its standing ends.
            assert!(
                store
                    .claim_command_against("existing", "scope", "existing", "original", &basis)
                    .unwrap()
                    .1
            );
            store.set_command_status("existing", "received").unwrap();
            match change {
                "stale" => {
                    store.append_record("grants", "grant", "removed").unwrap();
                }
                "expired" => {
                    basis = basis.with_deadline(std::time::UNIX_EPOCH);
                }
                "revoked" => active.store(false, std::sync::atomic::Ordering::Release),
                "foreign" => {
                    let other = Store::open_in_memory().unwrap();
                    basis = other.read_for_dispatch(&["grants"], |_| Ok(())).unwrap().1;
                }
                _ => unreachable!(),
            }
            assert!(
                store
                    .claim_command_against("new", "scope", "new", "new input", &basis)
                    .is_err(),
                "{change}"
            );
            assert!(store.command("new").unwrap().is_none(), "{change}");
            assert!(
                store
                    .claim_command_excluding(
                        "new-format",
                        ("opaque-scope", "opaque-key"),
                        "new input",
                        Some(&basis),
                        &[("old-scope", "old-key")],
                    )
                    .is_err(),
                "{change}"
            );
            assert!(store.command("new-format").unwrap().is_none(), "{change}");
            assert!(
                store
                    .claim_command_against("existing", "scope", "existing", "original", &basis)
                    .is_err(),
                "{change}"
            );
            let original = store.command("existing").unwrap().unwrap();
            assert_eq!(original.status, "received", "{change}");
            assert_eq!(original.snapshot_json, "original", "{change}");
        }
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

    /// Reads hand a codec every row of a scope at once (Hub lock work). One
    /// that answers a different number of rows than it was given has answered
    /// none of them: a retained read refuses and an ordinary one reads nothing,
    /// rather than pairing answers with the wrong rows or losing some quietly.
    #[test]
    fn a_codec_answering_the_wrong_number_of_rows_answers_none() {
        struct ShortCodec;
        impl ContentCodec for ShortCodec {
            fn encode(&self, _scope: &str, _kind: &str, payload: &str) -> Result<String, String> {
                Ok(payload.to_owned())
            }
            fn decode(&self, _scope: &str, _kind: &str, payload: &str) -> Option<String> {
                Some(payload.to_owned())
            }
            fn decode_scope(&self, _scope: &str, rows: &[(&str, &str)]) -> Vec<Option<String>> {
                rows.iter()
                    .skip(1)
                    .map(|(_, payload)| Some((*payload).to_owned()))
                    .collect()
            }
        }
        let mut store = Store::open_in_memory()
            .unwrap()
            .with_codec(std::sync::Arc::new(ShortCodec));
        store.append_record("eng-1", "secret", "first").unwrap();
        store.append_record("eng-1", "secret", "second").unwrap();
        store.append_record("eng-2", "secret", "third").unwrap();
        assert!(store.records("eng-1", "secret").unwrap().is_empty());
        assert!(store.retained_records("eng-1", "secret").is_err());
        assert!(store.events("eng-1").unwrap().is_empty());
        assert!(store.retained_events("eng-1").is_err());
        assert!(store.records_across_scopes("secret").unwrap().is_empty());
    }

    /// The default `decode_scope` is `decode` row by row, and every read that
    /// now batches still answers per scope: rows of two scopes read across
    /// scopes are each decoded under their own scope.
    #[test]
    fn a_batched_read_decodes_each_row_under_its_own_scope() {
        let codec = std::sync::Arc::new(RevCodec {
            erased: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        });
        let mut store = Store::open_in_memory().unwrap().with_codec(codec.clone());
        for (scope, payload) in [
            ("eng-1", "a1"),
            ("eng-2", "b1"),
            ("eng-1", "a2"),
            ("eng-3", "c1"),
        ] {
            store.append_record(scope, "secret", payload).unwrap();
        }
        codec.erased.lock().unwrap().insert("eng-2".into());
        assert_eq!(
            store.records_across_scopes("secret").unwrap(),
            vec![
                ("eng-1".to_owned(), "a1".to_owned()),
                ("eng-1".to_owned(), "a2".to_owned()),
                ("eng-3".to_owned(), "c1".to_owned()),
            ]
        );
        assert_eq!(store.records("eng-1", "secret").unwrap(), vec!["a1", "a2"]);
        assert!(store.records("eng-2", "secret").unwrap().is_empty());
        assert!(store.retained_records("eng-2", "secret").is_err());
        assert_eq!(
            store.retained_records("eng-3", "secret").unwrap(),
            vec!["c1"]
        );
    }

    /// A projection may be remembered against a read stamp only if every way
    /// the scopes' reads could change moves it, and should survive anything
    /// that cannot change them (WS-1010).
    #[test]
    fn a_read_stamp_moves_with_its_scopes_and_codec_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.db");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        let first = store.read_stamp(&["eng-1"]).unwrap();
        assert_eq!(
            store.read_stamp(&["eng-1"]),
            Some(first.clone()),
            "a read changes nothing"
        );
        store.records("eng-1", "secret").unwrap();
        assert_eq!(store.read_stamp(&["eng-1"]), Some(first.clone()));

        store.append_record("eng-2", "secret", "elsewhere").unwrap();
        assert_eq!(
            store.read_stamp(&["eng-1"]),
            Some(first.clone()),
            "another scope's write changes nothing this scope reads"
        );
        store.append_record("eng-1", "secret", "mine").unwrap();
        let after_own = store.read_stamp(&["eng-1"]).unwrap();
        assert_ne!(
            after_own, first,
            "a write to the scope through this connection moves it"
        );

        let mut other = store.sibling().unwrap();
        other.append_record("eng-1", "secret", "theirs").unwrap();
        let after_other = store.read_stamp(&["eng-1"]).unwrap();
        assert_ne!(
            after_other, after_own,
            "so does one through another connection"
        );
        assert_ne!(
            store.read_stamp(&["eng-1", "eng-2"]).unwrap(),
            after_other,
            "a stamp is of exactly the scopes named"
        );

        store.conn.execute_batch("BEGIN").unwrap();
        assert_eq!(
            store.read_stamp(&["eng-1"]),
            None,
            "inside a transaction its reads may yet roll back"
        );
        store.conn.execute_batch("ROLLBACK").unwrap();
        assert!(store.read_stamp(&["eng-1"]).is_some());

        // A codec that cannot say when it changes makes nothing rememberable.
        let silent = Store::open(path.to_str().unwrap())
            .unwrap()
            .with_codec(std::sync::Arc::new(FailingCodec));
        assert_eq!(silent.read_stamp(&["eng-1"]), None);
        assert!(
            silent.read_stamp(&[]).is_some(),
            "no scope, no codec answer needed"
        );

        struct Epochs(std::sync::atomic::AtomicU64);
        impl ContentCodec for Epochs {
            fn encode(&self, _scope: &str, _kind: &str, payload: &str) -> Result<String, String> {
                Ok(payload.to_owned())
            }
            fn decode(&self, _scope: &str, _kind: &str, payload: &str) -> Option<String> {
                Some(payload.to_owned())
            }
            fn epoch(&self, scope: &str) -> Option<u64> {
                (scope != "held-project").then(|| self.0.load(std::sync::atomic::Ordering::SeqCst))
            }
        }
        let epochs = std::sync::Arc::new(Epochs(std::sync::atomic::AtomicU64::new(0)));
        let watched = Store::open(path.to_str().unwrap())
            .unwrap()
            .with_codec(epochs.clone());
        let before = watched.read_stamp(&["eng-1", "eng-2"]).unwrap();
        epochs.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_ne!(watched.read_stamp(&["eng-1", "eng-2"]).unwrap(), before);
        assert_eq!(watched.read_stamp(&["eng-1", "held-project"]), None);
    }

    /// WS-1010: a remembered fold is answered without folding again until
    /// anything that could change its answer happens, and never inside a
    /// transaction, after an error, or through a codec that cannot tell.
    #[test]
    fn a_remembered_fold_is_answered_until_its_scope_could_have_changed() {
        let folds = std::cell::Cell::new(0);
        let count = |store: &Store| {
            folds.set(folds.get() + 1);
            Ok(store.records("eng-1", "secret")?.len())
        };
        let mut store = Store::open_in_memory().unwrap();
        store.append_record("eng-1", "secret", "one").unwrap();
        assert_eq!(store.remember("count", "eng-1", count).unwrap(), 1);
        assert_eq!(store.remember("count", "eng-1", count).unwrap(), 1);
        assert_eq!(folds.get(), 1, "the second answer came from memory");
        assert_eq!(store.remember("other", "eng-1", count).unwrap(), 1);
        assert_eq!(folds.get(), 2, "another fold of the scope is its own");

        store.append_record("eng-2", "secret", "elsewhere").unwrap();
        assert_eq!(store.remember("count", "eng-1", count).unwrap(), 1);
        assert_eq!(folds.get(), 2, "another scope's write leaves it remembered");

        store.append_record("eng-1", "secret", "two").unwrap();
        assert_eq!(store.remember("count", "eng-1", count).unwrap(), 2);
        assert_eq!(folds.get(), 3, "a write to the scope is folded again");

        let mut other = store.sibling().unwrap();
        other.append_record("eng-1", "secret", "three").unwrap();
        assert_eq!(store.remember("count", "eng-1", count).unwrap(), 3);
        assert_eq!(folds.get(), 4, "so is another connection's");

        store.conn.execute_batch("BEGIN").unwrap();
        assert_eq!(store.remember("count", "eng-1", count).unwrap(), 3);
        assert_eq!(store.remember("count", "eng-1", count).unwrap(), 3);
        assert_eq!(folds.get(), 6, "nothing is remembered inside a transaction");
        store.conn.execute_batch("ROLLBACK").unwrap();

        let refusals = std::cell::Cell::new(0);
        let refuse = |_: &Store| -> Result<usize, AdmitError> {
            refusals.set(refusals.get() + 1);
            Err(AdmitError::Codec("unavailable".into()))
        };
        assert!(store.remember("refuse", "eng-1", refuse).is_err());
        assert!(store.remember("refuse", "eng-1", refuse).is_err());
        assert_eq!(refusals.get(), 2, "an error is never remembered");

        let silent = Store::open_in_memory()
            .unwrap()
            .with_codec(std::sync::Arc::new(FailingCodec));
        let before = folds.get();
        silent.remember("count", "eng-1", count).unwrap();
        silent.remember("count", "eng-1", count).unwrap();
        assert_eq!(
            folds.get(),
            before + 2,
            "a codec that cannot tell disables it"
        );
    }

    /// WS-926: tracker discovery names a project's tracker scopes by prefix,
    /// and must find exactly the ones `scope_high_water_marks` would have.
    #[test]
    fn scopes_with_a_prefix_are_exactly_those_the_high_water_marks_name() {
        let mut store = Store::open_in_memory().unwrap();
        for scope in [
            "project::a::tracker::74",
            "project::a::tracker::7461736b73",
            "project::a::tracker::74::grant",
            "project::a::tracker:",
            "project::a::trackers",
            "project::a::tracker",
            "project::ab::tracker::74",
            "project::a::tracker::%_",
            "project::a::tracker::\u{10FFFF}",
            "project::a::tracker::\u{10FFFF}\u{10FFFF}x",
            "project::a::tracker;",
            "project::b::tracker::74",
            "zzz",
        ] {
            store.append_record(scope, "note", "{}").unwrap();
            store.append_record(scope, "note", "{}").unwrap();
        }
        for prefix in [
            "project::a::tracker::",
            "project::a::tracker",
            "project::",
            "project::a::tracker::\u{10FFFF}",
            "\u{10FFFF}",
            "",
            "nothing",
        ] {
            let expected: Vec<String> = store
                .scope_high_water_marks()
                .unwrap()
                .into_keys()
                .filter(|scope| scope.starts_with(prefix))
                .collect();
            assert_eq!(
                store.scopes_with_prefix(prefix).unwrap(),
                expected,
                "{prefix}"
            );
        }
        assert_eq!(
            store
                .scopes_with_prefix("project::a::tracker::")
                .unwrap()
                .len(),
            6
        );
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

#[cfg(test)]
mod scope_discovery_tests {
    use super::*;
    use std::num::NonZeroUsize;

    struct NoPayloadReads;
    impl ContentCodec for NoPayloadReads {
        fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
            Ok(payload.into())
        }
        fn decode(&self, _: &str, _: &str, _: &str) -> Option<String> {
            panic!("discovery must never read content")
        }
    }

    #[test]
    fn scope_discovery_pages_unique_matching_ids_without_reading_payloads() {
        let mut store = Store::open_in_memory()
            .unwrap()
            .with_codec(Arc::new(NoPayloadReads));
        for (scope, kind) in [
            ("c", "grant"),
            ("a", "grant"),
            ("a", "grant"),
            ("b", "other"),
        ] {
            store.append_record(scope, kind, "private payload").unwrap();
        }
        let one = NonZeroUsize::new(1).unwrap();
        assert_eq!(
            store.scope_ids_with_kind("grant", None, one).unwrap(),
            ["a"]
        );
        assert_eq!(
            store.scope_ids_with_kind("grant", Some("a"), one).unwrap(),
            ["c"]
        );
        assert!(store
            .scope_ids_with_kind("grant", Some("c"), one)
            .unwrap()
            .is_empty());
        store
            .append_record("aa", "grant", "new before cursor")
            .unwrap();
        assert!(store
            .scope_ids_with_kind("grant", Some("c"), one)
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .scope_ids_with_kind("grant", None, NonZeroUsize::new(10).unwrap())
                .unwrap(),
            ["a", "aa", "c"]
        );
        assert_eq!(
            store.scope_ids_with_kind("other", None, one).unwrap(),
            ["b"]
        );
        assert!(store
            .scope_ids_with_kind("missing", None, one)
            .unwrap()
            .is_empty());
    }
}
