//! Per-boundary WhippleScript tracker runtime (ADR 0075).
//!
//! One [`WhipTrackerHandle`] per trust boundary (a gaugewright scope key). The
//! handle owns two whip stores, both under
//! `<control_plane_root>/trackers/<boundary_id>/`:
//!
//! - a [`RuntimeKernel`] over `runtime.sqlite` — the event-sourced workflow log
//!   (events → facts → effects). It carries the *provenance* of the onboarding
//!   run: every app event that advances the checklist is ingested here as an
//!   external event, so the "why did this issue close" trail is durable.
//! - a [`WorkItemStore`] over `items.sqlite` — the thin row store that holds the
//!   actual checklist issues (`WS-N`) the task bar projects.
//!
//! Isolation is **structural, not label-based** (ADR 0075 §1): each boundary
//! gets its own directory, so there is no code path from one boundary's runtime
//! to another's files. whip's tracker plane is not IFC-labeled yet, so structure
//! is the guarantee.
//!
//! The runtime is embedded because it is cheap and sans-IO: `RuntimeKernel` is
//! synchronous and holds no threads or sockets. See ADR 0075 for the truth split
//! (issue content = whip happenings; assignment/acceptance = gaugewright
//! decisions, admitted elsewhere).

use std::fs;
use std::path::{Path, PathBuf};

use whipplescript_kernel::{ProgramVersionInput, RuntimeKernel};
use whipplescript_store::items::{ClaimOutcome, WorkItem, WorkItemStore};
use whipplescript_store::{SqliteStore, StoreError};

/// The onboarding runtime's program name inside a boundary's `runtime.sqlite`.
/// A single long-lived instance per boundary carries the provenance stream; we
/// do not compile a whip program for it yet (ADR 0075 Phase 2b — rules-driven
/// effects are deferred), so this is a bare provenance shell.
const ONBOARDING_PROGRAM: &str = "onboarding";

/// Sidecar file recording the runtime instance id, so reopening a boundary's
/// tracker reuses its existing provenance instance instead of minting a new one.
const INSTANCE_MARKER: &str = "runtime.instance";

/// Errors from the tracker surface. whip's `StoreError` is `Debug`-only (no
/// `Display`), so we render it eagerly and keep a flat, `Display`-able type the
/// app crate can thread without depending on whip's error enum.
#[derive(Debug)]
pub enum TrackerError {
    /// A whip store operation failed (sqlite/json/conflict).
    Store(String),
    /// Filesystem setup (creating the boundary directory / marker) failed.
    Io(std::io::Error),
}

impl std::fmt::Display for TrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrackerError::Store(msg) => write!(f, "tracker store error: {msg}"),
            TrackerError::Io(err) => write!(f, "tracker io error: {err}"),
        }
    }
}

impl std::error::Error for TrackerError {}

impl From<StoreError> for TrackerError {
    fn from(err: StoreError) -> Self {
        TrackerError::Store(format!("{err:?}"))
    }
}

impl From<std::io::Error> for TrackerError {
    fn from(err: std::io::Error) -> Self {
        TrackerError::Io(err)
    }
}

pub type TrackerResult<T> = Result<T, TrackerError>;

/// One trust boundary's embedded whip tracker: a provenance [`RuntimeKernel`]
/// plus the [`WorkItemStore`] the task bar reads. Cheap to construct; hold one
/// per boundary in a `BTreeMap`, spawned on demand, mirroring the `sessions`
/// harness map (ADR 0075 §1).
pub struct WhipTrackerHandle {
    boundary_id: String,
    dir: PathBuf,
    kernel: RuntimeKernel<SqliteStore>,
    /// The long-lived onboarding provenance instance in `runtime.sqlite`.
    instance_id: String,
    items: WorkItemStore,
}

impl WhipTrackerHandle {
    /// Open (creating if absent) the tracker for `boundary_id` under
    /// `root/trackers/<boundary_id>/`. Idempotent: reopening reuses the existing
    /// provenance instance recorded in the marker file.
    pub fn open(root: &Path, boundary_id: &str) -> TrackerResult<Self> {
        let dir = root.join("trackers").join(boundary_id);
        fs::create_dir_all(&dir)?;

        let runtime_store = SqliteStore::open(dir.join("runtime.sqlite"))?;
        let mut kernel = RuntimeKernel::new(runtime_store);
        let instance_id = Self::open_or_create_instance(&dir, &mut kernel)?;

        let items = WorkItemStore::open(dir.join("items.sqlite"))?;

        Ok(Self {
            boundary_id: boundary_id.to_owned(),
            dir,
            kernel,
            instance_id,
            items,
        })
    }

    fn open_or_create_instance(
        dir: &Path,
        kernel: &mut RuntimeKernel<SqliteStore>,
    ) -> TrackerResult<String> {
        let marker = dir.join(INSTANCE_MARKER);
        if let Ok(existing) = fs::read_to_string(&marker) {
            let existing = existing.trim();
            if !existing.is_empty() {
                return Ok(existing.to_owned());
            }
        }

        // Bare provenance shell: no compiled whip program yet (ADR 0075 Phase
        // 2b). `create_program_version` declares empty capabilities, which is
        // exactly what a provenance-only instance needs.
        let version = kernel.create_program_version(ProgramVersionInput {
            program_name: ONBOARDING_PROGRAM,
            source_hash: "onboarding-v1",
            ir_hash: "onboarding-v1",
            compiler_version: env!("CARGO_PKG_VERSION"),
        })?;
        let instance_id = kernel.create_instance(&version, "{}")?;
        fs::write(&marker, &instance_id)?;
        Ok(instance_id)
    }

    /// The boundary this tracker is scoped to.
    pub fn boundary_id(&self) -> &str {
        &self.boundary_id
    }

    /// The on-disk directory backing this tracker.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Record an app event into the runtime kernel for provenance. `event_type`
    /// is a dotted app-domain name (e.g. `app.credential_connected`);
    /// `payload_json` must be a JSON object string. Returns the appended event's
    /// id. This is the app→whip bridge's write side (ADR 0075 §Consequences).
    pub fn record_event(&self, event_type: &str, payload_json: &str) -> TrackerResult<String> {
        let stored =
            self.kernel
                .ingest_external_event(&self.instance_id, event_type, payload_json, None)?;
        Ok(stored.event_id)
    }

    /// File a checklist issue into `queue`. Returns the minted `WS-N` item.
    pub fn file_item(
        &mut self,
        queue: &str,
        title: &str,
        body: &str,
        labels: &[String],
        metadata: &serde_json::Value,
        filed_by: Option<&str>,
    ) -> TrackerResult<WorkItem> {
        Ok(self
            .items
            .file_item(queue, title, body, labels, metadata, filed_by)?)
    }

    /// List issues, optionally filtered by queue and status.
    pub fn list_items(
        &self,
        queue: Option<&str>,
        status: Option<&str>,
    ) -> TrackerResult<Vec<WorkItem>> {
        Ok(self.items.list_items(queue, status)?)
    }

    /// Fetch one issue by id.
    pub fn get_item(&self, item_id: &str) -> TrackerResult<Option<WorkItem>> {
        Ok(self.items.get_item(item_id)?)
    }

    /// Atomically claim an issue for `holder` (CAS; the store is the arbiter).
    ///
    /// `expires` bounds the claim (WhippleScript 0.2.2). `None` is unbounded,
    /// which is right for a person holding a task — someone who steps away has
    /// not abandoned it. An automated holder should pass a bound so a dead
    /// worker does not hold an issue forever.
    pub fn claim_item(
        &mut self,
        item_id: &str,
        holder: &str,
        expires: Option<&str>,
    ) -> TrackerResult<ClaimOutcome> {
        Ok(self.items.claim_item(item_id, holder, expires)?)
    }

    /// Direct an open issue at `assignee`, or clear it with `None` (0.2.2).
    ///
    /// Advisory: it records who *should* answer and does not stop anyone else
    /// claiming (ADR 0111 §4). Unassigned means "whoever has access".
    pub fn assign_item(&mut self, item_id: &str, assignee: Option<&str>) -> TrackerResult<bool> {
        Ok(self.items.assign_item(item_id, assignee)?)
    }

    /// Close an issue (open/in_progress → closed). Returns whether a row moved.
    pub fn finish_item(&mut self, item_id: &str, summary: Option<&str>) -> TrackerResult<bool> {
        Ok(self.items.finish_item(item_id, summary)?)
    }

    /// Whether any issue has been filed into `queue` — used to seed the
    /// onboarding checklist exactly once.
    pub fn has_items(&self, queue: &str) -> TrackerResult<bool> {
        Ok(!self.items.list_items(Some(queue), None)?.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_is_idempotent_and_reuses_instance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = WhipTrackerHandle::open(tmp.path(), "account::global").expect("open");
        let instance = first.instance_id.clone();
        drop(first);

        let second = WhipTrackerHandle::open(tmp.path(), "account::global").expect("reopen");
        assert_eq!(
            second.instance_id, instance,
            "reopening a boundary must reuse its provenance instance"
        );
    }

    #[test]
    fn files_and_lists_checklist_items() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut tracker = WhipTrackerHandle::open(tmp.path(), "account::global").expect("open");

        assert!(!tracker.has_items("onboarding").expect("has_items"));
        let item = tracker
            .file_item(
                "onboarding",
                "Connect a model",
                "Add an LLM credential to start building.",
                &["onboarding".to_owned()],
                &serde_json::json!({ "step": "credential" }),
                Some("system"),
            )
            .expect("file_item");
        assert!(item.id.starts_with("WS-"));
        assert!(tracker.has_items("onboarding").expect("has_items"));

        let open = tracker
            .list_items(Some("onboarding"), Some("open"))
            .expect("list_items");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].title, "Connect a model");

        assert!(tracker
            .finish_item(&item.id, Some("connected"))
            .expect("finish_item"));
        let still_open = tracker
            .list_items(Some("onboarding"), Some("open"))
            .expect("list_items");
        assert!(still_open.is_empty());
    }

    #[test]
    fn records_provenance_events() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tracker = WhipTrackerHandle::open(tmp.path(), "account::global").expect("open");
        let event_id = tracker
            .record_event("app.credential_connected", r#"{"provider":"anthropic"}"#)
            .expect("record_event");
        assert!(!event_id.is_empty());
    }
}
