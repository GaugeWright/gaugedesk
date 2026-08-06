//! Untrusted inbound material, held where no agent can reach it (ADR 0110).
//!
//! The invariant this module exists to make true:
//!
//! > **A write-enabled agent never reads unfiltered data.**
//!
//! Material arrives here — today from a drained public-session collection,
//! later from any inbound source — and waits outside every agent file store
//! until the project's gate passes it into the workspace. The protection is a
//! **path boundary, not a policy check**: WhippleScript grants a file store an
//! explicit root and globs, so material outside that root is not a *denied*
//! path, there is no path. An agent cannot read it, cannot be argued into
//! reading it, and needs no stamp, purpose gate, or reduced ceiling for that to
//! hold. See [`isolation_violations`], which is the check rather than the
//! comment.
//!
//! Once the gate approves an item it is written into the workspace and becomes
//! ordinary content that any agent reads at full authority. The gate is the
//! whole protection, and it is exactly as strong as the author made it.
//!
//! This deliberately shares a name with neither the `inbox_items` inside a
//! WhippleScript session object (pending human and tool interactions for one
//! running session) nor `/federation/inbox` (facts that crossed from a peer).
//! Those are different jurisdictions.
//!
//! Disposition is an append-only record folded latest-wins by item id, exactly
//! as [`crate::resource_store`] folds resources: a gate verdict is a newer
//! revision, not a mutation.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use gaugedesk_store::{AdmitError, Store};
use serde::{Deserialize, Serialize};

/// The record kind under which quarantine dispositions are stored.
const QUARANTINE_KIND: &str = "quarantined-item";

/// The project scope holding a project's quarantine index. Distinct from any
/// chat engagement scope: unfiltered material belongs to no conversation.
pub fn quarantine_scope(project_id: &str) -> String {
    format!("quarantine::{project_id}")
}

/// The stable identity of one quarantined item. For a collected artifact that
/// is the producing session and the deposit revision it was sealed under.
pub fn item_id(source_id: &str, revision: u64) -> String {
    format!("{source_id}:{revision}")
}

/// Where one quarantined item stands with respect to the gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum ItemStatus {
    /// Held here, awaiting the gate. This is what the attention count counts.
    Pending,
    /// The gate approved it and wrote it into the workspace at this path.
    Approved { workspace_path: String },
    /// The gate rejected it. The record and its provenance remain; the item
    /// never becomes workspace content and no agent ever reads it.
    Rejected,
}

impl ItemStatus {
    pub fn key(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved { .. } => "approved",
            Self::Rejected => "rejected",
        }
    }
}

/// One item in a project's quarantine. Carries provenance and custody facts
/// only; the payload lives behind [`QuarantineStore`], never in the event log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinedItem {
    pub item_id: String,
    /// What produced this. `collection:{deployment}` for a drained artifact.
    pub source: String,
    pub source_id: String,
    pub release_id: String,
    pub revision: u64,
    pub schema_ref: String,
    pub byte_len: u64,
    pub produced_at_unix_ms: u64,
    pub arrived_at_unix_ms: u64,
    pub status: ItemStatus,
}

/// Record a freshly arrived item. Idempotent by item id: re-arrival of
/// something the gate has already ruled on leaves that verdict alone rather
/// than resetting it to pending, so a repeated drain cannot resurrect an item
/// the gate already rejected.
pub fn record(
    store: &mut Store,
    project_id: &str,
    item: &QuarantinedItem,
) -> Result<bool, AdmitError> {
    if get(store, project_id, &item.item_id)?.is_some() {
        return Ok(false);
    }
    store.append_record(
        &quarantine_scope(project_id),
        QUARANTINE_KIND,
        &serde_json::to_string(item)?,
    )?;
    Ok(true)
}

/// Every item in a project's quarantine at its current disposition, oldest
/// arrival first. This is the index the review surface renders — provenance
/// only; reading an item's content goes through [`QuarantineStore`].
pub fn list(store: &Store, project_id: &str) -> Result<Vec<QuarantinedItem>, AdmitError> {
    let mut latest: BTreeMap<String, QuarantinedItem> = BTreeMap::new();
    for row in store.records(&quarantine_scope(project_id), QUARANTINE_KIND)? {
        let item: QuarantinedItem = serde_json::from_str(&row)?;
        // records() is position-ordered (oldest→newest), so a later write wins.
        latest.insert(item.item_id.clone(), item);
    }
    let mut items: Vec<QuarantinedItem> = latest.into_values().collect();
    items.sort_by(|left, right| {
        left.produced_at_unix_ms
            .cmp(&right.produced_at_unix_ms)
            .then_with(|| left.item_id.cmp(&right.item_id))
    });
    Ok(items)
}

pub fn get(
    store: &Store,
    project_id: &str,
    item_id: &str,
) -> Result<Option<QuarantinedItem>, AdmitError> {
    Ok(list(store, project_id)?
        .into_iter()
        .find(|item| item.item_id == item_id))
}

/// Items still awaiting the gate.
pub fn pending(store: &Store, project_id: &str) -> Result<Vec<QuarantinedItem>, AdmitError> {
    Ok(list(store, project_id)?
        .into_iter()
        .filter(|item| matches!(item.status, ItemStatus::Pending))
        .collect())
}

/// The attention count the top bar shows: material waiting for review.
pub fn pending_count(store: &Store, project_id: &str) -> Result<usize, AdmitError> {
    Ok(pending(store, project_id)?.len())
}

/// Record the gate's verdict on one item.
///
/// This is bookkeeping, not enforcement: writing the approved bytes into the
/// workspace is the gate's own act. Recording `Approved` for an item whose
/// bytes were never written would leave an index that lies, which is why the
/// two happen in one operation at the caller.
pub fn settle(
    store: &mut Store,
    project_id: &str,
    item_id: &str,
    status: ItemStatus,
) -> Result<(), AdmitError> {
    let Some(existing) = get(store, project_id, item_id)? else {
        return Ok(());
    };
    let settled = QuarantinedItem { status, ..existing };
    store.append_record(
        &quarantine_scope(project_id),
        QUARANTINE_KIND,
        &serde_json::to_string(&settled)?,
    )?;
    Ok(())
}

/// Local custody for quarantined payload.
///
/// Kept outside the event log because payload behind a handle is the whole
/// discipline (`INV-10`), and outside every agent file store because that is the
/// invariant. Same on-disk posture as the recipient key store — 0700 directory,
/// 0600 file.
pub struct QuarantineStore {
    dir: PathBuf,
}

fn valid_project_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl QuarantineStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory holding every project's quarantined payload. Checked
    /// against agent file store roots by [`isolation_violations`].
    pub fn root(&self) -> &Path {
        &self.dir
    }

    fn path(&self, project_id: &str, item_id: &str) -> io::Result<PathBuf> {
        if !valid_project_id(project_id) {
            return Err(io::Error::other("project id is invalid"));
        }
        // Hex, not the raw id: a source id is producer-shaped and a revision
        // separator is not a path separator anywhere we get to choose.
        Ok(self
            .dir
            .join(project_id)
            .join(format!("{}.item", hex::encode(item_id))))
    }

    pub fn put(&self, project_id: &str, item_id: &str, payload: &[u8]) -> io::Result<()> {
        let path = self.path(project_id, item_id)?;
        let dir = path.parent().expect("item path has a parent").to_owned();
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(payload)?;
        file.sync_all()
    }

    /// Read one item's payload. Reachable from the gate and the review surface,
    /// never from an agent tool: no file store root resolves in here.
    pub fn read(&self, project_id: &str, item_id: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.path(project_id, item_id)?)
    }

    pub fn exists(&self, project_id: &str, item_id: &str) -> bool {
        self.path(project_id, item_id)
            .map(|path| path.exists())
            .unwrap_or(false)
    }

    /// Drop one item's payload once the gate has ruled and the approved copy is
    /// durably in the workspace. The index record and its provenance remain.
    pub fn discard(&self, project_id: &str, item_id: &str) -> io::Result<()> {
        let path = self.path(project_id, item_id)?;
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Every agent file store root that would let an agent reach quarantine.
///
/// **This function is the boundary**, not the prose above it. It is written to
/// be called with *all* configured roots rather than today's, so that a store
/// rooted somewhere new later fails the check instead of silently opening a path
/// to unfiltered material. An empty result means the invariant holds.
///
/// Containment is decided on lexical, normalized paths and is deliberately
/// symmetric: a root inside quarantine is as much a violation as quarantine
/// inside a root, since either way one resolves into the other.
pub fn isolation_violations<'a>(
    quarantine_root: &Path,
    file_store_roots: impl IntoIterator<Item = &'a Path>,
) -> Vec<PathBuf> {
    let quarantine = normalize(quarantine_root);
    file_store_roots
        .into_iter()
        .filter(|root| {
            let root = normalize(root);
            root.starts_with(&quarantine) || quarantine.starts_with(&root)
        })
        .map(PathBuf::from)
        .collect()
}

/// Lexical normalization: resolve `.` and `..` without touching the filesystem,
/// so the check works for paths that do not exist yet (a worktree about to be
/// created) and cannot be defeated by a traversal component.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn item(source: &str, revision: u64, produced: u64) -> QuarantinedItem {
        QuarantinedItem {
            item_id: item_id(source, revision),
            source: "collection:dep-1".into(),
            source_id: source.into(),
            release_id: "rel-1".into(),
            revision,
            schema_ref: "survey/v1".into(),
            byte_len: 12,
            produced_at_unix_ms: produced,
            arrived_at_unix_ms: produced + 5,
            status: ItemStatus::Pending,
        }
    }

    #[test]
    fn arrived_material_waits_for_the_gate_and_counts() {
        let mut store = Store::open_in_memory().unwrap();
        assert!(record(&mut store, "proj", &item("s1", 1, 100)).unwrap());
        assert!(record(&mut store, "proj", &item("s2", 1, 200)).unwrap());
        let items = list(&store, "proj").unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|i| i.status == ItemStatus::Pending));
        assert_eq!(pending_count(&store, "proj").unwrap(), 2);
        assert_eq!(items[0].source_id, "s1", "oldest first");
    }

    #[test]
    fn quarantine_is_project_scoped() {
        let mut store = Store::open_in_memory().unwrap();
        record(&mut store, "proj-a", &item("s1", 1, 100)).unwrap();
        assert!(list(&store, "proj-b").unwrap().is_empty());
        assert_eq!(pending_count(&store, "proj-b").unwrap(), 0);
    }

    #[test]
    fn a_repeated_arrival_does_not_resurrect_a_rejected_item() {
        let mut store = Store::open_in_memory().unwrap();
        record(&mut store, "proj", &item("s1", 1, 100)).unwrap();
        settle(&mut store, "proj", "s1:1", ItemStatus::Rejected).unwrap();
        assert!(
            !record(&mut store, "proj", &item("s1", 1, 100)).unwrap(),
            "re-arrival leaves the gate's verdict alone"
        );
        assert_eq!(
            get(&store, "proj", "s1:1").unwrap().unwrap().status,
            ItemStatus::Rejected,
        );
    }

    #[test]
    fn a_settled_item_stops_asking_for_attention() {
        let mut store = Store::open_in_memory().unwrap();
        record(&mut store, "proj", &item("s1", 1, 100)).unwrap();
        record(&mut store, "proj", &item("s2", 1, 200)).unwrap();
        settle(
            &mut store,
            "proj",
            "s1:1",
            ItemStatus::Approved {
                workspace_path: "collected/s1-1.json".into(),
            },
        )
        .unwrap();
        assert_eq!(pending_count(&store, "proj").unwrap(), 1);
        assert_eq!(pending(&store, "proj").unwrap()[0].source_id, "s2");
    }

    #[test]
    fn an_approved_item_records_where_it_landed() {
        let mut store = Store::open_in_memory().unwrap();
        record(&mut store, "proj", &item("s1", 1, 100)).unwrap();
        settle(
            &mut store,
            "proj",
            "s1:1",
            ItemStatus::Approved {
                workspace_path: "collected/s1-1.json".into(),
            },
        )
        .unwrap();
        assert_eq!(
            get(&store, "proj", "s1:1").unwrap().unwrap().status,
            ItemStatus::Approved {
                workspace_path: "collected/s1-1.json".into()
            },
        );
    }

    proptest! {
        #[test]
        fn quarantine_verdict_is_terminal(
            approved in any::<bool>(),
            repeated_arrivals in 0_u8..8,
        ) {
            let mut store = Store::open_in_memory().unwrap();
            let arrived = item("property-session", 7, 100);
            prop_assert!(record(&mut store, "property-project", &arrived).unwrap());
            let terminal = if approved {
                ItemStatus::Approved {
                    workspace_path: "collected/property-session-7.json".into(),
                }
            } else {
                ItemStatus::Rejected
            };
            settle(
                &mut store,
                "property-project",
                "property-session:7",
                terminal.clone(),
            )
            .unwrap();
            for _ in 0..repeated_arrivals {
                prop_assert!(
                    !record(&mut store, "property-project", &arrived).unwrap(),
                    "a retry must not resurrect a terminal verdict",
                );
            }
            prop_assert_eq!(
                get(&store, "property-project", "property-session:7")
                    .unwrap()
                    .unwrap()
                    .status,
                terminal,
            );
            prop_assert_eq!(pending_count(&store, "property-project").unwrap(), 0);
        }
    }

    #[test]
    fn custody_round_trips_and_stays_project_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::new(dir.path());
        store.put("proj", "s1:1", b"{\"a\":1}").unwrap();
        assert_eq!(store.read("proj", "s1:1").unwrap(), b"{\"a\":1}");
        assert!(store.exists("proj", "s1:1"));
        assert!(!store.exists("other", "s1:1"));
    }

    #[test]
    fn custody_refuses_an_unsafe_project_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::new(dir.path());
        assert!(store.put("../escape", "s1:1", b"x").is_err());
    }

    #[test]
    fn discarding_payload_leaves_the_index() {
        let mut store = Store::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let payloads = QuarantineStore::new(dir.path());
        record(&mut store, "proj", &item("s1", 1, 100)).unwrap();
        payloads.put("proj", "s1:1", b"x").unwrap();
        payloads.discard("proj", "s1:1").unwrap();
        assert!(!payloads.exists("proj", "s1:1"));
        assert!(get(&store, "proj", "s1:1").unwrap().is_some());
        payloads
            .discard("proj", "s1:1")
            .expect("discard is idempotent");
    }

    // ---- the boundary ------------------------------------------------------

    #[test]
    fn a_sibling_file_store_root_is_no_violation() {
        assert!(isolation_violations(
            Path::new("/home/u/.gaugewright/quarantine"),
            [Path::new("/home/u/.gaugewright/targets/proj")],
        )
        .is_empty());
    }

    #[test]
    fn a_file_store_root_containing_quarantine_is_a_violation() {
        // The failure this exists to catch: someone roots a worktree at the
        // state root, and every agent can suddenly read unfiltered material.
        let found = isolation_violations(
            Path::new("/home/u/.gaugewright/quarantine"),
            [Path::new("/home/u/.gaugewright")],
        );
        assert_eq!(found, vec![PathBuf::from("/home/u/.gaugewright")]);
    }

    #[test]
    fn quarantine_inside_a_file_store_root_is_a_violation() {
        let found = isolation_violations(
            Path::new("/home/u/wt/quarantine"),
            [Path::new("/home/u/wt")],
        );
        assert_eq!(found, vec![PathBuf::from("/home/u/wt")]);
    }

    #[test]
    fn containment_is_not_defeated_by_a_traversal_component() {
        let found = isolation_violations(
            Path::new("/home/u/.gaugewright/quarantine"),
            [Path::new("/home/u/.gaugewright/targets/../..")],
        );
        assert_eq!(
            found,
            vec![PathBuf::from("/home/u/.gaugewright/targets/../..")],
            "a root that walks up into quarantine's ancestor still reaches it",
        );
    }

    #[test]
    fn a_prefix_that_is_not_a_path_ancestor_is_no_violation() {
        // `/home/u/quarantine-old` shares a string prefix with
        // `/home/u/quarantine` but is a different directory.
        assert!(isolation_violations(
            Path::new("/home/u/quarantine"),
            [Path::new("/home/u/quarantine-old")],
        )
        .is_empty());
    }

    #[test]
    fn every_offending_root_is_reported_not_just_the_first() {
        let found = isolation_violations(
            Path::new("/root/q"),
            [
                Path::new("/root"),
                Path::new("/elsewhere"),
                Path::new("/root/q/x"),
            ],
        );
        assert_eq!(
            found,
            vec![PathBuf::from("/root"), PathBuf::from("/root/q/x")],
        );
    }
}
