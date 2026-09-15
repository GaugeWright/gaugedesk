//! Consistent native store copies for workspace relocation and VCS forks.
//! The caller selects the store set; a VCS fork never selects tracker stores.

use std::path::PathBuf;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use super::{Result, WorkspaceError};

fn sqlite(error: rusqlite::Error) -> WorkspaceError {
    WorkspaceError::msg(error.to_string())
}

pub(super) fn snapshot_stores<const N: usize>(paths: [PathBuf; N]) -> Result<[Vec<u8>; N]> {
    FrozenStores::acquire(paths, Duration::from_secs(5))?.copy()
}

/// Workflow publication retains inputs before opening target/runtime writers.
/// All snapshots containing this plane use that same order; the remaining
/// canonical order is shared with VCS-only snapshots.
pub(super) fn snapshot_stores_with_input<const N: usize>(
    paths: [PathBuf; N],
    input: &std::path::Path,
) -> Result<[Vec<u8>; N]> {
    FrozenStores::acquire_ordered(paths, Duration::from_secs(5), Some(input))?.copy()
}

/// Each connection holds a RESERVED writer lock, but writes no state. Once the
/// last lock is held, all stores describe one instant. Separate read connections
/// can VACUUM INTO while these locks prevent commits between the individual
/// copies, including in WAL mode. Closing the connections rolls back and releases
/// every acquired lock on success, error, or unwinding.
struct FrozenStores<const N: usize> {
    paths: [PathBuf; N],
    _writers: Vec<Connection>,
}

impl<const N: usize> FrozenStores<N> {
    fn acquire(paths: [PathBuf; N], timeout: Duration) -> Result<Self> {
        Self::acquire_ordered(paths, timeout, None)
    }
    fn acquire_ordered(
        mut paths: [PathBuf; N],
        timeout: Duration,
        input: Option<&std::path::Path>,
    ) -> Result<Self> {
        for path in &mut paths {
            *path = path.canonicalize().map_err(WorkspaceError::io)?;
        }
        // Every snapshot takes locks in the same order. Repeated input paths
        // need only one lock, while the returned copies retain caller order.
        let mut ordered = paths.to_vec();
        ordered.sort();
        ordered.dedup();
        if let Some(input) = input {
            let input = input.canonicalize().map_err(WorkspaceError::io)?;
            let index = ordered
                .iter()
                .position(|path| path == &input)
                .ok_or_else(|| WorkspaceError::msg("snapshot input is outside its store set"))?;
            let input = ordered.remove(index);
            ordered.insert(0, input);
        }
        let mut writers = Vec::with_capacity(ordered.len());
        for path in ordered {
            let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(sqlite)?;
            connection.busy_timeout(timeout).map_err(sqlite)?;
            connection
                .execute_batch("BEGIN IMMEDIATE")
                .map_err(sqlite)?;
            writers.push(connection);
        }
        Ok(Self {
            paths,
            _writers: writers,
        })
    }

    fn copy(&self) -> Result<[Vec<u8>; N]> {
        let directory = tempfile::tempdir().map_err(WorkspaceError::io)?;
        let mut copies = std::array::from_fn(|_| Vec::new());
        for (index, (path, bytes)) in self.paths.iter().zip(&mut copies).enumerate() {
            let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(sqlite)?;
            let target = directory.path().join(format!("{index}.sqlite"));
            connection
                .execute("VACUUM INTO ?1", [target.to_string_lossy().as_ref()])
                .map_err(sqlite)?;
            *bytes = std::fs::read(target).map_err(WorkspaceError::io)?;
        }
        Ok(copies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stores<const N: usize>(directory: &std::path::Path) -> [PathBuf; N] {
        std::array::from_fn(|index| {
            let path = directory.join(format!("{index}.sqlite"));
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "PRAGMA journal_mode=WAL;
                     CREATE TABLE marker (value INTEGER NOT NULL);
                     INSERT INTO marker VALUES (1);",
                )
                .unwrap();
            path
        })
    }

    fn writer(path: &std::path::Path) -> Connection {
        let connection =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        connection.busy_timeout(Duration::ZERO).unwrap();
        connection
    }

    #[test]
    fn snapshot_holds_every_writer_until_all_wal_stores_are_copied() {
        let directory = tempfile::tempdir().unwrap();
        let paths = stores::<3>(directory.path());
        let frozen = FrozenStores::acquire(paths.clone(), Duration::ZERO).unwrap();
        let writers = paths.each_ref().map(|path| writer(path));
        for connection in &writers {
            assert!(matches!(
                connection.execute("UPDATE marker SET value = 2", []),
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::DatabaseBusy
            ));
        }
        let copies = frozen.copy().unwrap();
        for (index, bytes) in copies.iter().enumerate() {
            let path = directory.path().join(format!("copy-{index}.sqlite"));
            std::fs::write(&path, bytes).unwrap();
            let connection =
                Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            assert_eq!(
                connection
                    .query_row("SELECT value FROM marker", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
        // Copying did not release the fence early.
        for connection in &writers {
            assert!(connection
                .execute("UPDATE marker SET value = 2", [])
                .is_err());
        }
        drop(frozen);
        for connection in &writers {
            assert_eq!(
                connection
                    .execute("UPDATE marker SET value = 2", [])
                    .unwrap(),
                1
            );
        }
    }

    #[test]
    fn workflow_snapshot_waits_for_inputs_before_taking_target_writers() {
        use std::sync::mpsc;
        use std::time::Instant;
        let directory = tempfile::tempdir().unwrap();
        let paths = stores::<2>(directory.path());
        let input = writer(&paths[1]);
        input.execute_batch("BEGIN IMMEDIATE").unwrap();
        let target = writer(&paths[0]);
        let (tx, rx) = mpsc::channel();
        let snapshot_paths = paths.clone();
        let worker = std::thread::spawn(move || {
            let started = Instant::now();
            let result = FrozenStores::acquire_ordered(
                snapshot_paths.clone(),
                Duration::from_millis(250),
                Some(&snapshot_paths[1]),
            );
            tx.send((started.elapsed(), result.is_err())).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut writes = 0;
        loop {
            if let Ok((elapsed, refused)) = rx.try_recv() {
                assert!(refused);
                assert!(
                    elapsed >= Duration::from_millis(200),
                    "snapshot never waited for inputs"
                );
                break;
            }
            assert!(Instant::now() < deadline);
            // A target-first snapshot holds this writer while waiting for the
            // input, which is the inverse of native publication's lock order.
            target
                .execute("UPDATE marker SET value = value + 1", [])
                .unwrap();
            writes += 1;
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(writes > 0);
        worker.join().unwrap();
        input.execute_batch("ROLLBACK").unwrap();
        assert_eq!(
            snapshot_stores_with_input(paths.clone(), &paths[1])
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn a_busy_store_releases_previously_acquired_locks() {
        let directory = tempfile::tempdir().unwrap();
        let paths = stores::<2>(directory.path());
        let occupied = writer(&paths[1]);
        occupied.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(FrozenStores::acquire(paths.clone(), Duration::ZERO).is_err());
        let first = writer(&paths[0]);
        assert_eq!(first.execute("UPDATE marker SET value = 2", []).unwrap(), 1);
        occupied.execute_batch("ROLLBACK").unwrap();
        let frozen = FrozenStores::acquire(paths, Duration::ZERO).unwrap();
        assert_eq!(frozen.copy().unwrap().len(), 2);
    }

    #[test]
    fn missing_stores_are_not_created_and_input_order_is_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let paths = stores::<2>(directory.path());
        let missing = directory.path().join("missing.sqlite");
        assert!(snapshot_stores([paths[0].clone(), missing.clone()]).is_err());
        assert!(!missing.exists());
        writer(&paths[1])
            .execute("UPDATE marker SET value = 2", [])
            .unwrap();
        let copies =
            snapshot_stores([paths[1].clone(), paths[0].clone(), paths[1].clone()]).unwrap();
        for (index, expected) in [2, 1, 2].into_iter().enumerate() {
            let path = directory.path().join(format!("copy-{index}.sqlite"));
            std::fs::write(&path, &copies[index]).unwrap();
            let connection =
                Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            assert_eq!(
                connection
                    .query_row("SELECT value FROM marker", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                expected
            );
        }
    }
}
