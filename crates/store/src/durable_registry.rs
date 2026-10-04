//! Durable metadata commits, independent of ordinary product settings.

use rusqlite::{Connection, Transaction, TransactionBehavior};

pub(crate) fn write<T, E: From<rusqlite::Error>>(
    conn: &mut Connection,
    open_writer_error: E,
    write: impl FnOnce(&Transaction<'_>) -> Result<T, E>,
) -> Result<T, E> {
    if !conn.is_autocommit() {
        return Err(open_writer_error);
    }
    let original: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let fullfsync: i64 = conn.query_row("PRAGMA fullfsync", [], |row| row.get(0))?;
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let durable = if mode == "wal" { 2 } else { 3 };
    conn.execute_batch(&format!(
        "PRAGMA synchronous={durable}; PRAGMA fullfsync=ON;"
    ))?;
    let result: Result<T, E> = (|| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = write(&tx)?;
        tx.commit()?;
        Ok(value)
    })();
    let restored = conn.execute_batch(&format!(
        "PRAGMA synchronous={original}; PRAGMA fullfsync={fullfsync};"
    ));
    match result {
        Ok(value) => {
            restored?;
            Ok(value)
        }
        Err(error) => {
            let _ = restored;
            Err(error)
        }
    }
}
