//! An exact, read-only inventory of one legacy product database snapshot.
//!
//! The Home migration must account for every old row, including rows in tables
//! added after this inventory was written. A digest of known event scopes alone
//! would silently omit a new store plane. This inventory enumerates SQLite's
//! actual tables and fingerprints their values under one read transaction. It
//! does not assign project ownership, copy rows, or certify Home coverage.

use rusqlite::{params, types::ValueRef, Transaction};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::{AdmitError, Store};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationTableInventory {
    pub table: String,
    pub rows: u64,
    /// SHA-256 of the table name, stored CREATE statement, and every row's
    /// typed values. Row hashes are sorted, so physical row order is irrelevant.
    pub contents_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationSourceInventory {
    /// SHA-256 of all retained SQLite schema objects, including indexes and
    /// triggers. Physical page numbers are deliberately excluded.
    pub schema_sha256: String,
    /// Every table in this snapshot, including a table this build does not
    /// recognize. A migration planner must classify every nonempty population.
    pub tables: Vec<MigrationTableInventory>,
}

/// An event population at the same SQLite cut as the table inventory. These
/// coordinates identify work the migration must classify; a scope name alone
/// does not prove which project owns any event inside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationEventScopePopulation {
    pub scope_id: String,
    pub rows: u64,
    pub first_position: i64,
    pub last_position: i64,
}

/// One product SQLite cut, including decoded retained events from a named
/// scope. The events are in-process migration input and may contain payloads;
/// only `inventory` is safe to use as a payload-free report.
pub struct MigrationSourceSnapshot {
    pub inventory: MigrationSourceInventory,
    pub event_scopes: Vec<MigrationEventScopePopulation>,
    pub retained_events: Vec<(i64, String, String)>,
}

impl MigrationSourceInventory {
    /// Schema discovery is not ownership discovery. Name every nonempty table
    /// a caller has not explicitly classified before it attempts a migration.
    /// Classifying a mixed table still requires a separate decision for each
    /// row; this method cannot certify a Home population.
    pub fn nonempty_unclassified_tables(&self, classified: &[&str]) -> Vec<String> {
        let classified: BTreeSet<&str> = classified.iter().copied().collect();
        self.tables
            .iter()
            .filter(|table| table.rows > 0 && !classified.contains(table.table.as_str()))
            .map(|table| table.table.clone())
            .collect()
    }
}

fn framed(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn value(hash: &mut Sha256, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hash.update([0]),
        ValueRef::Integer(number) => {
            hash.update([1]);
            framed(hash, &number.to_be_bytes());
        }
        ValueRef::Real(number) => {
            hash.update([2]);
            framed(hash, &number.to_bits().to_be_bytes());
        }
        ValueRef::Text(bytes) => {
            hash.update([3]);
            framed(hash, bytes);
        }
        ValueRef::Blob(bytes) => {
            hash.update([4]);
            framed(hash, bytes);
        }
    }
}

fn quoted(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

impl Store {
    /// Fingerprint every table and schema object at one consistent SQLite read
    /// cut. The result contains no payloads and makes no owner assertion. A
    /// later migration may use it to prove that its explicit row mapping did
    /// not silently ignore a newly introduced or changed population.
    pub fn migration_source_inventory(&self) -> Result<MigrationSourceInventory, AdmitError> {
        let snapshot = self.conn.unchecked_transaction()?;
        let inventory = inventory_at(&snapshot)?;
        snapshot.commit()?;
        Ok(inventory)
    }

    /// Read one scope's complete retained event history and the whole product
    /// database inventory at the same SQLite cut. The decoded event payloads
    /// are for an in-process migration classifier; callers must not publish
    /// them as part of the payload-free inventory. External codec authority
    /// can still refuse the read, and this does not snapshot other stores.
    pub fn migration_source_inventory_with_retained_events(
        &self,
        scope_id: &str,
    ) -> Result<MigrationSourceSnapshot, AdmitError> {
        let snapshot = self.conn.unchecked_transaction()?;
        let inventory = inventory_at(&snapshot)?;
        let event_scopes = event_scopes_at(&snapshot)?;
        let retained_events = self.retained_events_at(&snapshot, scope_id)?;
        snapshot.commit()?;
        Ok(MigrationSourceSnapshot {
            inventory,
            event_scopes,
            retained_events,
        })
    }

    fn retained_events_at(
        &self,
        snapshot: &Transaction<'_>,
        scope_id: &str,
    ) -> Result<Vec<(i64, String, String)>, AdmitError> {
        let mut statement = snapshot.prepare(
            "SELECT position, kind, payload FROM events WHERE scope_id = ?1 ORDER BY position",
        )?;
        let rows = statement.query_map(params![scope_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (position, kind, payload) = row?;
            let payload = match &self.codec {
                Some(codec) => codec.decode(scope_id, &kind, &payload).ok_or_else(|| {
                    AdmitError::Codec("authority history contains an unavailable record".into())
                })?,
                None => payload,
            };
            events.push((position, kind, payload));
        }
        Ok(events)
    }
}

fn event_scopes_at(
    snapshot: &Transaction<'_>,
) -> Result<Vec<MigrationEventScopePopulation>, AdmitError> {
    let mut statement = snapshot.prepare(
        "SELECT scope_id, COUNT(*), MIN(position), MAX(position) \
         FROM events GROUP BY scope_id ORDER BY scope_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut populations = Vec::new();
    for row in rows {
        let (scope_id, rows, first_position, last_position) = row?;
        let rows = u64::try_from(rows)
            .map_err(|_| AdmitError::Codec("event scope has a negative row count".into()))?;
        populations.push(MigrationEventScopePopulation {
            scope_id,
            rows,
            first_position,
            last_position,
        });
    }
    Ok(populations)
}

fn inventory_at(snapshot: &Transaction<'_>) -> Result<MigrationSourceInventory, AdmitError> {
    let schema_objects: Vec<(String, String, String, Option<String>)> = {
        let mut query = snapshot.prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name, tbl_name",
        )?;
        let objects = query
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<Result<_, _>>()?;
        objects
    };
    let mut schema_hash = Sha256::new();
    framed(&mut schema_hash, b"gaugedesk.migration.schema.v1");
    for (kind, name, table, sql) in &schema_objects {
        framed(&mut schema_hash, kind.as_bytes());
        framed(&mut schema_hash, name.as_bytes());
        framed(&mut schema_hash, table.as_bytes());
        match sql {
            Some(sql) => {
                schema_hash.update([1]);
                framed(&mut schema_hash, sql.as_bytes());
            }
            None => schema_hash.update([0]),
        }
    }

    let mut tables = Vec::new();
    for (kind, name, _, sql) in &schema_objects {
        if kind != "table" {
            continue;
        }
        let mut row_hashes = Vec::new();
        let mut statement = snapshot.prepare(&format!("SELECT * FROM {}", quoted(name)))?;
        let columns = statement.column_count();
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let mut row_hash = Sha256::new();
            framed(&mut row_hash, b"gaugedesk.migration.row.v1");
            row_hash.update((columns as u64).to_be_bytes());
            for column in 0..columns {
                value(&mut row_hash, row.get_ref(column)?);
            }
            row_hashes.push(row_hash.finalize().to_vec());
        }
        row_hashes.sort();
        let mut table_hash = Sha256::new();
        framed(&mut table_hash, b"gaugedesk.migration.table.v1");
        framed(&mut table_hash, name.as_bytes());
        framed(&mut table_hash, sql.as_deref().unwrap_or("").as_bytes());
        table_hash.update((row_hashes.len() as u64).to_be_bytes());
        for row_hash in &row_hashes {
            framed(&mut table_hash, row_hash);
        }
        tables.push(MigrationTableInventory {
            table: name.clone(),
            rows: row_hashes.len() as u64,
            contents_sha256: hex::encode(table_hash.finalize()),
        });
    }
    Ok(MigrationSourceInventory {
        schema_sha256: hex::encode(schema_hash.finalize()),
        tables,
    })
}

#[cfg(test)]
mod tests {
    use crate::Store;

    fn table<'a>(
        inventory: &'a super::MigrationSourceInventory,
        name: &str,
    ) -> &'a super::MigrationTableInventory {
        inventory
            .tables
            .iter()
            .find(|entry| entry.table == name)
            .expect("table is inventoried")
    }

    #[test]
    fn inventory_binds_values_and_exposes_an_unknown_legacy_population() {
        let mut store = Store::open_in_memory().expect("store");
        store
            .append_record("legacy-scope", "legacy-kind", "private body")
            .expect("event");
        let first = store.migration_source_inventory().expect("first inventory");
        assert_eq!(table(&first, "events").rows, 1);
        assert!(
            !format!("{first:?}").contains("private body"),
            "a migration report contains hashes and coordinates, not payloads"
        );

        // A row-count-only inventory would miss a rewrite of existing history.
        store
            .conn
            .execute(
                "UPDATE events SET payload = 'changed body' WHERE scope_id = 'legacy-scope'",
                [],
            )
            .expect("simulate changed legacy bytes");
        let changed = store
            .migration_source_inventory()
            .expect("changed inventory");
        assert_eq!(table(&changed, "events").rows, 1);
        assert_ne!(
            table(&first, "events").contents_sha256,
            table(&changed, "events").contents_sha256
        );

        // A future schema's unclassified table must be visible even when this
        // build has no migration logic for its rows. A quote in its name also
        // proves that metadata-derived identifiers are quoted as identifiers.
        store
            .conn
            .execute_batch("CREATE TABLE \"later\"\"plane\" (body TEXT); INSERT INTO \"later\"\"plane\" VALUES ('unmapped');")
            .expect("later population");
        let later = store.migration_source_inventory().expect("later inventory");
        assert_eq!(table(&later, "later\"plane").rows, 1);
        assert_ne!(first.schema_sha256, later.schema_sha256);
        assert!(!format!("{later:?}").contains("unmapped"));
        assert!(later
            .nonempty_unclassified_tables(&["events"])
            .contains(&"later\"plane".to_owned()));
    }

    #[test]
    fn product_inventory_and_retained_history_observe_the_same_cut() {
        let mut writer = Store::open_in_memory().expect("store");
        writer
            .append_record("library", "project", r#"{"id":"first"}"#)
            .expect("first event");
        let reader = writer.sibling().expect("reader");
        let snapshot = reader.conn.unchecked_transaction().expect("snapshot");
        let before = super::inventory_at(&snapshot).expect("inventory");
        let before_scopes = super::event_scopes_at(&snapshot).expect("event scopes");

        // A second connection may commit while the migration reader is
        // walking its snapshot. Its new row must join neither half of that
        // reader's evidence.
        writer
            .append_record("library", "project", r#"{"id":"second"}"#)
            .expect("concurrent event");
        let retained = reader
            .retained_events_at(&snapshot, "library")
            .expect("retained history");
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].0, 0);
        assert_eq!(table(&before, "events").rows, 1);
        assert_eq!(before_scopes[0].rows, 1);
        assert_eq!(before_scopes[0].last_position, 0);
        snapshot.commit().expect("finish read");

        let after = reader
            .migration_source_inventory_with_retained_events("library")
            .expect("fresh cut");
        assert_eq!(after.retained_events.len(), 2);
        assert_eq!(table(&after.inventory, "events").rows, 2);
        assert_eq!(after.event_scopes[0].rows, 2);
        assert_eq!(after.event_scopes[0].last_position, 1);
        assert_ne!(before, after.inventory);
    }
}
