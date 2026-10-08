//! Dedicated Home product storage and host-side binding catalog (DR-0414).
//!
//! These are storage coordinates, not membership or an activation certificate.
//! Explicit population/migration and current authority remain the Home shell's
//! responsibility. No accepting path is switched by initializing these files.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::home_reference_journal::{HomeReferenceJournal, JournalError};
use crate::Store;

pub(crate) const CATALOG_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS home_product_bindings (
        project_id TEXT PRIMARY KEY CHECK (length(project_id) > 0),
        home_id TEXT NOT NULL UNIQUE CHECK (length(home_id) > 0),
        incarnation TEXT NOT NULL UNIQUE CHECK (length(incarnation) = 32)
    );
    CREATE TABLE IF NOT EXISTS home_product_ready (
        project_id TEXT PRIMARY KEY REFERENCES home_product_bindings(project_id),
        home_id TEXT NOT NULL,
        incarnation TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS home_product_bindings_no_update BEFORE UPDATE ON home_product_bindings
        BEGIN SELECT RAISE(ABORT, 'Home product binding is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS home_product_bindings_no_delete BEFORE DELETE ON home_product_bindings
        BEGIN SELECT RAISE(ABORT, 'Home product binding is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS home_product_bindings_no_replace BEFORE INSERT ON home_product_bindings
        WHEN EXISTS (SELECT 1 FROM home_product_bindings WHERE project_id = NEW.project_id)
        BEGIN SELECT RAISE(ABORT, 'Home product binding is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS home_product_ready_exact BEFORE INSERT ON home_product_ready
        WHEN NOT EXISTS (SELECT 1 FROM home_product_bindings WHERE project_id = NEW.project_id
            AND home_id = NEW.home_id AND incarnation = NEW.incarnation)
        BEGIN SELECT RAISE(ABORT, 'Home product readiness requires its exact registration'); END;
    CREATE TRIGGER IF NOT EXISTS home_product_ready_no_update BEFORE UPDATE ON home_product_ready
        BEGIN SELECT RAISE(ABORT, 'Home product readiness is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS home_product_ready_no_delete BEFORE DELETE ON home_product_ready
        BEGIN SELECT RAISE(ABORT, 'Home product readiness is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS home_product_ready_no_replace BEFORE INSERT ON home_product_ready
        WHEN EXISTS (SELECT 1 FROM home_product_ready WHERE project_id = NEW.project_id)
        BEGIN SELECT RAISE(ABORT, 'Home product readiness is immutable'); END;";

const STORAGE_SCHEMA: &str = "
    CREATE TABLE home_product_storage (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        project_id TEXT NOT NULL CHECK (length(project_id) > 0),
        home_id TEXT NOT NULL CHECK (length(home_id) > 0),
        incarnation TEXT NOT NULL CHECK (length(incarnation) = 32)
    );
    CREATE TRIGGER home_product_storage_no_update BEFORE UPDATE ON home_product_storage
        BEGIN SELECT RAISE(ABORT, 'Home product storage binding is immutable'); END;
    CREATE TRIGGER home_product_storage_no_delete BEFORE DELETE ON home_product_storage
        BEGIN SELECT RAISE(ABORT, 'Home product storage binding is immutable'); END;
    CREATE TRIGGER home_product_storage_no_replace BEFORE INSERT ON home_product_storage
        WHEN EXISTS (SELECT 1 FROM home_product_storage)
        BEGIN SELECT RAISE(ABORT, 'Home product storage binding is immutable'); END;
    CREATE TRIGGER home_product_reference_state_read_only BEFORE UPDATE ON home_reference_state
        BEGIN SELECT RAISE(ABORT, 'Home operations require the separate journal'); END;";

/// Retained by the Home/host catalog independently of the product file. A
/// supplied descriptor alone grants no authority to create or populate a Home.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeProductBinding {
    pub project_id: String,
    pub home_id: String,
    pub incarnation: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeProductRegistration {
    pub binding: HomeProductBinding,
    /// Storage initialized, not populated, migrated or activated.
    pub ready: bool,
}

/// Storage prepared for one exact project Home. This grants no membership,
/// migrated population, use authority, or Home-wide coverage.
pub struct PreparedHomeStorage {
    pub product: Store,
    pub journal: HomeReferenceJournal,
}

#[derive(Debug)]
pub enum HomeStoragePreparationError {
    Product(HomeProductError),
    Journal(JournalError),
    Conflict(&'static str),
}

impl From<HomeProductError> for HomeStoragePreparationError {
    fn from(error: HomeProductError) -> Self {
        Self::Product(error)
    }
}

impl From<JournalError> for HomeStoragePreparationError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl std::fmt::Display for HomeStoragePreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Product(error) => error.fmt(f),
            Self::Journal(error) => error.fmt(f),
            Self::Conflict(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for HomeStoragePreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Product(error) => Some(error),
            Self::Journal(error) => Some(error),
            Self::Conflict(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum HomeProductError {
    Database(rusqlite::Error),
    Storage(std::io::Error),
    Conflict(&'static str),
}
impl From<rusqlite::Error> for HomeProductError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}
impl From<std::io::Error> for HomeProductError {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(error)
    }
}
impl std::fmt::Display for HomeProductError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => error.fmt(f),
            Self::Storage(error) => error.fmt(f),
            Self::Conflict(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for HomeProductError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::Conflict(_) => None,
        }
    }
}

pub(crate) fn as_database_error(error: HomeProductError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

fn validate(binding: &HomeProductBinding) -> Result<(), HomeProductError> {
    if binding.project_id.trim().is_empty() || binding.home_id.trim().is_empty() {
        return Err(HomeProductError::Conflict("Home product identity is empty"));
    }
    if binding.incarnation.len() != 32
        || !binding
            .incarnation
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(HomeProductError::Conflict(
            "Home product incarnation is invalid",
        ));
    }
    Ok(())
}

fn path_string(path: &Path) -> Result<String, HomeProductError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(HomeProductError::Conflict("Home product path is not UTF-8"))
}

/// Full opaque project identity, never a display slug or an incarnation. A lost
/// catalog cannot evade an old file by choosing another incarnation directory.
pub fn home_product_path(root: &Path, project_id: &str) -> PathBuf {
    crate::home_reference_catalog::home_reference_journal_path(root, project_id)
        .with_file_name("product.sqlite")
}

pub(crate) fn refuse_unbound_open(conn: &Connection) -> Result<(), rusqlite::Error> {
    let bound: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE name = 'home_product_storage')",
        [],
        |row| row.get(0),
    )?;
    if bound {
        return Err(as_database_error(HomeProductError::Conflict(
            "Home product storage requires an independently retained binding",
        )));
    }
    Ok(())
}

pub(crate) fn binding_in(conn: &Connection) -> Result<Option<HomeProductBinding>, rusqlite::Error> {
    let bound: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE name = 'home_product_storage')",
        [],
        |row| row.get(0),
    )?;
    if !bound {
        return Ok(None);
    }
    conn.query_row(
        "SELECT project_id, home_id, incarnation FROM home_product_storage WHERE id = 1",
        [],
        |row| {
            Ok(HomeProductBinding {
                project_id: row.get(0)?,
                home_id: row.get(1)?,
                incarnation: row.get(2)?,
            })
        },
    )
    .map(Some)
}

/// Product/journal metadata may not register contradictory Home coordinates.
/// The check belongs inside the durable catalog writer, not a prior observation.
pub(crate) fn check_product_identity(
    conn: &Connection,
    project: &str,
    home: &str,
) -> Result<(), rusqlite::Error> {
    if binding_in(conn)?.is_some_and(|bound| bound.project_id != project || bound.home_id != home) {
        return Err(as_database_error(HomeProductError::Conflict(
            "journal registration names another Home product store",
        )));
    }
    let conflict: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM home_product_bindings WHERE (project_id = ?1 OR home_id = ?2) AND (project_id != ?1 OR home_id != ?2))",
        params![project, home], |row| row.get(0),
    )?;
    if conflict {
        return Err(as_database_error(HomeProductError::Conflict(
            "journal registration contradicts a Home product binding",
        )));
    }
    Ok(())
}

fn connection_policy(conn: &Connection) -> Result<(), HomeProductError> {
    conn.busy_timeout(Duration::from_secs(30))?;
    let sync = crate::synchronous_mode(gaugedesk_env::var("SQLITE_SYNCHRONOUS").as_deref());
    let journal = crate::journal_mode(gaugedesk_env::var("SQLITE_JOURNAL_MODE").as_deref());
    conn.execute_batch(&format!(
        "PRAGMA journal_mode={journal}; PRAGMA synchronous={sync}; PRAGMA foreign_keys=ON;"
    ))?;
    conn.set_prepared_statement_cache_capacity(crate::STATEMENT_CACHE_CAPACITY);
    Ok(())
}

fn verify_existing(
    conn: &Connection,
    expected: &HomeProductBinding,
) -> Result<(), HomeProductError> {
    let found = conn.query_row(
        "SELECT project_id, home_id, incarnation FROM home_product_storage WHERE id = 1",
        [],
        |row| {
            Ok(HomeProductBinding {
                project_id: row.get(0)?,
                home_id: row.get(1)?,
                incarnation: row.get(2)?,
            })
        },
    )?;
    if found != *expected {
        return Err(HomeProductError::Conflict(
            "Home product storage differs from its retained binding",
        ));
    }
    // A runtime reopen cannot initialize or upgrade a partial/older store.
    let mut statement = conn.prepare("SELECT version FROM schema_migrations ORDER BY version")?;
    let versions = statement
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if versions
        != crate::MIGRATIONS
            .iter()
            .map(|migration| migration.version)
            .collect::<Vec<_>>()
    {
        return Err(HomeProductError::Conflict(
            "Home product schema requires explicit migration or recovery",
        ));
    }
    // Verify the supported schema shape, including all tables, indexes and
    // immutable binding guards. A matching ledger alone is not recovery proof.
    if schema_shape(conn)? != supported_shape()? {
        return Err(HomeProductError::Conflict(
            "Home product schema is partial or incompatible",
        ));
    }
    Ok(())
}

fn schema_shape(conn: &Connection) -> Result<Vec<(String, String, String)>, rusqlite::Error> {
    conn.prepare("SELECT type, name, sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY type, name")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect()
}

fn supported_shape() -> Result<Vec<(String, String, String)>, rusqlite::Error> {
    // Build the reference from the one schema source; never maintain a second
    // table inventory. Once per process, independent of project files.
    static SHAPE: std::sync::OnceLock<Vec<(String, String, String)>> = std::sync::OnceLock::new();
    if let Some(shape) = SHAPE.get() {
        return Ok(shape.clone());
    }
    let mut conn = Connection::open_in_memory()?;
    let tx = conn.transaction()?;
    initialize(&tx)?;
    tx.execute_batch(STORAGE_SCHEMA)?;
    let shape = schema_shape(&tx)?;
    let _ = SHAPE.set(shape.clone());
    Ok(shape)
}

fn initialize(tx: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    tx.execute_batch("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);")?;
    for migration in crate::MIGRATIONS {
        tx.execute_batch(migration.sql)?;
        tx.execute(
            "INSERT INTO schema_migrations(version) VALUES (?1)",
            [migration.version],
        )?;
    }
    Ok(())
}

fn existing(
    path: &Path,
    expected: &HomeProductBinding,
    read_only: bool,
) -> Result<Store, HomeProductError> {
    validate(expected)?;
    let path_string = path_string(path)?;
    let flags = if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    let mut conn = Connection::open_with_flags(path, flags)?;
    conn.busy_timeout(Duration::from_secs(30))?;
    // Identity and schema come from one snapshot before any journal-setting write.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
    verify_existing(&tx, expected)?;
    tx.commit()?;
    if !read_only {
        connection_policy(&conn)?;
    }
    Ok(Store {
        conn,
        codec: None,
        path: path_string,
        scratch: None,
        home_product: Some(expected.clone()),
        remembered: Default::default(),
    })
}

pub(crate) fn reopen(
    source: &Store,
    expected: &HomeProductBinding,
    read_only: bool,
) -> Result<Store, HomeProductError> {
    let mut store = existing(
        Path::new(&source.path),
        expected,
        read_only || source.conn.is_readonly("main")?,
    )?;
    store.codec = source.codec.clone();
    Ok(store)
}

fn registration(
    conn: &Connection,
    project: &str,
) -> Result<Option<HomeProductRegistration>, HomeProductError> {
    let binding = conn.query_row(
        "SELECT project_id, home_id, incarnation FROM home_product_bindings WHERE project_id = ?1", [project],
        |row| Ok(HomeProductBinding {project_id: row.get(0)?, home_id: row.get(1)?, incarnation: row.get(2)?}),
    ).optional()?;
    let Some(binding) = binding else {
        return Ok(None);
    };
    let ready = conn
        .query_row(
            "SELECT home_id, incarnation FROM home_product_ready WHERE project_id = ?1",
            [project],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if ready.as_ref().is_some_and(|(home, incarnation)| {
        home != &binding.home_id || incarnation != &binding.incarnation
    }) {
        return Err(HomeProductError::Conflict(
            "Home product readiness differs from its registration",
        ));
    }
    Ok(Some(HomeProductRegistration {
        binding,
        ready: ready.is_some(),
    }))
}

impl Store {
    /// Prepare both files beneath one retained project/Home identity. The host
    /// catalog binds the product store; that exact product store then binds its
    /// own journal. An interrupted preparation resumes only those same
    /// bindings; missing or partial ready files never become empty replacements.
    /// Product readiness before journal readiness remains inert: the caller
    /// must independently authenticate, migrate and activate the Home.
    pub fn prepare_project_home_storage(
        &mut self,
        root: &Path,
        project: &str,
        home: &str,
    ) -> Result<PreparedHomeStorage, HomeStoragePreparationError> {
        if self.home_product.is_some() || project.trim().is_empty() || home.trim().is_empty() {
            return Err(HomeStoragePreparationError::Conflict(
                "Home storage preparation requires a host catalog and exact identities",
            ));
        }
        let product_registration = self.home_product_registration(project)?;
        if product_registration
            .as_ref()
            .is_some_and(|registered| registered.binding.home_id != home)
        {
            return Err(HomeStoragePreparationError::Conflict(
                "project Home storage is already bound to another identity",
            ));
        }
        let mut product = self.initialize_home_product(root, project, home)?;
        let journal = product.initialize_home_journal(root, project, home)?;
        Ok(PreparedHomeStorage { product, journal })
    }

    /// Exact identity of this bound connection; absent for the install prototype
    /// and host catalog. This is not the project's current hosting assignment.
    pub fn home_product_binding(&self) -> Option<&HomeProductBinding> {
        self.home_product.as_ref()
    }

    /// Explicit, no-replace creation. Schema and storage identity commit together
    /// durably. Partial files survive refusal for explicit owning-Home recovery.
    pub fn create_home_product(
        path: &Path,
        binding: HomeProductBinding,
    ) -> Result<Self, HomeProductError> {
        validate(&binding)?;
        let path_string = path_string(path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        drop(file);
        let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection_policy(&conn)?;
        crate::durable_registry::write(
            &mut conn,
            HomeProductError::Conflict("Home product creation requires an independent writer"),
            |tx| {
                initialize(tx)?;
                tx.execute_batch(STORAGE_SCHEMA)?;
                tx.execute(
                    "INSERT INTO home_product_storage VALUES (1, ?1, ?2, ?3)",
                    params![binding.project_id, binding.home_id, binding.incarnation],
                )?;
                Ok(())
            },
        )?;
        Ok(Self {
            conn,
            codec: None,
            path: path_string,
            scratch: None,
            home_product: Some(binding),
            remembered: Default::default(),
        })
    }

    /// Runtime opening requires independently retained coordinates. No CREATE,
    /// migration, registration or project discovery. Ordinary Store::open refuses
    /// a bound file so it cannot silently downgrade into the install prototype.
    pub fn open_home_product_existing(
        path: &Path,
        expected: &HomeProductBinding,
    ) -> Result<Self, HomeProductError> {
        existing(path, expected, false)
    }

    pub fn home_product_registration(
        &self,
        project: &str,
    ) -> Result<Option<HomeProductRegistration>, HomeProductError> {
        if self.home_product.is_some() {
            return Err(HomeProductError::Conflict(
                "a Home product store is not a host catalog",
            ));
        }
        registration(&self.conn, project)
    }

    /// Host catalog retention under the authenticated Home creation shell. Exact
    /// retries keep the winner's incarnation; changed project/Home meaning refuses.
    pub fn register_home_product(
        &mut self,
        project: &str,
        home: &str,
    ) -> Result<HomeProductRegistration, HomeProductError> {
        if self.home_product.is_some() || project.trim().is_empty() || home.trim().is_empty() {
            return Err(HomeProductError::Conflict(
                "Home product registration requires a host catalog and exact identities",
            ));
        }
        crate::durable_registry::write(
            &mut self.conn,
            HomeProductError::Conflict("Home product registration must precede the product writer"),
            |tx| {
                let conflict: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM home_reference_journal_bindings WHERE (project_id = ?1 OR home_id = ?2) AND (project_id != ?1 OR home_id != ?2))",
                    params![project, home], |row| row.get(0),
                )?;
                if conflict {
                    return Err(HomeProductError::Conflict(
                        "Home product registration contradicts a journal binding",
                    ));
                }
                if let Some(found) = registration(tx, project)? {
                    if found.binding.home_id != home {
                        return Err(HomeProductError::Conflict(
                            "project product store belongs to a different Home",
                        ));
                    }
                    return Ok(found);
                }
                let other = tx
                    .query_row(
                        "SELECT project_id FROM home_product_bindings WHERE home_id = ?1",
                        [home],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                if other.is_some() {
                    return Err(HomeProductError::Conflict(
                        "Home product store belongs to another project",
                    ));
                }
                tx.execute(
                    "INSERT INTO home_product_bindings VALUES (?1, ?2, lower(hex(randomblob(16))))",
                    params![project, home],
                )?;
                registration(tx, project)?.ok_or(HomeProductError::Conflict(
                    "Home product registration disappeared",
                ))
            },
        )
    }

    /// Stage or recover exact storage only. Ready registrations never recreate
    /// lost files; interrupted initialization reuses only the original binding.
    pub fn initialize_home_product(
        &mut self,
        root: &Path,
        project: &str,
        home: &str,
    ) -> Result<Store, HomeProductError> {
        let registered = self.register_home_product(project, home)?;
        let path = home_product_path(root, project);
        if registered.ready {
            return Self::open_home_product_existing(&path, &registered.binding);
        }
        let store = if path.try_exists()? {
            Self::open_home_product_existing(&path, &registered.binding)?
        } else {
            std::fs::create_dir_all(
                path.parent()
                    .ok_or(HomeProductError::Conflict("Home product root is absent"))?,
            )?;
            Self::create_home_product(&path, registered.binding.clone())?
        };
        crate::durable_registry::write(
            &mut self.conn,
            HomeProductError::Conflict("Home product readiness must precede the product writer"),
            |tx| {
                let current = registration(tx, project)?.ok_or(HomeProductError::Conflict(
                    "Home product registration disappeared",
                ))?;
                if current.binding != registered.binding {
                    return Err(HomeProductError::Conflict(
                        "Home product registration changed",
                    ));
                }
                if !current.ready {
                    tx.execute(
                        "INSERT INTO home_product_ready VALUES (?1, ?2, ?3)",
                        params![project, home, registered.binding.incarnation],
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(store)
    }

    pub fn open_registered_home_product(
        &self,
        root: &Path,
        project: &str,
    ) -> Result<Store, HomeProductError> {
        let registered =
            self.home_product_registration(project)?
                .ok_or(HomeProductError::Conflict(
                    "Home product store has no registration",
                ))?;
        if !registered.ready {
            return Err(HomeProductError::Conflict(
                "Home product storage is not ready",
            ));
        }
        Self::open_home_product_existing(&home_product_path(root, project), &registered.binding)
    }
}

#[cfg(test)]
mod tests;
