//! Immutable project authority-key retention (DR-0312, WS-673).
//! Private seeds reach this layer only as project-custodied ciphertext.

use rusqlite::{params, Connection, OptionalExtension};

use crate::Store;

/// This stores ciphertext, not an unwrapped private key. No Debug or wire
/// serialization: ordinary diagnostics and product responses expose no custody.
#[derive(Clone, PartialEq, Eq)]
pub struct ProjectAuthorityKey {
    pub project_id: String,
    pub authority_id: String,
    pub public_key: String,
    pub custody: String,
    pub wrapped_seed: Vec<u8>,
}

#[derive(Debug)]
pub enum AuthorityKeyError {
    Database(rusqlite::Error),
    Conflict(&'static str),
}
impl From<rusqlite::Error> for AuthorityKeyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}
impl std::fmt::Display for AuthorityKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => error.fmt(f),
            Self::Conflict(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for AuthorityKeyError {}

fn read(
    conn: &Connection,
    project: &str,
) -> Result<Option<ProjectAuthorityKey>, AuthorityKeyError> {
    Ok(conn
        .query_row(
            "SELECT authority_id, public_key, custody, wrapped_seed
             FROM project_authority_keys WHERE project_id = ?1",
            [project],
            |row| {
                Ok(ProjectAuthorityKey {
                    project_id: project.into(),
                    authority_id: row.get(0)?,
                    public_key: row.get(1)?,
                    custody: row.get(2)?,
                    wrapped_seed: row.get(3)?,
                })
            },
        )
        .optional()?)
}

impl Store {
    /// Reopen-only metadata read. Absence grants no initialization authority.
    pub fn project_authority_key(
        &self,
        project: &str,
    ) -> Result<Option<ProjectAuthorityKey>, AuthorityKeyError> {
        read(&self.conn, project)
    }

    /// Explicit creation under the project owner's shell. Commit before any
    /// signed fact can escape. Exact retries are inert; changed meaning refuses.
    pub fn retain_project_authority_key(
        &mut self,
        key: &ProjectAuthorityKey,
    ) -> Result<ProjectAuthorityKey, AuthorityKeyError> {
        if key.project_id.trim().is_empty() || key.authority_id.trim().is_empty() {
            return Err(AuthorityKeyError::Conflict(
                "project authority identity is empty",
            ));
        }
        crate::durable_registry::write(
            &mut self.conn,
            AuthorityKeyError::Conflict("project key creation must precede the product writer"),
            |tx| {
                if let Some(found) = read(tx, &key.project_id)? {
                    if found != *key {
                        return Err(AuthorityKeyError::Conflict(
                            "project authority key already has different meaning",
                        ));
                    }
                    return Ok(found);
                }
                tx.execute(
                    "INSERT INTO project_authority_keys VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        key.project_id,
                        key.authority_id,
                        key.public_key,
                        key.custody,
                        key.wrapped_seed
                    ],
                )?;
                Ok(key.clone())
            },
        )
    }

    /// True only for Store's explicitly disposable scratch database. A missing
    /// application root must never make a persistent database a loopback double.
    pub fn is_ephemeral(&self) -> bool {
        self.scratch.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(project: &str, marker: char) -> ProjectAuthorityKey {
        ProjectAuthorityKey {
            project_id: project.into(),
            authority_id: format!("project:{marker}"),
            public_key: format!("04{}", marker.to_string().repeat(128)),
            custody: "project-v1".into(),
            wrapped_seed: vec![1, 2, 3],
        }
    }

    #[test]
    fn durable_retention_reopens_and_refuses_changed_meaning() {
        let mut store = Store::open_in_memory().unwrap();
        let key = candidate("project", 'a');
        assert!(store.project_authority_key("project").unwrap().is_none());
        let before = store.synchronous().unwrap();
        assert!(store.retain_project_authority_key(&key).unwrap() == key);
        assert_eq!(store.synchronous().unwrap(), before);
        assert!(store.retain_project_authority_key(&key).unwrap() == key);
        assert!(store
            .retain_project_authority_key(&candidate("project", 'b'))
            .is_err());
        assert!(store
            .retain_project_authority_key(&candidate("other", 'a'))
            .is_err());
        assert!(
            store
                .sibling()
                .unwrap()
                .project_authority_key("project")
                .unwrap()
                .unwrap()
                == key
        );
        for sql in [
            "UPDATE project_authority_keys SET custody = 'loopback-v1'",
            "DELETE FROM project_authority_keys",
            "INSERT OR REPLACE INTO project_authority_keys SELECT * FROM project_authority_keys",
        ] {
            assert!(store.conn.execute_batch(sql).is_err());
        }
        assert!(store.project_authority_key("project").unwrap().unwrap() == key);
    }

    #[test]
    fn open_product_writer_cannot_publish_a_new_key() {
        let mut store = Store::open_in_memory().unwrap();
        store.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(store
            .retain_project_authority_key(&candidate("project", 'a'))
            .is_err());
        assert!(store.project_authority_key("project").unwrap().is_none());
        store.conn.execute_batch("ROLLBACK").unwrap();
        assert!(store
            .retain_project_authority_key(&candidate("project", 'a'))
            .is_ok());
    }
}
