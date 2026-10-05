//! Project signing custody (DR-0312, WS-673). This is a key-storage boundary,
//! not membership, methodology standing or planner coverage.

use std::io;

use gaugedesk_core::ids::{AuthorityId, PublicKey};
use gaugedesk_core::signature::SigningKey;
use gaugedesk_store::project_authority::ProjectAuthorityKey;
use sha2::{Digest, Sha256};

use crate::at_rest::{KeyWrap, LoopbackKeyWrap};
use crate::Workbench;

pub(crate) fn authority(public_key: &PublicKey) -> AuthorityId {
    AuthorityId::new(format!(
        "project:{}",
        hex::encode(Sha256::digest(public_key.as_str().as_bytes()))
    ))
}

impl Workbench {
    pub(crate) fn require_owned_project(&self, project: &str) -> io::Result<()> {
        let library = crate::library::Library::rebuild(self.store_ref())
            .map_err(|e| io::Error::other(format!("{e:?}")))?;
        if project.trim().is_empty()
            || library
                .projects
                .get(project)
                .is_none_or(|record| record.home_id != *self.home_id())
        {
            return Err(io::Error::other("project signing authority is not local"));
        }
        Ok(())
    }

    fn bare_signing_custody(&self) -> bool {
        self.root_path().as_os_str().is_empty() && self.store_ref().is_ephemeral()
    }

    /// Explicit project initialization, before entering a product writer or
    /// publishing signed facts. A concurrent creator's durable key wins; no
    /// losing private candidate can escape this method. The trusted composition
    /// must admit the project creation/recovery first; this storage operation
    /// grants no membership or permission to publish a signed fact.
    pub fn initialize_project_authority(&mut self, project: &str) -> io::Result<()> {
        let handoff = crate::federation::handoff_scope(project);
        let (_, basis) = self
            .store_ref()
            .read_for_dispatch(&[crate::library::LIBRARY_SCOPE, &handoff], |store| {
                crate::federation::require_project_writes_available(store, project)
            })
            .map_err(|error| {
                io::Error::other(format!(
                    "project initialization authority refused: {error:?}"
                ))
            })?;
        self.initialize_project_authority_at(project, &basis)
    }

    pub(crate) fn initialize_project_authority_against(
        &mut self,
        project: &str,
        basis: &gaugedesk_store::command_dispatch::DispatchReadBasis,
    ) -> io::Result<()> {
        self.initialize_project_authority_at(project, basis)
    }

    fn initialize_project_authority_at(
        &mut self,
        project: &str,
        basis: &gaugedesk_store::command_dispatch::DispatchReadBasis,
    ) -> io::Result<()> {
        self.require_owned_project(project)?;
        if self
            .store_ref()
            .project_authority_key(project)
            .map_err(io::Error::other)?
            .is_some()
        {
            self.project_signing_key(project)?;
            return Ok(());
        }
        let key = loop {
            let mut seed = [0; 32];
            getrandom::getrandom(&mut seed).map_err(|error| io::Error::other(error.to_string()))?;
            if let Ok(key) = SigningKey::from_seed(&seed) {
                break key;
            }
        };
        let (custody, wrapped_seed) = match self.content_vault.as_ref() {
            Some(vault) => (
                "project-v1",
                vault.seal_project_authority_seed(project, &key.to_seed_bytes())?,
            ),
            None if self.bare_signing_custody() => (
                "loopback-v1",
                LoopbackKeyWrap::new(self.governance_seed())
                    .wrap(&key.to_seed_bytes())
                    .map_err(|_| io::Error::other("loopback project key custody failed"))?,
            ),
            None => {
                return Err(io::Error::other(
                    "project signing-key custody is unavailable",
                ))
            }
        };
        let public_key = key.public_key();
        let retained = ProjectAuthorityKey {
            project_id: project.into(),
            authority_id: authority(&public_key).as_str().into(),
            public_key: public_key.as_str().into(),
            custody: custody.into(),
            wrapped_seed,
        };
        let retention = self
            .store_mut()
            .retain_project_authority_key_against(&retained, basis);
        if let Err(error) = retention {
            // A crash/retry or concurrent initializer may have committed first.
            // Recover only an actually retained key through the strict reader.
            if self
                .store_ref()
                .project_authority_key(project)
                .map_err(io::Error::other)?
                .is_none()
            {
                return Err(io::Error::other(error));
            }
        }
        self.project_signing_key(project)?;
        Ok(())
    }

    /// Read existing project authority only. Does not mint keys or fall back to
    /// the host signer. Callers still owe current project admission on each use.
    pub(crate) fn project_signing_key(&self, project: &str) -> io::Result<SigningKey> {
        self.require_owned_project(project)?;
        self.require_signing_activation(project)?;
        self.retained_project_signing_key(project)
    }

    fn require_signing_activation(&self, project: &str) -> io::Result<()> {
        let retained = self
            .store_ref()
            .project_authority_key(project)
            .map_err(io::Error::other)?;
        if retained.is_some_and(|key| key.custody == "incoming-project-v1")
            && self
                .store_ref()
                .committed_record_snapshot(&crate::federation::handoff_scope(project), "receive")
                .map_err(|_| {
                    io::Error::other("receiving project authority admission is unavailable")
                })?
                .is_none()
        {
            return Err(io::Error::other(
                "staged project signing custody has no receiving admission",
            ));
        }
        Ok(())
    }

    /// Custody validation for receiving staging, before project standing exists.
    /// This private reader must never be used as an authorization predicate.
    fn retained_project_signing_key(&self, project: &str) -> io::Result<SigningKey> {
        let retained = self
            .store_ref()
            .project_authority_key(project)
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("project signing authority is not initialized"))?;
        let seed = match (retained.custody.as_str(), self.content_vault.as_ref()) {
            ("project-v1" | "incoming-project-v1", Some(vault)) => {
                vault.open_project_authority_seed(project, &retained.wrapped_seed)?
            }
            ("loopback-v1", None) if self.bare_signing_custody() => {
                LoopbackKeyWrap::new(self.governance_seed())
                    .unwrap(&retained.wrapped_seed)
                    .map_err(|_| io::Error::other("loopback project key custody is unavailable"))?
            }
            _ => {
                return Err(io::Error::other(
                    "project signing-key custody is unavailable",
                ))
            }
        };
        let key = SigningKey::from_seed(&seed)
            .map_err(|_| io::Error::other("project signing key is invalid"))?;
        let public_key = key.public_key();
        if public_key.as_str() != retained.public_key
            || authority(&public_key).as_str() != retained.authority_id
        {
            return Err(io::Error::other(
                "project signing key differs from its retained authority",
            ));
        }
        Ok(key)
    }

    /// Called only after authenticated receiving consent and current-basis
    /// validation. Registration precedes the product writer, but only the
    /// receiving product commit can grant standing to use this staged key.
    pub(crate) fn stage_project_authority(
        &mut self,
        project: &str,
        key: &SigningKey,
        recovery: bool,
    ) -> io::Result<()> {
        if self
            .store_ref()
            .project_authority_key(project)
            .map_err(io::Error::other)?
            .is_some()
        {
            let existing = self.retained_project_signing_key(project)?;
            if existing.public_key() != key.public_key() {
                return Err(io::Error::other(
                    "incoming project authority conflicts with retained custody",
                ));
            }
            return Ok(());
        }
        if recovery {
            return Err(io::Error::other(
                "committed project authority custody is missing",
            ));
        }
        let vault = self
            .content_vault
            .as_ref()
            .ok_or_else(|| io::Error::other("receiving project signing custody is unavailable"))?;
        let public_key = key.public_key();
        let retained = ProjectAuthorityKey {
            project_id: project.into(),
            authority_id: authority(&public_key).as_str().into(),
            public_key: public_key.as_str().into(),
            custody: "incoming-project-v1".into(),
            wrapped_seed: vault.seal_project_authority_seed(project, &key.to_seed_bytes())?,
        };
        self.store_mut()
            .retain_project_authority_key(&retained)
            .map_err(io::Error::other)?;
        self.retained_project_signing_key(project)?;
        Ok(())
    }

    /// Public identity for an existing local project. No private material is
    /// exposed, and absent registration cannot become a host authority alias.
    pub fn project_authority_identity(
        &self,
        project: &str,
    ) -> io::Result<(AuthorityId, PublicKey)> {
        self.require_owned_project(project)?;
        self.require_signing_activation(project)?;
        let retained = self
            .store_ref()
            .project_authority_key(project)
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("project signing authority is not initialized"))?;
        let public_key = PublicKey::new(retained.public_key);
        let id = authority(&public_key);
        if id.as_str() != retained.authority_id {
            return Err(io::Error::other(
                "project public authority binding is invalid",
            ));
        }
        Ok((id, public_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_vault::ContentVault;
    use gaugedesk_core::signature::verify_signature;
    use gaugedesk_store::Store;

    fn project(wb: &mut Workbench, id: &str) {
        let record = crate::library::ProjectRecord {
            id: id.into(),
            op: crate::library::RecordOp::Upsert,
            name: id.into(),
            home_id: wb.home_id().clone(),
            is_default: false,
            network_isolated: false,
            run_purpose: None,
            deployment_mode: None,
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        };
        wb.store_mut()
            .append_record(
                crate::library::LIBRARY_SCOPE,
                "project",
                &serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
        wb.library.projects.insert(id.into(), record);
    }

    fn workbench(root: &std::path::Path) -> Workbench {
        let store = Store::open(root.join("product.sqlite").to_str().unwrap()).unwrap();
        let vault = std::sync::Arc::new(ContentVault::new(
            root.join("content-keys"),
            Box::new(LoopbackKeyWrap::new([7; 32])),
        ));
        let mut wb = Workbench::new(store)
            .with_root(root)
            .with_content_vault(vault);
        project(&mut wb, "a");
        project(&mut wb, "b");
        wb
    }

    #[test]
    fn cached_project_without_current_ownership_cannot_initialize_signing_authority() {
        let root = tempfile::tempdir().unwrap();
        let mut wb = workbench(root.path());
        let mut deleted = wb.library.projects["a"].clone();
        deleted.op = crate::library::RecordOp::Tombstone;
        wb.store_mut()
            .append_record(
                crate::library::LIBRARY_SCOPE,
                "project",
                &serde_json::to_string(&deleted).unwrap(),
            )
            .unwrap();
        assert!(
            wb.library.projects.contains_key("a"),
            "stale cache still claims the project"
        );
        assert!(wb
            .initialize_project_authority("a")
            .unwrap_err()
            .to_string()
            .contains("not local"));
        assert!(wb.store_ref().project_authority_key("a").unwrap().is_none());
        assert!(!root
            .path()
            .join("content-keys/projects")
            .join(format!("{}.key", crate::org::sha256_hex("a")))
            .exists());
    }

    #[test]
    fn distinct_project_signers_are_retained_and_host_cannot_verify_them() {
        let root = tempfile::tempdir().unwrap();
        let mut wb = workbench(root.path());
        assert!(wb.project_signing_key("a").is_err());
        assert!(wb.store_ref().project_authority_key("a").unwrap().is_none());
        wb.initialize_project_authority("a").unwrap();
        wb.initialize_project_authority("b").unwrap();
        let a = wb.project_signing_key("a").unwrap();
        let b = wb.project_signing_key("b").unwrap();
        let signature = a.sign(b"project fact");
        assert!(verify_signature(b"project fact", &signature, &a.public_key()).unwrap());
        assert!(!verify_signature(b"project fact", &signature, &b.public_key()).unwrap());
        assert!(
            !verify_signature(b"project fact", &signature, &wb.governance_public_key()).unwrap()
        );
        let public = a.public_key();
        wb.initialize_project_authority("a").unwrap();
        assert_eq!(wb.project_signing_key("a").unwrap().public_key(), public);
        // Keys reopen with a fresh custody cache, rather than only in this process.
        drop(wb);
        let reopened = workbench(root.path());
        assert_eq!(
            reopened.project_signing_key("a").unwrap().public_key(),
            public
        );
    }

    #[test]
    fn same_process_missing_custody_refuses_without_reminting() {
        let root = tempfile::tempdir().unwrap();
        let mut wb = workbench(root.path());
        wb.initialize_project_authority("a").unwrap();
        let path = root
            .path()
            .join("content-keys/projects")
            .join(format!("{}.key", crate::org::sha256_hex("a")));
        std::fs::remove_file(&path).unwrap();
        assert!(wb.project_signing_key("a").is_err());
        assert!(wb.initialize_project_authority("a").is_err());
        assert!(!path.exists());
    }

    #[test]
    fn changed_public_binding_cannot_sign_with_the_old_private_seed() {
        let root = tempfile::tempdir().unwrap();
        let mut wb = workbench(root.path());
        wb.initialize_project_authority("a").unwrap();
        let different = SigningKey::from_seed(&[9; 32]).unwrap().public_key();
        let replacement_authority = authority(&different);
        let conn = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        conn.execute_batch("DROP TRIGGER project_authority_no_update")
            .unwrap();
        conn.execute(
            "UPDATE project_authority_keys SET public_key = ?1, authority_id = ?2 WHERE project_id = 'a'",
            rusqlite::params![different.as_str(), replacement_authority.as_str()],
        ).unwrap();
        assert!(wb.project_signing_key("a").is_err());
        assert!(wb.initialize_project_authority("a").is_err());
    }

    #[test]
    fn another_projects_ciphertext_cannot_be_opened_under_this_project() {
        let root = tempfile::tempdir().unwrap();
        let vault = ContentVault::new(root.path(), Box::new(LoopbackKeyWrap::new([7; 32])));
        let sealed = vault.seal_project_authority_seed("a", &[3; 32]).unwrap();
        assert!(vault.open_project_authority_seed("b", &sealed).is_err());
        assert!(vault.open_project_authority_seed("a", &sealed).unwrap() == [3; 32]);
        assert!(!root
            .path()
            .join("projects")
            .join(format!("{}.key", crate::org::sha256_hex("b")))
            .exists());
    }

    #[test]
    fn persistent_database_without_root_never_uses_loopback_custody() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(root.path().join("persistent.sqlite").to_str().unwrap()).unwrap();
        let mut wb = Workbench::new(store);
        project(&mut wb, "a");
        assert!(wb
            .initialize_project_authority("a")
            .unwrap_err()
            .to_string()
            .contains("custody is unavailable"));
        assert!(wb.store_ref().project_authority_key("a").unwrap().is_none());
        // A real scratch store may use the explicitly marked development double.
        let mut bare = Workbench::new(Store::open_in_memory().unwrap());
        project(&mut bare, "a");
        bare.initialize_project_authority("a").unwrap();
        let key = bare.project_signing_key("a").unwrap();
        assert!(verify_signature(b"fact", &key.sign(b"fact"), &key.public_key()).unwrap());
    }
}
