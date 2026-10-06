//! A key per project, wrapping its parts' keys (DR-0312, WS-586).
//!
//! Every scope's data key used to be wrapped by the one install-wide content
//! key. A scope that belongs to a project — a chat, `project::<id>`, the
//! project's workflow storage — now has its data key wrapped by that project's
//! own key instead, and the project's key is what custody acts on. A scope that
//! belongs to no project (an account, an organization, an Agent's edit chat)
//! keeps the install wrap until account keys replace it (WS-674).
//!
//! This phase adds structure, not yet protection: a project's key is itself
//! wrapped by the install-wide key, in [`ContentVault::seal_project_key`]. That
//! one function is the custody seam. Delegations derived from current work
//! (WS-672) and members' account keys (WS-674) replace what it wraps with,
//! without touching the per-scope layer beneath it.
//!
//! A wrapped data key records which key wrapped it. A file written before this
//! phase carries no header and reads as install custody; at startup each such
//! file whose scope belongs to a project is re-wrapped under that project's
//! key ([`ContentVault::adopt_project_custody`]). The data key itself never
//! changes, so nothing sealed under it is rewritten.

use super::*;
use crate::at_rest::LoopbackKeyWrap;
use std::sync::RwLock;

/// Marks a data key wrapped with an explicit custody header.
const DEK_V2: &[u8] = b"gaugedesk.dek.v2\n";
const INSTALL: u8 = 0;
const PROJECT: u8 = 1;
/// A project key id is the hex SHA-256 of the project id.
const PROJECT_KEY_ID_LEN: usize = 64;

/// Which key wraps a scope's data key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DekCustody {
    Install,
    Project(String),
}

pub(crate) fn encode_dek(custody: &DekCustody, wrapped: &[u8]) -> Vec<u8> {
    let mut out = DEK_V2.to_vec();
    match custody {
        DekCustody::Install => out.push(INSTALL),
        DekCustody::Project(key_id) => {
            out.push(PROJECT);
            out.extend_from_slice(key_id.as_bytes());
        }
    }
    out.extend_from_slice(wrapped);
    out
}

pub(crate) fn decode_dek(bytes: &[u8]) -> std::io::Result<(DekCustody, &[u8])> {
    let Some(rest) = bytes.strip_prefix(DEK_V2) else {
        // Written before custody headers existed: the install wrap.
        return Ok((DekCustody::Install, bytes));
    };
    let malformed = || std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed data key");
    match rest.split_first() {
        Some((&INSTALL, wrapped)) => Ok((DekCustody::Install, wrapped)),
        Some((&PROJECT, rest)) if rest.len() > PROJECT_KEY_ID_LEN => {
            let (id, wrapped) = rest.split_at(PROJECT_KEY_ID_LEN);
            let id = std::str::from_utf8(id).map_err(|_| malformed())?;
            if !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(malformed());
            }
            Ok((DekCustody::Project(id.to_owned()), wrapped))
        }
        _ => Err(malformed()),
    }
}

/// The project each scope belongs to, kept current by the library as it
/// applies chat and instance records. The vault cannot ask the workbench while
/// a store write holds the workbench, so the library writes through to this.
#[derive(Default)]
pub struct ScopeProjectIndex {
    maps: RwLock<IndexMaps>,
}

#[derive(Default)]
struct IndexMaps {
    chat_instance: HashMap<String, String>,
    instance_project: HashMap<String, String>,
}

impl ScopeProjectIndex {
    /// A chat's placement. A tombstone keeps the mapping: the chat's content
    /// stays under its project's key until its own key is erased.
    pub fn record_chat(&self, chat: &str, instance: &str) {
        if let Ok(mut maps) = self.maps.write() {
            maps.chat_instance
                .insert(chat.to_owned(), instance.to_owned());
        }
    }

    /// A placement's project, or none for an Agent's authoring root.
    pub fn record_instance(&self, instance: &str, project: Option<&str>) {
        if let Ok(mut maps) = self.maps.write() {
            match project {
                Some(project) => {
                    maps.instance_project
                        .insert(instance.to_owned(), project.to_owned());
                }
                None => {
                    maps.instance_project.remove(instance);
                }
            }
        }
    }

    /// Replace everything with what `library` says, after it is rebuilt.
    pub fn replace_from(&self, library: &crate::library::Library) {
        if let Ok(mut maps) = self.maps.write() {
            maps.chat_instance = library
                .chats
                .values()
                .map(|chat| (chat.id.clone(), chat.instance_id.clone()))
                .collect();
            maps.instance_project = library
                .instances
                .values()
                .filter_map(|instance| {
                    instance
                        .project_id
                        .clone()
                        .map(|project| (instance.id.clone(), project))
                })
                .collect();
        }
    }

    /// The project `scope` belongs to: `project::<id>` and everything under it,
    /// or a chat through its placement. `None` for any other scope.
    pub fn project_of(&self, scope: &str) -> Option<String> {
        if let Some(rest) = scope.strip_prefix("project::") {
            let id = rest.split("::").next().unwrap_or_default();
            return (!id.is_empty()).then(|| id.to_owned());
        }
        let maps = self.maps.read().ok()?;
        let instance = maps.chat_instance.get(scope)?;
        maps.instance_project.get(instance).cloned()
    }
}

/// Unwrapped project keys, by key id, while a session or step holds their
/// project (WS-740).
#[derive(Default)]
pub(crate) struct ProjectKeyCache {
    keys: Mutex<HashMap<String, [u8; 32]>>,
}

impl ProjectKeyCache {
    /// Forget `project`'s key.
    pub(crate) fn forget(&self, project: &str) {
        self.keys.lock().unwrap().remove(&project_key_id(project));
    }

    pub(crate) fn clear(&self) {
        self.keys.lock().unwrap().clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.keys.lock().unwrap().len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.keys.lock().unwrap().is_empty()
    }
}

fn project_key_id(project: &str) -> String {
    crate::org::sha256_hex(project)
}

impl ContentVault {
    /// Explicit authority-key creation uses the project's existing custody
    /// seam, never the install wrapper directly. No raw seed is persisted.
    pub(crate) fn seal_project_authority_seed(
        &self,
        project: &str,
        seed: &[u8; 32],
    ) -> std::io::Result<Vec<u8>> {
        self.wrap_dek_for_project(project, seed)
    }

    /// Reopen exact custody without cache-based availability or initialization.
    /// The expected project comes from the owner, not a ciphertext header.
    pub(crate) fn open_project_authority_seed(
        &self,
        project: &str,
        sealed: &[u8],
    ) -> std::io::Result<[u8; 32]> {
        let (custody, wrapped) = decode_dek(sealed)?;
        let id = project_key_id(project);
        if custody != DekCustody::Project(id.clone()) {
            return Err(std::io::Error::other(
                "authority key has different project custody",
            ));
        }
        // Ordinary content may cache a key; signing must also prove its
        // retained custody still exists, including within that same process.
        let retained = std::fs::read(self.project_keys_dir().join(format!("{id}.key")))?;
        let key = self.open_project_key(&retained)?;
        LoopbackKeyWrap::new(key)
            .unwrap(wrapped)
            .map_err(custody_error)
    }

    /// The project each scope belongs to, for the library to keep current.
    pub fn scope_index(&self) -> Arc<ScopeProjectIndex> {
        self.scope_projects.clone()
    }

    fn project_keys_dir(&self) -> PathBuf {
        self.dir.join("projects")
    }

    /// The custody seam: what a project's key is wrapped with at rest. Today
    /// the install-wide key; delegations (WS-672) and members' account keys
    /// (WS-674) replace this, and nothing beneath it changes.
    fn seal_project_key(&self, key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
        self.wrap.wrap(key).map_err(custody_error)
    }

    fn open_project_key(&self, sealed: &[u8]) -> std::io::Result<[u8; 32]> {
        self.wrap.unwrap(sealed).map_err(custody_error)
    }

    /// A project's key, minted on first use when `create` is set. Never
    /// replaces one that exists.
    pub(crate) fn project_key(&self, key_id: &str, create: bool) -> std::io::Result<[u8; 32]> {
        if let Some(key) = self.project_keys.keys.lock().unwrap().get(key_id) {
            return Ok(*key);
        }
        let dir = self.project_keys_dir();
        let path = dir.join(format!("{key_id}.key"));
        let key = match std::fs::read(&path) {
            Ok(sealed) => self.open_project_key(&sealed)?,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                let mut key = [0; 32];
                SystemRandom::new()
                    .fill(&mut key)
                    .map_err(|_| std::io::Error::other("project key generation failed"))?;
                std::fs::create_dir_all(&dir)?;
                let root = std::fs::canonicalize(&dir)?;
                match persist_new(
                    &root,
                    &root.join(format!("{key_id}.key")),
                    &self.seal_project_key(&key)?,
                ) {
                    Ok(()) => key,
                    // Another writer minted it first: theirs is the project's key.
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        self.open_project_key(&std::fs::read(&path)?)?
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        self.project_keys
            .keys
            .lock()
            .unwrap()
            .insert(key_id.to_owned(), key);
        Ok(key)
    }

    /// Wrap `dek` for `scope`: under its project's key when it has one.
    pub(crate) fn wrap_dek(&self, scope: &str, dek: &[u8; 32]) -> std::io::Result<Vec<u8>> {
        match self.scope_projects.project_of(scope) {
            Some(project) => self.wrap_dek_for_project(&project, dek),
            None => Ok(encode_dek(
                &DekCustody::Install,
                &self.wrap.wrap(dek).map_err(custody_error)?,
            )),
        }
    }

    fn wrap_dek_for_project(&self, project: &str, dek: &[u8; 32]) -> std::io::Result<Vec<u8>> {
        let key_id = project_key_id(project);
        let key = self.project_key(&key_id, true)?;
        let wrapped = LoopbackKeyWrap::new(key).wrap(dek).map_err(custody_error)?;
        Ok(encode_dek(&DekCustody::Project(key_id), &wrapped))
    }

    /// Unwrap a stored data key with whichever key its header names.
    pub(crate) fn unwrap_dek(&self, stored: &[u8]) -> std::io::Result<[u8; 32]> {
        let (custody, wrapped) = decode_dek(stored)?;
        match custody {
            DekCustody::Install => self.wrap.unwrap(wrapped).map_err(custody_error),
            DekCustody::Project(key_id) => LoopbackKeyWrap::new(self.project_key(&key_id, false)?)
                .unwrap(wrapped)
                .map_err(custody_error),
        }
    }

    /// Re-wrap `scope`'s data key under its project's key if it is still under
    /// the install wrap. The data key does not change. Returns whether it moved.
    /// Runs at startup, before anything retains the scope.
    pub fn adopt_project_custody(&self, scope: &str) -> std::io::Result<bool> {
        let Some(project) = self.scope_projects.project_of(scope) else {
            return Ok(false);
        };
        let Ok(root) = std::fs::canonicalize(&self.dir) else {
            return Ok(false);
        };
        let key_id = crate::org::sha256_hex(scope);
        let path = key_path(&root, &key_id);
        // Every start sweeps every scope, and nearly all have moved already:
        // look before taking the scope's exclusive lock, then look again under it.
        match std::fs::read(&path) {
            Ok(stored) if decode_dek(&stored)?.0 == DekCustody::Install => {}
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
        let _exclusive = exclusive(&root, &key_id)?;
        available(&root, &key_id)?;
        let stored = match std::fs::read(&path) {
            Ok(stored) => stored,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if decode_dek(&stored)?.0 != DekCustody::Install {
            return Ok(false);
        }
        let dek = self.unwrap_dek(&stored)?;
        let rewrapped = self.wrap_dek_for_project(&project, &dek)?;
        replace_durably(&root, &path, &rewrapped)?;
        Ok(true)
    }
}

/// Replace `path` with `bytes` atomically and durably.
fn replace_durably(root: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut staged = tempfile::NamedTempFile::new_in(root)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged.persist(path).map_err(|error| error.error)?;
    sync_directory(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_store::ContentCodec;

    fn vault(dir: &Path) -> ContentVault {
        ContentVault::new(dir, Box::new(LoopbackKeyWrap::new([7u8; 32])))
    }

    fn dek_file(dir: &Path, scope: &str) -> PathBuf {
        dir.join(format!("{}.dek", crate::org::sha256_hex(scope)))
    }

    fn custody_of(dir: &Path, scope: &str) -> DekCustody {
        decode_dek(&std::fs::read(dek_file(dir, scope)).unwrap())
            .unwrap()
            .0
    }

    fn place(vault: &ContentVault, chat: &str, instance: &str, project: Option<&str>) {
        let index = vault.scope_index();
        index.record_instance(instance, project);
        index.record_chat(chat, instance);
    }

    #[test]
    fn each_project_keys_its_own_chats_under_its_own_key() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        place(&v, "chat-a", "place-a", Some("proj-a"));
        place(&v, "chat-b", "place-b", Some("proj-b"));
        let sealed = v.encode("chat-a", "transcript", "alpha").unwrap();
        v.encode("chat-b", "transcript", "beta").unwrap();
        v.encode("project::proj-a", "credential", "a provider key")
            .unwrap();

        assert_eq!(
            custody_of(dir.path(), "chat-a"),
            DekCustody::Project(project_key_id("proj-a"))
        );
        assert_eq!(
            custody_of(dir.path(), "chat-b"),
            DekCustody::Project(project_key_id("proj-b"))
        );
        assert_eq!(
            custody_of(dir.path(), "project::proj-a"),
            DekCustody::Project(project_key_id("proj-a"))
        );
        let key = |project: &str| {
            std::fs::read(
                dir.path()
                    .join("projects")
                    .join(format!("{}.key", project_key_id(project))),
            )
            .unwrap()
        };
        assert_ne!(key("proj-a"), key("proj-b"), "two projects, two keys");

        // A fresh vault holding nothing in memory opens it through the project key.
        let reopened = vault(dir.path());
        assert_eq!(
            reopened.decode("chat-a", "transcript", &sealed).as_deref(),
            Some("alpha")
        );
    }

    #[test]
    fn a_scope_outside_any_project_keeps_the_install_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        place(&v, "edit-chat", "authoring-root", None);
        v.encode("account", "credential", "a token").unwrap();
        v.encode("edit-chat", "transcript", "agent work").unwrap();
        assert_eq!(custody_of(dir.path(), "account"), DekCustody::Install);
        assert_eq!(custody_of(dir.path(), "edit-chat"), DekCustody::Install);
        assert!(!dir.path().join("projects").exists());
    }

    #[test]
    fn a_key_written_before_project_keys_moves_under_its_project_with_its_content_intact() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        // Sealed before the chat was known to belong anywhere, then stored in
        // the headerless format every key had before this phase.
        let sealed = v
            .encode("chat-a", "transcript", "written long ago")
            .unwrap();
        let path = dek_file(dir.path(), "chat-a");
        let stored = std::fs::read(&path).unwrap();
        let (_, raw) = decode_dek(&stored).unwrap();
        std::fs::write(&path, raw).unwrap();
        assert_eq!(custody_of(dir.path(), "chat-a"), DekCustody::Install);

        let v = vault(dir.path());
        place(&v, "chat-a", "place-a", Some("proj-a"));
        assert!(v.adopt_project_custody("chat-a").unwrap());
        assert_eq!(
            custody_of(dir.path(), "chat-a"),
            DekCustody::Project(project_key_id("proj-a"))
        );
        assert!(
            !v.adopt_project_custody("chat-a").unwrap(),
            "adopting again moves nothing"
        );
        assert_eq!(
            vault(dir.path())
                .decode("chat-a", "transcript", &sealed)
                .as_deref(),
            Some("written long ago"),
            "the data key did not change, so old content still opens"
        );
    }

    #[test]
    fn erasing_a_project_chat_still_destroys_its_content() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path()).with_ledger(Box::new(super::super::LocalFileErasureLedger::new(
            dir.path().join("erased.ledger"),
        )));
        place(&v, "chat-a", "place-a", Some("proj-a"));
        let sealed = v.encode("chat-a", "transcript", "to forget").unwrap();
        assert!(v.erase_scope_key("chat-a").unwrap());
        assert_eq!(v.decode("chat-a", "transcript", &sealed), None);
        assert_eq!(
            vault(dir.path()).decode("chat-a", "transcript", &sealed),
            None
        );
    }

    #[test]
    fn a_malformed_custody_header_is_refused() {
        let mut bad = DEK_V2.to_vec();
        bad.push(PROJECT);
        bad.extend_from_slice(b"not-hex");
        assert!(decode_dek(&bad).is_err());
        let mut unknown = DEK_V2.to_vec();
        unknown.push(9);
        assert!(decode_dek(&unknown).is_err());
        let mut nonhex = DEK_V2.to_vec();
        nonhex.push(PROJECT);
        nonhex.extend_from_slice(&[b'z'; PROJECT_KEY_ID_LEN]);
        nonhex.extend_from_slice(b"wrapped");
        assert!(decode_dek(&nonhex).is_err());
    }

    #[test]
    fn a_workbench_keys_a_projects_chat_under_it_and_adopts_older_keys_on_start() {
        use crate::LockUnpoisoned;
        let root = tempfile::tempdir().unwrap();
        let keys = root.path().join("content-keys");
        let (chat, project) = {
            let wb = crate::open_workbench(root.path()).unwrap();
            let mut guard = wb.lock_unpoisoned();
            let created = guard
                .create_default_engagement("chat-x".into(), "a chat".into())
                .unwrap_or_else(|_| panic!("the default chat is created"));
            let project = guard
                .library
                .project_of_chat(&created.id)
                .expect("a default chat lives in a project")
                .to_owned();
            guard.hold_session_for_tests(&project);
            guard
                .store_mut()
                .append_record(&created.id, "transcript", r#"{"said":"hello"}"#)
                .unwrap();
            (created.id, project)
        };
        assert_eq!(
            custody_of(&keys, &chat),
            DekCustody::Project(project_key_id(&project)),
            "a new chat's key is wrapped under its project's key"
        );

        // Put the chat's key back under the install wrap, headerless, as every
        // key was before this phase.
        let path = dek_file(&keys, &chat);
        let dek = vault_over(root.path())
            .unwrap_dek(&std::fs::read(&path).unwrap())
            .unwrap();
        let install = crate::at_rest::local_content_keywrap(root.path()).unwrap();
        std::fs::write(&path, install.wrap(&dek).unwrap()).unwrap();
        assert_eq!(custody_of(&keys, &chat), DekCustody::Install);

        let wb = crate::open_workbench(root.path()).unwrap();
        assert_eq!(
            custody_of(&keys, &chat),
            DekCustody::Project(project_key_id(&project)),
            "starting the workbench moves it under its project's key"
        );
        let mut guard = wb.lock_unpoisoned();
        let vault = guard.content_vault.clone().unwrap();
        assert_eq!(
            vault.open_project_keys(),
            0,
            "the start-up re-wrap leaves no project key open (WS-740)"
        );
        assert!(vault.opened_projects().is_empty());
        guard.hold_session_for_tests(&project);
        let transcript = guard.store_ref().records(&chat, "transcript").unwrap();
        assert_eq!(transcript, vec![r#"{"said":"hello"}"#.to_owned()]);
    }

    /// A vault over a workbench root's own keyring and install key.
    fn vault_over(root: &Path) -> ContentVault {
        ContentVault::new(
            root.join("content-keys"),
            crate::at_rest::local_content_keywrap(root).unwrap(),
        )
    }
}
