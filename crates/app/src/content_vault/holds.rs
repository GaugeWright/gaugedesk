//! Session holds: a project's keys are open only while a session uses them
//! (DR-0312 phase 2, WS-740).
//!
//! A member's admitted request on a project holds that project for as long as
//! the request and its response body last, so an open event stream holds it
//! while it is connected. A request that used the project leaves the hold
//! lingering for [`LINGER_MS`], the gap between one click and the next. When
//! nothing holds a project any more, the vault drops the project's key and
//! every scope key under it from memory, and opens none of them again until a
//! session or an unattended step's delegation asks.
//!
//! Background work does not take a hold: an unattended step runs inside
//! [`super::act_for`], which already admits exactly the scopes it declared,
//! and the keys it opened are dropped when it ends unless a session holds the
//! project.
//!
//! Until account keys replace the install's custody (WS-674), a refusal here
//! governs which keys the host opens, not which it could open.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// How long a project stays held after the last request that used it.
pub const LINGER_MS: u64 = 15 * 60 * 1000;

#[derive(Default)]
pub(crate) struct Holds {
    projects: Mutex<HashMap<String, ProjectHold>>,
    /// Whether the gate refuses a project scope nothing holds. Off for a vault
    /// that serves no sessions at all — a tool, a migration, a unit test that
    /// drives the store directly — and on for every composition that serves.
    enforced: AtomicBool,
}

#[derive(Default, Debug)]
struct ProjectHold {
    guards: usize,
    linger_until_ms: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

/// While alive, the host may open its project's keys. Dropped at the end of
/// the request or stream that took it.
#[must_use = "a hold covers its project only while it is alive"]
pub struct SessionHold {
    vault: Arc<ContentVault>,
    project: String,
    linger: AtomicBool,
}

impl SessionHold {
    /// The session used the project: keep it held for [`LINGER_MS`] after
    /// this hold ends.
    pub fn linger(&self) {
        self.linger.store(true, Ordering::Relaxed);
    }

    pub fn project(&self) -> &str {
        &self.project
    }
}

impl std::fmt::Debug for SessionHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHold")
            .field("project", &self.project)
            .finish()
    }
}

impl Drop for SessionHold {
    fn drop(&mut self) {
        let now = now_ms();
        let released = {
            let mut projects = self
                .vault
                .holds
                .projects
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(hold) = projects.get_mut(&self.project) else {
                return;
            };
            hold.guards = hold.guards.saturating_sub(1);
            if self.linger.load(Ordering::Relaxed) {
                hold.linger_until_ms = hold.linger_until_ms.max(now.saturating_add(LINGER_MS));
            }
            let released = hold.guards == 0 && hold.linger_until_ms <= now;
            if released {
                projects.remove(&self.project);
            }
            released
        };
        if released {
            self.vault.evict_project(&self.project);
        }
    }
}

impl ContentVault {
    /// Refuse project scopes that no session holds and no unattended step
    /// declared. Every composition that serves sessions turns this on.
    pub fn enforce_session_holds(&self) {
        self.holds.enforced.store(true, Ordering::Relaxed);
    }

    pub(super) fn session_holds_enforced(&self) -> bool {
        self.holds.enforced.load(Ordering::Relaxed)
    }

    /// Hold `project` for a session until the returned hold is dropped.
    pub fn hold(self: &Arc<Self>, project: &str) -> SessionHold {
        self.holds
            .projects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(project.to_owned())
            .or_default()
            .guards += 1;
        SessionHold {
            vault: self.clone(),
            project: project.to_owned(),
            linger: AtomicBool::new(false),
        }
    }

    /// Whether a session holds `project` at `now`.
    pub(super) fn held(&self, project: &str, now: u64) -> bool {
        self.holds
            .projects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(project)
            .is_some_and(|hold| hold.guards > 0 || hold.linger_until_ms > now)
    }

    /// The projects a session holds now.
    pub fn held_projects(&self) -> BTreeSet<String> {
        let now = now_ms();
        self.holds
            .projects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|(_, hold)| hold.guards > 0 || hold.linger_until_ms > now)
            .map(|(project, _)| project.clone())
            .collect()
    }

    /// The projects with a scope key in memory now.
    pub fn opened_projects(&self) -> BTreeSet<String> {
        self.key_state
            .lock()
            .unwrap()
            .cache
            .keys()
            .filter_map(|scope| self.scope_projects.project_of(scope))
            .collect()
    }

    /// How many project keys are in memory now.
    pub fn open_project_keys(&self) -> usize {
        self.project_keys.len()
    }

    /// How many live holds `project` has, not counting a linger.
    #[cfg(test)]
    pub(crate) fn live_sessions(&self, project: &str) -> usize {
        self.holds
            .projects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(project)
            .map_or(0, |hold| hold.guards)
    }

    /// Drop the keys of every project whose last hold has lingered out.
    /// Returns how many projects it released.
    pub fn release_idle(&self, now: u64) -> usize {
        let released: Vec<String> = {
            let mut projects = self
                .holds
                .projects
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let expired: Vec<String> = projects
                .iter()
                .filter(|(_, hold)| hold.guards == 0 && hold.linger_until_ms <= now)
                .map(|(project, _)| project.clone())
                .collect();
            for project in &expired {
                projects.remove(project);
            }
            expired
        };
        for project in &released {
            self.evict_project(project);
        }
        released.len()
    }

    /// Drop `project`'s keys unless a session holds it. An unattended step
    /// calls this when it ends.
    pub fn release_unless_held(&self, project: &str) {
        if !self.held(project, now_ms()) {
            self.evict_project(project);
        }
    }

    /// Drop the keys of every project no session holds: after maintenance
    /// that opened keys with nobody present, such as the startup re-wrap.
    pub fn release_unheld(&self) {
        let projects: BTreeSet<String> = {
            let state = self.key_state.lock().unwrap();
            state
                .cache
                .keys()
                .filter_map(|scope| self.scope_projects.project_of(scope))
                .collect()
        };
        let now = now_ms();
        for project in projects {
            if !self.held(&project, now) {
                self.evict_project(&project);
            }
        }
        // A project key opened for maintenance has no scope in the cache to
        // name it; with nothing held, none of them should stay.
        if self.held_projects().is_empty() {
            self.project_keys.clear();
        }
    }

    /// Forget `project`'s key and every scope key under it.
    fn evict_project(&self, project: &str) {
        self.key_state
            .lock()
            .unwrap()
            .cache
            .retain(|scope, _| self.scope_projects.project_of(scope).as_deref() != Some(project));
        self.project_keys.forget(project);
    }

    /// Whether the session gate admits `scope` at `now` outside an unattended
    /// step: a scope of no project always, a project scope while a session
    /// holds its project.
    pub(super) fn session_admits(&self, scope: &str, now: u64) -> std::io::Result<()> {
        if !self.session_holds_enforced() {
            return Ok(());
        }
        let Some(project) = self.scope_projects.project_of(scope) else {
            return Ok(());
        };
        if self.held(&project, now) {
            return Ok(());
        }
        // Every path that serves a member holds what it reads, so a refusal
        // here is a path missing its hold — and it reads as missing content,
        // because the store omits what it cannot open.
        tracing::warn!(%project, "content vault: refused a project scope no session holds");
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no current work holds this project's keys",
        ))
    }
}

/// A response body that keeps `holds` alive until it has been sent or
/// dropped, so a stream holds its project while it is connected.
pub fn held_body(inner: axum::body::Body, holds: Vec<SessionHold>) -> axum::body::Body {
    use futures::StreamExt;
    axum::body::Body::from_stream(inner.into_data_stream().map(move |chunk| {
        let _held = &holds;
        chunk
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::at_rest::LoopbackKeyWrap;
    use gaugedesk_store::ContentCodec;

    fn vault(dir: &Path) -> Arc<ContentVault> {
        let vault = ContentVault::new(dir, Box::new(LoopbackKeyWrap::new([5u8; 32])));
        let index = vault.scope_index();
        index.record_instance("place-a", Some("proj-a"));
        index.record_chat("chat-a", "place-a");
        index.record_instance("place-b", Some("proj-b"));
        index.record_chat("chat-b", "place-b");
        vault.enforce_session_holds();
        Arc::new(vault)
    }

    fn sealed(v: &Arc<ContentVault>, scope: &str, text: &str) -> String {
        let project = v.scope_projects.project_of(scope).unwrap();
        let _hold = v.hold(&project);
        v.encode(scope, "transcript", text).unwrap()
    }

    #[test]
    fn a_project_opens_only_while_a_session_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let a = sealed(&v, "chat-a", "alpha");
        let b = sealed(&v, "chat-b", "beta");
        let account = v.encode("account", "credential", "not a project").unwrap();

        assert_eq!(
            v.decode("chat-a", "transcript", &a),
            None,
            "nothing holds proj-a"
        );
        assert!(v.encode("chat-a", "transcript", "a write").is_err());
        assert_eq!(
            v.decode("account", "credential", &account).as_deref(),
            Some("not a project"),
            "a scope of no project is not a project key"
        );

        let hold = v.hold("proj-a");
        assert_eq!(
            v.decode("chat-a", "transcript", &a).as_deref(),
            Some("alpha")
        );
        assert_eq!(
            v.decode("chat-b", "transcript", &b),
            None,
            "one project's hold is not another's"
        );
        drop(hold);
        assert_eq!(
            v.decode("chat-a", "transcript", &a),
            None,
            "dropped when it ends"
        );
    }

    #[test]
    fn a_used_project_lingers_and_then_its_keys_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let a = sealed(&v, "chat-a", "alpha");
        let hold = v.hold("proj-a");
        hold.linger();
        assert!(v.decode("chat-a", "transcript", &a).is_some());
        drop(hold);
        assert!(v.decode("chat-a", "transcript", &a).is_some(), "it lingers");
        assert!(v.key_state.lock().unwrap().cache.contains_key("chat-a"));

        assert_eq!(v.release_idle(now_ms()), 0, "still within the linger");
        assert_eq!(v.release_idle(now_ms() + LINGER_MS + 1), 1);
        assert!(
            !v.key_state.lock().unwrap().cache.contains_key("chat-a"),
            "its scope key is gone from memory"
        );
        assert!(v.project_keys.is_empty(), "and its project key");
        assert!(v.held_projects().is_empty());
    }

    #[test]
    fn an_unattended_step_opens_only_its_declaration_and_nothing_lingers_after() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let a = sealed(&v, "chat-a", "alpha");
        let declared: BTreeSet<String> = std::iter::once("chat-a".to_owned()).collect();
        let (read, refused) =
            super::super::act_for("proj-a", &declared, || v.decode("chat-a", "transcript", &a));
        assert_eq!(
            read.as_deref(),
            Some("alpha"),
            "its delegation covers it without a session"
        );
        assert!(refused.is_empty());
        v.release_unless_held("proj-a");
        assert!(!v.key_state.lock().unwrap().cache.contains_key("chat-a"));
    }

    #[test]
    fn a_vault_that_serves_no_sessions_does_not_gate() {
        let dir = tempfile::tempdir().unwrap();
        let v = ContentVault::new(dir.path(), Box::new(LoopbackKeyWrap::new([5u8; 32])));
        v.scope_index().record_instance("place-a", Some("proj-a"));
        v.scope_index().record_chat("chat-a", "place-a");
        let a = v.encode("chat-a", "transcript", "alpha").unwrap();
        assert_eq!(
            v.decode("chat-a", "transcript", &a).as_deref(),
            Some("alpha")
        );
    }

    #[test]
    fn startup_maintenance_leaves_no_project_key_open() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        sealed(&v, "chat-a", "alpha");
        // Held and released: the hold lingered nothing, so nothing is open.
        assert!(v.project_keys.is_empty());
        v.project_key(&crate::org::sha256_hex("proj-b"), true)
            .unwrap();
        assert!(!v.project_keys.is_empty());
        v.release_unheld();
        assert!(v.project_keys.is_empty());
    }
}
