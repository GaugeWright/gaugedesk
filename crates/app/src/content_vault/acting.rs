//! The background work a host is acting for, and the keys it was delegated
//! (DR-0312, WS-672).
//!
//! An unattended step runs inside [`act_for`]. While it does, the vault opens a
//! scope that belongs to a project only when the step's delegation names it.
//! Another project's scope, or a part of its own project the work did not
//! declare, is refused, and the refusal is kept so the run can report what it
//! could not reach. A scope that belongs to no project — an account's, an
//! organization's — is not a project key and stays with the install's custody
//! until account keys replace it (WS-674).
//!
//! Outside `act_for` nothing here applies: an attended request is a member's
//! own session. The context is per thread because a step runs on one thread
//! while it holds the workbench, and a request served beside it on another
//! thread must never inherit it.

use super::*;
use std::cell::RefCell;
use std::rc::Rc;

struct Acting {
    project: String,
    scopes: BTreeSet<String>,
    refused: RefCell<BTreeSet<String>>,
}

thread_local! {
    static ACTING: RefCell<Option<Rc<Acting>>> = const { RefCell::new(None) };
}

/// Run `work` as background work delegated `scopes` of `project`. Returns what
/// it returned and every scope the vault refused it, which is empty when the
/// work kept to its declaration.
pub fn act_for<T>(
    project: &str,
    scopes: &BTreeSet<String>,
    work: impl FnOnce() -> T,
) -> (T, BTreeSet<String>) {
    struct Restore(Option<Rc<Acting>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            ACTING.with(|slot| *slot.borrow_mut() = previous);
        }
    }
    let acting = Rc::new(Acting {
        project: project.to_owned(),
        scopes: scopes.clone(),
        refused: RefCell::default(),
    });
    let _restore = Restore(ACTING.with(|slot| slot.replace(Some(acting.clone()))));
    let result = work();
    let refused = acting.refused.borrow().clone();
    (result, refused)
}

impl ContentVault {
    /// Refuse `scope` to background work whose delegation does not name it,
    /// and, outside background work, to a session that does not hold its
    /// project (WS-740). Every path that hands out a scope's data key asks
    /// this first.
    pub(super) fn delegated(&self, scope: &str) -> std::io::Result<()> {
        ACTING.with(|slot| {
            let slot = slot.borrow();
            let Some(acting) = slot.as_ref() else {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_millis() as u64)
                    .unwrap_or_default();
                return self.session_admits(scope, now);
            };
            let Some(project) = self.scope_projects.project_of(scope) else {
                return Ok(());
            };
            if project == acting.project && acting.scopes.contains(scope) {
                return Ok(());
            }
            acting.refused.borrow_mut().insert(scope.to_owned());
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "outside the keys this work was delegated",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::at_rest::LoopbackKeyWrap;
    use gaugedesk_store::ContentCodec;

    fn vault(dir: &Path) -> ContentVault {
        let vault = ContentVault::new(dir, Box::new(LoopbackKeyWrap::new([7u8; 32])));
        let index = vault.scope_index();
        index.record_instance("place-a", Some("proj-a"));
        index.record_chat("chat-a", "place-a");
        index.record_chat("chat-a2", "place-a");
        index.record_instance("place-b", Some("proj-b"));
        index.record_chat("chat-b", "place-b");
        vault
    }

    fn declared(scopes: &[&str]) -> BTreeSet<String> {
        scopes.iter().map(|scope| scope.to_string()).collect()
    }

    #[test]
    fn background_work_opens_only_what_its_delegation_names() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let own = v.encode("chat-a", "transcript", "declared").unwrap();
        let sibling = v.encode("chat-a2", "transcript", "same project").unwrap();
        let other = v.encode("chat-b", "transcript", "other project").unwrap();
        let account = v
            .encode("account", "credential", "not a project key")
            .unwrap();
        // A fresh vault holds nothing in memory, so every read below unwraps.
        let v = vault(dir.path());

        let (read, refused) = act_for("proj-a", &declared(&["chat-a"]), || {
            (
                v.decode("chat-a", "transcript", &own),
                v.decode("chat-a2", "transcript", &sibling),
                v.decode("chat-b", "transcript", &other),
                v.decode("account", "credential", &account),
                v.encode("chat-b", "transcript", "a write elsewhere"),
            )
        });
        assert_eq!(read.0.as_deref(), Some("declared"));
        assert_eq!(
            read.1, None,
            "an undeclared part of its own project is refused"
        );
        assert_eq!(read.2, None, "another project is refused");
        assert_eq!(read.3.as_deref(), Some("not a project key"));
        assert!(
            read.4.is_err(),
            "writing outside the declaration is refused"
        );
        assert_eq!(refused, declared(&["chat-a2", "chat-b"]));

        // Attended work outside the context is unaffected, and the refusal
        // did not linger on the thread.
        assert_eq!(
            v.decode("chat-b", "transcript", &other).as_deref(),
            Some("other project")
        );
    }

    #[test]
    fn a_key_already_in_memory_is_still_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let other = v.encode("chat-b", "transcript", "cached").unwrap();
        assert!(v.decode("chat-b", "transcript", &other).is_some());
        let (read, refused) = act_for("proj-a", &declared(&["chat-a"]), || {
            v.decode("chat-b", "transcript", &other)
        });
        assert_eq!(read, None);
        assert_eq!(refused, declared(&["chat-b"]));
    }

    #[test]
    fn a_prepared_key_outside_the_declaration_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path()).with_ledger(Box::new(LocalFileErasureLedger::new(
            dir.path().join("erased.ledger"),
        )));
        v.initialize_scope_key("project::proj-b::workflow").unwrap();
        let (prepared, refused) =
            act_for("proj-a", &declared(&["project::proj-a::workflow"]), || {
                v.prepare_scope_key("project::proj-b::workflow").map(|_| ())
            });
        assert_eq!(
            prepared.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(refused, declared(&["project::proj-b::workflow"]));
    }

    #[test]
    fn the_context_ends_with_its_work_even_when_the_work_panics() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let other = v.encode("chat-b", "transcript", "after").unwrap();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            act_for("proj-a", &declared(&[]), || panic!("the step failed"))
        }));
        assert!(panicked.is_err());
        assert_eq!(
            v.decode("chat-b", "transcript", &other).as_deref(),
            Some("after")
        );
    }
}
