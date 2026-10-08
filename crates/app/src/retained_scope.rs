//! One scope's history, read strictly once and answered by kind.
//!
//! An authority fold that must refuse when any record of its scope cannot be
//! opened used to read the scope twice: once through
//! [`Store::retained_events`] to prove every record opens, and again kind by
//! kind to fold. Under the Workbench lock that decrypted the scope twice, and
//! the two reads could disagree: a record that failed to open on the second
//! read silently left the fold (WS-1010). Folding from this reads it once, and
//! the fold sees exactly the records the strict read returned.

use std::collections::HashMap;

use gaugedesk_store::{AdmitError, Store};

pub(crate) struct RetainedScope {
    by_kind: HashMap<String, Vec<String>>,
}

impl RetainedScope {
    /// Every record of `scope`, or a refusal when any of them cannot be opened.
    pub(crate) fn read(store: &Store, scope: &str) -> Result<Self, AdmitError> {
        let mut by_kind: HashMap<String, Vec<String>> = HashMap::new();
        for (_, kind, payload) in store.retained_events(scope)? {
            by_kind.entry(kind).or_default().push(payload);
        }
        Ok(Self { by_kind })
    }

    /// The records of one kind, in position order, as
    /// [`Store::records`] would answer them for a fully readable scope.
    pub(crate) fn records(&self, kind: &str) -> Vec<String> {
        self.by_kind.get(kind).cloned().unwrap_or_default()
    }
}
