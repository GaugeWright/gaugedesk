//! DR-0334 end to end on the desktop side: several desktops of one account
//! against one authority that runs [`crate::account_links`]' own rules.
use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::account_links::{self, LinkSet};

const PERSON: &str = "acct-person";

/// The account authority in memory. Each handle is one device's session.
#[derive(Clone)]
struct Authority {
    set: Rc<RefCell<LinkSet>>,
    device: String,
}

impl Authority {
    fn shared() -> Rc<RefCell<LinkSet>> {
        Rc::new(RefCell::new(LinkSet::default()))
    }

    /// A trusted device of the account, as the Hub sees its bound session.
    fn device(set: &Rc<RefCell<LinkSet>>, id: &str) -> Self {
        set.borrow_mut().active_devices.insert(id.to_owned());
        Self {
            set: set.clone(),
            device: id.to_owned(),
        }
    }

    fn revoke_device(&self, id: &str) {
        let mut set = self.set.borrow_mut();
        set.active_devices.remove(id);
        let (facts, _) = account_links::forget_device(&set, id);
        set.apply(facts);
    }
}

fn refused(refusal: account_links::LinkRefusal) -> String {
    format!("{refusal:?}")
}

impl LinkAuthority for Authority {
    fn register(&self, public_key: &str) -> Result<String, String> {
        let mut set = self.set.borrow_mut();
        let facts = account_links::register_recipient(&set, &self.device, public_key, 1)
            .map_err(refused)?;
        set.apply(facts);
        Ok(self.device.clone())
    }

    fn recipients(&self) -> Result<Vec<LinkRecipient>, String> {
        Ok(self
            .set
            .borrow()
            .recipients()
            .into_iter()
            .map(|(device, key)| LinkRecipient::new(device, key.clone()).unwrap())
            .collect())
    }

    fn links(&self) -> Result<Vec<LinkSummary>, String> {
        let view = account_links::links_view(&self.set.borrow(), Some(&self.device));
        Ok(serde_json::from_value(view["links"].clone()).unwrap())
    }

    fn copy(&self, provider: &str) -> Result<Option<CopyEnvelope>, String> {
        let set = self.set.borrow();
        let Some(copy) = set.copy_for(provider, &self.device) else {
            return Ok(None);
        };
        let link = &set.links[provider];
        Ok(Some(CopyEnvelope {
            provider: provider.to_owned(),
            version: link.version,
            base_url: link.base_url.clone(),
            execution_classes: link.execution_classes.clone(),
            copy: copy.clone(),
        }))
    }

    fn put(&self, provider: &str, put: &PutLink) -> Result<u64, String> {
        let mut set = self.set.borrow_mut();
        let facts =
            account_links::put_link(&set, provider, Some(&self.device), put, 1).map_err(refused)?;
        set.apply(facts);
        Ok(put.expected_version + 1)
    }

    fn add_copies(
        &self,
        provider: &str,
        version: u64,
        copies: &[SealedLinkCopy],
    ) -> Result<(), String> {
        let mut set = self.set.borrow_mut();
        let facts = account_links::add_copies(&set, provider, version, copies).map_err(refused)?;
        set.apply(facts);
        Ok(())
    }
    fn revoke(&self, provider: &str) -> Result<(), String> {
        let mut set = self.set.borrow_mut();
        let facts = account_links::revoke_link(&set, provider, 1).map_err(refused)?;
        set.apply(facts);
        Ok(())
    }

    fn take_lease(&self, provider: &str, ttl_ms: u64) -> Result<Lease, String> {
        let mut set = self.set.borrow_mut();
        match account_links::take_lease(&set, provider, &self.device, ttl_ms, 1) {
            Ok(facts) => {
                set.apply(facts);
                Ok(Lease::Granted)
            }
            Err(account_links::LinkRefusal::LeaseHeld { .. }) => Ok(Lease::HeldElsewhere),
            Err(refusal) => Err(refused(refusal)),
        }
    }
}

/// One desktop: its own store, its own key directory, its own session.
struct Desktop {
    _root: tempfile::TempDir,
    wb: SharedWorkbench,
    keys: LinkRecipientStore,
    authority: Authority,
}

impl Desktop {
    fn new(set: &Rc<RefCell<LinkSet>>, device: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let keys = LinkRecipientStore::new(root.path().join("keys/account-link"));
        Self {
            _root: root,
            wb,
            keys,
            authority: Authority::device(set, device),
        }
    }

    fn scope(&self) -> String {
        crate::account::account_scope(PERSON)
    }

    fn link_locally(&self, provider: &str, secret: &str) {
        let mut guard = self.wb.lock_unpoisoned();
        let sealed = guard.seal_account_secret(secret).unwrap();
        guard
            .upsert_account_credential_in_with_policy(
                &self.scope(),
                provider.to_owned(),
                sealed,
                String::new(),
                BTreeSet::from([ModelExecutionClass::LocalInteractive]),
            )
            .unwrap();
    }

    fn reconcile(&self) -> Reconciled {
        reconcile(&self.wb, PERSON, &self.scope(), &self.keys, &self.authority).unwrap()
    }

    fn publish_link(&self, provider: &str) -> Result<u64, String> {
        publish_link(
            &self.wb,
            PERSON,
            &self.scope(),
            provider,
            &self.keys,
            &self.authority,
        )
    }

    /// The secret a turn on this desktop would run on, if it has one.
    fn token(&self, provider: &str) -> Option<String> {
        let guard = self.wb.lock_unpoisoned();
        let record = credentials_in_scope(guard.store_ref(), &self.scope())
            .remove(provider)
            .filter(|record| record.admits(ModelExecutionClass::LocalInteractive))?;
        guard.unseal_account_secret(&record.sealed_token)
    }
}

#[test]
fn a_link_made_on_one_desktop_reaches_the_accounts_other_desktop() {
    let set = Authority::shared();
    let (mac, laptop) = (
        Desktop::new(&set, "device:mac"),
        Desktop::new(&set, "device:laptop"),
    );
    mac.reconcile();
    laptop.reconcile();

    mac.link_locally("openai", "sk-from-the-mac");
    assert_eq!(mac.publish_link("openai"), Ok(1));
    assert_eq!(laptop.token("openai"), None);

    let done = laptop.reconcile();
    assert_eq!(done.taken, vec!["openai".to_owned()]);
    assert_eq!(laptop.token("openai").as_deref(), Some("sk-from-the-mac"));
    assert!(
        laptop.reconcile().taken.is_empty(),
        "a version already taken is not taken again"
    );

    // The Hub holds only ciphertext: no copy contains the secret's bytes.
    let stored = format!("{:?}", set.borrow().copies);
    assert!(!stored.contains("sk-from-the-mac"));
    assert!(!stored.contains(&hex::encode("sk-from-the-mac")));
}

#[test]
fn a_device_trusted_later_is_sealed_for_by_one_that_holds_the_link() {
    let set = Authority::shared();
    let mac = Desktop::new(&set, "device:mac");
    mac.reconcile();
    mac.link_locally("openai", "sk-1");
    mac.publish_link("openai").unwrap();

    let laptop = Desktop::new(&set, "device:laptop");
    let first = laptop.reconcile();
    assert!(first.taken.is_empty(), "nothing is sealed for it yet");
    assert_eq!(laptop.token("openai"), None);

    let sealed = mac.reconcile();
    assert_eq!(
        sealed.sealed_for,
        vec![("openai".to_owned(), "device:laptop".to_owned())]
    );
    laptop.reconcile();
    assert_eq!(laptop.token("openai").as_deref(), Some("sk-1"));
    assert!(mac.reconcile().sealed_for.is_empty());
}

#[test]
fn a_newer_version_replaces_the_one_a_desktop_holds() {
    let set = Authority::shared();
    let (mac, laptop) = (
        Desktop::new(&set, "device:mac"),
        Desktop::new(&set, "device:laptop"),
    );
    mac.reconcile();
    laptop.reconcile();
    mac.link_locally("openai", "sk-1");
    mac.publish_link("openai").unwrap();
    laptop.reconcile();

    laptop.link_locally("openai", "sk-2");
    assert_eq!(laptop.publish_link("openai"), Ok(2));
    mac.reconcile();
    assert_eq!(mac.token("openai").as_deref(), Some("sk-2"));
}

#[test]
fn a_link_the_account_revokes_leaves_every_desktop() {
    let set = Authority::shared();
    let (mac, laptop) = (
        Desktop::new(&set, "device:mac"),
        Desktop::new(&set, "device:laptop"),
    );
    mac.reconcile();
    laptop.reconcile();
    mac.link_locally("openai", "sk-1");
    mac.publish_link("openai").unwrap();
    laptop.reconcile();

    revoke("openai", &laptop.authority).unwrap();
    assert_eq!(laptop.reconcile().removed, vec!["openai".to_owned()]);
    assert_eq!(laptop.token("openai"), None);
    mac.reconcile();
    assert_eq!(mac.token("openai"), None);
}

#[test]
fn a_revoked_device_is_not_sealed_for_again() {
    let set = Authority::shared();
    let (mac, laptop) = (
        Desktop::new(&set, "device:mac"),
        Desktop::new(&set, "device:laptop"),
    );
    mac.reconcile();
    laptop.reconcile();
    mac.link_locally("openai", "sk-1");
    mac.publish_link("openai").unwrap();

    mac.authority.revoke_device("device:laptop");
    mac.link_locally("openai", "sk-rotated");
    assert_eq!(mac.publish_link("openai"), Ok(2));
    let copies = set.borrow().copies.clone();
    assert!(copies
        .values()
        .all(|copy| copy.copy.device_id == "device:mac"));
}

#[test]
fn a_link_this_desktop_already_held_becomes_the_accounts() {
    let set = Authority::shared();
    let (mac, laptop) = (
        Desktop::new(&set, "device:mac"),
        Desktop::new(&set, "device:laptop"),
    );
    laptop.reconcile();
    // Made before the account held links, or by a provider sign-in, which
    // never goes through publish.
    mac.link_locally("anthropic", "sk-ant-local");
    assert_eq!(mac.reconcile().published, vec!["anthropic".to_owned()]);
    assert!(
        mac.reconcile().published.is_empty(),
        "a link already the account's is not published again"
    );
    laptop.reconcile();
    assert_eq!(laptop.token("anthropic").as_deref(), Some("sk-ant-local"));
}

#[test]
fn a_link_changed_here_is_published_and_one_unlinked_here_is_revoked() {
    let set = Authority::shared();
    let (mac, laptop) = (
        Desktop::new(&set, "device:mac"),
        Desktop::new(&set, "device:laptop"),
    );
    mac.reconcile();
    laptop.reconcile();
    mac.link_locally("openai", "sk-1");
    mac.reconcile();
    laptop.reconcile();

    // A refresh or a new sign-in rewrites the local record.
    mac.link_locally("openai", "sk-refreshed");
    assert_eq!(mac.reconcile().published, vec!["openai".to_owned()]);
    laptop.reconcile();
    assert_eq!(laptop.token("openai").as_deref(), Some("sk-refreshed"));

    // Unlinked here while the account was unreachable.
    mac.wb
        .lock_unpoisoned()
        .tombstone_account_credential_in(&mac.scope(), "openai".into())
        .unwrap();
    assert_eq!(mac.reconcile().revoked, vec!["openai".to_owned()]);
    assert_eq!(laptop.reconcile().removed, vec!["openai".to_owned()]);
    assert_eq!(laptop.token("openai"), None);
    assert!(mac.reconcile().revoked.is_empty());
}

#[test]
fn one_device_refreshes_a_shared_sign_in_and_the_other_takes_its_result() {
    let set = Authority::shared();
    let (mac, laptop) = (
        Desktop::new(&set, "device:mac"),
        Desktop::new(&set, "device:laptop"),
    );
    mac.reconcile();
    laptop.reconcile();
    mac.link_locally("openai-codex", "bundle-1");
    mac.reconcile();
    laptop.reconcile();

    let ask = |desktop: &Desktop, wait_ms: u64| {
        before_refresh_with(
            &desktop.wb,
            PERSON,
            &desktop.scope(),
            "openai-codex",
            &desktop.keys,
            &desktop.authority,
            std::time::Duration::from_millis(wait_ms),
        )
    };
    assert_eq!(
        ask(&mac, 0),
        RefreshTurn::Refresh,
        "the first to ask refreshes"
    );
    assert!(
        matches!(ask(&laptop, 0), RefreshTurn::Busy(_)),
        "the other does not spend the same refresh token"
    );

    // The holder refreshes and publishes, which frees the lease.
    mac.link_locally("openai-codex", "bundle-2");
    mac.publish_link("openai-codex").unwrap();
    assert_eq!(ask(&laptop, 0), RefreshTurn::Taken);
    assert_eq!(laptop.token("openai-codex").as_deref(), Some("bundle-2"));
}

#[test]
fn a_sign_in_only_this_desktop_holds_refreshes_without_asking() {
    let set = Authority::shared();
    let mac = Desktop::new(&set, "device:mac");
    mac.link_locally("openai-codex", "bundle-1");
    // Never reconciled: no account holds it, and there is no Hub session.
    assert_eq!(
        before_refresh(&mac.wb, &mac.scope(), "openai-codex"),
        RefreshTurn::Refresh
    );
}
