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
            .all_recipients()
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

    fn report_check(&self, provider: &str, version: u64, reachable: bool) -> Result<(), String> {
        let mut set = self.set.borrow_mut();
        let facts =
            account_links::record_check(&set, provider, &self.device, version, reachable, 1)
                .map_err(refused)?;
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

#[test]
fn a_device_checks_a_link_it_holds_and_the_account_keeps_only_the_answer() {
    let set = Authority::shared();
    let (mac, laptop) = (
        Desktop::new(&set, "device:mac"),
        Desktop::new(&set, "device:laptop"),
    );
    mac.reconcile();
    laptop.reconcile();
    mac.link_locally("openai", "sk-good");
    mac.link_locally("openai-codex", "bundle");
    mac.reconcile();

    let asked = std::sync::Mutex::new(Vec::new());
    let checker = |provider: &str, _base_url: &str, secret: &str| {
        asked
            .lock()
            .unwrap()
            .push((provider.to_owned(), secret.to_owned()));
        (provider == "openai").then_some(secret == "sk-good")
    };
    let checked = check_links(
        PERSON,
        &["openai".to_owned(), "openai-codex".to_owned()],
        &laptop.keys,
        &laptop.authority,
        &checker,
    )
    .unwrap();
    assert_eq!(checked, vec![("openai".to_owned(), true)]);
    assert_eq!(
        asked.lock().unwrap()[0],
        ("openai".to_owned(), "sk-good".to_owned())
    );

    let held = format!("{:?}", set.borrow().checks);
    assert!(
        !held.contains("sk-good"),
        "the account keeps the answer, never the key"
    );
    assert!(set
        .borrow()
        .check("openai")
        .is_some_and(|check| check.reachable));
    assert!(set.borrow().check("openai-codex").is_none());

    // A newer version needs its own check.
    mac.link_locally("openai", "sk-rotated");
    mac.reconcile();
    assert!(set.borrow().check("openai").is_none());
}

// ---- hosted Homes (DR-0380) -----------------------------------------------------

const HOME: &str = "home:cloud:personal";
/// The id the Home knows the person by, which is not their account id.
const HOME_ACTOR: &str = "person@example.com";

/// A hosted Home that serves the account, asking the authority in memory.
struct HostedHome {
    _root: tempfile::TempDir,
    wb: SharedWorkbench,
    key: crate::account_link_seal::HomeLinkRecipientKey,
    set: Rc<RefCell<LinkSet>>,
    /// The account answers; when false, asking fails and changes nothing.
    reachable: std::cell::Cell<bool>,
}

impl HostedHome {
    fn new(set: &Rc<RefCell<LinkSet>>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let key = crate::account_link_seal::HomeLinkRecipientKey::new(
            root.path().join("keys/account-link/home.recipient"),
            Box::new(crate::at_rest::LoopbackKeyWrap::generate().unwrap()),
        );
        let home = Self {
            _root: root,
            wb,
            key,
            set: set.clone(),
            reachable: std::cell::Cell::new(true),
        };
        home.serve();
        home
    }

    /// The Hub records this Home's key in a tenant the person belongs to.
    fn serve(&self) {
        let public = self.key.ensure().unwrap();
        self.set.borrow_mut().homes.insert(HOME.to_owned(), public);
    }

    fn scope(&self) -> String {
        crate::account::account_scope(HOME_ACTOR)
    }

    fn reconcile(&self) -> HomeReconciled {
        reconcile_home(&self.wb, HOME, &self.scope(), &self.key, self).unwrap()
    }

    /// The secret this Home's broker would resolve for the person's turn.
    fn token(&self, provider: &str) -> Option<String> {
        let guard = self.wb.lock_unpoisoned();
        let record = credentials_in_scope(guard.store_ref(), &self.scope())
            .remove(provider)
            .filter(|record| record.admits(ModelExecutionClass::PrivateHome))?;
        guard.unseal_account_secret(&record.sealed_token)
    }
}

impl HomeLinkSource for HostedHome {
    fn home_links(&self, home_id: &str) -> Result<Option<HomeLinks>, String> {
        if !self.reachable.get() {
            return Err("the account did not answer".into());
        }
        match account_links::home_links_view(&self.set.borrow(), home_id) {
            Ok(view) => Ok(Some(HomeLinks {
                account: PERSON.to_owned(),
                links: serde_json::from_value(view["links"].clone()).unwrap(),
            })),
            Err(account_links::LinkRefusal::HomeNotServing) => Ok(None),
            Err(refusal) => Err(refused(refusal)),
        }
    }
}

impl Desktop {
    fn link_for_homes(&self, provider: &str, secret: &str) {
        let mut guard = self.wb.lock_unpoisoned();
        let sealed = guard.seal_account_secret(secret).unwrap();
        guard
            .upsert_account_credential_in_with_policy(
                &self.scope(),
                provider.to_owned(),
                sealed,
                String::new(),
                BTreeSet::from([
                    ModelExecutionClass::LocalInteractive,
                    ModelExecutionClass::PrivateHome,
                ]),
            )
            .unwrap();
    }
}

#[test]
fn a_home_use_link_made_on_a_desktop_reaches_the_persons_hosted_home() {
    let set = Authority::shared();
    let mac = Desktop::new(&set, "device:mac");
    let home = HostedHome::new(&set);
    mac.reconcile();
    mac.link_for_homes("openai", "sk-for-homes");
    mac.publish_link("openai").unwrap();

    assert_eq!(home.reconcile().taken, vec!["openai".to_owned()]);
    assert_eq!(home.token("openai").as_deref(), Some("sk-for-homes"));
    assert!(home.reconcile().taken.is_empty(), "taken once");

    // A link only for the person's own devices never reaches it.
    mac.link_locally("anthropic", "sk-local");
    mac.publish_link("anthropic").unwrap();
    home.reconcile();
    assert_eq!(home.token("anthropic"), None);
}

#[test]
fn a_home_that_starts_serving_later_is_sealed_for_by_a_device() {
    let set = Authority::shared();
    let mac = Desktop::new(&set, "device:mac");
    mac.reconcile();
    mac.link_for_homes("openai", "sk-1");
    mac.publish_link("openai").unwrap();

    let home = HostedHome::new(&set);
    assert!(home.reconcile().taken.is_empty(), "waiting for a device");
    assert_eq!(
        mac.reconcile().sealed_for,
        vec![("openai".to_owned(), HOME.to_owned())]
    );
    assert_eq!(home.reconcile().taken, vec!["openai".to_owned()]);
    assert_eq!(home.token("openai").as_deref(), Some("sk-1"));
}

#[test]
fn a_home_drops_what_the_account_takes_away_and_only_that() {
    let set = Authority::shared();
    let mac = Desktop::new(&set, "device:mac");
    let home = HostedHome::new(&set);
    mac.reconcile();
    mac.link_for_homes("openai", "sk-1");
    mac.publish_link("openai").unwrap();
    home.reconcile();

    // Not reaching the account removes nothing.
    home.reachable.set(false);
    assert!(reconcile_home(&home.wb, HOME, &home.scope(), &home.key, &home).is_err());
    assert_eq!(home.token("openai").as_deref(), Some("sk-1"));
    home.reachable.set(true);

    // The person's own link on this Home is never replaced or removed.
    {
        let mut guard = home.wb.lock_unpoisoned();
        let sealed = guard.seal_account_secret("sk-home-own").unwrap();
        guard
            .upsert_account_credential_in_with_policy(
                &home.scope(),
                "xai".to_owned(),
                sealed,
                String::new(),
                BTreeSet::from([ModelExecutionClass::PrivateHome]),
            )
            .unwrap();
    }

    // The person leaves the Home's tenant.
    set.borrow_mut().homes.clear();
    assert_eq!(home.reconcile().removed, vec!["openai".to_owned()]);
    assert_eq!(home.token("openai"), None);
    assert_eq!(home.token("xai").as_deref(), Some("sk-home-own"));

    // Back again, then the link is revoked.
    home.serve();
    mac.reconcile();
    assert_eq!(home.reconcile().taken, vec!["openai".to_owned()]);
    mac.authority.revoke("openai").unwrap();
    assert_eq!(home.reconcile().removed, vec!["openai".to_owned()]);
    assert_eq!(home.token("xai").as_deref(), Some("sk-home-own"));
}
