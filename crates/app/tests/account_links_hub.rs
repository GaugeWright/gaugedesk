//! DR-0334 over the wire: two desktops of one account share a provider link
//! through the Hub's account-link routes, and the Hub stores only copies it
//! cannot open.
//!
//! An integration test is its own process, so it can switch the account
//! routes into Hub mode with `GAUGEDESK_WEB_ACCOUNT` without reaching into
//! any other test. Everything here runs in one test for the same reason.

use std::collections::BTreeSet;

use gaugedesk_app::account::{
    account_scope, credentials_in_scope, DeviceKind, DeviceRecord, DeviceStatus,
    ModelExecutionClass, RecordOp,
};
use gaugedesk_app::account_link_seal::LinkRecipientStore;
use gaugedesk_app::account_links::{authority_routes, LinkSet};
use gaugedesk_app::account_links_sync::{
    publish_link, reconcile, revoke, HubLinkAuthority, LinkAuthority, NOT_SERVED,
};
use gaugedesk_app::{open_workbench, LockUnpoisoned, SharedWorkbench};

const PERSON: &str = "acct-person";

fn trusted_device(hub: &SharedWorkbench, id: &str) -> String {
    let mut guard = hub.lock_unpoisoned();
    guard
        .upsert_account_device_in(
            &account_scope(PERSON),
            &DeviceRecord {
                id: id.into(),
                op: RecordOp::Upsert,
                label: id.into(),
                kind: DeviceKind::Computer,
                subkey_pubkey: String::new(),
                status: DeviceStatus::Active,
                enrolled_at: 1,
            },
        )
        .unwrap();
    let token = guard.mint_account_session(PERSON, "passkey", 3600).unwrap();
    let session = gaugedesk_app::account_session::session_id(&token);
    assert!(guard.bind_account_session_device(&session, PERSON, id));
    token
}

struct Desktop {
    _root: tempfile::TempDir,
    wb: SharedWorkbench,
    keys: LinkRecipientStore,
    authority: HubLinkAuthority,
}

impl Desktop {
    fn new(hub_url: &str, bearer: String) -> Self {
        let root = tempfile::tempdir().unwrap();
        let wb = open_workbench(root.path()).unwrap();
        let keys = LinkRecipientStore::new(root.path().join("keys/account-link"));
        Self {
            _root: root,
            wb,
            keys,
            authority: HubLinkAuthority::new(hub_url.to_owned(), bearer),
        }
    }

    fn token(&self, provider: &str) -> Option<String> {
        let guard = self.wb.lock_unpoisoned();
        let record = credentials_in_scope(guard.store_ref(), &account_scope(PERSON))
            .remove(provider)
            .filter(|record| record.admits(ModelExecutionClass::LocalInteractive))?;
        guard.unseal_account_secret(&record.sealed_token)
    }
}

#[test]
fn two_desktops_share_a_link_through_the_hub_which_cannot_read_it() {
    std::env::set_var("GAUGEDESK_WEB_ACCOUNT", "1");
    let hub_root = tempfile::tempdir().unwrap();
    let hub = open_workbench(hub_root.path()).unwrap();
    let mac_bearer = trusted_device(&hub, "device:mac");
    let laptop_bearer = trusted_device(&hub, "device:laptop");

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = authority_routes().with_state(hub.clone());
    runtime.spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mac = Desktop::new(&url, mac_bearer);
    let laptop = Desktop::new(&url, laptop_bearer);
    let scope = account_scope(PERSON);
    for desktop in [&mac, &laptop] {
        let done = reconcile(
            &desktop.wb,
            PERSON,
            &scope,
            &desktop.keys,
            &desktop.authority,
        )
        .unwrap();
        assert!(done.taken.is_empty());
    }

    {
        let mut guard = mac.wb.lock_unpoisoned();
        let sealed = guard.seal_account_secret("sk-over-the-wire").unwrap();
        guard
            .upsert_account_credential_in_with_policy(
                &scope,
                "openai".into(),
                sealed,
                String::new(),
                BTreeSet::from([ModelExecutionClass::LocalInteractive]),
            )
            .unwrap();
    }
    assert_eq!(
        publish_link(&mac.wb, PERSON, &scope, "openai", &mac.keys, &mac.authority),
        Ok(1)
    );

    let done = reconcile(&laptop.wb, PERSON, &scope, &laptop.keys, &laptop.authority).unwrap();
    assert_eq!(done.device_id, "device:laptop");
    assert_eq!(done.taken, vec!["openai".to_owned()]);
    assert_eq!(laptop.token("openai").as_deref(), Some("sk-over-the-wire"));

    // Everything the Hub keeps for the account, in every kind, holds no trace
    // of the secret.
    {
        let guard = hub.lock_unpoisoned();
        let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
        assert_eq!(set.copies.len(), 2);
        let held = format!("{set:?}");
        assert!(!held.contains("sk-over-the-wire"));
        assert!(!held.contains(&hex::encode("sk-over-the-wire")));
    }

    // A Hub from before account links answers 404, which a desktop takes as
    // "keep your links as they are" rather than as a failure to report.
    let old_hub = HubLinkAuthority::new(format!("{url}/before-account-links"), "bearer".into());
    assert_eq!(old_hub.register("04ab"), Err(NOT_SERVED.to_owned()));
    assert_eq!(old_hub.revoke("openai"), Ok(()));

    revoke("openai", &mac.authority).unwrap();
    let done = reconcile(&laptop.wb, PERSON, &scope, &laptop.keys, &laptop.authority).unwrap();
    assert_eq!(done.removed, vec!["openai".to_owned()]);
    assert_eq!(laptop.token("openai"), None);
}
