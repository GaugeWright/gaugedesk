//! DR-0334: what the account authority admits for a person's provider links.
use super::*;
use crate::account::{DeviceKind, DeviceRecord};
use crate::account_link_seal::{
    open_link_copy, seal_link_copy, LinkContext, LinkRecipient, LinkRecipientPrivateKey,
};

const PERSON: &str = "acct-person";
const NOW: u64 = 1_000_000;

fn key(seed: u8) -> LinkRecipientPrivateKey {
    LinkRecipientPrivateKey::from_seed([seed; 32]).unwrap()
}

fn device(id: &str) -> DeviceRecord {
    DeviceRecord {
        id: id.into(),
        op: RecordOp::Upsert,
        label: id.into(),
        kind: DeviceKind::Computer,
        subkey_pubkey: String::new(),
        status: DeviceStatus::Active,
        enrolled_at: 1,
    }
}

/// Decide against `set`, then fold what was admitted into it.
macro_rules! apply {
    ($set:ident, $facts:expr $(,)?) => {{
        let facts = $facts;
        fold_facts(&mut $set, facts);
    }};
}

fn fold_facts(set: &mut LinkSet, facts: Vec<LinkFact>) {
    set.apply(facts);
}

/// An account with these trusted devices, each registered with its key.
fn set_with(devices: &[(&str, u8)]) -> LinkSet {
    let mut set = LinkSet::default();
    for (id, seed) in devices {
        set.active_devices.insert((*id).to_owned());
        apply!(
            set,
            register_recipient(&set, id, key(*seed).public_key().as_str(), NOW).unwrap(),
        );
    }
    set
}

fn sealed(version: u64, secret: &str, devices: &[(&str, u8)]) -> Vec<SealedLinkCopy> {
    let context = LinkContext::new(PERSON, "openai", version).unwrap();
    devices
        .iter()
        .map(|(id, seed)| {
            seal_link_copy(
                &context,
                secret.as_bytes(),
                &LinkRecipient::new(*id, key(*seed).public_key()).unwrap(),
            )
            .unwrap()
        })
        .collect()
}

fn put(expected_version: u64, copies: Vec<SealedLinkCopy>) -> PutLink {
    PutLink {
        expected_version,
        base_url: String::new(),
        authentication: CredentialAuthentication::Bearer,
        execution_classes: BTreeSet::from([ModelExecutionClass::LocalInteractive]),
        copies,
    }
}

fn open(set: &LinkSet, device: &str, seed: u8) -> Option<String> {
    let copy = set.copy_for("openai", device)?;
    let version = set.links["openai"].version;
    let context = LinkContext::new(PERSON, "openai", version).unwrap();
    open_link_copy(&context, &key(seed), copy)
        .ok()
        .map(|bytes| String::from_utf8(bytes).unwrap())
}

const MAC: (&str, u8) = ("device:mac", 7);
const PHONE: (&str, u8) = ("device:phone", 9);

#[test]
fn a_link_made_anywhere_opens_on_every_trusted_device() {
    let mut set = set_with(&[MAC, PHONE]);
    // A browser page makes it: no device of its own.
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(0, sealed(1, "sk-1", &[MAC, PHONE])),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(open(&set, MAC.0, MAC.1).as_deref(), Some("sk-1"));
    assert_eq!(open(&set, PHONE.0, PHONE.1).as_deref(), Some("sk-1"));
    assert!(set.waiting("openai").is_empty());
}

#[test]
fn a_new_version_must_be_sealed_for_exactly_the_trusted_devices() {
    let set = set_with(&[MAC, PHONE]);
    assert_eq!(
        put_link(&set, "openai", None, &put(0, sealed(1, "sk", &[MAC])), NOW),
        Err(LinkRefusal::Coverage {
            missing: vec![PHONE.0.into()],
            unexpected: vec![]
        })
    );
    let stranger = ("device:stranger", 3);
    assert!(matches!(
        put_link(&set, "openai", None, &put(0, sealed(1, "sk", &[MAC, PHONE, stranger])), NOW),
        Err(LinkRefusal::Coverage { unexpected, .. }) if unexpected == vec![stranger.0.to_owned()]
    ));
    let mut twice = sealed(1, "sk", &[MAC, PHONE]);
    twice.push(twice[0].clone());
    assert!(matches!(
        put_link(&set, "openai", None, &put(0, twice), NOW),
        Err(LinkRefusal::InvalidCopy(_))
    ));
    for classes in [
        BTreeSet::new(),
        BTreeSet::from([ModelExecutionClass::PublicDeployment]),
    ] {
        let mut public = put(0, sealed(1, "sk", &[MAC, PHONE]));
        public.execution_classes = classes;
        assert_eq!(
            put_link(&set, "openai", None, &public, NOW),
            Err(LinkRefusal::InvalidClasses)
        );
    }
    assert_eq!(
        put_link(
            &LinkSet::default(),
            "openai",
            None,
            &put(0, Vec::new()),
            NOW
        ),
        Err(LinkRefusal::NoRecipients),
        "with no device to open it, a link is refused rather than held unreadable"
    );
}

#[test]
fn a_version_is_admitted_only_over_the_one_its_author_read() {
    let mut set = set_with(&[MAC]);
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(0, sealed(1, "sk-1", &[MAC])),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(
        put_link(
            &set,
            "openai",
            None,
            &put(0, sealed(1, "sk-x", &[MAC])),
            NOW
        ),
        Err(LinkRefusal::Stale { current: 1 })
    );
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(1, sealed(2, "sk-2", &[MAC])),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(open(&set, MAC.0, MAC.1).as_deref(), Some("sk-2"));
}

#[test]
fn a_device_trusted_later_waits_until_a_holder_seals_for_it() {
    let mut set = set_with(&[MAC]);
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(0, sealed(1, "sk-1", &[MAC])),
            NOW,
        )
        .unwrap(),
    );
    set.active_devices.insert(PHONE.0.into());
    apply!(
        set,
        register_recipient(&set, PHONE.0, key(PHONE.1).public_key().as_str(), NOW).unwrap(),
    );
    assert_eq!(set.waiting("openai"), vec![PHONE.0.to_owned()]);
    assert_eq!(open(&set, PHONE.0, PHONE.1), None);

    // Only a waiting device, only at the current version, only once.
    assert!(matches!(
        add_copies(&set, "openai", 1, &sealed(1, "sk-1", &[MAC])),
        Err(LinkRefusal::Coverage { .. })
    ));
    assert_eq!(
        add_copies(&set, "openai", 2, &sealed(2, "sk-1", &[PHONE])),
        Err(LinkRefusal::Stale { current: 1 })
    );
    let mut twice = sealed(1, "sk-1", &[PHONE]);
    twice.push(twice[0].clone());
    assert!(add_copies(&set, "openai", 1, &twice).is_err());

    apply!(
        set,
        add_copies(&set, "openai", 1, &sealed(1, "sk-1", &[PHONE])).unwrap(),
    );
    assert_eq!(open(&set, PHONE.0, PHONE.1).as_deref(), Some("sk-1"));
    assert!(set.waiting("openai").is_empty());
}

#[test]
fn only_a_trusted_device_registers_and_a_new_key_voids_its_old_copies() {
    let mut set = set_with(&[MAC]);
    assert_eq!(
        register_recipient(&set, "device:stranger", key(3).public_key().as_str(), NOW),
        Err(LinkRefusal::NotADevice)
    );
    assert_eq!(
        register_recipient(&set, MAC.0, "zz", NOW),
        Err(LinkRefusal::InvalidKey)
    );
    assert!(
        register_recipient(&set, MAC.0, key(MAC.1).public_key().as_str(), NOW)
            .unwrap()
            .is_empty()
    );

    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(0, sealed(1, "sk-1", &[MAC])),
            NOW,
        )
        .unwrap(),
    );
    apply!(
        set,
        register_recipient(&set, MAC.0, key(8).public_key().as_str(), NOW).unwrap(),
    );
    assert_eq!(
        set.copy_for("openai", MAC.0),
        None,
        "a copy to the replaced key is dropped"
    );
    assert_eq!(set.waiting("openai"), vec![MAC.0.to_owned()]);
}

#[test]
fn revoking_a_device_deletes_its_copies_and_names_what_it_held() {
    let mut set = set_with(&[MAC, PHONE]);
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(0, sealed(1, "sk-1", &[MAC, PHONE])),
            NOW,
        )
        .unwrap(),
    );
    set.active_devices.remove(PHONE.0);
    let (facts, held) = forget_device(&set, PHONE.0);
    assert_eq!(held, vec!["openai".to_owned()]);
    apply!(set, facts);
    assert!(set
        .copies
        .values()
        .all(|copy| copy.copy.device_id != PHONE.0));
    assert!(!set.recipients.contains_key(PHONE.0));
    // A rotation reaches only the devices that remain.
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(1, sealed(2, "sk-2", &[MAC])),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(open(&set, MAC.0, MAC.1).as_deref(), Some("sk-2"));
}

#[test]
fn a_revoked_link_keeps_its_record_and_loses_every_copy() {
    let mut set = set_with(&[MAC]);
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(0, sealed(1, "sk-1", &[MAC])),
            NOW,
        )
        .unwrap(),
    );
    apply!(set, revoke_link(&set, "openai", NOW).unwrap());
    assert_eq!(set.links["openai"].status, LinkStatus::Revoked);
    assert!(set.copies.is_empty());
    assert!(set.waiting("openai").is_empty());
    // Relinking continues the version sequence.
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(1, sealed(2, "sk-2", &[MAC])),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(open(&set, MAC.0, MAC.1).as_deref(), Some("sk-2"));
}

#[test]
fn one_device_refreshes_an_oauth_link_at_a_time() {
    let mut set = set_with(&[MAC, PHONE]);
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(0, sealed(1, "sk-1", &[MAC, PHONE])),
            NOW,
        )
        .unwrap(),
    );
    apply!(set, take_lease(&set, "openai", MAC.0, 60_000, NOW).unwrap(),);
    assert!(matches!(
        take_lease(&set, "openai", PHONE.0, 60_000, NOW + 1),
        Err(LinkRefusal::LeaseHeld { device_id, .. }) if device_id == MAC.0
    ));
    assert!(matches!(
        put_link(
            &set,
            "openai",
            Some(PHONE.0),
            &put(1, sealed(2, "sk-p", &[MAC, PHONE])),
            NOW + 1
        ),
        Err(LinkRefusal::LeaseHeld { .. })
    ));
    // The holder publishes, which frees the lease.
    apply!(
        set,
        put_link(
            &set,
            "openai",
            Some(MAC.0),
            &put(1, sealed(2, "sk-2", &[MAC, PHONE])),
            NOW + 2,
        )
        .unwrap(),
    );
    assert!(set.leases.is_empty());
    assert!(take_lease(&set, "openai", PHONE.0, 60_000, NOW + 3).is_ok());

    // A holder that dies leaves the link refreshable once its lease lapses,
    // and no lease outlives the bound.
    apply!(
        set,
        take_lease(&set, "openai", MAC.0, u64::MAX / 4, NOW).unwrap(),
    );
    assert_eq!(set.leases["openai"].expires_at_ms, NOW + MAX_LEASE_MS);
    assert!(take_lease(&set, "openai", PHONE.0, 60_000, NOW + MAX_LEASE_MS + 1).is_ok());
}

#[test]
fn the_authority_answers_only_on_the_hub_and_only_a_bound_device_is_a_device() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    let mut guard = wb.lock_unpoisoned();
    let scope = crate::account::account_scope(PERSON);
    guard
        .upsert_account_device_in(&scope, &device(MAC.0))
        .unwrap();
    let browser = guard.mint_account_session(PERSON, "passkey", 3600).unwrap();
    let desktop = guard.mint_account_session(PERSON, "passkey", 3600).unwrap();
    assert!(guard.bind_account_session_device(
        &crate::account_session::session_id(&desktop),
        PERSON,
        MAC.0
    ));

    assert!(matches!(
        caller_on(&guard, Some(&desktop), false),
        Err(LinkRefusal::Unauthenticated)
    ));
    assert!(matches!(
        caller_on(&guard, None, true),
        Err(LinkRefusal::Unauthenticated)
    ));
    let page = caller_on(&guard, Some(&browser), true).ok().unwrap();
    assert_eq!((page.scope.as_str(), page.device), (scope.as_str(), None));
    let mac = caller_on(&guard, Some(&desktop), true).ok().unwrap();
    assert_eq!(mac.device.as_deref(), Some(MAC.0));
}

#[test]
fn revoking_a_trusted_device_in_the_registry_deletes_its_copies() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    let mut guard = wb.lock_unpoisoned();
    let scope = crate::account::account_scope(PERSON);
    for id in [MAC.0, PHONE.0] {
        guard.upsert_account_device_in(&scope, &device(id)).unwrap();
    }
    let admit = |guard: &mut crate::Workbench, facts: Vec<LinkFact>| {
        for fact in facts {
            fact.append(guard, &scope).unwrap();
        }
    };
    for (id, seed) in [MAC, PHONE] {
        let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
        let facts = register_recipient(&set, id, key(seed).public_key().as_str(), NOW).unwrap();
        admit(&mut guard, facts);
    }
    let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
    let facts = put_link(
        &set,
        "openai",
        None,
        &put(0, sealed(1, "sk-1", &[MAC, PHONE])),
        NOW,
    )
    .unwrap();
    admit(&mut guard, facts);

    guard.revoke_account_device_in(&scope, PHONE.0).unwrap();
    let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
    assert!(set
        .copies
        .values()
        .all(|copy| copy.copy.device_id != PHONE.0));
    assert!(!set.recipients.contains_key(PHONE.0));
    assert_eq!(open(&set, PHONE.0, PHONE.1), None);
    assert_eq!(open(&set, MAC.0, MAC.1).as_deref(), Some("sk-1"));
}

/// A Hub-held link from before DR-0334, sealed with the Hub's own key.
fn hold_on_the_hub(guard: &mut crate::Workbench, scope: &str, provider: &str, secret: &str) {
    let sealed = guard.seal_account_secret(secret).unwrap();
    guard
        .upsert_account_credential_in_with_policy(
            scope,
            provider.to_owned(),
            sealed,
            String::new(),
            BTreeSet::from([ModelExecutionClass::PrivateHome]),
        )
        .unwrap();
}

#[test]
fn what_the_hub_held_moves_to_the_devices_once_one_can_hold_it() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    let mut guard = wb.lock_unpoisoned();
    let scope = crate::account::account_scope(PERSON);
    hold_on_the_hub(&mut guard, &scope, "openai", "sk-web");

    // No device yet: nothing moves, and the Hub's copy stays.
    assert_eq!(
        migrate_held_links(&mut guard, PERSON, &scope, NOW).ok(),
        Some(vec![])
    );
    assert!(
        crate::account::credentials_in_scope(guard.store_ref(), &scope)["openai"]
            .admits(ModelExecutionClass::PrivateHome)
    );

    for id in [MAC.0, PHONE.0] {
        guard.upsert_account_device_in(&scope, &device(id)).unwrap();
    }
    for (id, seed) in [MAC, PHONE] {
        let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
        for fact in register_recipient(&set, id, key(seed).public_key().as_str(), NOW).unwrap() {
            fact.append(&mut guard, &scope).unwrap();
        }
    }
    assert_eq!(
        migrate_held_links(&mut guard, PERSON, &scope, NOW).ok(),
        Some(vec!["openai".to_owned()])
    );
    let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
    assert_eq!(open(&set, MAC.0, MAC.1).as_deref(), Some("sk-web"));
    assert_eq!(open(&set, PHONE.0, PHONE.1).as_deref(), Some("sk-web"));
    assert!(set.links["openai"]
        .execution_classes
        .contains(&ModelExecutionClass::LocalInteractive));
    let held = crate::account::credentials_in_scope(guard.store_ref(), &scope);
    assert!(
        held["openai"].sealed_token.is_empty(),
        "the Hub's copy is gone"
    );
    assert!(!held["openai"].admits(ModelExecutionClass::PrivateHome));
    assert_eq!(
        migrate_held_links(&mut guard, PERSON, &scope, NOW).ok(),
        Some(vec![]),
        "it moves once"
    );
}

#[test]
fn a_link_the_account_already_holds_wins_over_the_hubs_older_copy() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    let mut guard = wb.lock_unpoisoned();
    let scope = crate::account::account_scope(PERSON);
    guard
        .upsert_account_device_in(&scope, &device(MAC.0))
        .unwrap();
    let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
    for fact in register_recipient(&set, MAC.0, key(MAC.1).public_key().as_str(), NOW).unwrap() {
        fact.append(&mut guard, &scope).unwrap();
    }
    let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
    for fact in put_link(
        &set,
        "openai",
        None,
        &put(0, sealed(1, "sk-device", &[MAC])),
        NOW,
    )
    .unwrap()
    {
        fact.append(&mut guard, &scope).unwrap();
    }
    hold_on_the_hub(&mut guard, &scope, "openai", "sk-older-web");

    assert_eq!(
        migrate_held_links(&mut guard, PERSON, &scope, NOW).ok(),
        Some(vec![])
    );
    let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
    assert_eq!(open(&set, MAC.0, MAC.1).as_deref(), Some("sk-device"));
    assert!(
        crate::account::credentials_in_scope(guard.store_ref(), &scope)["openai"]
            .sealed_token
            .is_empty()
    );
}

#[test]
fn only_a_device_holding_the_current_version_records_a_check() {
    let mut set = set_with(&[MAC]);
    // A trusted device that never registered a key holds no copy.
    set.active_devices.insert(PHONE.0.to_owned());
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put(0, sealed(1, "sk-1", &[MAC])),
            NOW
        )
        .unwrap()
    );
    assert_eq!(
        record_check(&set, "openai", PHONE.0, 1, true, NOW),
        Err(LinkRefusal::NotADevice),
        "a device with no copy has not used the key"
    );
    assert_eq!(
        record_check(&set, "openai", MAC.0, 2, true, NOW),
        Err(LinkRefusal::Stale { current: 1 })
    );
    apply!(
        set,
        record_check(&set, "openai", MAC.0, 1, false, NOW).unwrap()
    );
    assert_eq!(
        set.check("openai").map(|check| check.reachable),
        Some(false)
    );
    assert_eq!(
        links_view(&set, None)["links"][0]["reachable"],
        serde_json::json!(false)
    );
}

// ---- hosted Homes (DR-0380) -----------------------------------------------------

const HOME: (&str, u8) = ("home:cloud:personal", 11);

/// An account with these devices, served by [`HOME`].
fn set_served(devices: &[(&str, u8)]) -> LinkSet {
    let mut set = set_with(devices);
    set.homes
        .insert(HOME.0.to_owned(), key(HOME.1).public_key());
    set
}

fn put_for_homes(expected_version: u64, copies: Vec<SealedLinkCopy>) -> PutLink {
    let mut put = put(expected_version, copies);
    put.execution_classes = BTreeSet::from([
        ModelExecutionClass::LocalInteractive,
        ModelExecutionClass::PrivateHome,
    ]);
    put
}

#[test]
fn a_home_use_link_reaches_every_home_serving_the_person_without_a_grant() {
    let mut set = set_served(&[MAC]);
    // Made on a device that seals for every recipient it is given.
    apply!(
        set,
        put_link(
            &set,
            "openai",
            Some(MAC.0),
            &put_for_homes(0, sealed(1, "sk-1", &[MAC, HOME])),
            NOW
        )
        .unwrap(),
    );
    assert_eq!(open(&set, HOME.0, HOME.1).as_deref(), Some("sk-1"));
    assert_eq!(set.homes_holding("openai"), vec![HOME.0.to_owned()]);
    let view = home_links_view(&set, HOME.0).unwrap();
    assert_eq!(view["links"][0]["provider"], "openai");
    assert!(view["links"][0]["copy"].is_object());

    // Made by a page that sealed only for the devices: the Home waits for one,
    // which seals for it as for a device trusted later.
    apply!(
        set,
        put_link(
            &set,
            "openai",
            None,
            &put_for_homes(1, sealed(2, "sk-2", &[MAC])),
            NOW
        )
        .unwrap(),
    );
    assert_eq!(set.waiting("openai"), vec![HOME.0.to_owned()]);
    assert_eq!(open(&set, HOME.0, HOME.1), None, "the old version is gone");
    assert!(home_links_view(&set, HOME.0).unwrap()["links"][0]["copy"].is_null());
    apply!(
        set,
        add_copies(&set, "openai", 2, &sealed(2, "sk-2", &[HOME])).unwrap()
    );
    assert_eq!(open(&set, HOME.0, HOME.1).as_deref(), Some("sk-2"));
    assert!(set.waiting("openai").is_empty());
}

#[test]
fn a_link_not_for_home_use_never_reaches_a_home() {
    let mut set = set_served(&[MAC]);
    // The device offered the Home a copy anyway; it is dropped, not refused.
    apply!(
        set,
        put_link(
            &set,
            "openai",
            Some(MAC.0),
            &put(0, sealed(1, "sk-1", &[MAC, HOME])),
            NOW
        )
        .unwrap(),
    );
    assert!(set
        .copies
        .values()
        .all(|copy| copy.copy.device_id != HOME.0));
    assert!(set.waiting("openai").is_empty());
    assert!(add_copies(&set, "openai", 1, &sealed(1, "sk-1", &[HOME])).is_err());
    assert_eq!(home_links_view(&set, HOME.0).unwrap()["links"], json!([]));

    // A sign-in a Home would have to refresh on its own does not reach one yet.
    let mut oauth = put_for_homes(1, sealed(2, "bundle", &[MAC, HOME]));
    oauth.authentication = CredentialAuthentication::OAuth;
    apply!(
        set,
        put_link(&set, "openai", Some(MAC.0), &oauth, NOW).unwrap()
    );
    assert_eq!(open(&set, HOME.0, HOME.1), None);
    assert!(set.waiting("openai").is_empty());
}

#[test]
fn a_copy_for_a_home_that_does_not_serve_the_person_is_refused() {
    let set = set_with(&[MAC]);
    assert!(matches!(
        put_link(&set, "openai", Some(MAC.0), &put_for_homes(0, sealed(1, "sk", &[MAC, HOME])), NOW),
        Err(LinkRefusal::Coverage { unexpected, .. }) if unexpected == vec![HOME.0.to_owned()]
    ));
    assert_eq!(
        home_links_view(&set, HOME.0),
        Err(LinkRefusal::HomeNotServing)
    );
}

#[test]
fn leaving_the_homes_tenant_takes_its_copies_away() {
    let mut set = set_served(&[MAC]);
    apply!(
        set,
        put_link(
            &set,
            "openai",
            Some(MAC.0),
            &put_for_homes(0, sealed(1, "sk-1", &[MAC, HOME])),
            NOW
        )
        .unwrap(),
    );
    set.homes.clear();
    assert_eq!(open(&set, HOME.0, HOME.1), None);
    assert_eq!(
        home_links_view(&set, HOME.0),
        Err(LinkRefusal::HomeNotServing)
    );
    let departed = set.departed_copies();
    assert_eq!(departed.len(), 1);
    apply!(set, departed);
    assert!(set
        .copies
        .values()
        .all(|copy| copy.copy.device_id != HOME.0));
    assert_eq!(open(&set, MAC.0, MAC.1).as_deref(), Some("sk-1"));

    // Revoking the link takes every copy, the Home's included.
    let mut set = set_served(&[MAC]);
    apply!(
        set,
        put_link(
            &set,
            "openai",
            Some(MAC.0),
            &put_for_homes(0, sealed(1, "sk-1", &[MAC, HOME])),
            NOW
        )
        .unwrap(),
    );
    apply!(set, revoke_link(&set, "openai", NOW).unwrap());
    assert!(set.copies.is_empty());
}

#[test]
fn the_homes_serving_a_person_are_their_active_tenants_recorded_homes() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    let mut guard = wb.lock_unpoisoned();
    let scope = crate::account::account_scope(PERSON);
    let tenant =
        crate::tenancy::provision_personal_tenant(guard.store_mut(), PERSON, "Person").unwrap();
    assert!(LinkSet::rebuild(guard.store_ref(), &scope)
        .unwrap()
        .homes
        .is_empty());

    // Only a Home id may be recorded, and only a P-256 key.
    assert!(record_hosted_home_recipient(
        &mut guard,
        &tenant,
        "device:mac",
        key(1).public_key().as_str(),
        NOW
    )
    .is_err());
    assert!(record_hosted_home_recipient(&mut guard, &tenant, HOME.0, "not a key", NOW).is_err());
    let public = key(HOME.1).public_key();
    assert!(
        record_hosted_home_recipient(&mut guard, &tenant, HOME.0, public.as_str(), NOW).unwrap()
    );
    assert!(
        !record_hosted_home_recipient(&mut guard, &tenant, HOME.0, public.as_str(), NOW).unwrap()
    );
    let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
    assert_eq!(set.homes.get(HOME.0), Some(&public));

    // Someone who is not a member of that tenant is not served by its Home.
    let stranger = crate::account::account_scope("acct-stranger");
    assert!(LinkSet::rebuild(guard.store_ref(), &stranger)
        .unwrap()
        .homes
        .is_empty());

    // A member who leaves is no longer served.
    let tenant_scope = crate::org::tenant_scope(&tenant);
    let mut member = crate::org::Org::rebuild_in(guard.store_ref(), &tenant_scope)
        .unwrap()
        .member_by_authority(PERSON)
        .unwrap()
        .clone();
    member.status = crate::org::MembershipStatus::Deprovisioned;
    guard
        .write_account_record_in(&tenant_scope, "membership", &member.id.clone(), &member)
        .unwrap();
    assert!(LinkSet::rebuild(guard.store_ref(), &scope)
        .unwrap()
        .homes
        .is_empty());

    // An erased Home is forgotten for everyone.
    member.status = crate::org::MembershipStatus::Active;
    guard
        .write_account_record_in(&tenant_scope, "membership", &member.id.clone(), &member)
        .unwrap();
    assert_eq!(
        LinkSet::rebuild(guard.store_ref(), &scope)
            .unwrap()
            .homes
            .len(),
        1
    );
    forget_hosted_home_recipient(&mut guard, &tenant, HOME.0).unwrap();
    assert!(LinkSet::rebuild(guard.store_ref(), &scope)
        .unwrap()
        .homes
        .is_empty());
}

// DR-0380: Home recipient copies have no key revision. A rekey must remove
// every retained account copy, including a former member's account scope.
fn home_rekey_fixture(wb: &mut crate::Workbench) -> (String, Vec<String>) {
    let people = [PERSON, "acct-former-member"];
    let tenant = crate::tenancy::provision_organization(
        wb.store_mut(),
        PERSON,
        &crate::account::account_scope(PERSON),
        "Rekey fixture",
        None,
    )
    .unwrap()
    .id;
    let tenant_scope = crate::org::tenant_scope(&tenant);
    let member = crate::org::MembershipRecord {
        id: people[1].into(),
        op: RecordOp::Upsert,
        org_id: tenant.clone(),
        authority: people[1].into(),
        email: String::new(),
        role: "member".into(),
        status: crate::org::MembershipStatus::Invited,
        managed_by_scim: false,
        team: None,
    };
    wb.write_account_record_in(&tenant_scope, "membership", &member.id, &member)
        .unwrap();
    crate::tenancy::accept_tenant_invitation_in(wb.store_mut(), people[1], &tenant)
        .unwrap()
        .unwrap();
    record_hosted_home_recipient(wb, &tenant, HOME.0, key(HOME.1).public_key().as_str(), NOW)
        .unwrap();
    record_hosted_home_recipient(
        wb,
        &tenant,
        "home:other",
        key(12).public_key().as_str(),
        NOW,
    )
    .unwrap();
    let mut scopes = Vec::new();
    for person in people {
        let scope = crate::account::account_scope(person);
        wb.write_account_record_in(&scope, "device", MAC.0, &device(MAC.0))
            .unwrap();
        let set = LinkSet::rebuild(wb.store_ref(), &scope).unwrap();
        for fact in register_recipient(&set, MAC.0, key(MAC.1).public_key().as_str(), NOW).unwrap()
        {
            fact.append(wb, &scope).unwrap();
        }
        let context = LinkContext::new(person, "openai", 1).unwrap();
        let copies = [MAC, HOME, ("home:other", 12)]
            .into_iter()
            .map(|(id, seed)| {
                seal_link_copy(
                    &context,
                    b"synthetic-provider-key",
                    &LinkRecipient::new(id, key(seed).public_key()).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = LinkSet::rebuild(wb.store_ref(), &scope).unwrap();
        for fact in put_link(&set, "openai", Some(MAC.0), &put_for_homes(0, copies), NOW).unwrap() {
            fact.append(wb, &scope).unwrap();
        }
        assert!(set.homes.contains_key(HOME.0));
        let set = LinkSet::rebuild(wb.store_ref(), &scope).unwrap();
        assert!(set.waiting("openai").is_empty());
        assert_eq!(
            open_link_copy(
                &context,
                &key(HOME.1),
                set.copy_for("openai", HOME.0).unwrap()
            )
            .unwrap(),
            b"synthetic-provider-key"
        );
        scopes.push(scope);
    }
    let mut departed = member;
    departed.status = crate::org::MembershipStatus::Deprovisioned;
    wb.write_account_record_in(&tenant_scope, "membership", &departed.id, &departed)
        .unwrap();
    (tenant, scopes)
}

#[test]
fn home_rekey_invalidates_all_accounts_and_preserves_other_recipients_and_grants() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    let mut guard = wb.lock_unpoisoned();
    let (tenant, scopes) = home_rekey_fixture(&mut guard);
    let tenant_scope = crate::org::tenant_scope(&tenant);
    let before: Vec<_> = scopes
        .iter()
        .map(|scope| LinkSet::rebuild(guard.store_ref(), scope).unwrap())
        .collect();
    let histories: Vec<_> = scopes
        .iter()
        .map(|scope| guard.store_ref().records(scope, LINK_COPY_KIND).unwrap())
        .collect();
    let keys = guard
        .store_ref()
        .records(&tenant_scope, HOSTED_HOME_RECIPIENT_KIND)
        .unwrap();
    let members = guard
        .store_ref()
        .records(&tenant_scope, "membership")
        .unwrap();
    assert!(!record_hosted_home_recipient(
        &mut guard,
        &tenant,
        HOME.0,
        key(HOME.1).public_key().as_str(),
        NOW + 1
    )
    .unwrap());
    assert_eq!(
        guard
            .store_ref()
            .records(&tenant_scope, HOSTED_HOME_RECIPIENT_KIND)
            .unwrap(),
        keys
    );
    for (scope, history) in scopes.iter().zip(&histories) {
        assert_eq!(
            &guard.store_ref().records(scope, LINK_COPY_KIND).unwrap(),
            history
        );
    }
    assert!(record_hosted_home_recipient(
        &mut guard,
        &tenant,
        HOME.0,
        key(22).public_key().as_str(),
        NOW + 2
    )
    .unwrap());
    for (index, scope) in scopes.iter().enumerate() {
        let set = LinkSet::rebuild(guard.store_ref(), scope).unwrap();
        assert!(
            set.copy_for("openai", HOME.0).is_none(),
            "old Home ciphertext still counted in an account"
        );
        assert_eq!(
            set.copy_for("openai", MAC.0),
            before[index].copy_for("openai", MAC.0)
        );
        assert_eq!(
            set.copy_for("openai", "home:other"),
            before[index].copy_for("openai", "home:other")
        );
        assert_eq!(set.links, before[index].links);
        assert_eq!(set.recipients, before[index].recipients);
        if index == 0 {
            assert_eq!(set.waiting("openai"), vec![HOME.0.to_string()]);
        }
    }
    assert_eq!(
        guard
            .store_ref()
            .records(&tenant_scope, "membership")
            .unwrap(),
        members
    );
    // The active account can reseal through the ordinary add-copies admission.
    let set = LinkSet::rebuild(guard.store_ref(), &scopes[0]).unwrap();
    let context = LinkContext::new(PERSON, "openai", 1).unwrap();
    let copy = seal_link_copy(
        &context,
        b"synthetic-provider-key",
        &LinkRecipient::new(HOME.0, key(22).public_key()).unwrap(),
    )
    .unwrap();
    for fact in add_copies(&set, "openai", 1, &[copy]).unwrap() {
        fact.append(&mut guard, &scopes[0]).unwrap();
    }
    let set = LinkSet::rebuild(guard.store_ref(), &scopes[0]).unwrap();
    assert!(set.waiting("openai").is_empty());
    assert!(
        open_link_copy(
            &context,
            &key(HOME.1),
            set.copy_for("openai", HOME.0).unwrap()
        )
        .is_err(),
        "old Home key opened the newly resealed copy"
    );
    assert_eq!(
        open_link_copy(&context, &key(22), set.copy_for("openai", HOME.0).unwrap()).unwrap(),
        b"synthetic-provider-key"
    );
}

#[test]
fn home_rekey_late_key_append_failure_rolls_back_every_account_tombstone() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    let mut guard = wb.lock_unpoisoned();
    let (tenant, scopes) = home_rekey_fixture(&mut guard);
    let before: Vec<_> = scopes
        .iter()
        .map(|scope| guard.store_ref().records(scope, LINK_COPY_KIND).unwrap())
        .collect();
    let tenant_scope = crate::org::tenant_scope(&tenant);
    let keys = guard
        .store_ref()
        .records(&tenant_scope, HOSTED_HOME_RECIPIENT_KIND)
        .unwrap();
    let fault = rusqlite::Connection::open(guard.store_ref().path()).unwrap();
    fault.execute_batch(&format!("CREATE TRIGGER refuse_rekey BEFORE INSERT ON events WHEN NEW.kind = '{HOSTED_HOME_RECIPIENT_KIND}' BEGIN SELECT RAISE(ABORT, 'synthetic late key write failure'); END;")).unwrap();
    assert!(record_hosted_home_recipient(
        &mut guard,
        &tenant,
        HOME.0,
        key(22).public_key().as_str(),
        NOW + 1
    )
    .is_err());
    assert_eq!(
        guard
            .store_ref()
            .records(&tenant_scope, HOSTED_HOME_RECIPIENT_KIND)
            .unwrap(),
        keys
    );
    for (scope, history) in scopes.iter().zip(&before) {
        assert_eq!(
            &guard.store_ref().records(scope, LINK_COPY_KIND).unwrap(),
            history
        );
    }
    fault.execute_batch("DROP TRIGGER refuse_rekey").unwrap();
    assert!(record_hosted_home_recipient(
        &mut guard,
        &tenant,
        HOME.0,
        key(22).public_key().as_str(),
        NOW + 2
    )
    .unwrap());
}

#[test]
fn home_rekey_refuses_malformed_or_unavailable_history_before_key_write() {
    struct UnavailableCopies;
    impl gaugedesk_store::ContentCodec for UnavailableCopies {
        fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
            Ok(payload.to_owned())
        }
        fn decode(&self, _: &str, kind: &str, payload: &str) -> Option<String> {
            (kind != LINK_COPY_KIND).then(|| payload.to_owned())
        }
    }
    for unavailable in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut guard = wb.lock_unpoisoned();
        let (tenant, _) = home_rekey_fixture(&mut guard);
        let tenant_scope = crate::org::tenant_scope(&tenant);
        let keys = guard
            .store_ref()
            .records(&tenant_scope, HOSTED_HOME_RECIPIENT_KIND)
            .unwrap();
        let path = guard.store_ref().path().to_owned();
        let probe = rusqlite::Connection::open(&path).unwrap();
        if unavailable {
            // Declared Store codec fault: retained ciphertext cannot be opened.
            guard.store = Store::open(&path)
                .unwrap()
                .with_codec(std::sync::Arc::new(UnavailableCopies));
        } else {
            guard
                .store_mut()
                .append_record("account::unknown-history", LINK_COPY_KIND, "not JSON")
                .unwrap();
        }
        let count: i64 = probe
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert!(record_hosted_home_recipient(
            &mut guard,
            &tenant,
            HOME.0,
            key(22).public_key().as_str(),
            NOW + 1
        )
        .is_err());
        assert_eq!(
            probe
                .query_row("SELECT count(*) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            count
        );
        assert_eq!(
            guard
                .store_ref()
                .records(&tenant_scope, HOSTED_HOME_RECIPIENT_KIND)
                .unwrap(),
            keys
        );
    }
}

#[test]
fn home_rekey_discovers_copy_accounts_past_the_first_metadata_page() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    let mut guard = wb.lock_unpoisoned();
    let (tenant, mut scopes) = home_rekey_fixture(&mut guard);
    let tenant_scope = crate::org::tenant_scope(&tenant);
    for index in 0..129 {
        let person = format!("acct-bulk-{index:03}");
        let scope = crate::account::account_scope(&person);
        let member = crate::org::MembershipRecord {
            id: person.clone(),
            op: RecordOp::Upsert,
            org_id: tenant.clone(),
            authority: person.clone(),
            email: String::new(),
            role: "member".into(),
            status: crate::org::MembershipStatus::Invited,
            managed_by_scim: false,
            team: None,
        };
        guard
            .write_account_record_in(&tenant_scope, "membership", &person, &member)
            .unwrap();
        crate::tenancy::accept_tenant_invitation_in(guard.store_mut(), &person, &tenant)
            .unwrap()
            .unwrap();
        guard
            .write_account_record_in(&scope, "device", MAC.0, &device(MAC.0))
            .unwrap();
        let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
        for fact in register_recipient(&set, MAC.0, key(MAC.1).public_key().as_str(), NOW).unwrap()
        {
            fact.append(&mut guard, &scope).unwrap();
        }
        let context = LinkContext::new(&person, "openai", 1).unwrap();
        let copies = [MAC, HOME, ("home:other", 12)]
            .into_iter()
            .map(|(id, seed)| {
                seal_link_copy(
                    &context,
                    b"synthetic-provider-key",
                    &LinkRecipient::new(id, key(seed).public_key()).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
        for fact in put_link(&set, "openai", Some(MAC.0), &put_for_homes(0, copies), NOW).unwrap() {
            fact.append(&mut guard, &scope).unwrap();
        }
        scopes.push(scope);
    }
    let first = guard
        .store_ref()
        .scope_ids_with_kind(
            LINK_COPY_KIND,
            None,
            std::num::NonZeroUsize::new(128).unwrap(),
        )
        .unwrap();
    assert_eq!(first.len(), 128);
    assert_eq!(
        guard
            .store_ref()
            .scope_ids_with_kind(
                LINK_COPY_KIND,
                first.last().map(String::as_str),
                std::num::NonZeroUsize::new(128).unwrap()
            )
            .unwrap()
            .len(),
        3
    );
    assert!(record_hosted_home_recipient(
        &mut guard,
        &tenant,
        HOME.0,
        key(22).public_key().as_str(),
        NOW + 1
    )
    .unwrap());
    for scope in scopes {
        let set = LinkSet::rebuild(guard.store_ref(), &scope).unwrap();
        assert!(
            set.copy_for("openai", HOME.0).is_none(),
            "second-page account retained old Home ciphertext"
        );
        assert!(set.copy_for("openai", MAC.0).is_some());
    }
}
