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
