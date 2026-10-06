//! DR-0334 cross-language vector for a provider link's per-device copy.
//!
//! The browser seals a link for every trusted device before submitting it, and
//! a desktop opens its own copy, so the two constructions must agree byte for
//! byte. `account-link-seal-vector.json` holds one copy sealed by each side to
//! the same device key; each side's test opens the other's. To regenerate,
//! run `print_account_link_vector` in `account_link_seal.rs` for `rust_copy`,
//! and seal `browser_copy` with `sealLinkCopy` in
//! `web/packages/control-plane-client/src/account-link-seal.ts`.

use gaugedesk_app::account_link_seal::{
    open_link_copy, LinkContext, LinkRecipientPrivateKey, SealedLinkCopy,
};

#[derive(serde::Deserialize)]
struct Vector {
    recipient_private_seed_hex: String,
    recipient_public_key_hex: String,
    account: String,
    provider: String,
    version: u64,
    secret: String,
    rust_copy: SealedLinkCopy,
    browser_copy: SealedLinkCopy,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!("account-link-seal-vector.json")).expect("vector parses")
}

fn device(vector: &Vector) -> LinkRecipientPrivateKey {
    let seed: [u8; 32] = hex::decode(&vector.recipient_private_seed_hex)
        .expect("seed is hex")
        .try_into()
        .expect("seed is 32 bytes");
    LinkRecipientPrivateKey::from_seed(seed).expect("seed is a key")
}

#[test]
fn the_device_opens_the_copy_the_browser_sealed() {
    let vector = vector();
    let key = device(&vector);
    assert_eq!(key.public_key().as_str(), vector.recipient_public_key_hex);
    let context = LinkContext::new(&vector.account, &vector.provider, vector.version).unwrap();
    for (side, copy) in [
        ("browser", &vector.browser_copy),
        ("rust", &vector.rust_copy),
    ] {
        let opened = open_link_copy(&context, &key, copy)
            .unwrap_or_else(|error| panic!("the {side} copy did not open: {error:?}"));
        assert_eq!(opened, vector.secret.as_bytes(), "{side}");
    }
}

#[test]
fn the_browsers_copy_is_bound_to_its_version() {
    let vector = vector();
    let stale = LinkContext::new(&vector.account, &vector.provider, vector.version - 1).unwrap();
    assert!(open_link_copy(&stale, &device(&vector), &vector.browser_copy).is_err());
}
