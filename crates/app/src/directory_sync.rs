//! Library sync — the account-side **blind-directory client** (`ADR 0054` / the `library_sync`
//! facility, `ADR 0077`). The device holding the account root key publishes its **sealed account
//! blob** + a **readable directory record** to the always-on blind directory
//! ([`crate::account::AccountBlob`] / [`crate::account::DirectoryRecord`]), so the person's other
//! (enrolled) devices can pull their account state — devices, settings, the sealed linked model
//! key — even with the first machine off. The directory stores the blob **opaquely** (`INV-10`);
//! only a device holding the shared account key can open it.
//!
//! This is the **client** half of the deployed directory *service* (`gaugewright-directory`,
//! `PUT/GET /directory/:root`): it signs the publish with the root key (only the root may
//! overwrite its own record) and fetches the opaque record back. The wire shapes
//! ([`DirectoryEntry`] / [`SignedDirectoryPut`] / [`signing_bytes`]) mirror the service exactly —
//! same [`DirectoryRecord`] + `serde_json`, so the signatures agree — and are the canonical
//! definitions the service should import (a byte-compatible unify is owed).
//!
//! It runs where the **root key lives** — the desktop workbench (the hosted hub authenticates a
//! person via OIDC and holds no sovereign keypair, so it does not publish). The facility flag in
//! the person's account scope says whether sync is on.

use gaugewright_core::signature::SigningKey;
pub use gaugewright_directory_protocol::{
    put_verifies, signing_bytes, DirectoryEntry, SignedDirectoryPut,
};

use crate::account::{directory_record, seal_account_blob, Account};
use crate::key_store::KeyStore; // brings the `signing_key` trait method into scope
use crate::net_http::HttpClient;

/// Build the signed publish for the account rooted at `signing_key`: seal the account blob under
/// the account `key`, assemble the readable directory record (root pubkey + active device
/// pubkeys + placement pointers), and sign it with the root key. Pure (no I/O), so it is testable
/// against the same [`verify_signature`] the service runs. `None` if the blob fails to seal.
pub fn signed_put(
    signing_key: &SigningKey,
    key: [u8; 32],
    acct: &Account,
    generation: u64,
    placement_pointers: Vec<String>,
    home_routes: Vec<crate::home::OpaqueHomeRoute>,
) -> Option<SignedDirectoryPut> {
    if generation == 0 {
        return None;
    }
    let root_pubkey = signing_key.public_key().as_str().to_string();
    let entry = DirectoryEntry {
        generation,
        directory: directory_record(&root_pubkey, acct, placement_pointers, home_routes),
        sealed_blob: seal_account_blob(key, acct)?,
    };
    gaugewright_directory_protocol::sign_entry(entry, signing_key).ok()
}

/// Publish a signed record to the blind directory (`PUT {base}/directory/:root`). `base` is the
/// directory service origin (e.g. `https://…:7901`). A non-2xx status is an error.
pub fn publish(http: &HttpClient, base: &str, put: &SignedDirectoryPut) -> Result<(), String> {
    let root = &put.entry.directory.root_pubkey;
    let url = format!("{}/directory/{}", base.trim_end_matches('/'), root);
    let body = serde_json::to_string(put).map_err(|e| format!("serialize: {e}"))?;
    let (status, resp) = http.put_json(&url, &body)?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("directory publish HTTP {status}: {resp}"))
    }
}

/// Fetch the readable record + opaque sealed blob for `root` (`GET {base}/directory/:root`).
/// `Ok(None)` when the directory has nothing for `root` (404). The blob stays sealed — the caller
/// opens it with [`crate::account::open_account_blob`] under the account key.
pub fn fetch(http: &HttpClient, base: &str, root: &str) -> Result<Option<DirectoryEntry>, String> {
    let url = format!("{}/directory/{}", base.trim_end_matches('/'), root);
    match http.get_string(&url) {
        Ok(body) => {
            let entry = serde_json::from_str(&body).map_err(|e| format!("parse entry: {e}"))?;
            Ok(Some(entry))
        }
        // get_string errors on non-2xx; a 404 (no record yet) is not a failure.
        Err(e) if e.contains("HTTP 404") => Ok(None),
        Err(e) => Err(e),
    }
}

impl crate::Workbench {
    /// Whether the `library_sync` facility is active for this account (`ADR 0077`). The store-side
    /// gate the publish/pull halves check; sync is off unless the person attached it.
    pub fn library_sync_active(&self) -> bool {
        crate::facility::Facilities::rebuild_account(self.store_ref())
            .map(|f| f.has_active(crate::facility::FacilityKind::LibrarySync))
            .unwrap_or(false)
    }

    /// The account root pubkey this workbench publishes under (its governance key) — the directory
    /// path/identity for [`fetch`].
    pub fn library_sync_root(&self) -> String {
        self.governance_public_key().as_str().to_string()
    }

    /// The signed publish for the current account state, **iff** library sync is active — built
    /// under the workbench lock (store + root key), so the caller can then publish it over the
    /// network *off* the lock. `None` when sync is off or the blob fails to seal.
    pub fn library_sync_signed_put(&self, generation: u64) -> Option<SignedDirectoryPut> {
        if !self.library_sync_active() {
            return None;
        }
        let signing_key = crate::key_store::FileKeyStore::new(self.root_path().join("keys"))
            .signing_key(self.authority());
        let acct = Account::rebuild(self.store_ref()).ok()?;
        let home_routes = acct.home_routes.values().cloned().map(Into::into).collect();
        signed_put(
            &signing_key,
            self.account_key(),
            &acct,
            generation,
            vec![],
            home_routes,
        )
    }

    /// Merge a fetched directory entry's sealed blob into the local account scope (the pull half):
    /// open it under this account's key and upsert its devices/settings/credentials (latest-wins
    /// fold). Returns how many records merged; errors if the blob does not open (a foreign key).
    pub fn library_sync_apply(&mut self, entry: &DirectoryEntry) -> Result<usize, String> {
        use crate::account::{open_account_blob, ACCOUNT_SCOPE};
        let blob = open_account_blob(self.account_key(), &entry.sealed_blob)
            .ok_or_else(|| "sealed blob did not open under this account key".to_string())?;
        let mut n = 0usize;
        for d in &blob.devices {
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "device", &d.id, d)
                .is_ok()
            {
                n += 1;
            }
        }
        for c in &blob.credentials {
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "credential", &c.id, c)
                .is_ok()
            {
                n += 1;
            }
        }
        for home in &blob.homes {
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "home", home.id.as_str(), home)
                .is_ok()
            {
                n += 1;
            }
        }
        for route in &entry.directory.home_routes {
            let record = crate::account::HomeRouteRecord {
                id: route.project.clone(),
                op: crate::account::RecordOp::Upsert,
                home_id: route.home_id.clone(),
                endpoint: route.endpoint.clone(),
                relay: route.relay.clone(),
            };
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "home_route", &record.id, &record)
                .is_ok()
            {
                n += 1;
            }
        }
        for (id, value) in &blob.settings {
            let rec = crate::account::SettingRecord {
                id: id.clone(),
                op: crate::account::RecordOp::Upsert,
                value: value.clone(),
            };
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "setting", id, &rec)
                .is_ok()
            {
                n += 1;
            }
        }
        Ok(n)
    }
}

/// Canonical public blind-directory origin. Development and hermetic tests may
/// override it with `GAUGEWRIGHT_DIRECTORY_URL`; a release never silently
/// disables account sync because an environment variable was omitted.
pub const DIRECTORY_URL: &str = "https://directory.gaugewright.com";

pub fn directory_url_from_env() -> String {
    std::env::var("GAUGEWRIGHT_DIRECTORY_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DIRECTORY_URL.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{open_account_blob, DeviceRecord, DeviceStatus, RecordOp, SettingRecord};

    fn seeded_account() -> Account {
        let mut a = Account::default();
        a.devices.insert(
            "phone".into(),
            DeviceRecord {
                id: "phone".into(),
                op: RecordOp::Upsert,
                label: "My phone".into(),
                subkey_pubkey: "dev-pub-1".into(),
                status: DeviceStatus::Active,
                enrolled_at: 1_700_000_000,
            },
        );
        a.settings.insert(
            "theme".into(),
            SettingRecord {
                id: "theme".into(),
                op: RecordOp::Upsert,
                value: "dark".into(),
            },
        );
        a
    }

    #[test]
    fn canonical_directory_origin_is_public_tls() {
        assert_eq!(DIRECTORY_URL, "https://directory.gaugewright.com");
    }

    fn key() -> SigningKey {
        SigningKey::from_seed(&[7u8; 32]).unwrap()
    }

    /// A fixed account (sealing) key for these tests — distinct from the signing key.
    const AKEY: [u8; 32] = [11u8; 32];
    const OTHER_AKEY: [u8; 32] = [22u8; 32];

    #[test]
    fn signed_put_verifies_under_its_own_root_key() {
        // The signature the client produces passes the exact check the directory service runs at
        // PUT — so a real publish would be accepted (and a forged one rejected).
        let k = key();
        let put = signed_put(&k, AKEY, &seeded_account(), 1, vec![], vec![]).expect("seals");
        assert_eq!(put.entry.generation, 1);
        assert_eq!(put.entry.directory.root_pubkey, k.public_key().as_str());
        assert!(put_verifies(&put), "verifies under its own root key");

        // Tampering with the entry (a different device pubkey) breaks the signature (fail-closed).
        let mut forged = put.clone();
        forged.entry.directory.device_pubkeys = vec!["attacker".into()];
        assert!(!put_verifies(&forged));
        assert!(
            signed_put(&k, AKEY, &seeded_account(), 0, vec![], vec![]).is_none(),
            "generation zero is reserved for reading legacy entries"
        );
    }

    #[test]
    fn the_directory_record_carries_no_secrets_and_the_blob_round_trips() {
        // The readable record is routing-only (root + device pubkeys); the settings/credentials
        // live only inside the sealed blob, which opens only under the same account key.
        let put = signed_put(
            &key(),
            AKEY,
            &seeded_account(),
            7,
            vec!["relay://x".into()],
            vec![],
        )
        .expect("seals");
        assert_eq!(
            put.entry.directory.device_pubkeys,
            vec!["dev-pub-1".to_string()]
        );
        assert_eq!(
            put.entry.directory.placement_pointers,
            vec!["relay://x".to_string()]
        );
        // the sealed blob is opaque hex, not the plaintext settings.
        assert!(!put.entry.sealed_blob.contains("dark"));
        // the same account key opens it back to the account metadata.
        let blob = open_account_blob(AKEY, &put.entry.sealed_blob).expect("opens");
        assert_eq!(blob.settings.get("theme").map(String::as_str), Some("dark"));
        assert_eq!(blob.devices.len(), 1);
        // a different account key cannot open it (fail-closed).
        assert!(open_account_blob(OTHER_AKEY, &put.entry.sealed_blob).is_none());
    }
}
