//! Canonical blind-directory wire and signing contract.
//!
//! The account client and edge host both use this crate. Storage and HTTP
//! routing deliberately remain outside it: this boundary owns only the exact
//! JSON shape, canonical signing bytes, and fail-closed P-256 verification.

use gaugedesk_core::ids::{HomeId, PublicKey};
use gaugedesk_core::signature::{verify_signature, Signature, SigningKey};
use serde::{Deserialize, Serialize};

/// Blind durable reachability metadata. Possession permits a tunnel attempt
/// only; the pinned inner TLS certificate and Home admission remain required.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueRelayLocator {
    /// Canonical provider-TLS origin of the shared relay fabric.
    pub endpoint: String,
    /// Stable opaque Durable Object selector, base64url without padding.
    pub handle: String,
    /// Rotatable route proof, base64url without padding. Possession grants a
    /// tunnel attempt only and is not Home admission.
    pub proof: String,
    pub route_epoch: u64,
    /// Lowercase SHA-256 certificate fingerprint.
    pub home_fingerprint: String,
}

/// The only project information the blind account plane may publish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueHomeRoute {
    pub project: String,
    pub home_id: HomeId,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<OpaqueRelayLocator>,
}

/// Readable identity and opaque routing facts stored by the blind directory.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectoryRecord {
    pub root_pubkey: String,
    pub device_pubkeys: Vec<String>,
    pub placement_pointers: Vec<String>,
    #[serde(default)]
    pub home_routes: Vec<OpaqueHomeRoute>,
}

/// One appendable directory value: readable routing plus sealed account state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Root-signed optimistic generation. New publishes start at one and advance
    /// exactly once from the current directory head. Zero is read-only
    /// compatibility for entries written before replay fencing was introduced.
    #[serde(default)]
    pub generation: u64,
    pub directory: DirectoryRecord,
    /// Opaque hex ciphertext. The directory never opens this value.
    pub sealed_blob: String,
}

/// A root-authorized append request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedDirectoryPut {
    pub entry: DirectoryEntry,
    pub signature: Signature,
}

/// Exact bytes signed by clients and verified by the directory host.
///
/// Serialization cannot fail for this closed wire type. Returning a `Result`
/// keeps an allocation/serialization failure fail-closed instead of silently
/// signing or verifying an empty message.
pub fn signing_bytes(entry: &DirectoryEntry) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(entry)
}

/// Sign an entry with the account root key.
pub fn sign_entry(
    entry: DirectoryEntry,
    signing_key: &SigningKey,
) -> Result<SignedDirectoryPut, serde_json::Error> {
    let signature = signing_key.sign(&signing_bytes(&entry)?);
    Ok(SignedDirectoryPut { entry, signature })
}

/// Verify a publish under the root public key named by its own entry.
pub fn put_verifies(put: &SignedDirectoryPut) -> bool {
    let Ok(bytes) = signing_bytes(&put.entry) else {
        return false;
    };
    let pubkey = PublicKey::new(put.entry.directory.root_pubkey.clone());
    verify_signature(&bytes, &put.signature, &pubkey).unwrap_or(false)
}

/// Wasm host entry point. Edge TypeScript may bind HTTP and SQLite but cannot
/// independently reproduce or weaken the signing contract.
#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn verify_signed_put_json(json: &str) -> bool {
    serde_json::from_str::<SignedDirectoryPut>(json)
        .map(|put| put_verifies(&put))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_seed(&[seed; 32]).expect("valid deterministic test key")
    }

    fn entry(root: String) -> DirectoryEntry {
        DirectoryEntry {
            generation: 1,
            directory: DirectoryRecord {
                root_pubkey: root,
                device_pubkeys: vec!["device".into()],
                placement_pointers: vec!["wss://relay.example/opaque".into()],
                home_routes: vec![OpaqueHomeRoute {
                    project: "project-route".into(),
                    home_id: HomeId::new("home:opaque"),
                    endpoint: String::new(),
                    relay: None,
                }],
            },
            sealed_blob: "deadbeef".into(),
        }
    }

    #[test]
    fn signed_wire_round_trips_and_verifies() {
        let key = signer(7);
        let put = sign_entry(entry(key.public_key().as_str().into()), &key).unwrap();
        let json = serde_json::to_string(&put).unwrap();
        let decoded: SignedDirectoryPut = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, put);
        assert!(put_verifies(&decoded));
    }

    #[test]
    fn mutation_and_foreign_root_fail_closed() {
        let key = signer(7);
        let mut put = sign_entry(entry(key.public_key().as_str().into()), &key).unwrap();
        put.entry.sealed_blob.push('0');
        assert!(!put_verifies(&put));

        let mut foreign = sign_entry(entry(key.public_key().as_str().into()), &key).unwrap();
        foreign.entry.directory.root_pubkey = signer(9).public_key().as_str().into();
        assert!(!put_verifies(&foreign));
    }

    #[test]
    fn canonical_bytes_are_stable() {
        let key = signer(7);
        let value = entry(key.public_key().as_str().into());
        assert_eq!(
            String::from_utf8(signing_bytes(&value).unwrap()).unwrap(),
            format!(
                "{{\"generation\":1,\"directory\":{{\"root_pubkey\":\"{}\",\"device_pubkeys\":[\"device\"],\"placement_pointers\":[\"wss://relay.example/opaque\"],\"home_routes\":[{{\"project\":\"project-route\",\"home_id\":\"home:opaque\"}}]}},\"sealed_blob\":\"deadbeef\"}}",
                key.public_key()
            )
        );
    }

    #[test]
    fn legacy_entry_reads_as_generation_zero_but_new_signatures_bind_generation() {
        let key = signer(7);
        let legacy = format!(
            "{{\"directory\":{{\"root_pubkey\":\"{}\",\"device_pubkeys\":[],\"placement_pointers\":[],\"home_routes\":[]}},\"sealed_blob\":\"00\"}}",
            key.public_key()
        );
        let decoded: DirectoryEntry = serde_json::from_str(&legacy).unwrap();
        assert_eq!(decoded.generation, 0);

        let mut put = sign_entry(entry(key.public_key().as_str().into()), &key).unwrap();
        put.entry.generation = 2;
        assert!(!put_verifies(&put));
    }
}
