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
    /// Present for a route authored by someone else's Home. The recipient's
    /// account-root signature carries this proof to its other clients; the
    /// serving root remains the actual route author.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub author_authority: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub author_root_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_signature: Option<Signature>,
    /// The project's own statements about this route (DR-0370): its authority
    /// key signs which Home serves it and that Home's host key, and the host
    /// key signs where the Home is reachable. Absent from a route only the
    /// enclosing record's signature speaks for, and skipped so those routes'
    /// signed bytes are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<SignedPlacement>,
}

/// A project's signed placement and its host's signed locator (DR-0370 §3-4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPlacement {
    /// The project's authority public key, which signs the placement.
    pub project_key: String,
    /// The serving host's signing key, which the placement names and which
    /// signs the locator.
    pub host_key: String,
    pub placement_signature: Signature,
    pub locator_signature: Signature,
}

/// Exact bytes a project's authority key signs to place it on a Home.
pub fn placement_signing_bytes(
    project: &str,
    home_id: &HomeId,
    host_key: &str,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&("gaugedesk-project-placement-v1", project, home_id, host_key))
}

/// Exact bytes a host's key signs for where its Home is reachable.
pub fn locator_signing_bytes(
    home_id: &HomeId,
    endpoint: &str,
    relay: &Option<OpaqueRelayLocator>,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&("gaugedesk-host-locator-v1", home_id, endpoint, relay))
}

/// Attach the project's placement and the host's locator to `route`.
pub fn sign_placement(
    mut route: OpaqueHomeRoute,
    project_key: &SigningKey,
    host_key: &SigningKey,
) -> Result<OpaqueHomeRoute, serde_json::Error> {
    let host = host_key.public_key().as_str().to_owned();
    let placement_signature = project_key.sign(&placement_signing_bytes(
        &route.project,
        &route.home_id,
        &host,
    )?);
    let locator_signature = host_key.sign(&locator_signing_bytes(
        &route.home_id,
        &route.endpoint,
        &route.relay,
    )?);
    route.placement = Some(SignedPlacement {
        project_key: project_key.public_key().as_str().to_owned(),
        host_key: host,
        placement_signature,
        locator_signature,
    });
    Ok(route)
}

/// Whether `route` carries a placement by `trusted_project_key` and a locator
/// by the host key that placement names (DR-0370). The caller supplies the
/// project key it trusts: the one the owning account's root-signed entry
/// names, or the one an invitation pinned.
pub fn placement_verifies(route: &OpaqueHomeRoute, trusted_project_key: &str) -> bool {
    let Some(placement) = route.placement.as_ref() else {
        return false;
    };
    if placement.project_key != trusted_project_key || placement.host_key.is_empty() {
        return false;
    }
    let placed = placement_signing_bytes(&route.project, &route.home_id, &placement.host_key)
        .ok()
        .and_then(|bytes| {
            verify_signature(
                &bytes,
                &placement.placement_signature,
                &PublicKey::new(placement.project_key.clone()),
            )
            .ok()
        })
        .unwrap_or(false);
    let located = locator_signing_bytes(&route.home_id, &route.endpoint, &route.relay)
        .ok()
        .and_then(|bytes| {
            verify_signature(
                &bytes,
                &placement.locator_signature,
                &PublicKey::new(placement.host_key.clone()),
            )
            .ok()
        })
        .unwrap_or(false);
    placed && located
}

/// Wasm entry point: a route's placement against the project key the reader
/// trusts.
#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn placement_verifies_json(route_json: &str, trusted_project_key: &str) -> bool {
    serde_json::from_str::<OpaqueHomeRoute>(route_json)
        .map(|route| placement_verifies(&route, trusted_project_key))
        .unwrap_or(false)
}

/// Exact bytes a serving Home signs for a shared project route. Proof fields
/// are excluded so the signature cannot recursively contain itself.
pub fn home_route_signing_bytes(
    authority: &str,
    route: &OpaqueHomeRoute,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&(
        "gaugedesk-shared-home-route-v1",
        authority,
        &route.project,
        &route.home_id,
        &route.endpoint,
        &route.relay,
    ))
}

pub fn sign_home_route(
    authority: &str,
    mut route: OpaqueHomeRoute,
    signing_key: &SigningKey,
) -> Result<OpaqueHomeRoute, serde_json::Error> {
    route.author_authority = authority.to_owned();
    route.author_root_pubkey = signing_key.public_key().as_str().to_owned();
    route.author_signature = Some(signing_key.sign(&home_route_signing_bytes(authority, &route)?));
    Ok(route)
}

pub fn shared_home_route_verifies(route: &OpaqueHomeRoute) -> bool {
    let Some(signature) = route.author_signature.as_ref() else {
        return false;
    };
    if route.author_authority.is_empty() || route.author_root_pubkey.is_empty() {
        return false;
    }
    let Ok(bytes) = home_route_signing_bytes(&route.author_authority, route) else {
        return false;
    };
    verify_signature(
        &bytes,
        signature,
        &PublicKey::new(route.author_root_pubkey.clone()),
    )
    .unwrap_or(false)
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
    /// A root-signed **retraction** (ADR 0153): the latest entry for a root that
    /// withdraws its published presence. The host folds a retracted latest entry
    /// to *absent*, serving `410 Gone` on read. It is a terminal append, not a
    /// deletion — append-only (`INV-6`) is preserved and the generation fence still
    /// advances exactly once, so it cannot be replayed to un-retract and a stale
    /// retraction cannot clobber a newer publish. A retraction carries an empty
    /// routing record and empty sealed blob (see [`retraction_entry`]), so it
    /// discloses nothing beyond the already-public root pubkey. Skipped when false
    /// so every pre-retraction entry serializes byte-for-byte as before — existing
    /// signatures and canonical bytes (`INV-5`) are unchanged.
    #[serde(default, skip_serializing_if = "is_not_retracted")]
    pub retracted: bool,
    /// The computer this entry speaks for (DR-0359 §2): an account keeps one
    /// root across its computers, and each publishes and withdraws its own
    /// entry under it, fenced by its own generation, without overwriting
    /// another's. Empty is the one entry a root had before per-computer
    /// entries, and is skipped so those entries' signed bytes are unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
}

/// `serde` skip predicate: a non-retracted entry omits the `retracted` field entirely,
/// so its signed bytes match those written before retraction existed.
fn is_not_retracted(retracted: &bool) -> bool {
    !*retracted
}

/// The canonical **retraction** entry for `root_pubkey` at `generation` (ADR 0153): an
/// empty routing record and empty sealed blob with `retracted` set, so the record itself
/// discloses nothing beyond the already-public root pubkey. Sign it with [`sign_entry`]
/// under the root key and publish it like any other generation-advancing entry; the host
/// folds a retracted latest entry to `410 Gone`.
pub fn retraction_entry(root_pubkey: String, generation: u64) -> DirectoryEntry {
    device_retraction_entry(root_pubkey, String::new(), generation)
}

/// The retraction of one computer's entry under `root_pubkey` (DR-0359 §2):
/// signing out withdraws that computer's routes and leaves the account's other
/// computers' entries standing.
pub fn device_retraction_entry(
    root_pubkey: String,
    device: String,
    generation: u64,
) -> DirectoryEntry {
    DirectoryEntry {
        generation,
        directory: DirectoryRecord {
            root_pubkey,
            device_pubkeys: Vec::new(),
            placement_pointers: Vec::new(),
            home_routes: Vec::new(),
        },
        sealed_blob: String::new(),
        retracted: true,
        device,
    }
}

/// Whether a (verified) entry is a retraction — the host serves `410 Gone` for a root
/// whose latest entry is one (ADR 0153).
pub fn is_retraction(entry: &DirectoryEntry) -> bool {
    entry.retracted
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

/// A statement, signed by an account's outgoing root, that `to` replaces it
/// (ADR 0133 §3, DR-0361 §1). A client that pinned `from` follows it to `to`
/// instead of raising the changed-root alarm.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootTransition {
    pub from: String,
    pub to: String,
    pub issued_at_ms: u64,
    pub signature: Signature,
}

/// Exact bytes the outgoing root signs for a transition.
pub fn root_transition_signing_bytes(
    from: &str,
    to: &str,
    issued_at_ms: u64,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&("gaugedesk-root-transition-v1", from, to, issued_at_ms))
}

/// Sign the replacement of `outgoing`'s root by `to`.
pub fn sign_root_transition(
    to: &str,
    issued_at_ms: u64,
    outgoing: &SigningKey,
) -> Result<RootTransition, serde_json::Error> {
    let from = outgoing.public_key().as_str().to_owned();
    let signature = outgoing.sign(&root_transition_signing_bytes(&from, to, issued_at_ms)?);
    Ok(RootTransition {
        from,
        to: to.to_owned(),
        issued_at_ms,
        signature,
    })
}

/// Whether a transition names two different roots and is signed by the one it
/// replaces.
pub fn root_transition_verifies(transition: &RootTransition) -> bool {
    if transition.from.is_empty() || transition.to.is_empty() || transition.from == transition.to {
        return false;
    }
    let Ok(bytes) =
        root_transition_signing_bytes(&transition.from, &transition.to, transition.issued_at_ms)
    else {
        return false;
    };
    verify_signature(
        &bytes,
        &transition.signature,
        &PublicKey::new(transition.from.clone()),
    )
    .unwrap_or(false)
}

/// Whether `current` is reached from `pinned` by following verified
/// transitions in order. Equal roots need no chain; a broken, unsigned or
/// unrelated link reaches nothing.
pub fn root_chain_reaches(pinned: &str, current: &str, chain: &[RootTransition]) -> bool {
    if pinned == current {
        return true;
    }
    let mut at = pinned;
    for transition in chain {
        if transition.from != at {
            continue;
        }
        if !root_transition_verifies(transition) {
            return false;
        }
        at = &transition.to;
        if at == current {
            return true;
        }
    }
    false
}

/// Wasm entry point for clients following a pinned root to the current one.
#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn root_chain_reaches_json(pinned: &str, current: &str, chain_json: &str) -> bool {
    serde_json::from_str::<Vec<RootTransition>>(chain_json)
        .map(|chain| root_chain_reaches(pinned, current, &chain))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_root_follows_only_signed_transitions_to_the_current_one() {
        let (a, b, c) = (signer(1), signer(2), signer(3));
        let (ka, kb, kc) = (
            a.public_key().as_str().to_owned(),
            b.public_key().as_str().to_owned(),
            c.public_key().as_str().to_owned(),
        );
        let ab = sign_root_transition(&kb, 1, &a).unwrap();
        let bc = sign_root_transition(&kc, 2, &b).unwrap();
        assert!(root_transition_verifies(&ab));
        assert!(root_chain_reaches(&ka, &ka, &[]));
        assert!(root_chain_reaches(&ka, &kc, &[ab.clone(), bc.clone()]));
        assert!(root_chain_reaches(&kb, &kc, &[ab.clone(), bc.clone()]));
        assert!(
            !root_chain_reaches(&ka, &kc, std::slice::from_ref(&ab)),
            "an unfinished chain"
        );
        assert!(
            !root_chain_reaches(&kc, &ka, &[ab.clone(), bc.clone()]),
            "never backwards"
        );

        // Signed by the incoming key instead of the outgoing one.
        let forged = RootTransition {
            from: ka.clone(),
            to: kb.clone(),
            issued_at_ms: 1,
            signature: b.sign(&root_transition_signing_bytes(&ka, &kb, 1).unwrap()),
        };
        assert!(!root_transition_verifies(&forged));
        assert!(!root_chain_reaches(&ka, &kb, &[forged]));
        let mut retargeted = ab.clone();
        retargeted.to = kc.clone();
        assert!(
            !root_chain_reaches(&ka, &kc, &[retargeted]),
            "the target is signed"
        );
    }

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
                    author_authority: String::new(),
                    author_root_pubkey: String::new(),
                    author_signature: None,
                    placement: None,
                }],
            },
            sealed_blob: "deadbeef".into(),
            retracted: false,
            device: String::new(),
        }
    }

    #[test]
    fn a_placement_binds_the_project_to_its_home_and_the_host_to_its_locator() {
        let (project, host) = (signer(21), signer(22));
        let project_key = project.public_key().as_str().to_owned();
        let route = OpaqueHomeRoute {
            project: "project-placed".into(),
            home_id: HomeId::new("home:placed"),
            endpoint: "https://home.example".into(),
            relay: None,
            author_authority: String::new(),
            author_root_pubkey: String::new(),
            author_signature: None,
            placement: None,
        };
        assert!(!placement_verifies(&route, &project_key), "nothing placed");
        let placed = sign_placement(route, &project, &host).unwrap();
        assert!(placement_verifies(&placed, &project_key));
        assert!(
            !placement_verifies(&placed, signer(23).public_key().as_str()),
            "only against the project key the reader trusts"
        );

        // The host alone may move where its Home is reachable...
        let mut moved = placed.clone();
        moved.endpoint = "https://elsewhere.example".into();
        assert!(!placement_verifies(&moved, &project_key));
        let relocated = sign_placement(moved.clone(), &project, &host).unwrap();
        assert!(placement_verifies(&relocated, &project_key));

        // ...and the project alone which Home and host serve it.
        let mut rehomed = placed.clone();
        rehomed.home_id = HomeId::new("home:other");
        assert!(!placement_verifies(&rehomed, &project_key));
        let mut other_host = placed;
        other_host.placement.as_mut().unwrap().host_key = signer(24).public_key().as_str().into();
        assert!(!placement_verifies(&other_host, &project_key));
    }

    #[test]
    fn a_shared_home_route_is_bound_to_its_author_and_every_reachability_field() {
        let key = signer(9);
        let route = OpaqueHomeRoute {
            project: "project-shared".into(),
            home_id: HomeId::new("home:root-p256:host"),
            endpoint: "https://home.example".into(),
            relay: None,
            author_authority: String::new(),
            author_root_pubkey: String::new(),
            author_signature: None,
            placement: None,
        };
        let signed = sign_home_route("root-p256:host", route, &key).unwrap();
        assert!(shared_home_route_verifies(&signed));

        let mut redirected = signed.clone();
        redirected.endpoint = "https://attacker.example".into();
        assert!(!shared_home_route_verifies(&redirected));

        let mut renamed = signed;
        renamed.author_authority = "root-p256:attacker".into();
        assert!(!shared_home_route_verifies(&renamed));
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
    fn a_signed_retraction_verifies_and_discloses_no_routing() {
        let key = signer(7);
        let root = key.public_key().as_str().to_string();
        let put = sign_entry(retraction_entry(root.clone(), 3), &key).unwrap();
        // Round-trips, verifies under the root's own key, and is recognizable as a retraction.
        let json = serde_json::to_string(&put).unwrap();
        let decoded: SignedDirectoryPut = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, put);
        assert!(put_verifies(&decoded));
        assert!(is_retraction(&decoded.entry));
        // The retraction record itself carries no routing beyond the (already public) root.
        assert_eq!(decoded.entry.directory.root_pubkey, root);
        assert!(decoded.entry.directory.device_pubkeys.is_empty());
        assert!(decoded.entry.directory.placement_pointers.is_empty());
        assert!(decoded.entry.directory.home_routes.is_empty());
        assert!(decoded.entry.sealed_blob.is_empty());
    }

    /// The retraction's bytes, pinned the way a publish's are — and for a
    /// sharper reason. A publish's shape predates every deployed verifier; the
    /// retraction's does not, so the hosted directory carries a *compiled* copy
    /// of this contract that can be older than this crate. A verifier that does
    /// not know a field does not reject the entry: serde drops it, re-serializes
    /// without it, and reports a signature mismatch, which reaches a person as
    /// `401 invalid root signature` — indistinguishable from a wrong key. That
    /// is what production did to every retraction until it was redeployed on
    /// 2026-09-23 (gaugewright-cloud#332).
    ///
    /// So these are not decorative bytes. They are the exact message a deployed
    /// verifier must reproduce to admit a withdrawal, and changing them obliges
    /// a redeploy before any client that signs the new shape can retract.
    #[test]
    fn a_retraction_has_canonical_bytes_too() {
        let key = signer(7);
        let root = key.public_key().as_str().to_string();
        assert_eq!(
            String::from_utf8(signing_bytes(&retraction_entry(root, 5)).unwrap()).unwrap(),
            format!(
                "{{\"generation\":5,\"directory\":{{\"root_pubkey\":\"{}\",\"device_pubkeys\":[],\"placement_pointers\":[],\"home_routes\":[]}},\"sealed_blob\":\"\",\"retracted\":true}}",
                key.public_key()
            ),
        );
    }

    /// A computer's own entry (DR-0359 §2). Pinned for the same reason as the
    /// retraction's bytes: a deployed verifier older than this field drops it
    /// and reports a signature mismatch, so the hosted directory is redeployed
    /// before any computer signs an entry naming itself.
    #[test]
    fn a_computers_entry_names_it_inside_the_signature() {
        let key = signer(7);
        let root = key.public_key().as_str().to_string();
        assert_eq!(
            String::from_utf8(
                signing_bytes(&device_retraction_entry(root.clone(), "device-a".into(), 2)).unwrap()
            )
            .unwrap(),
            format!(
                "{{\"generation\":2,\"directory\":{{\"root_pubkey\":\"{root}\",\"device_pubkeys\":[],\"placement_pointers\":[],\"home_routes\":[]}},\"sealed_blob\":\"\",\"retracted\":true,\"device\":\"device-a\"}}",
            ),
        );

        let mut own = entry(root.clone());
        own.device = "device-a".into();
        let put = sign_entry(own, &key).unwrap();
        assert!(put_verifies(&put));
        let decoded: SignedDirectoryPut =
            serde_json::from_str(&serde_json::to_string(&put).unwrap()).unwrap();
        assert_eq!(decoded.entry.device, "device-a");

        // An intermediary cannot file one computer's entry under another.
        let mut moved = put;
        moved.entry.device = "device-b".into();
        assert!(!put_verifies(&moved));
    }

    #[test]
    fn flipping_the_retracted_flag_after_signing_fails_closed() {
        let key = signer(7);
        // A publish cannot be turned into a retraction (or vice versa) by an intermediary:
        // the flag is inside the signed bytes.
        let mut put = sign_entry(entry(key.public_key().as_str().into()), &key).unwrap();
        put.entry.retracted = true;
        assert!(!put_verifies(&put));

        let root = key.public_key().as_str().to_string();
        let mut retraction = sign_entry(retraction_entry(root, 1), &key).unwrap();
        retraction.entry.retracted = false;
        assert!(!put_verifies(&retraction));
    }

    #[test]
    fn a_non_retracted_entry_serializes_without_the_flag() {
        // Byte-compat: `retracted:false` is skipped, so pre-retraction signatures are unchanged.
        let key = signer(7);
        let bytes = signing_bytes(&entry(key.public_key().as_str().into())).unwrap();
        assert!(!String::from_utf8(bytes).unwrap().contains("retracted"));
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
