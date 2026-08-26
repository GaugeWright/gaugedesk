//! Federation pairing + crossing over the network (M4 / D-REMOTE / `SERVE-1`).
//!
//! Turns the proven seams — [`net_tls`](crate::net_tls) (cert-pinned TLS),
//! [`net_server`](crate::net_server) (the TOFU pin registry), the rendezvous broker
//! (the WSS crossing integration tests), and the verified
//! [`gaugedesk_core::federation`] crossing reducer — into a runnable surface a person
//! and Playwright can drive between two machines:
//!
//! 1. **Pairing ticket** — the owner mints a [`PairingTicket`] describing itself
//!    (authority id, governance public key, TLS-cert fingerprint, broker address,
//!    scope, expiry). It travels out-of-band (`INV-7`: no global directory).
//! 2. **Pair (TOFU)** — the peer accepts the ticket: it pins the ticket's
//!    governance key into a [`BridgeGrant`](gaugedesk_core::bridge_grant::BridgeGrant)
//!    and the cert fingerprint into the [`PinnedTlsClientConfig`], so every later
//!    crossing is verified against *these pinned values* (`INV-21`, C-1).
//! 3. **Receiver loop** — for each paired peer, a task dials the broker on a derived
//!    inbox token, completes the cert-pinned TLS handshake (this side is the TLS
//!    server), receives a signed crossing, and admits it through the
//!    [`CrossingState`](gaugedesk_core::federation::CrossingState) reducer **against the
//!    pinned grant** — only the target's admission writes the fact (`INV-13`).
//! 4. **Cross** — the source signs a handle with its governance key and sends it
//!    over the TLS leg; the verified, grant-pinned admission happens on the peer.
//!
//! The crossing's security teeth (cert pin, source-key pin, grant validity,
//! signature) are exactly the ones the loopback/harness tests prove; only the
//! transport — a real TLS session through the blind broker — is new.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;

use gaugedesk_core::bridge_grant::BridgeGrant;
use gaugedesk_core::delegation::{DeviceDelegation, SubkeyRevocation};
use gaugedesk_core::federated_delivery::{
    DeliveryCommand, DeliveryEnvelope, DeliveryPhase, DeliveryState,
};
use gaugedesk_core::federation::{CrossingCommand, CrossingEnvelope, CrossingState};
use gaugedesk_core::handoff::{self, HandoffCommand, HandoffEvent, HandoffPhase, HandoffState};
use gaugedesk_core::ids::{AuthorityId, BridgeGrantId, DeviceId, HomeId, KeyId, Nonce, PublicKey};
use gaugedesk_core::review::{ReviewCommand, ReviewState};
use gaugedesk_core::run::{RunCommand, RunState};
use gaugedesk_core::signature::{verify_signature, SigningKey};
use gaugedesk_relay_transport::{connect_one_shot, BoxedRelayByteStream, OneShotLeg};
use gaugedesk_store::Store;

use crate::device_enroll::{open_sealed, seal_to_subkey, SealedKey};
use crate::key_store::{FileKeyStore, KeyStore};
use crate::library::LIBRARY_SCOPE;
use crate::net_server::{CertFingerprint, PinnedTlsClientConfig};
use crate::net_tls::{tls_accept, tls_connect, TlsIdentity};
use crate::stream::ServerEvent;
use crate::{io, LockUnpoisoned, SharedWorkbench, Workbench};

/// The fixed rendezvous session-token width (matches the broker). Tokens are
/// opaque routing metadata, never payload.
const TOKEN_LEN: usize = 32;

/// The stable scope federated facts are recorded into, so `GET /federation/inbox`
/// can list what crossed in (the demo's far-side evidence).
pub const FED_INBOX_SCOPE: &str = "federation::inbox";

impl Workbench {
    /// Set this control plane's authority identity (`SERVE-1`). Federation tests
    /// and fixtures set it explicitly so two in-process workbenches can stand in
    /// for two machines.
    pub fn with_authority(mut self, authority: AuthorityId) -> Self {
        self.home_id = HomeId::new(format!("home:{}", authority.as_str()));
        self.authority = authority;
        self
    }

    /// Set the state root where federation key/TLS stores live. Builder-style;
    /// startup sets it from the resolved root, federation tests set it explicitly.
    pub fn with_root(mut self, root: impl Into<std::path::PathBuf>) -> Self {
        self.root = root.into();
        self
    }

    /// Attach federation state (`SERVE-1`). Startup does this from env;
    /// integration tests inject two instances pointed at a shared broker.
    pub fn with_federation(mut self, federation: Federation) -> Self {
        self.federation = Some(federation);
        self
    }

    pub(crate) fn apply_startup_federation(&mut self, federation: Federation) {
        self.federation = Some(federation);
    }

    /// This control plane's network federation state (`SERVE-1`), or `None` for a
    /// deliberately minimal in-memory test workbench.
    pub fn federation_ref(&self) -> Option<&Federation> {
        self.federation.as_ref()
    }

    /// Mutable federation state; pairing and handoff routes pin peers through this.
    pub fn federation_mut(&mut self) -> Option<&mut Federation> {
        self.federation.as_mut()
    }

    /// The governance-root identity exposed at a cross-authority edge. A Home's
    /// local ownership alias is deliberately not a federation identity: fresh
    /// installations may all begin as `local-user`, while their independently
    /// generated governance roots are globally distinct.
    pub fn federation_authority(&self) -> &AuthorityId {
        self.federation
            .as_ref()
            .map(|federation| &federation.authority)
            .unwrap_or(&self.authority)
    }

    /// Public Home identity paired with the root-derived authority. Like the
    /// authority id, this is distinct across fresh default installations even
    /// when both retain `home:local-user` as their internal ownership alias.
    pub fn federation_home_id(&self) -> HomeId {
        self.federation
            .as_ref()
            .map(|federation| HomeId::new(format!("home:{}", federation.authority.as_str())))
            .unwrap_or_else(|| self.home_id.clone())
    }

    /// Key-store slot backing this Home's governance root. It remains the local
    /// authority alias so activating federation does not rewrite existing local
    /// ownership or mint a second root key.
    fn federation_key_authority(&self) -> &AuthorityId {
        self.federation
            .as_ref()
            .map(|federation| &federation.key_authority)
            .unwrap_or(&self.authority)
    }

    pub(crate) fn create_default_target_engagement(
        &mut self,
        id: &str,
    ) -> Option<std::path::PathBuf> {
        let target_id = self.default_instance.clone();
        if target_id.is_empty() {
            return None;
        }
        let target = self.targets.get(&target_id)?;
        let eng = target.create_engagement(id).ok()?;
        let worktree = eng.path().to_path_buf();
        self.register_engagement(id, &target_id, eng);
        Some(worktree)
    }

    pub(crate) fn project_display_name(&self, project_id: &str) -> String {
        self.library_project_display_name(project_id)
    }

    /// Register a live managed-target store under its id. Federation relocation
    /// uses this after materializing a handoff content bundle.
    pub fn register_target(
        &mut self,
        target_id: impl Into<String>,
        target: Box<dyn gaugedesk_workspace::Workspace>,
    ) {
        self.targets.insert(target_id.into(), target);
    }

    /// Whether a managed target is registered under this id after local creation
    /// or federation relocation.
    pub fn has_target(&self, target_id: &str) -> bool {
        self.targets.contains_key(target_id)
    }

    /// Re-materialize a relocated target from its handoff content bundle: lay
    /// its store down under `targets/<id>`, register it, and rehydrate
    /// its engagement worktrees before the home commit lands.
    pub fn materialize_target(
        &mut self,
        target_id: &str,
        format: &str,
        bundle: &[u8],
    ) -> std::io::Result<()> {
        let dir = self.root.join("targets").join(target_id);
        let provider = self.workspace_provider(target_id);
        if format != provider.export_format() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "workspace export format `{format}` is incompatible with `{}`",
                    provider.export_format()
                ),
            ));
        }
        let target = provider.from_export_at(&dir, bundle).map_err(io)?;
        for (chat_id, eng) in target.reconcile_engagements().map_err(io)? {
            self.register_engagement(chat_id, target_id.to_string(), eng);
        }
        self.register_target(target_id.to_string(), target);
        Ok(())
    }

    /// Collect the content bundles for every live managed target owned by a
    /// project relocation. Federation owns the wire shape and uses this helper to
    /// produce the opaque bytes behind relocated handles.
    pub(crate) fn project_relocation_content_bundles(
        &self,
        project: &str,
    ) -> Vec<(String, String, Vec<u8>)> {
        self.library_project_relocation_content_bundles(project)
    }
}

pub(crate) fn activate_configured_federation(wb: &mut Workbench) -> std::io::Result<()> {
    let broker_addr = gaugedesk_env::var("RELAY_ENDPOINT")
        .unwrap_or_else(|| "wss://relay.gaugewright.com".to_string());
    let key_authority = wb.authority().clone();
    let authority = root_authority_id(&wb.governance_public_key());
    let mut fed = Federation::open_bound(authority, key_authority, &wb.root_path(), broker_addr)?;
    fed.restore_bridges(&folded_bridges(wb.store_ref()));
    wb.apply_startup_federation(fed);
    Ok(())
}

/// Default grant lifetime if a ticket request gives none (1 hour) — short by
/// design; re-pairing is the recovery path in the single-key slice.
const DEFAULT_TTL_SECS: u64 = 3600;

/// The self-operated federation route surface (D-REMOTE / SERVE-1).
///
/// Mounted when the workbench has initialized its federation identity. These
/// routes stay outside the enterprise auth layer because cross-authority auth
/// rides signed envelopes plus broker pins.
pub(crate) fn featured_routes(on: bool) -> axum::Router<SharedWorkbench> {
    if on {
        routes()
    } else {
        axum::Router::new()
    }
}

pub(crate) fn routes() -> axum::Router<SharedWorkbench> {
    use axum::routing::{delete, get, post};

    axum::Router::new()
        // Pairing: mint a ticket, accept a peer's ticket (TOFU pin), and list peers.
        .route("/federation/pairing-ticket", post(post_pairing_ticket))
        .route("/federation/pair", post(post_pair))
        .route("/federation/peers", get(get_peers))
        .route("/federation/peers/{authority}", delete(delete_peer))
        // Project handoff / authority relocation (FED-6): the shipped control
        // surface is relocate/consent/abort/status. The reducer's former raw
        // offer -> sync -> commit HTTP steps were retired because no product
        // client consumed them and exposing them allowed bypassing the atomic
        // cross-machine orchestration.
        .route("/federation/handoff/abort", post(post_handoff_abort))
        .route("/federation/handoff/status", get(get_handoff_status))
        .route("/federation/handoff/relocate", post(post_handoff_relocate))
        // Combined engagement invite (FED-7 Slice 2, ADR 0047): pair + hand off in one Accept.
        .route("/federation/invite", post(post_invite))
        .route("/federation/invite/accept", post(post_invite_accept))
        .route("/federation/invite/status", get(get_invite_status))
        // Co-drive (FED-7): operator places a run; host admits (standing allow / once) or queues.
        .route("/federation/run/place", post(post_run_place))
        .route("/federation/run/queue", get(get_run_queue))
        // Cross-authority erasure-on-revocation (ERASE-1, ADR 0067).
        .route("/federation/run/allow", post(post_run_allow))
        .route("/federation/run/deny", post(post_run_deny))
        .route("/federation/run/admit-once", post(post_run_admit_once))
        .route("/federation/run/result", get(get_run_result))
        .route("/federation/handoff/incoming", get(get_handoff_incoming))
        .route("/federation/handoff/accept", post(post_handoff_accept))
        .route(
            "/federation/handoff/accept-all",
            post(post_handoff_accept_all),
        )
        .route("/federation/handoff/decline", post(post_handoff_decline))
        .route("/federation/handoff/preauth", post(post_handoff_preauth))
        .route(
            "/federation/handoff/participants",
            get(get_handoff_participants),
        )
        .route("/federation/handoff/revoke", post(post_handoff_revoke))
        .route(
            "/federation/handoff/connect-data",
            post(post_handoff_connect_data),
        )
        .route("/federation/handoff/data", get(get_handoff_data))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The out-of-band artifact an owner hands a peer to pair (TOFU). Everything the
/// peer needs to **reach** (broker) and **trust** (governance key + cert pin) this
/// authority, pinned on first contact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingTicket {
    /// The minting authority's id.
    pub authority: String,
    /// Its P-256 governance public key (hex) — pinned as the grant's source key.
    pub governance_pubkey: String,
    /// Its TLS certificate fingerprint (hex SHA-256) — pinned for the relay legs.
    pub cert_fingerprint: String,
    /// Where the two authorities rendezvous (the broker address).
    pub broker_addr: String,
    /// The governance scope the resulting grant admits.
    pub scope: String,
    /// Unix time at/after which the grant is no longer valid.
    pub expiry: u64,
}

/// A paired peer as `GET /federation/peers` projects it: who they are, the pins in
/// force, and the grant binding them — handle/metadata only, never a key secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    pub authority: String,
    pub governance_pubkey: String,
    pub cert_fingerprint: String,
    pub grant_id: String,
    pub broker_addr: String,
    pub active: bool,
}

/// This control plane's federation state (`SERVE-1`): its own TLS identity, the
/// TOFU pin registry, and the grants/peers it has paired with. Held on the
/// [`Workbench`](crate::Workbench) behind the same mutex that serializes admission.
pub struct Federation {
    authority: AuthorityId,
    /// Local key-store slot for `authority`. Kept separate because the public
    /// authority is root-derived while old local state may use a human-readable
    /// alias such as `local-user`.
    key_authority: AuthorityId,
    identity: TlsIdentity,
    broker_addr: String,
    /// Pinned peer cert fingerprints (cloned into each TLS client handshake).
    pins: PinnedTlsClientConfig,
    /// One pinned grant per paired peer authority (the source-key pin + validity).
    grants: BTreeMap<String, BridgeGrant>,
    /// The peer projection, by authority.
    peers: BTreeMap<String, PeerRecord>,
    /// Device subkeys this authority has learned are **revoked**, by the peer that
    /// owns them (Model A / FED-5a): a crossing presenting a revoked subkey is denied
    /// even before its delegation expires. Populated by root-signed revocations
    /// pushed over the bridge.
    revoked_subkeys: BTreeMap<String, BTreeSet<String>>,
}

impl Federation {
    /// Build this instance's federation state: load (or generate + persist) its TLS
    /// identity under `root/tls`, recording the authority + broker it pairs through.
    pub fn open(authority: AuthorityId, root: &Path, broker_addr: String) -> std::io::Result<Self> {
        Self::open_bound(authority.clone(), authority, root, broker_addr)
    }

    fn open_bound(
        authority: AuthorityId,
        key_authority: AuthorityId,
        root: &Path,
        broker_addr: String,
    ) -> std::io::Result<Self> {
        let identity = TlsIdentity::load_or_generate(&root.join("tls"))?;
        Ok(Self {
            authority,
            key_authority,
            identity,
            broker_addr,
            pins: PinnedTlsClientConfig::new(),
            grants: BTreeMap::new(),
            peers: BTreeMap::new(),
            revoked_subkeys: BTreeMap::new(),
        })
    }

    /// Record that `subkey` (owned by peer `authority`) is revoked — future crossings
    /// presenting it are denied (Model A). Called after a root-signed revocation is
    /// verified against that peer's pinned root.
    pub fn record_revocation(&mut self, authority: &str, subkey: &str) {
        self.revoked_subkeys
            .entry(authority.to_string())
            .or_default()
            .insert(subkey.to_string());
    }

    /// Whether `subkey` (owned by peer `authority`) has been revoked.
    pub fn is_revoked(&self, authority: &str, subkey: &str) -> bool {
        self.revoked_subkeys
            .get(authority)
            .is_some_and(|s| s.contains(subkey))
    }

    /// Mint a pairing ticket describing this authority — its governance public key
    /// (the peer pins it as the grant's source key) and TLS fingerprint (the peer
    /// pins it for the legs). `scope`/`ttl` bound what the resulting grant admits.
    pub fn mint_ticket(
        &self,
        governance_pubkey: PublicKey,
        scope: String,
        ttl_secs: Option<u64>,
    ) -> PairingTicket {
        PairingTicket {
            authority: self.authority.as_str().to_string(),
            governance_pubkey: governance_pubkey.as_str().to_string(),
            cert_fingerprint: hex::encode(self.identity.fingerprint().as_bytes()),
            broker_addr: self.broker_addr.clone(),
            scope,
            expiry: now_secs() + ttl_secs.unwrap_or(DEFAULT_TTL_SECS),
        }
    }

    /// Accept a peer's ticket (TOFU): pin its governance key into a fresh
    /// [`BridgeGrant`] and its cert fingerprint into the TLS registry, then record
    /// the peer. Every later crossing from this peer is verified against these
    /// pinned values. Returns the peer projection.
    pub fn accept_ticket(&mut self, ticket: &PairingTicket, grant_id: String) -> PeerRecord {
        let pubkey = PublicKey::new(ticket.governance_pubkey.clone());
        let fingerprint =
            CertFingerprint::new(hex::decode(&ticket.cert_fingerprint).unwrap_or_default());
        self.pins
            .pin(AuthorityId::new(&ticket.authority), fingerprint);

        let grant = BridgeGrant {
            id: BridgeGrantId::new(grant_id.clone()),
            source_authority_root_pubkey: pubkey,
            source_authority_key_id: KeyId::new("gov-1"),
            target_environment: self.authority.as_str().to_string(),
            target_route: ticket.scope.clone(),
            // The device key the crossing presents — reuse the bound device of the
            // single-key slice; per-device subkeys are the deferred Model-A upgrade.
            device_key: PublicKey::new("04dev1ce0ke7"),
            governance_scope: ticket.scope.clone(),
            expiry: ticket.expiry,
            active: true,
        };
        self.grants.insert(ticket.authority.clone(), grant);

        let record = PeerRecord {
            authority: ticket.authority.clone(),
            governance_pubkey: ticket.governance_pubkey.clone(),
            cert_fingerprint: ticket.cert_fingerprint.clone(),
            grant_id,
            broker_addr: ticket.broker_addr.clone(),
            active: true,
        };
        self.peers.insert(ticket.authority.clone(), record.clone());
        record
    }

    /// The paired-peer projection.
    pub fn peers(&self) -> Vec<PeerRecord> {
        self.peers.values().cloned().collect()
    }

    /// The pinned grant for a peer authority (the source-key pin the crossing
    /// verifies against).
    pub fn grant_for(&self, peer: &str) -> Option<BridgeGrant> {
        self.grants.get(peer).cloned()
    }

    /// A cloneable snapshot of the TLS pin registry for a client handshake.
    pub fn pins_arc(&self) -> Arc<PinnedTlsClientConfig> {
        Arc::new(self.pins.clone())
    }

    /// Re-pin a peer roster persisted across a restart (`ITGOV-2`): replay each
    /// **active** bridge record through [`accept_ticket`](Self::accept_ticket) so the
    /// peer, its grant, and its TLS pin are back exactly as the original pairing left
    /// them. A revoked (`active == false`) record is skipped — revoke is durable too.
    pub fn restore_bridges(&mut self, bridges: &[BridgeRecord]) {
        for b in bridges {
            if b.active {
                self.accept_ticket(&b.ticket, b.grant_id.clone());
            }
        }
    }

    /// Revoke a paired peer (`ITGOV-2`): drop its grant and TLS pin and mark the peer
    /// inactive, so a later crossing from it is denied fail-closed (`INV-20`). Future-only
    /// — the audit trail (the bridge record's tombstone) is the durable evidence; payload
    /// already crossed is `ERASE-1`'s concern. Returns whether a peer was actually paired.
    pub fn revoke_peer(&mut self, authority: &str) -> bool {
        self.grants.remove(authority);
        self.pins.unpin(&AuthorityId::new(authority));
        if let Some(p) = self.peers.get_mut(authority) {
            p.active = false;
            true
        } else {
            false
        }
    }
}

/// The reserved store scope holding the **durable bridge roster** (`ITGOV-2`, ADR 0066 §B):
/// the federation peers this authority has paired with, event-sourced so the roster (and
/// each revoke) survives a restart instead of living only in [`Federation`]'s in-memory maps.
pub const BRIDGE_SCOPE: &str = "federation::bridges";

/// One durable bridge: the pairing that pinned a peer, kept so the peer/grant/TLS-pin can
/// be re-established on boot. Folded latest-wins by `id` (= the peer authority). `active`
/// flips to `false` on revoke (kept, not erased — the roster is auditable, `INV-18`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeRecord {
    /// The peer authority — the fold id (one bridge per peer in the single-key slice).
    pub id: String,
    #[serde(default)]
    pub op: crate::library::RecordOp,
    pub ticket: PairingTicket,
    pub grant_id: String,
    #[serde(default = "default_true")]
    pub active: bool,
}

fn default_true() -> bool {
    true
}

/// Append a bridge record to the durable roster (`ITGOV-2`). Called at pairing and at
/// revoke; the in-memory [`Federation`] is the live projection, this is its log.
pub fn persist_bridge(store: &mut Store, ticket: &PairingTicket, grant_id: &str, active: bool) {
    let rec = BridgeRecord {
        id: ticket.authority.clone(),
        op: crate::library::RecordOp::Upsert,
        ticket: ticket.clone(),
        grant_id: grant_id.to_string(),
        active,
    };
    let _ = store.append_record(
        BRIDGE_SCOPE,
        "bridge",
        &serde_json::to_string(&rec).unwrap(),
    );
}

/// The folded bridge roster (latest-wins by peer authority) — the durable source the
/// boot path replays into [`Federation::restore_bridges`] and `/admin/bridges` lists.
pub fn folded_bridges(store: &Store) -> Vec<BridgeRecord> {
    let mut by_id: BTreeMap<String, BridgeRecord> = BTreeMap::new();
    if let Ok(rows) = store.records(BRIDGE_SCOPE, "bridge") {
        for row in rows {
            if let Ok(r) = serde_json::from_str::<BridgeRecord>(&row) {
                by_id.insert(r.id.clone(), r);
            }
        }
    }
    by_id.into_values().collect()
}

/// The derived rendezvous inbox token a `source → target` crossing uses. Both sides
/// compute it identically from the authority pair, so no extra signalling channel is
/// needed: the receiver parks on `source → me`, the sender dials `me → target`.
fn inbox_token(source: &str, target: &str) -> String {
    format!("gaugewright-inbox::{source}->{target}")
}

fn token_bytes(token: &str) -> [u8; TOKEN_LEN] {
    Sha256::digest(token.as_bytes()).into()
}

/// Stable, collision-resistant public authority id for a governance root. The
/// complete public key still travels in the pairing ticket and is pinned by the
/// bridge grant; the digest is only the compact identifier used in scopes and
/// rendezvous tokens.
fn root_authority_id(root: &PublicKey) -> AuthorityId {
    AuthorityId::new(format!(
        "root-p256:{}",
        hex::encode(Sha256::digest(root.as_str().as_bytes()))
    ))
}

fn federation_root_signing_key(workbench: &Workbench) -> SigningKey {
    FileKeyStore::new(workbench.root_path().join("keys"))
        .signing_key(workbench.federation_key_authority())
}

#[cfg(test)]
mod public_authority_tests {
    use super::*;

    #[test]
    fn normal_homes_expose_distinct_stable_root_authorities_without_rewriting_local_ownership() {
        let left_dir = tempfile::tempdir().unwrap();
        let right_dir = tempfile::tempdir().unwrap();

        let mut left = Workbench::new(Store::open_in_memory().unwrap()).with_root(left_dir.path());
        activate_configured_federation(&mut left).unwrap();
        let first = left.federation_authority().clone();
        let first_home = left.federation_home_id();
        assert_eq!(left.authority().as_str(), crate::LOCAL_AUTHORITY);
        assert_eq!(
            left.home_id().as_str(),
            format!("home:{}", crate::LOCAL_AUTHORITY)
        );
        assert!(first.as_str().starts_with("root-p256:"));
        assert_eq!(first_home.as_str(), format!("home:{}", first.as_str()));

        let mut reopened =
            Workbench::new(Store::open_in_memory().unwrap()).with_root(left_dir.path());
        activate_configured_federation(&mut reopened).unwrap();
        assert_eq!(reopened.federation_authority(), &first);
        assert_eq!(reopened.federation_home_id(), first_home);

        let mut right =
            Workbench::new(Store::open_in_memory().unwrap()).with_root(right_dir.path());
        activate_configured_federation(&mut right).unwrap();
        assert_ne!(right.federation_authority(), &first);
        assert_ne!(right.federation_home_id(), first_home);
    }
}

async fn park_relay(broker: &str, token: &str) -> std::io::Result<BoxedRelayByteStream> {
    connect_one_shot(broker, token_bytes(token), OneShotLeg::Initializer).await
}

async fn join_relay(broker: &str, token: &str) -> std::io::Result<BoxedRelayByteStream> {
    connect_one_shot(broker, token_bytes(token), OneShotLeg::Joiner).await
}

/// The signed crossing as it travels the TLS leg: the handle + the canonical bytes
/// the source signed and the key it claims (verified against the *grant's* pinned
/// key on admission, C-1). The payload never travels — only its handle (`INV-10`).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CrossWire {
    correlation: String,
    source: String,
    target: String,
    payload_handle: String,
    signed_bytes: Vec<u8>,
    signature: gaugedesk_core::signature::Signature,
    source_pubkey: String,
    /// The signer's **device-subkey delegation** (Model A, FED-5a). Present when the
    /// crossing is signed by a device subkey rather than the root governance key
    /// directly; the target verifies it chains to the grant's pinned root.
    #[serde(default)]
    delegation: Option<DeviceDelegation>,
}

/// The TTL of a freshly-issued device-subkey delegation (30 days). The root re-signs
/// a delegation per send; a lost/rotated device's subkey simply ages out, so a
/// stale device cannot keep crossing once its delegation expires (per-device
/// revocation, Model A).
const DEVICE_DELEGATION_TTL_SECS: u64 = 30 * 24 * 3600;

/// This authority's device subkey + a fresh self-delegation chaining it to the root
/// governance key (Model A / FED-5a). The subkey is persisted alongside the root
/// (a distinct `<authority>::device` key) so it is stable across restarts; the root
/// signs a short-lived delegation so federated envelopes are signed by the subkey,
/// never the root directly. The root key never leaves the key store.
fn device_identity(
    root_dir: &std::path::Path,
    authority: &AuthorityId,
    root: &SigningKey,
) -> (SigningKey, DeviceDelegation) {
    let ks = FileKeyStore::new(root_dir.join("keys"));
    let subkey = ks.signing_key(&AuthorityId::new(format!("{}::device", authority.as_str())));
    let delegation = DeviceDelegation::issue(
        root,
        subkey.public_key(),
        now_secs() + DEVICE_DELEGATION_TTL_SECS,
    );
    (subkey, delegation)
}

/// Resolve the effective key a federated message from `source` must verify under,
/// given the `grant` it crosses and an optional device delegation (Model A). The
/// shared C-1 gate for the consent + observation paths (the crossing path runs the
/// equivalent inside the `gaugedesk_core::federation` reducer):
/// - **no delegation:** the claimed key must equal the grant's pinned root.
/// - **delegation:** it must be issued by the pinned root, unexpired, the claimed
///   key must be the delegated subkey, and that subkey must not be revoked.
///
/// Returns the effective verifying key, or `None` (fail-closed) on any mismatch.
fn effective_source_key(
    fed: &Federation,
    source: &str,
    grant: &BridgeGrant,
    claimed: &PublicKey,
    delegation: &Option<DeviceDelegation>,
) -> Option<PublicKey> {
    match delegation {
        None => (*claimed == grant.source_authority_root_pubkey).then(|| claimed.clone()),
        Some(d) => {
            if d.authority_root != grant.source_authority_root_pubkey
                || d.verify(now_secs()).is_err()
                || *claimed != d.subkey
                || fed.is_revoked(source, d.subkey.as_str())
            {
                return None;
            }
            Some(d.subkey.clone())
        }
    }
}

async fn write_frame<S: AsyncWriteExt + Unpin>(s: &mut S, bytes: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    s.write_all(&len.to_be_bytes()).await?;
    s.write_all(bytes).await?;
    s.flush().await
}

async fn read_frame<S: AsyncReadExt + Unpin>(s: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds cap",
        ));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Admit one received crossing through the verified, grant-pinned reducer and
/// record the federated fact + emit SSE on success. Locks the workbench only here
/// (never across network I/O). Returns whether the target admitted.
fn admit_crossing(wb: &SharedWorkbench, wire: &CrossWire) -> bool {
    let scope = format!("federation::{}", wire.correlation);
    let envelope = CrossingEnvelope {
        signed_bytes: wire.signed_bytes.clone(),
        signature: wire.signature.clone(),
        source_pubkey: PublicKey::new(wire.source_pubkey.clone()),
        // Model A: when the source signed with a device subkey, the reducer verifies
        // this delegation chains to the grant's pinned root (FED-5a).
        delegation: wire.delegation.clone(),
    };
    let mut guard = wb.lock_unpoisoned();
    let Some(grant) = guard
        .federation_ref()
        .and_then(|f| f.grant_for(&wire.source))
    else {
        return false; // no pinned grant for this source — not a paired peer
    };
    // Model A revocation (FED-5a): a crossing signed by a device subkey the source's
    // authority has revoked is denied even before the delegation expires.
    if let Some(delegation) = &wire.delegation {
        let revoked = guard
            .federation_ref()
            .is_some_and(|f| f.is_revoked(&wire.source, delegation.subkey.as_str()));
        if revoked {
            return false;
        }
    }
    // Source authorizes → relay routes → TARGET admits (verifies signature against
    // the grant's pinned source key + validates the grant), exactly the loopback
    // sequence — only the target's admission writes the fact (INV-13/INV-21).
    let admitted = {
        let store = guard.store_mut();
        let routed = store
            .admit::<CrossingState>(&scope, CrossingCommand::SourceAuthorize)
            .and_then(|_| store.admit::<CrossingState>(&scope, CrossingCommand::RelayRoute));
        if routed.is_err() {
            false
        } else {
            matches!(
                store.admit::<CrossingState>(
                    &scope,
                    CrossingCommand::TargetAdmit {
                        envelope,
                        grant,
                        now: now_secs(),
                    },
                ),
                Ok(s) if s.target_fact_written()
            )
        }
    };
    if admitted {
        let rec = serde_json::json!({
            "correlation": wire.correlation,
            "source": wire.source,
            "target": wire.target,
            "payload_handle": wire.payload_handle, // a handle — never the payload
        });
        let _ = guard
            .store_mut()
            .append_record(FED_INBOX_SCOPE, "federated", &rec.to_string());
        guard.publish(
            FED_INBOX_SCOPE,
            ServerEvent::Admitted {
                kind: "federated".into(),
                text: format!(
                    "{} ← {} : {}",
                    wire.target, wire.source, wire.payload_handle
                ),
            },
        );
    }
    admitted
}

/// The per-peer **receiver loop** (`SERVE-1`): park on the broker for crossings
/// `peer → me`, complete the cert-pinned TLS handshake as the server, admit each
/// crossing against the pinned grant, and write the verdict back. Re-dials after
/// each crossing so the inbox stays open. Spawned when a pair is accepted.
pub async fn run_receiver(wb: SharedWorkbench, peer: AuthorityId) {
    loop {
        // Snapshot the transport bits without holding the lock across I/O.
        let (broker, identity, me, still_paired) = {
            let guard = wb.lock_unpoisoned();
            match guard.federation_ref() {
                Some(fed) => (
                    fed.broker_addr.clone(),
                    fed.identity.clone(),
                    fed.authority.clone(),
                    fed.grant_for(peer.as_str()).is_some(),
                ),
                None => return,
            }
        };
        if !still_paired {
            return; // unpaired (revoked) — stop listening
        }
        let token = inbox_token(peer.as_str(), me.as_str());
        if let Err(e) = receive_once(&wb, &broker, &identity, &token).await {
            // A transport hiccup (broker down, peer gone) — back off briefly and
            // re-park rather than spin or die.
            tracing::debug!("federation receiver {peer}→{me}: {e}; retrying");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

async fn receive_once(
    wb: &SharedWorkbench,
    broker: &str,
    identity: &TlsIdentity,
    token: &str,
) -> std::io::Result<()> {
    let tcp = park_relay(broker, token).await?;
    // This side presents its pinned certificate (TLS server); the sender pins it.
    let mut tls = tls_accept(tcp, identity).await?;
    let bytes = read_frame(&mut tls).await?;
    let wire: CrossWire = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let admitted = admit_crossing(wb, &wire);
    let verdict = serde_json::json!({ "correlation": wire.correlation, "admitted": admitted });
    write_frame(&mut tls, verdict.to_string().as_bytes()).await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// Send one signed crossing to `peer` over the cert-pinned TLS leg and return
/// whether the peer admitted it. The source signs the canonical bytes with its own
/// governance key; the peer verifies against the key it pinned at pairing (C-1).
#[allow(clippy::too_many_arguments)]
async fn send_crossing(
    broker: &str,
    me: &AuthorityId,
    subkey: &SigningKey,
    delegation: &DeviceDelegation,
    peer: &AuthorityId,
    pins: Arc<PinnedTlsClientConfig>,
    correlation: &str,
    payload_handle: &str,
) -> std::io::Result<bool> {
    let signed_bytes = correlation.as_bytes().to_vec();
    // Model A: sign with the device subkey and carry the root-issued delegation; the
    // peer verifies the delegation chains to the root it pinned at pairing (C-1).
    let wire = CrossWire {
        correlation: correlation.to_string(),
        source: me.as_str().to_string(),
        target: peer.as_str().to_string(),
        payload_handle: payload_handle.to_string(),
        signature: subkey.sign(&signed_bytes),
        source_pubkey: subkey.public_key().as_str().to_string(),
        signed_bytes,
        delegation: Some(delegation.clone()),
    };
    let token = inbox_token(me.as_str(), peer.as_str());
    let tcp = join_relay(broker, &token).await?;
    // This side is the TLS client; it pins the peer's certificate.
    let mut tls = tls_connect(tcp, peer, pins).await?;
    let bytes = serde_json::to_vec(&wire)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_frame(&mut tls, &bytes).await?;
    let vbytes = read_frame(&mut tls).await?;
    let _ = tls.shutdown().await;
    let verdict: serde_json::Value = serde_json::from_slice(&vbytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(verdict
        .get("admitted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

// ----- Remote-run observations (Flow 1 / OBSERVATION-FEDERATION-1) -----------
//
// The owner *places a run on the peer*: it sends a RunReq over the cert-pinned TLS
// leg; the peer executes a turn through the configured GaugeDesk engine and
// returns its [`Observation`](gaugedesk_harness::Observation)s; the owner then
// federates each one back through the relay seam and admits it as run evidence —
// standing run truth only via the **owner's** RecordObservation admission (INV-4).

/// The owner's request to run a turn on the peer's runtime.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RunReq {
    run_scope: String,
    prompt: String,
}

/// One observation as it returns over the leg — a kind + detail (never payload),
/// **signed by the peer's governance key** (FED-3) so the owner admits it against
/// the peer's pinned grant (C-1 / INV-21), not merely on TLS-channel trust.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ObsWire {
    kind: String,
    detail: String,
    /// The canonical bytes the peer signed (the observation's correlation).
    signed_bytes: Vec<u8>,
    signature: gaugedesk_core::signature::Signature,
    /// The peer's governance pubkey — must equal the grant's pinned source key.
    source_pubkey: String,
    /// Single-use per-observation nonce (anti-replay within the run delivery).
    nonce: String,
}

/// The peer's turn outcome returning to the owner: the observations the owner will
/// admit, the assistant text (for display), and the peer's device-subkey delegation
/// (Model A) the whole batch was signed under, so the owner verifies it chains to
/// the grant's pinned root.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RunResp {
    observations: Vec<ObsWire>,
    assistant_text: String,
    #[serde(default)]
    delegation: Option<DeviceDelegation>,
}

/// The derived rendezvous token a `owner → peer` runtime call uses.
fn runtime_token(owner: &str, peer: &str) -> String {
    format!("gaugewright-runtime::{owner}->{peer}")
}

/// Execute one turn on the peer through its configured GaugeDesk engine. A peer
/// with no registered instance may use the neutral scripted harness in explicit
/// fake-agent mode; a real run without an instance fails closed.
fn execute_peer_turn(
    wb: &SharedWorkbench,
    prompt: &str,
    run_scope: &str,
    target_chat: Option<&str>,
    contribution_by: Option<&str>,
    subkey: &SigningKey,
    delegation: &DeviceDelegation,
) -> RunResp {
    // FED-5b-3: when the peer has its own instance, run the turn in a **persistent,
    // registered engagement** (durable run + transcript + worktree diff on the peer,
    // inspectable + keep/merge-able by the peer's operator — the "you are the
    // operating host" trust model). A minimal workbench with no instance falls back
    // to the in-process turn. Either way the observations federate to the owner.
    let (observations, assistant_text) =
        match engine_peer_turn(wb, prompt, target_chat, contribution_by) {
            Some((count, text)) => (
                // Per-observation detail isn't surfaced through the engine's TaskResult
                // (the durable transcript on the peer has it); only the handle crosses
                // (INV-10), so the owner admits `count` signed observation handles.
                (0..count)
                    .map(|_| ("text".to_string(), String::new()))
                    .collect::<Vec<_>>(),
                text,
            ),
            None => {
                let o = run_peer_outcome(prompt, run_scope);
                (
                    o.observations
                        .iter()
                        .map(|o| (o.kind.to_string(), o.detail.clone()))
                        .collect(),
                    o.assistant_text,
                )
            }
        };

    let source_pubkey = subkey.public_key().as_str().to_string();
    RunResp {
        observations: observations
            .iter()
            .enumerate()
            .map(|(i, (kind, detail))| {
                // Sign each observation under the peer's **device subkey** (Model A),
                // bound to this run + index; the owner verifies the batch delegation
                // chains to the grant's pinned root, then each sig under the subkey.
                let signed_bytes = format!("obs::{run_scope}::{i}").into_bytes();
                ObsWire {
                    kind: kind.clone(),
                    detail: detail.clone(),
                    signature: subkey.sign(&signed_bytes),
                    signed_bytes,
                    source_pubkey: source_pubkey.clone(),
                    nonce: format!("obs-nonce::{run_scope}::{i}"),
                }
            })
            .collect(),
        assistant_text,
        delegation: Some(delegation.clone()),
    }
}

/// Run the peer turn in a real, **persistent peer-side engagement** through the
/// engine (FED-5b-3): create + register an engagement (a worktree off the peer's
/// default instance), drive the turn with the full membrane / sandbox / run
/// lifecycle (`run_engagement_turn` — fake under `GAUGEDESK_FAKE_AGENT`,
/// WhippleScript otherwise), and return the run's admitted-observation count + assistant text.
/// `None` when the peer has no instance (a minimal/test workbench) — the caller
/// then falls back to the in-process turn.
fn engine_peer_turn(
    wb: &SharedWorkbench,
    prompt: &str,
    target_chat: Option<&str>,
    contribution_by: Option<&str>,
) -> Option<(u32, String)> {
    use gaugedesk_core::run::RunState;
    let (eng_id, worktree) = {
        let mut g = wb.lock_unpoisoned();
        if let Some(target_chat) = target_chat {
            let worktree = g.engagements.get(target_chat)?.path().to_path_buf();
            (target_chat.to_owned(), worktree)
        } else {
            let eng_id = crate::library::gen_id("remote-run");
            let worktree = g.create_default_target_engagement(&eng_id)?;
            (eng_id, worktree)
        }
    };
    // A throwaway sink: the peer's durable transcript is the record; the owner gets
    // the federated observations separately. run_engagement_turn locks the workbench
    // internally, so it is called without the lock held.
    let (tx, _rx) = broadcast::channel(256);
    let assistant = match crate::engine::run_engagement_turn(
        wb,
        &eng_id,
        &worktree,
        &tx,
        crate::engine::EngagementTurnInput {
            task: prompt,
            images: &[], // remote/federated runs are text-only (no image attachments yet)
            mode: crate::library::ChatMode::Use,
            authenticated_actor: None,
            contribution_by,
            account_scope: crate::account::ACCOUNT_SCOPE,
            tenant_scope: crate::org::ORG_SCOPE,
            runtime_command_id: None,
            harness_factory: None,
        },
    ) {
        Ok(r) => r.assistant_text,
        Err(e) => format!("remote runtime error: {e}"),
    };
    let count = wb
        .lock_unpoisoned()
        .store_ref()
        .fold::<RunState>(&eng_id)
        .map(|s| s.observations)
        .unwrap_or(0);
    Some((count, assistant))
}

/// Run the no-instance fallback for a peer (FED-4). Explicit fake-agent mode uses
/// the neutral scripted harness so CI can exercise the federation transport. A
/// real peer must have a registered instance and therefore fails closed here.
fn run_peer_outcome(prompt: &str, run_scope: &str) -> gaugedesk_harness::TurnOutcome {
    use gaugedesk_harness::testing::{ScriptedHarness, ScriptedTurn};
    use gaugedesk_harness::{AllowAllGate, Harness, Observation, TurnOutcome};

    if gaugedesk_env::var("FAKE_AGENT").is_some() {
        let text = format!("remote ran: {prompt}");
        return ScriptedHarness::from_neutral_turns(vec![ScriptedTurn {
            assistant_text: text.clone(),
            observations: vec![Observation {
                kind: "text",
                detail: text,
                tool: None,
            }],
            tool_calls: Vec::new(),
            ..ScriptedTurn::default()
        }])
        .run_turn(&AllowAllGate, prompt, &[], &mut |_| {})
        .unwrap_or_default();
    }

    let reason = format!(
        "remote run `{run_scope}` has no registered GaugeDesk instance; refusing an ungoverned runtime fallback"
    );
    TurnOutcome {
        observations: vec![Observation {
            kind: "other",
            detail: reason.clone(),
            tool: None,
        }],
        error: Some(reason),
        ..Default::default()
    }
}

/// The per-peer **runtime receiver** (REMOTE-RPC-1): park on the broker for run
/// requests `owner → me`, complete the cert-pinned TLS handshake as the server,
/// execute the turn locally, and return the observations. Spawned alongside the
/// crossing receiver when a pair is accepted.
pub async fn run_runtime_receiver(wb: SharedWorkbench, owner: AuthorityId) {
    loop {
        let (broker, identity, me, subkey, delegation, still_paired) = {
            let guard = wb.lock_unpoisoned();
            let me = guard.federation_authority().clone();
            let root = federation_root_signing_key(&guard);
            let (subkey, delegation) = device_identity(&guard.root_path(), &me, &root);
            match guard.federation_ref() {
                Some(fed) => (
                    fed.broker_addr.clone(),
                    fed.identity.clone(),
                    me,
                    subkey,
                    delegation,
                    fed.grant_for(owner.as_str()).is_some(),
                ),
                None => return,
            }
        };
        if !still_paired {
            return;
        }
        let token = runtime_token(owner.as_str(), me.as_str());
        if let Err(e) =
            runtime_serve_once(&wb, &broker, &identity, &subkey, &delegation, &token).await
        {
            tracing::debug!("federation runtime receiver {owner}→{me}: {e}; retrying");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

async fn runtime_serve_once(
    wb: &SharedWorkbench,
    broker: &str,
    identity: &TlsIdentity,
    subkey: &SigningKey,
    delegation: &DeviceDelegation,
    token: &str,
) -> std::io::Result<()> {
    let tcp = park_relay(broker, token).await?;
    let mut tls = tls_accept(tcp, identity).await?;
    let bytes = read_frame(&mut tls).await?;
    let req: RunReq = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let resp = execute_peer_turn(
        wb,
        &req.prompt,
        &req.run_scope,
        None,
        None,
        subkey,
        delegation,
    );
    let out = serde_json::to_vec(&resp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_frame(&mut tls, &out).await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// Owner side: send a RunReq to the peer's runtime over the cert-pinned TLS leg and
/// return the observations the peer produced. The owner admits them separately
/// (INV-4) — the network call only fetches the evidence.
async fn remote_run_rpc(
    broker: &str,
    me: &AuthorityId,
    peer: &AuthorityId,
    pins: Arc<PinnedTlsClientConfig>,
    run_scope: &str,
    prompt: &str,
) -> std::io::Result<RunResp> {
    let req = RunReq {
        run_scope: run_scope.to_string(),
        prompt: prompt.to_string(),
    };
    let token = runtime_token(me.as_str(), peer.as_str());
    let tcp = join_relay(broker, &token).await?;
    let mut tls = tls_connect(tcp, peer, pins).await?;
    let bytes = serde_json::to_vec(&req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_frame(&mut tls, &bytes).await?;
    let resp_bytes = read_frame(&mut tls).await?;
    let _ = tls.shutdown().await;
    serde_json::from_slice(&resp_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Drive a run scope to `Running` from wherever it is (idempotent across the
/// happy-path prefix), so the owner can admit observations into it (INV-4).
fn ensure_running(store: &mut gaugedesk_store::Store, run_scope: &str) {
    use gaugedesk_core::run::{RunCommand, RunPhase, RunState};
    let phase = store
        .fold::<RunState>(run_scope)
        .map(|s| s.phase)
        .unwrap_or(RunPhase::Init);
    let steps: &[RunCommand] = match phase {
        RunPhase::Init => &[
            RunCommand::RequestRun,
            RunCommand::AdmitRun,
            RunCommand::StartRun,
        ],
        RunPhase::Requested => &[RunCommand::AdmitRun, RunCommand::StartRun],
        RunPhase::Admitted => &[RunCommand::StartRun],
        _ => &[],
    };
    for cmd in steps {
        let _ = store.admit::<RunState>(run_scope, cmd.clone());
    }
}

/// Owner-side admission of the peer's observations (FED-3): each observation was
/// **signed by the peer**, so the owner admits it against the peer's pinned grant —
/// the delivery is *bound to the real grant + device* and the envelope's source key
/// must equal the grant's pinned source key (C-1) and verify under it (INV-21).
/// Each admitted observation then becomes run evidence via the owner's
/// RecordObservation (INV-4). Returns the run's admitted-observation count. Locks
/// the workbench only here, never across the RPC.
fn admit_observations(
    wb: &SharedWorkbench,
    run_scope: &str,
    source: &str,
    observations: &[ObsWire],
    delegation: &Option<DeviceDelegation>,
) -> u32 {
    let mut guard = wb.lock_unpoisoned();
    // Verify the source key once for the batch (all observations share it): the
    // grant's pinned root, or — under a device delegation (Model A) — the delegated,
    // unrevoked subkey the delegation chains to that root (C-1).
    let (grant, verify_key) = {
        let Some(fed) = guard.federation_ref() else {
            return 0;
        };
        let Some(grant) = fed.grant_for(source) else {
            return 0; // not a paired peer
        };
        let claimed = PublicKey::new(
            observations
                .first()
                .map(|o| o.source_pubkey.clone())
                .unwrap_or_default(),
        );
        match effective_source_key(fed, source, &grant, &claimed, delegation) {
            Some(vk) => (grant, vk),
            None => return 0, // bad/foreign/expired/revoked source key — admit nothing
        }
    };
    let mut admitted = 0u32;
    {
        let store = guard.store_mut();
        ensure_running(store, run_scope);
        for (i, obs) in observations.iter().enumerate() {
            // Each observation must present the verified source key (the subkey or
            // root) — a mixed batch is rejected per-item.
            if obs.source_pubkey != verify_key.as_str() {
                continue;
            }
            let dscope = format!("{run_scope}::obs-delivery::{i}");
            // Bind the delivery to the real per-peer grant + device, then run the
            // source-authorize → relay → TARGET-admit sequence with the peer-signed
            // envelope. The reducer verifies the signature (INV-21) and that the
            // envelope's grant + device match the bound real ones (FED-3).
            let _ = store.admit::<DeliveryState>(
                &dscope,
                DeliveryCommand::BindDelivery {
                    bridge_grant_id: grant.id.clone(),
                    device_key: grant.device_key.clone(),
                    device: DeviceId::new(source),
                },
            );
            let envelope = DeliveryEnvelope {
                signed_bytes: obs.signed_bytes.clone(),
                signature: obs.signature.clone(),
                source_pubkey: verify_key.clone(),
                nonce: Nonce::new(obs.nonce.clone()),
                bridge_grant_id: grant.id.clone(),
                device_key: grant.device_key.clone(),
                device_active: grant.active,
            };
            let admitted_obs = store
                .admit::<DeliveryState>(&dscope, DeliveryCommand::AuthorizeFederatedMessage)
                .and_then(|_| {
                    store.admit::<DeliveryState>(&dscope, DeliveryCommand::EnqueueFederatedMessage)
                })
                .and_then(|_| {
                    store.admit::<DeliveryState>(&dscope, DeliveryCommand::RecordRelayDelivery)
                })
                .and_then(|_| {
                    store.admit::<DeliveryState>(
                        &dscope,
                        DeliveryCommand::AdmitTargetReceipt { envelope },
                    )
                })
                .map(|s| s.phase == DeliveryPhase::TargetAdmitted)
                .unwrap_or(false);
            // Only an admitted, verified crossing becomes run evidence (INV-4).
            if admitted_obs {
                if let Ok(s) = store.admit::<RunState>(run_scope, RunCommand::RecordObservation) {
                    admitted = s.observations;
                }
            }
        }
    }
    guard.publish(
        run_scope,
        ServerEvent::Admitted {
            kind: "remote-run".into(),
            text: format!(
                "{} observation(s) federated from {source}",
                observations.len()
            ),
        },
    );
    admitted
}

// ----- Cross-machine output review (Flow 2 / conjunctive consent) ------------
//
// An output owned by two authorities releases only with the consent of *both*
// (INV-16 / SAFE_RELEASE). The owner consents locally; the **remote** stakeholder's
// consent crosses the network as a signed message the owner authenticates against
// the peer's pinned grant (C-1 / INV-21) before admitting it into the review scope.
// One authority — local or remote — can never release shared content alone.

/// A remote stakeholder's signed consent for one review scope.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConsentReq {
    review_scope: String,
    consenting_authority: String,
    signed_bytes: Vec<u8>,
    signature: gaugedesk_core::signature::Signature,
    source_pubkey: String,
    /// The consenter's device-subkey delegation (Model A); `None` for a root-signed
    /// consent. The owner verifies it chains to the consenter's pinned root.
    #[serde(default)]
    delegation: Option<DeviceDelegation>,
}

/// The derived rendezvous token a `consenter → owner` consent crossing uses.
fn consent_token(consenter: &str, owner: &str) -> String {
    format!("gaugewright-consent::{consenter}->{owner}")
}

/// The canonical bytes a stakeholder signs to consent to a release — bound to the
/// exact review scope and the consenting authority, so a captured signature cannot
/// be replayed onto a different review.
fn consent_bytes(review_scope: &str, authority: &str) -> Vec<u8> {
    format!("review-consent::{review_scope}::{authority}").into_bytes()
}

/// Owner side: authenticate a remote consent against the peer's pinned grant (the
/// source key the grant pins must equal the presenting key, the signature must
/// verify under it, and the grant must be valid — C-1 / INV-21), then admit
/// `ReviewCommand::Consent(peer)` into the review scope. Returns the resulting
/// review state, or `None` if authentication or admission fails (fail-closed).
fn admit_remote_consent(wb: &SharedWorkbench, req: &ConsentReq) -> Option<ReviewState> {
    let mut guard = wb.lock_unpoisoned();
    let fed = guard.federation_ref()?;
    let grant = fed.grant_for(&req.consenting_authority)?;
    let claimed = PublicKey::new(req.source_pubkey.clone());
    // C-1: resolve the effective signing key (the pinned root, or a delegated +
    // unrevoked device subkey under Model A), then verify the consent signature
    // under it and that the bytes bind this exact scope + authority (no replay).
    let verify_key = effective_source_key(
        fed,
        &req.consenting_authority,
        &grant,
        &claimed,
        &req.delegation,
    )?;
    if !grant.is_valid(now_secs())
        || req.signed_bytes != consent_bytes(&req.review_scope, &req.consenting_authority)
        || verify_signature(&req.signed_bytes, &req.signature, &verify_key) != Ok(true)
    {
        return None;
    }
    let state = guard
        .store_mut()
        .admit::<ReviewState>(
            &req.review_scope,
            ReviewCommand::Consent(req.consenting_authority.clone().into()),
        )
        .ok()?;
    guard.publish(
        &req.review_scope,
        ServerEvent::Admitted {
            kind: "review".into(),
            text: format!(
                "remote consent from {} → {:?}",
                req.consenting_authority, state.phase
            ),
        },
    );
    Some(state)
}

/// The per-peer **consent receiver**: park on the broker for consent crossings
/// `peer → me`, complete the cert-pinned TLS handshake as the server, authenticate
/// + admit the consent, and reply with the resulting review state.
pub async fn run_consent_receiver(wb: SharedWorkbench, peer: AuthorityId) {
    loop {
        let (broker, identity, me, still_paired) = {
            let guard = wb.lock_unpoisoned();
            match guard.federation_ref() {
                Some(fed) => (
                    fed.broker_addr.clone(),
                    fed.identity.clone(),
                    fed.authority.clone(),
                    fed.grant_for(peer.as_str()).is_some(),
                ),
                None => return,
            }
        };
        if !still_paired {
            return;
        }
        let token = consent_token(peer.as_str(), me.as_str());
        if let Err(e) = consent_serve_once(&wb, &broker, &identity, &token).await {
            tracing::debug!("federation consent receiver {peer}→{me}: {e}; retrying");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

async fn consent_serve_once(
    wb: &SharedWorkbench,
    broker: &str,
    identity: &TlsIdentity,
    token: &str,
) -> std::io::Result<()> {
    let tcp = park_relay(broker, token).await?;
    let mut tls = tls_accept(tcp, identity).await?;
    let bytes = read_frame(&mut tls).await?;
    let req: ConsentReq = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let resp = match admit_remote_consent(wb, &req) {
        Some(state) => serde_json::json!({ "ok": true, "review": state }),
        None => serde_json::json!({ "ok": false }),
    };
    write_frame(&mut tls, resp.to_string().as_bytes()).await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// Consenter side: sign a consent for `review_scope` and send it to the `owner`
/// over the cert-pinned TLS leg; return the owner's reply (the new review state).
#[allow(clippy::too_many_arguments)]
async fn send_consent(
    broker: &str,
    me: &AuthorityId,
    subkey: &SigningKey,
    delegation: &DeviceDelegation,
    owner: &AuthorityId,
    pins: Arc<PinnedTlsClientConfig>,
    review_scope: &str,
) -> std::io::Result<serde_json::Value> {
    let signed_bytes = consent_bytes(review_scope, me.as_str());
    // Model A: sign the consent with the device subkey and carry the delegation.
    let req = ConsentReq {
        review_scope: review_scope.to_string(),
        consenting_authority: me.as_str().to_string(),
        signature: subkey.sign(&signed_bytes),
        source_pubkey: subkey.public_key().as_str().to_string(),
        signed_bytes,
        delegation: Some(delegation.clone()),
    };
    let token = consent_token(me.as_str(), owner.as_str());
    let tcp = join_relay(broker, &token).await?;
    let mut tls = tls_connect(tcp, owner, pins).await?;
    let bytes = serde_json::to_vec(&req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_frame(&mut tls, &bytes).await?;
    let resp_bytes = read_frame(&mut tls).await?;
    let _ = tls.shutdown().await;
    serde_json::from_slice(&resp_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ----- Device-subkey revocation distribution (Model A / FED-5a) --------------
//
// With no directory, a peer learns a device subkey is revoked only via a
// root-signed revocation pushed over the existing bridge. The revoking authority
// signs a SubkeyRevocation under its root and sends it; the peer verifies it under
// the root it pinned at pairing (C-1) and records the subkey, after which any
// crossing presenting it is denied — cutting off a lost/compromised device
// immediately, not at delegation expiry.

/// The derived rendezvous token a `revoker → peer` revocation push uses.
fn revocation_token(revoker: &str, peer: &str) -> String {
    format!("gaugewright-revoke::{revoker}->{peer}")
}

/// Peer side: verify a root-signed revocation against the revoker's pinned root and
/// record the revoked subkey. Returns whether it was accepted (fail-closed).
fn admit_revocation(wb: &SharedWorkbench, revoker: &str, rev: &SubkeyRevocation) -> bool {
    let mut guard = wb.lock_unpoisoned();
    let Some(grant) = guard.federation_ref().and_then(|f| f.grant_for(revoker)) else {
        return false;
    };
    // C-1: the revocation must be signed by the root pinned for this peer.
    if rev.authority_root != grant.source_authority_root_pubkey || rev.verify().is_err() {
        return false;
    }
    let subkey = rev.subkey.as_str().to_string();
    if let Some(fed) = guard.federation_mut() {
        fed.record_revocation(revoker, &subkey);
    }
    guard.publish(
        FED_INBOX_SCOPE,
        ServerEvent::Admitted {
            kind: "revocation".into(),
            text: format!("revoked a device subkey of {revoker}"),
        },
    );
    true
}

/// The per-peer **revocation receiver**: park on the broker for revocations
/// `revoker → me`, verify + record them. Spawned alongside the other receivers.
pub async fn run_revocation_receiver(wb: SharedWorkbench, revoker: AuthorityId) {
    loop {
        let (broker, identity, me, still_paired) = {
            let guard = wb.lock_unpoisoned();
            match guard.federation_ref() {
                Some(fed) => (
                    fed.broker_addr.clone(),
                    fed.identity.clone(),
                    fed.authority.clone(),
                    fed.grant_for(revoker.as_str()).is_some(),
                ),
                None => return,
            }
        };
        if !still_paired {
            return;
        }
        let token = revocation_token(revoker.as_str(), me.as_str());
        if let Err(e) = revocation_serve_once(&wb, &broker, &identity, &revoker, &token).await {
            tracing::debug!("federation revocation receiver {revoker}→{me}: {e}; retrying");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

async fn revocation_serve_once(
    wb: &SharedWorkbench,
    broker: &str,
    identity: &TlsIdentity,
    revoker: &AuthorityId,
    token: &str,
) -> std::io::Result<()> {
    let tcp = park_relay(broker, token).await?;
    let mut tls = tls_accept(tcp, identity).await?;
    let bytes = read_frame(&mut tls).await?;
    let rev: SubkeyRevocation = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let ok = admit_revocation(wb, revoker.as_str(), &rev);
    let resp = serde_json::json!({ "ok": ok });
    write_frame(&mut tls, resp.to_string().as_bytes()).await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// Revoker side: push a root-signed revocation of `rev`'s subkey to `peer`.
async fn send_revocation(
    broker: &str,
    me: &AuthorityId,
    peer: &AuthorityId,
    pins: Arc<PinnedTlsClientConfig>,
    rev: &SubkeyRevocation,
) -> std::io::Result<bool> {
    let token = revocation_token(me.as_str(), peer.as_str());
    let tcp = join_relay(broker, &token).await?;
    let mut tls = tls_connect(tcp, peer, pins).await?;
    let bytes = serde_json::to_vec(rev)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_frame(&mut tls, &bytes).await?;
    let resp_bytes = read_frame(&mut tls).await?;
    let _ = tls.shutdown().await;
    let v: serde_json::Value = serde_json::from_slice(&resp_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false))
}

// ----- HTTP routes -----------------------------------------------------------

#[derive(Deserialize)]
pub struct TicketRequest {
    /// The governance scope the resulting grant admits (default `bridge:invoke`).
    #[serde(default)]
    pub scope: Option<String>,
    /// Grant lifetime in seconds (default 1 hour).
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

/// `POST /federation/pairing-ticket` — mint a ticket describing this authority.
pub async fn post_pairing_ticket(
    State(wb): State<SharedWorkbench>,
    body: Option<Json<TicketRequest>>,
) -> impl IntoResponse {
    let req = body.map(|b| b.0);
    let scope = req
        .as_ref()
        .and_then(|r| r.scope.clone())
        .unwrap_or_else(|| "bridge:invoke".to_string());
    let ttl = req.as_ref().and_then(|r| r.ttl_secs);
    let guard = wb.lock_unpoisoned();
    let pubkey = guard.governance_public_key();
    match guard.federation_ref() {
        Some(fed) => (StatusCode::OK, Json(fed.mint_ticket(pubkey, scope, ttl))).into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, "federation not configured").into_response(),
    }
}

/// `POST /federation/pair` — accept a peer's ticket (TOFU pin) and start listening
/// for its crossings. Idempotent per peer; re-pairing rotates the pins.
pub async fn post_pair(
    State(wb): State<SharedWorkbench>,
    Json(ticket): Json<PairingTicket>,
) -> impl IntoResponse {
    let peer = AuthorityId::new(&ticket.authority);
    let record = {
        let mut guard = wb.lock_unpoisoned();
        let grant_id = crate::library::gen_id("grant");
        let record = match guard.federation_mut() {
            Some(fed) => fed.accept_ticket(&ticket, grant_id.clone()),
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured")
                    .into_response()
            }
        };
        // Persist the pairing to the durable roster (ITGOV-2) so the peer/grant/pin
        // survive a restart instead of living only in the in-memory maps.
        persist_bridge(guard.store_mut(), &ticket, &grant_id, true);
        record
    };
    spawn_peer_receivers(&wb, peer);
    (StatusCode::OK, Json(record)).into_response()
}

/// Park every receiver leg used by the shipped handoff, co-drive, and erasure flows
/// for a freshly pinned `peer`. Shared by `POST /federation/pair` and the combined-invite
/// Accept, which pins a peer the same way (ADR 0047).
fn spawn_peer_receivers(wb: &SharedWorkbench, peer: AuthorityId) {
    tokio::spawn(run_handoff_receiver(wb.clone(), peer.clone()));
    tokio::spawn(run_place_receiver(wb.clone(), peer.clone()));
    tokio::spawn(run_result_receiver(wb.clone(), peer.clone()));
    tokio::spawn(run_erasure_receiver(wb.clone(), peer));
}

/// Re-park the per-peer receiver legs for every **active** peer restored from the durable
/// roster at boot (`ITGOV-2`). The boot path re-pins peers/grants in-memory but cannot spawn
/// the tokio receiver tasks (they need the shared `Workbench` handle); `serve` calls this once
/// the handle exists, so a paired peer can receive crossings again after a restart.
pub fn respawn_restored_receivers(wb: &SharedWorkbench) {
    let peers = {
        let guard = wb.lock_unpoisoned();
        guard
            .federation_ref()
            .map(|f| f.peers())
            .unwrap_or_default()
    };
    for p in peers.into_iter().filter(|p| p.active) {
        spawn_peer_receivers(wb, AuthorityId::new(&p.authority));
    }
}

/// `DELETE /federation/peers/:authority` — revoke a paired peer (`ITGOV-2`): drop the live
/// grant/pin (future crossings denied, fail-closed) and tombstone the durable bridge so the
/// revoke survives a restart. Future-only; payload already crossed is `ERASE-1`.
pub async fn delete_peer(
    State(wb): State<SharedWorkbench>,
    axum::extract::Path(authority): axum::extract::Path<String>,
) -> impl IntoResponse {
    let mut guard = wb.lock_unpoisoned();
    let Some(fed) = guard.federation_mut() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured").into_response();
    };
    if !fed.revoke_peer(&authority) {
        return (StatusCode::NOT_FOUND, "no such peer").into_response();
    }
    // Tombstone the durable bridge: a fresh load no longer re-pins it. The roster keeps the
    // history (active=false), so IT's revoke is auditable (INV-18).
    if let Some(b) = folded_bridges(guard.store_ref())
        .into_iter()
        .find(|b| b.id == authority)
    {
        persist_bridge(guard.store_mut(), &b.ticket, &b.grant_id, false);
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "authority": authority, "active": false })),
    )
        .into_response()
}

/// `GET /federation/peers` — the paired-peer projection.
pub async fn get_peers(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let guard = wb.lock_unpoisoned();
    let peers = guard
        .federation_ref()
        .map(|f| f.peers())
        .unwrap_or_default();
    Json(serde_json::json!({ "peers": peers }))
}

#[derive(Deserialize)]
pub struct CrossRequest {
    /// The peer authority to cross to.
    pub peer: String,
    /// The payload **handle** to cross (never the payload, `INV-10`).
    pub handle: String,
    /// A unique correlation id for this crossing (the caller supplies one).
    pub correlation: String,
}

/// `POST /federation/cross` — hand-drive one crossing to a paired peer over the
/// cert-pinned TLS leg; returns whether the peer admitted it. The far side records
/// the fact (and emits SSE) only on its own verified admission.
pub async fn post_cross(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<CrossRequest>,
) -> impl IntoResponse {
    let peer = AuthorityId::new(&req.peer);
    // Snapshot transport + signing material without holding the lock across I/O. The
    // device subkey + its root-signed delegation (Model A) sign the crossing.
    let (broker, me, subkey, delegation, pins, paired) = {
        let guard = wb.lock_unpoisoned();
        let me = guard.federation_authority().clone();
        let root = federation_root_signing_key(&guard);
        let (subkey, delegation) = device_identity(&guard_root(&guard), &me, &root);
        match guard.federation_ref() {
            Some(fed) => (
                fed.broker_addr.clone(),
                me,
                subkey,
                delegation,
                fed.pins_arc(),
                fed.grant_for(peer.as_str()).is_some(),
            ),
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured")
                    .into_response()
            }
        }
    };
    if !paired {
        return (
            StatusCode::BAD_REQUEST,
            format!("not paired with {}", req.peer),
        )
            .into_response();
    }
    match send_crossing(
        &broker,
        &me,
        &subkey,
        &delegation,
        &peer,
        pins,
        &req.correlation,
        &req.handle,
    )
    .await
    {
        Ok(admitted) => (
            StatusCode::OK,
            Json(serde_json::json!({ "admitted": admitted })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("crossing failed: {e}")).into_response(),
    }
}

#[derive(Deserialize)]
pub struct RevokeRequest {
    /// The peer to notify (it stops accepting crossings from the revoked subkey).
    pub peer: String,
}

/// `POST /federation/revoke-device` — revoke **this** authority's current device
/// subkey and push the root-signed revocation to a paired peer (Model A / FED-5a).
/// The peer denies any later crossing presenting the revoked subkey, before its
/// delegation expires. Returns whether the peer accepted the revocation.
pub async fn post_revoke_device(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<RevokeRequest>,
) -> impl IntoResponse {
    let peer = AuthorityId::new(&req.peer);
    let (broker, me, root, pins, paired) = {
        let guard = wb.lock_unpoisoned();
        let me = guard.federation_authority().clone();
        let root = federation_root_signing_key(&guard);
        match guard.federation_ref() {
            Some(fed) => (
                fed.broker_addr.clone(),
                me,
                root,
                fed.pins_arc(),
                fed.grant_for(peer.as_str()).is_some(),
            ),
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured")
                    .into_response()
            }
        }
    };
    if !paired {
        return (
            StatusCode::BAD_REQUEST,
            format!("not paired with {}", req.peer),
        )
            .into_response();
    }
    // Revoke this authority's current device subkey under its root.
    let (subkey, _) = device_identity(&guard_root(&wb.lock_unpoisoned()), &me, &root);
    let rev = SubkeyRevocation::issue(&root, subkey.public_key(), now_secs());
    match send_revocation(&broker, &me, &peer, pins, &rev).await {
        Ok(ok) => (StatusCode::OK, Json(serde_json::json!({ "accepted": ok }))).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("revoke failed: {e}")).into_response(),
    }
}

#[derive(Deserialize)]
pub struct RemoteRunRequest {
    /// The peer authority whose runtime executes the turn.
    pub peer: String,
    /// The run scope the owner admits the returned observations into.
    pub run_scope: String,
    /// The prompt the peer's runtime runs.
    pub prompt: String,
}

/// `POST /federation/remote-run` — place a run on a paired peer (Flow 1 /
/// OBSERVATION-FEDERATION-1): send the prompt over the cert-pinned TLS leg, the
/// peer executes a turn, and the owner admits each returned observation as run
/// evidence (standing truth only via the owner's admission, INV-4). Returns how
/// many observations the owner admitted.
pub async fn post_remote_run(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<RemoteRunRequest>,
) -> impl IntoResponse {
    let peer = AuthorityId::new(&req.peer);
    let (broker, me, pins, paired) = {
        let guard = wb.lock_unpoisoned();
        let me = guard.federation_authority().clone();
        match guard.federation_ref() {
            Some(fed) => (
                fed.broker_addr.clone(),
                me,
                fed.pins_arc(),
                fed.grant_for(peer.as_str()).is_some(),
            ),
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured")
                    .into_response()
            }
        }
    };
    if !paired {
        return (
            StatusCode::BAD_REQUEST,
            format!("not paired with {}", req.peer),
        )
            .into_response();
    }
    match remote_run_rpc(&broker, &me, &peer, pins, &req.run_scope, &req.prompt).await {
        Ok(resp) => {
            let admitted = admit_observations(
                &wb,
                &req.run_scope,
                peer.as_str(),
                &resp.observations,
                &resp.delegation,
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "observations_admitted": admitted,
                    "assistant_text": resp.assistant_text,
                })),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("remote run failed: {e}")).into_response(),
    }
}

// --- Co-drive: host admission of operator-driven runs (FED-7) ---------------------
//
// After a handoff the project's home is the HOST; the OPERATOR may drive runs, but each
// is a federation crossing the host ADMITS before it executes (INV-13/INV-4). The
// operator *places* a run (an archetype over a connected data handle) on a hosted
// project; the host executes it immediately if it holds a standing per-project **allow**,
// else the run lands in the host's admission **queue** (fail-closed) for the host to
// *Allow for project* or *Deny*. Modeled in
// [`run-admission.qnt`](../../../specs/models/run-admission.qnt). Distinct from the
// legacy ungated `POST /federation/remote-run`.

/// The host's admission queue of operator runs (pending, folded latest-wins per
/// correlation: `placed` opens, `resolved` closes), and the per-project standing allows.
const RUN_QUEUE_SCOPE: &str = "run::queue";
fn run_allow_scope(project: &str) -> String {
    format!("run::allow::{project}")
}

/// Whether `operator` has a standing per-project allow on `project` (folded latest-wins:
/// an `allow` grants, a `revoke` withdraws). Fail-closed by default.
fn run_allowed(store: &Store, project: &str, operator: &str) -> bool {
    let mut allowed = false;
    for payload in store
        .records(&run_allow_scope(project), "operator")
        .unwrap_or_default()
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            if v.get("operator").and_then(|o| o.as_str()) == Some(operator) {
                allowed = v.get("allow").and_then(|a| a.as_bool()).unwrap_or(false);
            }
        }
    }
    allowed
}

/// ITGOV-3(b) / [ADR 0074]: the **continuous placement floor** on a federated run (ADR 0061
/// entry-point #2). A standing [`run_allowed`] grant admits *that the operator may drive*; the
/// org's placement policy still governs *where the run may execute*. The run runs host-side in
/// `project`'s boundary, so its declared deployment mode ([`Library::deployment_mode_of`]) must
/// satisfy the org's [`effective_placement_policy`](crate::org::Org::effective_placement_policy) —
/// the per-run analog of the accept gate (`accept_boundary` / `post_handoff_accept`). No
/// attestation quote crosses on a run-place, so an attested-required policy refuses a run that
/// cannot prove it (`measurement_verified = false`), fail-closed (`INV-20`). Restrict-only and
/// monotone: it can only *narrow* what the grant allowed, never widen. **Open policy ⇒ admits**
/// (the solo / no-policy default; org-ness never touches the core path, ADR 0061 §4).
///
/// [ADR 0074]: ../../../specs/decisions/0074-continuous-abac-floor-on-federated-runs.md
fn run_place_floor_admits(store: &Store, library: &crate::library::Library, project: &str) -> bool {
    use gaugedesk_core::boundary_lifecycle::{pairing_admitted, PlacementPolicy};
    let policy = crate::org::Org::rebuild(store)
        .map(|o| o.effective_placement_policy())
        .unwrap_or_else(|_| PlacementPolicy::open());
    if policy == PlacementPolicy::open() {
        return true; // no-op on the default (no-org) path
    }
    pairing_admitted(&policy, &library.deployment_mode_of(project), false)
}

/// Record a pending operator run in the host's admission queue.
fn record_pending_run(store: &mut Store, wire: &RunPlaceWire) {
    let rec = serde_json::json!({
        "op": "placed",
        "correlation": wire.correlation,
        "operator": wire.source,
        "project": wire.project,
        "archetype": wire.archetype,
        "data_handle": wire.data_handle,
        "prompt": wire.prompt,
        "target_chat": wire.target_chat,
    });
    let _ = store.append_record(RUN_QUEUE_SCOPE, "event", &rec.to_string());
}

/// The pending (placed, unresolved) operator runs, as the host's admission queue —
/// handles + correlation only (`INV-10`), never peer payload.
fn pending_runs(store: &Store) -> Vec<serde_json::Value> {
    let mut by_corr: BTreeMap<String, Option<serde_json::Value>> = BTreeMap::new();
    for payload in store.records(RUN_QUEUE_SCOPE, "event").unwrap_or_default() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            let corr = v
                .get("correlation")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            match v.get("op").and_then(|o| o.as_str()) {
                Some("placed") => {
                    by_corr.insert(corr, Some(v));
                }
                Some("resolved") => {
                    by_corr.insert(corr, None);
                }
                _ => {}
            }
        }
    }
    by_corr.into_values().flatten().collect()
}

fn resolve_run(store: &mut Store, correlation: &str, how: &str) {
    let rec = serde_json::json!({ "op": "resolved", "correlation": correlation, "how": how });
    let _ = store.append_record(RUN_QUEUE_SCOPE, "event", &rec.to_string());
}

/// The bytes the operator signs when placing a run (`INV-21`: the placement is
/// source-authorized by the operator's key, verified against the pinned grant).
fn run_place_bytes(correlation: &str) -> Vec<u8> {
    format!("gaugewright-run-place::{correlation}").into_bytes()
}

/// The rendezvous token an `operator → host` run placement uses.
fn run_place_token(operator: &str, host: &str) -> String {
    format!("gaugewright-run-place::{operator}->{host}")
}

/// A run the operator places on a hosted project, sent to the host over the cert-pinned
/// leg (archetype + data handle only — never payload, `INV-10`; signed, `INV-21`).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RunPlaceWire {
    correlation: String,
    project: String,
    archetype: String,
    data_handle: String,
    prompt: String,
    /// Existing hub-resident workstream member to drive. Older generic co-drive
    /// callers omit this and retain the legacy isolated-run behavior.
    #[serde(default)]
    target_chat: Option<String>,
    source: String,
    target: String,
    signed_bytes: Vec<u8>,
    signature: gaugedesk_core::signature::Signature,
    source_pubkey: String,
    #[serde(default)]
    delegation: Option<DeviceDelegation>,
}

/// The host's verdict on a placed run: `admitted` (executed now — standing allow — with
/// the observations), or `pending` (queued for the host's decision).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RunPlaceVerdict {
    status: String, // "admitted" | "pending" | "refused"
    #[serde(default)]
    resp: Option<RunResp>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
pub struct ConsentRequest {
    /// The owner authority hosting the review (the consent's destination).
    pub owner: String,
    /// The review scope being consented to.
    pub review_scope: String,
}

/// `POST /federation/consent` — this authority, a remote stakeholder on `owner`'s
/// review, signs and sends its consent over the cert-pinned TLS leg (Flow 2). The
/// owner authenticates it against this authority's pinned grant and admits it into
/// the conjunctive-consent review. Returns the owner's resulting review state.
pub async fn post_consent(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<ConsentRequest>,
) -> impl IntoResponse {
    let owner = AuthorityId::new(&req.owner);
    let (broker, me, subkey, delegation, pins, paired) = {
        let guard = wb.lock_unpoisoned();
        let me = guard.federation_authority().clone();
        let root = federation_root_signing_key(&guard);
        let (subkey, delegation) = device_identity(&guard.root_path(), &me, &root);
        match guard.federation_ref() {
            Some(fed) => (
                fed.broker_addr.clone(),
                me,
                subkey,
                delegation,
                fed.pins_arc(),
                fed.grant_for(owner.as_str()).is_some(),
            ),
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured")
                    .into_response()
            }
        }
    };
    if !paired {
        return (
            StatusCode::BAD_REQUEST,
            format!("not paired with {}", req.owner),
        )
            .into_response();
    }
    match send_consent(
        &broker,
        &me,
        &subkey,
        &delegation,
        &owner,
        pins,
        &req.review_scope,
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("consent failed: {e}")).into_response(),
    }
}

/// KEY-EGRESS guard (CONF-6): refuse a key-material operation while network HTTP is
/// enabled (`GAUGEDESK_ALLOW_NETWORK_HTTP=1`). The control-plane API is unauthenticated
/// and peers federate over the broker, never this API — so root-key export/restore
/// is a loopback-only, local-operator operation. Fail-closed: any network-HTTP
/// posture refuses regardless of the actual bind.
fn network_http_refusal(op: &str) -> Option<axum::response::Response> {
    if gaugedesk_env::enabled("ALLOW_NETWORK_HTTP") {
        return Some(
            (
                StatusCode::FORBIDDEN,
                format!("{op} is loopback-only; refused while GAUGEDESK_ALLOW_NETWORK_HTTP=1"),
            )
                .into_response(),
        );
    }
    None
}

/// `POST /federation/recovery-code` — export this authority's **root** governance
/// key as a transcribable recovery code (sovereign-peer backup, FED-5b-2).
/// **SENSITIVE**: the code is the private key in transcribable form. It may cross
/// the API only to the local operator over a loopback-only control plane; if
/// network HTTP is enabled the (unauthenticated) API may be reachable by others, so
/// export hard-refuses (CONF-6 / KEY-EGRESS, fail-closed).
pub async fn post_recovery_code(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    if let Some(resp) = network_http_refusal("recovery-code export") {
        return resp;
    }
    let guard = wb.lock_unpoisoned();
    let me = guard.federation_authority().clone();
    let root = federation_root_signing_key(&guard);
    let code = gaugedesk_core::recovery::export_recovery(&root);
    Json(serde_json::json!({ "authority": me.as_str(), "recovery_code": code })).into_response()
}

#[derive(Deserialize)]
pub struct RestoreRequest {
    /// The recovery code previously exported (dashes / whitespace / case ignored).
    pub code: String,
}

/// `POST /federation/restore` — restore this authority's root from a recovery code
/// (re-enroll the recovered seed). The recovered key has the **same** public
/// identity it had when exported, so peers keep the root they pinned (restore is
/// recovery). Returns the resulting governance public key.
pub async fn post_restore(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<RestoreRequest>,
) -> impl IntoResponse {
    // CONF-6 / KEY-EGRESS: restore re-enrolls the authority's root key — an
    // identity-changing key-material op. Loopback-only, for the same reason as
    // export; over a network-reachable unauthenticated API it would be an identity
    // takeover. Fail-closed.
    if let Some(resp) = network_http_refusal("recovery restore") {
        return resp;
    }
    let key = match gaugedesk_core::recovery::import_recovery(&req.code) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid recovery code: {e:?}"),
            )
                .into_response()
        }
    };
    let guard = wb.lock_unpoisoned();
    let me = guard.federation_authority().clone();
    if root_authority_id(&key.public_key()) != me {
        return (
            StatusCode::CONFLICT,
            "recovery code belongs to a different federation authority",
        )
            .into_response();
    }
    let ks = FileKeyStore::new(guard_root(&guard).join("keys"));
    if let Err(e) = ks.enroll(guard.federation_key_authority(), &key) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("enroll failed: {e}"),
        )
            .into_response();
    }
    Json(serde_json::json!({
        "authority": me.as_str(),
        "governance_pubkey": key.public_key().as_str(),
    }))
    .into_response()
}

/// `GET /federation/inbox` — the federated facts that have crossed into this
/// authority (handles + correlation only), the far-side demo evidence.
pub async fn get_inbox(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let guard = wb.lock_unpoisoned();
    let facts: Vec<serde_json::Value> = guard
        .store_ref()
        .records(FED_INBOX_SCOPE, "federated")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| serde_json::from_str(&r).ok())
        .collect();
    Json(serde_json::json!({ "federated": facts }))
}

/// The workbench's state root (for resolving the FileKeyStore). A thin accessor so
/// the route doesn't reach into private fields.
fn guard_root(guard: &crate::Workbench) -> std::path::PathBuf {
    guard.root_path()
}

// ---------------------------------------------------------------------------
// Project handoff / authority relocation (FED-6) — the control-plane surface over
// the `gaugedesk_core::handoff` reducer. A project's handoff history is an append-only
// per-project event scope; current state is the deterministic fold of those events
// through `handoff::evolve` (`INV-6`/`INV-7`/`INV-8`). Each endpoint `decide`s one
// command against the folded state and appends the resulting event(s).
//
// This exposes and drives the relocation lifecycle locally on each control plane.
// The cross-machine carriage of the offer + the target-side receiver that ships the
// log and commits on the peer is the remaining D-REMOTE exercise (tracker `FED-6`);
// it rides the same broker/TLS legs as the existing crossing.

const HANDOFF_KIND: &str = "event";

fn handoff_scope(project: &str) -> String {
    format!("handoff::{project}")
}

fn handoff_phase_str(p: HandoffPhase) -> &'static str {
    match p {
        HandoffPhase::Draft => "draft",
        HandoffPhase::Offered => "offered",
        HandoffPhase::LogSynced => "log_synced",
        HandoffPhase::Committed => "committed",
        HandoffPhase::Aborted => "aborted",
    }
}

fn handoff_state_json(project: &str, s: &HandoffState) -> serde_json::Value {
    serde_json::json!({
        "project": project,
        "phase": handoff_phase_str(s.phase),
        // Derive the two wire flags from the single typed home (the client reads
        // `home_target` to pick its `home` union; the wire shape is unchanged).
        "home_origin": s.home == handoff::Home::Origin,
        "home_target": s.home == handoff::Home::Target,
        "target_has_log": s.target_has_log,
    })
}

/// Current handoff state for a project: the deterministic fold of its event scope.
fn load_handoff(store: &Store, project: &str) -> HandoffState {
    store
        .records(&handoff_scope(project), HANDOFF_KIND)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| serde_json::from_str::<HandoffEvent>(&r).ok())
        .fold(HandoffState::default(), |s, e| handoff::evolve(&s, e))
}

/// `decide` one command against the folded state, append the resulting events, and
/// return the new state. A rejection appends nothing (fail-closed).
fn apply_handoff(
    store: &mut Store,
    project: &str,
    cmd: HandoffCommand,
) -> Result<HandoffState, &'static str> {
    let mut state = load_handoff(store, project);
    let events = handoff::decide(&state, cmd).map_err(|r| r.reason)?;
    let scope = handoff_scope(project);
    for e in &events {
        let payload = serde_json::to_string(e).expect("handoff event serializes");
        store
            .append_record(&scope, HANDOFF_KIND, &payload)
            .map_err(|_| "handoff: store append failed")?;
        state = handoff::evolve(&state, *e);
    }
    Ok(state)
}

/// Commit the reducer's Home flip and the concrete project→Home binding in one
/// SQLite transaction. A crash exposes both facts or neither, never split-brain.
fn commit_handoff_and_rebind(
    wb: &mut Workbench,
    project: &str,
    home: HomeId,
) -> Result<HandoffState, &'static str> {
    let mut state = load_handoff(wb.store_ref(), project);
    let events = handoff::decide(&state, HandoffCommand::CommitHandoff).map_err(|r| r.reason)?;
    let project_record = wb
        .project_record_for_home_rebind(project, home)
        .ok_or("handoff: project binding missing")?;
    let scope = handoff_scope(project);
    let event_payloads: Vec<String> = events
        .iter()
        .map(|event| serde_json::to_string(event).expect("handoff event serializes"))
        .collect();
    let project_payload =
        serde_json::to_string(&project_record).map_err(|_| "handoff: project serialize failed")?;
    let mut records: Vec<(&str, &str, &str)> = event_payloads
        .iter()
        .map(|payload| (scope.as_str(), HANDOFF_KIND, payload.as_str()))
        .collect();
    records.push((
        crate::library::LIBRARY_SCOPE,
        "project",
        project_payload.as_str(),
    ));
    wb.store_mut()
        .append_records_atomically(&records)
        .map_err(|_| "handoff: atomic Home commit failed")?;
    for event in events {
        state = handoff::evolve(&state, event);
    }
    wb.apply_atomic_project_home_rebind(project_record);
    Ok(state)
}

fn handoff_response(
    wb: &SharedWorkbench,
    project: &str,
    cmd: HandoffCommand,
) -> axum::response::Response {
    let mut guard = wb.lock_unpoisoned();
    match apply_handoff(guard.store_mut(), project, cmd) {
        Ok(state) => (StatusCode::OK, Json(handoff_state_json(project, &state))).into_response(),
        Err(reason) => (StatusCode::BAD_REQUEST, reason).into_response(),
    }
}

#[derive(Deserialize)]
pub struct HandoffProjectRequest {
    /// The project whose home is being relocated.
    pub project: String,
}

/// `POST /federation/handoff/abort` — abandon the in-flight handoff; home rolls back
/// to the origin (the `INV-23` escape). A cross-machine pending offer is cancelled
/// on the target before the origin records its terminal abort, so a stale consent
/// cannot later promote the target after the origin has rolled back.
pub async fn post_handoff_abort(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<HandoffProjectRequest>,
) -> impl IntoResponse {
    let peer = {
        let guard = wb.lock_unpoisoned();
        pending_outgoing_peer(guard.store_ref(), &req.project)
    };
    let Some(peer) = peer else {
        return handoff_response(&wb, &req.project, HandoffCommand::AbortHandoff);
    };
    let peer = AuthorityId::new(peer);
    let (broker, me, source_home, subkey, delegation, pins) = {
        let guard = wb.lock_unpoisoned();
        let me = guard.federation_authority().clone();
        let root = federation_root_signing_key(&guard);
        let (subkey, delegation) = device_identity(&guard_root(&guard), &me, &root);
        let Some(fed) = guard.federation_ref() else {
            return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured").into_response();
        };
        (
            fed.broker_addr.clone(),
            me,
            guard.federation_home_id(),
            subkey,
            delegation,
            fed.pins_arc(),
        )
    };
    let verdict = match send_handoff(
        &broker,
        &me,
        &source_home,
        &subkey,
        &delegation,
        &peer,
        pins,
        HandoffMsgKind::Cancelled,
        &req.project,
        Vec::new(),
        Vec::new(),
        None,
        None,
    )
    .await
    {
        Ok(verdict) => verdict,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("handoff cancellation transport failed: {error}"),
            )
                .into_response();
        }
    };
    if !verdict
        .get("cancelled")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return (
            StatusCode::CONFLICT,
            "target no longer holds a pending handoff",
        )
            .into_response();
    }
    let mut guard = wb.lock_unpoisoned();
    let response = match apply_handoff(
        guard.store_mut(),
        &req.project,
        HandoffCommand::AbortHandoff,
    ) {
        Ok(state) => {
            let _ =
                record_outgoing_handoff(guard.store_mut(), "resolved", &req.project, peer.as_str());
            (
                StatusCode::OK,
                Json(handoff_state_json(&req.project, &state)),
            )
                .into_response()
        }
        Err(reason) => (StatusCode::CONFLICT, reason).into_response(),
    };
    response
}

#[derive(Deserialize)]
pub struct HandoffStatusQuery {
    pub project: String,
}

/// `GET /federation/handoff/status?project=…` — the handoff projection (phase + which
/// authority is home), folded from the project's event scope (`INV-5`).
pub async fn get_handoff_status(
    State(wb): State<SharedWorkbench>,
    Query(q): Query<HandoffStatusQuery>,
) -> impl IntoResponse {
    let guard = wb.lock_unpoisoned();
    let state = load_handoff(guard.store_ref(), &q.project);
    Json(handoff_state_json(&q.project, &state))
}

// --- Cross-machine carriage: relocate a project's home to a paired peer ----------
//
// The origin offers (stays home), ships the project log + a signed offer over the
// cert-pinned TLS leg, and the peer's parked handoff receiver verifies the offer
// against the pinned grant (C-1/INV-21), imports the log, and drives ITS handoff
// reducer to Committed — the peer becomes home (`LOG_BEFORE_HOME`, `INV-13`). On the
// peer's commit ack the origin commits its own side (origin → operator); a decline
// or transport failure rolls the origin back (abort). Mirrors the crossing carriage.

/// The project's relocatable event log lives under this scope; relocation ships it.
fn project_log_scope(project: &str) -> String {
    format!("project_log::{project}")
}

/// The canonical bytes a handoff offer signs — binds the offer to its project so a
/// captured offer cannot be replayed against a different project (no-replay).
fn handoff_bytes(project: &str, source_home: &HomeId) -> Vec<u8> {
    format!("handoff-offer::{project}::{}", source_home.as_str()).into_bytes()
}

/// The derived rendezvous token a `source → target` handoff uses (a namespace
/// distinct from crossings so the two receivers never contend on one token).
fn handoff_inbox_token(source: &str, target: &str) -> String {
    format!("gaugewright-handoff::{source}->{target}")
}

/// One relocated log record (scope/kind/payload) imported verbatim on the target.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct HandoffLogRecord {
    scope: String,
    kind: String,
    payload: String,
}

/// One relocated target's versioned-workspace export. The format tag prevents a
/// mixed-substrate target from interpreting opaque bytes under the wrong provider.
/// The bytes are opaque to
/// the relay (`INV-14`); they re-derive no state (the log is authority, `INV-5`), they
/// only place the content the log's handles point at. They land **before** the target's
/// home commits (`STATE_BEFORE_HOME`, FED-6).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct HandoffContentBundle {
    target_id: String,
    format: String,
    bundle: Vec<u8>,
}

/// What a handoff message asks the receiver to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum HandoffMsgKind {
    /// origin → target: a relocation offer (carries the log). The target admits it —
    /// auto if pre-authorized, else it lands pending for explicit consent (`INV-13`).
    Offer,
    /// target → origin: the target consented and committed (is now home); the origin
    /// commits its side (becomes operator).
    Committed,
    /// target → origin: the target declined; the origin rolls back (stays home).
    Declined,
    /// origin → target: the origin cancelled an offer that is still pending target
    /// consent. The target removes the held offer without importing or committing it.
    Cancelled,
    /// serving Home → operator: a root-signed reachability update for the
    /// shared project. It changes no handoff state.
    Route,
}

/// A handoff message as it travels the TLS leg: the kind, the project, the log
/// snapshot (on `Offer`), and the signature the target verifies against the grant's
/// pinned source key (C-1).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct HandoffWire {
    kind: HandoffMsgKind,
    project: String,
    source: String,
    target: String,
    /// The sender's actual logical Home. On a committed target→origin
    /// notification this is the new authoritative project binding.
    source_home: HomeId,
    #[serde(default)]
    log: Vec<HandoffLogRecord>,
    /// The project's content bytes — one bundle per bound instance (on `Offer`).
    #[serde(default)]
    content: Vec<HandoffContentBundle>,
    /// The project credential data key, sealed to the target authority's
    /// pinned governance key. The relay and source log see ciphertext only;
    /// the target re-wraps the opened key inside its Home boundary.
    #[serde(default)]
    credential_key: Option<SealedKey>,
    #[serde(default)]
    shared_route: Option<crate::home::OpaqueHomeRoute>,
    signed_bytes: Vec<u8>,
    signature: gaugedesk_core::signature::Signature,
    source_pubkey: String,
    #[serde(default)]
    delegation: Option<DeviceDelegation>,
}

/// Whether a scope belongs to `project` — its owned event scopes: the canonical
/// `project_log::<id>` plus any `project::<id>::*` sub-scope. The trailing `::` guards
/// against an id that is a prefix of another (`eng` vs `eng2`).
fn is_project_scope(scope: &str, project: &str) -> bool {
    scope == project_log_scope(project)
        || scope == format!("project::{project}")
        || scope.starts_with(&format!("project::{project}::"))
}

/// The latest record (folded by `id`) of one `library` kind for which `keep` holds —
/// shipped so the target's library projection registers exactly the relocated
/// project's nouns, never another project's. Only the latest per id travels (the
/// target re-folds it); never the whole library scope.
fn latest_library_records(
    store: &Store,
    kind: &str,
    keep: impl Fn(&serde_json::Value) -> bool,
) -> Vec<HandoffLogRecord> {
    latest_library_records_by(store, kind, "id", keep)
}

fn latest_library_records_by(
    store: &Store,
    kind: &str,
    key: &str,
    keep: impl Fn(&serde_json::Value) -> bool,
) -> Vec<HandoffLogRecord> {
    let mut by_id: BTreeMap<String, String> = BTreeMap::new();
    for payload in store.records(LIBRARY_SCOPE, kind).unwrap_or_default() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            if keep(&v) {
                if let Some(id) = v.get(key).and_then(|i| i.as_str()) {
                    by_id.insert(id.to_string(), payload);
                }
            }
        }
    }
    by_id
        .into_values()
        .map(|payload| HandoffLogRecord {
            scope: LIBRARY_SCOPE.to_string(),
            kind: kind.to_string(),
            payload,
        })
        .collect()
}

/// The origin's snapshot of a project's relocatable log: **every** record under
/// **every** scope the project owns (`project_log::<id>` and `project::<id>::*`),
/// across all kinds, plus the project's `library` nouns (its `ProjectRecord`, the
/// placements, targets, chats, workstreams, and referenced archetypes required to
/// register the project as a usable whole. Records cross verbatim; protected bytes
/// behind handles travel separately as content bundles ([`collect_project_content`]).
fn collect_project_log(store: &Store, project: &str) -> Vec<HandoffLogRecord> {
    let mut out = Vec::new();
    for scope in store.scope_ids().unwrap_or_default() {
        if !is_project_scope(&scope, project) {
            continue;
        }
        for (_pos, kind, payload) in store.events(&scope).unwrap_or_default() {
            out.push(HandoffLogRecord {
                scope: scope.clone(),
                kind,
                payload,
            });
        }
    }
    // The project's library nouns. Only this project's records — never the whole
    // library scope (that holds other projects).
    out.extend(latest_library_records(store, "project", |v| {
        v.get("id").and_then(|i| i.as_str()) == Some(project)
    }));
    // The using-instances bound into the project — and, via them, the chats they hold
    // and the agents they bind, so the relocated project is a complete library subtree.
    let instances = latest_library_records(store, "instance", |v| {
        v.get("project_id").and_then(|p| p.as_str()) == Some(project)
    });
    let inst_ids: std::collections::BTreeSet<String> = instances
        .iter()
        .filter_map(|r| serde_json::from_str::<serde_json::Value>(&r.payload).ok())
        .filter_map(|v| v.get("id").and_then(|i| i.as_str()).map(str::to_string))
        .collect();
    let agent_ids: std::collections::BTreeSet<String> = instances
        .iter()
        .filter_map(|r| serde_json::from_str::<serde_json::Value>(&r.payload).ok())
        .filter_map(|v| {
            v.get("agent_id")
                .and_then(|a| a.as_str())
                .map(str::to_string)
        })
        .collect();
    let instance_values = instances
        .iter()
        .filter_map(|record| serde_json::from_str::<serde_json::Value>(&record.payload).ok())
        .collect::<Vec<_>>();
    // Omit authoring bytes only when every placement of this Agent in the
    // relocating project is protected. A mixed licensed/protected project
    // retains the ordinary target for its licensed placement.
    let protected_agent_ids: std::collections::BTreeSet<String> = agent_ids
        .iter()
        .filter(|agent| {
            let matching = instance_values
                .iter()
                .filter(|value| {
                    value.get("agent_id").and_then(|id| id.as_str()) == Some(agent.as_str())
                })
                .collect::<Vec<_>>();
            !matching.is_empty()
                && matching.iter().all(|value| {
                    value
                        .get("id")
                        .and_then(|id| id.as_str())
                        .is_some_and(|placement| {
                            crate::protected_profiles::distribution_for(store, placement)
                                .is_some_and(|record| {
                                    record.profile
                                        == crate::protected_profiles::DistributionProfile::ProtectedCommercial
                                })
                        })
                })
        })
        .cloned()
        .collect();
    let mut agents = latest_library_records(store, "agent", |v| {
        v.get("id")
            .and_then(|i| i.as_str())
            .is_some_and(|i| agent_ids.contains(i))
    });
    let protected_authoring_instance_ids = agents
        .iter()
        .filter_map(|record| serde_json::from_str::<serde_json::Value>(&record.payload).ok())
        .filter(|value| {
            value
                .get("id")
                .and_then(|id| id.as_str())
                .is_some_and(|id| protected_agent_ids.contains(id))
        })
        .filter_map(|value| {
            value
                .get("instance_id")
                .and_then(|id| id.as_str())
                .map(str::to_owned)
        })
        .collect::<std::collections::BTreeSet<_>>();
    // Protected placements carry public identity/version metadata but never the
    // plaintext config or a usable authoring-target pointer. Those bytes live
    // only inside the owner-authorized protected artifact.
    for record in &mut agents {
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&record.payload) else {
            continue;
        };
        if value
            .get("id")
            .and_then(|id| id.as_str())
            .is_some_and(|id| protected_agent_ids.contains(id))
        {
            value["config"] = serde_json::Value::String("{}".to_owned());
            value["instance_id"] = serde_json::Value::String(String::new());
            if let Ok(payload) = serde_json::to_string(&value) {
                record.payload = payload;
            }
        }
    }
    let authoring_instance_ids: std::collections::BTreeSet<String> = agents
        .iter()
        .filter_map(|record| serde_json::from_str::<serde_json::Value>(&record.payload).ok())
        .filter_map(|value| {
            value
                .get("instance_id")
                .and_then(|id| id.as_str())
                .map(str::to_owned)
        })
        .collect();
    let authoring_instances = latest_library_records(store, "instance", |v| {
        v.get("id")
            .and_then(|id| id.as_str())
            .is_some_and(|id| authoring_instance_ids.contains(id))
            && v.get("agent_id")
                .and_then(|id| id.as_str())
                .is_none_or(|id| !protected_agent_ids.contains(id))
    });
    out.extend(instances);
    out.extend(authoring_instances);
    // Instance lifecycle is reduced under the instance id, outside the
    // `project::<id>::*` namespace. Carry both using and referenced authoring
    // instance scopes so the target receives runnable placements and a usable
    // archetype definition rather than library nouns with missing state.
    for instance_id in inst_ids.iter().chain(
        authoring_instance_ids
            .iter()
            .filter(|id| !protected_authoring_instance_ids.contains(*id)),
    ) {
        for (_position, kind, payload) in store.events(instance_id).unwrap_or_default() {
            out.push(HandoffLogRecord {
                scope: instance_id.clone(),
                kind,
                payload,
            });
        }
    }
    out.extend(latest_library_records_by(
        store,
        "placement_targets",
        "placement_id",
        |v| {
            v.get("placement_id")
                .and_then(|i| i.as_str())
                .is_some_and(|i| inst_ids.contains(i))
        },
    ));
    let targets = latest_library_records(store, "work_target", |v| {
        let owner = v.get("owner");
        let project_owned = owner
            .and_then(|owner| owner.get("kind"))
            .and_then(|kind| kind.as_str())
            == Some("project")
            && owner
                .and_then(|owner| owner.get("project_id"))
                .and_then(|id| id.as_str())
                == Some(project);
        let referenced_archetype = owner
            .and_then(|owner| owner.get("kind"))
            .and_then(|kind| kind.as_str())
            == Some("archetype")
            && owner
                .and_then(|owner| owner.get("archetype_id"))
                .and_then(|id| id.as_str())
                .is_some_and(|id| agent_ids.contains(id) && !protected_agent_ids.contains(id));
        project_owned || referenced_archetype
    });
    out.extend(targets);
    let chats = latest_library_records(store, "chat", |v| {
        v.get("instance_id")
            .and_then(|i| i.as_str())
            .is_some_and(|i| inst_ids.contains(i))
    });
    let chat_ids: std::collections::BTreeSet<String> = chats
        .iter()
        .filter_map(|record| serde_json::from_str::<serde_json::Value>(&record.payload).ok())
        .filter_map(|value| {
            value
                .get("id")
                .and_then(|id| id.as_str())
                .map(str::to_owned)
        })
        .collect();
    out.extend(chats);
    out.extend(latest_library_records_by(
        store,
        "chat_target",
        "chat_id",
        |v| {
            v.get("chat_id")
                .and_then(|id| id.as_str())
                .is_some_and(|id| chat_ids.contains(id))
        },
    ));
    let workstreams = latest_library_records(store, "workstream", |v| {
        v.get("instance_id")
            .and_then(|id| id.as_str())
            .is_some_and(|id| inst_ids.contains(id))
    });
    let workstream_ids: std::collections::BTreeSet<String> = workstreams
        .iter()
        .filter_map(|record| serde_json::from_str::<serde_json::Value>(&record.payload).ok())
        .filter_map(|value| {
            value
                .get("id")
                .and_then(|id| id.as_str())
                .map(str::to_owned)
        })
        .collect();
    out.extend(workstreams);
    // A workstream's library record names and roots the line, but its active
    // membership is authoritative in the reducer log under the workstream id
    // itself. Carry those related scopes as part of the project subtree;
    // otherwise relocation renders the line with zero members and the new Home
    // refuses a production co-drive run aimed at the relocated chat.
    for workstream_id in &workstream_ids {
        for (_position, kind, payload) in store.events(workstream_id).unwrap_or_default() {
            out.push(HandoffLogRecord {
                scope: workstream_id.clone(),
                kind,
                payload,
            });
        }
    }
    out.extend(latest_library_records_by(
        store,
        "workstream_root",
        "workstream_id",
        |v| {
            v.get("workstream_id")
                .and_then(|id| id.as_str())
                .is_some_and(|id| workstream_ids.contains(id))
        },
    ));
    out.extend(agents);
    out.extend(
        crate::protected_profiles::distribution_records_for_placements(store, &inst_ids)
            .into_iter()
            .map(|payload| HandoffLogRecord {
                scope: LIBRARY_SCOPE.to_owned(),
                kind: "placement_distribution".to_owned(),
                payload,
            }),
    );
    out
}

/// The origin's snapshot of a project's content: one tagged, erasure-respecting
/// workspace export per managed target. This is the bytes behind every relocated handle; the target
/// re-materializes each before its home commits (`STATE_BEFORE_HOME`, FED-6). An
/// instance whose repo cannot be bundled is skipped (logged), not silently dropped.
fn collect_project_content(wb: &Workbench, project: &str) -> Vec<HandoffContentBundle> {
    wb.project_relocation_content_bundles(project)
        .into_iter()
        .map(|(target_id, format, bundle)| HandoffContentBundle {
            target_id,
            format,
            bundle,
        })
        .collect()
}

/// Send one signed handoff message to `peer` over the cert-pinned TLS leg; returns
/// the peer's JSON verdict (`committed` / `pending` flags for an `Offer`).
#[allow(clippy::too_many_arguments)]
async fn send_handoff(
    broker: &str,
    me: &AuthorityId,
    source_home: &HomeId,
    subkey: &SigningKey,
    delegation: &DeviceDelegation,
    peer: &AuthorityId,
    pins: Arc<PinnedTlsClientConfig>,
    kind: HandoffMsgKind,
    project: &str,
    log: Vec<HandoffLogRecord>,
    content: Vec<HandoffContentBundle>,
    credential_key: Option<SealedKey>,
    shared_route: Option<crate::home::OpaqueHomeRoute>,
) -> std::io::Result<serde_json::Value> {
    let signed_bytes = handoff_bytes(project, source_home);
    let wire = HandoffWire {
        kind,
        project: project.to_string(),
        source: me.as_str().to_string(),
        target: peer.as_str().to_string(),
        source_home: source_home.clone(),
        log,
        content,
        credential_key,
        shared_route,
        signature: subkey.sign(&signed_bytes),
        source_pubkey: subkey.public_key().as_str().to_string(),
        signed_bytes,
        delegation: Some(delegation.clone()),
    };
    let token = handoff_inbox_token(me.as_str(), peer.as_str());
    let tcp = join_relay(broker, &token).await?;
    let mut tls = tls_connect(tcp, peer, pins).await?;
    let bytes = serde_json::to_vec(&wire)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_frame(&mut tls, &bytes).await?;
    let vbytes = read_frame(&mut tls).await?;
    let _ = tls.shutdown().await;
    serde_json::from_slice(&vbytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// --- Target-side consent + standing pre-authorization (FED-6 FO-2/FO-3) ----------

/// Pending incoming handoffs awaiting the target's consent, and the per-peer standing
/// pre-authorizations that auto-accept, both live in this authority's store.
const HANDOFF_INCOMING_SCOPE: &str = "handoff::incoming";
const HANDOFF_PREAUTH_SCOPE: &str = "handoff::preauth";
const HANDOFF_OUTGOING_SCOPE: &str = "handoff::outgoing";

fn record_outgoing_handoff(
    store: &mut Store,
    op: &str,
    project: &str,
    peer: &str,
) -> Result<(), &'static str> {
    store
        .append_record(
            HANDOFF_OUTGOING_SCOPE,
            "event",
            &serde_json::json!({ "op": op, "project": project, "peer": peer }).to_string(),
        )
        .map(|_| ())
        .map_err(|_| "handoff: outgoing state append failed")
}

fn pending_outgoing_peer(store: &Store, project: &str) -> Option<String> {
    let mut peer = None;
    for payload in store
        .records(HANDOFF_OUTGOING_SCOPE, "event")
        .unwrap_or_default()
    {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&payload) else {
            continue;
        };
        if value.get("project").and_then(|v| v.as_str()) != Some(project) {
            continue;
        }
        match value.get("op").and_then(|v| v.as_str()) {
            Some("offer") => {
                peer = value
                    .get("peer")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
            }
            Some("resolved") => peer = None,
            _ => {}
        }
    }
    peer
}

/// Peers this authority will **auto-accept** handoffs from (standing pre-auth). Folded
/// latest-wins per peer: an `allow` record grants, a `revoke` record withdraws.
fn handoff_preauthorized(store: &Store, peer: &str) -> bool {
    let mut allowed = false;
    for payload in store
        .records(HANDOFF_PREAUTH_SCOPE, "peer")
        .unwrap_or_default()
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            if v.get("peer").and_then(|p| p.as_str()) == Some(peer) {
                allowed = v.get("allow").and_then(|a| a.as_bool()).unwrap_or(false);
            }
        }
    }
    allowed
}

/// One-shot, offer-scoped pre-authorizations (ADR 0047): recorded when a target accepts
/// a combined engagement invite. Each is keyed `(source, project, invite_id)`, single-use,
/// and expires with the invite — strictly narrower than the standing per-peer pre-auth.
/// Modeled in [`consent-guard.qnt`](../../../specs/models/consent-guard.qnt).
const HANDOFF_ONESHOT_SCOPE: &str = "handoff::preauth-oneshot";

/// Arm a one-shot pre-authorization for `(source, project, invite_id)`, valid until
/// `expiry` — the target's `INV-13` admission of that one relocation, front-loaded into
/// its invite Accept.
fn handoff_oneshot_arm(
    store: &mut Store,
    source: &str,
    project: &str,
    invite_id: &str,
    expiry: u64,
) {
    let rec = serde_json::json!({
        "op": "arm", "source": source, "project": project, "invite_id": invite_id, "expiry": expiry,
    });
    let _ = store.append_record(HANDOFF_ONESHOT_SCOPE, "event", &rec.to_string());
}

/// Take (consume) a valid one-shot for `(source, project)` if one exists — armed,
/// unexpired, not already consumed. Returns `true` and appends a `consume` record so it
/// can never admit a second relocation (`SINGLE_USE` of the consent guard). Returns
/// `false` (fail-closed) otherwise.
fn handoff_oneshot_take(store: &mut Store, source: &str, project: &str) -> bool {
    let mut armed: BTreeMap<String, u64> = BTreeMap::new(); // invite_id -> expiry
    let mut consumed: BTreeSet<String> = BTreeSet::new();
    for payload in store
        .records(HANDOFF_ONESHOT_SCOPE, "event")
        .unwrap_or_default()
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            let iid = v
                .get("invite_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            match v.get("op").and_then(|o| o.as_str()) {
                Some("arm")
                    if v.get("source").and_then(|s| s.as_str()) == Some(source)
                        && v.get("project").and_then(|p| p.as_str()) == Some(project) =>
                {
                    armed.insert(iid, v.get("expiry").and_then(|e| e.as_u64()).unwrap_or(0));
                }
                Some("consume") => {
                    consumed.insert(iid);
                }
                _ => {}
            }
        }
    }
    let now = now_secs();
    if let Some((iid, _)) = armed
        .into_iter()
        .find(|(iid, exp)| !consumed.contains(iid) && *exp >= now)
    {
        let rec = serde_json::json!({ "op": "consume", "invite_id": iid });
        let _ = store.append_record(HANDOFF_ONESHOT_SCOPE, "event", &rec.to_string());
        return true;
    }
    false
}

/// The pending incoming handoffs (offers recorded but not yet accepted/declined),
/// folded latest-wins per project: an `offer` record opens it, a `resolved` closes it.
fn pending_incoming(store: &Store) -> Vec<serde_json::Value> {
    let mut by_project: BTreeMap<String, Option<serde_json::Value>> = BTreeMap::new();
    for payload in store
        .records(HANDOFF_INCOMING_SCOPE, "event")
        .unwrap_or_default()
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            let project = v
                .get("project")
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            match v.get("op").and_then(|o| o.as_str()) {
                Some("offer") => {
                    by_project.insert(project, Some(v));
                }
                Some("resolved") => {
                    by_project.insert(project, None);
                }
                _ => {}
            }
        }
    }
    by_project.into_values().flatten().collect()
}

/// The per-peer **handoff receiver loop**: park on the broker for offers `peer → me`,
/// complete the cert-pinned TLS handshake as the server, and commit each verified
/// relocation. Spawned when a pair is accepted.
pub async fn run_handoff_receiver(wb: SharedWorkbench, peer: AuthorityId) {
    loop {
        let (broker, identity, me, still_paired) = {
            let guard = wb.lock_unpoisoned();
            match guard.federation_ref() {
                Some(fed) => (
                    fed.broker_addr.clone(),
                    fed.identity.clone(),
                    fed.authority.clone(),
                    fed.grant_for(peer.as_str()).is_some(),
                ),
                None => return,
            }
        };
        if !still_paired {
            return;
        }
        let token = handoff_inbox_token(peer.as_str(), me.as_str());
        if let Err(e) = handoff_receive_once(&wb, &broker, &identity, &token).await {
            tracing::debug!("handoff receiver {peer}→{me}: {e}; retrying");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

async fn handoff_receive_once(
    wb: &SharedWorkbench,
    broker: &str,
    identity: &TlsIdentity,
    token: &str,
) -> std::io::Result<()> {
    let tcp = park_relay(broker, token).await?;
    let mut tls = tls_accept(tcp, identity).await?;
    let bytes = read_frame(&mut tls).await?;
    let wire: HandoffWire = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let verdict = admit_handoff(wb, &wire);
    write_frame(&mut tls, verdict.to_string().as_bytes()).await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// Import the relocated log **and** materialize the content bytes, then drive the
/// target's handoff reducer to Committed so the target becomes home (`STATE_BEFORE_HOME`,
/// `INV-13`). The bytes land **before** `SyncLog`/`CommitHandoff`, so the home never
/// commits over absent content; any failure (a bad log record or an un-materializable
/// bundle) is fail-closed — no commit, and the origin stays home (`ABORT_KEEPS_ORIGIN_HOME`).
fn commit_incoming_handoff(
    guard: &mut Workbench,
    project: &str,
    log: &[HandoffLogRecord],
    content: &[HandoffContentBundle],
    credential_key: Option<&SealedKey>,
) -> bool {
    let carries_project_credentials = log
        .iter()
        .any(|record| record.scope == format!("project::{project}") && record.kind == "credential");
    let project_credential_key = match credential_key {
        Some(sealed) => {
            let target_key = federation_root_signing_key(guard);
            let Some(bytes) = open_sealed(&target_key, sealed) else {
                tracing::warn!("handoff commit: project credential key did not open for target");
                return false;
            };
            let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                tracing::warn!("handoff commit: project credential key has invalid length");
                return false;
            };
            Some(key)
        }
        None if carries_project_credentials => {
            tracing::warn!(
                "handoff commit: project carries credentials without a target-sealed key"
            );
            return false;
        }
        None => None,
    };
    // 1. Import the relocated log (the authority — INV-5), and open the handoff.
    {
        let store = guard.store_mut();
        for rec in log {
            if store
                .append_record(&rec.scope, &rec.kind, &rec.payload)
                .is_err()
            {
                return false;
            }
        }
    }
    if let Err(e) = apply_handoff(guard.store_mut(), project, HandoffCommand::OfferHandoff) {
        // Fail-closed, but say why: a silent `false` here is exactly what makes a
        // handoff failure read as a generic "something went wrong" with no trail.
        tracing::warn!("handoff commit: OfferHandoff failed for {project}: {e:?}");
        return false;
    }
    // 2. Materialize the content bytes behind the project's handles BEFORE the home can
    //    commit (STATE_BEFORE_HOME). A bundle that will not lay down blocks the commit.
    for b in content {
        if let Err(e) = guard.materialize_target(&b.target_id, &b.format, &b.bundle) {
            tracing::warn!(
                "handoff commit: materialize instance {} failed: {e:?}",
                b.target_id
            );
            return false;
        }
    }
    if let Some(key) = project_credential_key {
        if guard.install_project_credential_key(project, key).is_none() {
            tracing::warn!("handoff commit: target could not persist project credential key");
            return false;
        }
    }
    // 3. Full state present (log + content): sync, then flip home to the target.
    if let Err(e) = apply_handoff(guard.store_mut(), project, HandoffCommand::SyncLog) {
        tracing::warn!("handoff commit: SyncLog failed for {project}: {e:?}");
        return false;
    }
    let home = guard.home_id().clone();
    guard.rebuild_library();
    if let Err(e) = commit_handoff_and_rebind(guard, project, home) {
        tracing::warn!("handoff commit: atomic Home flip failed for {project}: {e:?}");
        return false;
    }
    true
}

/// A wire verdict **refusing** the request: the peer deciding no, not the peer
/// breaking.
///
/// A caller cannot see the reasoning behind an admission function — the only
/// thing that crosses the relay leg is this JSON — so, exactly as a refused turn
/// is classified inside `gaugedesk-whip-runtime` while `HostRuntimeError` is
/// still in hand, the classification is minted here, where the decision is
/// actually taken. `refused` is the carrier that survives the wire seam, the
/// moral equivalent of the `io::ErrorKind` that carries a refused turn out of
/// the runtime, and [`verdict_refusal_reason`] reads it back at the route.
///
/// The flag is explicit rather than inferred from `ok: false` because the two
/// answers that share that shape are opposites: a peer that *decided* not to
/// admit will decide identically on every retry, while a peer that accepted the
/// request and then broke part-way through may well succeed on the next one.
/// Only a decision is stamped.
fn refused_verdict(reason: &str) -> serde_json::Value {
    serde_json::json!({ "ok": false, "refused": true, "reason": reason })
}

/// Read back the [`refused_verdict`] stamp: `Some(reason)` when the peer says it
/// *decided* against the request, `None` for everything else.
///
/// Reading the stamp rather than sniffing the reason text is the point — a
/// string match would hold only until someone rewords the message. An unstamped
/// verdict is never read as a refusal, so a peer built before the flag existed
/// behaves exactly as it does today and only an explicit decision is ever moved
/// out of the 5xx range.
fn verdict_refusal_reason(verdict: &serde_json::Value) -> Option<&str> {
    verdict
        .get("refused")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        .then(|| verdict.get("reason").and_then(|value| value.as_str()))
        .map(|reason| reason.unwrap_or_default())
}

/// The status for a peer verdict that declined: `403` when the peer *decided*,
/// `502` when it broke. The plain form of the split [`relocation_verdict`] makes,
/// for the routes that pass the peer's verdict through unchanged.
fn refusal_status(verdict: &serde_json::Value) -> StatusCode {
    match verdict_refusal_reason(verdict) {
        Some(_) => StatusCode::FORBIDDEN,
        None => StatusCode::BAD_GATEWAY,
    }
}

/// Handle a received handoff message after authenticating it against the source's
/// pinned grant (C-1 / INV-21 — the effective source key, an unexpired/unrevoked
/// subkey or the pinned root, must verify the project-bound bytes). Returns the JSON
/// verdict written back to the sender. Fail-closed on any check.
///
/// Every fail-closed check here is a *refusal* and says so on the wire via
/// [`refused_verdict`]; a commit that starts and then fails is not.
///
/// - `Offer` (origin→target): auto-accept if the target pre-authorized the source
///   (import + commit), else record a **pending** offer for explicit consent
///   (`INV-13`); never auto-commits an un-pre-authorized relocation.
/// - `Committed` (target→origin): the target consented and is now home; commit our
///   side (become operator).
/// - `Declined` (target→origin): roll our side back (stay home).
fn admit_handoff(wb: &SharedWorkbench, wire: &HandoffWire) -> serde_json::Value {
    let mut guard = wb.lock_unpoisoned();
    let Some(grant) = guard
        .federation_ref()
        .and_then(|f| f.grant_for(&wire.source))
    else {
        return refused_verdict("unpaired source");
    };
    let claimed = PublicKey::new(wire.source_pubkey.clone());
    let Some(verify_key) = guard
        .federation_ref()
        .and_then(|f| effective_source_key(f, &wire.source, &grant, &claimed, &wire.delegation))
    else {
        return refused_verdict("bad source key");
    };
    if !grant.is_valid(now_secs())
        || wire.signed_bytes != handoff_bytes(&wire.project, &wire.source_home)
        || verify_signature(&wire.signed_bytes, &wire.signature, &verify_key) != Ok(true)
    {
        return refused_verdict("verification failed");
    }
    if wire.kind != HandoffMsgKind::Route && wire.shared_route.is_some() {
        return refused_verdict("unexpected shared route");
    }
    if wire.kind == HandoffMsgKind::Offer {
        // DEPLOY-4 / ITGOV-3: every offer crosses the placement floor before
        // *any* admission branch. Standing preauthorization and a combined
        // invite's one-shot consent reduce human friction; neither is a policy
        // bypass. No quote travels on this leg, so attested declarations fail
        // closed until a measurement-bearing transport exists.
        let placement_policy = crate::org::Org::rebuild(guard.store_ref())
            .map(|org| org.effective_placement_policy())
            .unwrap_or_else(|_| gaugedesk_core::boundary_lifecycle::PlacementPolicy::open());
        if !handoff_placement_admitted(&placement_policy, &wire.log, &wire.project) {
            return refused_verdict(
                "the incoming project's deployment mode is not admitted by this org's placement policy",
            );
        }
    }
    // `registered` = the target imported a relocated project (its library changed).
    let (verdict, registered) = match wire.kind {
        HandoffMsgKind::Offer => {
            // Three admission paths (INV-13), all the target's: a standing per-peer
            // pre-auth, or a one-shot from an accepted invite (consumed here, ADR 0047),
            // else the offer lands pending an explicit accept. `||` short-circuits so a
            // standing pre-auth never burns a one-shot.
            let preauth = handoff_preauthorized(guard.store_ref(), &wire.source);
            let oneshot =
                !preauth && handoff_oneshot_take(guard.store_mut(), &wire.source, &wire.project);
            if preauth || oneshot {
                let committed = commit_incoming_handoff(
                    &mut guard,
                    &wire.project,
                    &wire.log,
                    &wire.content,
                    wire.credential_key.as_ref(),
                );
                if committed {
                    // host = this authority (the target), operator = the origin.
                    record_participants(
                        guard.store_mut(),
                        &wire.project,
                        &wire.target,
                        &wire.source,
                    );
                }
                (
                    serde_json::json!({
                        "ok": committed,
                        "committed": committed,
                        "pending": false,
                        "home": committed.then(|| guard.federation_home_id()),
                    }),
                    committed,
                )
            } else {
                // Fail-closed: record a pending offer (log + content) for explicit
                // consent (INV-13); the bytes wait with the offer until the host accepts.
                let rec = serde_json::json!({
                    "op": "offer",
                    "project": wire.project,
                    "source": wire.source,
                    "log": wire.log,
                    "content": wire.content,
                    "credential_key": wire.credential_key,
                });
                let _ = guard.store_mut().append_record(
                    HANDOFF_INCOMING_SCOPE,
                    "event",
                    &rec.to_string(),
                );
                (
                    serde_json::json!({ "ok": true, "committed": false, "pending": true }),
                    false,
                )
            }
        }
        HandoffMsgKind::Committed => {
            let _ = apply_handoff(guard.store_mut(), &wire.project, HandoffCommand::SyncLog);
            let ok = commit_handoff_and_rebind(&mut guard, &wire.project, wire.source_home.clone())
                .is_ok();
            if ok {
                let _ = record_outgoing_handoff(
                    guard.store_mut(),
                    "resolved",
                    &wire.project,
                    &wire.source,
                );
                if let Err(error) = guard.remove_project_credential_key(&wire.project) {
                    tracing::error!(
                        project = %wire.project,
                        error = %error,
                        "handoff committed but former Home could not remove its project credential key"
                    );
                }
                // origin side: host = the target who notified us, operator = self.
                record_participants(guard.store_mut(), &wire.project, &wire.source, &wire.target);
            }
            (serde_json::json!({ "ok": ok }), false)
        }
        HandoffMsgKind::Declined => {
            let ok = apply_handoff(
                guard.store_mut(),
                &wire.project,
                HandoffCommand::AbortHandoff,
            )
            .is_ok();
            if ok {
                let _ = record_outgoing_handoff(
                    guard.store_mut(),
                    "resolved",
                    &wire.project,
                    &wire.source,
                );
            }
            (serde_json::json!({ "ok": ok }), false)
        }
        HandoffMsgKind::Cancelled => {
            let pending = pending_incoming(guard.store_ref())
                .into_iter()
                .any(|offer| {
                    offer["project"].as_str() == Some(wire.project.as_str())
                        && offer["source"].as_str() == Some(wire.source.as_str())
                });
            if pending {
                let _ = guard.store_mut().append_record(
                    HANDOFF_INCOMING_SCOPE,
                    "event",
                    &serde_json::json!({
                        "op": "resolved",
                        "project": wire.project,
                    })
                    .to_string(),
                );
            }
            (
                serde_json::json!({ "ok": pending, "cancelled": pending }),
                false,
            )
        }
        HandoffMsgKind::Route => {
            let Some(route) = wire.shared_route.as_ref() else {
                return refused_verdict("shared route missing");
            };
            if route.project != wire.project
                || route.home_id != wire.source_home
                || route.author_authority != wire.source
                || route.author_root_pubkey != grant.source_authority_root_pubkey.as_str()
                || !crate::home::shared_home_route_verifies(route)
            {
                return refused_verdict("shared route verification failed");
            }
            let record = crate::account::HomeRouteRecord {
                id: route.project.clone(),
                op: if route.endpoint.is_empty() && route.relay.is_none() {
                    crate::account::RecordOp::Tombstone
                } else {
                    crate::account::RecordOp::Upsert
                },
                home_id: route.home_id.clone(),
                endpoint: route.endpoint.clone(),
                relay: route.relay.clone(),
                author_authority: route.author_authority.clone(),
                author_root_pubkey: route.author_root_pubkey.clone(),
                author_signature: route.author_signature.clone(),
            };
            let ok = guard
                .write_account_record_in(
                    crate::account::ACCOUNT_SCOPE,
                    "home_route",
                    &record.id,
                    &record,
                )
                .is_ok();
            (serde_json::json!({ "ok": ok }), false)
        }
    };
    if registered {
        guard.rebuild_library();
    }
    verdict
}

#[derive(Deserialize)]
pub struct HandoffRelocateRequest {
    pub project: String,
    pub peer: String,
}

/// The status + body for a peer that answered the offer without taking it.
///
/// Two very different things arrive in the same shape — `committed: false,
/// pending: false` — and the origin cannot tell them apart unaided:
///
/// - The peer **refused**: its placement policy declined the project's
///   deployment mode, or an identity check failed closed. That is a decision,
///   it answers `403`, and it carries the peer's own sentence.
/// - The peer **broke**: it admitted the offer and then failed part-way through
///   importing or committing it. That keeps `502`, and it is the only one of the
///   two worth retrying.
///
/// Reporting the first as the second is expensive twice over — the same two
/// costs that made a refused turn unreadable in `post_task`. A 5xx invites a
/// retry of something that will be refused identically every time; and
/// Cloudflare substitutes its own body for an origin 5xx, so the peer's
/// explanation of *which* policy declined *which* project is replaced by "the
/// origin is overloaded or misconfigured" before the caller ever sees it.
///
/// [`admit_handoff`] stamps `refused` on its decisions and [`verdict_refusal_reason`]
/// reads it back; an unstamped verdict keeps `502`.
fn relocation_verdict(verdict: &serde_json::Value) -> (StatusCode, serde_json::Value) {
    let Some(reason) = verdict_refusal_reason(verdict) else {
        return (
            StatusCode::BAD_GATEWAY,
            serde_json::json!({ "error": "peer did not admit the handoff" }),
        );
    };
    let error = match reason {
        "" => "peer refused the handoff".to_string(),
        reason => format!("peer refused the handoff: {reason}"),
    };
    (StatusCode::FORBIDDEN, serde_json::json!({ "error": error }))
}

/// Drive a project's relocation to a paired peer over the wire — the cross-machine
/// carriage shared by `POST …/relocate` and the combined-invite receiver
/// ([ADR 0047](../../../specs/decisions/0047-combined-pairing-and-handoff-invite.md)).
/// Offer (origin stays home) → ship log + content + signed offer → peer admits (explicit,
/// standing pre-auth, or a one-shot from an accepted invite) and commits → origin commits
/// its side (becomes operator). A decline/failure rolls the origin back. Returns an HTTP
/// status + the origin's resulting handoff state (or `{error}`).
///
/// A peer that did not admit is answered by [`relocation_verdict`], which keeps a
/// refusal out of the 5xx range.
async fn drive_relocate(
    wb: &SharedWorkbench,
    project: &str,
    peer: &AuthorityId,
) -> (StatusCode, serde_json::Value) {
    let (broker, me, source_home, subkey, delegation, pins, peer_key, project_credential_key) = {
        let guard = wb.lock_unpoisoned();
        let me = guard.federation_authority().clone();
        let root = federation_root_signing_key(&guard);
        let (subkey, delegation) = device_identity(&guard_root(&guard), &me, &root);
        match guard.federation_ref() {
            Some(fed) => {
                let peer_key = fed
                    .grant_for(peer.as_str())
                    .map(|grant| grant.source_authority_root_pubkey);
                (
                    fed.broker_addr.clone(),
                    me,
                    guard.federation_home_id(),
                    subkey,
                    delegation,
                    fed.pins_arc(),
                    peer_key,
                    guard.project_credential_key_for_handoff(project),
                )
            }
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({ "error": "federation not configured" }),
                )
            }
        }
    };
    let Some(peer_key) = peer_key else {
        return (
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": format!("not paired with {}", peer.as_str()) }),
        );
    };
    {
        let mut guard = wb.lock_unpoisoned();
        if let Err(error) = crate::protected_profiles::prepare_project_relocation(
            &mut guard,
            project,
            peer_key.as_str(),
        ) {
            return (
                StatusCode::FORBIDDEN,
                serde_json::json!({ "error": format!("protected placement issuance failed: {error}") }),
            );
        }
    }
    let (log, content) = {
        let guard = wb.lock_unpoisoned();
        (
            collect_project_log(guard.store_ref(), project),
            collect_project_content(&guard, project),
        )
    };
    let credential_key = match project_credential_key {
        Some(key) => match seal_to_subkey(&peer_key, &key) {
            Some(sealed) => Some(sealed),
            None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({ "error": "could not seal project credential key to target" }),
                )
            }
        },
        None => None,
    };
    // Origin offers — it stays home until the peer commits (INV-13).
    {
        let mut guard = wb.lock_unpoisoned();
        if let Err(e) = apply_handoff(guard.store_mut(), project, HandoffCommand::OfferHandoff) {
            return (
                StatusCode::CONFLICT,
                serde_json::json!({ "error": format!("handoff offer: {e}") }),
            );
        }
        if let Err(error) =
            record_outgoing_handoff(guard.store_mut(), "offer", project, peer.as_str())
        {
            let _ = apply_handoff(guard.store_mut(), project, HandoffCommand::AbortHandoff);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": error }),
            );
        }
    }
    match send_handoff(
        &broker,
        &me,
        &source_home,
        &subkey,
        &delegation,
        peer,
        pins,
        HandoffMsgKind::Offer,
        project,
        log,
        content,
        credential_key,
        None,
    )
    .await
    {
        Ok(verdict) => {
            let committed = verdict
                .get("committed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let pending = verdict
                .get("pending")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mut guard = wb.lock_unpoisoned();
            if committed {
                let _ =
                    record_outgoing_handoff(guard.store_mut(), "resolved", project, peer.as_str());
                // Peer committed immediately (pre-auth / one-shot); origin commits its side.
                let _ = apply_handoff(guard.store_mut(), project, HandoffCommand::SyncLog);
                let target_home = verdict
                    .get("home")
                    .and_then(|value| value.as_str())
                    .and_then(|value| HomeId::parse(value).ok());
                match target_home
                    .ok_or("target omitted its Home binding")
                    .and_then(|home| commit_handoff_and_rebind(&mut guard, project, home))
                {
                    Ok(s) => {
                        if let Err(error) = guard.remove_project_credential_key(project) {
                            tracing::error!(
                                project,
                                error = %error,
                                "handoff committed but former Home could not remove its project credential key"
                            );
                        }
                        record_participants(guard.store_mut(), project, peer.as_str(), me.as_str());
                        (StatusCode::OK, handoff_state_json(project, &s))
                    }
                    Err(e) => (
                        StatusCode::BAD_GATEWAY,
                        serde_json::json!({ "error": format!("origin commit: {e}") }),
                    ),
                }
            } else if pending {
                // The peer must consent; the origin stays home (offered) until it does.
                let s = load_handoff(guard.store_ref(), project);
                (StatusCode::ACCEPTED, handoff_state_json(project, &s))
            } else {
                let _ =
                    record_outgoing_handoff(guard.store_mut(), "resolved", project, peer.as_str());
                let _ = apply_handoff(guard.store_mut(), project, HandoffCommand::AbortHandoff);
                relocation_verdict(&verdict)
            }
        }
        Err(e) => {
            let mut guard = wb.lock_unpoisoned();
            let _ = record_outgoing_handoff(guard.store_mut(), "resolved", project, peer.as_str());
            let _ = apply_handoff(guard.store_mut(), project, HandoffCommand::AbortHandoff);
            (
                StatusCode::BAD_GATEWAY,
                serde_json::json!({ "error": format!("handoff transport failed: {e}") }),
            )
        }
    }
}

/// `POST /federation/handoff/relocate` — relocate a project's home to a paired peer.
/// Thin wrapper over [`drive_relocate`].
pub async fn post_handoff_relocate(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<HandoffRelocateRequest>,
) -> impl IntoResponse {
    let peer = AuthorityId::new(&req.peer);
    let (status, body) = drive_relocate(&wb, &req.project, &peer).await;
    (status, Json(body)).into_response()
}

// --- Combined engagement invite (FED-7 Slice 2, ADR 0047) -------------------------
//
// One invite folds pairing + a project disposition into a single Accept: the origin mints an
// `gaugewright://invite?d=…` (its pairing ticket + the offer — no log/content); the target's
// Accept pins the origin, arms a one-shot pre-auth, and sends an `InviteAccept` back; the
// origin pins the target (mutual pairing, `INV-21`) and either drives the initial relocate or
// adds the target to the already-hosted project without moving its Home. Consent is
// front-loaded into the Accept (`INV-13`), never bypassed.

/// Pending outgoing invites this authority has minted, keyed by `invite_id`, so its
/// invite-response receiver knows what to expect and the surface can show status.
const INVITE_OUTGOING_SCOPE: &str = "invite::outgoing";
/// An unaccepted invite expires (`INV-23` bounded escape); the one-shot expires with it.
const INVITE_TTL_SECS: u64 = 3600;

/// What accepting an engagement invitation does to the project Home. `Relocate` is the
/// legacy/default first-contact journey; `Join` is the N-party journey and never moves or
/// copies the Home.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteDisposition {
    #[default]
    Relocate,
    Join,
}

/// The engagement invite payload — the origin's pairing ticket (pin + reach-back) + the
/// project offer (name + archetype manifest, never bodies, `INV-10`) + the rendezvous
/// `invite_id` and read-aloud confirm code. Carries **no** log/content; those ship later,
/// over the cert-pinned leg, only once the target is pinned.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EngagementInvite {
    invite_id: String,
    ticket: PairingTicket,
    project: String,
    project_name: String,
    #[serde(default)]
    disposition: InviteDisposition,
    #[serde(default = "gaugedesk_core::boundary_lifecycle::Placement::local")]
    deployment_mode: gaugedesk_core::boundary_lifecycle::Placement,
    #[serde(default)]
    manifest: Vec<String>,
    #[serde(default)]
    agent_distributions: Vec<crate::protected_profiles::DistributionOfferSummary>,
    confirm_code: String,
}

impl EngagementInvite {
    /// Encode as the deep link the target opens / a QR renders: `gaugewright://invite?d=<hex>`.
    fn to_url(&self) -> String {
        format!(
            "gaugewright://invite?d={}",
            hex::encode(serde_json::to_vec(self).unwrap_or_default())
        )
    }
    /// Decode a deep link (or the bare hex blob) back to an invite.
    fn from_url(raw: &str) -> Option<Self> {
        let hexpart = raw.trim().rsplit("d=").next().unwrap_or(raw).trim();
        serde_json::from_slice(&hex::decode(hexpart).ok()?).ok()
    }
}

/// A short read-aloud confirm code derived from the invite id — the out-of-band integrity
/// check (anti-MITM). Deterministic, so origin and target show the same code without a
/// round trip; the consultant verifies the client reads it back.
fn invite_confirm_code(invite_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(invite_id.as_bytes());
    format!("{}-{}-{}", d[0] % 10, d[1] % 10, d[2] % 10)
}

/// The rendezvous token the invite-response leg uses (origin parks; target sends),
/// namespaced by `invite_id` since the origin does not yet know the target's authority.
fn invite_inbox_token(invite_id: &str) -> String {
    format!("gaugewright-invite::{invite_id}")
}

/// The bytes the target signs to prove it holds the key in its returned ticket (`INV-21`).
fn invite_accept_bytes(invite_id: &str) -> Vec<u8> {
    format!("gaugewright-invite-accept::{invite_id}").into_bytes()
}

/// The acceptance the target sends back (target → origin): its own pairing ticket (so the
/// origin pins it, completing the mutual pairing) + a signature over the invite id.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct InviteAcceptWire {
    invite_id: String,
    ticket: PairingTicket,
    signed_bytes: Vec<u8>,
    signature: gaugedesk_core::signature::Signature,
}

/// Record / look up a pending outgoing invite (origin side), folded latest-wins per
/// `invite_id`: `mint` opens it, `accepted`/`expired` closes it.
fn record_pending_invite(
    store: &mut Store,
    invite_id: &str,
    project: &str,
    disposition: InviteDisposition,
    confirm: &str,
    expiry: u64,
) {
    let rec = serde_json::json!({
        "op": "mint", "invite_id": invite_id, "project": project, "disposition": disposition,
        "confirm_code": confirm, "expiry": expiry,
    });
    let _ = store.append_record(INVITE_OUTGOING_SCOPE, "event", &rec.to_string());
}

/// The pending (minted, unresolved, unexpired) outgoing invite for `invite_id`, as
/// `(project, expiry)`, or `None` if it was never minted / already accepted / expired.
fn pending_invite(store: &Store, invite_id: &str) -> Option<(String, InviteDisposition, u64)> {
    let mut open: Option<(String, InviteDisposition, u64)> = None;
    for payload in store
        .records(INVITE_OUTGOING_SCOPE, "event")
        .unwrap_or_default()
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            if v.get("invite_id").and_then(|x| x.as_str()) != Some(invite_id) {
                continue;
            }
            match v.get("op").and_then(|o| o.as_str()) {
                Some("mint") => {
                    open = Some((
                        v.get("project")
                            .and_then(|p| p.as_str())
                            .unwrap_or("")
                            .to_string(),
                        v.get("disposition")
                            .cloned()
                            .and_then(|value| serde_json::from_value(value).ok())
                            .unwrap_or_default(),
                        v.get("expiry").and_then(|e| e.as_u64()).unwrap_or(0),
                    ));
                }
                Some("accepted") | Some("expired") => open = None,
                _ => {}
            }
        }
    }
    open.filter(|(_, _, exp)| *exp >= now_secs())
}

/// Mark a pending invite resolved (accepted), recording which device accepted (so the
/// origin can confirm the read-aloud code against the human).
fn resolve_invite(store: &mut Store, invite_id: &str, accepted_by: &str) {
    let rec = serde_json::json!({
        "op": "accepted", "invite_id": invite_id, "accepted_by": accepted_by,
    });
    let _ = store.append_record(INVITE_OUTGOING_SCOPE, "event", &rec.to_string());
}

#[derive(Deserialize)]
pub struct InviteRequest {
    pub project: String,
    #[serde(default)]
    pub disposition: InviteDisposition,
}

/// `POST /federation/invite` — mint a combined engagement invite for a project and park
/// its invite-response receiver. Returns the deep link + confirm code; the surface shows
/// the QR + code + "waiting for the client to accept". The origin stays home.
pub async fn post_invite(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<InviteRequest>,
) -> impl IntoResponse {
    let invite_id = crate::library::gen_id("invite");
    let confirm = invite_confirm_code(&invite_id);
    let expiry = now_secs() + INVITE_TTL_SECS;
    let invite = {
        let mut guard = wb.lock_unpoisoned();
        let pubkey = guard.governance_public_key();
        let project_name = guard.project_display_name(&req.project);
        let deployment_mode = guard.project_deployment_mode(&req.project);
        if req.disposition == InviteDisposition::Join && !guard.owns_project(&req.project) {
            return (
                StatusCode::CONFLICT,
                "a join invitation must be minted by the project Home",
            )
                .into_response();
        }
        // `mint_ticket` returns an owned ticket, so the `fed` borrow ends here — before
        // `store_mut` below.
        let ticket = match guard.federation_ref() {
            Some(fed) => {
                fed.mint_ticket(pubkey, "bridge:invoke".to_string(), Some(INVITE_TTL_SECS))
            }
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured")
                    .into_response()
            }
        };
        record_pending_invite(
            guard.store_mut(),
            &invite_id,
            &req.project,
            req.disposition,
            &confirm,
            expiry,
        );
        EngagementInvite {
            invite_id: invite_id.clone(),
            ticket,
            project: req.project.clone(),
            project_name,
            disposition: req.disposition,
            deployment_mode,
            manifest: Vec::new(),
            agent_distributions: crate::protected_profiles::project_distribution_offers(
                &guard,
                &req.project,
            ),
            confirm_code: confirm.clone(),
        }
    };
    tokio::spawn(run_invite_receiver(wb.clone(), invite_id.clone()));
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "invite_id": invite_id,
            "invite_url": invite.to_url(),
            "confirm_code": confirm,
            "project": req.project,
            "disposition": invite.disposition,
            "deployment_mode": invite.deployment_mode,
        })),
    )
        .into_response()
}

/// `GET /federation/invite/status?id=<invite_id>` — the origin's pending-invite
/// projection (its confirm code + whether/by-whom accepted + expiry).
pub async fn get_invite_status(
    State(wb): State<SharedWorkbench>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let id = q.get("id").cloned().unwrap_or_default();
    let guard = wb.lock_unpoisoned();
    let pending = pending_invite(guard.store_ref(), &id).is_some();
    // Surface the latest accepted_by, if any.
    let mut accepted_by: Option<String> = None;
    for payload in guard
        .store_ref()
        .records(INVITE_OUTGOING_SCOPE, "event")
        .unwrap_or_default()
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            if v.get("invite_id").and_then(|x| x.as_str()) == Some(id.as_str())
                && v.get("op").and_then(|o| o.as_str()) == Some("accepted")
            {
                accepted_by = v
                    .get("accepted_by")
                    .and_then(|a| a.as_str())
                    .map(str::to_string);
            }
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "invite_id": id,
            "pending": pending,
            "accepted": accepted_by.is_some(),
            "accepted_by": accepted_by,
            "confirm_code": invite_confirm_code(&id),
        })),
    )
        .into_response()
}

/// The origin-side **invite-response receiver**: parked on the broker at the invite's
/// rendezvous token, it accepts the target's `InviteAccept`, pins the target (mutual
/// pairing), and drives the relocate. Loops until the invite is resolved or expires.
pub async fn run_invite_receiver(wb: SharedWorkbench, invite_id: String) {
    let token = invite_inbox_token(&invite_id);
    loop {
        let (broker, identity, still_pending) = {
            let guard = wb.lock_unpoisoned();
            match guard.federation_ref() {
                Some(fed) => (
                    fed.broker_addr.clone(),
                    fed.identity.clone(),
                    pending_invite(guard.store_ref(), &invite_id).is_some(),
                ),
                None => return,
            }
        };
        if !still_pending {
            return;
        }
        if let Err(e) = invite_receive_once(&wb, &broker, &identity, &token).await {
            tracing::debug!("invite receiver {invite_id}: {e}; retrying");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

async fn invite_receive_once(
    wb: &SharedWorkbench,
    broker: &str,
    identity: &TlsIdentity,
    token: &str,
) -> std::io::Result<()> {
    let tcp = park_relay(broker, token).await?;
    let mut tls = tls_accept(tcp, identity).await?;
    let bytes = read_frame(&mut tls).await?;
    let wire: InviteAcceptWire = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let verdict = admit_invite_accept(wb, &wire);
    write_frame(&mut tls, verdict.to_string().as_bytes()).await?;
    let _ = tls.shutdown().await;
    // Apply the disposition *after* responding, now that the target is pinned, if accepted.
    if verdict.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        let peer = AuthorityId::new(wire.ticket.authority.as_str());
        let project = verdict
            .get("project")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        let disposition: InviteDisposition = verdict
            .get("disposition")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default();
        if !project.is_empty() {
            if disposition == InviteDisposition::Relocate {
                let (_status, _body) = drive_relocate(wb, &project, &peer).await;
            } else {
                distribute_authored_home_routes(wb);
            }
        }
    }
    Ok(())
}

/// Verify a target's `InviteAccept` against the pending invite (`INV-21`: the ticket's
/// key signed the invite id), pin the target (mutual pairing), and mark the invite
/// accepted. Returns the verdict (`ok` + the project to relocate). Fail-closed.
///
/// The two fail-closed checks are *decisions* and say so via [`refused_verdict`],
/// so the accepting side can answer `403` rather than reporting a stale invite as
/// a broken origin. An unconfigured federation is the origin being wrong, not the
/// origin deciding, and is left unstamped.
fn admit_invite_accept(wb: &SharedWorkbench, wire: &InviteAcceptWire) -> serde_json::Value {
    let (project, disposition) = {
        let mut guard = wb.lock_unpoisoned();
        let Some((project, disposition, _expiry)) =
            pending_invite(guard.store_ref(), &wire.invite_id)
        else {
            return refused_verdict("no pending invite");
        };
        // INV-21: the key in the returned ticket must have signed the invite id.
        let verify_key = PublicKey::new(wire.ticket.governance_pubkey.clone());
        if wire.signed_bytes != invite_accept_bytes(&wire.invite_id)
            || verify_signature(&wire.signed_bytes, &wire.signature, &verify_key) != Ok(true)
        {
            return refused_verdict("verification failed");
        }
        // Pin the target (TOFU) — mutual pairing complete.
        let grant_id = crate::library::gen_id("grant");
        match guard.federation_mut() {
            Some(fed) => {
                fed.accept_ticket(&wire.ticket, grant_id.clone());
            }
            None => {
                return serde_json::json!({ "ok": false, "reason": "federation not configured" })
            }
        }
        persist_bridge(guard.store_mut(), &wire.ticket, &grant_id, true);
        if disposition == InviteDisposition::Join {
            let host = guard.federation_authority().as_str().to_owned();
            record_operator_participant(guard.store_mut(), &project, &host, &wire.ticket.authority);
        }
        resolve_invite(guard.store_mut(), &wire.invite_id, &wire.ticket.authority);
        (project, disposition)
    };
    spawn_peer_receivers(wb, AuthorityId::new(wire.ticket.authority.as_str()));
    serde_json::json!({ "ok": true, "project": project, "disposition": disposition })
}

#[derive(Deserialize)]
pub struct InviteAcceptRequest {
    /// The invite deep link / blob the consultant sent.
    pub invite: String,
}

/// `POST /federation/invite/accept` — the target's single Accept: pin the origin, arm a
/// one-shot pre-authorization for the offered relocation, and send the acceptance back so
/// the origin pins us and relocates. One action pairs and admits the handoff (ADR 0047).
pub async fn post_invite_accept(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<InviteAcceptRequest>,
) -> impl IntoResponse {
    let Some(invite) = EngagementInvite::from_url(&req.invite) else {
        return (StatusCode::BAD_REQUEST, "malformed invite").into_response();
    };
    {
        let guard = wb.lock_unpoisoned();
        let policy = crate::org::Org::rebuild(guard.store_ref())
            .map(|org| org.effective_placement_policy())
            .unwrap_or_else(|_| gaugedesk_core::boundary_lifecycle::PlacementPolicy::open());
        if !gaugedesk_core::boundary_lifecycle::pairing_admitted(
            &policy,
            &invite.deployment_mode,
            false,
        ) {
            return (
                StatusCode::FORBIDDEN,
                "the invited project's deployment mode is not admitted by this org's placement policy",
            )
                .into_response();
        }
    }
    let origin = AuthorityId::new(invite.ticket.authority.as_str());
    let (broker, pins, accept_wire) = {
        let mut guard = wb.lock_unpoisoned();
        // Pin the origin (TOFU) — the same pinning `POST /federation/pair` does. The
        // mut-`fed` borrow ends with this block, before `store_mut` below.
        {
            let grant_id = crate::library::gen_id("grant");
            match guard.federation_mut() {
                Some(fed) => {
                    fed.accept_ticket(&invite.ticket, grant_id.clone());
                }
                None => {
                    return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured")
                        .into_response()
                }
            }
            persist_bridge(guard.store_mut(), &invite.ticket, &grant_id, true);
        }
        // Only relocation needs a one-shot handoff admission. Join consent is represented by
        // the participant record the serving Home writes after verifying this acceptance.
        if invite.disposition == InviteDisposition::Relocate {
            handoff_oneshot_arm(
                guard.store_mut(),
                origin.as_str(),
                &invite.project,
                &invite.invite_id,
                invite.ticket.expiry,
            );
        }
        // Sign the invite id with our governance key so the origin can pin us (INV-21).
        let root = federation_root_signing_key(&guard);
        let pubkey = guard.governance_public_key();
        let signed_bytes = invite_accept_bytes(&invite.invite_id);
        let (broker, pins, ticket) = match guard.federation_ref() {
            Some(fed) => (
                fed.broker_addr.clone(),
                fed.pins_arc(),
                fed.mint_ticket(pubkey, "bridge:invoke".to_string(), Some(INVITE_TTL_SECS)),
            ),
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured")
                    .into_response()
            }
        };
        let accept_wire = InviteAcceptWire {
            invite_id: invite.invite_id.clone(),
            ticket,
            signature: root.sign(&signed_bytes),
            signed_bytes,
        };
        (broker, pins, accept_wire)
    };
    // Park the origin's receiver legs so the incoming relocate Offer has somewhere to land.
    spawn_peer_receivers(&wb, origin.clone());
    // A brief settle so the handoff receiver parks before the origin's Offer arrives.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // Send the acceptance to the origin's invite-response receiver.
    let token = invite_inbox_token(&invite.invite_id);
    let send = async {
        let tcp = join_relay(&broker, &token).await?;
        let mut tls = tls_connect(tcp, &origin, pins).await?;
        let bytes = serde_json::to_vec(&accept_wire)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_frame(&mut tls, &bytes).await?;
        let vbytes = read_frame(&mut tls).await?;
        let _ = tls.shutdown().await;
        serde_json::from_slice::<serde_json::Value>(&vbytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    };
    // Bound the wait: a stale/consumed invite has no parked receiver, so the rendezvous
    // would otherwise hang forever. Time out into a clean error instead (INV-23 flavour).
    let sent =
        match tokio::time::timeout(std::time::Duration::from_secs(15), send).await {
            Ok(r) => r,
            Err(_) => return (
                StatusCode::GATEWAY_TIMEOUT,
                Json(
                    serde_json::json!({ "ok": false, "reason": "invite expired or already used" }),
                ),
            )
                .into_response(),
        };
    match sent {
        Ok(v) if v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "project": invite.project,
                "project_name": invite.project_name,
                "origin": origin.as_str(),
                "disposition": invite.disposition,
                "confirm_code": invite.confirm_code,
            })),
        )
            .into_response(),
        // The origin answered and declined. A stale or already-consumed invite,
        // or an acceptance whose key did not sign the invite id, is the origin
        // *deciding* — identically on every retry — so it answers `403` and
        // keeps its own sentence, which a 5xx would lose at the edge. Anything
        // unstamped is the origin being broken rather than deciding, and keeps
        // `502`. Same split as [`relocation_verdict`].
        Ok(v) => (
            refusal_status(&v),
            Json(serde_json::json!({ "ok": false, "reason": v.get("reason") })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            format!("invite accept failed: {e}"),
        )
            .into_response(),
    }
}

// --- Co-drive run placement: the wire legs + endpoints (FED-7) ---------------------

/// The host-side **run-place receiver**: parked per operator, it admits a placed run
/// (executes now under a standing allow, else queues it for the host's decision).
pub async fn run_place_receiver(wb: SharedWorkbench, operator: AuthorityId) {
    loop {
        let (broker, identity, me, subkey, delegation, still_paired) = {
            let guard = wb.lock_unpoisoned();
            let me = guard.federation_authority().clone();
            let root = federation_root_signing_key(&guard);
            let (subkey, delegation) = device_identity(&guard.root_path(), &me, &root);
            match guard.federation_ref() {
                Some(fed) => (
                    fed.broker_addr.clone(),
                    fed.identity.clone(),
                    me,
                    subkey,
                    delegation,
                    fed.grant_for(operator.as_str()).is_some(),
                ),
                None => return,
            }
        };
        if !still_paired {
            return;
        }
        let token = run_place_token(operator.as_str(), me.as_str());
        if let Err(e) =
            run_place_serve_once(&wb, &broker, &identity, &subkey, &delegation, &token).await
        {
            tracing::debug!("run-place receiver {operator}→{me}: {e}; retrying");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

async fn run_place_serve_once(
    wb: &SharedWorkbench,
    broker: &str,
    identity: &TlsIdentity,
    subkey: &SigningKey,
    delegation: &DeviceDelegation,
    token: &str,
) -> std::io::Result<()> {
    let tcp = park_relay(broker, token).await?;
    let mut tls = tls_accept(tcp, identity).await?;
    let bytes = read_frame(&mut tls).await?;
    let wire: RunPlaceWire = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let verdict = admit_run_place(wb, &wire, subkey, delegation);
    let out = serde_json::to_vec(&verdict)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_frame(&mut tls, &out).await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// Host admission of a placed run (`INV-13`/`INV-21`): verify the operator's signature
/// against the pinned grant, then — under a standing per-project allow — execute now and
/// return the observations; otherwise queue it pending the host's decision (fail-closed).
fn admit_run_place(
    wb: &SharedWorkbench,
    wire: &RunPlaceWire,
    subkey: &SigningKey,
    delegation: &DeviceDelegation,
) -> RunPlaceVerdict {
    let refused = |reason: &str| RunPlaceVerdict {
        status: "refused".into(),
        resp: None,
        reason: Some(reason.to_string()),
    };
    // Verify + decide under the lock, then RELEASE it before executing (the engine turn
    // re-locks the workbench, so holding the guard across it would deadlock).
    let allowed = {
        let mut guard = wb.lock_unpoisoned();
        let Some(grant) = guard
            .federation_ref()
            .and_then(|f| f.grant_for(&wire.source))
        else {
            return refused("unpaired source");
        };
        let claimed = PublicKey::new(wire.source_pubkey.clone());
        let Some(verify_key) = guard.federation_ref().and_then(|f| {
            effective_source_key(f, &wire.source, &grant, &claimed, &wire.delegation)
        }) else {
            return refused("bad source key");
        };
        if !grant.is_valid(now_secs())
            || wire.signed_bytes != run_place_bytes(&wire.correlation)
            || verify_signature(&wire.signed_bytes, &wire.signature, &verify_key) != Ok(true)
        {
            return refused("verification failed");
        }
        if !active_operator_participant(guard.store_ref(), &wire.project, &wire.source) {
            return refused("source is not an active operator participant in the project");
        }
        if let Some(target_chat) = wire.target_chat.as_deref() {
            use gaugedesk_core::workstream::{WorkstreamPhase, WorkstreamState};

            let target_is_member = guard.library.project_of_chat(target_chat)
                == Some(wire.project.as_str())
                && guard.engagements.contains_key(target_chat)
                && guard.library.workstreams.values().any(|workstream| {
                    guard
                        .store_ref()
                        .fold::<WorkstreamState>(&workstream.id)
                        .is_ok_and(|state| {
                            state.phase == WorkstreamPhase::Active
                                && state.members.contains(target_chat)
                        })
                });
            if !target_is_member {
                return refused(
                    "target_chat is not an active hub-resident workstream member in the project",
                );
            }
        }
        let allowed = run_allowed(guard.store_ref(), &wire.project, &wire.source);
        if allowed {
            // ITGOV-3(b) / ADR 0074: the continuous placement floor (ADR 0061 entry-point #2).
            // A standing grant admits *that the operator may drive*; the org's placement policy
            // still governs *where the run executes*. Refuse (not queue) an allowed run whose
            // deployment mode the policy forbids — restrict-only after the grant, fail-closed,
            // no-op under `open`.
            if !run_place_floor_admits(guard.store_ref(), &guard.library, &wire.project) {
                return refused(
                    "the run's deployment mode is not admitted by this org's placement policy",
                );
            }
            // ADR 0139 §5 layer 3 (SUPPLY-1..3): assemble the envelope set this
            // run is governed by. Restrict-only like the two layers above, and
            // last only because it is the one that needs the set assembled
            // first. Derivation reads records this home holds, never the
            // submission — a set the submitter names is a set it can shorten.
            let host = guard.federation_authority().clone();
            let host_root = federation_root_signing_key(&guard).public_key();
            // Today the host executes its own admitted runs, so the executor
            // coincides with it and the set absorbs the duplicate. Once
            // execution is leased off-box they diverge, and the authority
            // running the code is a stakeholder in what it can observe.
            let executor = host.clone();
            let stakeholders = match crate::envelope_supply::derive_stakeholders(
                guard.store_ref(),
                wire.target_chat.as_deref(),
                &host,
                &executor,
            ) {
                Ok(stakeholders) => stakeholders,
                Err(refusal) => return refused(&refusal.to_string()),
            };
            let supplied =
                crate::envelope_supply::registered_envelopes(guard.store_ref(), &wire.project);
            let federation = guard.federation_ref();
            let supply = match gaugedesk_core::envelope_supply::assemble(
                &stakeholders,
                &supplied,
                |authority| {
                    crate::envelope_supply::root_key_of(federation, &host, &host_root, authority)
                },
            ) {
                Ok(supply) => supply,
                Err(refusal) => return refused(&refusal.to_string()),
            };
            // The evidence a composed run cites. Recorded whether or not any
            // stakeholder supplied policy: an empty record beside a populated
            // roster is the durable statement that every party was ungoverned,
            // which is exactly what must not be indistinguishable from a set
            // that was never assembled. Fail-closed, unlike the admission
            // queue's best-effort append beside it — a run admitted without this
            // is a run whose governance cannot be audited afterwards, and that
            // is the question the record exists to answer.
            // SUPPLY-4: evaluate the meet. Everything above assembles and
            // authenticates the set; this is the layer that lets it decide.
            // Composition itself is `whip`'s — this side supplies the documents
            // and the authority-to-root-key bindings, and refuses on its verdict
            // without reinterpreting it (ADR 0139 §6).
            let constituents: Vec<crate::envelope_composition::SignedConstituent> =
                crate::envelope_supply::registered_records(guard.store_ref(), &wire.project)
                    .into_iter()
                    .filter(|record| {
                        // Only the constituents the record was actually checked
                        // under. An envelope registered for a non-stakeholder has
                        // already refused the run above; this keeps the composed
                        // set and the evidence the same set.
                        supply
                            .record
                            .iter()
                            .any(|entry| entry.authority == record.authority)
                    })
                    .map(|record| crate::envelope_composition::SignedConstituent {
                        authority: record.authority,
                        signed_document: record.signed_document,
                    })
                    .collect();
            let composition_record: Vec<whipplescript_kernel::ifc::CompositionEntry> = supply
                .record
                .iter()
                .map(|entry| whipplescript_kernel::ifc::CompositionEntry {
                    authority: entry.authority.as_str().to_string(),
                    envelope_hash: entry.envelope_hash.clone(),
                    epoch: entry.epoch,
                })
                .collect();
            if let Err(refusal) = crate::envelope_composition::compose(
                &constituents,
                composition_record,
                |authority| {
                    crate::envelope_supply::root_key_of(federation, &host, &host_root, authority)
                },
            ) {
                return refused(&refusal.to_string());
            }
            if crate::envelope_supply::record_supply(guard.store_mut(), &wire.correlation, &supply)
                .is_err()
            {
                return refused("the run's envelope set could not be recorded");
            }
        } else {
            // Fail-closed: queue the run for the host's decision (the admission queue).
            record_pending_run(guard.store_mut(), wire);
        }
        allowed
    };
    if allowed {
        let resp = execute_peer_turn(
            wb,
            &wire.prompt,
            &wire.project,
            wire.target_chat.as_deref(),
            wire.target_chat.as_ref().map(|_| wire.source.as_str()),
            subkey,
            delegation,
        );
        RunPlaceVerdict {
            status: "admitted".into(),
            resp: Some(resp),
            reason: None,
        }
    } else {
        RunPlaceVerdict {
            status: "pending".into(),
            resp: None,
            reason: None,
        }
    }
}

#[derive(Deserialize)]
pub struct RunPlaceRequest {
    pub peer: String,
    pub project: String,
    pub archetype: String,
    pub data_handle: String,
    pub prompt: String,
    #[serde(default)]
    pub target_chat: Option<String>,
}

/// `POST /federation/run/place` — the operator places a project-scoped run on the host.
/// Executes now if the host holds a standing allow (observations admitted), else lands
/// in the host's admission queue (`status: pending`). Co-drive (`INV-13`).
pub async fn post_run_place(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<RunPlaceRequest>,
) -> impl IntoResponse {
    let peer = AuthorityId::new(&req.peer);
    let correlation = crate::library::gen_id("run");
    let (broker, me, subkey, delegation, pins, paired) = {
        let guard = wb.lock_unpoisoned();
        let me = guard.federation_authority().clone();
        let root = federation_root_signing_key(&guard);
        let (subkey, delegation) = device_identity(&guard_root(&guard), &me, &root);
        match guard.federation_ref() {
            Some(fed) => (
                fed.broker_addr.clone(),
                me,
                subkey,
                delegation,
                fed.pins_arc(),
                fed.grant_for(peer.as_str()).is_some(),
            ),
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured")
                    .into_response()
            }
        }
    };
    if !paired {
        return (
            StatusCode::BAD_REQUEST,
            format!("not paired with {}", req.peer),
        )
            .into_response();
    }
    let signed_bytes = run_place_bytes(&correlation);
    let wire = RunPlaceWire {
        correlation: correlation.clone(),
        project: req.project.clone(),
        archetype: req.archetype.clone(),
        data_handle: req.data_handle.clone(),
        prompt: req.prompt.clone(),
        target_chat: req.target_chat.clone(),
        source: me.as_str().to_string(),
        target: peer.as_str().to_string(),
        signature: subkey.sign(&signed_bytes),
        source_pubkey: subkey.public_key().as_str().to_string(),
        signed_bytes,
        delegation: Some(delegation.clone()),
    };
    let run_scope = format!("project::{}::observations", req.project);
    let token = run_place_token(me.as_str(), peer.as_str());
    let send = async {
        let tcp = join_relay(&broker, &token).await?;
        let mut tls = tls_connect(tcp, &peer, pins).await?;
        write_frame(&mut tls, &serde_json::to_vec(&wire).unwrap()).await?;
        let vbytes = read_frame(&mut tls).await?;
        let _ = tls.shutdown().await;
        serde_json::from_slice::<RunPlaceVerdict>(&vbytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    };
    match send.await {
        Ok(v) if v.status == "admitted" => {
            let admitted = match &v.resp {
                Some(r) => admit_observations(
                    &wb,
                    &run_scope,
                    peer.as_str(),
                    &r.observations,
                    &r.delegation,
                ),
                None => 0,
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "admitted",
                    "correlation": correlation,
                    "observations_admitted": admitted,
                    "assistant_text": v.resp.map(|r| r.assistant_text).unwrap_or_default(),
                })),
            )
                .into_response()
        }
        Ok(v) if v.status == "pending" => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "pending", "correlation": correlation })),
        )
            .into_response(),
        // The host refused the placement. `RunPlaceVerdict` already says so in as
        // many words, so unlike the handoff and invite legs nothing needs to be
        // carried here — the classification survives the wire in the type, and
        // the route simply stopped reading it. A refusal is the host's decision
        // (unpaired source, bad key, failed verification, or the placement floor
        // declining the project) and answers `403`.
        Ok(v) if v.status == "refused" => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "status": "refused", "reason": v.reason })),
        )
            .into_response(),
        // A status outside the three the type documents is the host being wrong,
        // not the host deciding, and stays `502` — the same narrowness that keeps
        // an unstamped handoff verdict out of the 4xx range.
        Ok(v) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "status": v.status, "reason": v.reason })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("run place failed: {e}")).into_response(),
    }
}

// ---- cross-authority erasure-on-revocation (ERASE-1, ADR 0067) ------------------
//
// An **erasure crossing**: an upstream authority asks a remote home to erase a payload
// it hosts. Carried over the bridge as an `INV-13` crossing (handle + basis only, never
// payload, `INV-10`; signed, `INV-21`), verified against the pinned grant, and — with a
// pre-agreed **erasure term** — driving the home's local content-erasure lifecycle. Absent
// the term it is **request-only**, fail-closed: queued, never auto-erased (the ADR's honest
// tier). Mirrors the run-place crossing shape; the local lifecycle is `resource_store`.
// The hardware non-retention *guarantee* (D-ATTEST) and a proof-of-erasure receipt across
// the bridge stay deferred (ADR 0067 Consequences).

/// Peers this home has granted a standing **erasure term** — a policy-authorized erasure
/// authority it will auto-honor (ADR 0008 hook). Folded latest-wins per peer: an `allow`
/// grants, a `revoke` withdraws. Fail-closed by default.
const ERASE_TERM_SCOPE: &str = "erase::term";
fn erase_term_granted(store: &Store, peer: &str) -> bool {
    let mut allowed = false;
    for payload in store.records(ERASE_TERM_SCOPE, "peer").unwrap_or_default() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            if v.get("peer").and_then(|p| p.as_str()) == Some(peer) {
                allowed = v.get("allow").and_then(|a| a.as_bool()).unwrap_or(false);
            }
        }
    }
    allowed
}

/// Grant/withdraw the standing erasure term for `peer` (the pre-agreed term, recorded at
/// pairing or by the home's operator). `allow=false` withdraws it.
#[cfg(test)]
fn set_erase_term(store: &mut Store, peer: &str, allow: bool) {
    let rec = serde_json::json!({ "peer": peer, "allow": allow });
    let _ = store.append_record(ERASE_TERM_SCOPE, "peer", &rec.to_string());
}

/// The home's queue of erasure requests it has NOT auto-honored (no term) — request-only,
/// awaiting the home's own decision. Handles + basis only (`INV-10`).
const ERASE_QUEUE_SCOPE: &str = "erase::queue";
fn record_pending_erase(
    store: &mut Store,
    source: &str,
    engagement: &str,
    resource: &str,
    basis: &str,
) {
    let rec = serde_json::json!({
        "source": source,
        "engagement": engagement,
        "resource": resource,
        "basis": basis,
    });
    let _ = store.append_record(ERASE_QUEUE_SCOPE, "event", &rec.to_string());
}

/// The pending (un-honored) erasure requests — the home's "an upstream asked to erase this"
/// list, for the operator to act on. Handles + basis only, never payload.
#[cfg(test)]
fn pending_erasures(store: &Store) -> Vec<serde_json::Value> {
    store
        .records(ERASE_QUEUE_SCOPE, "event")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| serde_json::from_str::<serde_json::Value>(&p).ok())
        .collect()
}

/// The bytes the upstream signs to place an erasure request (`INV-21`).
fn erase_bytes(correlation: &str) -> Vec<u8> {
    format!("gaugewright-erase::{correlation}").into_bytes()
}

/// The rendezvous token an `upstream → home` erasure crossing uses.
fn erase_token(source: &str, home: &str) -> String {
    format!("gaugewright-erase::{source}->{home}")
}

/// An erasure request the upstream places on a home, sent over the cert-pinned leg —
/// the resource handle + basis only (never payload, `INV-10`; signed, `INV-21`).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EraseWire {
    correlation: String,
    /// The resource's engagement scope on the home.
    engagement: String,
    /// The resource handle to erase.
    resource: String,
    /// Why (the revocation basis) — recorded, never a secret.
    basis: String,
    source: String,
    target: String,
    signed_bytes: Vec<u8>,
    signature: gaugedesk_core::signature::Signature,
    source_pubkey: String,
    #[serde(default)]
    delegation: Option<DeviceDelegation>,
}

/// The home's verdict on an erasure request: `erased` (term present — the local lifecycle
/// drove it to tombstoned), `pending` (no term — queued, request-only), or `refused`.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EraseVerdict {
    status: String, // "erased" | "pending" | "refused"
    #[serde(default)]
    reason: Option<String>,
}

/// The home's decision on a **verified** erasure request (ERASE-1): with a standing erasure
/// term for `source`, honor it now by driving the local content-erasure lifecycle
/// ([`resource_store::tombstone`]); absent the term, queue it request-only — fail-closed, no
/// auto-erase. Pure over the store, so it is unit-testable without the crossing transport.
fn decide_erasure(
    store: &mut Store,
    source: &str,
    engagement: &str,
    resource: &str,
    basis: &str,
) -> EraseVerdict {
    if erase_term_granted(store, source) {
        let id = gaugedesk_core::resource::ResourceId::new(resource);
        match crate::resource_store::tombstone(store, engagement, &id) {
            Ok(true) => EraseVerdict {
                status: "erased".into(),
                reason: None,
            },
            Ok(false) => EraseVerdict {
                status: "refused".into(),
                reason: Some("no such resource".into()),
            },
            Err(_) => EraseVerdict {
                status: "refused".into(),
                reason: Some("erasure failed".into()),
            },
        }
    } else {
        record_pending_erase(store, source, engagement, resource, basis);
        EraseVerdict {
            status: "pending".into(),
            reason: None,
        }
    }
}

/// Home admission of an erasure request (`INV-13`/`INV-21`): verify the upstream's signature
/// against the pinned grant, then [`decide_erasure`]. Same verification spine as
/// [`admit_run_place`]; only the action (drive the local erasure lifecycle vs. queue) differs.
fn admit_erasure(wb: &SharedWorkbench, wire: &EraseWire) -> EraseVerdict {
    let refused = |reason: &str| EraseVerdict {
        status: "refused".into(),
        reason: Some(reason.to_string()),
    };
    let mut guard = wb.lock_unpoisoned();
    let Some(grant) = guard
        .federation_ref()
        .and_then(|f| f.grant_for(&wire.source))
    else {
        return refused("unpaired source");
    };
    let claimed = PublicKey::new(wire.source_pubkey.clone());
    let Some(verify_key) = guard
        .federation_ref()
        .and_then(|f| effective_source_key(f, &wire.source, &grant, &claimed, &wire.delegation))
    else {
        return refused("bad source key");
    };
    if !grant.is_valid(now_secs())
        || wire.signed_bytes != erase_bytes(&wire.correlation)
        || verify_signature(&wire.signed_bytes, &wire.signature, &verify_key) != Ok(true)
    {
        return refused("verification failed");
    }
    decide_erasure(
        guard.store_mut(),
        &wire.source,
        &wire.engagement,
        &wire.resource,
        &wire.basis,
    )
}

/// Receiver leg for erasure crossings from `peer` (parked at pairing alongside the other
/// legs). Dials the broker on the derived `peer → me` token, completes the cert-pinned TLS
/// handshake (server side), admits the request, and returns the verdict.
pub async fn run_erasure_receiver(wb: SharedWorkbench, peer: AuthorityId) {
    loop {
        let (broker, identity, me, still_paired) = {
            let guard = wb.lock_unpoisoned();
            let me = guard.federation_authority().clone();
            match guard.federation_ref() {
                Some(fed) => (
                    fed.broker_addr.clone(),
                    fed.identity.clone(),
                    me,
                    fed.grant_for(peer.as_str()).is_some(),
                ),
                None => return,
            }
        };
        if !still_paired {
            return;
        }
        let token = erase_token(peer.as_str(), me.as_str());
        if let Err(e) = erasure_serve_once(&wb, &broker, &identity, &token).await {
            tracing::debug!("erasure receiver {peer}→{me}: {e}; retrying");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

async fn erasure_serve_once(
    wb: &SharedWorkbench,
    broker: &str,
    identity: &TlsIdentity,
    token: &str,
) -> std::io::Result<()> {
    let tcp = park_relay(broker, token).await?;
    let mut tls = tls_accept(tcp, identity).await?;
    let bytes = read_frame(&mut tls).await?;
    let wire: EraseWire = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let verdict = admit_erasure(wb, &wire);
    let out = serde_json::to_vec(&verdict)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_frame(&mut tls, &out).await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// `GET /federation/run/queue` — the host's admission queue: operator runs awaiting a
/// decision (correlation + operator + project + archetype + data handle, `INV-10`).
pub async fn get_run_queue(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let guard = wb.lock_unpoisoned();
    Json(serde_json::json!({ "queue": pending_runs(guard.store_ref()) }))
}

#[derive(Deserialize)]
pub struct RunAllowRequest {
    pub project: String,
    pub operator: String,
    /// `true` (default) to allow this operator's runs on the project; `false` to revoke.
    pub allow: Option<bool>,
}

/// `POST /federation/run/allow` — the host sets (or revokes) a standing per-project
/// **allow** for an operator (the *Allow for project* admission). Future runs from that
/// operator on that project auto-admit; revoking is future-only (`INV-18`/`INV-20`).
pub async fn post_run_allow(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<RunAllowRequest>,
) -> impl IntoResponse {
    let allow = req.allow.unwrap_or(true);
    let mut guard = wb.lock_unpoisoned();
    let rec = serde_json::json!({ "operator": req.operator, "allow": allow });
    let _ = guard.store_mut().append_record(
        &run_allow_scope(&req.project),
        "operator",
        &rec.to_string(),
    );
    Json(serde_json::json!({ "project": req.project, "operator": req.operator, "allow": allow }))
}

#[derive(Deserialize)]
pub struct RunDenyRequest {
    pub correlation: String,
}

/// `POST /federation/run/deny` — the host denies a queued run (resolves it without
/// execution). Fail-closed: a denied run never executes (`run-admission.qnt`).
pub async fn post_run_deny(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<RunDenyRequest>,
) -> impl IntoResponse {
    let mut guard = wb.lock_unpoisoned();
    resolve_run(guard.store_mut(), &req.correlation, "denied");
    Json(serde_json::json!({ "correlation": req.correlation, "denied": true }))
}

// --- Co-drive "Allow once": execute a queued run on admit + deliver the result --------

/// The operator-local store of a delivered run result (FED-7 Allow once), keyed by
/// correlation so the operator can poll for a run it placed that landed pending.
const RUN_RESULT_SCOPE: &str = "run::result";

/// The rendezvous token a `host → operator` run-result delivery uses.
fn run_result_token(host: &str, operator: &str) -> String {
    format!("gaugewright-run-result::{host}->{operator}")
}

/// A run's result, delivered host → operator after an `Allow once` admission: the
/// project it ran on + the signed observations (the operator admits them, `INV-4`).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RunResultWire {
    correlation: String,
    project: String,
    resp: RunResp,
}

/// The pending queued run for `correlation`, as
/// `(operator, project, prompt, target_chat)`.
fn pending_run_by(
    store: &Store,
    correlation: &str,
) -> Option<(String, String, String, Option<String>)> {
    pending_runs(store).into_iter().find_map(|r| {
        if r.get("correlation").and_then(|c| c.as_str()) == Some(correlation) {
            Some((
                r.get("operator")
                    .and_then(|o| o.as_str())
                    .unwrap_or("")
                    .to_string(),
                r.get("project")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string(),
                r.get("prompt")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string(),
                r.get("target_chat")
                    .and_then(|chat| chat.as_str())
                    .map(str::to_owned),
            ))
        } else {
            None
        }
    })
}

#[derive(Deserialize)]
pub struct RunAdmitOnceRequest {
    pub correlation: String,
}

/// `POST /federation/run/admit-once` — the host admits **this one** queued run (Allow
/// once): execute it now on the host, deliver the result to the operator, and resolve
/// the queue entry — without setting a standing allow (`run-admission.qnt`). Single-run.
pub async fn post_run_admit_once(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<RunAdmitOnceRequest>,
) -> impl IntoResponse {
    // Find the queued run + this host's signing identity.
    let (operator, project, prompt, target_chat, broker, me, subkey, delegation, pins) = {
        let guard = wb.lock_unpoisoned();
        let Some((operator, project, prompt, target_chat)) =
            pending_run_by(guard.store_ref(), &req.correlation)
        else {
            return (StatusCode::NOT_FOUND, "no such queued run").into_response();
        };
        let me = guard.federation_authority().clone();
        let root = federation_root_signing_key(&guard);
        let (subkey, delegation) = device_identity(&guard_root(&guard), &me, &root);
        match guard.federation_ref() {
            Some(fed) => (
                operator,
                project,
                prompt,
                target_chat,
                fed.broker_addr.clone(),
                me,
                subkey,
                delegation,
                fed.pins_arc(),
            ),
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "federation not configured")
                    .into_response()
            }
        }
    };
    // Execute the run on the host (it is the project's home), then resolve the queue.
    let resp = execute_peer_turn(
        &wb,
        &prompt,
        &project,
        target_chat.as_deref(),
        target_chat.as_ref().map(|_| operator.as_str()),
        &subkey,
        &delegation,
    );
    {
        let mut guard = wb.lock_unpoisoned();
        resolve_run(guard.store_mut(), &req.correlation, "admitted-once");
    }
    // Deliver the result to the operator (host → operator over the cert-pinned leg).
    let wire = RunResultWire {
        correlation: req.correlation.clone(),
        project,
        resp,
    };
    let token = run_result_token(me.as_str(), &operator);
    let delivered =
        push_run_result(&broker, &AuthorityId::new(&operator), pins, &token, &wire).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({ "correlation": req.correlation, "admitted": true, "delivered": delivered.is_ok() })),
    )
        .into_response()
}

/// Push a run result to the operator's run-result receiver. Best-effort (the operator
/// also polls); a transient failure leaves the operator polling.
async fn push_run_result(
    broker: &str,
    operator: &AuthorityId,
    pins: Arc<PinnedTlsClientConfig>,
    token: &str,
    wire: &RunResultWire,
) -> std::io::Result<()> {
    let tcp = join_relay(broker, token).await?;
    let mut tls = tls_connect(tcp, operator, pins).await?;
    write_frame(&mut tls, &serde_json::to_vec(wire).unwrap()).await?;
    let _ = read_frame(&mut tls).await; // ack
    let _ = tls.shutdown().await;
    Ok(())
}

/// The operator-side **run-result receiver**: parked per host, it admits a delivered
/// run's observations (`INV-4`) and records the result locally for the operator to poll.
pub async fn run_result_receiver(wb: SharedWorkbench, host: AuthorityId) {
    loop {
        let (broker, identity, me, still_paired) = {
            let guard = wb.lock_unpoisoned();
            let me = guard.federation_authority().clone();
            match guard.federation_ref() {
                Some(fed) => (
                    fed.broker_addr.clone(),
                    fed.identity.clone(),
                    me,
                    fed.grant_for(host.as_str()).is_some(),
                ),
                None => return,
            }
        };
        if !still_paired {
            return;
        }
        let token = run_result_token(host.as_str(), me.as_str());
        if let Err(e) = run_result_serve_once(&wb, &broker, &identity, &host, &token).await {
            tracing::debug!("run-result receiver {host}→{me}: {e}; retrying");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

async fn run_result_serve_once(
    wb: &SharedWorkbench,
    broker: &str,
    identity: &TlsIdentity,
    host: &AuthorityId,
    token: &str,
) -> std::io::Result<()> {
    let tcp = park_relay(broker, token).await?;
    let mut tls = tls_accept(tcp, identity).await?;
    let bytes = read_frame(&mut tls).await?;
    let wire: RunResultWire = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let run_scope = format!("project::{}::observations", wire.project);
    let admitted = admit_observations(
        wb,
        &run_scope,
        host.as_str(),
        &wire.resp.observations,
        &wire.resp.delegation,
    );
    {
        let mut guard = wb.lock_unpoisoned();
        let rec = serde_json::json!({
            "correlation": wire.correlation,
            "observations_admitted": admitted,
            "assistant_text": wire.resp.assistant_text,
        });
        let _ = guard
            .store_mut()
            .append_record(RUN_RESULT_SCOPE, "result", &rec.to_string());
    }
    write_frame(&mut tls, b"ok").await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// `GET /federation/run/result?correlation=<id>` — the operator's local projection of a
/// run it placed: `done` (with the admitted-observation count + assistant text) once the
/// host has delivered the result, else `pending`.
pub async fn get_run_result(
    State(wb): State<SharedWorkbench>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let corr = q.get("correlation").cloned().unwrap_or_default();
    let guard = wb.lock_unpoisoned();
    for payload in guard
        .store_ref()
        .records(RUN_RESULT_SCOPE, "result")
        .unwrap_or_default()
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            if v.get("correlation").and_then(|c| c.as_str()) == Some(corr.as_str()) {
                return Json(serde_json::json!({
                    "correlation": corr,
                    "status": "done",
                    "observations_admitted": v.get("observations_admitted"),
                    "assistant_text": v.get("assistant_text"),
                }))
                .into_response();
            }
        }
    }
    Json(serde_json::json!({ "correlation": corr, "status": "pending" })).into_response()
}

/// `GET /federation/handoff/incoming` — pending incoming handoffs awaiting this
/// authority's consent (each carries its project + source; the log is held until
/// accepted).
pub async fn get_handoff_incoming(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let guard = wb.lock_unpoisoned();
    let incoming: Vec<serde_json::Value> = pending_incoming(guard.store_ref())
        .into_iter()
        .map(|o| {
            let project = o["project"].as_str().unwrap_or_default();
            let log: Vec<HandoffLogRecord> =
                serde_json::from_value(o["log"].clone()).unwrap_or_default();
            let deployment_mode = incoming_deployment_mode(&log, project)
                .unwrap_or_else(gaugedesk_core::boundary_lifecycle::Placement::local);
            serde_json::json!({
                "project": o["project"],
                "source": o["source"],
                "deployment_mode": deployment_mode,
            })
        })
        .collect();
    Json(serde_json::json!({ "incoming": incoming }))
}

#[derive(Deserialize)]
pub struct HandoffConsentRequest {
    pub project: String,
    pub source: String,
}

/// `POST /federation/handoff/accept` — consent to a pending incoming handoff: import
/// its held log, commit (this authority becomes home), mark it resolved, and notify
/// the origin (which then commits its side). The target's explicit admission (`INV-13`).
/// The declared deployment mode of the relocated project inside a handoff `log` (`ITGOV-3`):
/// the `deployment_mode` on the incoming `ProjectRecord`, or `None` when the project carries
/// no declared ceiling (the local default applies).
fn incoming_deployment_mode(
    log: &[HandoffLogRecord],
    project: &str,
) -> Option<gaugedesk_core::boundary_lifecycle::Placement> {
    log.iter()
        .filter(|r| r.kind == "project")
        .filter_map(|r| serde_json::from_str::<crate::library::ProjectRecord>(&r.payload).ok())
        .find(|p| p.id == project)
        .and_then(|p| p.deployment_mode)
}

/// ITGOV-3(a): does `policy` admit the relocated `project`'s declared deployment mode?
/// No attestation quote is exchanged over a handoff, so an attested-required policy refuses a
/// handoff that can't prove it (`pairing_admitted(..., measurement_verified = false)`),
/// fail-closed. An open org policy removes no constraint of its own, but an engagement that
/// itself declares attested placement still needs measurement proof. Shared by explicit,
/// batch, preauthorized, and one-shot admission so every path enforces the same gate.
fn handoff_placement_admitted(
    policy: &gaugedesk_core::boundary_lifecycle::PlacementPolicy,
    log: &[HandoffLogRecord],
    project: &str,
) -> bool {
    let declared = incoming_deployment_mode(log, project)
        .unwrap_or_else(gaugedesk_core::boundary_lifecycle::Placement::local);
    gaugedesk_core::boundary_lifecycle::pairing_admitted(policy, &declared, false)
}

pub async fn post_handoff_accept(
    State(wb): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
    Json(req): Json<HandoffConsentRequest>,
) -> impl IntoResponse {
    let (committed, notify) = {
        let mut guard = wb.lock_unpoisoned();
        // ITGOV-3(c): accepting a handoff relocates a project's home onto this org — a governance
        // action. In enterprise mode it must be driven by an authenticated **active member**
        // (ENTSEC-1); solo / bootstrap is unchanged. Fail-closed (`INV-20`; ADR 0066 §C).
        if let Err((code, msg)) = guard.authenticate_request(crate::net_http::bearer(&headers)) {
            return (code, msg).into_response();
        }
        let Some(offer) = pending_incoming(guard.store_ref()).into_iter().find(|o| {
            o["project"].as_str() == Some(req.project.as_str())
                && o["source"].as_str() == Some(req.source.as_str())
        }) else {
            return (
                StatusCode::NOT_FOUND,
                "no pending handoff for that project/source",
            )
                .into_response();
        };
        let log: Vec<HandoffLogRecord> =
            serde_json::from_value(offer["log"].clone()).unwrap_or_default();
        let content: Vec<HandoffContentBundle> =
            serde_json::from_value(offer["content"].clone()).unwrap_or_default();
        let credential_key: Option<SealedKey> =
            serde_json::from_value(offer["credential_key"].clone())
                .ok()
                .flatten();
        let me = guard.federation_authority().as_str().to_string();
        // ITGOV-3(a): a relocated project's declared deployment mode must satisfy this org's
        // placement policy before the target admits it — the handoff analog of the
        // boundary-accept gate (`accept_boundary`). No attestation quote is exchanged over the
        // handoff, so an attested-required policy refuses a handoff that cannot prove it
        // (`pairing_admitted(..., measurement_verified = false)`), fail-closed. An open org
        // floor admits the local/unattested default but does not fabricate measurement proof
        // for an engagement that declares attested placement.
        let placement_policy = crate::org::Org::rebuild(guard.store_ref())
            .map(|o| o.effective_placement_policy())
            .unwrap_or_else(|_| gaugedesk_core::boundary_lifecycle::PlacementPolicy::open());
        if !handoff_placement_admitted(&placement_policy, &log, req.project.as_str()) {
            return (
                StatusCode::FORBIDDEN,
                "the incoming project's deployment mode is not admitted by this org's placement policy",
            )
                .into_response();
        }
        let committed = commit_incoming_handoff(
            &mut guard,
            &req.project,
            &log,
            &content,
            credential_key.as_ref(),
        );
        if committed {
            // host = this authority (consented), operator = the origin.
            record_participants(guard.store_mut(), &req.project, &me, &req.source);
        }
        let _ = guard.store_mut().append_record(
            HANDOFF_INCOMING_SCOPE,
            "event",
            &serde_json::json!({ "op": "resolved", "project": req.project }).to_string(),
        );
        if committed {
            guard.rebuild_library(); // the relocated project now appears in our library
        }
        let notify = handoff_notify_material(&guard, &req.source);
        (committed, notify)
    };
    if !committed {
        return (StatusCode::INTERNAL_SERVER_ERROR, "handoff commit failed").into_response();
    }
    notify_origin(notify, HandoffMsgKind::Committed, &req.project).await;
    let guard = wb.lock_unpoisoned();
    let s = load_handoff(guard.store_ref(), &req.project);
    (StatusCode::OK, Json(handoff_state_json(&req.project, &s))).into_response()
}

/// `POST /federation/handoff/decline` — decline a pending incoming handoff: mark it
/// resolved and notify the origin (which rolls back and stays home).
pub async fn post_handoff_decline(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<HandoffConsentRequest>,
) -> impl IntoResponse {
    let notify = {
        let mut guard = wb.lock_unpoisoned();
        let found = pending_incoming(guard.store_ref()).into_iter().any(|o| {
            o["project"].as_str() == Some(req.project.as_str())
                && o["source"].as_str() == Some(req.source.as_str())
        });
        if !found {
            return (
                StatusCode::NOT_FOUND,
                "no pending handoff for that project/source",
            )
                .into_response();
        }
        let _ = guard.store_mut().append_record(
            HANDOFF_INCOMING_SCOPE,
            "event",
            &serde_json::json!({ "op": "resolved", "project": req.project }).to_string(),
        );
        handoff_notify_material(&guard, &req.source)
    };
    notify_origin(notify, HandoffMsgKind::Declined, &req.project).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({ "project": req.project, "declined": true })),
    )
        .into_response()
}

/// `POST /federation/handoff/accept-all` — consent to **all** pending incoming
/// handoffs at once (batched admission): commit each, register the projects, and
/// notify each origin. Returns the accepted project ids.
pub async fn post_handoff_accept_all(
    State(wb): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (accepted, notifies) = {
        let mut guard = wb.lock_unpoisoned();
        // ITGOV-3(c): the bulk analog of `post_handoff_accept` — gated behind an authenticated
        // active member in enterprise mode (ENTSEC-1); solo / bootstrap unchanged (`INV-20`).
        if let Err((code, msg)) = guard.authenticate_request(crate::net_http::bearer(&headers)) {
            return (code, msg).into_response();
        }
        let me = guard.federation_authority().as_str().to_string();
        // ITGOV-3(a): the same org placement policy `post_handoff_accept` enforces, applied per
        // offer in the batch — a non-compliant relocated project is skipped (left pending, not
        // committed), the bulk analog of the single-accept 403. Rebuilt once (org-wide).
        let placement_policy = crate::org::Org::rebuild(guard.store_ref())
            .map(|o| o.effective_placement_policy())
            .unwrap_or_else(|_| gaugedesk_core::boundary_lifecycle::PlacementPolicy::open());
        let mut accepted: Vec<String> = Vec::new();
        let mut notifies: Vec<(HandoffNotify, String)> = Vec::new();
        for offer in pending_incoming(guard.store_ref()) {
            let project = offer["project"].as_str().unwrap_or("").to_string();
            let source = offer["source"].as_str().unwrap_or("").to_string();
            if project.is_empty() || source.is_empty() {
                continue;
            }
            let log: Vec<HandoffLogRecord> =
                serde_json::from_value(offer["log"].clone()).unwrap_or_default();
            let content: Vec<HandoffContentBundle> =
                serde_json::from_value(offer["content"].clone()).unwrap_or_default();
            let credential_key: Option<SealedKey> =
                serde_json::from_value(offer["credential_key"].clone())
                    .ok()
                    .flatten();
            // Fail-closed: a project whose declared deployment mode the org policy won't admit is
            // not committed and not marked resolved — it stays pending (`INV-20`).
            if !handoff_placement_admitted(&placement_policy, &log, &project) {
                continue;
            }
            let committed = commit_incoming_handoff(
                &mut guard,
                &project,
                &log,
                &content,
                credential_key.as_ref(),
            );
            if committed {
                record_participants(guard.store_mut(), &project, &me, &source);
            }
            let _ = guard.store_mut().append_record(
                HANDOFF_INCOMING_SCOPE,
                "event",
                &serde_json::json!({ "op": "resolved", "project": project }).to_string(),
            );
            if committed {
                notifies.push((handoff_notify_material(&guard, &source), project.clone()));
                accepted.push(project);
            }
        }
        if !accepted.is_empty() {
            guard.rebuild_library();
        }
        (accepted, notifies)
    };
    for (n, project) in notifies {
        notify_origin(n, HandoffMsgKind::Committed, &project).await;
    }
    Json(serde_json::json!({ "accepted": accepted })).into_response()
}

#[derive(Deserialize)]
pub struct HandoffPreauthRequest {
    pub peer: String,
    /// `true` (default) to auto-accept handoffs from `peer`; `false` to withdraw.
    pub allow: Option<bool>,
}

/// `POST /federation/handoff/preauth` — set a standing pre-authorization: handoffs
/// from `peer` auto-accept (friction reduction; default fail-closed without it).
pub async fn post_handoff_preauth(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<HandoffPreauthRequest>,
) -> impl IntoResponse {
    let allow = req.allow.unwrap_or(true);
    let mut guard = wb.lock_unpoisoned();
    let _ = guard.store_mut().append_record(
        HANDOFF_PREAUTH_SCOPE,
        "peer",
        &serde_json::json!({ "peer": req.peer, "allow": allow }).to_string(),
    );
    Json(serde_json::json!({ "peer": req.peer, "preauthorized": allow }))
}

// --- Engagement surfaces: participants/ownership, revoke, connect-data (FO-2) -----

fn project_participants_scope(project: &str) -> String {
    format!("project::{project}::participants")
}
fn project_data_scope(project: &str) -> String {
    format!("project::{project}::data")
}

/// The payload class a project participant owns — the closed set the revoke path
/// dispatches on. Parsing it as an enum (not a bare `String`) means an out-of-set
/// value is a deserialize-time rejection, not a silent fall-through to
/// `operator`/`archetypes` on a security-relevant revoke path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadClass {
    Data,
    Archetypes,
}

impl PayloadClass {
    /// The participant role that owns this class (`data`→host, `archetypes`→operator).
    fn role(self) -> &'static str {
        match self {
            PayloadClass::Data => "host",
            PayloadClass::Archetypes => "operator",
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            PayloadClass::Data => "data",
            PayloadClass::Archetypes => "archetypes",
        }
    }
}

/// A persisted project-participant record (FO-2). Typed so the written shape is
/// checked at compile time rather than shaped by an ad-hoc `json!` literal — a
/// renamed/typo'd key is a build error, not a silently-malformed durable fact.
#[derive(Serialize, Deserialize)]
struct ParticipantRecord {
    authority: String,
    role: String,
    owns: PayloadClass,
    revoked: bool,
}

/// A persisted connected-data record: a host-owned handle + optional label (`INV-10`).
#[derive(Serialize, Deserialize)]
struct DataRecord {
    handle: String,
    label: Option<String>,
}

/// Record the two participants of a relocated project: the **host** (home authority,
/// owns the data) and the **operator** (owns the archetypes). Idempotent enough —
/// the projection folds latest-wins per (authority, owns).
fn record_participants(store: &mut Store, project: &str, host: &str, operator: &str) {
    let scope = project_participants_scope(project);
    for (authority, owns) in [
        (host, PayloadClass::Data),
        (operator, PayloadClass::Archetypes),
    ] {
        let rec = ParticipantRecord {
            authority: authority.to_string(),
            role: owns.role().to_string(),
            owns,
            revoked: false,
        };
        let _ = store.append_record(
            &scope,
            "participant",
            &serde_json::to_string(&rec).unwrap_or_default(),
        );
    }
}

/// Add one operator to an already-hosted project without relocating or copying its Home.
/// Reuses the same participant projection as relocation, so admission, revoke, route
/// distribution, and the UI do not grow a parallel N-party state machine.
fn record_operator_participant(store: &mut Store, project: &str, host: &str, operator: &str) {
    let scope = project_participants_scope(project);
    for (authority, owns) in [
        (host, PayloadClass::Data),
        (operator, PayloadClass::Archetypes),
    ] {
        let rec = ParticipantRecord {
            authority: authority.to_string(),
            role: owns.role().to_string(),
            owns,
            revoked: false,
        };
        let _ = store.append_record(
            &scope,
            "participant",
            &serde_json::to_string(&rec).unwrap_or_default(),
        );
    }
}

fn active_operator_participant(store: &Store, project: &str, authority: &str) -> bool {
    participants_of(store, project)
        .into_iter()
        .any(|participant| {
            participant
                .get("authority")
                .and_then(|value| value.as_str())
                == Some(authority)
                && participant.get("role").and_then(|value| value.as_str()) == Some("operator")
                && !participant
                    .get("revoked")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(true)
        })
}

pub(crate) fn distribution_operator_authorized(
    store: &Store,
    project: &str,
    authority: &str,
) -> bool {
    let participants = participants_of(store, project);
    participants.is_empty()
        || participants.into_iter().any(|participant| {
            participant
                .get("authority")
                .and_then(|value| value.as_str())
                == Some(authority)
                && participant.get("role").and_then(|value| value.as_str()) == Some("operator")
                && !participant
                    .get("revoked")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(true)
        })
}

/// The project's participants, folded latest-wins per (authority, owns) so a later
/// revoke supersedes the grant.
fn participants_of(store: &Store, project: &str) -> Vec<serde_json::Value> {
    let mut by_key: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for payload in store
        .records(&project_participants_scope(project), "participant")
        .unwrap_or_default()
    {
        if let Ok(r) = serde_json::from_str::<ParticipantRecord>(&payload) {
            let key = format!("{}::{}", r.authority, r.owns.as_str());
            if let Ok(v) = serde_json::to_value(&r) {
                by_key.insert(key, v);
            }
        }
    }
    by_key.into_values().collect()
}

/// `GET /federation/handoff/participants?project=…` — the project's host/operator
/// participants, each with the payload class it owns and whether that grant is revoked.
pub async fn get_handoff_participants(
    State(wb): State<SharedWorkbench>,
    Query(q): Query<HandoffStatusQuery>,
) -> impl IntoResponse {
    let guard = wb.lock_unpoisoned();
    Json(serde_json::json!({ "participants": participants_of(guard.store_ref(), &q.project) }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffRevokeRequest {
    pub project: String,
    pub authority: String,
    /// The payload class to revoke — a closed set (`data` | `archetypes`); an
    /// out-of-set value is rejected at deserialize, never silently mis-routed.
    pub owns: PayloadClass,
}

/// `POST /federation/handoff/revoke` — an owner revokes access to its payload class
/// (licensing, not secrecy): future-only, fail-closed (`INV-18`/`INV-20`).
pub async fn post_handoff_revoke(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<HandoffRevokeRequest>,
) -> impl IntoResponse {
    {
        let mut guard = wb.lock_unpoisoned();
        let rec = ParticipantRecord {
            authority: req.authority.clone(),
            role: req.owns.role().to_string(),
            owns: req.owns,
            revoked: true,
        };
        let _ = guard.store_mut().append_record(
            &project_participants_scope(&req.project),
            "participant",
            &serde_json::to_string(&rec).unwrap_or_default(),
        );
    }
    if req.owns == PayloadClass::Archetypes {
        distribute_home_routes(&wb, true, false, Some((&req.project, &req.authority)));
    }
    Json(
        serde_json::json!({ "project": req.project, "authority": req.authority, "owns": req.owns, "revoked": true }),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectDataRequest {
    pub project: String,
    /// The host-owned data **handle** registered into the project (never payload).
    pub handle: String,
    pub label: Option<String>,
}

/// `POST /federation/handoff/connect-data` — the host registers a data handle into a
/// project it hosts (the connect-data picker). Crosses by handle only (`INV-10`).
pub async fn post_handoff_connect_data(
    State(wb): State<SharedWorkbench>,
    Json(req): Json<ConnectDataRequest>,
) -> impl IntoResponse {
    let mut guard = wb.lock_unpoisoned();
    let rec = DataRecord {
        handle: req.handle.clone(),
        label: req.label.clone(),
    };
    let _ = guard.store_mut().append_record(
        &project_data_scope(&req.project),
        "data",
        &serde_json::to_string(&rec).unwrap_or_default(),
    );
    Json(serde_json::json!({ "project": req.project, "handle": req.handle, "connected": true }))
}

/// `GET /federation/handoff/data?project=…` — the host-owned data handles connected
/// to a project (handles + labels only, never payload — `INV-10`).
pub async fn get_handoff_data(
    State(wb): State<SharedWorkbench>,
    Query(q): Query<HandoffStatusQuery>,
) -> impl IntoResponse {
    let guard = wb.lock_unpoisoned();
    let data: Vec<serde_json::Value> = guard
        .store_ref()
        .records(&project_data_scope(&q.project), "data")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| serde_json::from_str(&p).ok())
        .collect();
    Json(serde_json::json!({ "data": data }))
}

/// Transport + signing material to notify an origin of a consent outcome.
struct HandoffNotify {
    broker: String,
    me: AuthorityId,
    home: HomeId,
    origin: AuthorityId,
    subkey: SigningKey,
    delegation: DeviceDelegation,
    pins: Option<Arc<PinnedTlsClientConfig>>,
}

/// Snapshot the material needed to notify `source` (the origin) of a consent outcome.
/// `pins` is `None` when `source` is not a paired peer (no leg to send on).
fn handoff_notify_material(guard: &crate::Workbench, source: &str) -> HandoffNotify {
    let me = guard.federation_authority().clone();
    let root = federation_root_signing_key(guard);
    let (subkey, delegation) = device_identity(&guard_root(guard), &me, &root);
    let pins = guard
        .federation_ref()
        .filter(|f| f.grant_for(source).is_some())
        .map(|f| f.pins_arc());
    let broker = guard
        .federation_ref()
        .map(|f| f.broker_addr.clone())
        .unwrap_or_default();
    HandoffNotify {
        broker,
        me,
        home: guard.federation_home_id(),
        origin: AuthorityId::new(source),
        subkey,
        delegation,
        pins,
    }
}

/// Send a consent-outcome message (`Committed` / `Declined`) back to the origin over
/// the cert-pinned leg; the origin's parked handoff receiver commits/aborts its side.
async fn notify_origin(n: HandoffNotify, kind: HandoffMsgKind, project: &str) {
    let Some(pins) = n.pins else { return };
    let _ = send_handoff(
        &n.broker,
        &n.me,
        &n.home,
        &n.subkey,
        &n.delegation,
        &n.origin,
        pins,
        kind,
        project,
        vec![],
        vec![], // Committed/Declined carry no content — the origin already holds it.
        None,
        None,
    )
    .await;
}

/// Push every currently-authored route for a hosted shared project to its
/// active operators. The serving root signs the route; the ordinary handoff
/// device signature and pinned TLS leg authenticate this delivery act.
pub(crate) fn distribute_authored_home_routes(wb: &SharedWorkbench) {
    distribute_home_routes(wb, false, false, None);
}

/// Retract routes for projects this Home no longer serves before the local
/// account fold removes them, so operators never retain a live stale locator.
pub(crate) fn retract_departed_home_routes(wb: &SharedWorkbench) {
    distribute_home_routes(wb, true, false, None);
}

/// Retract every shared route before reachability publication is disabled.
pub(crate) fn retract_all_home_routes(wb: &SharedWorkbench) {
    distribute_home_routes(wb, true, true, None);
}

fn distribute_home_routes(
    wb: &SharedWorkbench,
    retract: bool,
    retract_all: bool,
    only: Option<(&str, &str)>,
) {
    let deliveries = {
        let guard = wb.lock_unpoisoned();
        let Some(fed) = guard.federation_ref() else {
            return;
        };
        let root = federation_root_signing_key(&guard);
        let me = fed.authority.clone();
        let home = guard.federation_home_id();
        let (subkey, delegation) = device_identity(&guard_root(&guard), &me, &root);
        let routes = crate::account::Account::rebuild(guard.store_ref())
            .map(|account| account.home_routes)
            .unwrap_or_default();
        let mut deliveries = Vec::new();
        for record in routes.into_values().filter(|record| {
            if record.op != crate::account::RecordOp::Upsert
                || record.home_id != *guard.home_id()
                || (record.endpoint.is_empty() && record.relay.is_none())
            {
                return false;
            }
            let served = guard
                .library
                .projects
                .get(&record.id)
                .is_some_and(|project| project.home_id == *guard.home_id());
            if let Some((project, _)) = only {
                return record.id == project && served;
            }
            if retract {
                retract_all || !served
            } else {
                served
            }
        }) {
            let project = record.id.clone();
            let mut route: crate::home::OpaqueHomeRoute = record.into();
            route.home_id = home.clone();
            if retract {
                route.endpoint.clear();
                route.relay = None;
            }
            route.author_authority.clear();
            route.author_root_pubkey.clear();
            route.author_signature = None;
            let Ok(route) = crate::home::sign_home_route(me.as_str(), route, &root) else {
                continue;
            };
            for participant in participants_of(guard.store_ref(), &project) {
                let Some(peer) = participant
                    .get("authority")
                    .and_then(|value| value.as_str())
                else {
                    continue;
                };
                if only.is_some_and(|(_, selected)| peer != selected) {
                    continue;
                }
                if participant.get("role").and_then(|value| value.as_str()) != Some("operator")
                    || (only.is_none()
                        && participant
                            .get("revoked")
                            .and_then(|value| value.as_bool())
                            .unwrap_or(true))
                    || fed.grant_for(peer).is_none()
                {
                    continue;
                }
                deliveries.push((
                    fed.broker_addr.clone(),
                    me.clone(),
                    home.clone(),
                    subkey.clone(),
                    delegation.clone(),
                    AuthorityId::new(peer),
                    fed.pins_arc(),
                    project.clone(),
                    route.clone(),
                ));
            }
        }
        deliveries
    };
    for (broker, me, home, subkey, delegation, peer, pins, project, route) in deliveries {
        tokio::spawn(async move {
            if let Err(error) = send_handoff(
                &broker,
                &me,
                &home,
                &subkey,
                &delegation,
                &peer,
                pins,
                HandoffMsgKind::Route,
                &project,
                Vec::new(),
                Vec::new(),
                None,
                Some(route),
            )
            .await
            {
                tracing::debug!(%project, %peer, %error, "shared Home route delivery failed");
            }
        });
    }
}

#[cfg(test)]
mod erasure_tests {
    use super::*;
    use crate::resource_store::{get, put};
    use gaugedesk_core::boundary::Authority;
    use gaugedesk_core::resource::{
        ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord,
    };

    fn put_resource(store: &mut Store, engagement: &str, id: &str) {
        let res = Resource::input(
            ResourceId::new(id),
            ResourceKind::context(),
            Authority::from("owner"),
        );
        let rec = ResourceRecord::new(
            res,
            ContentLocator::Workspace {
                path: "docs".into(),
                commit: "c1".into(),
            },
            |_| Authority::from("owner"),
        );
        put(store, engagement, &rec).unwrap();
    }

    /// ERASE-1: a verified erasure request without a standing term is queued (request-only,
    /// fail-closed — no auto-erase); with the term the local content-erasure lifecycle
    /// tombstones the payload. (`decide_erasure` is the post-verification decision.)
    #[test]
    fn term_gates_auto_erase_else_queues() {
        let mut store = Store::open_in_memory().unwrap();
        let eng = "engagement-1";
        put_resource(&mut store, eng, "r1");

        // No term → pending, payload untouched, one queued request.
        let v = decide_erasure(&mut store, "upstream-a", eng, "r1", "revoked");
        assert_eq!(v.status, "pending");
        assert!(
            !get(&store, eng, &ResourceId::new("r1"))
                .unwrap()
                .unwrap()
                .tombstoned
        );
        assert_eq!(pending_erasures(&store).len(), 1);

        // Grant the term → auto-honored: the lifecycle drives the payload to tombstoned.
        set_erase_term(&mut store, "upstream-a", true);
        let v = decide_erasure(&mut store, "upstream-a", eng, "r1", "revoked");
        assert_eq!(v.status, "erased");
        assert!(
            get(&store, eng, &ResourceId::new("r1"))
                .unwrap()
                .unwrap()
                .tombstoned
        );

        // The term is per-peer: it does not authorize a different upstream.
        assert!(!erase_term_granted(&store, "upstream-b"));
    }
}

#[cfg(test)]
mod bridge_roster_tests {
    use super::*;

    fn ticket(authority: &str) -> PairingTicket {
        PairingTicket {
            authority: authority.into(),
            governance_pubkey: "gov-pub".into(),
            cert_fingerprint: hex::encode([7u8; 32]),
            broker_addr: "ws://127.0.0.1:7900".into(),
            scope: "project::p1".into(),
            expiry: 9_999_999_999,
        }
    }

    /// ITGOV-2: a paired peer (and its later revoke) survives a restart — the in-memory
    /// `Federation` is rebuilt from the durable bridge roster, not reset to empty.
    #[test]
    fn roster_survives_restart_and_revoke_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let auth = AuthorityId::new("local-user");
        let broker = "ws://127.0.0.1:7900".to_string();

        // Pair a peer and persist the bridge (what `post_pair` does).
        let mut fed = Federation::open(auth.clone(), dir.path(), broker.clone()).unwrap();
        let t = ticket("peer-a");
        fed.accept_ticket(&t, "grant-1".into());
        persist_bridge(&mut store, &t, "grant-1", true);
        assert_eq!(fed.peers().len(), 1);

        // Restart: a fresh open starts empty, then restores from the durable roster.
        let mut booted = Federation::open(auth.clone(), dir.path(), broker.clone()).unwrap();
        assert!(
            booted.peers().is_empty(),
            "fresh open is empty without restore"
        );
        booted.restore_bridges(&folded_bridges(&store));
        assert_eq!(booted.peers().len(), 1, "peer restored across restart");
        assert!(booted.grant_for("peer-a").is_some(), "grant restored too");

        // Revoke is durable: tombstone (active=false) ⇒ a later boot does not re-pin it.
        persist_bridge(&mut store, &t, "grant-1", false);
        let mut after = Federation::open(auth, dir.path(), broker).unwrap();
        after.restore_bridges(&folded_bridges(&store));
        assert!(after.peers().is_empty(), "revoked peer is not restored");
    }
}

#[cfg(test)]
mod multiparty_join_tests {
    use super::*;

    #[test]
    fn joins_accumulate_independently_revocable_operators() {
        let mut store = Store::open_in_memory().unwrap();
        record_operator_participant(&mut store, "project", "host", "operator-a");
        record_operator_participant(&mut store, "project", "host", "operator-b");

        assert!(active_operator_participant(&store, "project", "operator-a"));
        assert!(active_operator_participant(&store, "project", "operator-b"));
        let revoked = ParticipantRecord {
            authority: "operator-a".into(),
            role: "operator".into(),
            owns: PayloadClass::Archetypes,
            revoked: true,
        };
        store
            .append_record(
                &project_participants_scope("project"),
                "participant",
                &serde_json::to_string(&revoked).unwrap(),
            )
            .unwrap();

        assert!(!active_operator_participant(
            &store,
            "project",
            "operator-a"
        ));
        assert!(active_operator_participant(&store, "project", "operator-b"));
        assert_eq!(participants_of(&store, "project").len(), 3);
    }

    #[test]
    fn pending_invitation_preserves_join_disposition() {
        let mut store = Store::open_in_memory().unwrap();
        let expiry = now_secs() + 60;
        record_pending_invite(
            &mut store,
            "invite",
            "project",
            InviteDisposition::Join,
            "1-2-3",
            expiry,
        );
        assert_eq!(
            pending_invite(&store, "invite"),
            Some(("project".into(), InviteDisposition::Join, expiry))
        );
    }
}

#[cfg(test)]
mod handoff_routes_tests {
    use super::*;
    use std::sync::Mutex;

    fn mem_store() -> Store {
        Store::open_in_memory().expect("in-memory store")
    }

    fn seed_relocation_agent(store: &mut Store, protected: bool) {
        for (kind, value) in [
            (
                "instance",
                serde_json::json!({
                    "id": "placement-1",
                    "project_id": "project-1",
                    "agent_id": "agent-1"
                }),
            ),
            (
                "instance",
                serde_json::json!({
                    "id": "authoring-1",
                    "project_id": null,
                    "agent_id": "agent-1"
                }),
            ),
            (
                "agent",
                serde_json::json!({
                    "id": "agent-1",
                    "instance_id": "authoring-1",
                    "config": "{\"secret_prompt\":\"owner IP\"}"
                }),
            ),
            (
                "work_target",
                serde_json::json!({
                    "id": "authoring-target-1",
                    "owner": {"kind": "archetype", "archetype_id": "agent-1"}
                }),
            ),
        ] {
            store
                .append_record(LIBRARY_SCOPE, kind, &value.to_string())
                .unwrap();
        }
        if protected {
            store
                .append_record(
                    LIBRARY_SCOPE,
                    "placement_distribution",
                    &serde_json::json!({
                        "placement_id": "placement-1",
                        "profile": "protected_commercial",
                        "recipient_authority": "tenant:recipient",
                        "lease_seconds": 3600
                    })
                    .to_string(),
                )
                .unwrap();
        }
    }

    #[test]
    fn protected_relocation_excludes_plaintext_agent_definition() {
        let mut store = mem_store();
        seed_relocation_agent(&mut store, true);

        let log = collect_project_log(&store, "project-1");
        let agent = log
            .iter()
            .find(|record| record.kind == "agent")
            .and_then(|record| serde_json::from_str::<serde_json::Value>(&record.payload).ok())
            .expect("sanitized Agent record");
        assert_eq!(agent["config"], "{}");
        assert_eq!(agent["instance_id"], "");
        assert!(!log.iter().any(|record| {
            record.kind == "instance"
                && serde_json::from_str::<serde_json::Value>(&record.payload)
                    .ok()
                    .and_then(|value| value["id"].as_str().map(str::to_owned))
                    .as_deref()
                    == Some("authoring-1")
        }));
        assert!(!log.iter().any(|record| {
            record.kind == "work_target"
                && serde_json::from_str::<serde_json::Value>(&record.payload)
                    .ok()
                    .and_then(|value| value["id"].as_str().map(str::to_owned))
                    .as_deref()
                    == Some("authoring-target-1")
        }));
        assert!(log
            .iter()
            .any(|record| record.kind == "placement_distribution"));
    }

    #[test]
    fn licensed_relocation_keeps_the_agent_definition() {
        let mut store = mem_store();
        seed_relocation_agent(&mut store, false);

        let log = collect_project_log(&store, "project-1");
        let agent = log
            .iter()
            .find(|record| record.kind == "agent")
            .and_then(|record| serde_json::from_str::<serde_json::Value>(&record.payload).ok())
            .expect("ordinary Agent record");
        assert_eq!(agent["config"], "{\"secret_prompt\":\"owner IP\"}");
        assert_eq!(agent["instance_id"], "authoring-1");
        assert!(log.iter().any(|record| {
            record.kind == "work_target"
                && serde_json::from_str::<serde_json::Value>(&record.payload)
                    .ok()
                    .and_then(|value| value["id"].as_str().map(str::to_owned))
                    .as_deref()
                    == Some("authoring-target-1")
        }));
    }

    #[test]
    fn a_serving_root_signed_route_lands_in_the_operators_account_and_tampering_refuses() {
        let source_dir = tempfile::tempdir().unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        let source_id = AuthorityId::new("source-root");
        let target_id = AuthorityId::new("target-root");
        let source_root = FileKeyStore::new(source_dir.path().join("keys")).signing_key(&source_id);
        let source_fed = Federation::open(
            source_id.clone(),
            source_dir.path(),
            "wss://relay.example".into(),
        )
        .unwrap();
        let ticket =
            source_fed.mint_ticket(source_root.public_key(), "bridge:invoke".into(), Some(3600));
        let mut target_fed = Federation::open(
            target_id.clone(),
            target_dir.path(),
            "wss://relay.example".into(),
        )
        .unwrap();
        target_fed.accept_ticket(&ticket, "grant-route".into());
        let target = Arc::new(Mutex::new(
            Workbench::new(mem_store())
                .with_authority(target_id.clone())
                .with_root(target_dir.path())
                .with_federation(target_fed),
        ));

        let home = HomeId::new("home:source-root");
        let route = crate::home::sign_home_route(
            source_id.as_str(),
            crate::home::OpaqueHomeRoute {
                project: "shared-project".into(),
                home_id: home.clone(),
                endpoint: "https://home.example".into(),
                relay: None,
                author_authority: String::new(),
                author_root_pubkey: String::new(),
                author_signature: None,
            },
            &source_root,
        )
        .unwrap();
        let (subkey, delegation) = device_identity(source_dir.path(), &source_id, &source_root);
        let signed_bytes = handoff_bytes("shared-project", &home);
        let wire = HandoffWire {
            kind: HandoffMsgKind::Route,
            project: "shared-project".into(),
            source: source_id.as_str().into(),
            target: target_id.as_str().into(),
            source_home: home,
            log: Vec::new(),
            content: Vec::new(),
            credential_key: None,
            shared_route: Some(route.clone()),
            signature: subkey.sign(&signed_bytes),
            source_pubkey: subkey.public_key().as_str().into(),
            signed_bytes,
            delegation: Some(delegation),
        };
        assert_eq!(
            admit_handoff(&target, &wire).get("ok"),
            Some(&serde_json::json!(true))
        );
        let stored = crate::account::Account::rebuild(target.lock_unpoisoned().store_ref())
            .unwrap()
            .home_routes
            .remove("shared-project")
            .unwrap();
        assert_eq!(stored.author_authority, source_id.as_str());
        assert_eq!(stored.endpoint, "https://home.example");

        let mut tampered = wire;
        tampered.shared_route.as_mut().unwrap().endpoint = "https://attacker.example".into();
        assert_eq!(
            admit_handoff(&target, &tampered).get("refused"),
            Some(&serde_json::json!(true))
        );

        let mut withdrawn = route;
        withdrawn.endpoint.clear();
        withdrawn.author_authority.clear();
        withdrawn.author_root_pubkey.clear();
        withdrawn.author_signature = None;
        let withdrawn =
            crate::home::sign_home_route(source_id.as_str(), withdrawn, &source_root).unwrap();
        let mut withdrawal = tampered;
        withdrawal.shared_route = Some(withdrawn);
        assert_eq!(
            admit_handoff(&target, &withdrawal).get("ok"),
            Some(&serde_json::json!(true))
        );
        assert!(
            !crate::account::Account::rebuild(target.lock_unpoisoned().store_ref())
                .unwrap()
                .home_routes
                .contains_key("shared-project"),
            "a serving-root-signed withdrawal tombstones the shared route"
        );
    }

    #[test]
    fn offer_sync_commit_relocates_home() {
        let mut store = mem_store();
        let p = "proj-1";
        let s = apply_handoff(&mut store, p, HandoffCommand::OfferHandoff).unwrap();
        assert_eq!(s.phase, HandoffPhase::Offered);
        assert_eq!(s.home, handoff::Home::Origin, "offer is not a transfer");
        let s = apply_handoff(&mut store, p, HandoffCommand::SyncLog).unwrap();
        assert!(
            s.target_has_log && s.home == handoff::Home::Origin,
            "log synced, origin still home"
        );
        let s = apply_handoff(&mut store, p, HandoffCommand::CommitHandoff).unwrap();
        assert_eq!(s.phase, HandoffPhase::Committed);
        assert_eq!(s.home, handoff::Home::Target, "home relocated to target");
        // Persisted: a fresh fold of the same scope yields the same state.
        assert_eq!(load_handoff(&store, p), s);
    }

    #[test]
    fn commit_before_sync_is_rejected_and_appends_nothing() {
        let mut store = mem_store();
        let p = "proj-2";
        apply_handoff(&mut store, p, HandoffCommand::OfferHandoff).unwrap();
        assert!(apply_handoff(&mut store, p, HandoffCommand::CommitHandoff).is_err());
        // Fail-closed: still Offered, origin still home.
        let s = load_handoff(&store, p);
        assert_eq!(s.phase, HandoffPhase::Offered);
        assert_eq!(s.home, handoff::Home::Origin);
    }

    #[test]
    fn abort_rolls_back_to_origin() {
        let mut store = mem_store();
        let p = "proj-3";
        apply_handoff(&mut store, p, HandoffCommand::OfferHandoff).unwrap();
        let s = apply_handoff(&mut store, p, HandoffCommand::AbortHandoff).unwrap();
        assert_eq!(s.phase, HandoffPhase::Aborted);
        assert_eq!(s.home, handoff::Home::Origin, "abort keeps origin home");
    }

    // ---- ITGOV-3(a): the placement-policy gate on federated handoff-accept ----

    #[test]
    fn incoming_deployment_mode_reads_the_relocated_project_ceiling() {
        use gaugedesk_core::boundary_lifecycle::{Operator, Placement};
        let project = crate::library::ProjectRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "p1".into(),
            op: crate::library::RecordOp::Upsert,
            name: "Acme".into(),
            is_default: false,
            home_id: gaugedesk_core::ids::HomeId::new("home:local-user"),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: Some(Placement {
                operator: Operator::Counterparty,
                attested: true,
            }),
        };
        let log = vec![
            HandoffLogRecord {
                scope: "library".into(),
                kind: "chat".into(),
                payload: "{}".into(),
            },
            HandoffLogRecord {
                scope: "library".into(),
                kind: "project".into(),
                payload: serde_json::to_string(&project).unwrap(),
            },
        ];
        let declared = incoming_deployment_mode(&log, "p1").expect("project ceiling");
        assert!(declared.attested && declared.operator == Operator::Counterparty);
        // A project not in the log, or one with no declared mode, yields None.
        assert!(incoming_deployment_mode(&log, "other").is_none());
    }

    #[tokio::test]
    async fn handoff_accept_refused_by_org_placement_policy() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use std::sync::{Arc, Mutex};
        use tower::ServiceExt;

        let mut wb = crate::Workbench::new(mem_store());
        // Org policy requires attested placements; a handoff carries no attestation quote, so
        // it cannot satisfy it (fail-closed) — the mirror of the boundary-accept gate.
        wb.store_mut()
            .append_record(
                "org",
                "placement_policy",
                &serde_json::json!({"id":"","op":"upsert","policy":{"require_attested":true,"allowed_operators":[]}})
                    .to_string(),
            )
            .unwrap();
        // A pending incoming handoff for a project that declares no (attested) deployment mode.
        wb.store_mut()
            .append_record(
                "handoff::incoming",
                "event",
                &serde_json::json!({"op":"offer","project":"p1","source":"peer","log":[],"content":[]})
                    .to_string(),
            )
            .unwrap();
        assert_eq!(
            pending_incoming(wb.store_ref()).len(),
            1,
            "the seeded offer is pending"
        );
        // Mount the self-operated federation route surface (as `open_control_plane` does when
        // federation is on) and drive the accept over it.
        let app = featured_routes(true).with_state(Arc::new(Mutex::new(wb)));
        let req = Request::builder()
            .method("POST")
            .uri("/federation/handoff/accept")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"project":"p1","source":"peer"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "an attested-required org policy refuses a handoff that can't prove attestation"
        );
    }

    #[tokio::test]
    async fn combined_invite_is_refused_before_it_arms_a_policy_bypassing_one_shot() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use std::sync::{Arc, Mutex};
        use tower::ServiceExt;

        let mut wb = crate::Workbench::new(mem_store());
        wb.store_mut()
            .append_record(
                "org",
                "placement_policy",
                &serde_json::json!({
                    "id": "",
                    "op": "upsert",
                    "policy": { "require_attested": true, "allowed_operators": [] },
                })
                .to_string(),
            )
            .unwrap();
        let invite = EngagementInvite {
            invite_id: "policy-one-shot".into(),
            ticket: PairingTicket {
                authority: "origin".into(),
                governance_pubkey: "unused-before-policy-gate".into(),
                cert_fingerprint: hex::encode([7u8; 32]),
                broker_addr: "ws://127.0.0.1:7900".into(),
                scope: "bridge:invoke".into(),
                expiry: 9_999_999_999,
            },
            project: "policy-project".into(),
            project_name: "Policy project".into(),
            disposition: InviteDisposition::Relocate,
            deployment_mode: gaugedesk_core::boundary_lifecycle::Placement::local(),
            manifest: Vec::new(),
            agent_distributions: Vec::new(),
            confirm_code: "1-2-3".into(),
        };
        let app = featured_routes(true).with_state(Arc::new(Mutex::new(wb)));
        let req = Request::builder()
            .method("POST")
            .uri("/federation/invite/accept")
            .header("content-type", "application/json")
            .header("idempotency-key", "policy-one-shot")
            .body(Body::from(
                serde_json::json!({ "invite": invite.to_url() }).to_string(),
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn handoff_accept_all_skips_projects_refused_by_org_placement_policy() {
        // ITGOV-3(a): the batch accept-all enforces the SAME placement policy as single accept —
        // a non-compliant relocated project is skipped (committed=no), left pending rather than
        // resolved. Previously accept-all had no policy gate (a fail-open batch seam).
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use std::sync::{Arc, Mutex};
        use tower::ServiceExt;

        let mut wb = crate::Workbench::new(mem_store());
        // Attested-required org policy; a handoff carries no attestation quote (fail-closed).
        wb.store_mut()
            .append_record(
                "org",
                "placement_policy",
                &serde_json::json!({"id":"","op":"upsert","policy":{"require_attested":true,"allowed_operators":[]}})
                    .to_string(),
            )
            .unwrap();
        // A pending incoming handoff for a project that declares no (attested) deployment mode.
        wb.store_mut()
            .append_record(
                "handoff::incoming",
                "event",
                &serde_json::json!({"op":"offer","project":"p1","source":"peer","log":[],"content":[]})
                    .to_string(),
            )
            .unwrap();
        assert_eq!(
            pending_incoming(wb.store_ref()).len(),
            1,
            "the seeded offer is pending"
        );

        let state = Arc::new(Mutex::new(wb));
        let app = featured_routes(true).with_state(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/federation/handoff/accept-all")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["accepted"].as_array().map(|a| a.len()),
            Some(0),
            "the non-compliant project is not accepted"
        );
        // Fail-closed, not declined: the offer stays pending (no `resolved` event written), so a
        // later policy-compliant path can still admit it.
        let guard = state.lock().unwrap();
        assert_eq!(
            pending_incoming(guard.store_ref()).len(),
            1,
            "the refused offer remains pending, not resolved"
        );
    }

    #[tokio::test]
    async fn handoff_accept_requires_member_auth_in_enterprise_mode() {
        // ITGOV-3(c): accepting a handoff relocates a project's home onto this org. In enterprise
        // mode (IdP attached + a provisioned directory) it must be driven by an authenticated
        // active member — an anonymous caller is `401`, not admitted. A valid member bearer is let
        // through (it reaches the "no pending handoff" `404`, past the auth gate). Solo mode is
        // covered by the other accept tests, which POST with no bearer and still proceed.
        use crate::identity::LoopbackIdentityProvider;
        use crate::library::RecordOp;
        use crate::org::{MembershipRecord, MembershipStatus, ORG_SCOPE};
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use gaugedesk_core::abac::AuthorityAttributes;
        use gaugedesk_core::ids::AuthorityId;
        use std::sync::{Arc, Mutex};
        use tower::ServiceExt;

        let idp = LoopbackIdentityProvider::new().enroll(
            "member-token",
            AuthorityId::new("member-auth"),
            AuthorityAttributes::default(),
        );
        let mut wb = crate::Workbench::new(mem_store()).with_identity_provider(Arc::new(idp));
        // Provision an active member so the gate engages (past bootstrap).
        let member = MembershipRecord {
            id: "member-auth".into(),
            op: RecordOp::Upsert,
            org_id: "org".into(),
            authority: "member-auth".into(),
            email: "m@e.com".into(),
            role: "member".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        };
        wb.store_mut()
            .append_record(
                ORG_SCOPE,
                "membership",
                &serde_json::to_string(&member).unwrap(),
            )
            .unwrap();

        let app = featured_routes(true).with_state(Arc::new(Mutex::new(wb)));
        let accept = |bearer: Option<&str>| {
            let mut b = Request::builder()
                .method("POST")
                .uri("/federation/handoff/accept")
                .header("content-type", "application/json");
            if let Some(t) = bearer {
                b = b.header("authorization", format!("Bearer {t}"));
            }
            b.body(Body::from(r#"{"project":"p1","source":"peer"}"#))
                .unwrap()
        };

        // No bearer ⇒ refused before any handoff work (fail-closed).
        let resp = app.clone().oneshot(accept(None)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an anonymous handoff-accept is refused in enterprise mode"
        );
        // A valid member bearer passes the gate and reaches the handoff logic (no pending ⇒ 404).
        let resp = app.oneshot(accept(Some("member-token"))).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a valid member is let through the auth gate"
        );
    }
}

#[cfg(test)]
mod run_place_floor_tests {
    //! ITGOV-3(b) / ADR 0074: the continuous placement floor on a federated run. A standing
    //! `run_allowed` grant no longer exempts a run from the org's placement policy.
    use super::*;
    use crate::library::{Library, ProjectRecord, RecordOp};
    use gaugedesk_core::boundary_lifecycle::{Operator, Placement, PlacementPolicy};
    use std::collections::BTreeSet;

    fn store_with_policy(policy: Option<PlacementPolicy>) -> Store {
        let mut store = Store::open_in_memory().unwrap();
        if let Some(p) = policy {
            store
                .append_record(
                    crate::org::ORG_SCOPE,
                    "placement_policy",
                    &serde_json::json!({ "id": "", "op": "upsert", "policy": p }).to_string(),
                )
                .unwrap();
        }
        store
    }

    fn lib_with(project: &str, mode: Option<Placement>) -> Library {
        let mut lib = Library::default();
        lib.apply_project(ProjectRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: project.into(),
            op: RecordOp::Upsert,
            name: project.into(),
            is_default: false,
            home_id: gaugedesk_core::ids::HomeId::new("home:local-user"),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: mode,
        });
        lib
    }

    #[test]
    fn open_policy_is_a_noop() {
        // No org policy configured ⇒ the floor admits every run (the solo / default path).
        let store = store_with_policy(None);
        let lib = lib_with(
            "p1",
            Some(Placement {
                operator: Operator::Counterparty,
                attested: false,
            }),
        );
        assert!(
            run_place_floor_admits(&store, &lib, "p1"),
            "no org policy ⇒ org-ness never touches the run path"
        );
    }

    #[test]
    fn attested_required_policy_refuses_a_run_that_cannot_prove_it() {
        // No attestation quote crosses on a run-place, so an attested-required policy refuses the
        // run (`measurement_verified = false`) — the fail-open seam ITGOV-3(b) closes: a standing
        // `run_allowed` grant would otherwise have executed it.
        let store = store_with_policy(Some(PlacementPolicy {
            require_attested: true,
            allowed_operators: BTreeSet::new(),
        }));
        let lib = lib_with("p1", Some(Placement::local()));
        assert!(!run_place_floor_admits(&store, &lib, "p1"));
    }

    #[test]
    fn operator_policy_narrows_where_the_run_may_execute() {
        // A non-attested policy that admits only Local-operated execution.
        let store = store_with_policy(Some(PlacementPolicy {
            require_attested: false,
            allowed_operators: BTreeSet::from([Operator::Local]),
        }));
        // A Local-operated project is admitted; the floor only narrows, and Local is in-policy.
        let local = lib_with("p1", Some(Placement::local()));
        assert!(run_place_floor_admits(&store, &local, "p1"));
        // A counterparty-operated project is refused (policy narrows execution to Local).
        let counterparty = lib_with(
            "p2",
            Some(Placement {
                operator: Operator::Counterparty,
                attested: false,
            }),
        );
        assert!(!run_place_floor_admits(&store, &counterparty, "p2"));
    }
}

#[cfg(test)]
mod relocation_verdict_tests {
    use super::{refused_verdict, relocation_verdict};
    use axum::http::StatusCode;

    /// The placement-policy refusal — the case `handoff_relocation.rs` pins.
    /// An org whose policy requires attestation declines a relocation that
    /// cannot prove it; that is the policy speaking, and it answers `403`.
    #[test]
    fn a_placement_policy_refusal_is_forbidden_not_a_gateway_failure() {
        let refusal = refused_verdict(
            "the incoming project's deployment mode is not admitted by this org's placement policy",
        );
        let (status, body) = relocation_verdict(&refusal);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("not admitted by this org's placement policy"),
            "the peer's own explanation must reach the caller: {body}",
        );
    }

    /// The identity checks fail closed for reasons that are equally decisions —
    /// each will decide the same way on every retry — so they answer `403` too.
    #[test]
    fn every_fail_closed_identity_check_is_a_refusal() {
        for reason in ["unpaired source", "bad source key", "verification failed"] {
            let (status, body) = relocation_verdict(&refused_verdict(reason));
            assert_eq!(status, StatusCode::FORBIDDEN, "{reason} is a decision");
            assert!(
                body["error"].as_str().unwrap_or_default().contains(reason),
                "{reason} must survive to the caller: {body}",
            );
        }
    }

    /// A target that admitted the offer and then **broke** while importing it
    /// answers the same `committed: false, pending: false` shape as a refusal —
    /// and must keep `502`. This is the retryable one, and the reason the flag
    /// is explicit instead of inferred from `ok: false`.
    #[test]
    fn a_failed_commit_is_still_a_gateway_failure() {
        let broke = serde_json::json!({
            "ok": false,
            "committed": false,
            "pending": false,
            "home": null,
        });
        let (status, body) = relocation_verdict(&broke);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"], "peer did not admit the handoff");
    }

    /// An unstamped verdict is never *read* as a refusal, however much its text
    /// looks like one. Sniffing the reason is exactly what the carried flag
    /// replaces, and defaulting to `502` keeps a peer built before the flag
    /// existed behaving as it does today.
    #[test]
    fn an_unstamped_verdict_is_never_read_as_a_refusal() {
        let unstamped = serde_json::json!({
            "ok": false,
            "reason": "the incoming project's deployment mode is not admitted",
        });
        assert_eq!(relocation_verdict(&unstamped).0, StatusCode::BAD_GATEWAY);
    }

    /// `refused: false` is not a refusal either — only an affirmative stamp moves
    /// a verdict out of the 5xx range.
    #[test]
    fn only_an_affirmative_stamp_forbids() {
        let not_refused = serde_json::json!({ "ok": false, "refused": false, "reason": "broke" });
        assert_eq!(relocation_verdict(&not_refused).0, StatusCode::BAD_GATEWAY);
    }

    /// A stamped verdict that somehow carries no sentence still answers `403` —
    /// the classification, not the prose, is what decides the status.
    #[test]
    fn a_refusal_without_a_reason_is_still_forbidden() {
        let bare = serde_json::json!({ "ok": false, "refused": true });
        let (status, body) = relocation_verdict(&bare);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "peer refused the handoff");
    }
}

#[cfg(test)]
mod invite_refusal_tests {
    use super::{refusal_status, refused_verdict};
    use axum::http::StatusCode;

    /// A stale or already-consumed invite is the origin **deciding**: the
    /// rendezvous it names is gone, and it will be gone on every retry. `403`.
    #[test]
    fn a_consumed_invite_is_forbidden_not_a_gateway_failure() {
        assert_eq!(
            refusal_status(&refused_verdict("no pending invite")),
            StatusCode::FORBIDDEN,
        );
    }

    /// An acceptance whose key did not sign the invite id fails `INV-21` closed.
    /// That is the same kind of decision, and answers the same way.
    #[test]
    fn a_failed_invite_verification_is_forbidden() {
        assert_eq!(
            refusal_status(&refused_verdict("verification failed")),
            StatusCode::FORBIDDEN,
        );
    }

    /// An origin with no federation configured is the origin being *wrong*, not
    /// the origin deciding — the same line #198 drew when it left `Incomplete`,
    /// `UngovernedHandle` and `UnknownInstance` on `502`. It is left unstamped
    /// and keeps `502`.
    #[test]
    fn an_unconfigured_origin_is_still_a_gateway_failure() {
        let unconfigured =
            serde_json::json!({ "ok": false, "reason": "federation not configured" });
        assert_eq!(refusal_status(&unconfigured), StatusCode::BAD_GATEWAY);
    }
}
