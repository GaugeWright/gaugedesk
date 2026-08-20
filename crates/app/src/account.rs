//! The **account** — the person behind the placements/devices (ACCT-1). Identity is
//! the governance root keypair; this module is the durable **account state** that
//! follows the person: the **device registry**, **settings**, and **sealed
//! linked-credentials**. See [`specs/primitives/account.md`](../../../specs/primitives/account.md)
//! and [ADR 0053](../../../specs/decisions/0053-account-root-identity-and-device-enrollment.md).
//!
//! Records folded latest-wins by id (`data.md`, `INV-5`/`INV-6`) in a reserved
//! `account` scope — the same discipline as [`crate::org`] / [`crate::library`]. The
//! linked credential is **sealed at rest** via the `SEC-4` [`Encryptor`](crate::at_rest::Encryptor):
//! the stored record is ciphertext, decrypted only when the local runtime needs it,
//! never crossing as payload (`INV-10`). Adds no protection invariant (ADR 0020).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub use gaugedesk_directory_protocol::DirectoryRecord;

use gaugedesk_harness::{CredentialCapability, CredentialMaterial};
use gaugedesk_store::{AdmitError, Store};

use crate::at_rest::{Encryptor, LocalAeadEncryptor};
pub use crate::library::RecordOp;
use crate::Workbench;
use gaugedesk_core::ids::HomeId;

/// The reserved store scope holding the person's account state.
pub const ACCOUNT_SCOPE: &str = "account";

/// A device's standing in the registry.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    #[default]
    Active,
    Revoked,
}

/// One enrolled device (the "trusted devices" surface). Durable, auditable
/// (`INV-5`/`INV-6`); revoke flips `status`, it does not erase history.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub label: String,
    /// Hex of the device subkey's public key (FED-5a).
    #[serde(default)]
    pub subkey_pubkey: String,
    #[serde(default)]
    pub status: DeviceStatus,
    /// When this device first joined the account. Zero denotes a legacy record
    /// written before enrollment time was durable; it is never guessed from
    /// projection or log order.
    #[serde(default)]
    pub enrolled_at: u64,
}

/// Wall-clock evidence recorded only when a device joins. Existing records retain
/// their original value across later metadata changes and revocation.
pub fn device_enrolled_at_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// A latest-wins preference (`id` = the setting key).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SettingRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub value: String,
}

/// A linked provider credential (`id` = provider, e.g. `openai`). The token is stored
/// **only** as `SEC-4` ciphertext (hex); the plaintext never lives at rest here.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// Hex-encoded `SEC-4` ciphertext of the OAuth token.
    #[serde(default)]
    pub sealed_token: String,
    /// The OpenAI-compatible endpoint base URL for an **endpoint-configurable**
    /// provider (`openai-generic`, ADR 0083). **Non-secret** — stored plaintext
    /// beside the sealed token; empty for the fixed-host providers. `#[serde(default)]`
    /// so every pre-existing credential record folds unchanged (no migration).
    #[serde(default)]
    pub base_url: String,
    /// Monotonic identity version. Linking or rotating material increments it;
    /// revocation preserves it so prior evidence keeps naming the exact version
    /// that was denied for future use.
    #[serde(default = "initial_credential_version")]
    pub version: u64,
    /// Authentication shape injected only by the final egress broker.
    #[serde(default)]
    pub authentication: CredentialAuthentication,
    /// Current future-use state. Revoked records remain in the append-only fold
    /// so a stale reference fails because it is revoked, not because history was
    /// rewritten.
    #[serde(default)]
    pub status: CredentialStatus,
    /// Explicit execution classes admitted by the owner. Empty denies all use.
    #[serde(default)]
    pub execution_classes: BTreeSet<ModelExecutionClass>,
}

fn initial_credential_version() -> u64 {
    1
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialAuthentication {
    #[default]
    Bearer,
    ApiKey,
    OAuth,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStatus {
    #[default]
    Active,
    Revoked,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ModelExecutionClass {
    LocalInteractive,
    PrivateHome,
    PublicDeployment,
}

impl CredentialRecord {
    pub fn admits(&self, class: ModelExecutionClass) -> bool {
        self.op == RecordOp::Upsert
            && self.status == CredentialStatus::Active
            && self.execution_classes.contains(&class)
    }
}

/// A Home the account may select for new projects. This is reachability and
/// facility metadata only; project records/content remain on the Home.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RegisteredHomeRecord {
    pub id: HomeId,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub kind: crate::home::HomeKind,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<crate::home::OpaqueRelayLocator>,
}

/// Where this account's root-signed directory record lives, and which key signs
/// it (DESK-5f, [ADR 0133](../../../specs/decisions/0133-the-hub-projects-the-account-root-key.md)).
///
/// The directory is addressed *by* the root key, so a client with no root of its
/// own — a browser — has nothing to start from. This is that starting point, and
/// it is only ever a **public** key: publishing it grants nothing, which is why
/// it may live in an account projection a page can read.
///
/// What this record cannot do is prove itself. Anyone holding the person's
/// bearer can write one, and a proof of possession would not help, because an
/// attacker signs their own key with their own root just as validly. The
/// defence is entirely on the reading side — a browser pins on first sight and
/// treats a later change as an alarm ([ADR 0132](../../../specs/decisions/0132-a-browser-pins-the-account-root-key.md)) —
/// and stating that here is the point, because a reader who mistook this for an
/// authenticated value would be trusting it for more than it can carry.
pub const DIRECTORY_RECORD_KIND: &str = "account_directory";
/// Latest-wins: one account, one root, one directory.
pub const DIRECTORY_RECORD_ID: &str = "directory";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountDirectoryRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// The account root's **public** half, as `library_sync_root` reports it.
    pub root_pubkey: String,
    /// The blind directory this record is published to. Carried so a
    /// self-hosted deployment can name its own; a reader with no value here
    /// falls back to its own canonical default rather than failing.
    #[serde(default)]
    pub origin: String,
}

/// The blind account-plane route for one granted project.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HomeRouteRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub home_id: HomeId,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<crate::home::OpaqueRelayLocator>,
}

impl From<HomeRouteRecord> for crate::home::OpaqueHomeRoute {
    fn from(record: HomeRouteRecord) -> Self {
        Self {
            project: record.id,
            home_id: record.home_id,
            endpoint: record.endpoint,
            relay: record.relay,
        }
    }
}

/// The folded account projection (derived, rebuildable — `INV-5`).
#[derive(Default, Clone, Debug)]
pub struct Account {
    pub devices: BTreeMap<String, DeviceRecord>,
    pub settings: BTreeMap<String, SettingRecord>,
    pub credentials: BTreeMap<String, CredentialRecord>,
    pub homes: BTreeMap<String, RegisteredHomeRecord>,
    pub home_routes: BTreeMap<String, HomeRouteRecord>,
    /// Absent until a root-holding client publishes it, which is the ordinary
    /// state for an account that has never enabled library sync.
    pub directory: Option<AccountDirectoryRecord>,
    pub managed_inference_plan: Option<crate::managed_inference::ManagedInferencePlan>,
}

fn fold<T>(map: &mut BTreeMap<String, T>, id: String, op: RecordOp, rec: T) {
    match op {
        RecordOp::Tombstone => {
            map.remove(&id);
        }
        RecordOp::Upsert => {
            map.insert(id, rec);
        }
    }
}

/// The store scope holding **one person's** account state (`ADR 0077`). The single-user desktop
/// (and every internal, non-per-request caller) uses the fixed [`ACCOUNT_SCOPE`]; the hosted hub
/// keys each person's devices/settings/credentials/facilities under `account::<root>` so
/// authenticated callers are isolated (`INV-1`) and never share one scope. An empty `person`
/// (solo / no session) collapses to [`ACCOUNT_SCOPE`], so the desktop path is unchanged.
pub fn account_scope(person: &str) -> String {
    if person.is_empty() {
        ACCOUNT_SCOPE.to_string()
    } else {
        format!("{ACCOUNT_SCOPE}::{person}")
    }
}

impl Account {
    /// Rebuild by folding the default [`ACCOUNT_SCOPE`] — the solo / single-user path.
    pub fn rebuild(store: &Store) -> Result<Account, AdmitError> {
        Self::rebuild_in(store, ACCOUNT_SCOPE)
    }

    /// Rebuild **one person's** account by folding `scope`'s records in position order. Pass
    /// [`ACCOUNT_SCOPE`] for the default tenant-of-one / desktop, or [`account_scope`]`(person)`
    /// for a hosted person. Scope-isolated (`INV-1`).
    pub fn rebuild_in(store: &Store, scope: &str) -> Result<Account, AdmitError> {
        let mut acct = Account::default();
        for row in store.records(scope, "device")? {
            let r: DeviceRecord = serde_json::from_str(&row)?;
            fold(&mut acct.devices, r.id.clone(), r.op, r);
        }
        for row in store.records(scope, "setting")? {
            let r: SettingRecord = serde_json::from_str(&row)?;
            fold(&mut acct.settings, r.id.clone(), r.op, r);
        }
        for row in store.records(scope, "credential")? {
            let r: CredentialRecord = serde_json::from_str(&row)?;
            fold(&mut acct.credentials, r.id.clone(), r.op, r);
        }
        for row in store.records(scope, "home")? {
            let r: RegisteredHomeRecord = serde_json::from_str(&row)?;
            fold(&mut acct.homes, r.id.as_str().to_owned(), r.op, r);
        }
        for row in store.records(scope, "home_route")? {
            let r: HomeRouteRecord = serde_json::from_str(&row)?;
            fold(&mut acct.home_routes, r.id.clone(), r.op, r);
        }
        let mut directory = BTreeMap::new();
        for row in store.records(scope, DIRECTORY_RECORD_KIND)? {
            let r: AccountDirectoryRecord = serde_json::from_str(&row)?;
            fold(&mut directory, r.id.clone(), r.op, r);
        }
        acct.directory = directory.remove(DIRECTORY_RECORD_ID);
        acct.managed_inference_plan = crate::managed_inference::fold_plan(store, scope)?;
        Ok(acct)
    }

    /// The active (non-revoked) devices, stable order.
    pub fn active_devices(&self) -> Vec<&DeviceRecord> {
        self.devices
            .values()
            .filter(|d| d.status == DeviceStatus::Active)
            .collect()
    }
}

// --- the account encryption key + sealing (SEC-4) -------------------------------

/// Derive the account encryption key from the governance root **seed** (ADR 0053 §4).
/// The seed is the *private* key material behind the recovery code — unlike the public
/// authority id it is secret, so this key is secret too. Restoring the seed
/// ([`gaugedesk_core::recovery`]) re-derives the **same** account key, so seed recovery
/// restores access to all sealed account state. The `v2` domain tag marks the deliberate
/// break from the old public-id "loopback double" (`v1`), which **anyone** who knew your
/// public root id could derive — the vulnerability this closes. Callers never derive this
/// themselves; the one resolver is [`Workbench::account_key`], which also returns a
/// device's *recovered* key (enrollment) ahead of the seed path.
pub fn account_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"gaugewright-account-key:v2:");
    h.update(seed);
    h.finalize().into()
}

/// The account [`Encryptor`] for a resolved account `key`.
pub fn account_encryptor(key: [u8; 32]) -> LocalAeadEncryptor {
    LocalAeadEncryptor::new(key)
}

/// Seal a plaintext token → hex ciphertext for storage, under the account `key`.
pub fn seal_token(key: [u8; 32], token: &str) -> Option<String> {
    account_encryptor(key)
        .encrypt(token.as_bytes())
        .ok()
        .map(hex::encode)
}

/// Unseal a stored hex ciphertext → the plaintext token under the account `key` (None on
/// any failure — fail-closed; a token sealed under a different key does not open).
pub fn unseal_token(key: [u8; 32], sealed_hex: &str) -> Option<String> {
    let ct = hex::decode(sealed_hex).ok()?;
    let pt = account_encryptor(key).decrypt(&ct).ok()?;
    String::from_utf8(pt).ok()
}

/// Resolve the **plaintext** linked token for `provider` under the account `key`,
/// decrypting the sealed record — the internal API the local runtime uses (never exposed
/// over HTTP). `None` if no credential is linked or it fails to unseal.
pub fn resolve_token(store: &Store, key: [u8; 32], provider: &str) -> Option<String> {
    let acct = Account::rebuild(store).ok()?;
    let rec = acct.credentials.get(provider)?;
    if !rec.admits(ModelExecutionClass::LocalInteractive) {
        return None;
    }
    unseal_token(key, &rec.sealed_token)
}

/// Validate the endpoint supplied when linking a credential and return the non-secret
/// `base_url` to persist (ADR 0083). `openai-generic` **requires** a base URL that
/// parses and satisfies the TLS policy (https for remote, http only for loopback); the
/// fixed-host providers ignore any supplied endpoint and persist an empty string. The
/// single home for the link-time endpoint rule, shared by the account + project routes.
pub fn link_base_url_for(provider: &str, base_url: Option<&str>) -> Result<String, String> {
    if provider != "openai-generic" {
        return Ok(String::new());
    }
    let base_url = base_url
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .ok_or_else(|| "openai-generic requires an endpoint URL".to_owned())?;
    // Validate parseability + TLS policy; the derived host is not needed here.
    gaugedesk_whip_runtime::openai_generic_endpoint_host(base_url)
        .map_err(|error| error.to_string())?;
    Ok(base_url.to_owned())
}

/// The provider → API-key env-var mapping — the ONE map (the engine's fail-closed
/// BYOK precheck keys off it too, so "which providers are BYOK" is answered here
/// only). Only mapped BYOK providers use the transitional env-shaped resolver;
/// OAuth providers travel through their separate GaugeDesk-owned resolved
/// binding path.
pub(crate) fn provider_env_var(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some("OPENAI_API_KEY"),
        "anthropic" => Some("ANTHROPIC_API_KEY"),
        _ => None,
    }
}

pub fn authentication_for_provider(provider: &str) -> CredentialAuthentication {
    match provider {
        "anthropic" => CredentialAuthentication::ApiKey,
        "openai-codex" => CredentialAuthentication::OAuth,
        _ => CredentialAuthentication::Bearer,
    }
}

/// The coordination scope holding a **project's** per-project overrides (`LLM-2`,
/// [ADR 0062]): the sealed credential a project pins to beat the account default for
/// chats in that project. The same `project::<id>` coordination scope the federation
/// relocation treats as project-owned, so a project's credential pin travels with it.
pub fn project_scope(project_id: &str) -> String {
    format!("project::{project_id}")
}

/// Fold the sealed `credential` records held in an arbitrary `scope` (latest-wins by
/// provider id) — the scope-parametric core under both the account store and the
/// project-scope override (`LLM-2`).
pub fn credentials_in_scope(store: &Store, scope: &str) -> BTreeMap<String, CredentialRecord> {
    let mut map = BTreeMap::new();
    if let Ok(rows) = store.records(scope, "credential") {
        for row in rows {
            if let Ok(r) = serde_json::from_str::<CredentialRecord>(&row) {
                fold(&mut map, r.id.clone(), r.op, r);
            }
        }
    }
    map
}

/// Env vars carrying the **resolved** (decrypted) linked-credential tokens held in
/// `scope`, for providers with a known API-key env mapping. Sealed to `authority`;
/// an entry that fails to unseal is skipped (fail-closed).
pub fn credential_envs_in_scope(
    store: &Store,
    scope: &str,
    key: [u8; 32],
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (provider, rec) in credentials_in_scope(store, scope) {
        if !rec.admits(ModelExecutionClass::LocalInteractive) {
            continue;
        }
        let Some(var) = provider_env_var(&provider) else {
            continue;
        };
        if let Some(token) = unseal_token(key, &rec.sealed_token) {
            out.push((var.to_string(), token));
        }
    }
    out
}

/// Env vars carrying the **resolved** (decrypted) account-linked credential tokens —
/// injected into the runtime so a linked account is actually *used* (ACCT-1 → the agent
/// harness). The account-scope tier of [`resolved_credential_envs`].
pub fn credential_envs(store: &Store, key: [u8; 32]) -> Vec<(String, String)> {
    credential_envs_in_scope(store, ACCOUNT_SCOPE, key)
}

/// The runtime credential env vars for a turn, applying **nearest-scope-wins** (`LLM-2`,
/// [ADR 0062]): the account default is the base; a credential pinned in the chat's
/// `project` overrides it **per provider** (so a project may redirect one provider while
/// inheriting the rest). `project = None` (an authoring/edit chat, the hidden Personal
/// default, or an unknown chat) resolves to the account default alone.
pub fn resolved_credential_envs(
    store: &Store,
    key: [u8; 32],
    project: Option<&str>,
) -> Vec<(String, String)> {
    let mut envs: BTreeMap<String, String> = credential_envs(store, key).into_iter().collect();
    if let Some(project) = project {
        for (var, token) in credential_envs_in_scope(store, &project_scope(project), key) {
            envs.insert(var, token); // project pin beats the account default for this provider
        }
    }
    envs.into_iter().collect()
}

#[derive(Clone, Debug)]
enum SelectedCredentialScope {
    Account(String),
    Project(String),
}

#[derive(Clone, Debug)]
struct SelectedCredential {
    scope: SelectedCredentialScope,
    record: CredentialRecord,
}

impl Workbench {
    /// The **account encryption key** this workbench seals/unseals account state with
    /// (ADR 0053 §4). Resolution order: the key this device **recovered** over enrollment
    /// (a device that joined someone else's root holds *their* account key), else the key
    /// derived from this account's own governance root **seed**. Never the retired
    /// public-id loopback double — see [`account_key_from_seed`].
    pub(crate) fn account_key(&self) -> [u8; 32] {
        if let Some(k) = self.recovered_account_key() {
            return k;
        }
        account_key_from_seed(&self.governance_seed())
    }

    /// Seal an account-scoped secret without exposing the resolved account key to a
    /// band-specific crate. Hosted and enterprise shells use this for credentials such as
    /// refresh tokens; key resolution remains centralized in [`Workbench::account_key`].
    pub fn seal_account_secret(&self, value: &str) -> Option<String> {
        seal_token(self.account_key(), value)
    }

    /// Open an account-scoped secret sealed by [`Workbench::seal_account_secret`].
    /// Returns `None` on malformed ciphertext or a non-matching account key.
    pub fn unseal_account_secret(&self, sealed: &str) -> Option<String> {
        unseal_token(self.account_key(), sealed)
    }

    /// Seal a project-owned credential under a project-specific data key. The
    /// data key is wrapped at rest by the current Home/account boundary, but the
    /// credential ciphertext itself is independent of that wrapper. A handoff
    /// transfers the data key sealed to the target authority and re-wraps it
    /// there, so the project does not remain encrypted to its former owner's
    /// account key (`LLM-5`, ADR 0085).
    pub fn seal_project_secret(&self, project_id: &str, value: &str) -> Option<String> {
        seal_token(self.project_credential_key(project_id)?, value)
    }

    /// Open a project-owned credential using only that project's data key.
    /// Account-key ciphertext therefore fails closed on this path and must be
    /// re-linked rather than silently retaining the old ownership boundary.
    pub fn unseal_project_secret(&self, project_id: &str, sealed: &str) -> Option<String> {
        unseal_token(self.existing_project_credential_key(project_id)?, sealed)
    }

    fn project_credential_key_path(&self, project_id: &str) -> PathBuf {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(project_id.as_bytes());
        self.root_path()
            .join("keys")
            .join("project-credentials")
            .join(format!("{}.key", hex::encode(digest)))
    }

    fn bare_project_credential_key(&self, project_id: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"gaugewright-project-credential-key:test:v1:");
        digest.update(self.account_key());
        digest.update(project_id.as_bytes());
        digest.finalize().into()
    }

    fn existing_project_credential_key(&self, project_id: &str) -> Option<[u8; 32]> {
        if self.root_path().as_os_str().is_empty() {
            return Some(self.bare_project_credential_key(project_id));
        }
        let wrapped = fs::read_to_string(self.project_credential_key_path(project_id)).ok()?;
        let encoded = unseal_token(self.account_key(), wrapped.trim())?;
        let bytes = hex::decode(encoded).ok()?;
        bytes.try_into().ok()
    }

    fn project_credential_key(&self, project_id: &str) -> Option<[u8; 32]> {
        if let Some(key) = self.existing_project_credential_key(project_id) {
            return Some(key);
        }
        let mut key = [0_u8; 32];
        getrandom::getrandom(&mut key).ok()?;
        self.install_project_credential_key(project_id, key)?;
        Some(key)
    }

    fn write_project_credential_key(&self, project_id: &str, key: [u8; 32]) -> Option<()> {
        if self.root_path().as_os_str().is_empty() {
            return Some(());
        }
        let path = self.project_credential_key_path(project_id);
        fs::create_dir_all(path.parent()?).ok()?;
        let wrapped = seal_token(self.account_key(), &hex::encode(key))?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, wrapped).ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).ok()?;
        }
        fs::rename(temporary, path).ok()?;
        Some(())
    }

    /// Raw project key access is crate-private and exists only for the authenticated
    /// handoff shell. It is never serialized unsealed or exposed through HTTP.
    pub(crate) fn project_credential_key_for_handoff(&self, project_id: &str) -> Option<[u8; 32]> {
        self.existing_project_credential_key(project_id)
    }

    /// Install a handoff-carried project key after it was opened under this
    /// authority's private governance key, re-wrapping it for this Home at rest.
    pub(crate) fn install_project_credential_key(
        &self,
        project_id: &str,
        key: [u8; 32],
    ) -> Option<()> {
        self.write_project_credential_key(project_id, key)
    }

    /// Remove this Home's wrapped copy only after the target commits the handoff.
    pub(crate) fn remove_project_credential_key(&self, project_id: &str) -> io::Result<()> {
        if self.root_path().as_os_str().is_empty() {
            return Ok(());
        }
        match fs::remove_file(self.project_credential_key_path(project_id)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// This account's governance root **seed** — the private key material the account key
    /// and the recovered-key wrap both derive from. Resolved through the file-backed key
    /// store when a real state root exists (persisted on first use, stable across restarts);
    /// a **bare/test workbench with no root** derives it purely via the loopback double
    /// *without touching disk*, so credential resolution never writes a key store into the
    /// process CWD. The private half never leaves this in-process value.
    pub(crate) fn governance_seed(&self) -> [u8; 32] {
        use crate::key_store::{FileKeyStore, KeyStore, LoopbackKeyStore};
        let root = self.root_path();
        if root.as_os_str().is_empty() {
            LoopbackKeyStore
                .signing_key(self.authority())
                .to_seed_bytes()
        } else {
            FileKeyStore::new(root.join("keys"))
                .signing_key(self.authority())
                .to_seed_bytes()
        }
    }

    /// The execution class this composition may grant by default when a person
    /// links a credential. Public use is never inferred here; it requires a
    /// deployment-specific grant.
    pub fn default_model_execution_classes(&self) -> BTreeSet<ModelExecutionClass> {
        BTreeSet::from([self.model_execution_class()])
    }

    pub fn model_execution_class(&self) -> ModelExecutionClass {
        if self.hosted_home_mode {
            ModelExecutionClass::PrivateHome
        } else {
            ModelExecutionClass::LocalInteractive
        }
    }

    fn selected_credential_for_chat_in_class(
        &self,
        chat_id: &str,
        provider: &str,
        actor: &str,
        class: ModelExecutionClass,
    ) -> Option<SelectedCredential> {
        if let Some(project_id) = self.library_project_of_chat(chat_id) {
            if let Some(record) =
                credentials_in_scope(self.store_ref(), &project_scope(&project_id))
                    .remove(provider)
                    .filter(|record| record.admits(class))
            {
                return Some(SelectedCredential {
                    scope: SelectedCredentialScope::Project(project_id),
                    record,
                });
            }
        }
        credentials_in_scope(self.store_ref(), &self.account_scope_for_actor(actor))
            .remove(provider)
            .filter(|record| record.admits(class))
            .map(|record| SelectedCredential {
                scope: SelectedCredentialScope::Account(actor.to_owned()),
                record,
            })
    }

    fn versioned_credential_ref(
        scope: &SelectedCredentialScope,
        provider: &str,
        version: u64,
    ) -> String {
        let (kind, owner) = match scope {
            SelectedCredentialScope::Account(authority) => ("account", authority.as_str()),
            SelectedCredentialScope::Project(project) => ("project", project.as_str()),
        };
        format!(
            "gaugedesk:credential:v2:{kind}:{}:{provider}:{version}",
            hex::encode(owner.as_bytes())
        )
    }

    /// Stable, non-secret identity for the credential selected by the same
    /// nearest-scope-wins rule as the ephemeral secret resolver.
    #[cfg(test)]
    pub(crate) fn credential_ref_for_chat(
        &self,
        chat_id: &str,
        provider: &str,
        actor: &str,
    ) -> String {
        self.credential_ref_for_chat_in_class(
            chat_id,
            provider,
            actor,
            self.model_execution_class(),
        )
    }

    pub(crate) fn credential_ref_for_chat_in_class(
        &self,
        chat_id: &str,
        provider: &str,
        actor: &str,
        class: ModelExecutionClass,
    ) -> String {
        self.selected_credential_for_chat_in_class(chat_id, provider, actor, class)
            .map(|selected| {
                Self::versioned_credential_ref(&selected.scope, provider, selected.record.version)
            })
            .unwrap_or_else(|| {
                Self::versioned_credential_ref(
                    &SelectedCredentialScope::Account(actor.to_owned()),
                    provider,
                    0,
                )
            })
    }

    /// Resolve the nearest-scope BYOK credential into an exact-reference
    /// capability. The secret remains private to this in-memory object and is
    /// released only after WhippleScript admits the matching reference.
    #[cfg(test)]
    pub(crate) fn credential_capability_for_chat(
        &self,
        chat_id: &str,
        provider: &str,
        actor: &str,
    ) -> Option<Arc<dyn CredentialCapability>> {
        self.credential_capability_for_chat_in_class(
            chat_id,
            provider,
            actor,
            self.model_execution_class(),
        )
    }

    pub(crate) fn credential_capability_for_chat_in_class(
        &self,
        chat_id: &str,
        provider: &str,
        actor: &str,
        class: ModelExecutionClass,
    ) -> Option<Arc<dyn CredentialCapability>> {
        let selected =
            self.selected_credential_for_chat_in_class(chat_id, provider, actor, class)?;
        let secret = match &selected.scope {
            SelectedCredentialScope::Project(project_id) => {
                self.unseal_project_secret(project_id, &selected.record.sealed_token)?
            }
            SelectedCredentialScope::Account(_) => {
                unseal_token(self.account_key(), &selected.record.sealed_token)?
            }
        };
        Some(resolved_credential_capability(
            Self::versioned_credential_ref(&selected.scope, provider, selected.record.version),
            secret,
            None,
        ))
    }

    /// The non-secret OpenAI-compatible endpoint of the nearest-scope credential for
    /// `provider` (ADR 0083), by the same project-then-account precedence as the secret
    /// resolver. `None` when no credential resolves or it carries no endpoint (the
    /// fixed-host providers) — the caller fails closed on a missing `openai-generic`
    /// endpoint.
    pub(crate) fn credential_base_url_for_chat_in_class(
        &self,
        chat_id: &str,
        provider: &str,
        actor: &str,
        class: ModelExecutionClass,
    ) -> Option<String> {
        let selected =
            self.selected_credential_for_chat_in_class(chat_id, provider, actor, class)?;
        Some(selected.record.base_url).filter(|url| !url.is_empty())
    }

    /// Provider ids pinned as BYOK credentials in one project's coordination scope.
    pub fn project_credential_providers(&self, project_id: &str) -> Vec<String> {
        let scope = project_scope(project_id);
        credentials_in_scope(self.store_ref(), &scope)
            .into_iter()
            .filter(|(_, record)| record.status == CredentialStatus::Active)
            .map(|(provider, _)| provider)
            .collect()
    }

    /// Persist a sealed BYOK credential pin for one project. `base_url` is the
    /// non-secret OpenAI-compatible endpoint for an `openai-generic` pin (ADR 0083),
    /// empty for the fixed-host providers.
    pub fn upsert_project_credential(
        &mut self,
        project_id: &str,
        provider: String,
        sealed_token: String,
        base_url: String,
    ) -> Result<(), AdmitError> {
        let execution_classes = self.default_model_execution_classes();
        self.upsert_project_credential_with_policy(
            project_id,
            provider,
            sealed_token,
            base_url,
            execution_classes,
        )
    }

    pub fn upsert_project_credential_with_policy(
        &mut self,
        project_id: &str,
        provider: String,
        sealed_token: String,
        base_url: String,
        execution_classes: BTreeSet<ModelExecutionClass>,
    ) -> Result<(), AdmitError> {
        let scope = project_scope(project_id);
        let version = credentials_in_scope(self.store_ref(), &scope)
            .get(&provider)
            .map(|record| record.version.saturating_add(1))
            .unwrap_or(1);
        let record = CredentialRecord {
            authentication: authentication_for_provider(&provider),
            id: provider,
            op: RecordOp::Upsert,
            sealed_token,
            base_url,
            version,
            status: CredentialStatus::Active,
            execution_classes,
        };
        self.store_mut().append_record(
            &scope,
            "credential",
            &serde_json::to_string(&record).unwrap(),
        )?;
        self.notify_library_changed(&scope, &record.id, "upsert");
        Ok(())
    }

    /// Tombstone a project's BYOK credential pin.
    pub fn tombstone_project_credential(
        &mut self,
        project_id: &str,
        provider: String,
    ) -> Result<(), AdmitError> {
        let scope = project_scope(project_id);
        let previous = credentials_in_scope(self.store_ref(), &scope).remove(&provider);
        let record = CredentialRecord {
            authentication: previous
                .as_ref()
                .map(|record| record.authentication)
                .unwrap_or_else(|| authentication_for_provider(&provider)),
            id: provider,
            op: RecordOp::Upsert,
            sealed_token: String::new(),
            base_url: previous
                .as_ref()
                .map(|record| record.base_url.clone())
                .unwrap_or_default(),
            version: previous.as_ref().map(|record| record.version).unwrap_or(1),
            status: CredentialStatus::Revoked,
            execution_classes: previous
                .map(|record| record.execution_classes)
                .unwrap_or_default(),
        };
        self.store_mut().append_record(
            &scope,
            "credential",
            &serde_json::to_string(&record).unwrap(),
        )?;
        self.notify_library_changed(&scope, &record.id, "revoke");
        Ok(())
    }

    /// Folded trusted-device records for the local account.
    pub fn account_devices(&self) -> Result<Vec<DeviceRecord>, AdmitError> {
        self.account_devices_in(ACCOUNT_SCOPE)
    }

    /// Trusted devices in `scope` (the caller's account, `ADR 0077`).
    pub fn account_devices_in(&self, scope: &str) -> Result<Vec<DeviceRecord>, AdmitError> {
        Ok(Account::rebuild_in(self.store_ref(), scope)?
            .devices
            .into_values()
            .collect())
    }

    /// Folded settings for the local account (default scope).
    pub fn account_settings(&self) -> Result<BTreeMap<String, String>, AdmitError> {
        self.account_settings_in(ACCOUNT_SCOPE)
    }

    /// Folded settings for the account in `scope` (the caller's account, `ADR 0077`).
    pub fn account_settings_in(&self, scope: &str) -> Result<BTreeMap<String, String>, AdmitError> {
        Ok(Account::rebuild_in(self.store_ref(), scope)?
            .settings
            .into_values()
            .map(|setting| (setting.id, setting.value))
            .collect())
    }

    /// Provider ids linked as sealed local account credentials (default scope).
    pub fn account_credential_providers(&self) -> Result<Vec<String>, AdmitError> {
        self.account_credential_providers_in(ACCOUNT_SCOPE)
    }

    /// Provider ids linked in `scope` (the caller's account). OAuth-linked
    /// providers are excluded: each one is projected by its own status route
    /// (e.g. `/account/oauth/openai-codex`) and unlinks through its own flow,
    /// so listing it here would present the same credential twice.
    pub fn account_credential_providers_in(&self, scope: &str) -> Result<Vec<String>, AdmitError> {
        Ok(Account::rebuild_in(self.store_ref(), scope)?
            .credentials
            .into_iter()
            .filter(|(_, record)| {
                record.status == CredentialStatus::Active
                    && record.authentication != CredentialAuthentication::OAuth
            })
            .map(|(provider, _)| provider)
            .collect())
    }

    /// Persist one account record into `scope` (one person's account scope, `ADR 0077`) and
    /// publish the change ref. `pub` so the per-request account routes write to the caller's
    /// [`account_scope`] rather than the shared default.
    pub fn write_account_record_in<T: serde::Serialize>(
        &mut self,
        scope: &str,
        kind: &str,
        id: &str,
        record: &T,
    ) -> Result<(), AdmitError> {
        self.store_mut()
            .append_record(scope, kind, &serde_json::to_string(record).unwrap())?;
        self.notify_library_changed("account", id, "upsert");
        Ok(())
    }

    /// Enroll or update one trusted device record (default scope).
    pub fn upsert_account_device(&mut self, record: &DeviceRecord) -> Result<(), AdmitError> {
        self.upsert_account_device_in(ACCOUNT_SCOPE, record)
    }

    /// Enroll or update one trusted device in `scope` (the caller's account).
    pub fn upsert_account_device_in(
        &mut self,
        scope: &str,
        record: &DeviceRecord,
    ) -> Result<(), AdmitError> {
        let account = Account::rebuild_in(self.store_ref(), scope)?;
        let mut stored = record.clone();
        if let Some(existing) = account.devices.get(&record.id) {
            // A zero is meaningful for legacy records: preserve its honest
            // "unknown" rather than relabeling an update as the enrollment.
            stored.enrolled_at = existing.enrolled_at;
        }
        self.write_account_record_in(scope, "device", &stored.id, &stored)
    }

    /// Mark one trusted device revoked in `scope`, preserving its label/subkey metadata.
    pub fn revoke_account_device_in(
        &mut self,
        scope: &str,
        device_id: &str,
    ) -> Result<Option<DeviceRecord>, AdmitError> {
        let account = Account::rebuild_in(self.store_ref(), scope)?;
        let Some(existing) = account.devices.get(device_id) else {
            return Ok(None);
        };
        let mut record = existing.clone();
        record.op = RecordOp::Upsert;
        record.status = DeviceStatus::Revoked;
        let id = record.id.clone();
        self.write_account_record_in(scope, "device", &id, &record)?;
        Ok(Some(record))
    }

    /// Mark one trusted device revoked (default scope).
    pub fn revoke_account_device(
        &mut self,
        device_id: &str,
    ) -> Result<Option<DeviceRecord>, AdmitError> {
        self.revoke_account_device_in(ACCOUNT_SCOPE, device_id)
    }

    /// Persist one account setting (default scope).
    pub fn upsert_account_setting(&mut self, record: &SettingRecord) -> Result<(), AdmitError> {
        self.upsert_account_setting_in(ACCOUNT_SCOPE, record)
    }

    /// Persist one account setting in `scope` (the caller's account).
    pub fn upsert_account_setting_in(
        &mut self,
        scope: &str,
        record: &SettingRecord,
    ) -> Result<(), AdmitError> {
        self.write_account_record_in(scope, "setting", &record.id, record)
    }

    /// Persist one sealed account credential (default scope).
    pub fn upsert_account_credential(
        &mut self,
        provider: String,
        sealed_token: String,
        base_url: String,
    ) -> Result<(), AdmitError> {
        self.upsert_account_credential_in(ACCOUNT_SCOPE, provider, sealed_token, base_url)
    }

    /// Persist one sealed account credential in `scope` (the caller's account).
    /// `base_url` is the non-secret OpenAI-compatible endpoint for an
    /// `openai-generic` credential (ADR 0083), empty for the fixed-host providers.
    pub fn upsert_account_credential_in(
        &mut self,
        scope: &str,
        provider: String,
        sealed_token: String,
        base_url: String,
    ) -> Result<(), AdmitError> {
        let execution_classes = self.default_model_execution_classes();
        self.upsert_account_credential_in_with_policy(
            scope,
            provider,
            sealed_token,
            base_url,
            execution_classes,
        )
    }

    pub fn upsert_account_credential_in_with_policy(
        &mut self,
        scope: &str,
        provider: String,
        sealed_token: String,
        base_url: String,
        execution_classes: BTreeSet<ModelExecutionClass>,
    ) -> Result<(), AdmitError> {
        let version = credentials_in_scope(self.store_ref(), scope)
            .get(&provider)
            .map(|record| record.version.saturating_add(1))
            .unwrap_or(1);
        let record = CredentialRecord {
            authentication: authentication_for_provider(&provider),
            id: provider,
            op: RecordOp::Upsert,
            sealed_token,
            base_url,
            version,
            status: CredentialStatus::Active,
            execution_classes,
        };
        self.write_account_record_in(scope, "credential", &record.id, &record)
    }

    /// Tombstone one account credential (default scope).
    pub fn tombstone_account_credential(&mut self, provider: String) -> Result<(), AdmitError> {
        self.tombstone_account_credential_in(ACCOUNT_SCOPE, provider)
    }

    /// Tombstone one account credential in `scope` (the caller's account).
    pub fn tombstone_account_credential_in(
        &mut self,
        scope: &str,
        provider: String,
    ) -> Result<(), AdmitError> {
        let previous = credentials_in_scope(self.store_ref(), scope).remove(&provider);
        let record = CredentialRecord {
            authentication: previous
                .as_ref()
                .map(|record| record.authentication)
                .unwrap_or_else(|| authentication_for_provider(&provider)),
            id: provider,
            op: RecordOp::Upsert,
            sealed_token: String::new(),
            base_url: previous
                .as_ref()
                .map(|record| record.base_url.clone())
                .unwrap_or_default(),
            version: previous.as_ref().map(|record| record.version).unwrap_or(1),
            status: CredentialStatus::Revoked,
            execution_classes: previous
                .map(|record| record.execution_classes)
                .unwrap_or_default(),
        };
        self.write_account_record_in(scope, "credential", &record.id, &record)
    }

    // --- facilities + tenancy (ADR 0077) -------------------------------------

    /// The account-level facilities in `scope` (the caller's account, `ADR 0077` §7) — the ones
    /// that follow the person into every tenant (e.g. library sync).
    pub fn account_facilities_in(
        &self,
        scope: &str,
    ) -> Result<crate::facility::Facilities, AdmitError> {
        crate::facility::Facilities::rebuild_in(self.store_ref(), scope)
    }

    /// The account-level facilities (default scope).
    pub fn account_facilities(&self) -> Result<crate::facility::Facilities, AdmitError> {
        self.account_facilities_in(ACCOUNT_SCOPE)
    }

    /// Attach or update one account-level facility in `scope` (the caller's account).
    pub fn upsert_account_facility_in(
        &mut self,
        scope: &str,
        record: &crate::facility::FacilityRecord,
    ) -> Result<(), AdmitError> {
        self.write_account_record_in(scope, crate::facility::FACILITY_KIND, &record.id, record)?;
        // Publication is a facility, and reachability follows it (ADR 0131 §6).
        // Signalled here rather than in the HTTP handler so every writer counts —
        // a route, a test, a future sync — and none can turn publishing on
        // without the Home noticing.
        self.signal_publication_changed();
        Ok(())
    }

    /// Attach or update one account-level facility (default scope).
    pub fn upsert_account_facility(
        &mut self,
        record: &crate::facility::FacilityRecord,
    ) -> Result<(), AdmitError> {
        self.upsert_account_facility_in(ACCOUNT_SCOPE, record)
    }

    /// Detach (tombstone) one account-level facility in `scope`, if present — future-only
    /// revocation (`INV-18`). Returns the removed record, or `None`.
    pub fn revoke_account_facility_in(
        &mut self,
        scope: &str,
        id: &str,
    ) -> Result<Option<crate::facility::FacilityRecord>, AdmitError> {
        let facilities = crate::facility::Facilities::rebuild_in(self.store_ref(), scope)?;
        let Some(existing) = facilities.get(id) else {
            return Ok(None);
        };
        let mut record = existing.clone();
        record.op = RecordOp::Tombstone;
        let id = record.id.clone();
        self.write_account_record_in(scope, crate::facility::FACILITY_KIND, &id, &record)?;
        self.signal_publication_changed();
        Ok(Some(record))
    }

    /// Detach (tombstone) one account-level facility (default scope).
    pub fn revoke_account_facility(
        &mut self,
        id: &str,
    ) -> Result<Option<crate::facility::FacilityRecord>, AdmitError> {
        self.revoke_account_facility_in(ACCOUNT_SCOPE, id)
    }

    /// The person's tenant switcher in `scope` (the caller's account, `ADR 0077` §9).
    pub fn account_tenancy_in(&self, scope: &str) -> Result<crate::tenancy::Tenancy, AdmitError> {
        crate::tenancy::Tenancy::rebuild_in(self.store_ref(), scope)
    }

    /// The person's tenant switcher (default scope). Empty on the solo desktop path.
    pub fn account_tenancy(&self) -> Result<crate::tenancy::Tenancy, AdmitError> {
        self.account_tenancy_in(ACCOUNT_SCOPE)
    }

    /// Delete one organization the caller owns and is alone in, then **crypto-erase**
    /// its content (SOC 2 finding 4.5 / DR-0086).
    ///
    /// [`crate::tenancy::delete_organization_in`] tombstones the org, membership, and
    /// switcher records but destroys no key, so every encrypted record under the
    /// tenant scope (org/membership/billing/policy, sealed under the scope's per-scope
    /// DEK since finding 2.6) stayed recoverable after a "delete". This tears that key
    /// down so the tombstoned ciphertext becomes permanently unrecoverable.
    ///
    /// Org scopes are never forked, so erasure is immediate — there is no descendant
    /// that could still reach the content, and no deferred sweep is involved. The
    /// account-scope `tenant_ref` tombstone is written under a *different* scope and is
    /// untouched, so the tenant still leaves the person's switcher.
    ///
    /// Erasure is idempotent and retryable: a second call finds no key left to destroy.
    /// A `false` from the erase while content encryption is configured leaves the tenant
    /// tombstoned but not yet erased, and is surfaced rather than swallowed.
    pub fn delete_organization_in(
        &mut self,
        authority: &str,
        account_scope: &str,
        tenant_id: &str,
    ) -> Result<
        Result<crate::tenancy::TenantRef, crate::tenancy::DeleteOrganizationRefusal>,
        AdmitError,
    > {
        let outcome = crate::tenancy::delete_organization_in(
            self.store_mut(),
            authority,
            account_scope,
            tenant_id,
        )?;
        if outcome.is_ok() {
            let scope = crate::org::tenant_scope(tenant_id);
            if !self.crypto_erase_content(&scope) && self.content_encryption_enabled() {
                tracing::warn!(
                    tenant = %tenant_id,
                    scope = %scope,
                    "tenant deleted but content crypto-erase destroyed no key; its \
                     tombstoned records are not yet erased (erasure is idempotent/retryable)"
                );
            }
        }
        Ok(outcome)
    }

    /// **Erase this person's own account** (SOC 2 finding 4.4a / DR-0086): the
    /// Hub-side, customer-facing self-erase. The authenticated person erases their
    /// own account scope — devices, settings, credentials, homes, home-routes, and
    /// the tenant switcher, all sealed under the account scope's per-scope content
    /// DEK since finding 2.6 — by destroying that key, so the retained ciphertext
    /// becomes permanently unrecoverable rather than merely tombstoned.
    ///
    /// It is deliberately narrow, mirroring [`Self::delete_organization_in`]:
    ///
    /// - It **refuses** ([`AccountEraseRefusal::OwnsOrganizations`]) while the
    ///   person is still the sole active owner of any non-personal organization, or
    ///   any such organization still has an active tenant-billable facility. Those
    ///   are the person's to wind down through the tenant-delete path first (which
    ///   detaches the facilities and requires the other members to have left);
    ///   account erase never cascade-deletes an organization out from under its
    ///   other members or its billing. This is the agreed refuse-and-require-cleanup
    ///   default.
    /// - It **deprovisions** (future-only, `INV-18`) the person's membership in
    ///   every non-personal organization they merely belong to (a non-owner
    ///   member), so their access is revoked without erasing a scope that belongs
    ///   to the tenant and its other members.
    /// - It **crypto-erases** the person's own **personal** tenant scope — the
    ///   tenant-of-one [`Self::delete_organization_in`] refuses to touch — after
    ///   tombstoning its org/membership, and then the **account scope** itself.
    ///
    /// 4.4b — erasing a *remote* Home's workbench content the person provisioned —
    /// is out of scope here and blocked on DR-0061 (the Hub has no signed
    /// provisioning channel to the Home plane). Content co-located under this one
    /// account scope is covered; a separate Home plane is not reached.
    ///
    /// Erasure is idempotent and retryable: a second call finds no key left to
    /// destroy. A `false` from an erase while content encryption is configured
    /// leaves the scope tombstoned-or-emptied but not yet erased, and is surfaced
    /// via `tracing::warn!` rather than swallowed, exactly as finding 4.5 does.
    pub fn erase_account_in(
        &mut self,
        actor: &str,
        account_scope: &str,
    ) -> Result<Result<(), AccountEraseRefusal>, AdmitError> {
        use crate::org::{MembershipStatus, Org, OrgRecord, ORG_ID};
        use crate::tenancy::Tenancy;

        let tenancy = Tenancy::rebuild_in(self.store_ref(), account_scope)?;

        // Partition the person's tenants. `personal` is their own tenant-of-one;
        // every other entry is an organization they belong to.
        let mut personal: Vec<crate::tenancy::TenantRef> = Vec::new();
        let mut blocking: Vec<String> = Vec::new();
        let mut deprovision: Vec<String> = Vec::new();
        for tenant in tenancy.list().cloned().collect::<Vec<_>>() {
            if tenant.personal {
                personal.push(tenant);
                continue;
            }
            let scope = crate::org::tenant_scope(&tenant.id);
            // The singleton local directory is not a hosted organization.
            if scope == crate::org::ORG_SCOPE {
                continue;
            }
            let org = Org::rebuild_in(self.store_ref(), &scope)?;
            let Some(member) = org.member_by_authority(actor).cloned() else {
                // A stale switcher entry for a tenant this person no longer has a
                // membership in — nothing there to revoke.
                continue;
            };
            // Reuse delete_organization_in's ownership test: a sole active owner is
            // an active owner with no other active member.
            let is_active_owner =
                member.status == MembershipStatus::Active && member.role == "owner";
            let others = org
                .members
                .values()
                .filter(|m| m.status == MembershipStatus::Active && m.authority != actor)
                .count();
            let sole_active_owner = is_active_owner && others == 0;
            let active_facilities =
                crate::facility::Facilities::rebuild_in(self.store_ref(), &scope)?
                    .active()
                    .count();
            if sole_active_owner || active_facilities > 0 {
                blocking.push(tenant.id.clone());
            } else if member.status == MembershipStatus::Active && member.role != "owner" {
                deprovision.push(tenant.id.clone());
            }
        }

        if !blocking.is_empty() {
            blocking.sort();
            return Ok(Err(AccountEraseRefusal::OwnsOrganizations(blocking)));
        }

        // Not refused: deprovision the person's non-owner memberships (future-only,
        // INV-18) under each organization's *own* scope — never erased here, it
        // belongs to the tenant and its other members.
        for tenant_id in &deprovision {
            let scope = crate::org::tenant_scope(tenant_id);
            if let Some(member) = Org::rebuild_in(self.store_ref(), &scope)?
                .member_by_authority(actor)
                .cloned()
            {
                let mut retired = member;
                retired.status = MembershipStatus::Deprovisioned;
                self.store_mut().append_record(
                    &scope,
                    "membership",
                    &serde_json::to_string(&retired)?,
                )?;
            }
        }

        // Crypto-erase the personal tenant-of-one: tombstone its org + owner
        // membership as delete_organization_in does, then destroy its content key so
        // the retained ciphertext is unrecoverable.
        for tenant in &personal {
            let scope = crate::org::tenant_scope(&tenant.id);
            let directory = OrgRecord {
                id: ORG_ID.into(),
                op: RecordOp::Tombstone,
                ..Default::default()
            };
            let mut records: Vec<(&str, &str, String)> =
                vec![(scope.as_str(), "org", serde_json::to_string(&directory)?)];
            if let Some(member) = Org::rebuild_in(self.store_ref(), &scope)?
                .member_by_authority(actor)
                .cloned()
            {
                let mut retired = member;
                retired.status = MembershipStatus::Deprovisioned;
                records.push((
                    scope.as_str(),
                    "membership",
                    serde_json::to_string(&retired)?,
                ));
            }
            let refs: Vec<(&str, &str, &str)> = records
                .iter()
                .map(|(s, k, v)| (*s, *k, v.as_str()))
                .collect();
            self.store_mut().append_records_atomically(&refs)?;
            if !self.crypto_erase_content(&scope) && self.content_encryption_enabled() {
                tracing::warn!(
                    tenant = %tenant.id,
                    scope = %scope,
                    "account erase tombstoned the personal tenant but its content \
                     crypto-erase destroyed no key; not yet erased (idempotent/retryable)"
                );
            }
        }

        // Finally, crypto-erase the account scope itself: devices, settings,
        // credentials, homes, home-routes, and the tenant_ref switcher entries all
        // become permanently unrecoverable — the intended "account gone" state.
        if !self.crypto_erase_content(account_scope) && self.content_encryption_enabled() {
            tracing::warn!(
                scope = %account_scope,
                "account erase destroyed no account-scope content key; the account's \
                 records are not yet erased (idempotent/retryable)"
            );
        }

        Ok(Ok(()))
    }
}

/// Why an [`Workbench::erase_account_in`] was refused. Mirrors
/// [`crate::tenancy::DeleteOrganizationRefusal`]'s "each arm is a distinct thing to
/// do next" shape — here there is one, and it names the cleanup the person owns.
#[derive(Debug, PartialEq, Eq)]
pub enum AccountEraseRefusal {
    /// The person still solely owns — or has an active tenant-billable facility in
    /// — one or more organizations (their ids). Account erase does not cascade-
    /// delete them out from under their other members or their billing: remove each
    /// through the tenant-delete path first, then erase the account.
    OwnsOrganizations(Vec<String>),
}

#[derive(Clone)]
struct ResolvedCredentialCapability {
    credential_ref: String,
    material: CredentialMaterial,
}

impl std::fmt::Debug for ResolvedCredentialCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedCredentialCapability")
            .field("credential_ref", &self.credential_ref)
            .field("material", &self.material)
            .finish()
    }
}

impl CredentialCapability for ResolvedCredentialCapability {
    fn credential_ref(&self) -> &str {
        &self.credential_ref
    }

    fn resolve(&self, credential_ref: &str) -> io::Result<CredentialMaterial> {
        if credential_ref != self.credential_ref {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential capability reference mismatch",
            ));
        }
        Ok(self.material.clone())
    }
}

pub(crate) fn resolved_credential_capability(
    credential_ref: String,
    secret: String,
    account_id: Option<String>,
) -> Arc<dyn CredentialCapability> {
    Arc::new(ResolvedCredentialCapability {
        credential_ref,
        material: CredentialMaterial::new(secret, account_id),
    })
}

// --- ACCT-2 core: the sealed sync blob + the readable directory record ----------
//
// The blind directory ([ADR 0054](../../../specs/decisions/0054-account-directory-and-sealed-sync.md))
// holds exactly two things: a **sealed account blob** (opaque to it; your devices
// decrypt) and a **readable directory record** (pubkeys + addresses, never secrets).
// These are the *data model*; the always-on directory *service* is needs-infra.

/// The syncable account metadata, sealed into one blob for the directory. Carries the
/// device registry + settings + the (already-sealed) credentials — never your work.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountBlob {
    pub settings: BTreeMap<String, String>,
    pub devices: Vec<DeviceRecord>,
    pub credentials: Vec<CredentialRecord>,
    #[serde(default)]
    pub homes: Vec<RegisteredHomeRecord>,
}

/// Project the folded account to the syncable blob shape.
pub fn account_blob(acct: &Account) -> AccountBlob {
    AccountBlob {
        settings: acct
            .settings
            .values()
            .map(|s| (s.id.clone(), s.value.clone()))
            .collect(),
        devices: acct.devices.values().cloned().collect(),
        credentials: acct.credentials.values().cloned().collect(),
        homes: acct.homes.values().cloned().collect(),
    }
}

/// Seal the account blob (hex ciphertext) for the directory to store opaquely, under the
/// account `key`.
pub fn seal_account_blob(key: [u8; 32], acct: &Account) -> Option<String> {
    let bytes = serde_json::to_vec(&account_blob(acct)).ok()?;
    account_encryptor(key).encrypt(&bytes).ok().map(hex::encode)
}

/// Open a sealed account blob back into its metadata — only the matching account `key`
/// can (fail-closed). This is what a device does after fetching the blob from the
/// directory.
pub fn open_account_blob(key: [u8; 32], sealed_hex: &str) -> Option<AccountBlob> {
    let ct = hex::decode(sealed_hex).ok()?;
    let pt = account_encryptor(key).decrypt(&ct).ok()?;
    serde_json::from_slice(&pt).ok()
}

/// The **readable** record the blind directory holds for routing/identity (`INV-10`:
/// pubkeys + addresses only, never secrets). It is what lets any device prove who you
/// are, see your devices, and find your placements — even with your machine off.
/// Build the directory record from the account + your placement pointers. Carries
/// **no** secrets: only the root pubkey, your active devices' pubkeys, and addresses.
pub fn directory_record(
    root_pubkey: &str,
    acct: &Account,
    placement_pointers: Vec<String>,
    home_routes: Vec<crate::home::OpaqueHomeRoute>,
) -> DirectoryRecord {
    DirectoryRecord {
        root_pubkey: root_pubkey.to_string(),
        device_pubkeys: acct
            .active_devices()
            .iter()
            .map(|d| d.subkey_pubkey.clone())
            .collect(),
        placement_pointers,
        home_routes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LockUnpoisoned;

    /// A fixed account key for the sealing tests (stands in for the seed-derived key the
    /// [`Workbench::account_key`] resolver hands the sealing primitives at runtime).
    const KEY: [u8; 32] = [7u8; 32];
    /// A *different* key — the "not your key" negative in the fail-closed cases.
    const OTHER: [u8; 32] = [9u8; 32];

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[test]
    fn account_scope_isolates_state_per_person() {
        // ADR 0077: the hosted hub keys each person's account under account::<root>, so one
        // person's devices/settings/credentials never fold into another's (INV-1). The empty
        // person collapses to the shared default scope (desktop unchanged).
        assert_eq!(account_scope(""), ACCOUNT_SCOPE);
        assert_ne!(account_scope("alice"), account_scope("bob"));
        assert_ne!(account_scope("alice"), ACCOUNT_SCOPE);

        let mut s = store();
        let setting = |v: &str| {
            serde_json::to_string(&SettingRecord {
                id: "theme".into(),
                op: RecordOp::Upsert,
                value: v.into(),
            })
            .unwrap()
        };
        s.append_record(&account_scope("alice"), "setting", &setting("dark"))
            .unwrap();

        // alice sees her setting; bob and the default scope see nothing.
        assert_eq!(
            Account::rebuild_in(&s, &account_scope("alice"))
                .unwrap()
                .settings
                .len(),
            1
        );
        assert!(Account::rebuild_in(&s, &account_scope("bob"))
            .unwrap()
            .settings
            .is_empty());
        assert!(Account::rebuild(&s).unwrap().settings.is_empty());
    }

    #[test]
    fn hosted_turn_resolves_the_authenticated_actors_scope_and_versioned_ref() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        wb.enable_hosted_home_mode();
        let sealed = seal_token(wb.account_key(), "alice-provider-secret").unwrap();
        wb.upsert_account_credential_in(
            &account_scope("alice"),
            "openai".to_owned(),
            sealed,
            String::new(),
        )
        .unwrap();

        assert_eq!(
            wb.credential_ref_for_chat("unknown-chat", "openai", "alice"),
            "gaugedesk:credential:v2:account:616c696365:openai:1"
        );
        let capability = wb
            .credential_capability_for_chat("unknown-chat", "openai", "alice")
            .expect("alice's Home-scoped credential resolves");
        assert_eq!(
            capability.credential_ref(),
            "gaugedesk:credential:v2:account:616c696365:openai:1"
        );
        assert_eq!(
            capability
                .resolve(capability.credential_ref())
                .unwrap()
                .secret(),
            "alice-provider-secret"
        );
        assert!(wb
            .credential_capability_for_chat("unknown-chat", "openai", "bob")
            .is_none());
    }

    #[test]
    fn rotation_versions_refs_and_revocation_or_wrong_execution_class_denies_future_use() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        wb.enable_hosted_home_mode();
        let scope = account_scope("alice");

        for secret in ["first", "rotated"] {
            let sealed = seal_token(wb.account_key(), secret).unwrap();
            wb.upsert_account_credential_in(&scope, "openai".to_owned(), sealed, String::new())
                .unwrap();
        }
        assert_eq!(
            wb.credential_ref_for_chat("unknown-chat", "openai", "alice"),
            "gaugedesk:credential:v2:account:616c696365:openai:2"
        );

        wb.tombstone_account_credential_in(&scope, "openai".to_owned())
            .unwrap();
        let revoked = credentials_in_scope(wb.store_ref(), &scope)
            .remove("openai")
            .unwrap();
        assert_eq!(revoked.version, 2);
        assert_eq!(revoked.status, CredentialStatus::Revoked);
        assert!(wb
            .credential_capability_for_chat("unknown-chat", "openai", "alice")
            .is_none());

        let sealed = seal_token(wb.account_key(), "local-only").unwrap();
        wb.upsert_account_credential_in_with_policy(
            &scope,
            "openai".to_owned(),
            sealed,
            String::new(),
            BTreeSet::from([ModelExecutionClass::LocalInteractive]),
        )
        .unwrap();
        assert_eq!(
            credentials_in_scope(wb.store_ref(), &scope)
                .remove("openai")
                .unwrap()
                .version,
            3
        );
        assert!(wb
            .credential_capability_for_chat("unknown-chat", "openai", "alice")
            .is_none());
    }

    #[test]
    fn public_execution_requires_an_explicit_public_credential_grant() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        wb.enable_hosted_home_mode();
        let scope = account_scope("alice");
        let sealed = seal_token(wb.account_key(), "public-secret").unwrap();
        wb.upsert_account_credential_in_with_policy(
            &scope,
            "openai".to_owned(),
            sealed,
            String::new(),
            BTreeSet::from([ModelExecutionClass::PublicDeployment]),
        )
        .unwrap();

        assert_eq!(
            wb.credential_ref_for_chat_in_class(
                "unknown-chat",
                "openai",
                "alice",
                ModelExecutionClass::PublicDeployment,
            ),
            "gaugedesk:credential:v2:account:616c696365:openai:1"
        );
        assert!(wb
            .credential_capability_for_chat_in_class(
                "unknown-chat",
                "openai",
                "alice",
                ModelExecutionClass::PublicDeployment,
            )
            .is_some());
        assert!(wb
            .credential_capability_for_chat_in_class(
                "unknown-chat",
                "openai",
                "alice",
                ModelExecutionClass::PrivateHome,
            )
            .is_none());
    }

    #[test]
    fn devices_settings_credentials_fold_latest_wins() {
        let mut s = store();
        let dev = DeviceRecord {
            id: "phone".into(),
            op: RecordOp::Upsert,
            label: "My phone".into(),
            subkey_pubkey: "abcd".into(),
            status: DeviceStatus::Active,
            enrolled_at: 1_700_000_000,
        };
        s.append_record(
            ACCOUNT_SCOPE,
            "device",
            &serde_json::to_string(&dev).unwrap(),
        )
        .unwrap();
        let setting = SettingRecord {
            id: "theme".into(),
            op: RecordOp::Upsert,
            value: "dark".into(),
        };
        s.append_record(
            ACCOUNT_SCOPE,
            "setting",
            &serde_json::to_string(&setting).unwrap(),
        )
        .unwrap();

        let acct = Account::rebuild(&s).unwrap();
        assert_eq!(acct.devices.len(), 1);
        assert_eq!(acct.settings.get("theme").unwrap().value, "dark");
        assert_eq!(acct.active_devices().len(), 1);
    }

    #[test]
    fn revoking_a_device_keeps_the_record() {
        let mut s = store();
        let mut dev = DeviceRecord {
            id: "old".into(),
            op: RecordOp::Upsert,
            label: "Old laptop".into(),
            subkey_pubkey: "ff".into(),
            status: DeviceStatus::Active,
            enrolled_at: 1_700_000_000,
        };
        s.append_record(
            ACCOUNT_SCOPE,
            "device",
            &serde_json::to_string(&dev).unwrap(),
        )
        .unwrap();
        dev.status = DeviceStatus::Revoked;
        s.append_record(
            ACCOUNT_SCOPE,
            "device",
            &serde_json::to_string(&dev).unwrap(),
        )
        .unwrap();

        let acct = Account::rebuild(&s).unwrap();
        // Record preserved (INV-6), but no longer active.
        assert_eq!(acct.devices.len(), 1);
        assert!(acct.active_devices().is_empty());
        assert_eq!(
            acct.devices.get("old").unwrap().status,
            DeviceStatus::Revoked
        );
    }

    #[test]
    fn device_enrollment_time_survives_metadata_updates_and_revocation() {
        let mut wb = Workbench::new(store());
        let original = DeviceRecord {
            id: "laptop".into(),
            op: RecordOp::Upsert,
            label: "Old label".into(),
            subkey_pubkey: "ff".into(),
            status: DeviceStatus::Active,
            enrolled_at: 1_700_000_000,
        };
        wb.upsert_account_device(&original).unwrap();
        wb.upsert_account_device(&DeviceRecord {
            label: "New label".into(),
            enrolled_at: 1_800_000_000,
            ..original.clone()
        })
        .unwrap();
        let revoked = wb.revoke_account_device("laptop").unwrap().unwrap();
        assert_eq!(revoked.enrolled_at, 1_700_000_000);
        assert_eq!(
            Account::rebuild(wb.store_ref()).unwrap().devices["laptop"].enrolled_at,
            1_700_000_000,
        );

        let legacy = DeviceRecord {
            id: "legacy".into(),
            op: RecordOp::Upsert,
            label: "Before dates".into(),
            subkey_pubkey: "old".into(),
            status: DeviceStatus::Active,
            enrolled_at: 0,
        };
        wb.upsert_account_device(&legacy).unwrap();
        wb.upsert_account_device(&DeviceRecord {
            label: "Renamed legacy".into(),
            enrolled_at: 1_800_000_000,
            ..legacy
        })
        .unwrap();
        assert_eq!(
            Account::rebuild(wb.store_ref()).unwrap().devices["legacy"].enrolled_at,
            0,
        );
    }

    #[test]
    fn token_seals_and_unseals_and_is_never_plaintext_at_rest() {
        let token = "sk-oauth-secret-12345";
        let sealed = seal_token(KEY, token).unwrap();
        assert!(
            !sealed.contains("secret"),
            "ciphertext is not the plaintext"
        );
        assert_eq!(unseal_token(KEY, &sealed).unwrap(), token);
        // A different authority's key cannot unseal it.
        assert_eq!(unseal_token(OTHER, &sealed), None);
    }

    fn seeded_account() -> Account {
        let mut acct = Account::default();
        acct.settings.insert(
            "theme".into(),
            SettingRecord {
                id: "theme".into(),
                op: RecordOp::Upsert,
                value: "dark".into(),
            },
        );
        acct.devices.insert(
            "phone".into(),
            DeviceRecord {
                id: "phone".into(),
                op: RecordOp::Upsert,
                label: "Phone".into(),
                subkey_pubkey: "dev-pub-1".into(),
                status: DeviceStatus::Active,
                enrolled_at: 1_700_000_000,
            },
        );
        acct.credentials.insert(
            "openai".into(),
            CredentialRecord {
                id: "openai".into(),
                op: RecordOp::Upsert,
                sealed_token: seal_token(KEY, "tok").unwrap(),
                base_url: String::new(),
                version: 1,
                authentication: CredentialAuthentication::Bearer,
                status: CredentialStatus::Active,
                execution_classes: BTreeSet::from([ModelExecutionClass::LocalInteractive]),
            },
        );
        acct
    }

    #[test]
    fn credential_envs_maps_linked_providers_to_resolved_tokens() {
        let mut s = store();
        for (provider, token) in [
            ("openai", "tok-oai"),
            ("anthropic", "tok-ant"),
            ("unknown", "x"),
        ] {
            let rec = CredentialRecord {
                id: provider.into(),
                op: RecordOp::Upsert,
                sealed_token: seal_token(KEY, token).unwrap(),
                base_url: String::new(),
                version: 1,
                authentication: authentication_for_provider(provider),
                status: CredentialStatus::Active,
                execution_classes: BTreeSet::from([ModelExecutionClass::LocalInteractive]),
            };
            s.append_record(
                ACCOUNT_SCOPE,
                "credential",
                &serde_json::to_string(&rec).unwrap(),
            )
            .unwrap();
        }
        let envs = credential_envs(&s, KEY);
        // Known providers map to their env var with the decrypted token; unknown skipped.
        assert!(envs.contains(&("OPENAI_API_KEY".to_string(), "tok-oai".to_string())));
        assert!(envs.contains(&("ANTHROPIC_API_KEY".to_string(), "tok-ant".to_string())));
        assert_eq!(envs.len(), 2);
    }

    #[test]
    fn account_blob_seals_and_opens_only_with_your_key() {
        let acct = seeded_account();
        let sealed = seal_account_blob(KEY, &acct).unwrap();
        // The directory stores opaque ciphertext — no readable settings/devices.
        assert!(!sealed.contains("dark") && !sealed.contains("phone"));
        // Your key opens it back to the same metadata.
        let blob = open_account_blob(KEY, &sealed).unwrap();
        assert_eq!(blob, account_blob(&acct));
        assert_eq!(blob.settings.get("theme").unwrap(), "dark");
        // A different key cannot (fail-closed).
        assert_eq!(open_account_blob(OTHER, &sealed), None);
    }

    #[test]
    fn directory_record_is_routing_only_no_secrets() {
        let acct = seeded_account();
        let rec = directory_record("root-pub", &acct, vec!["relay://abc".into()], vec![]);
        assert_eq!(rec.root_pubkey, "root-pub");
        assert_eq!(rec.device_pubkeys, vec!["dev-pub-1".to_string()]);
        assert_eq!(rec.placement_pointers, vec!["relay://abc".to_string()]);
        // No secret ever appears in the readable directory record.
        let raw = serde_json::to_string(&rec).unwrap();
        assert!(!raw.contains("tok") && !raw.contains("sealed") && !raw.contains("dark"));
    }

    #[test]
    fn resolve_token_decrypts_the_stored_credential() {
        let mut s = store();
        let cred = CredentialRecord {
            id: "openai".into(),
            op: RecordOp::Upsert,
            sealed_token: seal_token(KEY, "tok-abc").unwrap(),
            base_url: String::new(),
            version: 1,
            authentication: CredentialAuthentication::Bearer,
            status: CredentialStatus::Active,
            execution_classes: BTreeSet::from([ModelExecutionClass::LocalInteractive]),
        };
        s.append_record(
            ACCOUNT_SCOPE,
            "credential",
            &serde_json::to_string(&cred).unwrap(),
        )
        .unwrap();

        // The stored record is ciphertext, not the token…
        let acct = Account::rebuild(&s).unwrap();
        assert!(!acct
            .credentials
            .get("openai")
            .unwrap()
            .sealed_token
            .contains("tok-abc"));
        // …but the runtime resolves the plaintext.
        assert_eq!(resolve_token(&s, KEY, "openai").as_deref(), Some("tok-abc"));
        assert_eq!(resolve_token(&s, KEY, "anthropic"), None);
    }

    /// ADR 0083: linking `openai-generic` requires a policy-valid endpoint; the
    /// fixed-host providers ignore any supplied endpoint and persist nothing.
    #[test]
    fn link_base_url_for_enforces_the_endpoint_policy() {
        // Fixed-host providers: endpoint ignored (empty), even if one is passed.
        assert_eq!(
            link_base_url_for("openai", Some("https://api.example.com")).unwrap(),
            ""
        );
        assert_eq!(link_base_url_for("anthropic", None).unwrap(), "");
        // openai-generic: a valid https (or loopback http) endpoint is kept verbatim.
        assert_eq!(
            link_base_url_for("openai-generic", Some("https://api.together.xyz/v1")).unwrap(),
            "https://api.together.xyz/v1"
        );
        assert_eq!(
            link_base_url_for("openai-generic", Some("http://localhost:11434/v1")).unwrap(),
            "http://localhost:11434/v1"
        );
        // openai-generic without / with a policy-invalid endpoint fails closed.
        assert!(link_base_url_for("openai-generic", None).is_err());
        assert!(link_base_url_for("openai-generic", Some("  ")).is_err());
        assert!(link_base_url_for("openai-generic", Some("http://api.remote.com")).is_err());
    }

    /// LLM-2 (ADR 0062): a credential pinned in the chat's project overrides the account
    /// default **per provider** (nearest-scope-wins); providers the project does not pin
    /// fall through to the account; `project = None` resolves to the account alone.
    #[test]
    fn project_pin_beats_account_per_provider() {
        let mut s = store();
        let seal = |tok: &str| seal_token(KEY, tok).unwrap();
        let put = |s: &mut Store, scope: &str, provider: &str, tok: &str| {
            let rec = CredentialRecord {
                id: provider.into(),
                op: RecordOp::Upsert,
                sealed_token: seal(tok),
                base_url: String::new(),
                version: 1,
                authentication: authentication_for_provider(provider),
                status: CredentialStatus::Active,
                execution_classes: BTreeSet::from([ModelExecutionClass::LocalInteractive]),
            };
            s.append_record(scope, "credential", &serde_json::to_string(&rec).unwrap())
                .unwrap();
        };
        // Account links both providers; the project re-pins only openai.
        put(&mut s, ACCOUNT_SCOPE, "openai", "acct-openai");
        put(&mut s, ACCOUNT_SCOPE, "anthropic", "acct-anthropic");
        put(&mut s, &project_scope("proj-1"), "openai", "proj-openai");

        // No project → account default for both.
        let base: BTreeMap<_, _> = resolved_credential_envs(&s, KEY, None)
            .into_iter()
            .collect();
        assert_eq!(
            base.get("OPENAI_API_KEY").map(String::as_str),
            Some("acct-openai")
        );
        assert_eq!(
            base.get("ANTHROPIC_API_KEY").map(String::as_str),
            Some("acct-anthropic")
        );

        // In proj-1: openai is overridden, anthropic inherited from the account.
        let scoped: BTreeMap<_, _> = resolved_credential_envs(&s, KEY, Some("proj-1"))
            .into_iter()
            .collect();
        assert_eq!(
            scoped.get("OPENAI_API_KEY").map(String::as_str),
            Some("proj-openai")
        );
        assert_eq!(
            scoped.get("ANTHROPIC_API_KEY").map(String::as_str),
            Some("acct-anthropic")
        );

        // A project with no pin resolves exactly to the account default.
        let other = resolved_credential_envs(&s, KEY, Some("proj-other"));
        assert_eq!(other, resolved_credential_envs(&s, KEY, None));
    }

    #[test]
    fn resolved_credential_capability_is_exact_reference_bound_and_redacted() {
        let capability = resolved_credential_capability(
            "gaugedesk:credential:account:openai".to_owned(),
            "sk-secret-value".to_owned(),
            None,
        );
        assert!(capability
            .resolve("gaugedesk:credential:project:other:openai")
            .is_err());
        let material = capability
            .resolve("gaugedesk:credential:account:openai")
            .expect("exact ref resolves");
        assert_eq!(material.secret(), "sk-secret-value");
        assert!(!format!("{capability:?}").contains("sk-secret-value"));
        assert!(!format!("{material:?}").contains("sk-secret-value"));
    }
}
