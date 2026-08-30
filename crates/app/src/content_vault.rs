//! Content-only, per-unit at-rest encryption + crypto-erasure (`SECAUD-9` / `SECAUD-6`).
//!
//! A [`ContentVault`] implements the store's [`ContentCodec`] seam to transparently
//! encrypt **content** record kinds (e.g. `transcript` — the client's conversation) at
//! rest, under a **per-scope** data key, leaving lifecycle/metadata records plaintext.
//! Each scope (engagement) gets its own DEK, persisted only **wrapped by a KEK**
//! (`SEC-4` [`KeyWrap`] — `LoopbackKeyWrap` in dev, the Azure Key Vault adapter in
//! prod). Two properties fall out:
//!
//! - **Encryption at rest** (`SECAUD-9`): the payload column holds ciphertext; a disk /
//!   store compromise yields only ciphertext + a KMS-wrapped DEK.
//! - **Crypto-erasure** (`SECAUD-6`, GDPR right-to-erasure): [`crypto_erase`] destroys a
//!   scope's wrapped DEK, so that scope's retained ciphertext is permanently
//!   unrecoverable — the content is gone, the append-only log (`INV-6`) untouched.
//!
//! The keyring is **file-backed, outside the event store** (one wrapped-DEK file per
//! scope), so it never re-enters the store while the store is mid-write, and a key can
//! be deleted (erasure) without touching the immutable log.

use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, Write};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use ring::rand::{SecureRandom, SystemRandom};

use gaugedesk_store::{ContentCodec, Store};

use crate::at_rest::{Encryptor, KeyWrap, LocalAeadEncryptor};
use crate::workbench_state::Workbench;

/// Marks an encrypted payload so [`ContentVault::decode`] can tell ciphertext from a
/// legacy/plaintext row (mixed logs and the pre-encryption history stay readable).
const MARKER: &str = "gwenc:1:";

/// The content record kinds sealed at rest by default.
///
/// The set covers the durable conversation transcript plus every record kind that
/// carries personal data an erasure request must be able to destroy (SOC 2 finding
/// 2.6, authorized by DR-0086). `audit` is deliberately **excluded**: it lives on a
/// separate store, is hash-chained for keyless external verification, and holds
/// pseudonymous references rather than the PII erasure targets. Library/lifecycle
/// metadata kinds (`chat`, `project`, `target`, `engagement`, …) are also left
/// cleartext for a follow-on, so their titles are the remaining residual.
pub const DEFAULT_CONTENT_KINDS: &[&str] = &[
    // The durable conversation transcript (the client's own words).
    "transcript",
    // Org-scope personal-data records (SOC 2 finding 2.6 / DR-0086).
    "membership",
    "org",
    "billing",
    "sso",
    "scim_token",
    "member_grant",
    "group_mapping",
    "policy",
    "placement_policy",
    "security",
    "software_policy",
    "archetype_approval",
    // Account-scope personal-data records.
    "setting",
    "device",
    "home",
    "home_route",
    "credential",
];

pub(crate) fn configured_content_vault(
    root: &Path,
    content_keywrap: impl Fn(&Path) -> std::io::Result<Box<dyn KeyWrap>>,
) -> std::io::Result<Option<Arc<ContentVault>>> {
    // Fail-closed posture (SOC 2 finding 2.6 / DR-0086): content encryption is ON by
    // default so a deployment that forgets a flag still seals personal data at rest.
    // It is disabled only by an explicit opt-out. The local KEK works with no config,
    // so defaulting on is safe on the desktop path; the hosted path supplies its own
    // keywrap closure and is likewise unaffected by the default.
    if content_encryption_opted_out() {
        return Ok(None);
    }
    // KEK selection is creds-only: a hosted deployment sets GAUGEDESK_CONTENT_KEK_ID
    // + the AZURE_* Crypto User SP creds to use the KMS; dev uses the local KEK.
    //
    // The erasure ledger (SOC 2 finding 4.7 / DR-0086) is selected by config, like the
    // KEK above: a hosted deployment sets GAUGEDESK_ERASURE_LEDGER_ORIGIN to record
    // erasures OUT-OF-BAND through the edge Worker's object-locked R2 store, so the
    // record cannot be rolled back by a data-disk restore; a desktop / self-hosted
    // deployment sets nothing and uses the co-located local file.
    Ok(Some(Arc::new(
        ContentVault::new(root.join("content-keys"), content_keywrap(root)?)
            .with_ledger(configured_erasure_ledger(root)),
    )))
}

/// Select the erasure-ledger backend (SOC 2 finding 4.7 / DR-0086). Creds-driven, like
/// the KEK selection above. `GAUGEDESK_ERASURE_LEDGER_ORIGIN` (with a **required**
/// `GAUGEDESK_ERASURE_LEDGER_TOKEN`) records erasures out-of-band through the edge
/// Worker's object-locked R2 store, so a whole-disk restore of the Hub cannot un-erase;
/// with neither set, a desktop / self-hosted deployment uses the co-located local file.
/// A hosted deployment (web-account mode) that leaves the origin unset is the 4.7 gap and
/// is warned about loudly rather than silently accepted.
fn configured_erasure_ledger(root: &Path) -> Box<dyn ErasureLedger> {
    let local = || LocalFileErasureLedger::new(root.join("content-keys").join("erased.ledger"));
    let nonempty = |suffix: &str| {
        gaugedesk_env::var(suffix)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let Some(origin) = nonempty("ERASURE_LEDGER_ORIGIN") else {
        if crate::workbench_auth::web_account_mode() {
            tracing::warn!(
                "content-vault: hosted deployment has no out-of-band erasure ledger \
                 (GAUGEDESK_ERASURE_LEDGER_ORIGIN unset); an erasure would not survive a \
                 data-disk restore (finding 4.7)"
            );
        }
        return Box::new(local());
    };
    match nonempty("ERASURE_LEDGER_TOKEN") {
        Some(token) => Box::new(EdgeErasureLedger::new(&origin, token, local())),
        None => {
            tracing::error!(
                "content-vault: GAUGEDESK_ERASURE_LEDGER_ORIGIN is set but \
                 GAUGEDESK_ERASURE_LEDGER_TOKEN is missing; falling back to the local ledger, \
                 which does NOT survive a data-disk restore (finding 4.7)"
            );
            Box::new(local())
        }
    }
}

/// Whether an operator has explicitly opted out of at-rest content encryption.
/// Any other value (including the flag being unset) keeps encryption on.
fn content_encryption_opted_out() -> bool {
    matches!(
        gaugedesk_env::var("ENCRYPT_CONTENT")
            .as_deref()
            .map(str::trim),
        Some("0") | Some("false") | Some("off") | Some("no")
    )
}

pub(crate) fn open_startup_store(
    root: &Path,
    content_keywrap: impl Fn(&Path) -> std::io::Result<Box<dyn KeyWrap>>,
) -> std::io::Result<(Store, Option<Arc<ContentVault>>)> {
    let mut store =
        Store::open(root.join("gaugewright.db").to_str().expect("utf8 path")).map_err(crate::io)?;
    let content_vault = configured_content_vault(root, content_keywrap)?;
    if let Some(vault) = &content_vault {
        // Re-erase-on-open sweep (SOC 2 finding 4.7 / DR-0086): this runs on every
        // store open, which includes the open immediately after a backup restore and
        // before anything serves. A restore can resurrect an erased scope's wrapped-DEK
        // file (it lives on the whole-disk-backed data root) which the always-available
        // KEK would then unwrap — silently undoing an erasure. The sweep reads the
        // append-only ledger and re-deletes any wrapped-DEK file recorded as erased, so
        // a restore self-heals. Best-effort: a ledger read error must never abort
        // startup (it is logged), so the store still opens.
        let reerased = vault.reerase_recorded();
        if reerased > 0 {
            tracing::warn!(
                reerased,
                "content-vault: re-applied crypto-erasure for {reerased} recorded scope(s) on open (finding 4.7)"
            );
        }
        store = store.with_codec(vault.clone());
    }
    Ok((store, content_vault))
}

impl Workbench {
    pub(crate) fn apply_startup_content_vault(&mut self, content_vault: Option<Arc<ContentVault>>) {
        self.content_vault = content_vault;
    }
}

/// Per-scope content encryption + crypto-erasure. Held by the [`Store`](gaugedesk_store::Store)
/// as its [`ContentCodec`]; `Send + Sync` so it can ride the shared workbench.
pub struct ContentVault {
    /// Directory holding the per-scope wrapped-DEK files.
    dir: PathBuf,
    /// The KEK seam (`SEC-4`) wrapping each per-scope DEK.
    wrap: Box<dyn KeyWrap>,
    /// The record kinds treated as content (everything else passes through plaintext).
    kinds: BTreeSet<String>,
    /// In-memory DEK cache (scope → 32-byte key), so the KEK is touched once per scope.
    cache: Mutex<HashMap<String, [u8; 32]>>,
    /// Append-only record of crypto-erased key-ids (SOC 2 finding 4.7 / DR-0086), so an
    /// erasure survives a backup restore that resurrects the wrapped-DEK file. `None`
    /// means the vault keeps no durable erasure record (erasure is then only as durable
    /// as file deletion — undone by a restore); production always injects a backend.
    ledger: Option<Box<dyn ErasureLedger>>,
}

impl ContentVault {
    /// A vault rooted at `dir` (the wrapped-DEK keyring), wrapping DEKs with `wrap`,
    /// encrypting [`DEFAULT_CONTENT_KINDS`].
    pub fn new(dir: impl Into<PathBuf>, wrap: Box<dyn KeyWrap>) -> Self {
        Self {
            dir: dir.into(),
            wrap,
            kinds: DEFAULT_CONTENT_KINDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            cache: Mutex::new(HashMap::new()),
            ledger: None,
        }
    }

    /// Override which record kinds are treated as content (builder).
    pub fn with_kinds<I, S>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.kinds = kinds.into_iter().map(Into::into).collect();
        self
    }

    /// Inject the erasure ledger backend (builder, SOC 2 finding 4.7 / DR-0086).
    ///
    /// The desktop / self-hosted path wires a [`LocalFileErasureLedger`] co-located with
    /// the keyring; a HOSTED deployment must inject an OUT-OF-BAND backend (R2
    /// object-lock) here so the record of an erasure is not rolled back by a data-disk
    /// restore. Without a ledger, [`crypto_erase`](Self::crypto_erase) still deletes the
    /// key but [`reerase_recorded`](Self::reerase_recorded) has nothing to replay, so
    /// the erasure would not survive a restore.
    pub fn with_ledger(mut self, ledger: Box<dyn ErasureLedger>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    fn key_path(&self, scope: &str) -> PathBuf {
        self.dir
            .join(format!("{}.dek", crate::org::sha256_hex(scope)))
    }

    /// Seal private account-custody material under a per-account DEK whose only
    /// durable form is wrapped by this vault's KEK/KMS boundary.
    pub(crate) fn seal_private(&self, scope: &str, plaintext: &str) -> Option<String> {
        let dek = self.dek_for(scope, true)?;
        LocalAeadEncryptor::new(dek)
            .encrypt(plaintext.as_bytes())
            .ok()
            .map(hex::encode)
    }

    /// Open private account-custody material. A missing/erased/wrong DEK fails
    /// closed without distinguishing the cause.
    pub(crate) fn open_private(&self, scope: &str, sealed: &str) -> Option<String> {
        let dek = self.dek_for(scope, false)?;
        let ciphertext = hex::decode(sealed).ok()?;
        let plaintext = LocalAeadEncryptor::new(dek).decrypt(&ciphertext).ok()?;
        String::from_utf8(plaintext).ok()
    }

    /// The per-scope DEK. `create` mints + persists one on a miss (the write path);
    /// the read path passes `false`, so a scope whose key file is gone (crypto-erased)
    /// resolves to `None` — its content is unrecoverable.
    fn dek_for(&self, scope: &str, create: bool) -> Option<[u8; 32]> {
        if let Some(dek) = self.cache.lock().unwrap().get(scope) {
            return Some(*dek);
        }
        let path = self.key_path(scope);
        if let Ok(wrapped) = std::fs::read(&path) {
            if let Ok(dek) = self.wrap.unwrap(&wrapped) {
                self.cache.lock().unwrap().insert(scope.to_string(), dek);
                return Some(dek);
            }
            return None; // a key file we cannot unwrap is unrecoverable, fail-closed
        }
        if !create {
            return None;
        }
        // Mint a fresh DEK, persist it wrapped, cache it.
        let mut dek = [0u8; 32];
        SystemRandom::new().fill(&mut dek).ok()?;
        let wrapped = self.wrap.wrap(&dek).ok()?;
        std::fs::create_dir_all(&self.dir).ok()?;
        std::fs::write(&path, &wrapped).ok()?;
        self.cache.lock().unwrap().insert(scope.to_string(), dek);
        Some(dek)
    }

    /// **Crypto-erase** a scope (`SECAUD-6`): destroy its wrapped DEK (file + cache).
    /// Its retained ciphertext can never be opened again. Idempotent; returns whether a
    /// key was present.
    ///
    /// Besides deleting the wrapped-DEK file, this records the scope's key-id in the
    /// append-only erasure ledger (SOC 2 finding 4.7 / DR-0086) — even when the file was
    /// already gone — so the erasure can be re-applied by
    /// [`reerase_recorded`](Self::reerase_recorded) after a backup restore resurrects
    /// the file. The recorded id is the key-file stem (`sha256_hex(scope)`). The bool
    /// return still means only "a key file was present", unchanged by the ledger write;
    /// a ledger failure is logged but does not change the return.
    pub fn crypto_erase(&self, scope: &str) -> bool {
        self.cache.lock().unwrap().remove(scope);
        let key_id = crate::org::sha256_hex(scope);
        if let Some(ledger) = &self.ledger {
            if let Err(err) = ledger.record(&key_id) {
                tracing::warn!(
                    %err,
                    "content-vault: failed to record crypto-erasure in ledger (finding 4.7); \
                     erasure will not survive a restore for this scope"
                );
            }
        }
        std::fs::remove_file(self.key_path(scope)).is_ok()
    }

    /// **Re-erase-on-open sweep** (SOC 2 finding 4.7 / DR-0086): re-apply every recorded
    /// crypto-erasure whose wrapped-DEK file is present again — e.g. because a backup
    /// restore resurrected it. Reads the append-only ledger, and for each recorded
    /// key-id deletes `{dir}/{key_id}.dek` if present, also dropping any matching scope
    /// from the in-memory cache. Returns the number of files actually re-erased.
    ///
    /// Best-effort by design: a missing/unreadable ledger, or an already-absent file, is
    /// not an error — a ledger read failure yields `0` after logging, so a caller running
    /// this at store open never aborts startup. Because the ledger records key-ids (the
    /// file stem `sha256_hex(scope)`) rather than raw scopes, the cache is cleared by
    /// matching each live scope's hash against the recorded set.
    pub fn reerase_recorded(&self) -> usize {
        let Some(ledger) = &self.ledger else {
            return 0;
        };
        let recorded = match ledger.recorded() {
            Ok(ids) => ids,
            Err(err) => {
                tracing::warn!(
                    %err,
                    "content-vault: could not read erasure ledger for re-erase sweep \
                     (finding 4.7); skipping"
                );
                return 0;
            }
        };
        let recorded: BTreeSet<String> = recorded.into_iter().collect();
        let mut count = 0;
        for key_id in &recorded {
            let path = self.dir.join(format!("{key_id}.dek"));
            if std::fs::remove_file(&path).is_ok() {
                count += 1;
            }
        }
        // Drop any resurrected DEK from the in-memory cache so a cached key cannot keep
        // opening content the ledger says is erased.
        if !recorded.is_empty() {
            self.cache
                .lock()
                .unwrap()
                .retain(|scope, _| !recorded.contains(&crate::org::sha256_hex(scope)));
        }
        count
    }

    fn is_content(&self, kind: &str) -> bool {
        self.kinds.contains(kind)
    }
}

impl Workbench {
    /// Envelope-seal a custodied account root under its own wrapped DEK.
    pub fn seal_custodied_account_root(&self, account_id: &str, seed: &str) -> Option<String> {
        self.content_vault
            .as_ref()?
            .seal_private(&crate::account::account_scope(account_id), seed)
    }

    /// Open a custodied account root inside the private Hub boundary.
    pub fn unseal_custodied_account_root(&self, account_id: &str, sealed: &str) -> Option<String> {
        self.content_vault
            .as_ref()?
            .open_private(&crate::account::account_scope(account_id), sealed)
    }
}

impl ContentCodec for ContentVault {
    fn encode(&self, scope: &str, kind: &str, payload: &str) -> Result<String, String> {
        if !self.is_content(kind) {
            return Ok(payload.to_string());
        }
        match self.dek_for(scope, true).and_then(|dek| {
            LocalAeadEncryptor::new(dek)
                .encrypt(payload.as_bytes())
                .ok()
        }) {
            Some(ct) => Ok(format!("{MARKER}{}", hex::encode(ct))),
            None => Err(format!(
                "content encryption unavailable for scope {scope}; append refused (SECAUD-9)"
            )),
        }
    }

    fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String> {
        if !self.is_content(kind) {
            return Some(payload.to_string());
        }
        let Some(hexct) = payload.strip_prefix(MARKER) else {
            return Some(payload.to_string()); // legacy / pre-encryption plaintext
        };
        if hexct == "UNENCRYPTABLE" {
            return None;
        }
        let dek = self.dek_for(scope, false)?; // erased / missing key ⇒ unrecoverable
        let ct = hex::decode(hexct).ok()?;
        let plain = LocalAeadEncryptor::new(dek).decrypt(&ct).ok()?;
        String::from_utf8(plain).ok()
    }
}

/// The durable record of crypto-erasures (SOC 2 finding 4.7 / DR-0086).
///
/// An erasure destroys a scope's wrapped-DEK file, but that file lives on the
/// whole-disk-backed data root, so a backup restore can resurrect it — and the
/// always-available KEK would then unwrap it, silently undoing the erasure. This seam
/// records each erasure out of band from those key files, so a re-erase-on-open sweep
/// ([`ContentVault::reerase_recorded`]) can replay it and make the erasure self-heal
/// after a restore.
///
/// Entries are **key-ids** — the wrapped-DEK file stem `sha256_hex(scope)` — so the sweep
/// maps a recorded id straight to `{key_id}.dek`. The store never learns the raw scope
/// from the ledger. `Send + Sync` so the vault can ride the shared workbench.
///
/// The production durability of this record comes from an OUT-OF-BAND backend (R2
/// object-lock) that a data-disk restore cannot roll back; wiring that backend is an ops
/// step, out of scope here. This module ships the seam, a local file backend for the
/// desktop / self-hosted path, and the re-erase-on-open logic that consumes it.
pub trait ErasureLedger: Send + Sync {
    /// Append `key_id` to the durable record. Idempotent at the sweep level: recording
    /// the same id twice is harmless (the sweep dedups on read), and callers record even
    /// when the key file was already gone.
    fn record(&self, key_id: &str) -> std::io::Result<()>;

    /// Every recorded key-id (deduplicated). Order is not significant.
    fn recorded(&self) -> std::io::Result<Vec<String>>;
}

/// A [`ErasureLedger`] backed by an append-only file, one key-id per line.
///
/// **Durability boundary (SOC 2 finding 4.7 / DR-0086).** This file is CO-LOCATED with
/// the wrapped-DEK keyring on the data root, so it is durable **only for the desktop /
/// self-hosted path**. On a HOSTED deployment a whole-disk backup restore that
/// resurrects an erased scope's DEK file would roll this ledger back in the same motion,
/// leaving nothing for the sweep to replay. A hosted deployment MUST therefore inject an
/// OUT-OF-BAND backend (R2 object-lock) via [`ContentVault::with_ledger`] so the record
/// of an erasure cannot be undone by a data-disk restore. That injection is the ops
/// step; it is not built here.
pub struct LocalFileErasureLedger {
    path: PathBuf,
}

impl LocalFileErasureLedger {
    /// A ledger appending to `path` (created, with its parent dir, on first record).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ErasureLedger for LocalFileErasureLedger {
    fn record(&self, key_id: &str) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{key_id}")?;
        f.flush()
    }

    fn recorded(&self) -> std::io::Result<Vec<String>> {
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            // No ledger yet ⇒ nothing recorded (not an error).
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };
        let mut seen = BTreeSet::new();
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;
            let id = line.trim();
            if !id.is_empty() {
                seen.insert(id.to_string());
            }
        }
        Ok(seen.into_iter().collect())
    }
}

/// An [`ErasureLedger`] that records out-of-band, through the edge Worker's
/// object-locked R2 store (SOC 2 finding 4.7 / DR-0086), so an erasure survives a
/// whole-disk restore of the hosted Hub. It is a **composite** over a co-located
/// [`LocalFileErasureLedger`]:
///
/// - `record` writes the local queue immediately (fast, under the workbench lock),
///   then pushes to the edge on a **detached thread** — `crypto_erase` can run on a
///   runtime worker while holding the lock, so it must never block on network I/O.
///   A failed/slow push is logged; the local queue plus the open-time retry in
///   `recorded` backstop it.
/// - `recorded` (open-time sweep, off any lock) fetches the edge list — the
///   restore-proof source of truth — retries pushing any local-only id, and returns
///   the **union** so the sweep re-erases everything either side knows about. If the
///   edge is unreachable at open it falls back to the local queue (the residual gap:
///   a disk restore *and* an unreachable edge at that boot).
///
/// The ledger transmits only opaque key-ids (`sha256_hex(scope)`), never a raw scope.
pub struct EdgeErasureLedger {
    url: String,
    token: String,
    local: LocalFileErasureLedger,
}

impl EdgeErasureLedger {
    /// `origin` is the edge Worker origin (e.g. `https://edge.gaugewright.com`); the
    /// route path is appended. `local` is the co-located write-through queue.
    pub fn new(origin: &str, token: String, local: LocalFileErasureLedger) -> Self {
        Self {
            url: format!("{}/internal/erasure-ledger", origin.trim_end_matches('/')),
            token,
            local,
        }
    }

    fn auth(&self) -> Vec<(String, String)> {
        vec![(
            "Authorization".to_string(),
            format!("Bearer {}", self.token),
        )]
    }

    /// POST one key-id to the edge ledger. Blocking; callers that hold a lock run it
    /// off-thread.
    fn push(url: &str, auth: &[(String, String)], key_id: &str) -> Result<(), String> {
        let body = serde_json::json!({ "key_id": key_id }).to_string();
        let (status, resp) =
            crate::net_http::HttpClient::new().post_json_headers(url, auth, &body)?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(format!("edge erasure-ledger record HTTP {status}: {resp}"))
        }
    }

    fn fetch(&self) -> Result<Vec<String>, String> {
        let (status, resp) =
            crate::net_http::HttpClient::new().get_string_headers(&self.url, &self.auth())?;
        if !(200..300).contains(&status) {
            return Err(format!("edge erasure-ledger list HTTP {status}: {resp}"));
        }
        let parsed: serde_json::Value =
            serde_json::from_str(&resp).map_err(|e| format!("parse: {e}"))?;
        let ids = parsed
            .get("key_ids")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "edge erasure-ledger response missing key_ids".to_string())?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        Ok(ids)
    }
}

impl ErasureLedger for EdgeErasureLedger {
    fn record(&self, key_id: &str) -> std::io::Result<()> {
        // Local queue first: immediate, and durable enough to retry from on the next
        // open even if the edge push below never lands.
        self.local.record(key_id)?;
        let (url, auth, key_id) = (self.url.clone(), self.auth(), key_id.to_string());
        std::thread::spawn(move || {
            if let Err(err) = Self::push(&url, &auth, &key_id) {
                tracing::warn!(
                    %err,
                    "content-vault: out-of-band erasure record failed; queued locally, \
                     will retry on next open (finding 4.7)"
                );
            }
        });
        Ok(())
    }

    fn recorded(&self) -> std::io::Result<Vec<String>> {
        let local = self.local.recorded()?;
        match self.fetch() {
            Ok(edge) => {
                let auth = self.auth();
                let edge_set: BTreeSet<&String> = edge.iter().collect();
                // Retry the queue: push any locally-recorded id the edge has not got.
                for id in &local {
                    if !edge_set.contains(id) {
                        let _ = Self::push(&self.url, &auth, id);
                    }
                }
                let mut all: BTreeSet<String> = edge.into_iter().collect();
                all.extend(local);
                Ok(all.into_iter().collect())
            }
            Err(err) => {
                tracing::warn!(
                    %err,
                    "content-vault: out-of-band erasure ledger unreachable on open; \
                     re-erasing from local records only (finding 4.7)"
                );
                Ok(local)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::at_rest::LoopbackKeyWrap;

    fn vault(dir: &std::path::Path) -> ContentVault {
        ContentVault::new(dir, Box::new(LoopbackKeyWrap::new([7u8; 32])))
    }

    /// A vault whose keyring is `dir` and whose erasure ledger is co-located under it,
    /// mirroring the desktop wiring in `configured_content_vault`.
    fn vault_with_ledger(dir: &std::path::Path) -> ContentVault {
        ContentVault::new(dir, Box::new(LoopbackKeyWrap::new([7u8; 32]))).with_ledger(Box::new(
            LocalFileErasureLedger::new(dir.join("erased.ledger")),
        ))
    }

    #[test]
    fn content_is_encrypted_at_rest_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let stored = v
            .encode("eng-1", "transcript", "a private question")
            .unwrap();
        // The stored form is ciphertext, not the plaintext.
        assert!(stored.starts_with(MARKER));
        assert!(!stored.contains("a private question"));
        // ...and decodes back.
        assert_eq!(
            v.decode("eng-1", "transcript", &stored).as_deref(),
            Some("a private question")
        );
    }

    #[test]
    fn non_content_kinds_pass_through() {
        // `audit` is deliberately excluded from the sealed set (it verifies without
        // keys), so it must round-trip untouched — cleartext in, cleartext out.
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        assert_eq!(
            v.encode("eng-1", "audit", "advanced by rule R7").unwrap(),
            "advanced by rule R7"
        );
        assert_eq!(
            v.decode("eng-1", "audit", "advanced by rule R7").as_deref(),
            Some("advanced by rule R7")
        );
    }

    #[test]
    fn every_pii_kind_is_treated_as_content() {
        // Guards SOC 2 finding 2.6 (DR-0086): the whole personal-data set is sealed.
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        for kind in [
            "transcript",
            "membership",
            "org",
            "billing",
            "sso",
            "scim_token",
            "member_grant",
            "group_mapping",
            "policy",
            "placement_policy",
            "security",
            "software_policy",
            "archetype_approval",
            "setting",
            "device",
            "home",
            "home_route",
            "credential",
        ] {
            assert!(v.is_content(kind), "{kind} must be sealed at rest");
        }
        // Excluded kinds stay cleartext.
        for kind in ["audit", "chat", "project", "target", "engagement"] {
            assert!(!v.is_content(kind), "{kind} must remain cleartext");
        }
    }

    #[test]
    fn membership_is_sealed_through_the_store_and_erasable_audit_stays_cleartext() {
        // The full seam as the app runs it: a Store with the vault as its codec.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("s.db");
        let db_path = db.to_str().unwrap();
        let vault = Arc::new(vault(&dir.path().join("content-keys")));
        let mut store = Store::open(db_path).unwrap().with_codec(vault.clone());

        store
            .append_record("org", "membership", "role=admin;email=alice@example.com")
            .unwrap();
        // (d) an excluded `audit` record is written cleartext.
        store
            .append_record("eng-1", "audit", "advanced by rule R7")
            .unwrap();

        // (a) the raw stored membership payload is ciphertext (MARKER-prefixed), not
        //     the plaintext — read it back through a codec-less store to see the row.
        let raw = Store::open(db_path).unwrap();
        let stored_membership = raw.records("org", "membership").unwrap();
        assert!(
            stored_membership[0].starts_with(MARKER),
            "membership is sealed at rest: {}",
            stored_membership[0]
        );
        assert!(!stored_membership[0].contains("alice@example.com"));
        // (d, cont.) the audit row is stored verbatim, no marker.
        let stored_audit = raw.records("eng-1", "audit").unwrap();
        assert_eq!(stored_audit, vec!["advanced by rule R7".to_string()]);

        // (b) it round-trips: reading through the vault's decode seam yields plaintext.
        assert_eq!(
            store.records("org", "membership").unwrap(),
            vec!["role=admin;email=alice@example.com".to_string()]
        );

        // (c) after crypto-erasing the scope, the record is unreadable — the decode
        //     seam drops the now-unrecoverable row.
        assert!(vault.crypto_erase("org"), "the scope key existed");
        assert!(
            store.records("org", "membership").unwrap().is_empty(),
            "crypto-erased membership is gone from every reader"
        );
        // The audit row, on a different scope with no key, is untouched by erasure.
        assert_eq!(
            store.records("eng-1", "audit").unwrap(),
            vec!["advanced by rule R7".to_string()]
        );
    }

    #[test]
    fn crypto_erase_makes_a_scopes_content_unrecoverable_others_intact() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let a = v.encode("eng-a", "transcript", "alice data").unwrap();
        let b = v.encode("eng-b", "transcript", "bob data").unwrap();
        assert!(v.decode("eng-a", "transcript", &a).is_some());

        assert!(v.crypto_erase("eng-a"), "the key existed and is destroyed");
        // eng-a's ciphertext can never be opened again...
        assert_eq!(v.decode("eng-a", "transcript", &a), None);
        // ...while eng-b (a different unit) is untouched.
        assert_eq!(
            v.decode("eng-b", "transcript", &b).as_deref(),
            Some("bob data")
        );
        // Idempotent.
        assert!(!v.crypto_erase("eng-a"));
    }

    #[test]
    fn legacy_plaintext_rows_still_read() {
        // A row written before encryption (no marker) is returned as-is.
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        assert_eq!(
            v.decode("eng-1", "transcript", "old plaintext line")
                .as_deref(),
            Some("old plaintext line")
        );
    }

    #[test]
    fn crypto_erase_records_key_id_in_ledger_and_deletes_the_key() {
        // (a) SOC 2 finding 4.7: erasing a scope both destroys its wrapped-DEK file and
        //     records the scope's key-id in the append-only ledger.
        let dir = tempfile::tempdir().unwrap();
        let v = vault_with_ledger(dir.path());
        v.encode("eng-1", "transcript", "a private question")
            .unwrap();

        let key_id = crate::org::sha256_hex("eng-1");
        assert!(v.key_path("eng-1").exists(), "the key file was minted");

        assert!(v.crypto_erase("eng-1"), "the key existed and is destroyed");
        // The wrapped-DEK file is gone...
        assert!(!v.key_path("eng-1").exists(), "the key file is destroyed");
        // ...and the key-id is recorded in the ledger.
        let ledger = LocalFileErasureLedger::new(dir.path().join("erased.ledger"));
        assert_eq!(ledger.recorded().unwrap(), vec![key_id]);
    }

    #[test]
    fn reerase_recorded_survives_a_backup_restore() {
        // (b) SOC 2 finding 4.7: the re-erase-on-open sweep undoes a restore that
        //     resurrected an erased scope's wrapped-DEK file.
        let dir = tempfile::tempdir().unwrap();
        let v = vault_with_ledger(dir.path());
        let ct = v
            .encode("eng-1", "transcript", "a private question")
            .unwrap();

        // Capture the wrapped-DEK bytes as a backup would, then crypto-erase.
        let key_bytes = std::fs::read(v.key_path("eng-1")).unwrap();
        assert!(v.crypto_erase("eng-1"));
        assert_eq!(v.decode("eng-1", "transcript", &ct), None);

        // SIMULATE A RESTORE: a backup restore resurrects the wrapped-DEK file on the
        // data root. A fresh vault (no cached DEK) would now unwrap it with the ever-
        // present KEK — decode succeeds, i.e. the erasure has been silently undone.
        std::fs::write(v.key_path("eng-1"), &key_bytes).unwrap();
        let restored = vault_with_ledger(dir.path());
        assert_eq!(
            restored.decode("eng-1", "transcript", &ct).as_deref(),
            Some("a private question"),
            "a restore alone resurrects the key — this is exactly what the sweep must fix"
        );

        // The re-erase-on-open sweep re-applies the recorded erasure: the file is
        // deleted again and the content is unrecoverable once more.
        assert_eq!(
            restored.reerase_recorded(),
            1,
            "one recorded scope re-erased"
        );
        assert!(
            !restored.key_path("eng-1").exists(),
            "the resurrected key file is deleted again"
        );
        assert_eq!(
            restored.decode("eng-1", "transcript", &ct),
            None,
            "content is unrecoverable after the sweep"
        );
    }

    #[test]
    fn reerase_recorded_is_a_noop_for_scopes_not_in_the_ledger() {
        // (c) SOC 2 finding 4.7: a live scope's key survives a sweep — only recorded
        //     erasures are replayed.
        let dir = tempfile::tempdir().unwrap();
        let v = vault_with_ledger(dir.path());
        let a = v.encode("eng-a", "transcript", "alice data").unwrap();
        let b = v.encode("eng-b", "transcript", "bob data").unwrap();

        // Erase only eng-a; eng-b is never recorded.
        assert!(v.crypto_erase("eng-a"));

        // A sweep re-erases eng-a (already gone ⇒ nothing to re-delete) but must leave
        // the live eng-b key untouched.
        assert_eq!(v.reerase_recorded(), 0, "nothing present to re-erase");
        assert!(
            v.key_path("eng-b").exists(),
            "the live key survives the sweep"
        );
        assert_eq!(
            v.decode("eng-b", "transcript", &b).as_deref(),
            Some("bob data"),
            "the live scope still decodes after a sweep"
        );
        assert_eq!(
            v.decode("eng-a", "transcript", &a),
            None,
            "eng-a stays erased"
        );
    }

    #[test]
    fn edge_ledger_keeps_a_local_queue_and_falls_back_when_the_edge_is_unreachable() {
        // SOC 2 finding 4.7: the out-of-band ledger is a composite. `record` must write
        // the local queue immediately (so nothing is lost when the edge push fails), and
        // `recorded` must fall back to that queue when the edge is unreachable so the
        // open-time sweep still runs.
        let dir = tempfile::tempdir().unwrap();
        let local = LocalFileErasureLedger::new(dir.path().join("erased.ledger"));
        // Nothing is listening here, so both the detached push and the `recorded` fetch
        // fail fast (connection refused) — exercising the local-only fallback path.
        let ledger = EdgeErasureLedger::new("http://127.0.0.1:1", "test-token".into(), local);
        let key_id = "a".repeat(64);

        ledger.record(&key_id).unwrap();
        // The local queue holds it even though the edge is down.
        assert_eq!(
            LocalFileErasureLedger::new(dir.path().join("erased.ledger"))
                .recorded()
                .unwrap(),
            vec![key_id.clone()],
        );
        // `recorded` cannot reach the edge, so it returns the local queue rather than
        // erroring — the sweep re-erases what it can.
        assert_eq!(ledger.recorded().unwrap(), vec![key_id]);
    }

    #[test]
    fn keys_persist_across_vault_instances() {
        // A fresh vault over the same keyring dir decrypts what the first wrote
        // (keys survive a restart — the wrapped DEK is on disk).
        let dir = tempfile::tempdir().unwrap();
        let stored = vault(dir.path())
            .encode("eng-1", "transcript", "persisted")
            .unwrap();
        let reopened = vault(dir.path());
        assert_eq!(
            reopened.decode("eng-1", "transcript", &stored).as_deref(),
            Some("persisted")
        );
    }
}
