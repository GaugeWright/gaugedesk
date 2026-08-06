//! Per-actor audit timeline (M3 B14 / `AUD-1`,`AUD-2`). A governance-relevant
//! action (role change, member (de)provision, SSO/SCIM/policy config) appends an
//! immutable [`AuditEntry`] to a reserved `audit` scope, attributed to the
//! authenticated actor ([`Workbench::actor`](crate::Workbench::actor), `INV-21`).
//!
//! The timeline is the append-only event stream **pivoted by actor** (the ADR 0032
//! step-5 audit, now with the identity substrate as its concrete consumer): ordering
//! is the log's position order for readability, never an implied global total order
//! (`INV-7`). Entries carry **references** (actor / action / target id) — never
//! protected payloads (`INV-10`), so the timeline can be read and exported without
//! leaking content.

use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use gaugedesk_core::ids::{AuthorityId, PublicKey};
use gaugedesk_core::signature::{verify_signature, Signature};
use gaugedesk_store::{AdmitError, ChainedRecordFact, Store};

use crate::content_vault;
use crate::key_store::{FileKeyStore, KeyStore};
use crate::Workbench;

/// The reserved store scope holding the append-only audit timeline.
pub const AUDIT_SCOPE: &str = "audit";

/// The reserved scope holding the signed head checkpoints (`SECAUD-2`).
pub const AUDIT_CHECKPOINT_SCOPE: &str = "audit_checkpoint";

/// Resolve the audit chain belonging to one organization store scope. The default
/// singleton retains the historical scope; named hosted tenants receive disjoint
/// chains so admission to one tenant can never reveal another tenant's metadata.
pub fn scope_for(store_scope: &str) -> String {
    if store_scope == crate::org::ORG_SCOPE {
        AUDIT_SCOPE.to_string()
    } else {
        format!("{AUDIT_SCOPE}::{store_scope}")
    }
}

fn checkpoint_scope_for(store_scope: &str) -> String {
    if store_scope == crate::org::ORG_SCOPE {
        AUDIT_CHECKPOINT_SCOPE.to_string()
    } else {
        format!("{AUDIT_CHECKPOINT_SCOPE}::{store_scope}")
    }
}

/// One governance action: who did it, what they did, and the affected target id.
/// No payload, ever (`INV-10`).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuditEntry {
    /// The authenticated actor (an authority id, or `"scim"`/`"anonymous"`/the local
    /// authority for the non-IdP cases).
    pub actor: String,
    /// A short action verb (e.g. `member.role`, `member.deactivate`, `sso.configure`).
    pub action: String,
    /// The affected entity id (e.g. a member id) — a reference, not a payload.
    pub target: String,
    /// Hash-chain link (`SECAUD-2`, SOC 2 CC7.2/CC7.3): the hex SHA-256 of the
    /// **previous** entry in the `audit` scope, or [`GENESIS`] for the first. Editing
    /// any entry's content changes its hash, so the *successor*'s `prev` no longer
    /// matches the recomputed head and [`verify`] returns false — an in-place rewrite
    /// of history is detectable. `#[serde(default)]` keeps pre-chain entries parseable.
    /// Modeled in `specs/models/audit-chain.qnt`.
    #[serde(default)]
    pub prev: String,
}

/// The genesis chain link: the first audit entry's [`AuditEntry::prev`].
pub const GENESIS: &str = "";

/// The hash of one entry, binding its `prev` link and content under SHA-256. The
/// encoding is length-prefixed so field boundaries are unambiguous (no value can be
/// shifted across a delimiter to forge a collision). Mirrors `hash` in
/// `specs/models/audit-chain.qnt`.
fn entry_hash(e: &AuditEntry) -> String {
    let canon = format!(
        "{}:{}|{}:{}|{}:{}|{}:{}",
        e.prev.len(),
        e.prev,
        e.actor.len(),
        e.actor,
        e.action.len(),
        e.action,
        e.target.len(),
        e.target,
    );
    crate::org::sha256_hex(&canon)
}

/// The current head hash of the `audit` chain — the hash of the last entry, or
/// [`GENESIS`] for an empty log. Anchor this externally (or sign it) to also detect
/// a tail truncation / last-entry edit, which an unanchored chain cannot self-detect
/// (the SECAUD-2 follow-on).
///
/// **Read-only inspection.** Never use this to build the next entry's link: that
/// reads the head outside the transaction that appends, and two writers observing
/// the same head both link to it, forking the chain. Use [`link`] with
/// [`Store::append_chained_record`] or [`chained`], which resolve the predecessor
/// inside the appending transaction.
pub fn head_hash(store: &Store) -> String {
    head_hash_in(store, crate::org::ORG_SCOPE)
}

pub fn head_hash_in(store: &Store, store_scope: &str) -> String {
    match list_in(store, store_scope).last() {
        Some(last) => entry_hash(last),
        None => GENESIS.to_string(),
    }
}

/// A governance-signed anchor of the chain head at a position (`SECAUD-2`). Signing
/// the head (with the governance key the verifier independently trusts) closes the
/// gap a bare hash chain leaves open: a **tail truncation** or a **last-entry edit**
/// (neither has a successor link to break). The signature also makes a forged
/// checkpoint impossible — an attacker who rewrote history cannot re-sign it.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Checkpoint {
    count: usize,
    head: String,
    authority: String,
    sig: Signature,
}

/// The bytes signed by a checkpoint: the position + the head, bound together.
fn checkpoint_msg(count: usize, head: &str) -> Vec<u8> {
    format!("{count}:{head}").into_bytes()
}

/// Sign the current chain head with the governance key and persist a checkpoint
/// (`SECAUD-2`). Called on each append, so the latest checkpoint always pins the full
/// current chain — any later edit or truncation is then detectable by [`verify`].
pub fn sign_checkpoint(store: &mut Store, signer: &dyn KeyStore, authority: &AuthorityId) {
    sign_checkpoint_in(store, crate::org::ORG_SCOPE, signer, authority);
}

pub fn sign_checkpoint_in(
    store: &mut Store,
    store_scope: &str,
    signer: &dyn KeyStore,
    authority: &AuthorityId,
) {
    let entries = list_in(store, store_scope);
    let count = entries.len();
    let head = entries
        .last()
        .map(entry_hash)
        .unwrap_or_else(|| GENESIS.to_string());
    let sig = signer
        .signing_key(authority)
        .sign(&checkpoint_msg(count, &head));
    let cp = Checkpoint {
        count,
        head,
        authority: authority.as_str().to_string(),
        sig,
    };
    let _ = store.append_record(
        &checkpoint_scope_for(store_scope),
        "checkpoint",
        &serde_json::to_string(&cp).expect("checkpoint serializes"),
    );
}

/// The most recent signed checkpoint, if any (latest-wins over the append-only scope).
fn latest_checkpoint_in(store: &Store, store_scope: &str) -> Option<Checkpoint> {
    store
        .records(&checkpoint_scope_for(store_scope), "checkpoint")
        .ok()?
        .iter()
        .filter_map(|r| serde_json::from_str(r).ok())
        .next_back()
}

/// The result of verifying the audit chain's integrity (`SECAUD-2`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditIntegrity {
    /// True iff the chain links hold **and** any signed checkpoint anchors them.
    pub ok: bool,
    /// The number of entries walked.
    pub entries: usize,
    /// The hex SHA-256 head of the chain when `ok` (empty when broken or empty log).
    pub head: String,
    /// The 0-based index of the first entry whose chain link is broken, if any.
    pub broken_at: Option<usize>,
    /// Whether a **signed checkpoint** anchors the chain (`SECAUD-2`). When true, a
    /// tail truncation / last-entry edit is also caught; when false the log is
    /// chain-only verified (no signer configured, or a pre-checkpoint log) — alert on
    /// `anchored == false` if your deployment runs signed.
    pub anchored: bool,
}

/// Walk the `audit` chain and report whether history is intact (`SECAUD-2`). Mirrors
/// `verify` in `specs/models/audit-chain.qnt`: start from [`GENESIS`], require each
/// entry's stored `prev` to equal the running head, then advance the head to the
/// entry's hash. A single in-place edit *with a successor* breaks a link.
///
/// `expected_pubkey` is the **trusted** governance public key (supplied independently
/// by the caller, never read from the checkpoint itself). When a signed checkpoint is
/// present it must verify under this key and stay consistent with the current chain —
/// catching the tail truncation / last-entry edit the bare chain cannot.
pub fn verify(store: &Store, expected_pubkey: Option<&PublicKey>) -> AuditIntegrity {
    verify_in(store, crate::org::ORG_SCOPE, expected_pubkey)
}

pub fn verify_in(
    store: &Store,
    store_scope: &str,
    expected_pubkey: Option<&PublicKey>,
) -> AuditIntegrity {
    let entries = list_in(store, store_scope);
    let mut prev = GENESIS.to_string();
    let mut broken_at = None;
    for (i, e) in entries.iter().enumerate() {
        if e.prev != prev {
            broken_at = Some(i);
            break;
        }
        prev = entry_hash(e);
    }

    // SECAUD-2: a signed checkpoint anchors the head against truncation / last-entry edits.
    let mut anchored = false;
    let mut anchor_ok = true;
    if let Some(cp) = latest_checkpoint_in(store, store_scope) {
        anchored = true;
        let sig_valid = expected_pubkey
            .map(|pk| {
                verify_signature(&checkpoint_msg(cp.count, &cp.head), &cp.sig, pk) == Ok(true)
            })
            .unwrap_or(false);
        // The chain must extend at least to the checkpointed position, and folding the
        // first `count` entries must reproduce the signed head (so an edit at/before the
        // checkpoint, or a truncation below it, is caught).
        let consistent = cp.count <= entries.len()
            && entries[..cp.count]
                .last()
                .map(entry_hash)
                .unwrap_or_else(|| GENESIS.to_string())
                == cp.head;
        anchor_ok = sig_valid && consistent;
    }

    let ok = broken_at.is_none() && (!anchored || anchor_ok);
    AuditIntegrity {
        ok,
        entries: entries.len(),
        head: if ok { prev } else { String::new() },
        broken_at,
        anchored,
    }
}

/// A streaming sink for audit entries (`AUD-4`): the seam a customer SIEM
/// (Splunk / Datadog / …) attaches behind. The durable timeline in the `audit`
/// scope is the source of truth; a sink is an **additional**, best-effort fan-out —
/// it never gates the governed action. References only, never payloads (`INV-10`).
pub trait AuditSink: Send + Sync {
    fn emit(&self, entry: &AuditEntry);
}

/// The default loopback sink: stream entries to the structured tracing log under the
/// `audit` target (metadata only). A real SIEM HTTP exporter implements [`AuditSink`]
/// and attaches behind it with no change to the emit path.
pub struct LogAuditSink;

impl AuditSink for LogAuditSink {
    fn emit(&self, entry: &AuditEntry) {
        tracing::info!(
            target: "audit",
            actor = %entry.actor,
            action = %entry.action,
            subject = %entry.target,
            "governance action",
        );
    }
}

/// An in-memory sink that captures emitted entries — the test double for the SIEM
/// fan-out (and a building block for a buffered exporter).
#[derive(Clone, Default)]
pub struct BufferAuditSink {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
}

impl BufferAuditSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().expect("audit buffer mutex").clone()
    }
}

impl AuditSink for BufferAuditSink {
    fn emit(&self, entry: &AuditEntry) {
        self.entries
            .lock()
            .expect("audit buffer mutex")
            .push(entry.clone());
    }
}

/// The default audit checkpoint signer is the file-backed authority key store
/// rooted under the workbench state directory.
pub(crate) fn configured_audit_signer(root: &Path) -> Arc<dyn KeyStore + Send + Sync> {
    Arc::new(FileKeyStore::new(root.join("keys")))
}

/// Whether sensitive-read auditing is enabled from deployment env.
pub(crate) fn configured_audit_reads() -> bool {
    gaugedesk_env::var("AUDIT_READS").as_deref() == Some("1")
}

impl Workbench {
    /// Apply the default governance audit configuration for a workbench opened
    /// from `root`.
    pub(crate) fn apply_startup_audit(&mut self, root: &Path) {
        self.audit_reads = configured_audit_reads();
        self.audit_signer = Some(configured_audit_signer(root));
    }

    /// Attach a streaming [`AuditSink`] (`AUD-4`) — a SIEM exporter. Without
    /// one, audit entries live only in the durable `audit` scope. Builder.
    pub fn with_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// The configured audit sink, if any.
    pub fn audit_sink(&self) -> Option<&Arc<dyn AuditSink>> {
        self.audit_sink.as_ref()
    }

    /// Enable signed audit-head checkpoints (`SECAUD-2`): each governance action signs
    /// the new chain head with `signer` under this workbench's authority, so a tail
    /// truncation / last-entry edit is detectable by [`verify`]. Builder.
    pub fn with_audit_signer(mut self, signer: Arc<dyn KeyStore + Send + Sync>) -> Self {
        self.audit_signer = Some(signer);
        self
    }

    /// The configured audit checkpoint signer, if any.
    pub fn audit_signer(&self) -> Option<Arc<dyn KeyStore + Send + Sync>> {
        self.audit_signer.clone()
    }

    /// Hold the content-encryption vault (`SECAUD-9/6`) so erasure paths can reach its
    /// crypto-erase. The same vault should also be set as the store's codec. Builder.
    pub fn with_content_vault(mut self, vault: Arc<content_vault::ContentVault>) -> Self {
        self.content_vault = Some(vault);
        self
    }

    /// **Crypto-erase** a scope's content (`SECAUD-6`): destroy the per-scope key so its
    /// encrypted transcript becomes permanently unrecoverable (no-op when content
    /// encryption is not enabled). Called when a chat/engagement is deleted.
    pub fn crypto_erase_content(&self, scope: &str) -> bool {
        self.content_vault
            .as_ref()
            .map(|v| v.crypto_erase(scope))
            .unwrap_or(false)
    }

    /// Enable sensitive-read auditing (`SECAUD-4`): also record GET reads of
    /// project-scoped data to the org audit trail. Builder; off by default.
    pub fn with_audit_reads(mut self, on: bool) -> Self {
        self.audit_reads = on;
        self
    }

    /// Whether sensitive-read auditing is enabled (`SECAUD-4`).
    pub fn audits_reads(&self) -> bool {
        self.audit_reads
    }

    pub(crate) fn audit_events_value(&self, scope: &str) -> Result<serde_json::Value, AdmitError> {
        self.store_ref().events(scope).map(|events| {
            let rows: Vec<_> = events
                .into_iter()
                .map(|(position, kind, payload)| {
                    serde_json::json!({ "position": position, "kind": kind, "payload": payload })
                })
                .collect();
            serde_json::json!({ "events": rows })
        })
    }
}

/// A blocking HTTP POST — the network seam the real client attaches behind (a thin
/// `reqwest`/`ureq` wrapper in production; a fake in tests), mirroring the
/// enterprise band's `identity_oidc::HttpGet` seam (`gaugedesk-ee`). Returns the response status
/// code, or a transport error message. The literal network adapter is the one piece
/// that needs the outside world — every customer SIEM speaks plain HTTPS, so there is
/// no SIEM dependency here, only this wrapper.
pub trait HttpPost: Send + Sync {
    fn post(&self, url: &str, headers: &[(String, String)], body: &str) -> Result<u16, String>;
}

impl HttpPost for crate::net_http::HttpClient {
    fn post(&self, url: &str, headers: &[(String, String)], body: &str) -> Result<u16, String> {
        self.post_json_headers(url, headers, body)
            .map(|(status, _body)| status)
    }
}

/// The default bound on the in-memory retry backlog (`SECAUD-3`). Beyond this an
/// export is genuinely dropped — and counted (`dropped_count`) so the gap is visible.
pub const DEFAULT_AUDIT_EXPORT_BUFFER: usize = 1024;

/// The generic SIEM/webhook exporter (`AUD-4`): POST each audit entry as JSON to a
/// **customer-configured** collector URL, with optional auth headers (e.g.
/// `Authorization: Splunk <token>` for Splunk HEC, `DD-API-KEY: <key>` for Datadog, or
/// a bare webhook). The SIEM is the *customer's* system; this just streams references
/// to the endpoint they give us — never our own dependency, never a payload (`INV-10`).
///
/// **Best-effort but durable (`SECAUD-3`, SOC 2 CC7.2):** the durable `audit` scope is
/// always the source of truth, so an export never blocks or fails the governed action.
/// But a silently-dropped export means a *customer's* SIEM gaps invisibly — so a failed
/// post is **buffered** (bounded, FIFO) and **retried opportunistically** on the next
/// emit (a recovered collector drains the backlog in order), and two monotonic counters
/// are the alert signal: [`failure_count`](Self::failure_count) (export attempts that
/// failed — the "SIEM is unhealthy" rate) and [`dropped_count`](Self::dropped_count)
/// (entries lost to buffer overflow — the "we actually gapped" signal). A background
/// task can also call [`flush`](Self::flush) to drain without waiting for traffic.
pub struct HttpAuditSink<P: HttpPost> {
    poster: P,
    url: String,
    headers: Vec<(String, String)>,
    pending: Arc<Mutex<std::collections::VecDeque<AuditEntry>>>,
    max_buffer: usize,
    failures: Arc<std::sync::atomic::AtomicU64>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
}

impl<P: HttpPost> HttpAuditSink<P> {
    pub fn new(poster: P, url: impl Into<String>) -> Self {
        Self {
            poster,
            url: url.into(),
            headers: Vec::new(),
            pending: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            max_buffer: DEFAULT_AUDIT_EXPORT_BUFFER,
            failures: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Add a header sent on every export (e.g. the SIEM's auth header).
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Bound the retry backlog (default [`DEFAULT_AUDIT_EXPORT_BUFFER`]).
    pub fn with_max_buffer(mut self, n: usize) -> Self {
        self.max_buffer = n.max(1);
        self
    }

    /// Total export attempts that failed (the SIEM-health alert signal). Monotonic.
    pub fn failure_count(&self) -> u64 {
        self.failures.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Entries dropped because the retry backlog overflowed (the "audit actually
    /// gapped at the SIEM" signal — the durable timeline is unaffected). Monotonic.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Entries currently buffered awaiting a retry (export-lag observability).
    pub fn pending_count(&self) -> usize {
        self.pending.lock().expect("audit buffer mutex").len()
    }

    /// POST one entry once; `true` on a 2xx. Counts a failure (rejection or transport
    /// error) so `failure_count` reflects the SIEM's health.
    fn try_export(&self, entry: &AuditEntry) -> bool {
        let Ok(body) = serde_json::to_string(entry) else {
            return true; // unserializable is impossible here; never panic, never loop
        };
        let ok = matches!(
            self.poster.post(&self.url, &self.headers, &body),
            Ok(status) if (200..300).contains(&status)
        );
        if !ok {
            self.failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        ok
    }

    /// Drain the buffered backlog FIFO, stopping at the first failure (a still-down
    /// collector must not spin). The lock is released around each network post.
    pub fn flush(&self) {
        loop {
            let front = {
                self.pending
                    .lock()
                    .expect("audit buffer mutex")
                    .front()
                    .cloned()
            };
            let Some(front) = front else { break };
            if self.try_export(&front) {
                self.pending.lock().expect("audit buffer mutex").pop_front();
            } else {
                break; // collector still unhealthy; keep the backlog for next time
            }
        }
    }

    /// Buffer a failed entry, dropping (and counting) the oldest on overflow.
    fn buffer(&self, entry: AuditEntry) {
        let mut q = self.pending.lock().expect("audit buffer mutex");
        if q.len() >= self.max_buffer {
            q.pop_front();
            let dropped = self
                .dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            tracing::warn!(
                target: "audit",
                dropped,
                "SIEM export backlog overflowed — oldest entry dropped (durable timeline unaffected)",
            );
        } else {
            tracing::warn!(
                target: "audit",
                pending = q.len() + 1,
                "SIEM export failed — entry buffered for retry (durable timeline unaffected)",
            );
        }
        q.push_back(entry);
    }
}

impl<P: HttpPost> AuditSink for HttpAuditSink<P> {
    fn emit(&self, entry: &AuditEntry) {
        // Opportunistically drain any backlog first (a recovered collector catches up,
        // in order), then export this entry; on failure it joins the bounded backlog.
        self.flush();
        if !self.try_export(entry) {
            self.buffer(entry.clone());
        }
    }
}

/// The chain-link function for one governed action, to be resolved *inside* the
/// write transaction that appends it (`SECAUD-2`).
///
/// The link is a function rather than a prepared row because the predecessor is
/// not knowable until the transaction holds the write lock. An earlier version
/// read the head first and appended afterwards, relying on the process-wide
/// workbench mutex to keep the pair atomic; two writers on separate connections
/// would then link to the same predecessor and silently fork the chain. The store
/// owns *when* this runs; this owns *how* the link is computed.
pub fn link<'a>(
    actor: &'a str,
    action: &'a str,
    target: &'a str,
) -> impl Fn(Option<&str>) -> String + 'a {
    move |previous| {
        let prev = previous
            .and_then(|row| serde_json::from_str::<AuditEntry>(row).ok())
            .map(|entry| entry_hash(&entry))
            .unwrap_or_else(|| GENESIS.to_string());
        serde_json::to_string(&AuditEntry {
            actor: actor.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            prev,
        })
        .expect("audit entry serializes")
    }
}

/// Name the audit scope/kind a [`link`] appends into, for a caller committing the
/// entry alongside its own domain facts.
pub fn chained<'a>(link: &'a dyn Fn(Option<&str>) -> String) -> ChainedRecordFact<'a> {
    chained_in(AUDIT_SCOPE, link)
}

pub fn chained_in<'a>(
    audit_scope: &'a str,
    link: &'a dyn Fn(Option<&str>) -> String,
) -> ChainedRecordFact<'a> {
    ChainedRecordFact {
        scope_id: audit_scope,
        kind: "entry",
        link,
    }
}

/// The entry a chained append actually committed, recovered from the payload the
/// store resolved. `None` when the command replayed and appended nothing.
pub fn committed_entry(chained_payload: Option<&str>) -> Option<AuditEntry> {
    chained_payload.and_then(|payload| serde_json::from_str(payload).ok())
}

/// Complete non-authoritative audit side effects after an entry has committed.
/// The durable row itself must already be present; this method only refreshes
/// the signed checkpoint and fans the reference-only row out to a sink.
pub fn finish_committed(wb: &mut Workbench, entry: &AuditEntry) {
    finish_committed_in(wb, crate::org::ORG_SCOPE, entry);
}

pub fn finish_committed_in(wb: &mut Workbench, store_scope: &str, entry: &AuditEntry) {
    // SECAUD-2: anchor the new head with a governance-signed checkpoint, if a signer is
    // configured (production sets one; unit tests without one stay chain-only).
    if let Some(signer) = wb.audit_signer() {
        let authority = wb.authority().clone();
        sign_checkpoint_in(wb.store_mut(), store_scope, signer.as_ref(), &authority);
    }
    if let Some(sink) = wb.audit_sink() {
        sink.emit(entry);
    }
}

/// Append an audit entry and fan it out to the streaming sink (`AUD-4`), if one is
/// configured. Command paths with no domain facts of their own use this helper;
/// admitted Environment commands instead commit [`chained`] atomically with their
/// domain facts and receipt. Either way the chain link is resolved inside the
/// appending transaction.
pub fn record(wb: &mut Workbench, actor: &str, action: &str, target: &str) {
    record_in(wb, crate::org::ORG_SCOPE, actor, action, target);
}

pub fn record_in(wb: &mut Workbench, store_scope: &str, actor: &str, action: &str, target: &str) {
    let link = link(actor, action, target);
    let audit_scope = scope_for(store_scope);
    let appended = wb
        .store_mut()
        .append_chained_record(&audit_scope, "entry", &link);
    if let Ok((_, payload)) = appended {
        if let Some(entry) = committed_entry(Some(&payload)) {
            finish_committed_in(wb, store_scope, &entry);
        }
    }
}

/// The full timeline in position order (oldest first).
pub fn list(store: &Store) -> Vec<AuditEntry> {
    list_in(store, crate::org::ORG_SCOPE)
}

pub fn list_in(store: &Store, store_scope: &str) -> Vec<AuditEntry> {
    store
        .records(&scope_for(store_scope), "entry")
        .unwrap_or_default()
        .iter()
        .filter_map(|row| serde_json::from_str(row).ok())
        .collect()
}

/// CSV of the timeline (`actor,action,target` rows, with a header). Fields are
/// minimally escaped (quotes doubled, fields quoted) so a comma in a value is safe.
pub fn to_csv(entries: &[AuditEntry]) -> String {
    let mut out = String::from("actor,action,target\n");
    for e in entries {
        out.push_str(&format!(
            "{},{},{}\n",
            csv_field(&e.actor),
            csv_field(&e.action),
            csv_field(&e.target)
        ));
    }
    out
}

fn csv_field(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SECAUD-2 under REAL contention: the governance chain, appended from many
    /// connections at once, must still verify as one unbroken sequence.
    ///
    /// This is the property the workbench mutex used to supply by accident. The
    /// link is now resolved inside the appending transaction, so it holds without
    /// any process-wide lock — which is what lets a turn stop holding one.
    #[test]
    fn the_audit_chain_verifies_under_concurrent_appends() {
        const THREADS: usize = 6;
        const APPENDS: usize = 15;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let path = path.to_str().unwrap().to_string();
        let _prime = Store::open(&path).unwrap();

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let p = path.clone();
                std::thread::spawn(move || {
                    let mut store = Store::open(&p).unwrap();
                    for i in 0..APPENDS {
                        let actor = format!("actor-{t}");
                        let target = format!("target-{t}-{i}");
                        let entry = link(&actor, "member.role", &target);
                        store
                            .append_chained_record(AUDIT_SCOPE, "entry", &entry)
                            .expect("a contended audit append must wait, not fail");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(list(&store).len(), THREADS * APPENDS);
        let integrity = verify(&store, None);
        assert!(
            integrity.broken_at.is_none(),
            "the chain forked at {:?} under contention",
            integrity.broken_at
        );
        assert!(integrity.ok, "the contended chain must verify");
    }

    #[test]
    fn record_fans_out_to_the_configured_sink() {
        let buffer = BufferAuditSink::new();
        let mut wb = Workbench::new(Store::open_in_memory().unwrap())
            .with_audit_sink(Arc::new(buffer.clone()));
        record(&mut wb, "alice", "member.role", "bob");
        record(&mut wb, "scim", "scim.provision", "carol");
        // The SIEM sink saw both, in order, references only.
        let seen = buffer.entries();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].actor, "alice");
        assert_eq!(seen[0].action, "member.role");
        assert_eq!(seen[1].target, "carol");
        // And the durable timeline holds them too (the source of truth).
        assert_eq!(list(wb.store_ref()).len(), 2);
    }

    /// A fake collector: records every POST it receives, and can be told to fail.
    type FakePostCalls = Arc<Mutex<Vec<(String, Vec<(String, String)>, String)>>>;

    struct FakePoster {
        calls: FakePostCalls,
        fail: bool,
    }

    impl HttpPost for FakePoster {
        fn post(&self, url: &str, headers: &[(String, String)], body: &str) -> Result<u16, String> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_string(), headers.to_vec(), body.to_string()));
            if self.fail {
                Err("connection refused".into())
            } else {
                Ok(200)
            }
        }
    }

    #[test]
    fn http_sink_posts_each_entry_as_json_to_the_configured_url_with_headers() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sink = HttpAuditSink::new(
            FakePoster {
                calls: calls.clone(),
                fail: false,
            },
            "https://collector.example/services/collector",
        )
        .with_header("Authorization", "Splunk test-token");

        sink.emit(&AuditEntry {
            actor: "alice".into(),
            action: "member.role".into(),
            target: "bob".into(),
            ..Default::default()
        });

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1);
        let (url, headers, body) = &recorded[0];
        assert_eq!(url, "https://collector.example/services/collector");
        assert!(headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Splunk test-token"));
        // The body is the entry as JSON — a reference, not a payload (INV-10).
        let parsed: AuditEntry = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.actor, "alice");
        assert_eq!(parsed.action, "member.role");
        assert_eq!(parsed.target, "bob");
    }

    #[test]
    fn http_sink_is_best_effort_when_the_collector_fails() {
        // A failing collector must not panic out of emit().
        let sink = HttpAuditSink::new(
            FakePoster {
                calls: Arc::new(Mutex::new(Vec::new())),
                fail: true,
            },
            "https://down.example",
        );
        sink.emit(&AuditEntry {
            actor: "a".into(),
            action: "x".into(),
            target: "t".into(),
            ..Default::default()
        });
    }

    /// A collector that can be toggled down/up at runtime, recording successful posts.
    struct FlakyPoster {
        delivered: Arc<Mutex<Vec<String>>>,
        down: Arc<std::sync::atomic::AtomicBool>,
    }
    impl HttpPost for FlakyPoster {
        fn post(&self, _u: &str, _h: &[(String, String)], body: &str) -> Result<u16, String> {
            if self.down.load(std::sync::atomic::Ordering::Relaxed) {
                Err("collector down".into())
            } else {
                self.delivered.lock().unwrap().push(body.to_string());
                Ok(200)
            }
        }
    }

    fn actor_of(body: &str) -> String {
        serde_json::from_str::<AuditEntry>(body).unwrap().actor
    }

    #[test]
    fn a_down_siem_buffers_entries_and_counts_failures() {
        // SECAUD-3: a failed export is retained (not silently dropped) and the failure
        // counter — the alert signal — climbs, while the durable timeline is untouched.
        let down = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let sink = HttpAuditSink::new(
            FlakyPoster {
                delivered: Arc::new(Mutex::new(Vec::new())),
                down: down.clone(),
            },
            "https://siem.example",
        );
        for who in ["alice", "bob"] {
            sink.emit(&AuditEntry {
                actor: who.into(),
                action: "x".into(),
                target: "t".into(),
                ..Default::default()
            });
        }
        assert_eq!(sink.pending_count(), 2, "both failed exports are buffered");
        assert!(
            sink.failure_count() >= 2,
            "failures are counted for alerting"
        );
        assert_eq!(sink.dropped_count(), 0);
    }

    #[test]
    fn a_recovered_siem_drains_the_backlog_in_order() {
        // SECAUD-3: when the collector comes back, the next emit flushes the backlog
        // FIFO and then exports the new entry — no gap, original order preserved.
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let down = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let sink = HttpAuditSink::new(
            FlakyPoster {
                delivered: delivered.clone(),
                down: down.clone(),
            },
            "https://siem.example",
        );
        for who in ["alice", "bob"] {
            sink.emit(&AuditEntry {
                actor: who.into(),
                action: "x".into(),
                target: "t".into(),
                ..Default::default()
            });
        }
        assert_eq!(sink.pending_count(), 2);
        // Collector recovers; a fresh emit drains the backlog then delivers the new one.
        down.store(false, std::sync::atomic::Ordering::Relaxed);
        sink.emit(&AuditEntry {
            actor: "carol".into(),
            action: "x".into(),
            target: "t".into(),
            ..Default::default()
        });
        assert_eq!(sink.pending_count(), 0, "backlog fully drained");
        let seen: Vec<String> = delivered
            .lock()
            .unwrap()
            .iter()
            .map(|b| actor_of(b))
            .collect();
        assert_eq!(
            seen,
            vec!["alice", "bob", "carol"],
            "delivered in original order"
        );
    }

    #[test]
    fn the_retry_backlog_is_bounded_and_overflow_is_counted() {
        // SECAUD-3: the buffer cannot grow without bound; an overflow drops the OLDEST
        // and increments `dropped_count` — the honest "the SIEM actually gapped" signal.
        let down = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let sink = HttpAuditSink::new(
            FlakyPoster {
                delivered: Arc::new(Mutex::new(Vec::new())),
                down: down.clone(),
            },
            "https://siem.example",
        )
        .with_max_buffer(2);
        for who in ["a", "b", "c"] {
            sink.emit(&AuditEntry {
                actor: who.into(),
                action: "x".into(),
                target: "t".into(),
                ..Default::default()
            });
        }
        assert_eq!(sink.pending_count(), 2, "bounded at max_buffer");
        assert_eq!(
            sink.dropped_count(),
            1,
            "the oldest over-cap entry is counted as a gap"
        );
    }

    #[test]
    fn a_failing_siem_export_never_drops_the_durable_audit_record() {
        // The durable `audit` scope is the source of truth: even when the SIEM POST
        // fails, the governed action's entry is still recorded (best-effort fan-out).
        let sink = HttpAuditSink::new(
            FakePoster {
                calls: Arc::new(Mutex::new(Vec::new())),
                fail: true,
            },
            "https://down.example",
        );
        let mut wb =
            Workbench::new(Store::open_in_memory().unwrap()).with_audit_sink(Arc::new(sink));
        record(&mut wb, "alice", "member.role", "bob");
        assert_eq!(list(wb.store_ref()).len(), 1);
    }

    #[test]
    fn the_chain_verifies_for_an_honestly_appended_log() {
        // SECAUD-2: a log built only through `record` is a well-formed chain.
        let mut wb = Workbench::new(Store::open_in_memory().unwrap());
        record(&mut wb, "alice", "member.role", "bob");
        record(&mut wb, "scim", "scim.provision", "carol");
        record(&mut wb, "alice", "sso.configure", "okta");
        let integrity = verify(wb.store_ref(), None);
        assert!(integrity.ok);
        assert_eq!(integrity.entries, 3);
        assert!(integrity.broken_at.is_none());
        assert_eq!(integrity.head, head_hash(wb.store_ref()));
        assert_ne!(integrity.head, GENESIS);
        // Each entry's `prev` is the prior entry's hash (genesis-anchored first).
        let entries = list(wb.store_ref());
        assert_eq!(entries[0].prev, GENESIS);
        assert_eq!(entries[1].prev, entry_hash(&entries[0]));
        assert_eq!(entries[2].prev, entry_hash(&entries[1]));
    }

    #[test]
    fn an_in_place_edit_of_a_past_entry_is_detected() {
        // SECAUD-2: rewrite a non-terminal entry's content directly in the store
        // (the DB/host-level tamper a hash chain defends against). The successor's
        // `prev` no longer matches the recomputed head ⇒ verify reports the break.
        let mut wb = Workbench::new(Store::open_in_memory().unwrap());
        record(&mut wb, "alice", "member.role", "bob");
        record(&mut wb, "mallory", "member.role", "mallory"); // a self-promotion to hide
        record(&mut wb, "alice", "member.deactivate", "carol");
        assert!(verify(wb.store_ref(), None).ok);

        // Tamper entry 1: flip the action to erase the suspicious self-promotion.
        let mut entries = list(wb.store_ref());
        entries[1].action = "noop".into();
        // Re-materialize the scope with the tampered entry in place of the original.
        let mut tampered = Workbench::new(Store::open_in_memory().unwrap());
        for e in &entries {
            let _ = tampered.store_mut().append_record(
                AUDIT_SCOPE,
                "entry",
                &serde_json::to_string(e).unwrap(),
            );
        }
        let integrity = verify(tampered.store_ref(), None);
        assert!(!integrity.ok, "tampered history must not verify");
        assert_eq!(integrity.broken_at, Some(2)); // the successor catches it
        assert_eq!(integrity.head, "");
    }

    #[test]
    fn editing_an_entrys_own_chain_link_is_detected() {
        // SECAUD-2: editing the stored `prev` is caught at that entry itself.
        let mut wb = Workbench::new(Store::open_in_memory().unwrap());
        record(&mut wb, "alice", "member.role", "bob");
        record(&mut wb, "alice", "sso.configure", "okta");
        let mut entries = list(wb.store_ref());
        entries[1].prev = "deadbeef".into();
        let mut tampered = Workbench::new(Store::open_in_memory().unwrap());
        for e in &entries {
            let _ = tampered.store_mut().append_record(
                AUDIT_SCOPE,
                "entry",
                &serde_json::to_string(e).unwrap(),
            );
        }
        assert_eq!(verify(tampered.store_ref(), None).broken_at, Some(1));
    }

    #[test]
    fn the_empty_log_verifies_with_a_genesis_head() {
        let wb = Workbench::new(Store::open_in_memory().unwrap());
        let integrity = verify(wb.store_ref(), None);
        assert!(integrity.ok);
        assert_eq!(integrity.entries, 0);
        assert_eq!(head_hash(wb.store_ref()), GENESIS);
    }

    #[test]
    fn a_signed_checkpoint_catches_a_tail_truncation_the_chain_misses() {
        // SECAUD-2: with a governance signer, each append anchors the head. A tail
        // truncation leaves the remaining chain links intact (the bare chain can't see
        // it — no successor), but the signed checkpoint pins a longer history, so verify
        // catches it.
        use crate::key_store::LoopbackKeyStore;
        let signer: Arc<dyn KeyStore + Send + Sync> = Arc::new(LoopbackKeyStore);
        let mut wb =
            Workbench::new(Store::open_in_memory().unwrap()).with_audit_signer(signer.clone());
        // The trusted verifier key is this authority's governance key (matches the signer).
        let pubkey = LoopbackKeyStore.signing_key(wb.authority()).public_key();

        record(&mut wb, "alice", "member.role", "bob");
        record(&mut wb, "alice", "sso.configure", "okta");
        record(&mut wb, "alice", "member.deactivate", "carol");

        let honest = verify(wb.store_ref(), Some(&pubkey));
        assert!(honest.ok, "an honest signed log verifies");
        assert!(honest.anchored, "a signer produces a checkpoint anchor");

        // Attacker truncates the last entry but keeps the (unforgeable) checkpoints.
        let entries = list(wb.store_ref());
        let mut truncated = Workbench::new(Store::open_in_memory().unwrap());
        for e in &entries[..2] {
            let _ = truncated.store_mut().append_record(
                AUDIT_SCOPE,
                "entry",
                &serde_json::to_string(e).unwrap(),
            );
        }
        for cp in wb
            .store_ref()
            .records(AUDIT_CHECKPOINT_SCOPE, "checkpoint")
            .unwrap()
        {
            let _ = truncated
                .store_mut()
                .append_record(AUDIT_CHECKPOINT_SCOPE, "checkpoint", &cp);
        }
        // The chain links alone are intact after the truncation (the gap SECAUD-2 closes)...
        assert_eq!(verify(truncated.store_ref(), None).broken_at, None);
        // ...but the signed checkpoint (count=3 over only 2 entries) detects it.
        let caught = verify(truncated.store_ref(), Some(&pubkey));
        assert!(
            !caught.ok,
            "the checkpoint anchor catches the tail truncation"
        );
        assert!(caught.anchored);
    }

    #[test]
    fn a_checkpoint_not_signed_by_the_trusted_key_is_rejected() {
        // SECAUD-2: the verifier checks the checkpoint against the trusted governance
        // key it supplies independently — never a key embedded in the record. A
        // checkpoint signed by any other key (a forgery) fails.
        use crate::key_store::LoopbackKeyStore;
        let signer: Arc<dyn KeyStore + Send + Sync> = Arc::new(LoopbackKeyStore);
        let mut wb = Workbench::new(Store::open_in_memory().unwrap()).with_audit_signer(signer);
        record(&mut wb, "mallory", "member.role", "mallory");

        // Verified against a DIFFERENT key than the one that signed ⇒ rejected.
        let wrong = LoopbackKeyStore
            .signing_key(&AuthorityId::new("some-other-gov"))
            .public_key();
        let v = verify(wb.store_ref(), Some(&wrong));
        assert!(v.anchored);
        assert!(
            !v.ok,
            "a checkpoint not signed by the trusted key is rejected"
        );

        // Sanity: against the correct governance key it verifies.
        let correct = LoopbackKeyStore.signing_key(wb.authority()).public_key();
        assert!(verify(wb.store_ref(), Some(&correct)).ok);
    }

    #[test]
    fn csv_quotes_and_escapes() {
        let entries = vec![AuditEntry {
            actor: "a,b".into(),
            action: "member.role".into(),
            target: "x\"y".into(),
            ..Default::default()
        }];
        let csv = to_csv(&entries);
        assert_eq!(
            csv,
            "actor,action,target\n\"a,b\",\"member.role\",\"x\"\"y\"\n"
        );
    }
}
