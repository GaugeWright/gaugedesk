//! The device-enrollment **drive layer** (`ACCT-1`, [ADR 0055]) — the HTTP-facing shell
//! that runs the proven enrollment handshake ([`crate::device_enroll`]) over the live
//! shared WSS rendezvous for **both** roles. Where
//! `device_enroll` supplies the wire primitives (SAS, ECIES seal, delegation verify) and
//! `net_relay` supplies the transport, this module composes them into two long-running,
//! per-session HTTP flows a human can drive from "Your devices".
//!
//! The rendezvous ([ADR 0055] §1): an existing **holder** device mints an
//! [`EnrollmentTicket`] (`{ session, account_root, broker }`) shown out-of-band (QR +
//! copyable code). The **new device** consumes the ticket. Both dial the dumb broker with
//! that session token; the broker splices their two legs (`RELAY_NO_PAYLOAD_ACCESS`). The
//! new device sends its [`EnrollRequest`]; the holder reads the *presented* subkey and
//! derives the SAS over it; the human compares the 6-char SAS on both screens and, only on
//! a match, confirms. The holder then [`Holder::authorize`]s — a root-signed self-delegation
//! plus the account key **sealed to the subkey** (ECIES ciphertext, `INV-10`) — and records
//! the new [`DeviceRecord`]. The new device [`NewDevice::complete`]s: verify the delegation
//! chains to the pinned root, unseal the account key, persist it.
//!
//! Because a broker leg blocks awaiting its peer (and the holder blocks awaiting the human
//! confirm), each role runs as a **background task** and exposes a per-session
//! [`EnrollPhase`] the status routes poll. The account key **never** crosses HTTP — only the
//! sealed ciphertext crosses the broker; the status routes surface only the phase + SAS.
//!
//! Fail-closed: a relay-substituted subkey yields a mismatched SAS the human catches (they
//! decline → no authorize → no device enrolled); a lapsed pairing or handshake times the leg
//! out ([`ENROLL_SESSION_TIMEOUT`]) rather than wedging a broker leg; the holder never
//! authorizes without the explicit [`EnrollDrive::confirm_host`] the confirm route calls.
//!
//! [ADR 0055]: ../../specs/decisions/0055-enrollment-handshake-protocol.md

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;

use gaugedesk_core::ids::PublicKey;
use gaugedesk_core::signature::SigningKey;
use gaugedesk_relay_transport::{connect_one_shot, OneShotLeg};

use crate::account::{self, DeviceRecord, DeviceStatus, RecordOp};
use crate::at_rest::Encryptor;
use crate::device_enroll::{EnrollAuthorize, EnrollRequest, Holder, NewDevice};
use crate::key_store::{FileKeyStore, KeyStore};
use crate::net_relay::{read_frame, token_bytes, write_frame};
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};

/// How long a whole enrollment leg may live before it is timed out (pairing +
/// handshake + the human's SAS confirm). Generous for a person comparing two
/// screens, but bounded so a lapsed pairing never wedges a broker leg (RF-A2, the
/// [ADR 0055] expiry). Both legs use the same window.
const ENROLL_SESSION_TIMEOUT: Duration = Duration::from_secs(180);

/// The self-delegation lifetime the holder issues (FED-5a). Long-lived device
/// trust; re-enrollment renews it. `complete()` rejects an expired delegation.
const DELEGATION_TTL_SECS: u64 = 400 * 24 * 60 * 60;

/// The default broker the holder dials / advertises in its ticket when none is
/// configured — the same env seam federation reads ([`crate::federation`]).
fn default_broker_addr() -> String {
    gaugedesk_env::var("RELAY_ENDPOINT")
        .unwrap_or_else(|| "wss://relay.gaugewright.com".to_string())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The out-of-band enrollment ticket a holder mints and shows (QR + code): the
/// rendezvous `session`, the account `account_root` the new device pins, and the
/// `broker` both legs dial. It carries **no secret** — the trust anchor is the
/// SAS compare + the root-signed delegation, not the ticket.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentTicket {
    pub session: String,
    pub account_root: String,
    pub broker: String,
}

/// The runtime phase of one enrollment leg (distinct from the pure reducer's
/// [`gaugedesk_core::device_enrollment::EnrollmentPhase`], which is the proven
/// state machine; this is the drive-layer projection the status routes poll).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollPhase {
    /// The leg is dialing the broker / awaiting its peer to arrive and pair.
    AwaitingPeer,
    /// The SAS is derived and available for the out-of-band human compare.
    SasReady,
    /// The holder's human confirmed the SAS (or the new device received the
    /// authorization) — the handshake is proceeding.
    Authorized,
    /// Terminal success: the new device unsealed the key / the holder recorded it.
    Completed,
    /// Terminal failure: the handshake was refused (fail-closed) — see `error`.
    Failed,
    /// Terminal: the pairing/confirm window lapsed before completion.
    Expired,
}

/// The shared, mutable view of one leg the status routes read and the background
/// task writes.
struct LegState {
    phase: EnrollPhase,
    sas: Option<String>,
    error: Option<String>,
}

/// One in-flight enrollment leg: its live state plus the confirm signal the holder
/// task waits on (the new-device task never waits — it has no human step).
pub struct Leg {
    state: Mutex<LegState>,
    confirm: Notify,
    confirmed: AtomicBool,
}

impl Leg {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(LegState {
                phase: EnrollPhase::AwaitingPeer,
                sas: None,
                error: None,
            }),
            confirm: Notify::new(),
            confirmed: AtomicBool::new(false),
        })
    }

    /// Snapshot the phase + SAS + error for a status GET.
    fn snapshot(&self) -> (EnrollPhase, Option<String>, Option<String>) {
        let s = self.state.lock_unpoisoned();
        (s.phase, s.sas.clone(), s.error.clone())
    }

    fn set_phase(&self, phase: EnrollPhase) {
        self.state.lock_unpoisoned().phase = phase;
    }

    fn set_sas_ready(&self, sas: String) {
        let mut s = self.state.lock_unpoisoned();
        s.phase = EnrollPhase::SasReady;
        s.sas = Some(sas);
    }

    fn fail(&self, reason: String) {
        let mut s = self.state.lock_unpoisoned();
        s.phase = EnrollPhase::Failed;
        s.error = Some(reason);
    }

    fn expire(&self) {
        let mut s = self.state.lock_unpoisoned();
        // A leg that already terminated (e.g. Completed) is not retroactively expired.
        if !matches!(s.phase, EnrollPhase::Completed | EnrollPhase::Failed) {
            s.phase = EnrollPhase::Expired;
            s.error
                .get_or_insert_with(|| "enrollment timed out".to_string());
        }
    }

    /// Signal the holder task that the human confirmed the SAS. Idempotent and
    /// order-independent (tokio `Notify` stores a single permit).
    fn confirm(&self) {
        self.confirmed.store(true, Ordering::SeqCst);
        self.confirm.notify_one();
    }

    /// Block until the human confirms (returns immediately if already confirmed).
    async fn await_confirm(&self) {
        if !self.confirmed.load(Ordering::SeqCst) {
            self.confirm.notified().await;
        }
    }
}

/// The per-session pending-enrollment registry (one per workbench). Holder and new
/// device legs are keyed separately so a session id collision across roles cannot
/// cross-wire, and so [`confirm_host`](Self::confirm_host) can only ever fire a
/// holder leg.
#[derive(Default)]
pub struct EnrollDrive {
    host_legs: Mutex<HashMap<String, Arc<Leg>>>,
    join_legs: Mutex<HashMap<String, Arc<Leg>>>,
}

impl EnrollDrive {
    pub fn new() -> Self {
        Self::default()
    }

    fn register_host(&self, session: &str, leg: Arc<Leg>) {
        self.host_legs
            .lock_unpoisoned()
            .insert(session.to_string(), leg);
    }

    fn register_join(&self, session: &str, leg: Arc<Leg>) {
        self.join_legs
            .lock_unpoisoned()
            .insert(session.to_string(), leg);
    }

    /// The holder leg's current phase + SAS (for `GET .../host/:session`).
    pub fn host_snapshot(
        &self,
        session: &str,
    ) -> Option<(EnrollPhase, Option<String>, Option<String>)> {
        self.host_legs
            .lock_unpoisoned()
            .get(session)
            .map(|l| l.snapshot())
    }

    /// The new-device leg's current phase + SAS (for `GET .../join/:session`).
    pub fn join_snapshot(
        &self,
        session: &str,
    ) -> Option<(EnrollPhase, Option<String>, Option<String>)> {
        self.join_legs
            .lock_unpoisoned()
            .get(session)
            .map(|l| l.snapshot())
    }

    /// The human confirmed the SAS on the holder: release the holder leg to
    /// authorize. Fail-closed — refuses unless the leg exists **and** is in
    /// [`EnrollPhase::SasReady`] (never authorize before the peer/SAS is present).
    pub fn confirm_host(&self, session: &str) -> Result<(), &'static str> {
        let leg = self
            .host_legs
            .lock_unpoisoned()
            .get(session)
            .cloned()
            .ok_or("no such enrollment session")?;
        let (phase, _, _) = leg.snapshot();
        if phase != EnrollPhase::SasReady {
            return Err("enrollment is not awaiting SAS confirmation");
        }
        leg.set_phase(EnrollPhase::Authorized);
        leg.confirm();
        Ok(())
    }
}

// --- workbench glue ------------------------------------------------------------

impl Workbench {
    /// A cheap handle to the per-session enrollment registry (cloned out under the
    /// lock, then used without holding it — the leg tasks await on the broker).
    pub fn enroll_drive(&self) -> Arc<EnrollDrive> {
        self.enroll_drive.clone()
    }

    /// The broker address this workbench advertises in a ticket / dials as holder.
    pub fn enroll_broker_addr(&self) -> String {
        self.enroll_broker
            .clone()
            .unwrap_or_else(default_broker_addr)
    }

    /// Override the enrollment broker (config / tests). Empty is ignored.
    pub fn set_enroll_broker_addr(&mut self, addr: impl Into<String>) {
        let addr = addr.into();
        if !addr.is_empty() {
            self.enroll_broker = Some(addr);
        }
    }

    /// Build the [`Holder`] for a session: this account's governance root (the
    /// account identity, ADR 0053) from the file key store + the account key it
    /// hands over sealed. The private root never leaves the key store beyond this
    /// in-process `SigningKey`.
    pub fn enroll_holder(&self, session: &str) -> Holder {
        let root = FileKeyStore::new(self.root_path().join("keys")).signing_key(self.authority());
        let account_key = self.account_key();
        Holder::new(root, account_key, session)
    }

    /// Record the account key a newly-enrolled device recovered over the handshake, and
    /// **adopt it durably at rest** (ADR 0053 §4): held in memory for the running process
    /// *and* persisted, so a restart of the enrolled device still opens the sealed account
    /// state it joined — [`Workbench::account_key`] returns this recovered key ahead of the
    /// seed path. The key never crosses HTTP (`INV-10`); at rest it is wrapped under this
    /// device's own key material (see [`Workbench::persist_recovered_account_key`]).
    pub fn set_recovered_account_key(&mut self, key: [u8; 32]) {
        self.recovered_account_key = Some(key);
        self.persist_recovered_account_key(key);
    }

    /// The account key this device recovered on enrollment, if any (the internal
    /// accessor the integration test reads — off the HTTP surface).
    pub fn recovered_account_key(&self) -> Option<[u8; 32]> {
        self.recovered_account_key
    }

    /// Where the recovered account key is persisted (wrapped), alongside — but distinct
    /// from — the governance key store under the state root.
    fn recovered_account_key_path(&self) -> std::path::PathBuf {
        self.root_path().join("account").join("account-key.sealed")
    }

    /// The **key-encryption key** wrapping the recovered account key at rest. Derived from
    /// *this* device's own governance seed (stable, device-local), domain-separated from the
    /// account key itself. At-rest protection therefore tracks the key store's tier: today a
    /// loose seed file, a secure enclave later — moving the seed into an enclave protects
    /// this wrap with it, no code change. Returns `None` only if no device seed resolves.
    fn recovered_key_wrap(&self) -> [u8; 32] {
        let seed = self.governance_seed();
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"gaugewright-recovered-key-wrap:v1:");
        h.update(seed);
        h.finalize().into()
    }

    /// Wrap + write the recovered account key. Best-effort: a write failure leaves the
    /// in-memory key intact (this process still works); the next enrollment re-establishes
    /// it. Never writes the key in the clear.
    fn persist_recovered_account_key(&self, key: [u8; 32]) {
        let Ok(ct) = account::account_encryptor(self.recovered_key_wrap()).encrypt(&key) else {
            return;
        };
        let path = self.recovered_account_key_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, hex::encode(ct));
    }

    /// Reload a previously-adopted recovered account key from disk (called on workbench
    /// open), unwrapping it under this device's key. A missing/unreadable/foreign-wrapped
    /// file is simply "no recovered key" (fail-closed) — the seed path then applies.
    pub(crate) fn restore_recovered_account_key(&mut self) {
        let Ok(hexed) = std::fs::read_to_string(self.recovered_account_key_path()) else {
            return;
        };
        let Ok(ct) = hex::decode(hexed.trim()) else {
            return;
        };
        if let Ok(pt) = account::account_encryptor(self.recovered_key_wrap()).decrypt(&ct) {
            if let Ok(k) = <[u8; 32]>::try_from(pt.as_slice()) {
                self.recovered_account_key = Some(k);
            }
        }
    }
}

// --- the two role flows --------------------------------------------------------

/// Mint a fresh, CSPRNG-seeded device subkey (the new device's own P-256 key).
fn fresh_subkey() -> Option<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).ok()?;
    SigningKey::from_seed(&seed).ok()
}

/// A fresh, URL-safe rendezvous session token (16 CSPRNG bytes → 32 hex chars,
/// the broker's fixed token width).
fn fresh_session() -> Option<String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).ok()?;
    Some(hex::encode(b))
}

/// A short, human-facing device id derived from a subkey pubkey (the full pubkey
/// is kept on the record; the id just needs to be stable + unique).
fn device_id(subkey_pubkey: &str) -> String {
    format!("device:{}", &subkey_pubkey[..subkey_pubkey.len().min(12)])
}

/// Start the **holder** leg (an existing device authorizing a new one). Returns the
/// ticket to show out-of-band; the leg runs in the background until the human
/// confirms (or it times out).
pub fn start_host(wb: &SharedWorkbench, scope: String) -> Option<EnrollmentTicket> {
    let session = fresh_session()?;
    let (drive, broker, holder, ticket) = {
        let wb = wb.lock_unpoisoned();
        let drive = wb.enroll_drive();
        let broker = wb.enroll_broker_addr();
        let holder = wb.enroll_holder(&session);
        let ticket = EnrollmentTicket {
            session: session.clone(),
            account_root: holder.account_root().as_str().to_string(),
            broker: broker.clone(),
        };
        (drive, broker, holder, ticket)
    };
    let leg = Leg::new();
    drive.register_host(&session, leg.clone());
    let wb_task = wb.clone();
    tokio::spawn(run_host_leg(leg, wb_task, scope, broker, holder, session));
    Some(ticket)
}

/// Start the **new-device** leg from a consumed ticket. Returns the session id the
/// caller polls; the leg runs in the background until the handshake completes (or
/// is refused / times out).
pub fn start_join(
    wb: &SharedWorkbench,
    scope: String,
    ticket: EnrollmentTicket,
) -> Result<String, &'static str> {
    let subkey = fresh_subkey().ok_or("could not mint a device subkey")?;
    let nd = NewDevice::open(ticket.session.clone(), ticket.account_root.clone(), subkey);
    let drive = wb.lock_unpoisoned().enroll_drive();
    let leg = Leg::new();
    drive.register_join(&ticket.session, leg.clone());
    let wb_task = wb.clone();
    let session = ticket.session.clone();
    tokio::spawn(run_join_leg(leg, wb_task, scope, ticket.broker, nd));
    Ok(session)
}

async fn run_host_leg(
    leg: Arc<Leg>,
    wb: SharedWorkbench,
    scope: String,
    broker: String,
    holder: Holder,
    session: String,
) {
    match tokio::time::timeout(
        ENROLL_SESSION_TIMEOUT,
        host_handshake(&leg, &wb, &scope, &broker, &holder, &session),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => leg.fail(e),
        Err(_) => leg.expire(),
    }
}

/// The holder side of the handshake over the broker: read the request, derive the
/// SAS over the *presented* subkey, block on the human confirm, then authorize
/// (seal the account key + issue the self-delegation) and record the device.
async fn host_handshake(
    leg: &Leg,
    wb: &SharedWorkbench,
    scope: &str,
    broker: &str,
    holder: &Holder,
    session: &str,
) -> Result<(), String> {
    let mut s = connect_one_shot(broker, token_bytes(session), OneShotLeg::Initializer)
        .await
        .map_err(|e| format!("broker connect: {e}"))?;
    // Blocks until the new device's leg pairs at the broker and sends its request.
    let req_bytes = read_frame(&mut s)
        .await
        .map_err(|e| format!("read request: {e}"))?;
    let req: EnrollRequest =
        serde_json::from_slice(&req_bytes).map_err(|e| format!("decode request: {e}"))?;
    let presented = PublicKey::new(req.subkey.clone());
    // The SAS over the presented subkey — the out-of-band value the human compares
    // with the new device's. A relay substitution yields a different SAS here.
    leg.set_sas_ready(holder.sas_for(&presented));

    // The keystone gate: never authorize until the human confirms the SAS matches.
    leg.await_confirm().await;

    let auth = holder
        .authorize(&presented, now_secs() + DELEGATION_TTL_SECS)
        .ok_or_else(|| "seal to subkey failed".to_string())?;
    let bytes = serde_json::to_vec(&auth).map_err(|e| format!("encode authorize: {e}"))?;
    write_frame(&mut s, &bytes)
        .await
        .map_err(|e| format!("send authorize: {e}"))?;
    s.shutdown().await.map_err(|e| format!("close leg: {e}"))?;

    // The confirmed device joins this account's trusted-device registry.
    let record = DeviceRecord {
        id: device_id(&req.subkey),
        op: RecordOp::Upsert,
        label: "New device".to_string(),
        subkey_pubkey: req.subkey,
        status: DeviceStatus::Active,
        enrolled_at: crate::account::device_enrolled_at_now(),
    };
    wb.lock_unpoisoned()
        .upsert_account_device_in(scope, &record)
        .map_err(|e| format!("record device: {e:?}"))?;
    leg.set_phase(EnrollPhase::Completed);
    Ok(())
}

async fn run_join_leg(
    leg: Arc<Leg>,
    wb: SharedWorkbench,
    scope: String,
    broker: String,
    nd: NewDevice,
) {
    match tokio::time::timeout(
        ENROLL_SESSION_TIMEOUT,
        join_handshake(&leg, &wb, &scope, &broker, &nd),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => leg.fail(e),
        Err(_) => leg.expire(),
    }
}

/// The new-device side of the handshake over the broker: send the request, expose
/// its SAS, await the authorization, then verify + unseal the account key
/// (fail-closed on a bad delegation / foreign root / non-our-subkey / unseal) and
/// persist it locally.
async fn join_handshake(
    leg: &Leg,
    wb: &SharedWorkbench,
    scope: &str,
    broker: &str,
    nd: &NewDevice,
) -> Result<(), String> {
    let mut s = connect_one_shot(broker, token_bytes(&nd.session), OneShotLeg::Joiner)
        .await
        .map_err(|e| format!("broker connect: {e}"))?;
    let req = serde_json::to_vec(&nd.request()).map_err(|e| format!("encode request: {e}"))?;
    write_frame(&mut s, &req)
        .await
        .map_err(|e| format!("send request: {e}"))?;
    // This device's SAS — over its *own* subkey; ready as soon as it is minted.
    leg.set_sas_ready(nd.sas());

    // Blocks until the holder's human confirms and authorizes.
    let auth_bytes = read_frame(&mut s)
        .await
        .map_err(|e| format!("read authorize: {e}"))?;
    let auth: EnrollAuthorize =
        serde_json::from_slice(&auth_bytes).map_err(|e| format!("decode authorize: {e}"))?;
    s.shutdown().await.map_err(|e| format!("close leg: {e}"))?;

    // Verify the delegation chains to the pinned root + unseal the account key.
    let key = nd
        .complete(&auth, now_secs())
        .map_err(|e| format!("enrollment refused: {e:?}"))?;

    let own_subkey = nd.subkey_pubkey().as_str().to_string();
    {
        let mut wb = wb.lock_unpoisoned();
        wb.set_recovered_account_key(key);
        // This device now records itself as an enrolled, trusted device locally.
        let record = DeviceRecord {
            id: device_id(&own_subkey),
            op: RecordOp::Upsert,
            label: "This device".to_string(),
            subkey_pubkey: own_subkey,
            status: DeviceStatus::Active,
            enrolled_at: crate::account::device_enrolled_at_now(),
        };
        wb.upsert_account_device_in(scope, &record)
            .map_err(|e| format!("record device: {e:?}"))?;
    }
    leg.set_phase(EnrollPhase::Completed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    };
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use gaugedesk_core::ids::AuthorityId;
    use gaugedesk_store::Store;
    use gaugedesk_workspace::Instance;

    use super::{EnrollmentTicket, *};
    use crate::{account, open_control_plane, LockUnpoisoned, SharedWorkbench, Workbench};

    /// A bare workbench under a temp root (its own on-disk key store + in-memory store).
    /// The root is pinned to `dir` so the file key store writes under the tempdir, not cwd.
    fn workbench(dir: &std::path::Path) -> SharedWorkbench {
        let instance = Instance::init(dir.join("repo"), dir.join("wt")).unwrap();
        let store = Store::open_in_memory().unwrap();
        let mut wb = Workbench::with_target("inst-test", instance, store);
        wb.root = dir.to_path_buf();
        Arc::new(Mutex::new(wb))
    }

    /// Issue one request against a control-plane router; return the status + parsed JSON.
    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        static KEY: AtomicU64 = AtomicU64::new(1);
        let mut builder = Request::builder().method(method).uri(uri);
        if method != "GET" && method != "HEAD" && method != "OPTIONS" {
            builder = builder.header(
                "idempotency-key",
                format!("device-enroll-test-{}", KEY.fetch_add(1, Ordering::Relaxed)),
            );
        }
        let req = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// Poll a status route until it reports a SAS, returning it.
    async fn poll_sas(app: &Router, uri: &str) -> String {
        let mut last = (StatusCode::INTERNAL_SERVER_ERROR, serde_json::Value::Null);
        for _ in 0..300 {
            let (st, v) = send(app, "GET", uri, None).await;
            last = (st, v.clone());
            if st == StatusCode::OK {
                if let Some(s) = v.get("sas").and_then(|x| x.as_str()) {
                    return s.to_string();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("SAS never became ready at {uri} (last: {last:?})");
    }

    /// Poll a status route until it reports the wanted phase, returning the final body.
    async fn poll_phase(app: &Router, uri: &str, want: &str) -> serde_json::Value {
        for _ in 0..300 {
            let (st, v) = send(app, "GET", uri, None).await;
            if st == StatusCode::OK && v.get("phase").and_then(|x| x.as_str()) == Some(want) {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (_, v) = send(app, "GET", uri, None).await;
        panic!("phase never reached {want} at {uri} (last: {v})");
    }

    /// ACCT-1 mandatory E2E: the enrollment handshake driven through the **HTTP routes**
    /// of two separate `Workbench` instances over a real WSS relay. The holder
    /// hosts + authorizes; the new device joins. On a matched SAS + human confirm the new
    /// device recovers the holder's **account key** (proving the sealed transfer) and the
    /// holder's registry gains the new `DeviceRecord`. Mirrors
    /// `net_relay::the_enrollment_handshake_runs_over_the_real_broker`, one layer up.
    #[tokio::test]
    async fn enrollment_over_http_transfers_the_account_key_and_records_the_device() {
        let live_endpoint = gaugedesk_env::var("LIVE_RELAY_ENDPOINT");
        let (broker_addr, relay) = if let Some(endpoint) = live_endpoint {
            (endpoint, None)
        } else {
            let relay = gaugedesk_relay_transport::test_relay::TestRelay::bind()
                .await
                .unwrap();
            (relay.endpoint().to_owned(), Some(relay))
        };

        let holder_dir = tempfile::tempdir().unwrap();
        let device_dir = tempfile::tempdir().unwrap();
        let holder_wb = workbench(holder_dir.path());
        let device_wb = workbench(device_dir.path());

        // Give the holder a distinct account identity so the recovered key is provably
        // the *holder's* (not the new device's own default), and point it at our broker.
        {
            let mut g = holder_wb.lock_unpoisoned();
            g.authority = AuthorityId::new("holder-account");
            g.set_enroll_broker_addr(broker_addr.clone());
        }
        // Resolve each account's real (seed-derived) key through the same resolver the
        // runtime uses (ADR 0053 §4) — before enrollment, so the device's is still its own.
        let holder_account_key = holder_wb.lock_unpoisoned().account_key();
        let device_default_key = device_wb.lock_unpoisoned().account_key();
        assert_ne!(
            holder_account_key, device_default_key,
            "the two accounts must differ so the transfer is observable"
        );

        let holder_app = open_control_plane(holder_wb.clone());
        let device_app = open_control_plane(device_wb.clone());

        // Holder mints the ticket (session + account root + broker) shown out-of-band.
        let (st, body) = send(&holder_app, "POST", "/account/devices/enroll/host", None).await;
        assert_eq!(st, StatusCode::OK);
        let ticket: EnrollmentTicket = serde_json::from_value(body["ticket"].clone()).unwrap();
        let session = ticket.session.clone();

        // New device consumes the ticket.
        let (st, body) = send(
            &device_app,
            "POST",
            "/account/devices/enroll/join",
            Some(serde_json::json!({ "ticket": ticket })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["session"], session);

        // Both legs pair at the broker and derive a SAS; the human compares them.
        let host_uri = format!("/account/devices/enroll/host/{session}");
        let join_uri = format!("/account/devices/enroll/join/{session}");
        let holder_sas = poll_sas(&holder_app, &host_uri).await;
        let device_sas = poll_sas(&device_app, &join_uri).await;
        assert_eq!(
            holder_sas, device_sas,
            "an honest broker: the SAS matches on both screens"
        );

        // The human confirms the match → the holder authorizes.
        let (st, _) = send(
            &holder_app,
            "POST",
            "/account/devices/enroll/authorize",
            Some(serde_json::json!({ "session": session })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        // Both legs complete.
        poll_phase(&device_app, &join_uri, "completed").await;
        poll_phase(&holder_app, &host_uri, "completed").await;

        // The new device recovered the HOLDER's account key (the sealed transfer worked),
        // not its own default.
        let recovered = device_wb.lock_unpoisoned().recovered_account_key();
        assert_eq!(
            recovered,
            Some(holder_account_key),
            "the new device recovered the holder's account key over the handshake"
        );

        // The holder's trusted-device registry gained the new device.
        let holder_devices = holder_wb
            .lock_unpoisoned()
            .account_devices_in(account::ACCOUNT_SCOPE)
            .unwrap();
        assert_eq!(
            holder_devices.len(),
            1,
            "the holder recorded the new device"
        );
        assert_eq!(holder_devices[0].label, "New device");
        assert!(
            !holder_devices[0].subkey_pubkey.is_empty(),
            "the recorded device carries its subkey pubkey"
        );

        // Keeping the guard alive through both completed phases proves both
        // handshake messages crossed the same binary-WSS fabric.
        drop(relay);
    }

    /// ACCT-1 fail-closed: a **substituting MITM** between the two brokers swaps the new
    /// device's subkey for an attacker's. The two SAS then diverge — the human catches it
    /// and declines (no authorize). No device is enrolled and no key is recovered. This is
    /// the HTTP-drive analogue of the reducer's `CHANNEL_BINDING_HOLDS` / the
    /// `a_substituting_relay_is_caught_by_the_sas` primitive test.
    #[tokio::test]
    async fn a_substituted_subkey_is_caught_by_the_sas_and_refused() {
        use crate::device_enroll::EnrollRequest;
        use crate::net_relay::{read_frame, token_bytes, write_frame};
        use gaugedesk_relay_transport::{connect_one_shot, OneShotLeg};

        // Two brokers: the victim device dials A (a malicious ticket), the honest holder
        // dials B; the attacker bridges A→B, substituting the subkey in flight.
        let broker_a = gaugedesk_relay_transport::test_relay::TestRelay::bind()
            .await
            .unwrap();
        let broker_b = gaugedesk_relay_transport::test_relay::TestRelay::bind()
            .await
            .unwrap();
        let addr_a = broker_a.endpoint().to_owned();
        let addr_b = broker_b.endpoint().to_owned();

        let holder_dir = tempfile::tempdir().unwrap();
        let device_dir = tempfile::tempdir().unwrap();
        let holder_wb = workbench(holder_dir.path());
        let device_wb = workbench(device_dir.path());
        {
            let mut g = holder_wb.lock_unpoisoned();
            g.authority = AuthorityId::new("holder-account");
            g.set_enroll_broker_addr(addr_b.clone());
        }
        let holder_app = open_control_plane(holder_wb.clone());
        let device_app = open_control_plane(device_wb.clone());

        // Holder mints the ticket (broker B). The attacker rewrites the broker to A so the
        // victim dials the attacker; account_root + session are passed through unchanged.
        let (_, body) = send(&holder_app, "POST", "/account/devices/enroll/host", None).await;
        let mut ticket: EnrollmentTicket = serde_json::from_value(body["ticket"].clone()).unwrap();
        let session = ticket.session.clone();
        ticket.broker = addr_a.clone();

        // The attacker's own subkey, substituted for the victim's.
        let attacker_subkey = SigningKey::from_seed(&[0x42; 32])
            .unwrap()
            .public_key()
            .as_str()
            .to_string();
        let mitm_session = session.clone();
        let mitm = tokio::spawn(async move {
            // Read the victim's request off broker A…
            let mut a =
                connect_one_shot(&addr_a, token_bytes(&mitm_session), OneShotLeg::Initializer)
                    .await
                    .unwrap();
            let req_bytes = read_frame(&mut a).await.unwrap();
            let mut req: EnrollRequest = serde_json::from_slice(&req_bytes).unwrap();
            // …substitute the subkey, and forward to the holder over broker B.
            req.subkey = attacker_subkey;
            let mut b = connect_one_shot(&addr_b, token_bytes(&mitm_session), OneShotLeg::Joiner)
                .await
                .unwrap();
            write_frame(&mut b, &serde_json::to_vec(&req).unwrap())
                .await
                .unwrap();
            // Hold the legs open briefly so both sides derive their SAS before we drop.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        // Victim joins via the malicious ticket.
        let (st, _) = send(
            &device_app,
            "POST",
            "/account/devices/enroll/join",
            Some(serde_json::json!({ "ticket": ticket })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        let host_uri = format!("/account/devices/enroll/host/{session}");
        let join_uri = format!("/account/devices/enroll/join/{session}");
        let holder_sas = poll_sas(&holder_app, &host_uri).await;
        let device_sas = poll_sas(&device_app, &join_uri).await;
        // The load-bearing defense: the SAS diverges, so the human declines.
        assert_ne!(
            holder_sas, device_sas,
            "a substituted subkey yields a mismatched SAS the human catches"
        );

        // The human declines (never POSTs authorize). Nothing is enrolled, no key recovered.
        let _ = mitm.await;
        assert!(
            device_wb
                .lock_unpoisoned()
                .recovered_account_key()
                .is_none(),
            "fail-closed: the new device recovered no account key"
        );
        assert!(
            holder_wb
                .lock_unpoisoned()
                .account_devices_in(account::ACCOUNT_SCOPE)
                .unwrap()
                .is_empty(),
            "fail-closed: no device was enrolled without a confirmed SAS"
        );
    }

    /// ACCT-1 / ADR 0053 §4 — the account key is **secret**, reduced to the governance
    /// key's secrecy. It derives from the private root **seed** (not the public authority
    /// id, the retired v1 "loopback double"), so enrolling a real secret seed yields an
    /// account key equal to the seed-derived key — and restoring that seed re-derives it,
    /// while a foreign seed does not.
    #[test]
    fn the_account_key_derives_from_the_governance_seed() {
        use crate::key_store::FileKeyStore;
        let dir = tempfile::tempdir().unwrap();
        let wb = workbench(dir.path());
        let mut g = wb.lock_unpoisoned();
        g.authority = AuthorityId::new("me");
        // Enroll a real (secret) seed for this authority — the production substrate, not the
        // dev loopback default. The resolved account key must be exactly the seed-derived key.
        let secret_seed = [0x2c; 32];
        FileKeyStore::new(dir.path().join("keys"))
            .enroll(g.authority(), &SigningKey::from_seed(&secret_seed).unwrap())
            .unwrap();
        assert_eq!(
            g.account_key(),
            account::account_key_from_seed(&secret_seed)
        );
        // Recovery re-derives the same key; a different (foreign) seed cannot.
        assert_ne!(g.account_key(), account::account_key_from_seed(&[0x2d; 32]));
    }

    /// ACCT-1 / ADR 0053 §4 — durable at-rest adoption. A device that recovered another
    /// root's account key over enrollment keeps it across a restart: it is persisted
    /// (wrapped under this device's own key, never in the clear) and re-adopted on the next
    /// workbench open, so the sealed account state it joined still opens.
    #[test]
    fn a_recovered_account_key_is_adopted_durably_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let recovered = [0x5a; 32];
        {
            let wb = workbench(dir.path());
            let mut g = wb.lock_unpoisoned();
            g.authority = AuthorityId::new("enrolled-device");
            assert_ne!(
                g.account_key(),
                recovered,
                "own seed-derived key, pre-adoption"
            );
            g.set_recovered_account_key(recovered);
            assert_eq!(
                g.account_key(),
                recovered,
                "resolver returns the recovered key"
            );
            // It is never written in the clear.
            let raw = std::fs::read(dir.path().join("account").join("account-key.sealed")).unwrap();
            assert!(
                !raw.windows(recovered.len()).any(|w| w == recovered),
                "the recovered key is wrapped at rest, not plaintext"
            );
        }
        // A fresh workbench over the same root re-adopts it on open (the build path calls
        // this; here we drive it directly on the test double).
        let wb2 = workbench(dir.path());
        let mut g2 = wb2.lock_unpoisoned();
        g2.authority = AuthorityId::new("enrolled-device");
        assert_eq!(g2.recovered_account_key(), None, "not yet restored");
        g2.restore_recovered_account_key();
        assert_eq!(
            g2.account_key(),
            recovered,
            "the recovered account key survived the restart (durable adoption)"
        );
    }
}
