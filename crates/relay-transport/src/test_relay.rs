//! Hermetic WSS relay used by integration and browser acceptance tests.
//!
//! This is deliberately feature-gated out of release builds. It implements the
//! same fixed handshake and blind binary forwarding contract as the managed
//! edge object, so tests never need a raw-TCP compatibility transport.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch, Mutex};
use tokio::time::timeout;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::{WebSocketRelayRole, WSS_HANDSHAKE_LEN, WSS_MAX_FRAME_BYTES, WSS_PROTOCOL_VERSION};

const MAGIC: &[u8; 8] = b"GWRWSS1\n";
const READY: &[u8; 8] = b"GWRREADY";
const WAIT: Duration = Duration::from_secs(30);
const PARKED_WAIT: Duration = Duration::from_secs(600);
const SILENCE: Duration = Duration::from_secs(9);
type Socket = WebSocketStream<TcpStream>;
type Handoff = oneshot::Sender<Socket>;
struct Cancellation {
    route: watch::Receiver<Option<&'static str>>,
    shutdown: watch::Receiver<Option<&'static str>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Durable,
    OneShot,
}

#[derive(Clone, Copy)]
struct Handshake {
    role: WebSocketRelayRole,
    epoch: u64,
    proof_hash: [u8; 32],
    previous_hash: Option<[u8; 32]>,
}

struct Pending {
    id: u64,
    role: WebSocketRelayRole,
    handoff: oneshot::Sender<Handoff>,
    last_heard: Option<u128>,
    started: Instant,
    heard_at: Option<Instant>,
}

struct Route {
    epoch: u64,
    proof_hash: [u8; 32],
    family: Family,
    /// Legs waiting for a partner, oldest first. A one-shot route holds one; a
    /// durable route holds several Homes and many clients, as the edge does.
    pending: Vec<Pending>,
    cancellation: watch::Sender<Option<&'static str>>,
    active: Vec<u64>,
}

/// The edge's `MAX_WAITING_HOMES` and `MAX_WAITING_CLIENTS`.
const WAITING_HOMES: usize = 8;
const WAITING_CLIENTS: usize = 64;

struct RelayState {
    next_id: u64,
    clock: Instant,
    shutdown: watch::Sender<Option<&'static str>>,
    routes: HashMap<String, Route>,
    /// While set, one-shot legs are refused and any already-parked one-shot leg
    /// is evicted. See [`TestRelay::disrupt_one_shot`].
    disrupt_one_shot: bool,
    /// How many Home legs one durable route may hold waiting.
    waiting_homes: usize,
    /// Every Home leg admitted to wait, counted, so a test can see a pool.
    homes_parked: u64,
}

impl Default for RelayState {
    fn default() -> Self {
        Self {
            next_id: 0,
            clock: Instant::now(),
            shutdown: watch::channel(None).0,
            routes: HashMap::new(),
            disrupt_one_shot: false,
            waiting_homes: WAITING_HOMES,
            homes_parked: 0,
        }
    }
}

/// A loopback-only WSS relay. Dropping it aborts the listener task.
pub struct TestRelay {
    endpoint: String,
    state: Arc<Mutex<RelayState>>,
    task: tokio::task::JoinHandle<()>,
    shutdown: watch::Sender<Option<&'static str>>,
}

impl TestRelay {
    pub async fn bind() -> std::io::Result<Self> {
        Self::bind_holding(WAITING_HOMES).await
    }

    /// A relay that lets one durable route hold only `homes` waiting Home
    /// legs — `1` is the edge before Homes parked a pool.
    pub async fn bind_holding(homes: usize) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let endpoint = format!("ws://{address}");
        let state = Arc::new(Mutex::new(RelayState {
            waiting_homes: homes,
            ..RelayState::default()
        }));
        let shutdown = state.lock().await.shutdown.clone();
        let served = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let _ = serve_with(listener, served).await;
        });
        Ok(Self {
            endpoint,
            state,
            task,
            shutdown,
        })
    }

    /// Stop carrying **one-shot** legs, and evict any that are parked.
    ///
    /// One-shot legs are the request/response messages a control plane sends
    /// peer-to-peer — a handoff offer, its reply, a shared-route update. Durable
    /// legs (a Home's parked relay leg and the clients tunnelling to it) are
    /// untouched, so this severs peer messaging without taking the fabric down.
    ///
    /// It exists because a protocol's interesting failures are the ones where a
    /// *single* message is lost while everything else keeps working, and until
    /// now a test could only take the whole broker away — which is a different
    /// failure, and one both parties can see. Evicting parked legs as well as
    /// refusing new ones is what makes the disruption observable promptly rather
    /// than at the far end of the thirty-second wait.
    pub async fn disrupt_one_shot(&self) {
        let mut guard = self.state.lock().await;
        guard.disrupt_one_shot = true;
        let parked: Vec<String> = guard
            .routes
            .iter()
            .filter(|(_, route)| route.family == Family::OneShot && !route.pending.is_empty())
            .map(|(handle, _)| handle.clone())
            .collect();
        for handle in parked {
            if let Some(route) = guard.routes.get_mut(&handle) {
                // Dropping handoff senders tells each exclusive waiter owner
                // to close; no socket I/O happens under the route lock.
                route.pending.clear();
            }
        }
    }

    /// Carry one-shot legs again. A peer that was retrying reconnects on its own.
    pub async fn restore_one_shot(&self) {
        self.state.lock().await.disrupt_one_shot = false;
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// How many Home legs are waiting on the route `handle` right now.
    pub async fn waiting_homes(&self, handle: &str) -> usize {
        self.state
            .lock()
            .await
            .routes
            .get(handle)
            .map_or(0, |route| {
                route
                    .pending
                    .iter()
                    .filter(|pending| pending.role == WebSocketRelayRole::Home)
                    .count()
            })
    }

    /// How many Home legs this relay has admitted to wait, ever.
    pub async fn homes_parked(&self) -> u64 {
        self.state.lock().await.homes_parked
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.shutdown.send_replace(Some("relay closed"));
        self.task.abort();
    }
}

/// Serve the hermetic WSS relay forever on an already-bound listener.
pub async fn serve(listener: TcpListener) -> std::io::Result<()> {
    serve_with(listener, Arc::new(Mutex::new(RelayState::default()))).await
}

async fn serve_with(listener: TcpListener, state: Arc<Mutex<RelayState>>) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = accept_leg(stream, state).await;
        });
    }
}

// `accept_hdr_async` fixes the callback error type to tungstenite's full HTTP
// response; the test server cannot make that third-party variant smaller.
#[allow(clippy::result_large_err)]
async fn accept_leg(stream: TcpStream, state: Arc<Mutex<RelayState>>) -> std::io::Result<()> {
    let path = Arc::new(std::sync::Mutex::new(String::new()));
    let captured = Arc::clone(&path);
    let mut socket = tokio_tungstenite::accept_hdr_async(
        stream,
        move |request: &Request, response: Response| {
            *captured.lock().expect("test relay path lock") = request.uri().path().to_owned();
            Ok(response)
        },
    )
    .await
    .map_err(other)?;
    let path = path.lock().expect("test relay path lock").clone();
    let Some(handle) = path.strip_prefix("/v1/relay/") else {
        return refuse(&mut socket, "not found").await;
    };
    if handle.len() != 43
        || !handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return refuse(&mut socket, "not found").await;
    }

    let message = timeout(WAIT, socket.next())
        .await
        .map_err(|_| invalid("relay handshake timed out"))?
        .ok_or_else(|| invalid("relay closed before handshake"))?
        .map_err(other)?;
    let Message::Binary(bytes) = message else {
        return refuse(&mut socket, "binary relay handshake required").await;
    };
    let handshake = match parse_handshake(&bytes) {
        Ok(handshake) => handshake,
        Err(error) => return refuse(&mut socket, &error.to_string()).await,
    };

    let paired = {
        let mut guard = state.lock().await;
        if guard.disrupt_one_shot && family(handshake.role) == Family::OneShot {
            drop(guard);
            return refuse(&mut socket, "relay one-shot legs are disrupted").await;
        }
        let id = guard.next_id;
        guard.next_id = guard.next_id.wrapping_add(1);
        let waiting_homes = guard.waiting_homes;
        let clock = guard.clock;
        let shutdown = guard.shutdown.subscribe();
        let route = match admit(&mut guard.routes, handle, handshake) {
            Ok(route) => route,
            Err(reason) => {
                drop(guard);
                return refuse(&mut socket, reason).await;
            }
        };
        let cancellation = Cancellation {
            route: route.cancellation.subscribe(),
            shutdown,
        };
        if let Some(index) = pairing_index(&route.pending, handshake.role) {
            let pending = route.pending.remove(index);
            // Registration and removal share the same lock as epoch rotation.
            route.active.push(id);
            Some((id, pending, cancellation))
        } else {
            let same = route
                .pending
                .iter()
                .filter(|p| p.role == handshake.role)
                .count();
            if route.family == Family::OneShot && same > 0 {
                drop(guard);
                return refuse(&mut socket, "relay roles are not complementary").await;
            }
            let limit = match handshake.role {
                WebSocketRelayRole::Home => waiting_homes,
                WebSocketRelayRole::Client => WAITING_CLIENTS,
                _ => 1,
            };
            if same >= limit {
                drop(guard);
                return refuse(&mut socket, "relay waiting capacity reached").await;
            }
            let (handoff, commands) = oneshot::channel();
            route.pending.push(Pending {
                id,
                role: handshake.role,
                handoff,
                last_heard: None,
                started: Instant::now(),
                heard_at: None,
            });
            if handshake.role == WebSocketRelayRole::Home {
                guard.homes_parked += 1;
            }
            drop(guard);
            wait_leg(
                socket,
                commands,
                cancellation,
                Arc::clone(&state),
                handle.to_owned(),
                id,
                clock,
            )
            .await;
            return Ok(());
        }
    };
    if let Some((id, pending, mut cancellation)) = paired {
        let (deliver, received) = oneshot::channel();
        if let Err(deliver) = pending.handoff.send(deliver) {
            drop(deliver);
        }
        let left = tokio::select! {
            biased;
            _ = cancelled(&mut cancellation) => None,
            left = received => left.ok(),
        };
        if let Some(left) = left {
            relay_pair(left, socket, cancellation).await;
        } else {
            let _ = refuse(&mut socket, "relay partner is unavailable or route rotated").await;
        }
        let mut guard = state.lock().await;
        if let Some(route) = guard.routes.get_mut(handle) {
            // Late old-generation cleanup cannot touch a replacement pair.
            if route.epoch == handshake.epoch {
                route.active.retain(|pair| *pair != id);
            }
        }
    }
    Ok(())
}

fn pairing_index(pending: &[Pending], role: WebSocketRelayRole) -> Option<usize> {
    let mut selected: Option<usize> = None;
    for (index, leg) in pending.iter().enumerate() {
        if waiter_expired(leg.started, leg.heard_at, Instant::now())
            || !complementary(leg.role, role)
        {
            continue;
        }
        if selected.is_none()
            || (role == WebSocketRelayRole::Client
                && leg.last_heard > pending[selected.expect("selected waiter")].last_heard)
        {
            selected = Some(index);
        }
    }
    selected
}

fn waiter_expired(started: Instant, heard: Option<Instant>, now: Instant) -> bool {
    match heard {
        Some(heard) => {
            now.duration_since(started) >= PARKED_WAIT || now.duration_since(heard) > SILENCE
        }
        None => now.duration_since(started) >= WAIT,
    }
}

async fn cancelled(receiver: &mut Cancellation) -> &'static str {
    loop {
        if let Some(reason) = *receiver.route.borrow_and_update() {
            return reason;
        }
        if let Some(reason) = *receiver.shutdown.borrow_and_update() {
            return reason;
        }
        tokio::select! {
            result = receiver.route.changed() => { if result.is_err() { return "relay closed"; } }
            result = receiver.shutdown.changed() => { if result.is_err() { return "relay closed"; } }
        }
    }
}

async fn wait_leg(
    mut socket: Socket,
    mut commands: oneshot::Receiver<Handoff>,
    mut cancellation: Cancellation,
    state: Arc<Mutex<RelayState>>,
    handle: String,
    id: u64,
    clock: Instant,
) {
    let started = Instant::now();
    let mut heard = None;
    loop {
        let deadline = heard.map_or(started + WAIT, |at: Instant| {
            (started + PARKED_WAIT).min(at + SILENCE + Duration::from_millis(1))
        });
        tokio::select! {
            biased;
            reason = cancelled(&mut cancellation) => { let _ = refuse(&mut socket, reason).await; break; }
            command = &mut commands => {
                if let Ok(deliver) = command {
                    if let Err(mut abandoned) = deliver.send(socket) { let _ = abandoned.close(None).await; }
                    return;
                }
                let _ = refuse(&mut socket, "relay waiting leg was retired").await;
                break;
            }
            _ = tokio::time::sleep_until(deadline) => {
                if waiter_expired(started, heard, Instant::now()) {
                    let _ = refuse(&mut socket, crate::wire::RELAY_WAIT_EXPIRED).await;
                    break;
                }
            }
            message = socket.next() => {
                if is_keepalive(&message) {
                    let now = Instant::now();
                    heard = Some(now);
                    { let mut guard = state.lock().await;
                      if let Some(leg) = guard.routes.get_mut(&handle).and_then(|route| route.pending.iter_mut().find(|leg| leg.id == id)) {
                          leg.last_heard = Some(now.duration_since(clock).as_millis());
                          leg.heard_at = Some(now);
                      }
                    }
                    let answered = tokio::select! {
                        biased;
                        reason = cancelled(&mut cancellation) => { let _ = refuse(&mut socket, reason).await; false }
                        answered = answer_keepalive(&mut socket) => answered,
                    };
                    if !answered { break; }
                } else {
                    let _ = refuse(&mut socket, "carried data requires an active binary tunnel").await;
                    break;
                }
            }
        }
    }
    let mut guard = state.lock().await;
    if let Some(route) = guard.routes.get_mut(&handle) {
        route.pending.retain(|leg| leg.id != id);
    }
}

fn admit<'a>(
    routes: &'a mut HashMap<String, Route>,
    handle: &str,
    handshake: Handshake,
) -> Result<&'a mut Route, &'static str> {
    let family = family(handshake.role);
    if !routes.contains_key(handle) {
        if !handshake.role.is_initializer() {
            return Err("only an initializer may create a route");
        }
        if handshake.previous_hash.is_some() {
            return Err("a new route cannot present a previous proof");
        }
        routes.insert(
            handle.to_owned(),
            Route {
                epoch: handshake.epoch,
                proof_hash: handshake.proof_hash,
                family,
                pending: Vec::new(),
                cancellation: watch::channel(None).0,
                active: Vec::new(),
            },
        );
        return Ok(routes.get_mut(handle).expect("inserted route"));
    }

    let route = routes.get_mut(handle).expect("known route");
    if route.family != family {
        return Err("route family does not match");
    }
    if handshake.epoch < route.epoch {
        return Err("route epoch is stale");
    }
    if handshake.epoch == route.epoch {
        if handshake.previous_hash.is_some() {
            return Err("current epoch cannot present a previous proof");
        }
        if handshake.proof_hash != route.proof_hash {
            return Err("route proof does not match");
        }
        return Ok(route);
    }
    if !handshake.role.is_initializer() {
        return Err("only an initializer may advance a route");
    }
    if handshake.epoch != route.epoch + 1 {
        return Err("route epoch must advance exactly once");
    }
    if handshake.previous_hash != Some(route.proof_hash) {
        return Err("route rotation proof does not match");
    }
    if handshake.proof_hash == route.proof_hash {
        return Err("route rotation must replace the proof");
    }
    route.epoch = handshake.epoch;
    route.proof_hash = handshake.proof_hash;
    route.cancellation.send_replace(Some("route rotated"));
    route.cancellation = watch::channel(None).0;
    route.pending.clear();
    route.active.clear();
    Ok(route)
}

fn parse_handshake(bytes: &[u8]) -> std::io::Result<Handshake> {
    if bytes.len() != WSS_HANDSHAKE_LEN {
        return Err(invalid("relay handshake has the wrong size"));
    }
    if &bytes[..8] != MAGIC {
        return Err(invalid("relay handshake magic is invalid"));
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != WSS_PROTOCOL_VERSION {
        return Err(invalid("relay protocol version is unsupported"));
    }
    let role = match bytes[10] {
        1 => WebSocketRelayRole::Home,
        2 => WebSocketRelayRole::Client,
        3 => WebSocketRelayRole::Source,
        4 => WebSocketRelayRole::Target,
        _ => return Err(invalid("unknown relay role")),
    };
    let flags = bytes[11];
    // Parked keepalives are read and answered by the exclusive waiter owner.
    // Bit 2 is the promise to report consumption. This relay holds nothing
    // back, so it counts nothing; it takes the reports and forwards none.
    if flags & !(1 | crate::wire::WSS_KEEPALIVE_FLAG | crate::wire::WSS_ACCOUNTING_FLAG) != 0 {
        return Err(invalid("relay handshake flags are invalid"));
    }
    let epoch = u64::from_be_bytes(bytes[12..20].try_into().expect("fixed epoch"));
    if epoch == 0 {
        return Err(invalid("relay route epoch must be positive"));
    }
    let proof: [u8; 32] = bytes[20..52].try_into().expect("fixed proof");
    if proof == [0; 32] {
        return Err(invalid("relay route proof cannot be zero"));
    }
    let previous: [u8; 32] = bytes[52..84].try_into().expect("fixed previous proof");
    let previous_hash = match (flags & 1 != 0, previous == [0; 32]) {
        (false, false) => return Err(invalid("unexpected previous route proof")),
        (true, true) => return Err(invalid("previous route proof cannot be zero")),
        (true, false) if !role.is_initializer() => {
            return Err(invalid("only an initializer may rotate a route"));
        }
        (true, false) => Some(Sha256::digest(previous).into()),
        (false, true) => None,
    };
    Ok(Handshake {
        role,
        epoch,
        proof_hash: Sha256::digest(proof).into(),
        previous_hash,
    })
}

fn family(role: WebSocketRelayRole) -> Family {
    match role {
        WebSocketRelayRole::Home | WebSocketRelayRole::Client => Family::Durable,
        WebSocketRelayRole::Source | WebSocketRelayRole::Target => Family::OneShot,
    }
}

fn complementary(left: WebSocketRelayRole, right: WebSocketRelayRole) -> bool {
    matches!(
        (left, right),
        (WebSocketRelayRole::Home, WebSocketRelayRole::Client)
            | (WebSocketRelayRole::Client, WebSocketRelayRole::Home)
            | (WebSocketRelayRole::Source, WebSocketRelayRole::Target)
            | (WebSocketRelayRole::Target, WebSocketRelayRole::Source)
    )
}

async fn relay_pair(mut left: Socket, mut right: Socket, mut cancellation: Cancellation) {
    let reason = tokio::select! {
        biased;
        reason = cancelled(&mut cancellation) => Some(reason),
        _ = carry_pair(&mut left, &mut right) => None,
    };
    if let Some(reason) = reason {
        let _ = refuse(&mut left, reason).await;
        let _ = refuse(&mut right, reason).await;
    }
}

async fn carry_pair(left: &mut Socket, right: &mut Socket) {
    if left
        .send(Message::Binary(READY.to_vec().into()))
        .await
        .is_err()
        || right
            .send(Message::Binary(READY.to_vec().into()))
            .await
            .is_err()
    {
        return;
    }
    loop {
        tokio::select! {
            message = left.next() => {
                if is_keepalive(&message) {
                    if answer_keepalive(left).await { continue; }
                    let _ = right.close(None).await;
                    return;
                }
                if !forward(message, right).await {
                    let _ = right.close(None).await;
                    return;
                }
            }
            message = right.next() => {
                if is_keepalive(&message) {
                    if answer_keepalive(right).await { continue; }
                    let _ = left.close(None).await;
                    return;
                }
                if !forward(message, left).await {
                    let _ = left.close(None).await;
                    return;
                }
            }
        }
    }
}

/// A leg's keepalive, which the edge answers itself and never forwards. A leg
/// pings while parked too; its exclusive waiter owner answers those immediately.
fn is_keepalive(message: &Option<Result<Message, tokio_tungstenite::tungstenite::Error>>) -> bool {
    matches!(message, Some(Ok(Message::Text(text))) if text.as_str() == crate::wire::WSS_KEEPALIVE_REQUEST)
}

async fn answer_keepalive(socket: &mut WebSocketStream<TcpStream>) -> bool {
    socket
        .send(Message::Text(crate::wire::WSS_KEEPALIVE_RESPONSE.into()))
        .await
        .is_ok()
}

async fn forward(
    message: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
    target: &mut WebSocketStream<TcpStream>,
) -> bool {
    match message {
        // A report of consumption is the relay's, never the partner's: one
        // forwarded would be an unknown frame to the other leg.
        Some(Ok(Message::Binary(bytes))) if crate::wire::parse_credit(&bytes).is_some() => {
            CREDITED.fetch_add(
                u64::from(crate::wire::parse_credit(&bytes).unwrap_or(0)),
                std::sync::atomic::Ordering::Relaxed,
            );
            true
        }
        Some(Ok(Message::Binary(bytes))) if bytes.len() <= WSS_MAX_FRAME_BYTES => {
            target.send(Message::Binary(bytes)).await.is_ok()
        }
        Some(Ok(Message::Ping(bytes))) => target.send(Message::Ping(bytes)).await.is_ok(),
        Some(Ok(Message::Pong(_))) => true,
        _ => false,
    }
}

/// Every byte any leg of any test relay in this process has reported consuming.
pub static CREDITED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn refuse(socket: &mut WebSocketStream<TcpStream>, reason: &str) -> std::io::Result<()> {
    socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: reason.to_owned().into(),
        })))
        .await
        .map_err(other)
}

fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn other(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
#[path = "relay_fidelity_tests.rs"]
mod relay_fidelity_tests;
