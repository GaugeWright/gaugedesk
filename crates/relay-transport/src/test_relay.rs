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
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::{WebSocketRelayRole, WSS_HANDSHAKE_LEN, WSS_MAX_FRAME_BYTES, WSS_PROTOCOL_VERSION};

const MAGIC: &[u8; 8] = b"GWRWSS1\n";
const READY: &[u8; 8] = b"GWRREADY";
const WAIT: Duration = Duration::from_secs(30);

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
    socket: WebSocketStream<TcpStream>,
}

struct Route {
    epoch: u64,
    proof_hash: [u8; 32],
    family: Family,
    /// Legs waiting for a partner, oldest first. A one-shot route holds one; a
    /// durable route holds several Homes and many clients, as the edge does.
    pending: Vec<Pending>,
}

/// The edge's `MAX_WAITING_HOMES` and `MAX_WAITING_CLIENTS`.
const WAITING_HOMES: usize = 8;
const WAITING_CLIENTS: usize = 64;

struct RelayState {
    next_id: u64,
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
        let served = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let _ = serve_with(listener, served).await;
        });
        Ok(Self {
            endpoint,
            state,
            task,
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
                for mut pending in std::mem::take(&mut route.pending) {
                    let _ = refuse(&mut pending.socket, "relay one-shot legs are disrupted").await;
                }
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

    let pair = {
        let mut guard = state.lock().await;
        if guard.disrupt_one_shot && family(handshake.role) == Family::OneShot {
            drop(guard);
            return refuse(&mut socket, "relay one-shot legs are disrupted").await;
        }
        let id = guard.next_id;
        guard.next_id = guard.next_id.wrapping_add(1);
        let waiting_homes = guard.waiting_homes;
        match admit(&mut guard.routes, handle, handshake) {
            Ok(route) => {
                if let Some(index) = route
                    .pending
                    .iter()
                    .position(|pending| complementary(pending.role, handshake.role))
                {
                    let pending = route.pending.remove(index);
                    Some((pending.socket, socket))
                } else {
                    let same = route
                        .pending
                        .iter()
                        .filter(|pending| pending.role == handshake.role)
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
                    if handshake.role == WebSocketRelayRole::Home {
                        guard.homes_parked += 1;
                    }
                    let route = guard.routes.get_mut(handle).expect("route admitted above");
                    route.pending.push(Pending {
                        id,
                        role: handshake.role,
                        socket,
                    });
                    let state = Arc::clone(&state);
                    let handle = handle.to_owned();
                    tokio::spawn(async move {
                        tokio::time::sleep(WAIT).await;
                        let stale = {
                            let mut guard = state.lock().await;
                            guard.routes.get_mut(&handle).and_then(|route| {
                                let index =
                                    route.pending.iter().position(|pending| pending.id == id)?;
                                Some(route.pending.remove(index))
                            })
                        };
                        if let Some(mut pending) = stale {
                            let _ =
                                refuse(&mut pending.socket, crate::wire::RELAY_WAIT_EXPIRED).await;
                        }
                    });
                    None
                }
            }
            Err(reason) => {
                drop(guard);
                return refuse(&mut socket, reason).await;
            }
        }
    };
    if let Some((left, right)) = pair {
        relay_pair(left, right).await;
    }
    Ok(())
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
    route.pending.clear();
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
    // Bit 1 is the keepalive promise. This relay serves no auto-response and
    // holds nobody to their silence, so it accepts the bit and ignores it —
    // but it must accept it, or every durable leg fails its handshake here
    // while succeeding against the edge.
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

async fn relay_pair(mut left: WebSocketStream<TcpStream>, mut right: WebSocketStream<TcpStream>) {
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
                    if answer_keepalive(&mut left).await { continue; }
                    let _ = right.close(None).await;
                    return;
                }
                if !forward(message, &mut right).await {
                    let _ = right.close(None).await;
                    return;
                }
            }
            message = right.next() => {
                if is_keepalive(&message) {
                    if answer_keepalive(&mut right).await { continue; }
                    let _ = left.close(None).await;
                    return;
                }
                if !forward(message, &mut left).await {
                    let _ = left.close(None).await;
                    return;
                }
            }
        }
    }
}

/// A leg's keepalive, which the edge answers itself and never forwards. A leg
/// pings while it is parked too; those wait here until the leg is paired, and
/// are answered then.
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
