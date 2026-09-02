//! The native carrier: sockets, tasks, the filesystem, and the `ring` provider.
//!
//! Split out from `lib.rs` so a `wasm32` build links none of it (DESK-2). What a
//! leg says and what it accepts lives in [`crate::wire`]; this module only moves
//! bytes.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message;

use crate::wire;
use crate::wire::{
    invalid_data, one_shot_websocket_route, other, websocket_handshake, CertFingerprint,
    OneShotLeg, RouteProof, WebSocketRelayRole, WebSocketRelayRoute, PIN_SNI, TOKEN_LEN, WSS_DATA,
    WSS_FIN, WSS_FIN_ACK, WSS_HANDSHAKE_LEN, WSS_KEEPALIVE_REQUEST, WSS_KEEPALIVE_RESPONSE,
    WSS_MAX_FRAME_BYTES, WSS_READY, WSS_STREAM_BUFFER_BYTES,
};

/// Type-erased ordered byte stream used by the enrollment/federation shells.
pub trait RelayByteStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> RelayByteStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub type BoxedRelayByteStream = Box<dyn RelayByteStream>;

/// How long a leg that has sent its `FIN` waits for the peer's `FIN`/`FIN-ACK`
/// before closing the relay socket anyway. Bounds `shutdown` against a peer that
/// died mid-crossing: without it, a crash on one side would hang the survivor's
/// teardown, and that teardown now runs inside a request handler.
const TEARDOWN_GRACE: Duration = Duration::from_secs(5);

/// How often a durable leg tells the relay it is alive.
///
/// The relay closes a pair that has promised keepalives and then gone silent
/// for `IDLE_MILLIS` — 150s at the edge — so this must stay comfortably under a
/// fifth of it. The ping is served by the relay's auto-response: it never wakes
/// the Durable Object and is never forwarded to the peer.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Ordered byte stream backed by bounded binary WebSocket frames. Closing or
/// dropping it terminates the pump; no reconnect can silently join two TLS
/// streams. Callers retry by establishing a fresh pinned-TLS session.
pub struct WebSocketByteStream {
    stream: DuplexStream,
    // Dropping the handle detaches the pump. Dropping `stream` then closes the
    // duplex side, allowing the pump to flush already accepted bytes and send
    // the WebSocket close in order. Aborting here would discard the final
    // application frame after a successful `shutdown`.
    //
    // `shutdown` drives it to completion instead of detaching, so a caller that
    // shuts down cleanly knows the relay has been told the leg is finished. A
    // route handle is derived from the authority pair alone, so the *next*
    // crossing between the same two authorities is the same route object and
    // arrives at a route still holding two legs if this is left in flight. That
    // is what answered `409 route already has two legs` to a second
    // `/federation/run/place`, with both legs of the previous crossing already
    // shut down at their own ends.
    //
    // An `Option` because a `JoinHandle` may be polled to completion only once;
    // dropping it still detaches, which is what an un-shut-down stream wants.
    pump: Option<tokio::task::JoinHandle<()>>,
}

impl AsyncRead for WebSocketByteStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for WebSocketByteStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    /// Returns once the relay has been told this leg is finished, not merely
    /// once the local side stopped writing.
    ///
    /// Closing the duplex side makes the pump send `FIN`, exchange `FIN-ACK`,
    /// and close the WebSocket — but the pump is a detached task, so a caller
    /// that shut down and moved on used to race its own teardown. The pump
    /// bounds that wait itself (`TEARDOWN_GRACE`), so a dead peer delays this by
    /// seconds rather than indefinitely.
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        // Every field is `Unpin`, so the projection is a plain borrow.
        let this = self.get_mut();
        std::task::ready!(std::pin::Pin::new(&mut this.stream).poll_shutdown(cx))?;
        let Some(pump) = this.pump.as_mut() else {
            return std::task::Poll::Ready(Ok(()));
        };
        // A pump that panicked or was cancelled still means the leg is over, so
        // the join result is deliberately not an error here.
        let _joined = std::task::ready!(std::future::Future::poll(std::pin::Pin::new(pump), cx));
        this.pump = None;
        std::task::Poll::Ready(Ok(()))
    }
}

/// A dial that failed, and whether waiting could change the answer.
struct DialRefusal {
    error: std::io::Error,
    transient: bool,
}

/// Does this upgrade status mean "not yet" rather than "no"?
///
/// `409` is the relay refusing a third leg. It is inherently a *momentary*
/// answer: the relay decides from socket state that lags the peer's close, so a
/// route holding two live legs now may hold none a few hundred milliseconds
/// later. `routeAdmitsLeg` on the relay narrowed that window by discounting
/// sockets already closing, but no admission check can close it — there is
/// always an interval between a peer hanging up and the runtime saying so.
///
/// Retrying is safe as well as correct. A refused dial creates no route state,
/// and a genuine mismatch answers differently: a durable pair on this handle is
/// refused as a family mismatch, not a conflict.
fn upgrade_is_transient(status: tokio_tungstenite::tungstenite::http::StatusCode) -> bool {
    // Through tungstenite's re-export, so the type is by construction the one
    // its error carries rather than a second `http` version that merely looks
    // the same.
    status == tokio_tungstenite::tungstenite::http::StatusCode::CONFLICT
}

pub async fn connect_websocket_stream(
    route: &WebSocketRelayRoute,
    role: WebSocketRelayRole,
) -> std::io::Result<WebSocketByteStream> {
    dial_leg(route, role).await.map_err(|refusal| refusal.error)
}

async fn dial_leg(
    route: &WebSocketRelayRoute,
    role: WebSocketRelayRole,
) -> Result<WebSocketByteStream, DialRefusal> {
    let handshake = websocket_handshake(route, role).map_err(|error| DialRefusal {
        error,
        transient: false,
    })?;
    let url = route.url().map_err(|error| DialRefusal {
        error,
        transient: false,
    })?;
    let (socket, _) = match tokio_tungstenite::connect_async(url).await {
        Ok(connected) => connected,
        Err(error) => {
            // Read the status from the typed response rather than the rendered
            // message. Matching "409" in the text would also match a route
            // handle or a port that happened to contain those digits, and the
            // rendering is tungstenite's to change.
            let transient = match &error {
                tokio_tungstenite::tungstenite::Error::Http(response) => {
                    upgrade_is_transient(response.status())
                }
                _ => false,
            };
            return Err(DialRefusal {
                error: other(format!("connect relay WebSocket: {error}")),
                transient,
            });
        }
    };
    websocket_stream_from_socket(socket, handshake, role.sends_keepalives())
        .await
        .map_err(|error| {
            // Pairing refusals arrive as close frames once the socket is up.
            // Two are ordering races the joiner has always retried: it reached
            // the route before the initializer created or advanced it.
            let text = error.to_string();
            let transient = text.contains("only an initializer may create a route")
                || text.contains("only an initializer may advance a route");
            DialRefusal { error, transient }
        })
}

/// Dial a relay leg, waiting out a refusal that only means "not yet".
///
/// Both roles, deliberately. The joiner retried the two ordering races and the
/// initializer retried nothing at all, so a `409` — the one refusal that clears
/// on its own — was fatal for the role that meets it most. `/federation/run/place`
/// is the initializer, and it failed the whole federated run on a condition that
/// would have gone away in a few hundred milliseconds.
async fn connect_relay_leg(
    route: &WebSocketRelayRoute,
    role: WebSocketRelayRole,
) -> std::io::Result<WebSocketByteStream> {
    let mut delay = Duration::from_millis(25);
    for attempt in 0..8 {
        match dial_leg(route, role).await {
            Ok(stream) => return Ok(stream),
            Err(refusal) if attempt < 7 && refusal.transient => {
                sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(400));
            }
            Err(refusal) => return Err(refusal.error),
        }
    }
    unreachable!("bounded relay dial loop always returns")
}

/// Connect a bounded enrollment/federation leg through the canonical WSS
/// fabric. There is no raw-socket fallback; hermetic tests use the same WSS
/// contract over a loopback listener.
pub async fn connect_one_shot(
    endpoint: &str,
    token: [u8; TOKEN_LEN],
    leg: OneShotLeg,
) -> std::io::Result<BoxedRelayByteStream> {
    let route = one_shot_websocket_route(endpoint, token)?;
    let role = match leg {
        OneShotLeg::Initializer => WebSocketRelayRole::Source,
        OneShotLeg::Joiner => WebSocketRelayRole::Target,
    };
    connect_relay_leg(&route, role)
        .await
        .map(|stream| Box::new(stream) as BoxedRelayByteStream)
}

async fn websocket_stream_from_socket<S>(
    mut socket: tokio_tungstenite::WebSocketStream<S>,
    handshake: [u8; WSS_HANDSHAKE_LEN],
    keepalive: bool,
) -> std::io::Result<WebSocketByteStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    socket
        .send(Message::Binary(handshake.to_vec().into()))
        .await
        .map_err(|error| other(format!("send relay handshake: {error}")))?;
    let ready = timeout(Duration::from_secs(35), socket.next())
        .await
        .map_err(|_| other("relay pairing timed out".to_owned()))?
        .ok_or_else(|| other("relay closed before pairing".to_owned()))?
        .map_err(|error| other(format!("read relay pairing: {error}")))?;
    match ready {
        Message::Binary(bytes) if bytes.as_ref() == WSS_READY => {}
        Message::Close(Some(frame)) => {
            return Err(other(format!("relay refused pairing: {}", frame.reason)));
        }
        _ => return Err(invalid_data("relay returned an invalid pairing response")),
    }

    let (application, mut pump_side) = tokio::io::duplex(WSS_STREAM_BUFFER_BYTES);
    let pump = tokio::spawn(async move {
        let mut outgoing = vec![0u8; WSS_MAX_FRAME_BYTES - 1];
        let mut sent_fin = false;
        let mut received_fin = false;
        let mut fin_acknowledged = false;
        // Set once this side has sent its `FIN`. `shutdown` waits on this task
        // now, so a peer that died mid-crossing must not be able to hold the
        // waiter open: after the grace the socket closes regardless, which is
        // what tells the relay the leg is free.
        let mut teardown_deadline = None;
        // `None` for a one-shot crossing, which is bounded by its own expiry.
        let mut keepalive_at = keepalive.then(|| tokio::time::Instant::now() + KEEPALIVE_INTERVAL);
        loop {
            if sent_fin && received_fin && fin_acknowledged {
                let _ = socket.close(None).await;
                break;
            }
            tokio::select! {
                () = async {
                    match teardown_deadline {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                } => {
                    let _ = socket.close(None).await;
                    break;
                }
                // Only a leg that set the handshake flag speaks here, because
                // only such a leg is judged on its silence. Stops once this side
                // has sent its `FIN`: the leg is closing, and a ping after that
                // says nothing useful.
                () = async {
                    match keepalive_at {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                }, if !sent_fin => {
                    keepalive_at = Some(tokio::time::Instant::now() + KEEPALIVE_INTERVAL);
                    if socket
                        .send(Message::Text(WSS_KEEPALIVE_REQUEST.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                read = pump_side.read(&mut outgoing), if !sent_fin => {
                    match read {
                        Ok(0) => {
                            sent_fin = true;
                            teardown_deadline = Some(tokio::time::Instant::now() + TEARDOWN_GRACE);
                            if socket.send(Message::Binary(vec![WSS_FIN].into())).await.is_err() {
                                break;
                            }
                        }
                        Ok(count) => {
                            let mut frame = Vec::with_capacity(count + 1);
                            frame.push(WSS_DATA);
                            frame.extend_from_slice(&outgoing[..count]);
                            if socket.send(Message::Binary(frame.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                incoming = socket.next() => {
                    match incoming {
                        Some(Ok(Message::Binary(bytes))) if !bytes.is_empty() && bytes.len() <= WSS_MAX_FRAME_BYTES => {
                            match bytes[0] {
                                WSS_DATA if !received_fin => {
                                    if pump_side.write_all(&bytes[1..]).await.is_err() {
                                        break;
                                    }
                                }
                                WSS_FIN if bytes.len() == 1 && !received_fin => {
                                    received_fin = true;
                                    let _ = pump_side.shutdown().await;
                                    if socket.send(Message::Binary(vec![WSS_FIN_ACK].into())).await.is_err() {
                                        break;
                                    }
                                }
                                WSS_FIN_ACK if bytes.len() == 1 && sent_fin => {
                                    fin_acknowledged = true;
                                }
                                _ => break,
                            }
                        }
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                        // The relay's auto-response to a keepalive, or — from a
                        // relay that does not serve one — a peer's ping
                        // forwarded verbatim. Text used to fall through to the
                        // catch-all below and tear the leg down, so both had to
                        // become expected before any ping could be sent.
                        Some(Ok(Message::Text(text)))
                            if text.as_str() == WSS_KEEPALIVE_RESPONSE
                                || text.as_str() == WSS_KEEPALIVE_REQUEST => {}
                        _ => break,
                    }
                }
            }
        }
        let _ = pump_side.shutdown().await;
    });
    Ok(WebSocketByteStream {
        stream: application,
        pump: Some(pump),
    })
}

/// A complementary leg may win the network race before its initializer has
/// created the route object. Retry only that explicit refusal, and only before
/// a paired byte stream (and therefore before inner TLS) exists.

#[derive(Clone, Debug)]
pub struct TlsIdentity {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
    fingerprint: CertFingerprint,
}

impl TlsIdentity {
    pub fn generate() -> std::io::Result<Self> {
        let certified = rcgen::generate_simple_self_signed(vec![PIN_SNI.to_owned()])
            .map_err(|error| other(format!("generate relay TLS identity: {error}")))?;
        let cert = certified.cert.der().clone();
        // rcgen 0.14 renamed `CertifiedKey::key_pair` to `signing_key`. Same
        // key, same PKCS#8 DER serialization — the pinned certificate this
        // produces is unchanged.
        let key = certified.signing_key.serialize_der();
        let fingerprint = wire::fingerprint(&cert);
        Ok(Self {
            cert,
            key,
            fingerprint,
        })
    }

    /// Load the persisted identity, generating one only when **both** files are
    /// genuinely absent (a first run). Every peer pins this certificate's
    /// fingerprint, so any other outcome — one file present without the other,
    /// or an unreadable file — fails closed rather than silently regenerating
    /// and breaking every established pairing (DR-0054 Phase A; same contract
    /// as [`HomeRelayConfig::load_or_mint`]).
    pub fn load_or_generate(directory: &Path) -> std::io::Result<Self> {
        let cert_path = directory.join("relay-tls.crt");
        let key_path = directory.join("relay-tls.key");
        match (std::fs::read(&cert_path), std::fs::read(&key_path)) {
            (Ok(cert), Ok(key)) => {
                let cert = CertificateDer::from(cert);
                Ok(Self {
                    fingerprint: wire::fingerprint(&cert),
                    cert,
                    key,
                })
            }
            (Err(cert_error), Err(key_error))
                if cert_error.kind() == std::io::ErrorKind::NotFound
                    && key_error.kind() == std::io::ErrorKind::NotFound =>
            {
                let identity = Self::generate()?;
                std::fs::create_dir_all(directory)?;
                std::fs::write(cert_path, identity.cert.as_ref())?;
                std::fs::write(key_path, &identity.key)?;
                Ok(identity)
            }
            (Err(error), _) | (_, Err(error)) => Err(other(format!(
                "relay TLS identity in {} is unreadable ({error}); refusing to \
                 regenerate over an identity that peers may have pinned",
                directory.display()
            ))),
        }
    }

    pub fn fingerprint(&self) -> CertFingerprint {
        self.fingerprint
    }

    pub(crate) fn server_config(&self) -> std::io::Result<ServerConfig> {
        ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|error| other(format!("relay TLS versions: {error}")))?
        .with_no_client_auth()
        .with_single_cert(
            vec![self.cert.clone()],
            PrivatePkcs8KeyDer::from(self.key.clone()).into(),
        )
        .map_err(|error| other(format!("relay TLS identity: {error}")))
    }
}

#[derive(Clone, Debug)]
pub struct RelayRoute {
    pub endpoint: String,
    pub handle: String,
    pub epoch: u64,
    pub proof: RouteProof,
    pub previous_proof: Option<RouteProof>,
    pub home_fingerprint: CertFingerprint,
}

impl RelayRoute {
    pub fn validate(&self) -> std::io::Result<()> {
        websocket_route(self, self.previous_proof.is_some()).validate()
    }
}

/// Durable local configuration for one logical Home relay route. The opaque
/// handle is stable while the proof rotates; advancing the epoch on that same
/// object makes every previously published locator stale.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeRelayConfig {
    pub endpoint: String,
    pub handle: String,
    pub proof: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_proof: Option<String>,
    pub route_epoch: u64,
}

impl HomeRelayConfig {
    pub fn load_or_mint(directory: &Path, endpoint: &str) -> std::io::Result<Self> {
        validate_endpoint(endpoint)?;
        let path = directory.join("route.json");
        match std::fs::read(&path) {
            Ok(bytes) => {
                let config: Self = serde_json::from_slice(&bytes)
                    .map_err(|error| invalid_data(&format!("parse relay route: {error}")))?;
                config.validate()?;
                if config.endpoint != endpoint {
                    return Err(invalid_data(
                        "configured relay endpoint changed; mint a new route explicitly",
                    ));
                }
                Ok(config)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let config = Self {
                    endpoint: endpoint.to_owned(),
                    handle: mint_secret()?,
                    proof: mint_secret()?,
                    previous_proof: None,
                    route_epoch: 1,
                };
                config.persist(directory)?;
                Ok(config)
            }
            Err(error) => Err(error),
        }
    }

    pub fn rotate(&self, directory: &Path) -> std::io::Result<Self> {
        self.validate()?;
        let config = Self {
            endpoint: self.endpoint.clone(),
            handle: self.handle.clone(),
            proof: mint_secret()?,
            previous_proof: Some(self.proof.clone()),
            route_epoch: self
                .route_epoch
                .checked_add(1)
                .ok_or_else(|| invalid_data("relay route epoch exhausted"))?,
        };
        config.persist(directory)?;
        Ok(config)
    }

    pub fn relay_route(&self, identity: &TlsIdentity) -> std::io::Result<RelayRoute> {
        self.validate()?;
        Ok(RelayRoute {
            endpoint: self.endpoint.clone(),
            handle: self.handle.clone(),
            epoch: self.route_epoch,
            proof: RouteProof::from_base64url(&self.proof)?,
            previous_proof: self
                .previous_proof
                .as_deref()
                .map(RouteProof::from_base64url)
                .transpose()?,
            home_fingerprint: identity.fingerprint(),
        })
    }

    pub fn fingerprint_hex(identity: &TlsIdentity) -> String {
        hex::encode(identity.fingerprint())
    }

    fn validate(&self) -> std::io::Result<()> {
        validate_endpoint(&self.endpoint)?;
        if self.route_epoch == 0 {
            return Err(invalid_data("relay route epoch must be positive"));
        }
        validate_secret("handle", &self.handle)?;
        validate_secret("proof", &self.proof)?;
        if let Some(previous) = &self.previous_proof {
            validate_secret("previous proof", previous)?;
            if self.route_epoch == 1 || previous == &self.proof {
                return Err(invalid_data("relay route has an invalid proof rotation"));
            }
        }
        Ok(())
    }

    fn persist(&self, directory: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(directory)?;
        let path = directory.join("route.json");
        let temporary = directory.join("route.json.tmp");
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| other(format!("serialize relay route: {error}")))?;
        std::fs::write(&temporary, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(temporary, path)
    }
}

fn mint_secret() -> std::io::Result<String> {
    let mut bytes = [0u8; TOKEN_LEN];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| other(format!("mint relay route secret: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn validate_endpoint(endpoint: &str) -> std::io::Result<()> {
    let route = WebSocketRelayRoute {
        endpoint: endpoint.to_owned(),
        handle: URL_SAFE_NO_PAD.encode([1; 32]),
        epoch: 1,
        proof: RouteProof::new([1; 32]),
        previous_proof: None,
    };
    route.validate()
}

fn validate_secret(name: &str, value: &str) -> std::io::Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_data(&format!("relay route {name} is not base64url")))?;
    if bytes.len() != TOKEN_LEN {
        return Err(invalid_data(&format!(
            "relay route {name} must contain 32 bytes"
        )));
    }
    Ok(())
}

fn websocket_route(route: &RelayRoute, include_previous: bool) -> WebSocketRelayRoute {
    WebSocketRelayRoute {
        endpoint: route.endpoint.clone(),
        handle: route.handle.clone(),
        epoch: route.epoch,
        proof: route.proof,
        previous_proof: include_previous.then_some(route.previous_proof).flatten(),
    }
}

async fn connect_home_stream(route: &RelayRoute) -> std::io::Result<WebSocketByteStream> {
    let ordinary =
        connect_websocket_stream(&websocket_route(route, false), WebSocketRelayRole::Home).await;
    match (ordinary, route.previous_proof) {
        (Ok(stream), _) => Ok(stream),
        (Err(_), Some(_)) => {
            connect_websocket_stream(&websocket_route(route, true), WebSocketRelayRole::Home).await
        }
        (Err(error), None) => Err(error),
    }
}

/// Park one Home availability leg, accept one pinned TLS client through the
/// blind broker, and proxy it to the co-resident control plane.
pub async fn serve_home_once(
    route: &RelayRoute,
    local_control_plane: SocketAddr,
    identity: &TlsIdentity,
) -> std::io::Result<()> {
    let broker = connect_home_stream(route).await?;
    let mut tunnel = TlsAcceptor::from(Arc::new(identity.server_config()?))
        .accept(broker)
        .await?;
    let mut local = TcpStream::connect(local_control_plane).await?;
    tokio::io::copy_bidirectional(&mut tunnel, &mut local).await?;
    Ok(())
}

/// Replenish a Home availability leg after every completed tunnel. Failures use
/// bounded exponential backoff; a relay outage changes availability only.
pub async fn serve_home_forever(
    route: RelayRoute,
    local_control_plane: SocketAddr,
    identity: TlsIdentity,
) -> std::io::Result<()> {
    let mut delay = Duration::from_millis(100);
    loop {
        match serve_home_once(&route, local_control_plane, &identity).await {
            Ok(()) => delay = Duration::from_millis(100),
            Err(_) => {
                sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(10));
            }
        }
    }
}

/// The availability loop over a **rotatable** locator (DESK-5b).
///
/// Rotation is initializer-only and one step, and it takes effect at the relay
/// the moment the new proof is installed — so the loop must pick the new route
/// up rather than keep parking legs on a dead epoch. Each attempt reads the
/// latest route, and a rotation while a leg is parked interrupts that leg so the
/// next attempt uses the new proof. Republishing the rotated locator is the
/// caller's job, because only the caller knows the account it publishes under.
pub async fn serve_home_supervised(
    mut routes: tokio::sync::watch::Receiver<RelayRoute>,
    local_control_plane: SocketAddr,
    identity: TlsIdentity,
) -> std::io::Result<()> {
    let mut delay = Duration::from_millis(100);
    loop {
        let route = routes.borrow_and_update().clone();
        let outcome = tokio::select! {
            served = serve_home_once(&route, local_control_plane, &identity) => Some(served),
            // A rotation supersedes the parked leg: its proof is already stale.
            changed = routes.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                None
            }
        };
        match outcome {
            Some(Ok(())) | None => delay = Duration::from_millis(100),
            Some(Err(_)) => {
                sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(10));
            }
        }
    }
}

async fn connect_client(
    route: &RelayRoute,
) -> std::io::Result<tokio_rustls::client::TlsStream<WebSocketByteStream>> {
    let broker =
        connect_relay_leg(&websocket_route(route, false), WebSocketRelayRole::Client).await?;
    // The pin and the configuration are the portable half; only the provider is
    // this carrier's choice (ADR 0130 §4 — `ring` here, pure-Rust on wasm32).
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = wire::pinned_client_config(route.home_fingerprint, provider)?;
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(PIN_SNI)
        .map_err(|error| other(format!("relay TLS server name: {error}")))?;
    TlsConnector::from(Arc::new(config))
        .connect(name, broker)
        .await
}

/// Carry one accepted loopback HTTP/SSE connection through the pinned Home
/// tunnel. Home admission still occurs in the carried HTTP protocol.
pub async fn serve_client_once(route: &RelayRoute, mut loopback: TcpStream) -> std::io::Result<()> {
    let mut tunnel = connect_client(route).await?;
    tokio::io::copy_bidirectional(&mut loopback, &mut tunnel).await?;
    Ok(())
}

/// Bind an ephemeral device-loopback endpoint. Each accepted keep-alive/SSE
/// socket receives a fresh Home/client rendezvous tunnel.
pub async fn bind_client_loopback(
    route: RelayRoute,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    route.validate()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            if !peer.ip().is_loopback() {
                continue;
            }
            let route = route.clone();
            tokio::spawn(async move {
                let _ = serve_client_once(&route, stream).await;
            });
        }
    });
    Ok((address, task))
}

/// Wrap an ordered byte stream in a TLS client session **pinned** to one
/// end-entity certificate.
///
/// The same verifier the browser tunnel uses, on the native side. It exists
/// because the browser is not the only client that needs to reach something
/// whose identity is a fingerprint rather than a chain: a Home reaching a peer
/// it holds a pin for — a TokenWright box, say — needs exactly this, and
/// without it the only implementation of "pinned client" in the tree was the
/// wasm one, which is how a page ended up dialling things a Home should dial.
///
/// No chain is built, no name is checked, and no validity window is consulted,
/// because the route carries the pin (ADR 0041). A certificate that does not
/// match fails the handshake, so the stream never carries application bytes.
pub async fn connect_pinned<S>(
    stream: S,
    expected: CertFingerprint,
) -> std::io::Result<tokio_rustls::client::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let verifier = Arc::new(wire::PinnedVerifier::new(expected, provider.clone()));
    let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| other(format!("tls client versions: {error}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(PIN_SNI)
        .map_err(|error| other(format!("tls server name: {error}")))?;
    TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::PinnedVerifier;
    use sha2::{Digest, Sha256};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::ClientConfig;
    use tokio_tungstenite::{accept_async, connect_async};

    fn wss_test_route(epoch: u64) -> WebSocketRelayRoute {
        WebSocketRelayRoute {
            endpoint: "wss://relay.example".to_owned(),
            handle: URL_SAFE_NO_PAD.encode([3u8; 32]),
            epoch,
            proof: RouteProof::new([7; 32]),
            previous_proof: None,
        }
    }

    async fn test_relay() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (first_tcp, _) = listener.accept().await.unwrap();
            let mut first = accept_async(first_tcp).await.unwrap();
            let (second_tcp, _) = listener.accept().await.unwrap();
            let mut second = accept_async(second_tcp).await.unwrap();
            let first_header = first.next().await.unwrap().unwrap().into_data();
            let second_header = second.next().await.unwrap().unwrap().into_data();
            assert_eq!(first_header[10], WebSocketRelayRole::Home as u8);
            assert_eq!(second_header[10], WebSocketRelayRole::Client as u8);
            first
                .send(Message::Binary(WSS_READY.to_vec().into()))
                .await
                .unwrap();
            second
                .send(Message::Binary(WSS_READY.to_vec().into()))
                .await
                .unwrap();
            let (mut first_sink, mut first_source) = first.split();
            let (mut second_sink, mut second_source) = second.split();
            loop {
                tokio::select! {
                    message = first_source.next() => match message {
                        Some(Ok(Message::Binary(bytes))) => {
                            second_sink.send(Message::Binary(bytes)).await.unwrap();
                        }
                        _ => break,
                    },
                    message = second_source.next() => match message {
                        Some(Ok(Message::Binary(bytes))) => {
                            first_sink.send(Message::Binary(bytes)).await.unwrap();
                        }
                        _ => break,
                    },
                }
            }
        });
        (format!("ws://{address}"), task)
    }

    fn durable_test_route(endpoint: String, home_fingerprint: CertFingerprint) -> RelayRoute {
        RelayRoute {
            endpoint,
            handle: URL_SAFE_NO_PAD.encode([3; 32]),
            epoch: 1,
            proof: RouteProof::new([7; 32]),
            previous_proof: None,
            home_fingerprint,
        }
    }

    #[test]
    fn websocket_handshake_matches_the_fixed_edge_contract() {
        let route = wss_test_route(9);
        let frame = websocket_handshake(&route, WebSocketRelayRole::Home).unwrap();
        assert_eq!(&frame[..8], b"GWRWSS1\n");
        assert_eq!(u16::from_be_bytes(frame[8..10].try_into().unwrap()), 1);
        assert_eq!(frame[10], WebSocketRelayRole::Home as u8);
        // A Home is durable, so it promises keepalives; the edge accepts the bit
        // and holds a pair to it only when both legs set it.
        assert_eq!(frame[11], crate::wire::WSS_KEEPALIVE_FLAG);
        assert_eq!(u64::from_be_bytes(frame[12..20].try_into().unwrap()), 9);
        assert_eq!(&frame[20..52], &[7; 32]);
        assert_eq!(&frame[52..84], &[0; 32]);

        let rotated = WebSocketRelayRoute {
            epoch: 10,
            proof: RouteProof::new([8; 32]),
            previous_proof: Some(RouteProof::new([7; 32])),
            ..route
        };
        let frame = websocket_handshake(&rotated, WebSocketRelayRole::Home).unwrap();
        // Rotation and the keepalive promise are independent bits.
        assert_eq!(frame[11], 1 | crate::wire::WSS_KEEPALIVE_FLAG);
        assert_eq!(&frame[20..52], &[8; 32]);
        assert_eq!(&frame[52..84], &[7; 32]);
        assert!(websocket_handshake(&rotated, WebSocketRelayRole::Client).is_err());
    }

    #[test]
    fn one_shot_routes_bind_the_entire_rendezvous_token() {
        let first = one_shot_websocket_route(
            "wss://relay.gaugewright.com",
            Sha256::digest(b"shared-prefix-that-used-to-be-truncated/first").into(),
        )
        .unwrap();
        let second = one_shot_websocket_route(
            "wss://relay.gaugewright.com",
            Sha256::digest(b"shared-prefix-that-used-to-be-truncated/second").into(),
        )
        .unwrap();
        assert_ne!(first.handle, second.handle);
        assert_ne!(first.proof, second.proof);
    }

    #[test]
    fn tls_identity_generates_once_and_reloads_the_same_fingerprint() {
        let directory = tempfile::tempdir().unwrap();
        let first = TlsIdentity::load_or_generate(directory.path()).unwrap();
        let reloaded = TlsIdentity::load_or_generate(directory.path()).unwrap();
        assert_eq!(
            first.fingerprint(),
            reloaded.fingerprint(),
            "restarts keep the fingerprint peers pinned"
        );
    }

    #[test]
    fn tls_identity_fails_closed_when_only_one_half_is_present() {
        let directory = tempfile::tempdir().unwrap();
        let identity = TlsIdentity::load_or_generate(directory.path()).unwrap();
        let cert_bytes = std::fs::read(directory.path().join("relay-tls.crt")).unwrap();
        std::fs::remove_file(directory.path().join("relay-tls.key")).unwrap();

        let error = TlsIdentity::load_or_generate(directory.path())
            .expect_err("a half-present identity must never be silently regenerated");
        assert!(
            error.to_string().contains("refusing to regenerate"),
            "unexpected error: {error}"
        );
        assert_eq!(
            std::fs::read(directory.path().join("relay-tls.crt")).unwrap(),
            cert_bytes,
            "the surviving certificate is untouched, so the pinned fingerprint {} stays recoverable",
            hex::encode(identity.fingerprint()),
        );
    }

    #[tokio::test]
    async fn public_raw_relay_endpoints_are_not_a_runtime_fallback() {
        let error = connect_one_shot("192.0.2.1:7900", [4; TOKEN_LEN], OneShotLeg::Initializer)
            .await
            .err()
            .expect("a public raw endpoint must be refused");
        assert!(error.to_string().contains("loopback"));
    }

    #[tokio::test]
    async fn fragmented_websocket_frames_preserve_the_inner_pinned_tls_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (first_tcp, _) = listener.accept().await.unwrap();
            let mut first = accept_async(first_tcp).await.unwrap();
            let (second_tcp, _) = listener.accept().await.unwrap();
            let mut second = accept_async(second_tcp).await.unwrap();
            let first_header = first.next().await.unwrap().unwrap().into_data();
            let second_header = second.next().await.unwrap().unwrap().into_data();
            assert_eq!(first_header.len(), WSS_HANDSHAKE_LEN);
            assert_eq!(second_header.len(), WSS_HANDSHAKE_LEN);
            assert_ne!(first_header[10], second_header[10]);
            first
                .send(Message::Binary(WSS_READY.to_vec().into()))
                .await
                .unwrap();
            second
                .send(Message::Binary(WSS_READY.to_vec().into()))
                .await
                .unwrap();
            let (mut first_sink, mut first_source) = first.split();
            let (mut second_sink, mut second_source) = second.split();
            loop {
                tokio::select! {
                    message = first_source.next() => match message {
                        Some(Ok(Message::Binary(bytes))) => {
                            if bytes.first() == Some(&WSS_DATA) {
                                for fragment in bytes[1..].chunks(17) {
                                    let mut frame = vec![WSS_DATA];
                                    frame.extend_from_slice(fragment);
                                    second_sink.send(Message::Binary(frame.into())).await.unwrap();
                                }
                            } else {
                                second_sink.send(Message::Binary(bytes)).await.unwrap();
                            }
                        }
                        _ => break,
                    },
                    message = second_source.next() => match message {
                        Some(Ok(Message::Binary(bytes))) => {
                            if bytes.first() == Some(&WSS_DATA) {
                                for fragment in bytes[1..].chunks(23) {
                                    let mut frame = vec![WSS_DATA];
                                    frame.extend_from_slice(fragment);
                                    first_sink.send(Message::Binary(frame.into())).await.unwrap();
                                }
                            } else {
                                first_sink.send(Message::Binary(bytes)).await.unwrap();
                            }
                        }
                        _ => break,
                    },
                }
            }
        });

        let route = wss_test_route(1);
        let home_handshake = websocket_handshake(&route, WebSocketRelayRole::Home).unwrap();
        let client_handshake = websocket_handshake(&route, WebSocketRelayRole::Client).unwrap();
        let websocket_url = format!("ws://{address}/v1/relay/{}", route.handle);
        let home_connect = async {
            let (socket, _) = connect_async(&websocket_url).await.unwrap();
            let stream = websocket_stream_from_socket(
                socket,
                home_handshake,
                WebSocketRelayRole::Home.sends_keepalives(),
            )
            .await
            .unwrap();
            stream
        };
        let client_connect = async {
            let (socket, _) = connect_async(&websocket_url).await.unwrap();
            let stream = websocket_stream_from_socket(
                socket,
                client_handshake,
                WebSocketRelayRole::Client.sends_keepalives(),
            )
            .await
            .unwrap();
            stream
        };
        let (home_stream, client_stream) = tokio::join!(home_connect, client_connect);

        let identity = TlsIdentity::generate().unwrap();
        let expected = identity.fingerprint();
        let home_tls =
            TlsAcceptor::from(Arc::new(identity.server_config().unwrap())).accept(home_stream);
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinnedVerifier::new(expected, provider.clone()));
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let client_tls = TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from(PIN_SNI).unwrap(), client_stream);
        let (home_tls, client_tls) = tokio::join!(home_tls, client_tls);
        let mut home_tls = home_tls.unwrap();
        let mut client_tls = client_tls.unwrap();

        let request = vec![0x5a; 8 * 1024 + 19];
        client_tls.write_all(&request).await.unwrap();
        client_tls.flush().await.unwrap();
        let mut received = vec![0; request.len()];
        home_tls.read_exact(&mut received).await.unwrap();
        assert_eq!(received, request);

        home_tls.write_all(b"fragment-safe").await.unwrap();
        home_tls.flush().await.unwrap();
        let mut response = [0; 13];
        client_tls.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"fragment-safe");
        drop(client_tls);
        drop(home_tls);
        relay.abort();
    }

    #[tokio::test]
    async fn loopback_http_crosses_the_blind_pinned_home_tunnel() {
        let (endpoint, relay) = if let Some(endpoint) = gaugedesk_env::var("LIVE_RELAY_ENDPOINT") {
            (endpoint, None)
        } else {
            let (endpoint, relay) = test_relay().await;
            (endpoint, Some(relay))
        };

        let control_plane = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_plane_address = control_plane.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = control_plane.accept().await.unwrap();
            let mut request = [0u8; 36];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"GET /health HTTP/1.1\r\nHost: home\r\n\r\n");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let identity = TlsIdentity::generate().unwrap();
        let route = durable_test_route(endpoint, identity.fingerprint());
        let home_route = route.clone();
        tokio::spawn(async move {
            serve_home_once(&home_route, control_plane_address, &identity)
                .await
                .unwrap();
        });
        let (loopback_address, loopback_task) = bind_client_loopback(route).await.unwrap();
        let mut client = TcpStream::connect(loopback_address).await.unwrap();
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: home\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        loopback_task.abort();
        if let Some(relay) = relay {
            relay.abort();
        }
    }

    #[tokio::test]
    async fn a_wrong_home_pin_fails_before_http_reaches_the_home() {
        let (endpoint, relay) = test_relay().await;
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let identity = TlsIdentity::generate().unwrap();
        let home_route = durable_test_route(endpoint, identity.fingerprint());
        let client_route = RelayRoute {
            home_fingerprint: [7; 32],
            ..home_route.clone()
        };
        let home = tokio::spawn(async move {
            serve_home_once(&home_route, local.local_addr().unwrap(), &identity).await
        });

        let loopback = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = loopback.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let (stream, _) = loopback.accept().await.unwrap();
            serve_client_once(&client_route, stream).await
        });
        let mut caller = TcpStream::connect(address).await.unwrap();
        caller.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        assert!(client.await.unwrap().is_err());
        assert!(home.await.unwrap().is_err());
        relay.abort();
    }

    #[tokio::test]
    #[ignore = "requires GAUGEDESK_LIVE_RELAY_ENDPOINT"]
    async fn live_route_rotation_retires_the_stale_locator() {
        let endpoint = gaugedesk_env::var("LIVE_RELAY_ENDPOINT").expect("live relay endpoint");
        let mut handle = [0u8; 32];
        getrandom::getrandom(&mut handle).unwrap();
        let first = RelayRoute {
            endpoint,
            handle: URL_SAFE_NO_PAD.encode(handle),
            epoch: 1,
            proof: RouteProof::new([7; 32]),
            previous_proof: None,
            home_fingerprint: [0; 32],
        };
        let first_home = connect_home_stream(&first);
        let first_client_route = websocket_route(&first, false);
        let first_client = connect_relay_leg(&first_client_route, WebSocketRelayRole::Client);
        let (first_home, first_client) = tokio::join!(first_home, first_client);
        let mut first_home = first_home.unwrap();
        let mut first_client = first_client.unwrap();
        first_client.write_all(b"epoch-one").await.unwrap();
        let mut epoch_one = [0; 9];
        first_home.read_exact(&mut epoch_one).await.unwrap();
        assert_eq!(&epoch_one, b"epoch-one");
        first_home.shutdown().await.unwrap();
        first_client.shutdown().await.unwrap();
        drop(first_home);
        drop(first_client);
        sleep(Duration::from_millis(50)).await;

        let rotated = RelayRoute {
            epoch: 2,
            proof: RouteProof::new([8; 32]),
            previous_proof: Some(RouteProof::new([7; 32])),
            ..first.clone()
        };
        let rotated_home = connect_home_stream(&rotated);
        let rotated_client_route = websocket_route(&rotated, false);
        let rotated_client = connect_relay_leg(&rotated_client_route, WebSocketRelayRole::Client);
        let (rotated_home, rotated_client) = tokio::join!(rotated_home, rotated_client);
        let mut rotated_home = rotated_home.unwrap();
        let mut rotated_client = rotated_client.unwrap();
        rotated_client.write_all(b"epoch-two").await.unwrap();
        let mut epoch_two = [0; 9];
        rotated_home.read_exact(&mut epoch_two).await.unwrap();
        assert_eq!(&epoch_two, b"epoch-two");
        rotated_home.shutdown().await.unwrap();
        rotated_client.shutdown().await.unwrap();
        drop(rotated_home);
        drop(rotated_client);
        sleep(Duration::from_millis(50)).await;

        let stale =
            connect_relay_leg(&websocket_route(&first, false), WebSocketRelayRole::Client).await;
        assert!(
            stale.is_err(),
            "the epoch-one locator paired after rotation"
        );
    }

    #[test]
    fn a_home_route_is_stable_across_restart_and_rotates_monotonically() {
        let directory = tempfile::tempdir().unwrap();
        let first = HomeRelayConfig::load_or_mint(directory.path(), "wss://relay.example").unwrap();
        let restarted =
            HomeRelayConfig::load_or_mint(directory.path(), "wss://relay.example").unwrap();
        assert_eq!(first, restarted);
        let rotated = first.rotate(directory.path()).unwrap();
        assert_eq!(rotated.route_epoch, first.route_epoch + 1);
        assert_eq!(rotated.handle, first.handle);
        assert_ne!(rotated.proof, first.proof);
        assert_eq!(
            rotated.previous_proof.as_deref(),
            Some(first.proof.as_str())
        );
        assert_eq!(
            HomeRelayConfig::load_or_mint(directory.path(), "wss://relay.example").unwrap(),
            rotated
        );
    }

    #[test]
    fn malformed_or_implicitly_repointed_routes_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("route.json"), b"{not-json").unwrap();
        assert!(HomeRelayConfig::load_or_mint(directory.path(), "wss://relay.example").is_err());

        let directory = tempfile::tempdir().unwrap();
        HomeRelayConfig::load_or_mint(directory.path(), "wss://relay.example").unwrap();
        assert!(HomeRelayConfig::load_or_mint(directory.path(), "wss://other.example").is_err());
    }

    /// A `409` means "not yet", so a crossing must wait it out rather than fail.
    ///
    /// A rendezvous handle is derived from the authority pair alone, so
    /// consecutive `/federation/run/place` calls in one suite cross the *same*
    /// route object. The relay refuses a third leg from socket state that lags
    /// the peer's close, so the next place can arrive while the previous
    /// crossing's legs are still being reaped — and the answer changes on its
    /// own within a few hundred milliseconds.
    ///
    /// The initializer used to retry nothing at all and the joiner retried only
    /// the two ordering races, so this refusal failed the whole federated run.
    /// `desktop-federation` failed exactly this way in production.
    #[tokio::test]
    async fn a_conflicted_route_is_waited_out_rather_than_failing_the_crossing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            // Two refusals at the upgrade, then the previous crossing's legs are
            // gone and the route admits this one.
            for _ in 0..2 {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2048];
                let _ = tcp.read(&mut request).await.unwrap();
                tcp.write_all(
                    b"HTTP/1.1 409 Conflict\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await
                .unwrap();
                let _ = tcp.shutdown().await;
            }
            let (accepted_tcp, _) = listener.accept().await.unwrap();
            let mut accepted = accept_async(accepted_tcp).await.unwrap();
            let _handshake = accepted.next().await.unwrap().unwrap();
            accepted
                .send(Message::Binary(WSS_READY.to_vec().into()))
                .await
                .unwrap();
            // Hold the leg until the test drops its end.
            while let Some(Ok(message)) = accepted.next().await {
                if message.is_close() {
                    break;
                }
            }
        });

        let endpoint = format!("ws://{address}");
        let crossing = connect_one_shot(&endpoint, [9u8; TOKEN_LEN], OneShotLeg::Initializer).await;
        assert!(
            crossing.is_ok(),
            "a transient 409 failed the crossing: {:?}",
            crossing.err()
        );
        drop(crossing);
        let _ = timeout(Duration::from_secs(5), relay).await;
    }

    /// A clean teardown completes through the `FIN` exchange, not by waiting out
    /// the dead-peer grace.
    ///
    /// Deliberately *not* the regression test for the detached pump: it passes
    /// against the old fire-and-forget `shutdown` too, because the detached
    /// pump still delivered the close, just later than its caller. Checked by
    /// mutation, so the name claims only what it proves.
    /// `a_dead_peer_bounds_the_survivors_teardown` is the test that fails when
    /// `shutdown` stops waiting for the pump.
    ///
    /// What this guards is the cost: `shutdown` now runs inside a request
    /// handler, so a break in `FIN`/`FIN-ACK` handling that quietly routed every
    /// teardown through the grace would put five seconds into every crossing.
    #[tokio::test]
    async fn a_clean_crossing_tears_down_without_waiting_out_the_grace() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
        let relay = tokio::spawn(async move {
            let (source_tcp, _) = listener.accept().await.unwrap();
            let mut source = accept_async(source_tcp).await.unwrap();
            let (target_tcp, _) = listener.accept().await.unwrap();
            let mut target = accept_async(target_tcp).await.unwrap();
            let _ = source.next().await.unwrap().unwrap();
            let _ = target.next().await.unwrap().unwrap();
            source
                .send(Message::Binary(WSS_READY.to_vec().into()))
                .await
                .unwrap();
            target
                .send(Message::Binary(WSS_READY.to_vec().into()))
                .await
                .unwrap();
            // Splice until the source's WebSocket close arrives. That close is
            // the event the next crossing's admission depends on.
            loop {
                tokio::select! {
                    from_source = source.next() => match from_source {
                        Some(Ok(Message::Binary(bytes))) => {
                            target.send(Message::Binary(bytes)).await.unwrap();
                        }
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        _ => {}
                    },
                    from_target = target.next() => match from_target {
                        Some(Ok(Message::Binary(bytes))) => {
                            source.send(Message::Binary(bytes)).await.unwrap();
                        }
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        _ => {}
                    },
                }
            }
            let _ = closed_tx.send(());
        });

        let route = one_shot_websocket_route(&format!("ws://{address}"), [7u8; TOKEN_LEN]).unwrap();
        // Both legs must be in flight together: `READY` is what pairing sends,
        // so connecting them in sequence deadlocks on the first one's wait.
        let (source, target) = tokio::join!(
            connect_websocket_stream(&route, WebSocketRelayRole::Source),
            connect_websocket_stream(&route, WebSocketRelayRole::Target),
        );
        let mut source = source.unwrap();
        let mut target = target.unwrap();

        // Both ends shut down, exactly as a completed crossing does.
        let started = tokio::time::Instant::now();
        let (source_shutdown, target_shutdown) = tokio::join!(source.shutdown(), target.shutdown());
        source_shutdown.unwrap();
        target_shutdown.unwrap();

        // The relay observes the close essentially at once, because it was
        // already sent before shutdown returned. A bound rather than
        // `now_or_never`: the relay is another task and still has to be polled,
        // so an immediate probe would be testing the scheduler.
        tokio::time::timeout(Duration::from_secs(2), closed_rx)
            .await
            .expect("the relay was never told the leg was finished")
            .expect("the relay task ended without reporting the close");
        // And it got there by completing the `FIN` exchange, not by waiting out
        // the dead-peer deadline.
        assert!(
            started.elapsed() < TEARDOWN_GRACE,
            "a clean teardown should not need the grace period",
        );
        relay.await.unwrap();
    }

    /// A peer that dies mid-crossing must not hold the survivor's teardown
    /// open: `shutdown` now runs inside a request handler.
    #[tokio::test]
    async fn a_dead_peer_bounds_the_survivors_teardown() {
        tokio::time::pause();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(tcp).await.unwrap();
            let _ = socket.next().await.unwrap().unwrap();
            socket
                .send(Message::Binary(WSS_READY.to_vec().into()))
                .await
                .unwrap();
            // Never answers the `FIN`: the peer is gone.
            std::future::pending::<()>().await;
        });

        let route = one_shot_websocket_route(&format!("ws://{address}"), [9u8; TOKEN_LEN]).unwrap();
        let mut leg = connect_websocket_stream(&route, WebSocketRelayRole::Source)
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        leg.shutdown().await.unwrap();
        let waited = started.elapsed();
        assert!(
            waited >= TEARDOWN_GRACE && waited < TEARDOWN_GRACE * 3,
            "teardown waited {waited:?}, which is not the bounded grace",
        );
        relay.abort();
    }

    /// The relay's answer to a keepalive must not tear the leg down.
    ///
    /// Text used to fall through the pump's catch-all and break the loop, so
    /// shipping the ping without teaching the pump to expect a reply would have
    /// killed every durable route on its first keepalive — the client half
    /// cannot be split any finer than this.
    ///
    /// The interval itself is not exercised here: driving it needs a paused
    /// clock the pump's timer does not observe, and `KEEPALIVE_INTERVAL` is
    /// instead pinned against the edge's idle bound below.
    #[tokio::test]
    async fn a_keepalive_answer_does_not_tear_the_leg_down() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(tcp).await.unwrap();
            let handshake = socket.next().await.unwrap().unwrap().into_data();
            assert_eq!(
                handshake[11] & crate::wire::WSS_KEEPALIVE_FLAG,
                crate::wire::WSS_KEEPALIVE_FLAG,
                "a durable leg must advertise the promise it is about to keep",
            );
            socket
                .send(Message::Binary(WSS_READY.to_vec().into()))
                .await
                .unwrap();
            // Exactly what the edge's auto-response sends back, unprompted so
            // the test does not depend on the ping timer.
            socket
                .send(Message::Text(WSS_KEEPALIVE_RESPONSE.into()))
                .await
                .unwrap();
            // A relay that serves no auto-response forwards a peer's ping
            // verbatim instead; that must be survivable too.
            socket
                .send(Message::Text(WSS_KEEPALIVE_REQUEST.into()))
                .await
                .unwrap();
            // Then behave normally: echo one application frame back.
            while let Some(Ok(message)) = socket.next().await {
                match message {
                    Message::Binary(bytes) if bytes.first() == Some(&WSS_DATA) => {
                        socket.send(Message::Binary(bytes)).await.unwrap();
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });

        let route = WebSocketRelayRoute {
            endpoint: format!("ws://{address}"),
            handle: "A".repeat(43),
            epoch: 1,
            proof: RouteProof::new([5u8; 32]),
            previous_proof: None,
        };
        let mut leg = connect_websocket_stream(&route, WebSocketRelayRole::Home)
            .await
            .unwrap();

        // The leg still carries bytes after both text frames, which it could not
        // do if either had ended the pump.
        leg.write_all(b"still here").await.unwrap();
        leg.flush().await.unwrap();
        let mut echoed = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), leg.read_exact(&mut echoed))
            .await
            .expect("the leg died on a keepalive frame")
            .unwrap();
        assert_eq!(&echoed, b"still here");

        leg.shutdown().await.unwrap();
        relay.abort();
    }

    /// The client speaks often enough for the edge to believe it.
    ///
    /// `IDLE_MILLIS` at the edge is 150s. These two numbers live in different
    /// repositories, so nothing but this stops one from drifting into the
    /// other: an interval above a fifth of the bound would let two ordinary
    /// scheduling delays close a live Home.
    #[test]
    fn the_keepalive_interval_leaves_room_for_missed_pings() {
        const EDGE_IDLE_MILLIS: u128 = 150_000;
        assert!(
            KEEPALIVE_INTERVAL.as_millis() * 5 <= EDGE_IDLE_MILLIS,
            "five keepalives must fit inside the edge's idle bound",
        );
    }
}
