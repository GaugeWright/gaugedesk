//! The browser carrier (DESK-2, [ADR 0130](../../../specs/decisions/0130-browser-thin-client-tunnels-the-relay-fabric-in-wasm.md)).
//!
//! A page terminates the **outer** `wss://` itself, as any page does, and runs
//! the **inner** cert-pinned TLS session here. The relay still splices only
//! inner ciphertext, so `RELAY_NO_PAYLOAD_ACCESS` holds for a browser exactly as
//! it holds for a phone — terminating the outer carrier is what every leg
//! already relies on.
//!
//! Nothing about the fabric changes. This sends the same 84-byte handshake in
//! the same `client` role, over [`crate::wire`], and pins by the same end-entity
//! SHA-256. The provider is `ring`, the same one the native carrier uses.
//!
//! rustls is driven through its **unbuffered** API because there is no socket to
//! hand it: the carrier owns the bytes and pumps them.

use std::collections::VecDeque;
use std::sync::Arc;

use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::ServerName;
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, InsufficientSizeError,
    UnbufferedStatus,
};
use wasm_bindgen::JsCast;

use crate::wire::{
    other, pinned_client_config, websocket_handshake, CertFingerprint, WebSocketRelayRole,
    WebSocketRelayRoute, PIN_SNI, WSS_HANDSHAKE_LEN,
};

/// The inner pinned session, driven by whatever moves bytes for it.
///
/// Split from the socket deliberately: the handshake and record handling are
/// testable without a browser, and the `WebSocket` only has to deliver frames.
pub struct PinnedSession {
    connection: UnbufferedClientConnection,
    /// Ciphertext waiting to go out as relay `DATA` frames.
    outgoing: Vec<u8>,
    /// Ciphertext received from the peer and not yet consumed by rustls.
    incoming: Vec<u8>,
    /// Plaintext handed back to the caller in arrival order.
    plaintext: VecDeque<u8>,
    /// Plaintext queued by [`PinnedSession::send`] and not yet encrypted.
    pending_app_data: Vec<u8>,
    handshaking: bool,
    closed: bool,
}

impl PinnedSession {
    /// Begin a session pinned to `expected`. The SNI is the fixed placeholder —
    /// this authenticates by fingerprint, never by name.
    pub fn new(expected: CertFingerprint) -> std::io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = Arc::new(pinned_client_config(expected, provider)?);
        let name = ServerName::try_from(PIN_SNI)
            .map_err(|error| other(format!("relay TLS server name: {error}")))?
            .to_owned();
        let connection = UnbufferedClientConnection::new(config, name)
            .map_err(|error| other(format!("relay TLS client: {error}")))?;
        Ok(Self {
            connection,
            outgoing: Vec::new(),
            incoming: Vec::new(),
            plaintext: VecDeque::new(),
            pending_app_data: Vec::new(),
            handshaking: true,
            closed: false,
        })
    }

    pub fn handshaking(&self) -> bool {
        self.handshaking
    }

    pub fn closed(&self) -> bool {
        self.closed
    }

    /// Feed ciphertext that arrived from the peer.
    pub fn received(&mut self, bytes: &[u8]) {
        self.incoming.extend_from_slice(bytes);
    }

    /// Queue plaintext for the peer. It is encrypted on the next [`Self::pump`].
    pub fn send(&mut self, plaintext: &[u8]) -> std::io::Result<()> {
        if self.closed {
            return Err(other("pinned session is closed".to_owned()));
        }
        self.pending_app_data.extend_from_slice(plaintext);
        Ok(())
    }

    /// Take whatever plaintext has been decrypted so far.
    pub fn take_plaintext(&mut self) -> Vec<u8> {
        self.plaintext.drain(..).collect()
    }

    /// Take ciphertext that must be written to the peer.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outgoing)
    }

    /// Advance the state machine as far as the buffered bytes allow.
    ///
    /// Loops because one call can both consume received records and produce new
    /// ones — a handshake flight is several transitions, not one.
    pub fn pump(&mut self) -> std::io::Result<()> {
        loop {
            // `state` borrows the connection, so anything it produces is written
            // into a local first and appended once that borrow has ended.
            let mut produced: Vec<u8> = Vec::new();
            let mut progressed = false;
            let mut closed = false;
            let mut handshake_done = false;
            let mut decrypted: Vec<u8> = Vec::new();
            let pending = std::mem::take(&mut self.pending_app_data);
            let mut consumed_pending = false;

            let UnbufferedStatus { discard, state } =
                self.connection.process_tls_records(&mut self.incoming);
            let state = state.map_err(|error| other(format!("pinned TLS: {error}")))?;

            match state {
                ConnectionState::EncodeTlsData(mut encode) => {
                    produced = grow(|buffer| encode.encode(buffer).map_err(Grow::encode))?;
                    progressed = true;
                }
                ConnectionState::TransmitTlsData(transmit) => {
                    transmit.done();
                    progressed = true;
                }
                ConnectionState::BlockedHandshake => {}
                ConnectionState::WriteTraffic(mut traffic) => {
                    handshake_done = true;
                    if !pending.is_empty() {
                        produced = grow(|buffer| {
                            traffic.encrypt(&pending, buffer).map_err(Grow::encrypt)
                        })?;
                        consumed_pending = true;
                        progressed = true;
                    }
                }
                ConnectionState::ReadTraffic(mut traffic) => {
                    while let Some(record) = traffic.next_record() {
                        let AppDataRecord { payload, .. } =
                            record.map_err(|error| other(format!("pinned TLS: {error}")))?;
                        decrypted.extend_from_slice(payload);
                    }
                    progressed = true;
                }
                ConnectionState::Closed => closed = true,
                _ => {}
            }

            if discard > 0 {
                self.incoming.drain(..discard);
            }
            if !consumed_pending {
                self.pending_app_data = pending;
            }
            self.outgoing.append(&mut produced);
            self.plaintext.extend(decrypted);
            if handshake_done {
                self.handshaking = false;
            }
            if closed {
                self.closed = true;
                return Ok(());
            }
            if !progressed && discard == 0 {
                return Ok(());
            }
        }
    }
}

/// rustls reports the buffer it needs rather than allocating; grow and retry so
/// a large flight is never silently truncated.
fn grow(mut write: impl FnMut(&mut [u8]) -> Result<usize, Grow>) -> std::io::Result<Vec<u8>> {
    let mut size = 4096;
    loop {
        let mut buffer = vec![0u8; size];
        match write(&mut buffer) {
            Ok(written) => {
                buffer.truncate(written);
                return Ok(buffer);
            }
            Err(Grow::Need(required)) => size = required,
            Err(Grow::Fatal(error)) => return Err(other(format!("pinned TLS encode: {error}"))),
        }
    }
}

/// rustls' two write paths report "buffer too small" through different error
/// types; this is the one thing the growth loop needs from either.
enum Grow {
    Need(usize),
    Fatal(String),
}

impl Grow {
    fn encode(error: EncodeError) -> Self {
        match error {
            EncodeError::InsufficientSize(InsufficientSizeError { required_size }) => {
                Self::Need(required_size)
            }
            other => Self::Fatal(format!("{other}")),
        }
    }

    fn encrypt(error: EncryptError) -> Self {
        match error {
            EncryptError::InsufficientSize(InsufficientSizeError { required_size }) => {
                Self::Need(required_size)
            }
            other => Self::Fatal(format!("{other}")),
        }
    }
}

/// The `client` handshake for a durable Home route — the same 84 bytes every
/// other carrier sends.
pub fn client_handshake(route: &WebSocketRelayRoute) -> std::io::Result<[u8; WSS_HANDSHAKE_LEN]> {
    websocket_handshake(route, WebSocketRelayRole::Client)
}

/// Open the outer carrier. The page terminates this; the relay never sees inside
/// the inner session it carries.
pub fn open_socket(route: &WebSocketRelayRoute) -> std::io::Result<web_sys::WebSocket> {
    let socket = web_sys::WebSocket::new(&route.url()?)
        .map_err(|error| other(format!("open relay WebSocket: {error:?}")))?;
    socket.set_binary_type(web_sys::BinaryType::Arraybuffer);
    Ok(socket)
}

/// Send one binary frame on the carrier.
pub fn send_frame(socket: &web_sys::WebSocket, frame: &[u8]) -> std::io::Result<()> {
    socket
        .send_with_u8_array(frame)
        .map_err(|error| other(format!("send relay frame: {error:?}")))
}

/// Read a binary message event as bytes.
pub fn message_bytes(event: &web_sys::MessageEvent) -> Option<Vec<u8>> {
    let buffer = event.data().dyn_into::<js_sys::ArrayBuffer>().ok()?;
    Some(js_sys::Uint8Array::new(&buffer).to_vec())
}
