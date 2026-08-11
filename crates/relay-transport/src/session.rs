//! The inner pinned TLS session, driven by whatever moves its bytes (DESK-2).
//!
//! This is the half of the browser carrier with nothing browser-specific in it:
//! rustls' unbuffered state machine plus buffers. Keeping it out of the
//! `wasm32`-gated module is what lets a **native** test drive a real handshake
//! against a real Home server config, so the browser's own code path is proven
//! in ordinary CI rather than inferred from a successful compile (DESK-6).

use std::collections::VecDeque;
use std::sync::Arc;

use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::ServerName;
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, InsufficientSizeError,
    UnbufferedStatus,
};

use crate::wire::{other, pinned_client_config, CertFingerprint, PIN_SNI};

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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::TlsIdentity;
    use rustls::server::ServerConnection;
    use std::io::Read as _;
    use std::io::Write as _;

    /// Splice the unbuffered client against a buffered rustls server, the way a
    /// carrier splices it against a WebSocket. Returns once both are quiet.
    fn splice(session: &mut PinnedSession, server: &mut ServerConnection) -> std::io::Result<()> {
        for _ in 0..64 {
            session.pump()?;
            let to_server = session.take_outgoing();
            let mut moved = !to_server.is_empty();
            if moved {
                let mut cursor = std::io::Cursor::new(to_server);
                while (cursor.position() as usize) < cursor.get_ref().len() {
                    server.read_tls(&mut cursor).expect("server reads");
                    server.process_new_packets().expect("server processes");
                }
            }
            let mut to_client = Vec::new();
            server.write_tls(&mut to_client).ok();
            if !to_client.is_empty() {
                session.received(&to_client);
                moved = true;
            }
            if !moved {
                return Ok(());
            }
        }
        Err(other("splice did not settle".to_owned()))
    }

    fn home() -> (TlsIdentity, rustls::ServerConfig) {
        let directory = tempfile::tempdir().expect("temp");
        let identity = TlsIdentity::load_or_generate(directory.path()).expect("identity");
        let config = identity.server_config().expect("server config");
        (identity, config)
    }

    /// The claim DESK-2 could not make from a compile: the browser's own session
    /// completes a real pinned handshake against a real Home and carries traffic.
    #[test]
    fn the_browser_session_completes_a_pinned_handshake_and_carries_traffic() {
        let (identity, config) = home();
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        let mut session = PinnedSession::new(identity.fingerprint()).expect("session");

        splice(&mut session, &mut server).expect("handshake");
        assert!(!session.handshaking(), "the pinned handshake must complete");
        assert!(!session.closed());

        session
            .send(b"GET /home/admissions HTTP/1.1\r\n")
            .expect("queue");
        splice(&mut session, &mut server).expect("client traffic");
        let mut received = Vec::new();
        server
            .reader()
            .read_to_end(&mut received)
            .or_else(|error| match error.kind() {
                std::io::ErrorKind::WouldBlock => Ok(0),
                _ => Err(error),
            })
            .expect("server reads plaintext");
        assert_eq!(
            String::from_utf8_lossy(&received),
            "GET /home/admissions HTTP/1.1\r\n",
            "plaintext must cross the pinned session intact",
        );

        server
            .writer()
            .write_all(b"HTTP/1.1 201 Created\r\n")
            .expect("server writes");
        splice(&mut session, &mut server).expect("server traffic");
        assert_eq!(
            String::from_utf8_lossy(&session.take_plaintext()),
            "HTTP/1.1 201 Created\r\n",
            "the Home's reply must decrypt on the browser side",
        );
    }

    /// The pin is the whole authorization story for the transport: a Home that
    /// is not the pinned one must not complete, whatever it presents.
    #[test]
    fn a_wrong_pin_never_completes_the_handshake() {
        let (_identity, config) = home();
        let (other_identity, _other_config) = home();
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        let mut session = PinnedSession::new(other_identity.fingerprint()).expect("session");

        let error = splice(&mut session, &mut server)
            .expect_err("a mismatched pin must fail the handshake, not stall");
        assert!(
            error.to_string().contains("pin"),
            "the refusal must name the pin, got: {error}",
        );
        assert!(session.handshaking(), "traffic must never open");
        assert!(
            session.take_plaintext().is_empty(),
            "no plaintext may cross an unverified session",
        );
    }
}
