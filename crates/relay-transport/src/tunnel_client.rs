//! One request/response client over the pinned tunnel (DESK-7).
//!
//! Joins [`crate::session::PinnedSession`], which carries bytes, to
//! [`crate::http_stream`], which frames them, so a caller can issue
//! `POST /home/admissions` and read the reply without owning a socket. That is
//! the shape the multi-Home pool consumes as `routeJson`; a browser binding is
//! thin glue over this, and deliberately so — everything with a decision in it
//! lives here, where a native test can drive it against a real pinned server.

use std::collections::BTreeMap;

use crate::http_stream::{encode_request, HttpResponse, ResponseReader};
use crate::session::PinnedSession;
use crate::wire::CertFingerprint;

pub struct TunnelClient {
    session: PinnedSession,
    responses: ResponseReader,
}

impl TunnelClient {
    pub fn new(expected: CertFingerprint) -> std::io::Result<Self> {
        Ok(Self {
            session: PinnedSession::new(expected)?,
            responses: ResponseReader::new(),
        })
    }

    /// The carrier pumps this: feed it ciphertext, take ciphertext from it.
    pub fn session_mut(&mut self) -> &mut PinnedSession {
        &mut self.session
    }

    pub fn handshaking(&self) -> bool {
        self.session.handshaking()
    }

    /// Queue a request. It is encrypted on the session's next pump, so a caller
    /// may send before the handshake finishes without ordering it themselves.
    pub fn send(
        &mut self,
        method: &str,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: Option<&[u8]>,
    ) -> std::io::Result<()> {
        let encoded = encode_request(method, path, headers, body)?;
        // The reader answers responses in the order requests went out, and a
        // reply to HEAD carries no body however it frames one.
        self.responses.sent_request(method);
        self.session.send(&encoded)
    }

    /// Take a complete response, or `None` while more bytes are needed.
    /// Decrypted plaintext is moved into the reader every call, so a response
    /// split across records is reassembled rather than lost.
    pub fn poll(&mut self) -> std::io::Result<Option<HttpResponse>> {
        self.session.pump()?;
        let plaintext = self.session.take_plaintext();
        if !plaintext.is_empty() {
            self.responses.feed(&plaintext);
        }
        self.responses.take()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::TlsIdentity;
    use rustls::server::ServerConnection;
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;

    /// Drive both sides until the client has a response, answering whatever the
    /// client asks with `reply`. This is the journey the pool performs.
    fn exchange(
        client: &mut TunnelClient,
        server: &mut ServerConnection,
        reply: &[u8],
    ) -> Option<HttpResponse> {
        let mut answered = false;
        for _ in 0..64 {
            if let Some(response) = client.poll().expect("poll") {
                return Some(response);
            }
            let out = client.session_mut().take_outgoing();
            if !out.is_empty() {
                let mut cursor = std::io::Cursor::new(out);
                while (cursor.position() as usize) < cursor.get_ref().len() {
                    server.read_tls(&mut cursor).expect("server reads");
                    server.process_new_packets().expect("server processes");
                }
            }
            if !answered {
                let mut request = Vec::new();
                let _ = server.reader().read_to_end(&mut request);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    server.writer().write_all(reply).expect("server writes");
                    answered = true;
                }
            }
            let mut back = Vec::new();
            server.write_tls(&mut back).ok();
            if !back.is_empty() {
                client.session_mut().received(&back);
            }
        }
        None
    }

    fn home() -> (TlsIdentity, rustls::ServerConfig) {
        let directory = tempfile::tempdir().expect("temp");
        let identity = TlsIdentity::load_or_generate(directory.path()).expect("identity");
        let config = identity.server_config().expect("config");
        (identity, config)
    }

    /// The admission call the pool makes, carried end to end over a pinned
    /// tunnel: handshake, request framing, response parsing.
    #[test]
    fn an_admission_request_crosses_the_tunnel_and_its_reply_parses() {
        let (identity, config) = home();
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        let mut client = TunnelClient::new(identity.fingerprint()).expect("client");

        client
            .send("POST", "/home/admissions", &BTreeMap::new(), None)
            .expect("queue");
        let body = br#"{"home":"home:a","admission":"token"}"#;
        let reply = [
            format!(
                "HTTP/1.1 201 Created\r\ncontent-length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
            body,
        ]
        .concat();

        let response = exchange(&mut client, &mut server, &reply).expect("a reply must arrive");
        assert_eq!(response.status, 201);
        assert_eq!(response.body, body);
        assert!(
            !client.handshaking(),
            "traffic implies a completed handshake"
        );
    }

    /// A chunked reply is the streaming case, and it must reassemble across TLS
    /// records rather than surfacing a partial body.
    #[test]
    fn a_chunked_reply_reassembles_across_records() {
        let (identity, config) = home();
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        let mut client = TunnelClient::new(identity.fingerprint()).expect("client");
        client
            .send("GET", "/workspace", &BTreeMap::new(), None)
            .expect("queue");

        let reply = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n";
        let response = exchange(&mut client, &mut server, reply).expect("a reply must arrive");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"abcdefg");
    }

    /// The pin still governs: a client aimed at a different Home gets no reply,
    /// because it never reaches traffic.
    #[test]
    fn a_wrong_pin_carries_no_request_at_all() {
        let (_identity, config) = home();
        let (other, _unused) = home();
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        let mut client = TunnelClient::new(other.fingerprint()).expect("client");
        client
            .send("POST", "/home/admissions", &BTreeMap::new(), None)
            .expect("queue");

        let reply = b"HTTP/1.1 201 Created\r\ncontent-length: 0\r\n\r\n";
        // `poll` surfaces the pin failure; either way no response may appear.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            exchange(&mut client, &mut server, reply)
        }));
        assert!(
            outcome.is_err() || outcome.unwrap().is_none(),
            "a mismatched pin must never yield a response",
        );
    }
}
