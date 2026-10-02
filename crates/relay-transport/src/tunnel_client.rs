//! One request/response client over the pinned tunnel (DESK-7).
//!
//! Joins [`crate::session::PinnedSession`], which carries bytes, to
//! [`crate::http_stream`], which frames them, so a caller can issue
//! `POST /home/admissions` and read the reply without owning a socket. That is
//! the shape the multi-Home pool consumes as `routeJson`; a browser binding is
//! thin glue over this, and deliberately so — everything with a decision in it
//! lives here, where a native test can drive it against a real pinned server.

use std::collections::{BTreeMap, VecDeque};

use crate::http_stream::{
    encode_request, BodyPart, EventReader, HttpResponse, ResponseReader, ServerEvent,
};
use crate::session::PinnedSession;
use crate::wire::CertFingerprint;

pub struct TunnelClient {
    session: PinnedSession,
    responses: ResponseReader,
    /// Responses the reader has yielded and no caller has taken yet.
    ///
    /// A carrier pumps for two reasons — to collect ciphertext to write, and to
    /// look for a reply — and the reader hands each response out exactly once.
    /// Without somewhere to put it, whichever pump happens to decode the last
    /// record destroys the response the other one was waiting for. Holding it
    /// here is what makes the two reasons the same call.
    completed: VecDeque<HttpResponse>,
}

impl TunnelClient {
    pub fn new(expected: CertFingerprint) -> std::io::Result<Self> {
        Ok(Self {
            session: PinnedSession::new(expected)?,
            responses: ResponseReader::new(),
            completed: VecDeque::new(),
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

    /// Advance the session and decode whatever it yields, without taking a
    /// response. This is what a carrier calls when it wants ciphertext: it must
    /// still be able to find a reply afterwards, so anything decoded here is
    /// held rather than returned.
    pub fn pump(&mut self) -> std::io::Result<()> {
        self.session.pump()?;
        let plaintext = self.session.take_plaintext();
        if !plaintext.is_empty() {
            self.responses.feed(&plaintext);
        }
        while let Some(response) = self.responses.take()? {
            self.completed.push_back(response);
        }
        Ok(())
    }

    /// Take a complete response, or `None` while more bytes are needed.
    /// Decrypted plaintext is moved into the reader every call, so a response
    /// split across records is reassembled rather than lost.
    pub fn poll(&mut self) -> std::io::Result<Option<HttpResponse>> {
        self.pump()?;
        Ok(self.completed.pop_front())
    }
}

/// What one poll of a [`TunnelEventStream`] produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamPoll {
    /// The Home accepted the stream. Events follow.
    Opened,
    /// One event with data. Keep-alive comments and events without data are
    /// not reported, exactly as `EventSource` does not dispatch them.
    Event(ServerEvent),
    /// The Home answered with something other than a stream: its status, and
    /// the whole of its body, which carries the reason.
    Refused { status: u16, body: Vec<u8> },
    /// The stream's body ended. Nothing further will arrive on this session.
    Ended,
}

#[derive(Debug)]
enum StreamState {
    AwaitingHead,
    Open,
    Refusing { status: u16, body: Vec<u8> },
    Finished,
}

/// One event stream over its own pinned tunnel (WS-634).
///
/// A Home's `events` responses never end in normal operation, so a stream
/// cannot share a session with [`TunnelClient`], whose calls are answered one
/// whole response at a time: the first stream would hold every later call
/// behind it. A stream is therefore its own crossing — the Home serves up to
/// sixteen at once (DR-0284) — and is read head-then-body as bytes arrive.
pub struct TunnelEventStream {
    session: PinnedSession,
    responses: ResponseReader,
    events: EventReader,
    state: StreamState,
    /// What a pump decoded and no poll has taken yet, for the same reason
    /// [`TunnelClient`] holds completed responses: a carrier pumps for
    /// ciphertext as well as for news, and either may decode the last record.
    ready: VecDeque<StreamPoll>,
}

impl TunnelEventStream {
    /// Begin a session pinned to `expected` and queue `GET path` on it, asking
    /// for an event stream.
    pub fn open(
        expected: CertFingerprint,
        path: &str,
        headers: &BTreeMap<String, String>,
    ) -> std::io::Result<Self> {
        let mut headers = headers.clone();
        headers.insert("accept".to_owned(), "text/event-stream".to_owned());
        let encoded = encode_request("GET", path, &headers, None)?;
        let mut responses = ResponseReader::new();
        responses.sent_request("GET");
        let mut session = PinnedSession::new(expected)?;
        session.send(&encoded)?;
        Ok(Self {
            session,
            responses,
            events: EventReader::new(),
            state: StreamState::AwaitingHead,
            ready: VecDeque::new(),
        })
    }

    /// The carrier pumps this: feed it ciphertext, take ciphertext from it.
    pub fn session_mut(&mut self) -> &mut PinnedSession {
        &mut self.session
    }

    pub fn handshaking(&self) -> bool {
        self.session.handshaking()
    }

    /// Advance the session and decode whatever it yields, without taking it.
    pub fn pump(&mut self) -> std::io::Result<()> {
        self.session.pump()?;
        let plaintext = self.session.take_plaintext();
        if !plaintext.is_empty() {
            self.responses.feed(&plaintext);
        }
        loop {
            match &mut self.state {
                StreamState::AwaitingHead => {
                    let Some(head) = self.responses.take_head()? else {
                        break;
                    };
                    if (200..300).contains(&head.status) {
                        self.state = StreamState::Open;
                        self.ready.push_back(StreamPoll::Opened);
                    } else {
                        self.state = StreamState::Refusing {
                            status: head.status,
                            body: Vec::new(),
                        };
                    }
                }
                StreamState::Open => match self.responses.read_body()? {
                    BodyPart::Chunk(bytes) => {
                        self.events.feed(&bytes)?;
                        while let Some(event) = self.events.take() {
                            if !event.data.is_empty() {
                                self.ready.push_back(StreamPoll::Event(event));
                            }
                        }
                    }
                    BodyPart::End => {
                        self.state = StreamState::Finished;
                        self.ready.push_back(StreamPoll::Ended);
                    }
                    BodyPart::Pending => break,
                },
                StreamState::Refusing { status, body } => match self.responses.read_body()? {
                    BodyPart::Chunk(bytes) => body.extend_from_slice(&bytes),
                    BodyPart::End => {
                        let refused = StreamPoll::Refused {
                            status: *status,
                            body: std::mem::take(body),
                        };
                        self.state = StreamState::Finished;
                        self.ready.push_back(refused);
                    }
                    BodyPart::Pending => break,
                },
                StreamState::Finished => break,
            }
        }
        Ok(())
    }

    /// Take the next thing the stream produced, or `None` while more bytes are
    /// needed.
    pub fn poll(&mut self) -> std::io::Result<Option<StreamPoll>> {
        self.pump()?;
        Ok(self.ready.pop_front())
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

    /// A carrier pumps for ciphertext between reads and polls for a reply, and
    /// which of the two decodes the final record is a matter of timing. If
    /// pumping took the response, the reply would vanish exactly when the whole
    /// exchange fitted in one arrival — which is the common case, and which is
    /// what stalled the browser lane.
    #[test]
    fn pumping_for_ciphertext_does_not_consume_the_response() {
        let (identity, config) = home();
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        let mut client = TunnelClient::new(identity.fingerprint()).expect("client");
        client
            .send("POST", "/home/admissions", &BTreeMap::new(), None)
            .expect("queue");

        let reply = b"HTTP/1.1 201 Created\r\ncontent-length: 2\r\n\r\nhi";
        // Interleave a pump before every poll, the way a carrier that flushes
        // ciphertext after each arrival does.
        let mut answered = false;
        for _ in 0..64 {
            client.pump().expect("pump");
            if let Some(response) = client.poll().expect("poll") {
                assert_eq!(response.status, 201);
                assert_eq!(response.body, b"hi");
                return;
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
        panic!("a response decoded by a pump must survive until it is polled");
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

    /// Shuttle bytes between a stream and a Home until nothing more moves,
    /// collecting everything the stream reports. The Home's side reads the
    /// request once and then writes `reply` in the pieces given.
    fn stream_exchange(
        stream: &mut TunnelEventStream,
        server: &mut ServerConnection,
        pieces: &[&[u8]],
    ) -> (Vec<StreamPoll>, String) {
        let mut seen = Vec::new();
        let mut request = Vec::new();
        let mut pieces = pieces.iter();
        for _ in 0..128 {
            while let Some(polled) = stream.poll().expect("poll") {
                seen.push(polled);
            }
            let out = stream.session_mut().take_outgoing();
            if !out.is_empty() {
                let mut cursor = std::io::Cursor::new(out);
                while (cursor.position() as usize) < cursor.get_ref().len() {
                    server.read_tls(&mut cursor).expect("server reads");
                    server.process_new_packets().expect("server processes");
                }
            }
            let _ = server.reader().read_to_end(&mut request);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                // One piece per round, so the stream sees each as it arrives.
                if let Some(piece) = pieces.next() {
                    server.writer().write_all(piece).expect("server writes");
                }
            }
            let mut back = Vec::new();
            server.write_tls(&mut back).ok();
            if !back.is_empty() {
                stream.session_mut().received(&back);
            }
        }
        (seen, String::from_utf8_lossy(&request).into_owned())
    }

    fn event(data: &str) -> StreamPoll {
        StreamPoll::Event(ServerEvent {
            event: None,
            data: data.to_owned(),
        })
    }

    /// The case this exists for: a Home's event stream never ends, and each
    /// event must arrive while it is still open, carrying the credentials the
    /// Home demands of every work route.
    #[test]
    fn an_event_stream_delivers_each_event_while_it_stays_open() {
        let (identity, config) = home();
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        let headers = BTreeMap::from([(
            "x-gaugewright-home-admission".to_owned(),
            "admitted".to_owned(),
        )]);
        let mut stream =
            TunnelEventStream::open(identity.fingerprint(), "/chats/c1/events", &headers)
                .expect("open");

        let (seen, request) = stream_exchange(
            &mut stream,
            &mut server,
            &[
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
                b"d\r\ndata: first\n\n\r\n",
                // axum's keep-alive: a comment, which no subscriber should see.
                b"3\r\n:\n\n\r\n",
                b"e\r\ndata: second\n\n\r\n",
            ],
        );
        assert!(request.starts_with("GET /chats/c1/events HTTP/1.1\r\n"));
        assert!(request.contains("accept: text/event-stream\r\n"));
        assert!(request.contains("x-gaugewright-home-admission: admitted\r\n"));
        assert_eq!(
            seen,
            vec![StreamPoll::Opened, event("first"), event("second")],
            "events must arrive while the stream is open, and nothing else",
        );
    }

    /// A refusal is a whole response, and its body is the reason desk acts on
    /// — `target Home admission required` is what makes it admit again.
    #[test]
    fn a_refused_stream_reports_its_status_and_reason() {
        let (identity, config) = home();
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        let mut stream = TunnelEventStream::open(
            identity.fingerprint(),
            "/workspace/events",
            &BTreeMap::new(),
        )
        .expect("open");
        let body = br#"{"error":"target Home admission required"}"#;
        let head = format!(
            "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        let (seen, _) = stream_exchange(
            &mut stream,
            &mut server,
            &[head.as_bytes(), &body[..10], &body[10..]],
        );
        assert_eq!(
            seen,
            vec![StreamPoll::Refused {
                status: 401,
                body: body.to_vec()
            }],
        );
    }

    /// A stream the Home ends says so, so its subscriber can open another.
    #[test]
    fn a_stream_that_ends_reports_the_end_after_its_events() {
        let (identity, config) = home();
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        let mut stream =
            TunnelEventStream::open(identity.fingerprint(), "/chats/c1/events", &BTreeMap::new())
                .expect("open");
        let (seen, _) = stream_exchange(
            &mut stream,
            &mut server,
            &[b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nc\r\ndata: last\n\n\r\n0\r\n\r\n"],
        );
        assert_eq!(
            seen,
            vec![StreamPoll::Opened, event("last"), StreamPoll::Ended]
        );
    }

    /// Pumping for ciphertext must not swallow what it decoded, as for calls.
    #[test]
    fn pumping_a_stream_for_ciphertext_keeps_what_it_decoded() {
        let (identity, config) = home();
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        let mut stream =
            TunnelEventStream::open(identity.fingerprint(), "/chats/c1/events", &BTreeMap::new())
                .expect("open");
        let reply: &[u8] =
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nb\r\ndata: one\n\n\r\n";
        let mut answered = false;
        for _ in 0..64 {
            stream.pump().expect("pump");
            let out = stream.session_mut().take_outgoing();
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
                stream.session_mut().received(&back);
                // Pump once more before polling, the way a carrier flushes
                // after every arrival.
                stream.pump().expect("pump");
            }
        }
        assert_eq!(stream.poll().expect("poll"), Some(StreamPoll::Opened));
        assert_eq!(stream.poll().expect("poll"), Some(event("one")));
    }
}
