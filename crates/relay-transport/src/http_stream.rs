//! HTTP/1.1 over the pinned tunnel, for a client that has no socket (DESK-7).
//!
//! Native carriers never needed this: [`crate::bind_client_loopback`] exposes the
//! tunnel as a local listener and the operating system's HTTP stack speaks over
//! it, which is exactly what a `http://127.0.0.1:<port>` endpoint hands back. A
//! page has no loopback to bind, so the browser has to frame requests and parse
//! responses itself, on top of the byte stream [`crate::session::PinnedSession`]
//! carries.
//!
//! Sans-io on purpose, like the session it sits on: it turns bytes into messages
//! and back, holding no socket, so the whole of it is exercised by native tests
//! rather than only in a browser.

use std::collections::{BTreeMap, VecDeque};

use crate::wire::{invalid_data, other};

/// Encode a request. `Host` is fixed because the pinned session authenticates by
/// certificate fingerprint, not by name — there is no meaningful host to send,
/// and varying it would imply otherwise.
pub fn encode_request(
    method: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&[u8]>,
) -> std::io::Result<Vec<u8>> {
    if method.is_empty() || !path.starts_with('/') {
        return Err(invalid_data("request needs a method and an absolute path"));
    }
    for (name, value) in headers {
        // A header carrying CRLF would let a caller inject a second request.
        if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
            return Err(invalid_data("header name or value contains a control byte"));
        }
    }
    let mut out = format!("{method} {path} HTTP/1.1\r\nhost: gaugewright-home\r\n").into_bytes();
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    match body {
        Some(bytes) => {
            out.extend_from_slice(format!("content-length: {}\r\n\r\n", bytes.len()).as_bytes());
            out.extend_from_slice(bytes);
        }
        // A bodyless request still declares zero, so a Home never waits on one.
        None => out.extend_from_slice(b"content-length: 0\r\n\r\n"),
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// A response's head: everything a caller can act on before the body has
/// finished arriving, which for an event stream is everything it ever gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
}

/// What one streaming read of a body produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodyPart {
    /// Body bytes decoded since the last read. Never empty.
    Chunk(Vec<u8>),
    /// The body ended. A following response may now be read.
    End,
    /// Nothing further has arrived yet.
    Pending,
}

/// How a response body is delimited. Anything else is refused rather than
/// guessed at: reading to end-of-stream would make a truncated response
/// indistinguishable from a complete one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyFraming {
    /// The response ends with its header block, carrying no body at all.
    Empty,
    Length(usize),
    Chunked,
}

/// The body of the response currently being read, decoded as bytes arrive.
#[derive(Debug)]
struct BodyState {
    framing: BodyFraming,
    read: usize,
    decoded: Vec<u8>,
    complete: bool,
}

impl BodyState {
    fn new(framing: BodyFraming) -> Self {
        Self {
            framing,
            read: 0,
            decoded: Vec::new(),
            complete: false,
        }
    }
}

/// Incremental response reader. Feed it whatever arrives; read a response
/// whole with [`ResponseReader::take`], or head-then-body with
/// [`ResponseReader::take_head`] and [`ResponseReader::read_body`] when the
/// body is a stream that outlives the request.
#[derive(Debug, Default)]
pub struct ResponseReader {
    buffer: Vec<u8>,
    head: Option<ResponseHead>,
    body: Option<BodyState>,
    bodyless: VecDeque<bool>,
}

impl ResponseReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Note a request as it is sent. A response to `HEAD` carries no body
    /// however it frames one, and responses come back in the order the
    /// requests went out, so this is the only place that can be known from.
    pub fn sent_request(&mut self, method: &str) {
        self.bodyless.push_back(method.eq_ignore_ascii_case("HEAD"));
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Take the head of the next response as soon as its header block is
    /// whole, leaving the body to [`ResponseReader::read_body`].
    ///
    /// This is what an event stream needs. A Home's `events` responses are
    /// keep-alive SSE, so their terminating chunk does not arrive during
    /// normal operation: waiting for a complete response would withhold every
    /// event and grow the buffer without bound.
    pub fn take_head(&mut self) -> std::io::Result<Option<ResponseHead>> {
        // A body still in flight owns the bytes that follow; the next response
        // does not begin until it ends.
        if self.body.is_some() {
            return Ok(None);
        }
        let Some(head_end) = find(&self.buffer, b"\r\n\r\n") else {
            return Ok(None);
        };
        let head = std::str::from_utf8(&self.buffer[..head_end])
            .map_err(|_| invalid_data("response head is not utf-8"))?
            .to_owned();
        let mut lines = head.split("\r\n");
        let status = parse_status(lines.next().unwrap_or_default())?;
        let mut headers = BTreeMap::new();
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                return Err(invalid_data("response header is malformed"));
            };
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
        // An interim 1xx precedes the real response to the same request, so it
        // must not consume that request's entry.
        let to_head_request = if is_informational(status) {
            false
        } else {
            self.bodyless.pop_front().unwrap_or(false)
        };
        let framing = framing_of(&headers, status, to_head_request)?;
        self.buffer.drain(..head_end + 4);
        self.body = Some(BodyState::new(framing));
        Ok(Some(ResponseHead { status, headers }))
    }

    /// Read whatever of the current body has decoded since the last read.
    /// Yields `Pending` until bytes arrive, and `End` once the body is whole.
    pub fn read_body(&mut self) -> std::io::Result<BodyPart> {
        self.advance()?;
        let Some(state) = self.body.as_mut() else {
            return Ok(BodyPart::Pending);
        };
        if !state.decoded.is_empty() {
            return Ok(BodyPart::Chunk(std::mem::take(&mut state.decoded)));
        }
        if state.complete {
            self.body = None;
            return Ok(BodyPart::End);
        }
        Ok(BodyPart::Pending)
    }

    /// Take one complete response, or `None` while more bytes are needed. Use
    /// this for a body that ends; a stream is read head-then-body instead.
    pub fn take(&mut self) -> std::io::Result<Option<HttpResponse>> {
        if self.head.is_none() {
            let Some(head) = self.take_head()? else {
                return Ok(None);
            };
            self.head = Some(head);
        }
        self.advance()?;
        if !self.body.as_ref().is_some_and(|state| state.complete) {
            return Ok(None);
        }
        let head = self.head.take().expect("a head was taken just above");
        let body = self.body.take().expect("checked complete").decoded;
        Ok(Some(HttpResponse {
            status: head.status,
            headers: head.headers,
            body,
        }))
    }

    /// Decode as much of the current body as the buffered bytes allow.
    fn advance(&mut self) -> std::io::Result<()> {
        let Some(state) = self.body.as_mut() else {
            return Ok(());
        };
        if state.complete {
            return Ok(());
        }
        match state.framing {
            BodyFraming::Empty => state.complete = true,
            BodyFraming::Length(length) => {
                let take = (length - state.read).min(self.buffer.len());
                state.decoded.extend(self.buffer.drain(..take));
                state.read += take;
                state.complete = state.read == length;
            }
            BodyFraming::Chunked => {
                while let Some(line_end) = find(&self.buffer, b"\r\n") {
                    let header = std::str::from_utf8(&self.buffer[..line_end])
                        .map_err(|_| invalid_data("chunk size is not utf-8"))?;
                    let size =
                        usize::from_str_radix(header.split(';').next().unwrap_or("").trim(), 16)
                            .map_err(|_| invalid_data("chunk size is not hexadecimal"))?;
                    let start = line_end + 2;
                    if size == 0 {
                        if self.buffer.len() < start + 2 {
                            break;
                        }
                        // The terminating chunk carries its own CRLF. Anything else
                        // standing there is a trailer section, which this reader
                        // does not parse: guessing its length would run the next
                        // response's bytes into this one.
                        if &self.buffer[start..start + 2] != b"\r\n" {
                            return Err(invalid_data("chunked trailers are not supported"));
                        }
                        self.buffer.drain(..start + 2);
                        state.complete = true;
                        break;
                    }
                    if self.buffer.len() < start + size + 2 {
                        break;
                    }
                    state
                        .decoded
                        .extend_from_slice(&self.buffer[start..start + size]);
                    self.buffer.drain(..start + size + 2);
                }
            }
        }
        Ok(())
    }
}

fn parse_status(line: &str) -> std::io::Result<u16> {
    let mut parts = line.split(' ');
    let version = parts.next().unwrap_or_default();
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(invalid_data("response is not HTTP/1.x"));
    }
    parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|code| (100..=599).contains(code))
        .ok_or_else(|| invalid_data("response has no valid status code"))
}

fn is_informational(status: u16) -> bool {
    (100..200).contains(&status)
}

fn framing_of(
    headers: &BTreeMap<String, String>,
    status: u16,
    to_head_request: bool,
) -> std::io::Result<BodyFraming> {
    // A response to HEAD, and every 1xx, 204, and 304, ends with its header
    // block however it frames a body it does not send. Demanding a delimiter
    // of those would turn a Home's real `204 No Content` (revoking an
    // admission, say) into a transport error.
    if to_head_request || is_informational(status) || status == 204 || status == 304 {
        return Ok(BodyFraming::Empty);
    }
    if let Some(encoding) = headers.get("transfer-encoding") {
        if encoding.eq_ignore_ascii_case("chunked") {
            return Ok(BodyFraming::Chunked);
        }
        return Err(invalid_data("unsupported transfer-encoding"));
    }
    match headers.get("content-length") {
        Some(value) => value
            .parse::<usize>()
            .map(BodyFraming::Length)
            .map_err(|_| invalid_data("content-length is not a number")),
        // No delimiter at all: refuse rather than read to close, so a truncated
        // response cannot be mistaken for a complete one.
        None => Err(invalid_data("response declares no body framing")),
    }
}

/// One server-sent event, for the `events` half of the transport.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Incremental SSE reader over a streaming body.
#[derive(Debug, Default)]
pub struct EventReader {
    /// Bytes that arrived but do not yet form whole characters.
    undecoded: Vec<u8>,
    buffer: String,
}

impl EventReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.undecoded.extend_from_slice(bytes);
        // The tunnel splits plaintext at whatever boundary its segments fall
        // on, including the middle of a character. A trailing sequence that is
        // merely incomplete is held for the next arrival; only a byte that can
        // begin no character at all is a refusal, so text outside ASCII cannot
        // intermittently kill the stream.
        let decodable = match std::str::from_utf8(&self.undecoded) {
            Ok(_) => self.undecoded.len(),
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => return Err(other("event stream is not utf-8".to_owned())),
        };
        let decoded: Vec<u8> = self.undecoded.drain(..decodable).collect();
        self.buffer
            .push_str(std::str::from_utf8(&decoded).expect("validated as a whole prefix above"));
        Ok(())
    }

    /// Take the next complete event. Events are separated by a blank line, so a
    /// partially received one is held rather than delivered short.
    pub fn take(&mut self) -> Option<ServerEvent> {
        let end = self.buffer.find("\n\n")?;
        let frame = self.buffer[..end].to_owned();
        self.buffer.drain(..end + 2);
        let mut event = ServerEvent::default();
        let mut data: Vec<&str> = Vec::new();
        for line in frame.lines() {
            if let Some(value) = line.strip_prefix("event:") {
                event.event = Some(value.trim().to_owned());
            } else if let Some(value) = line.strip_prefix("data:") {
                data.push(value.strip_prefix(' ').unwrap_or(value));
            }
        }
        event.data = data.join("\n");
        Some(event)
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_request_declares_its_length_even_when_empty() {
        let encoded = encode_request("POST", "/home/admissions", &BTreeMap::new(), None).unwrap();
        let text = String::from_utf8(encoded).unwrap();
        assert!(text.starts_with("POST /home/admissions HTTP/1.1\r\n"));
        assert!(text.contains("content-length: 0\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_header_cannot_smuggle_a_second_request() {
        let bad = headers(&[("x-evil", "a\r\nGET /admin HTTP/1.1")]);
        assert!(encode_request("GET", "/x", &bad, None).is_err());
        assert!(encode_request("GET", "relative", &BTreeMap::new(), None).is_err());
    }

    #[test]
    fn a_length_delimited_response_is_yielded_only_once_whole() {
        let mut reader = ResponseReader::new();
        reader.feed(b"HTTP/1.1 201 Created\r\ncontent-length: 5\r\n\r\nab");
        assert_eq!(reader.take().unwrap(), None, "a short body must not yield");
        reader.feed(b"cde");
        let response = reader.take().unwrap().expect("complete");
        assert_eq!(response.status, 201);
        assert_eq!(response.body, b"abcde");
        assert_eq!(reader.take().unwrap(), None);
    }

    #[test]
    fn a_chunked_response_reassembles_across_arrivals() {
        let mut reader = ResponseReader::new();
        reader.feed(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n");
        assert_eq!(reader.take().unwrap(), None);
        reader.feed(b"2\r\nde\r\n0\r\n\r\n");
        let response = reader.take().unwrap().expect("complete");
        assert_eq!(response.body, b"abcde");
    }

    #[test]
    fn two_responses_on_one_stream_stay_separate() {
        let mut reader = ResponseReader::new();
        reader.feed(b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nAHTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n");
        assert_eq!(reader.take().unwrap().unwrap().body, b"A");
        assert_eq!(reader.take().unwrap().unwrap().status, 204);
    }

    #[test]
    fn a_bodyless_status_ends_with_its_head_rather_than_failing() {
        let mut reader = ResponseReader::new();
        // A Home revoking an admission answers a bare 204, which declares no
        // framing because it is not allowed to carry a body.
        reader.feed(b"HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 304 Not Modified\r\n\r\n");
        assert_eq!(reader.take().unwrap().expect("204").status, 204);
        let not_modified = reader.take().unwrap().expect("304");
        assert_eq!(not_modified.status, 304);
        assert!(not_modified.body.is_empty());
    }

    #[test]
    fn a_head_response_carries_no_body_despite_its_length() {
        let mut reader = ResponseReader::new();
        reader.sent_request("HEAD");
        reader.sent_request("GET");
        reader.feed(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n");
        let head = reader.take().unwrap().expect("the HEAD response is whole");
        assert!(head.body.is_empty(), "a HEAD response body is not sent");
        // The GET that followed it still reads its own body, which proves the
        // stream stayed aligned rather than eating the next response.
        reader.feed(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nabcde");
        assert_eq!(
            reader.take().unwrap().expect("the GET response").body,
            b"abcde"
        );
    }

    #[test]
    fn a_streaming_body_reaches_the_caller_before_its_terminating_chunk() {
        let mut reader = ResponseReader::new();
        // A keep-alive SSE response: the zero chunk does not arrive while the
        // stream is live, so nothing may wait on it.
        reader.feed(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-type: text/event-stream\r\n\r\n",
        );
        let head = reader.take_head().unwrap().expect("the head is whole");
        assert_eq!(head.status, 200);
        assert_eq!(reader.read_body().unwrap(), BodyPart::Pending);

        reader.feed(b"b\r\ndata: one\n\n\r\n");
        assert_eq!(
            reader.read_body().unwrap(),
            BodyPart::Chunk(b"data: one\n\n".to_vec()),
            "a live event must not wait for the response to end"
        );
        assert_eq!(reader.read_body().unwrap(), BodyPart::Pending);

        reader.feed(b"0\r\n\r\n");
        assert_eq!(reader.read_body().unwrap(), BodyPart::End);
    }

    #[test]
    fn a_response_with_no_framing_is_refused_rather_than_read_to_close() {
        let mut reader = ResponseReader::new();
        reader.feed(b"HTTP/1.1 200 OK\r\nserver: home\r\n\r\nbody");
        assert!(
            reader.take().is_err(),
            "truncation must not look like completion"
        );
    }

    #[test]
    fn events_are_held_until_their_blank_line_arrives() {
        let mut reader = EventReader::new();
        reader.feed(b"event: entry\ndata: one\n").unwrap();
        assert_eq!(reader.take(), None, "a partial event must not be delivered");
        reader.feed(b"\n").unwrap();
        assert_eq!(
            reader.take(),
            Some(ServerEvent {
                event: Some("entry".into()),
                data: "one".into()
            }),
        );
    }

    #[test]
    fn a_character_split_across_arrivals_is_held_rather_than_refused() {
        let mut reader = EventReader::new();
        let event = "data: café\n\n".as_bytes();
        let cut = event.len() - 3; // between the two bytes of the é
        reader.feed(&event[..cut]).unwrap();
        assert_eq!(reader.take(), None);
        reader.feed(&event[cut..]).unwrap();
        assert_eq!(reader.take().expect("the whole event").data, "café");
    }

    #[test]
    fn a_byte_that_can_begin_no_character_is_still_refused() {
        let mut reader = EventReader::new();
        assert!(reader.feed(&[0xff]).is_err());
    }

    #[test]
    fn multi_line_event_data_is_joined_in_order() {
        let mut reader = EventReader::new();
        reader.feed(b"data: first\ndata: second\n\n").unwrap();
        assert_eq!(reader.take().unwrap().data, "first\nsecond");
    }
}
