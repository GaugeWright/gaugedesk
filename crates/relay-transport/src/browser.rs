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

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::wire::{
    classify_frame, other, websocket_handshake, RelayFrame, WebSocketRelayRole,
    WebSocketRelayRoute, WSS_HANDSHAKE_LEN,
};

pub use crate::session::PinnedSession;

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

/// The tunnel as JavaScript sees it (DESK-7).
///
/// Byte-in, byte-out and **pump-driven**: TypeScript owns the `WebSocket` and
/// hands frames across, rather than this module opening one. That is deliberate.
/// ADR 0130 §6 puts the socket glue inside `control-plane-client`, the declared
/// browser transport owner, and keeping the socket there means the boundary
/// `scripts/architecture-check.py` enforces still describes reality.
///
/// It also keeps every decision on the Rust side of the line — framing,
/// reassembly, the pin — where native tests already exercise it, leaving the
/// JavaScript with a loop and no judgement calls.
#[wasm_bindgen]
pub struct BrowserTunnel {
    client: crate::tunnel_client::TunnelClient,
    /// Whether the relay has paired this leg with the Home's. Sending tunnel
    /// bytes before that is writing into a route with no other end.
    paired: bool,
    /// Body of the response whose status was last reported, held so the two
    /// halves cross the boundary as separate calls.
    pending: Option<Vec<u8>>,
    /// Headers of that response, for a caller that reads it raw (WS-678).
    pending_headers: std::collections::BTreeMap<String, String>,
    /// What this leg has taken from the relay and not yet reported (DR-0302).
    meter: crate::wire::CreditMeter,
    /// Ciphertext taken from the session and not yet sent, in frames the relay
    /// accepts.
    frames: crate::wire::FrameQueue,
}

#[wasm_bindgen]
impl BrowserTunnel {
    /// Begin a session pinned to a Home's lowercase hex certificate
    /// fingerprint — the `home_fingerprint` its opaque route carries.
    #[wasm_bindgen(constructor)]
    pub fn new(home_fingerprint: &str) -> Result<BrowserTunnel, JsValue> {
        crate::tunnel_client::TunnelClient::new(parse_fingerprint(home_fingerprint)?)
            .map(|client| BrowserTunnel {
                client,
                pending: None,
                pending_headers: Default::default(),
                paired: false,
                meter: crate::wire::CreditMeter::new(),
                frames: crate::wire::FrameQueue::new(),
            })
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    /// The 84-byte `client` handshake for this route — the first frame the
    /// caller must send on the socket, before any tunnel bytes.
    #[wasm_bindgen(js_name = relayHandshake)]
    pub fn relay_handshake(
        endpoint: &str,
        handle: &str,
        proof: &str,
        epoch: f64,
    ) -> Result<Vec<u8>, JsValue> {
        let route = WebSocketRelayRoute {
            endpoint: endpoint.to_owned(),
            handle: handle.to_owned(),
            epoch: epoch as u64,
            proof: crate::wire::RouteProof::from_base64url(proof)
                .map_err(|error| JsValue::from_str(&error.to_string()))?,
            previous_proof: None,
        };
        client_handshake(&route)
            .map(|frame| frame.to_vec())
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    /// Feed one binary frame received from the relay. `READY` and the shutdown
    /// frames are handled here so the caller never interprets the fabric.
    #[wasm_bindgen(js_name = receiveFrame)]
    pub fn receive_frame(&mut self, frame: &[u8]) -> Result<(), JsValue> {
        match classify_frame(frame).map_err(|error| JsValue::from_str(&error.to_string()))? {
            RelayFrame::Ready => {
                self.paired = true;
                Ok(())
            }
            RelayFrame::Data(bytes) => {
                // A page buffers whatever it is given, so a frame is consumed
                // the moment it arrives.
                self.meter.consumed(frame.len());
                self.client.session_mut().received(&bytes);
                Ok(())
            }
            RelayFrame::Fin | RelayFrame::FinAck => {
                self.meter.consumed(frame.len());
                Ok(())
            }
        }
    }

    /// The report of consumption the relay is owed now, or empty: send it on
    /// the socket as it is, after the frame that earned it (DR-0302).
    #[wasm_bindgen(js_name = takeCredit)]
    pub fn take_credit(&mut self) -> Vec<u8> {
        self.meter
            .take_credit()
            .map(|credit| credit.to_vec())
            .unwrap_or_default()
    }

    /// Queue a request. It is encrypted on the next [`Self::take_outgoing`], so
    /// a caller may send before the handshake completes.
    /// `headers` is a plain object of extra request headers, or `undefined`.
    ///
    /// It exists because a carried surface may require one. A TokenWright box
    /// admits nothing without `Authorization`, so a tunnel that could not send
    /// a header could reach that box, claim it, and then never use it — which
    /// is exactly what happened before this took an argument. The client
    /// underneath has always accepted headers; only this binding dropped them.
    #[wasm_bindgen(js_name = sendRequest)]
    pub fn send_request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<String>,
        headers: Option<js_sys::Object>,
    ) -> Result<(), JsValue> {
        let mut headers = header_map(headers);
        if body.is_some() {
            headers.insert("content-type".to_owned(), "application/json".to_owned());
        }
        self.client
            .send(method, path, &headers, body.as_deref().map(str::as_bytes))
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    /// Queue a request whose body follows in parts: its head declares
    /// `content_length` bytes, and [`Self::send_body`] hands them over as the
    /// caller reads them (WS-678). `headers` is a plain object, or `undefined`.
    #[wasm_bindgen(js_name = sendRequestHead)]
    pub fn send_request_head(
        &mut self,
        method: &str,
        path: &str,
        headers: Option<js_sys::Object>,
        content_length: f64,
    ) -> Result<(), JsValue> {
        if !(content_length >= 0.0 && content_length.fract() == 0.0) {
            return Err(JsValue::from_str("content length must be a whole number"));
        }
        self.client
            .send_head(method, path, &header_map(headers), content_length as usize)
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    /// The next part of a body [`Self::send_request_head`] declared.
    #[wasm_bindgen(js_name = sendBody)]
    pub fn send_body(&mut self, chunk: &[u8]) -> Result<(), JsValue> {
        self.client
            .send_body(chunk)
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    /// Bytes queued and not yet handed to the socket. A caller feeding a body
    /// adds the socket's own `bufferedAmount` and holds the next part back
    /// while the sum is large.
    #[wasm_bindgen(js_name = bufferedBytes)]
    pub fn buffered_bytes(&self) -> f64 {
        (self.client.buffered() + self.frames.len()) as f64
    }

    /// The next relay `DATA` frame to write to the socket, or empty. A large
    /// send takes several calls: no frame exceeds what the relay accepts.
    #[wasm_bindgen(js_name = takeOutgoing)]
    pub fn take_outgoing(&mut self) -> Result<Vec<u8>, JsValue> {
        // `pump`, not `poll`: taking a response here would consume the one
        // `pollStatus` is about to be called for.
        self.client
            .pump()
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        self.frames.push(self.client.session_mut().take_outgoing());
        Ok(self.frames.next_frame().unwrap_or_default())
    }

    /// The response status, or `undefined` while more bytes are needed. Call
    /// [`Self::take_body`] for its body.
    #[wasm_bindgen(js_name = pollStatus)]
    pub fn poll_status(&mut self) -> Result<Option<u16>, JsValue> {
        match self
            .client
            .poll()
            .map_err(|error| JsValue::from_str(&error.to_string()))?
        {
            Some(response) => {
                self.pending = Some(response.body);
                self.pending_headers = response.headers;
                Ok(Some(response.status))
            }
            None => Ok(None),
        }
    }

    /// The body of the response most recently reported by [`Self::poll_status`].
    #[wasm_bindgen(js_name = takeBody)]
    pub fn take_body(&mut self) -> String {
        self.pending
            .take()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    }

    /// The body of the response most recently reported, as bytes: a file is
    /// not text, and decoding it as such would corrupt it (WS-678).
    #[wasm_bindgen(js_name = takeBodyBytes)]
    pub fn take_body_bytes(&mut self) -> Vec<u8> {
        self.pending.take().unwrap_or_default()
    }

    /// The headers of the response most recently reported, as a plain object
    /// with lowercase names.
    #[wasm_bindgen(js_name = takeHeaders, unchecked_return_type = "Record<string, string>")]
    pub fn take_headers(&mut self) -> Result<js_sys::Object, JsValue> {
        let out = js_sys::Object::new();
        for (name, value) in std::mem::take(&mut self.pending_headers) {
            set(&out, &name, &value.into())?;
        }
        Ok(out)
    }

    /// Whether the relay has paired this leg. A caller must not send tunnel
    /// bytes until it has: the relay pairs complementary legs and only then
    /// splices, so anything written earlier has nowhere to go.
    #[wasm_bindgen(js_name = isPaired)]
    pub fn is_paired(&self) -> bool {
        self.paired
    }

    #[wasm_bindgen(js_name = isHandshaking)]
    pub fn is_handshaking(&self) -> bool {
        self.client.handshaking()
    }
}

/// A Home fingerprint as the route carries it: 32 bytes of lowercase hex.
fn parse_fingerprint(home_fingerprint: &str) -> Result<[u8; 32], JsValue> {
    let mut expected = [0u8; 32];
    if home_fingerprint.len() != 64 {
        return Err(JsValue::from_str("home fingerprint must be 32 hex bytes"));
    }
    for (slot, pair) in expected
        .iter_mut()
        .zip(home_fingerprint.as_bytes().chunks(2))
    {
        *slot = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| JsValue::from_str("fingerprint is not hex"))?,
            16,
        )
        .map_err(|_| JsValue::from_str("fingerprint is not hex"))?;
    }
    Ok(expected)
}

/// A plain object of extra request headers, lowercased because HTTP header
/// names are case-insensitive and the map they go into is not.
fn header_map(headers: Option<js_sys::Object>) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    if let Some(extra) = headers {
        for entry in js_sys::Object::entries(&extra).iter() {
            let pair: js_sys::Array = entry.into();
            if let (Some(name), Some(value)) = (pair.get(0).as_string(), pair.get(1).as_string()) {
                map.insert(name.to_ascii_lowercase(), value);
            }
        }
    }
    map
}

fn set(object: &js_sys::Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    js_sys::Reflect::set(object, &JsValue::from_str(key), value).map(|_| ())
}

/// One Home event stream over its own pinned tunnel, as JavaScript sees it
/// (WS-634).
///
/// A stream never ends in normal operation, so it cannot share
/// [`BrowserTunnel`]'s one-call-at-a-time session: it is its own crossing,
/// pump-driven the same way, opening with the request already queued.
#[wasm_bindgen]
pub struct BrowserEventTunnel {
    stream: crate::tunnel_client::TunnelEventStream,
    paired: bool,
    meter: crate::wire::CreditMeter,
    frames: crate::wire::FrameQueue,
}

#[wasm_bindgen]
impl BrowserEventTunnel {
    /// Begin a session pinned to the Home's fingerprint with `GET path` queued
    /// on it as an event stream. `headers` is a plain object, or `undefined`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        home_fingerprint: &str,
        path: &str,
        headers: Option<js_sys::Object>,
    ) -> Result<BrowserEventTunnel, JsValue> {
        crate::tunnel_client::TunnelEventStream::open(
            parse_fingerprint(home_fingerprint)?,
            path,
            &header_map(headers),
        )
        .map(|stream| BrowserEventTunnel {
            stream,
            paired: false,
            meter: crate::wire::CreditMeter::new(),
            frames: crate::wire::FrameQueue::new(),
        })
        .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    /// Feed one binary frame received from the relay, as [`BrowserTunnel`]
    /// does.
    #[wasm_bindgen(js_name = receiveFrame)]
    pub fn receive_frame(&mut self, frame: &[u8]) -> Result<(), JsValue> {
        match classify_frame(frame).map_err(|error| JsValue::from_str(&error.to_string()))? {
            RelayFrame::Ready => self.paired = true,
            RelayFrame::Data(bytes) => {
                self.meter.consumed(frame.len());
                self.stream.session_mut().received(&bytes);
            }
            RelayFrame::Fin | RelayFrame::FinAck => self.meter.consumed(frame.len()),
        }
        Ok(())
    }

    /// The report of consumption the relay is owed now, or empty, as
    /// [`BrowserTunnel::take_credit`].
    #[wasm_bindgen(js_name = takeCredit)]
    pub fn take_credit(&mut self) -> Vec<u8> {
        self.meter
            .take_credit()
            .map(|credit| credit.to_vec())
            .unwrap_or_default()
    }

    /// Ciphertext to write to the socket as a relay `DATA` frame, or empty.
    #[wasm_bindgen(js_name = takeOutgoing)]
    pub fn take_outgoing(&mut self) -> Result<Vec<u8>, JsValue> {
        self.stream
            .pump()
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        self.frames.push(self.stream.session_mut().take_outgoing());
        Ok(self.frames.next_frame().unwrap_or_default())
    }

    /// The next thing the stream produced, or `undefined`: `{ kind: "opened" }`,
    /// `{ kind: "event", data }`, `{ kind: "refused", status, body }`, or
    /// `{ kind: "ended" }`.
    #[wasm_bindgen(js_name = pollEvent)]
    pub fn poll_event(&mut self) -> Result<JsValue, JsValue> {
        use crate::tunnel_client::StreamPoll;
        let polled = self
            .stream
            .poll()
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let Some(polled) = polled else {
            return Ok(JsValue::UNDEFINED);
        };
        let out = js_sys::Object::new();
        match polled {
            StreamPoll::Opened => set(&out, "kind", &"opened".into())?,
            StreamPoll::Event(event) => {
                set(&out, "kind", &"event".into())?;
                set(&out, "data", &event.data.into())?;
            }
            StreamPoll::Refused { status, body } => {
                set(&out, "kind", &"refused".into())?;
                set(&out, "status", &JsValue::from(status))?;
                set(
                    &out,
                    "body",
                    &String::from_utf8_lossy(&body).into_owned().into(),
                )?;
            }
            StreamPoll::Ended => set(&out, "kind", &"ended".into())?,
        }
        Ok(out.into())
    }

    /// Whether the relay has paired this leg; nothing may be sent before.
    #[wasm_bindgen(js_name = isPaired)]
    pub fn is_paired(&self) -> bool {
        self.paired
    }
}
