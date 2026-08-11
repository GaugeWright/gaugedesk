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
    classify_frame, data_frame, other, websocket_handshake, RelayFrame, WebSocketRelayRole,
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
}

#[wasm_bindgen]
impl BrowserTunnel {
    /// Begin a session pinned to a Home's lowercase hex certificate
    /// fingerprint — the `home_fingerprint` its opaque route carries.
    #[wasm_bindgen(constructor)]
    pub fn new(home_fingerprint: &str) -> Result<BrowserTunnel, JsValue> {
        let mut expected = [0u8; 32];
        if home_fingerprint.len() != 64 {
            return Err(JsValue::from_str("home fingerprint must be 32 hex bytes"));
        }
        for (slot, pair) in expected
            .iter_mut()
            .zip(home_fingerprint.as_bytes().chunks(2))
        {
            *slot = u8::from_str_radix(
                std::str::from_utf8(pair)
                    .map_err(|_| JsValue::from_str("fingerprint is not hex"))?,
                16,
            )
            .map_err(|_| JsValue::from_str("fingerprint is not hex"))?;
        }
        crate::tunnel_client::TunnelClient::new(expected)
            .map(|client| BrowserTunnel {
                client,
                pending: None,
                paired: false,
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
                self.client.session_mut().received(&bytes);
                Ok(())
            }
            RelayFrame::Fin | RelayFrame::FinAck => Ok(()),
        }
    }

    /// Queue a request. It is encrypted on the next [`Self::take_outgoing`], so
    /// a caller may send before the handshake completes.
    #[wasm_bindgen(js_name = sendRequest)]
    pub fn send_request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<(), JsValue> {
        let mut headers = std::collections::BTreeMap::new();
        if body.is_some() {
            headers.insert("content-type".to_owned(), "application/json".to_owned());
        }
        self.client
            .send(method, path, &headers, body.as_deref().map(str::as_bytes))
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    /// Ciphertext to write to the socket, already framed as a relay `DATA`
    /// record. Empty when there is nothing to send.
    #[wasm_bindgen(js_name = takeOutgoing)]
    pub fn take_outgoing(&mut self) -> Result<Vec<u8>, JsValue> {
        self.client
            .poll()
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let ciphertext = self.client.session_mut().take_outgoing();
        Ok(if ciphertext.is_empty() {
            Vec::new()
        } else {
            data_frame(&ciphertext)
        })
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
