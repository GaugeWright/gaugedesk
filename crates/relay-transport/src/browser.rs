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

use wasm_bindgen::JsCast;

use crate::wire::{
    other, websocket_handshake, WebSocketRelayRole, WebSocketRelayRoute, WSS_HANDSHAKE_LEN,
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
