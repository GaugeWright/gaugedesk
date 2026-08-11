//! Shared Home/client reachability over GaugeWright's blind rendezvous relay.
//!
//! Both sides dial out. The edge object reads only a versioned role, epoch, and
//! opaque route proof, pairs complementary legs, and then blindly splices binary
//! frames. TLS is end to end between Home and client; the relay owns no key.
//!
//! One fabric, three carriers. [`wire`] holds the sans-io half — the handshake
//! frame, the route rules, the certificate pin — and names no crypto provider.
//! The **native** carrier owns sockets and the filesystem; the **browser**
//! carrier drives the identical bytes over a `WebSocket` and rustls' unbuffered
//! API, because a page has no socket to hand rustls (DESK-2, ADR 0130).

pub mod wire;
pub use wire::*;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::*;

/// The pinned session is target-independent, so it is compiled — and
/// handshake-tested — on every target.
pub mod session;

/// HTTP/1.1 and SSE over the tunnel, for a client with no socket to hand an
/// operating system. Sans-io, so it is tested natively (DESK-7).
pub mod http_stream;

/// The pinned tunnel as a request/response client — what the multi-Home pool
/// consumes. Target-independent, so the journey is tested natively (DESK-7).
pub mod tunnel_client;

#[cfg(target_arch = "wasm32")]
pub mod browser;

#[cfg(all(not(target_arch = "wasm32"), any(test, feature = "test-relay")))]
pub mod test_relay;
