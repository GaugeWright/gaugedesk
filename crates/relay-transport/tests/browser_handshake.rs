//! DESK-6: run the browser's pinned session **in a browser**.
//!
//! The native proof in `session.rs` establishes that the session completes a
//! pinned handshake and carries traffic. It cannot establish that `ring`'s
//! `wasm32` build — different codegen, `crypto.getRandomValues` for entropy,
//! `Date.now()` for time — actually executes correctly in a JS runtime. That is
//! what this asserts, and it is the one claim a compile could never support.
#![cfg(target_arch = "wasm32")]

use gaugedesk_relay_transport::session::PinnedSession;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

/// Constructing the session exercises the whole provider path in the browser:
/// ring's cipher suites, its entropy source, and the pinned configuration.
#[wasm_bindgen_test]
fn the_pinned_session_starts_in_a_browser() {
    let session = PinnedSession::new([0xAB; 32]).expect("ring must initialize in a browser");
    assert!(session.handshaking());
    assert!(!session.closed());
}

/// A ClientHello is real cryptographic output: key share, randoms, the lot. If
/// ring's wasm32 build or its entropy source were broken, this is where it shows.
#[wasm_bindgen_test]
fn the_browser_produces_a_client_hello() {
    let mut session = PinnedSession::new([0xAB; 32]).expect("session");
    session
        .pump()
        .expect("the handshake must advance in a browser");
    let hello = session.take_outgoing();
    assert!(
        !hello.is_empty(),
        "ring produced no ClientHello in the browser"
    );
    // TLS record: handshake content type, then the legacy record version.
    assert_eq!(hello[0], 0x16, "expected a TLS handshake record");
    assert_eq!(
        &hello[1..3],
        &[0x03, 0x01],
        "expected the legacy record version"
    );
    assert_eq!(hello[5], 0x01, "expected a ClientHello");
}

/// Entropy must actually vary. A stubbed or failing `crypto.getRandomValues`
/// would still produce a well-formed record, so shape alone is not enough.
#[wasm_bindgen_test]
fn browser_entropy_varies_between_sessions() {
    let mut first = PinnedSession::new([0xAB; 32]).expect("session");
    let mut second = PinnedSession::new([0xAB; 32]).expect("session");
    first.pump().expect("first");
    second.pump().expect("second");
    assert_ne!(
        first.take_outgoing(),
        second.take_outgoing(),
        "two ClientHellos were identical — entropy is not reaching ring",
    );
}

use gaugedesk_relay_transport::browser::BrowserTunnel;
use wasm_bindgen::JsValue;

/// The facade JavaScript actually holds: it must reject a malformed pin rather
/// than start a session that can never verify.
#[wasm_bindgen_test]
fn the_facade_refuses_a_fingerprint_that_is_not_32_hex_bytes() {
    assert!(BrowserTunnel::new("ab").is_err());
    assert!(BrowserTunnel::new(&"zz".repeat(32)).is_err());
    assert!(BrowserTunnel::new(&"ab".repeat(32)).is_ok());
}

/// The first frame on the socket is the fabric's, and it must be the same 84
/// bytes every other carrier sends.
#[wasm_bindgen_test]
fn the_facade_emits_the_canonical_client_handshake() {
    // A 43-character base64url value must leave its trailing bits zero, so the
    // last character is one whose low bits are clear. `B` repeated is rejected
    // by strict decoding, which is the validator doing its job.
    let proof = format!("{}A", "B".repeat(42));
    let handshake =
        BrowserTunnel::relay_handshake("wss://relay.example", &"A".repeat(43), &proof, 3.0)
            .expect("handshake");
    assert_eq!(handshake.len(), 84);
    assert_eq!(&handshake[..8], b"GWRWSS1\n");
    assert_eq!(handshake[10], 2, "the client role");
    assert_eq!(&handshake[12..20], &3u64.to_be_bytes());
}

/// A queued request must actually produce ciphertext to write, which is the
/// whole contract the JavaScript loop depends on.
#[wasm_bindgen_test]
fn a_queued_request_produces_ciphertext_to_send() {
    let mut tunnel = BrowserTunnel::new(&"ab".repeat(32)).expect("tunnel");
    assert!(tunnel.is_handshaking());
    tunnel
        .send_request("POST", "/home/admissions", None, None)
        .expect("queue");
    let frame = tunnel.take_outgoing().expect("outgoing");
    assert!(
        !frame.is_empty(),
        "the handshake must produce bytes to send"
    );
    assert_eq!(frame[0], 0, "framed as a relay DATA record");
    assert_eq!(tunnel.poll_status().expect("poll"), None, "no reply yet");
}

/// `sendRequest` must carry the headers a surface requires.
///
/// A TokenWright box admits nothing without `Authorization`, so a binding that
/// silently dropped one would let a page reach a box, claim it, and then be
/// refused on every call after — which is what happened before this argument
/// existed. The ciphertext is opaque here, so this asserts what this layer can
/// actually see: that a header object is accepted and encrypted without error,
/// and that a non-string value is skipped rather than panicking on a page that
/// hands us `{authorization: null}`.
#[wasm_bindgen_test]
fn a_request_carries_the_headers_it_was_given() {
    let mut tunnel = BrowserTunnel::new(&"ab".repeat(32)).expect("tunnel");
    let headers = js_sys::Object::new();
    js_sys::Reflect::set(&headers, &"Authorization".into(), &"Bearer secret".into()).expect("set");
    js_sys::Reflect::set(&headers, &"Idempotency-Key".into(), &"key-1".into()).expect("set");
    js_sys::Reflect::set(&headers, &"X-Ignored".into(), &JsValue::NULL).expect("set");

    tunnel
        .send_request("GET", "/v1/documents", None, Some(headers))
        .expect("queue with headers");

    let frame = tunnel.take_outgoing().expect("outgoing");
    assert!(!frame.is_empty(), "a headed request must produce bytes");
    assert_eq!(frame[0], 0, "framed as a relay DATA record");
}
