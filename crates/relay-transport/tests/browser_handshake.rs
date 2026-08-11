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
