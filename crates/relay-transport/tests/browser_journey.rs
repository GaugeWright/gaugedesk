//! DESK-7: drive the whole journey from a browser.
//!
//! `browser_handshake.rs` proves the pinned session runs in a page;
//! `tunnel_through_relay.rs` proves the splice carries an admission natively.
//! Neither proves the browser's own carrier does it end to end — the `READY`
//! frame, the `DATA` framing, the pump order the JavaScript loop uses — against
//! a relay it does not control.
//!
//! The harness (`examples/hermetic-home.rs`) supplies all of that on loopback.
//! Its relay port is ephemeral and this binary is compiled before the harness
//! exists, so the harness publishes its description on a fixed port and the page
//! fetches it. Without the harness the test **skips**: a lane that quietly passes
//! when its fixture is absent is worse than no lane.
//!
//! What it does **not** cover: the tunnel is built straight from the harness
//! description, so project→Home resolution and the pool's refusal of a Home that
//! answers as another id belong to `HomePool.connectProject` and are tested in
//! `web/packages/control-plane-client/src/home-pool.test.ts`, not here.
#![cfg(target_arch = "wasm32")]

use gaugedesk_relay_transport::browser::BrowserTunnel;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const CONFIG_URL: &str = "http://127.0.0.1:7908/";
const HOME_ID: &str = "home:hermetic";

struct Harness {
    endpoint: String,
    handle: String,
    proof: String,
    epoch: f64,
    fingerprint: String,
}

/// Read the harness description, or `None` when it is not running.
async fn harness() -> Option<Harness> {
    let window = web_sys::window().expect("window");
    let response = JsFuture::from(window.fetch_with_str(CONFIG_URL))
        .await
        .ok()?;
    let response: web_sys::Response = response.dyn_into().ok()?;
    let text = JsFuture::from(response.text().ok()?).await.ok()?;
    let text = text.as_string()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some(Harness {
        endpoint: value["relay_endpoint"].as_str()?.to_owned(),
        handle: value["handle"].as_str()?.to_owned(),
        proof: value["proof"].as_str()?.to_owned(),
        epoch: value["route_epoch"].as_f64()?,
        fingerprint: value["home_fingerprint"].as_str()?.to_owned(),
    })
}

/// Yield to the event loop so socket messages can be delivered.
async fn tick() {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        web_sys::window()
            .expect("window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 10)
            .expect("timeout");
    });
    let _ = JsFuture::from(promise).await;
}

/// The journey the multi-Home pool performs for a relay-only Home: open the
/// carrier, send the fabric's handshake, complete the pinned session through the
/// relay's splice, and admit — then check the Home answered *as the Home the
/// route named*, which is the assertion the whole tunnel exists to make possible.
#[wasm_bindgen_test]
async fn a_browser_admits_to_a_relay_only_home() {
    let Some(harness) = harness().await else {
        // Skipped, and said out loud: `scripts/browser-journey.sh` starts the
        // harness, and a silent pass here would look like a working lane.
        println!("SKIP: the hermetic harness is not running; use scripts/browser-journey.sh");
        return;
    };

    let mut tunnel = BrowserTunnel::new(&harness.fingerprint).expect("tunnel");
    let handshake = BrowserTunnel::relay_handshake(
        &harness.endpoint,
        &harness.handle,
        &harness.proof,
        harness.epoch,
    )
    .expect("client handshake");

    let url = format!("{}/v1/relay/{}", harness.endpoint, harness.handle);
    let socket = web_sys::WebSocket::new(&url).expect("open the relay carrier");
    socket.set_binary_type(web_sys::BinaryType::Arraybuffer);

    let frames: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
    let inbox = Rc::clone(&frames);
    let on_message = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |event| {
        if let Some(bytes) = gaugedesk_relay_transport::browser::message_bytes(&event) {
            inbox.borrow_mut().push(bytes);
        }
    });
    socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();

    let opened = Rc::new(RefCell::new(false));
    let flag = Rc::clone(&opened);
    let on_open = Closure::<dyn FnMut()>::new(move || *flag.borrow_mut() = true);
    socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    on_open.forget();

    for _ in 0..200 {
        if *opened.borrow() {
            break;
        }
        tick().await;
    }
    assert!(*opened.borrow(), "the relay carrier never opened");
    socket
        .send_with_u8_array(&handshake)
        .expect("send handshake");

    tunnel
        .send_request("POST", "/home/admissions", None, None)
        .expect("queue the admission");

    for _ in 0..400 {
        for frame in frames.borrow_mut().drain(..) {
            tunnel.receive_frame(&frame).expect("receive");
        }
        // The JavaScript loop's order exactly (`tunnel-route-json.ts`): flush
        // ciphertext only once the leg is paired, then look for a reply.
        if tunnel.is_paired() {
            let outgoing = tunnel.take_outgoing().expect("outgoing");
            if !outgoing.is_empty() {
                socket.send_with_u8_array(&outgoing).expect("send");
            }
        }
        if let Some(status) = tunnel.poll_status().expect("poll") {
            assert_eq!(status, 201, "the Home must admit");
            let body = tunnel.take_body();
            assert!(
                body.contains(HOME_ID),
                "the Home must answer as the Home the route named, got: {body}",
            );
            assert!(
                !tunnel.is_handshaking(),
                "traffic implies a pinned handshake"
            );
            return;
        }
        tick().await;
    }
    panic!("the Home never answered through the tunnel");
}
