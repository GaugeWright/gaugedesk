//! The browser's journey, minus the browser (DESK-7).
//!
//! `tunnel_client.rs` proves the pinned tunnel against an in-process rustls
//! server; `browser_handshake.rs` proves ring runs in a page. Neither exercises
//! the piece between them: a `Client` leg driven exactly as `BrowserTunnel`
//! drives it — 84-byte handshake, wait for `READY`, then `DATA`-framed
//! ciphertext — spliced by a real relay to a real parked Home leg.
//!
//! Running this natively means a failure in that splice is diagnosable in
//! seconds rather than through a headless browser.

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use gaugedesk_relay_transport::test_relay::TestRelay;
use gaugedesk_relay_transport::{
    classify_frame, data_frame, serve_home_forever, websocket_handshake, HomeRelayConfig,
    RelayFrame, TlsIdentity, WebSocketRelayRole,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const HOME_ID: &str = "home:hermetic";

/// Answer `POST /home/admissions` once per connection, as the hermetic harness
/// does, so this test and the browser lane exercise the same Home.
async fn serve_admissions(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            eprintln!("[stub] {} bytes: {:?}", read, request);
            let body = format!(r#"{{"home":"{HOME_ID}","admission":"hermetic-admission"}}"#);
            let response = format!(
                "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len(),
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        });
    }
}

#[tokio::test]
async fn a_client_leg_admits_through_the_relay_to_a_parked_home() {
    let relay = TestRelay::bind().await.expect("relay");
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = TlsIdentity::load_or_generate(directory.path()).expect("identity");
    let config = HomeRelayConfig::load_or_mint(directory.path(), relay.endpoint()).expect("config");
    let route = config.relay_route(&identity).expect("route");

    let stub = TcpListener::bind("127.0.0.1:0").await.expect("stub");
    let stub_addr = stub.local_addr().expect("stub addr");
    tokio::spawn(serve_admissions(stub));

    let parked = route.clone();
    let parked_identity = identity.clone();
    tokio::spawn(async move {
        if let Err(error) = serve_home_forever(parked, stub_addr, parked_identity).await {
            eprintln!("[home] the Home leg stopped: {error}");
        }
    });
    // Give the Home leg time to create the route before the client joins.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let wire_route = gaugedesk_relay_transport::WebSocketRelayRoute {
        endpoint: route.endpoint.clone(),
        handle: route.handle.clone(),
        epoch: route.epoch,
        proof: route.proof,
        previous_proof: None,
    };
    let handshake =
        websocket_handshake(&wire_route, WebSocketRelayRole::Client).expect("client handshake");

    let (mut socket, _) = tokio_tungstenite::connect_async(wire_route.url().expect("url"))
        .await
        .expect("connect relay");
    socket
        .send(Message::Binary(handshake.to_vec().into()))
        .await
        .expect("send handshake");

    let mut client =
        gaugedesk_relay_transport::tunnel_client::TunnelClient::new(route.home_fingerprint)
            .expect("client");
    client
        .send("POST", "/home/admissions", &BTreeMap::new(), None)
        .expect("queue admission");

    let mut paired = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if paired {
            // The browser's order exactly: flush ciphertext first, then look
            // for a reply. A flush that consumed the reply is invisible here
            // unless the two are separate calls, which is the point.
            client.pump().expect("pump");
            let outgoing = client.session_mut().take_outgoing();
            if !outgoing.is_empty() {
                eprintln!("[client] -> {} ciphertext bytes", outgoing.len());
                socket
                    .send(Message::Binary(data_frame(&outgoing).into()))
                    .await
                    .expect("send data");
            }
            if let Some(response) = client.poll().expect("poll") {
                eprintln!("[client] response {}", response.status);
                assert_eq!(response.status, 201);
                assert!(
                    String::from_utf8_lossy(&response.body).contains(HOME_ID),
                    "the Home must answer as itself",
                );
                return;
            }
        }

        let message = tokio::time::timeout_at(deadline, socket.next())
            .await
            .expect("the Home never answered through the tunnel")
            .expect("relay closed")
            .expect("relay frame");
        match message {
            Message::Binary(bytes) => match classify_frame(&bytes).expect("classify") {
                RelayFrame::Ready => {
                    eprintln!("[client] paired");
                    paired = true;
                }
                RelayFrame::Data(payload) => {
                    eprintln!("[client] <- {} ciphertext bytes", payload.len());
                    client.session_mut().received(&payload);
                }
                other => eprintln!("[client] <- {other:?}"),
            },
            Message::Close(frame) => panic!("relay closed the leg: {frame:?}"),
            _ => {}
        }
    }
}
