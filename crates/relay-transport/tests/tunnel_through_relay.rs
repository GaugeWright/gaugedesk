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
use gaugedesk_relay_transport::tunnel_client::{StreamPoll, TunnelClient, TunnelEventStream};
use gaugedesk_relay_transport::FrameQueue;
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

/// A Home that serves an event stream beside its calls: `GET /chats/c1/events`
/// sends one event, waits, sends another, and never ends — as a Home's stream
/// never does — while anything else is answered as an admission.
async fn serve_stream_and_calls(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            if request.starts_with("GET /chats/c1/events ") {
                let chunk = |data: &str| {
                    let event = format!("data: {data}\n\n");
                    format!("{:x}\r\n{event}\r\n", event.len())
                };
                let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n";
                let _ = stream
                    .write_all(format!("{head}{}", chunk("first")).as_bytes())
                    .await;
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = stream.write_all(chunk("second").as_bytes()).await;
                // Held open: a Home's stream ends only when its client goes.
                tokio::time::sleep(Duration::from_secs(60)).await;
                return;
            }
            let body = format!(r#"{{"home":"{HOME_ID}","admission":"hermetic-admission"}}"#);
            let response = format!(
                "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len(),
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

type RelaySocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Open one client leg to `route`, as the browser's carrier does.
async fn client_leg(route: &gaugedesk_relay_transport::WebSocketRelayRoute) -> RelaySocket {
    let handshake =
        websocket_handshake(route, WebSocketRelayRole::Client).expect("client handshake");
    let (mut socket, _) = tokio_tungstenite::connect_async(route.url().expect("url"))
        .await
        .expect("connect relay");
    socket
        .send(Message::Binary(handshake.to_vec().into()))
        .await
        .expect("send handshake");
    socket
}

/// The next relay frame on a leg: `true` for `READY`, otherwise its ciphertext
/// is handed to `received`.
async fn next_frame(socket: &mut RelaySocket, mut received: impl FnMut(&[u8])) -> bool {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await
            .expect("the relay went quiet")
            .expect("relay closed")
            .expect("relay frame");
        match message {
            Message::Binary(bytes) => match classify_frame(&bytes).expect("classify") {
                RelayFrame::Ready => return true,
                RelayFrame::Data(payload) => {
                    received(&payload);
                    return false;
                }
                _ => {}
            },
            Message::Close(frame) => panic!("relay closed the leg: {frame:?}"),
            _ => {}
        }
    }
}

/// WS-634: a browser's event stream crosses on a leg of its own, delivers each
/// event while it stays open, and does not hold the Home: a call on a second
/// leg is answered while the stream is still running.
#[tokio::test]
async fn an_event_stream_crosses_on_its_own_leg_beside_the_calls() {
    let relay = TestRelay::bind().await.expect("relay");
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = TlsIdentity::load_or_generate(directory.path()).expect("identity");
    let config = HomeRelayConfig::load_or_mint(directory.path(), relay.endpoint()).expect("config");
    let route = config.relay_route(&identity).expect("route");

    let stub = TcpListener::bind("127.0.0.1:0").await.expect("stub");
    let stub_addr = stub.local_addr().expect("stub addr");
    tokio::spawn(serve_stream_and_calls(stub));
    let parked = route.clone();
    tokio::spawn(async move {
        let _ = serve_home_forever(parked, stub_addr, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let wire_route = gaugedesk_relay_transport::WebSocketRelayRoute {
        endpoint: route.endpoint.clone(),
        handle: route.handle.clone(),
        epoch: route.epoch,
        proof: route.proof,
        previous_proof: None,
    };

    // The stream, until its first event arrives.
    let mut stream_socket = client_leg(&wire_route).await;
    let mut stream =
        TunnelEventStream::open(route.home_fingerprint, "/chats/c1/events", &BTreeMap::new())
            .expect("open stream");
    let mut seen = Vec::new();
    let mut paired = false;
    while seen.len() < 2 {
        if paired {
            stream.pump().expect("pump");
            let outgoing = stream.session_mut().take_outgoing();
            if !outgoing.is_empty() {
                stream_socket
                    .send(Message::Binary(data_frame(&outgoing).into()))
                    .await
                    .expect("send");
            }
            while let Some(polled) = stream.poll().expect("poll") {
                seen.push(polled);
            }
            if seen.len() >= 2 {
                break;
            }
        }
        paired |= next_frame(&mut stream_socket, |bytes| {
            stream.session_mut().received(bytes)
        })
        .await;
    }
    assert_eq!(seen[0], StreamPoll::Opened);
    assert!(matches!(&seen[1], StreamPoll::Event(event) if event.data == "first"));

    // A call on a second leg, answered while the stream holds its own.
    let mut call_socket = client_leg(&wire_route).await;
    let mut client = TunnelClient::new(route.home_fingerprint).expect("client");
    client
        .send("POST", "/home/admissions", &BTreeMap::new(), None)
        .expect("queue admission");
    let mut paired = false;
    let response = loop {
        if paired {
            client.pump().expect("pump");
            let outgoing = client.session_mut().take_outgoing();
            if !outgoing.is_empty() {
                call_socket
                    .send(Message::Binary(data_frame(&outgoing).into()))
                    .await
                    .expect("send");
            }
            if let Some(response) = client.poll().expect("poll") {
                break response;
            }
        }
        paired |= next_frame(&mut call_socket, |bytes| {
            client.session_mut().received(bytes)
        })
        .await;
    };
    assert_eq!(
        response.status, 201,
        "a call must be answered beside an open stream"
    );

    // And the stream goes on delivering.
    let second = loop {
        next_frame(&mut stream_socket, |bytes| {
            stream.session_mut().received(bytes)
        })
        .await;
        if let Some(polled) = stream.poll().expect("poll") {
            break polled;
        }
    };
    assert!(
        matches!(&second, StreamPoll::Event(event) if event.data == "second"),
        "the stream must keep delivering after the call, got {second:?}",
    );
}

/// A Home that reads one request's whole body by its declared length and
/// answers with how many bytes it got and a checksum of them.
async fn count_the_body(listener: TcpListener) {
    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024];
            let head_end = loop {
                let read = stream.read(&mut chunk).await.unwrap_or(0);
                if read == 0 {
                    return;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let head = String::from_utf8_lossy(&buffer[..head_end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0);
            while buffer.len() - head_end < length {
                let read = stream.read(&mut chunk).await.unwrap_or(0);
                if read == 0 {
                    return;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let body = &buffer[head_end..head_end + length];
            let sum: u64 = body.iter().map(|byte| u64::from(*byte)).sum();
            let reply = format!("{} {sum}", body.len());
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{reply}",
                reply.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

/// WS-678: a body many relay frames long crosses a real relay to a real Home
/// whole, because no frame the browser's queue hands out exceeds what the
/// relay accepts. The test relay, like the edge, ends a pair for one that does.
#[tokio::test]
async fn a_large_body_crosses_the_relay_in_frames_it_accepts() {
    let relay = TestRelay::bind().await.expect("relay");
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = TlsIdentity::load_or_generate(directory.path()).expect("identity");
    let config = HomeRelayConfig::load_or_mint(directory.path(), relay.endpoint()).expect("config");
    let route = config.relay_route(&identity).expect("route");
    let stub = TcpListener::bind("127.0.0.1:0").await.expect("stub");
    let stub_addr = stub.local_addr().expect("stub addr");
    tokio::spawn(count_the_body(stub));
    let parked = route.clone();
    tokio::spawn(async move {
        let _ = serve_home_forever(parked, stub_addr, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let wire_route = gaugedesk_relay_transport::WebSocketRelayRoute {
        endpoint: route.endpoint.clone(),
        handle: route.handle.clone(),
        epoch: route.epoch,
        proof: route.proof,
        previous_proof: None,
    };
    let mut socket = client_leg(&wire_route).await;
    let mut client = TunnelClient::new(route.home_fingerprint).expect("client");
    let body: Vec<u8> = (0..1_000_000u32).map(|index| (index % 251) as u8).collect();
    let expected = format!(
        "{} {}",
        body.len(),
        body.iter().map(|b| u64::from(*b)).sum::<u64>()
    );
    client
        .send_head(
            "PUT",
            "/chats/c1/file?path=big.bin",
            &BTreeMap::new(),
            body.len(),
        )
        .expect("head");
    for part in body.chunks(256 * 1024) {
        client.send_body(part).expect("part");
    }
    let mut frames = FrameQueue::new();
    let mut paired = false;
    let response = loop {
        if paired {
            client.pump().expect("pump");
            frames.push(client.session_mut().take_outgoing());
            while let Some(frame) = frames.next_frame() {
                assert!(frame.len() <= gaugedesk_relay_transport::WSS_MAX_FRAME_BYTES);
                socket
                    .send(Message::Binary(frame.into()))
                    .await
                    .expect("send");
            }
            if let Some(response) = client.poll().expect("poll") {
                break response;
            }
        }
        paired |= next_frame(&mut socket, |bytes| client.session_mut().received(bytes)).await;
    };
    assert_eq!(response.status, 200);
    assert_eq!(String::from_utf8_lossy(&response.body), expected);
}
