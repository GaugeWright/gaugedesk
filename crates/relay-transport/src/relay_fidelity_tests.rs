use super::*;
use crate::{websocket_handshake, RouteProof, WebSocketRelayRoute};
use tokio_tungstenite::{connect_async, MaybeTlsStream};

type Peer = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn route(relay: &TestRelay, handle: u8) -> WebSocketRelayRoute {
    use base64::Engine;
    WebSocketRelayRoute {
        endpoint: relay.endpoint().to_owned(),
        handle: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([handle; 32]),
        epoch: 1,
        proof: RouteProof::new([7; 32]),
        previous_proof: None,
    }
}

async fn leg(route: &WebSocketRelayRoute, role: WebSocketRelayRole) -> Peer {
    let (mut socket, _) = connect_async(format!("{}/v1/relay/{}", route.endpoint, route.handle))
        .await
        .expect("loopback relay websocket");
    socket
        .send(Message::Binary(
            websocket_handshake(route, role)
                .expect("real v1 handshake")
                .to_vec()
                .into(),
        ))
        .await
        .expect("send handshake");
    socket
}

async fn next(socket: &mut Peer) -> Message {
    timeout(Duration::from_secs(3), socket.next())
        .await
        .expect("bounded relay response")
        .expect("relay socket response")
        .expect("valid websocket response")
}

async fn ready(socket: &mut Peer) {
    assert_eq!(next(socket).await, Message::Binary(READY.to_vec().into()));
}

async fn ping(socket: &mut Peer) {
    socket
        .send(Message::Text(crate::wire::WSS_KEEPALIVE_REQUEST.into()))
        .await
        .expect("ping parked leg");
    assert_eq!(
        next(socket).await,
        Message::Text(crate::wire::WSS_KEEPALIVE_RESPONSE.into())
    );
}

async fn pair(route: &WebSocketRelayRoute) -> (Peer, Peer) {
    let mut home = leg(route, WebSocketRelayRole::Home).await;
    // Actual acknowledgement establishes admission before the client arrives.
    ping(&mut home).await;
    let mut client = leg(
        &WebSocketRelayRoute {
            previous_proof: None,
            ..route.clone()
        },
        WebSocketRelayRole::Client,
    )
    .await;
    ready(&mut home).await;
    ready(&mut client).await;
    (home, client)
}

async fn carry(home: &mut Peer, client: &mut Peer, bytes: &[u8]) {
    client
        .send(Message::Binary(bytes.to_vec().into()))
        .await
        .expect("send pair bytes");
    assert_eq!(next(home).await, Message::Binary(bytes.to_vec().into()));
}

async fn closed(socket: &mut Peer) {
    match next(socket).await {
        Message::Close(Some(frame)) => assert_eq!(frame.code, CloseCode::Policy),
        message => panic!("old route socket was not policy-closed: {message:?}"),
    }
}

#[tokio::test]
async fn rotation_closes_every_active_pair_and_waiter_then_new_epoch_carries() {
    let relay = TestRelay::bind().await.expect("relay");
    let first = route(&relay, 1);
    let (mut h1, mut c1) = pair(&first).await;
    let (mut h2, mut c2) = pair(&first).await;
    carry(&mut h1, &mut c1, b"first").await;
    carry(&mut h2, &mut c2, b"second").await;
    let mut w1 = leg(&first, WebSocketRelayRole::Home).await;
    let mut w2 = leg(&first, WebSocketRelayRole::Home).await;
    ping(&mut w1).await;
    ping(&mut w2).await;
    let second = WebSocketRelayRoute {
        epoch: 2,
        proof: RouteProof::new([8; 32]),
        previous_proof: Some(first.proof),
        ..first.clone()
    };
    let mut fresh_home = leg(&second, WebSocketRelayRole::Home).await;
    ping(&mut fresh_home).await;
    for socket in [&mut h1, &mut c1, &mut h2, &mut c2, &mut w1, &mut w2] {
        closed(socket).await;
    }
    let mut stale = leg(&first, WebSocketRelayRole::Client).await;
    closed(&mut stale).await;
    let mut fresh_client = leg(
        &WebSocketRelayRoute {
            previous_proof: None,
            ..second
        },
        WebSocketRelayRole::Client,
    )
    .await;
    ready(&mut fresh_home).await;
    ready(&mut fresh_client).await;
    carry(&mut fresh_home, &mut fresh_client, b"new epoch").await;
}

#[tokio::test]
async fn invalid_rotation_preserves_pairs_and_pair_close_is_local() {
    let relay = TestRelay::bind().await.expect("relay");
    let first = route(&relay, 2);
    let (mut h1, mut c1) = pair(&first).await;
    let (mut h2, mut c2) = pair(&first).await;
    for (epoch, previous) in [(2, RouteProof::new([9; 32])), (3, first.proof)] {
        let bad = WebSocketRelayRoute {
            epoch,
            previous_proof: Some(previous),
            proof: RouteProof::new([8; 32]),
            ..first.clone()
        };
        let mut bad_home = leg(&bad, WebSocketRelayRole::Home).await;
        closed(&mut bad_home).await;
        carry(&mut h1, &mut c1, b"still first").await;
        carry(&mut h2, &mut c2, b"still second").await;
    }
    c1.close(None).await.expect("close one pair");
    assert!(matches!(next(&mut h1).await, Message::Close(_)));
    carry(&mut h2, &mut c2, b"unaffected").await;
}

#[tokio::test]
async fn most_recent_acknowledged_ping_selects_home_not_connection_order() {
    let relay = TestRelay::bind().await.expect("relay");
    let r = route(&relay, 3);
    let mut older = leg(&r, WebSocketRelayRole::Home).await;
    ping(&mut older).await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    let mut newer = leg(&r, WebSocketRelayRole::Home).await;
    ping(&mut newer).await;
    let mut client = leg(&r, WebSocketRelayRole::Client).await;
    ready(&mut newer).await;
    ready(&mut client).await;
    carry(&mut newer, &mut client, b"newest hearing beats oldest").await;
    let mut replacement = leg(&r, WebSocketRelayRole::Home).await;
    ping(&mut replacement).await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    ping(&mut older).await;
    let mut client2 = leg(&r, WebSocketRelayRole::Client).await;
    ready(&mut older).await;
    ready(&mut client2).await;
    carry(
        &mut older,
        &mut client2,
        b"older refreshed beats connection order",
    )
    .await;
    // Unselected replacement is still parked, and pings are never forwarded.
    ping(&mut replacement).await;
}

#[tokio::test]
async fn rotation_closes_waiting_clients_and_one_shot_sources() {
    let relay = TestRelay::bind().await.expect("relay");
    let r = route(&relay, 4);
    let (mut h, mut c) = pair(&r).await;
    c.close(None).await.expect("close initial pair");
    assert!(matches!(next(&mut h).await, Message::Close(_)));
    let mut waiting = leg(&r, WebSocketRelayRole::Client).await;
    ping(&mut waiting).await;
    let rotated = WebSocketRelayRoute {
        epoch: 2,
        proof: RouteProof::new([8; 32]),
        previous_proof: Some(r.proof),
        ..r
    };
    let mut home = leg(&rotated, WebSocketRelayRole::Home).await;
    ping(&mut home).await;
    closed(&mut waiting).await;
    let one = route(&relay, 5);
    let mut source = leg(&one, WebSocketRelayRole::Source).await;
    ping(&mut source).await;
    let rotated = WebSocketRelayRoute {
        epoch: 2,
        proof: RouteProof::new([8; 32]),
        previous_proof: Some(one.proof),
        ..one
    };
    let mut new_source = leg(&rotated, WebSocketRelayRole::Source).await;
    ping(&mut new_source).await;
    closed(&mut source).await;
}

#[tokio::test(start_paused = true)]
async fn actual_clock_predicate_preserves_strict_silence_and_wait_bounds() {
    let start = Instant::now();
    tokio::time::advance(WAIT).await;
    assert!(waiter_expired(start, None, Instant::now()));
    let heard = Instant::now();
    tokio::time::advance(SILENCE).await;
    assert!(!waiter_expired(start, Some(heard), Instant::now()));
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(waiter_expired(start, Some(heard), Instant::now()));
    tokio::time::advance(PARKED_WAIT - WAIT - SILENCE - Duration::from_millis(1)).await;
    assert!(waiter_expired(start, Some(Instant::now()), Instant::now()));
}

#[tokio::test]
async fn no_ping_home_ties_and_waiting_client_order_remain_fifo() {
    let relay = TestRelay::bind().await.expect("relay");
    let r = route(&relay, 6);
    let mut first = leg(&r, WebSocketRelayRole::Home).await;
    timeout(Duration::from_secs(3), async {
        while relay.waiting_homes(&r.handle).await != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first home admission");
    let mut second = leg(&r, WebSocketRelayRole::Home).await;
    timeout(Duration::from_secs(3), async {
        while relay.waiting_homes(&r.handle).await != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second home admission");
    let mut client = leg(&r, WebSocketRelayRole::Client).await;
    ready(&mut first).await;
    ready(&mut client).await;
    carry(&mut first, &mut client, b"oldest without hearing").await;
    ping(&mut second).await;
    let (mut seed, mut seed_client) = pair(&route(&relay, 7)).await;
    seed_client.close(None).await.expect("close seed");
    assert!(matches!(next(&mut seed).await, Message::Close(_)));
    let r2 = route(&relay, 7);
    let mut c1 = leg(&r2, WebSocketRelayRole::Client).await;
    ping(&mut c1).await;
    let mut c2 = leg(&r2, WebSocketRelayRole::Client).await;
    ping(&mut c2).await;
    let mut home = leg(&r2, WebSocketRelayRole::Home).await;
    ready(&mut c1).await;
    ready(&mut home).await;
    carry(&mut home, &mut c1, b"waiting clients FIFO").await;
    ping(&mut c2).await;
}

#[tokio::test]
async fn equal_hearing_ticks_keep_first_and_expired_waiters_are_not_selected() {
    let now = Instant::now();
    let pending = |id, heard| Pending {
        id,
        role: WebSocketRelayRole::Home,
        handoff: oneshot::channel().0,
        last_heard: Some(10),
        started: now,
        heard_at: heard,
    };
    let legs = [pending(1, Some(now)), pending(2, Some(now))];
    assert_eq!(pairing_index(&legs, WebSocketRelayRole::Client), Some(0));
    let mut legs = legs;
    legs[0].started = now - WAIT - Duration::from_secs(1);
    legs[0].heard_at = None;
    assert_eq!(pairing_index(&legs, WebSocketRelayRole::Client), Some(1));
}

#[tokio::test]
async fn dropping_relay_closes_owned_pairs_and_pending_sockets() {
    let relay = TestRelay::bind().await.expect("relay");
    let r = route(&relay, 8);
    let (mut home, mut client) = pair(&r).await;
    let mut pending = leg(&r, WebSocketRelayRole::Home).await;
    ping(&mut pending).await;
    drop(relay);
    closed(&mut home).await;
    closed(&mut client).await;
    closed(&mut pending).await;
}

#[tokio::test]
async fn one_shot_rotation_closes_active_pair_and_waiting_target() {
    let relay = TestRelay::bind().await.expect("relay");
    let first = route(&relay, 9);
    let mut source = leg(&first, WebSocketRelayRole::Source).await;
    ping(&mut source).await;
    let mut target = leg(&first, WebSocketRelayRole::Target).await;
    ready(&mut source).await;
    ready(&mut target).await;
    carry(&mut source, &mut target, b"one shot pair").await;
    let second = WebSocketRelayRoute {
        epoch: 2,
        proof: RouteProof::new([8; 32]),
        previous_proof: Some(first.proof),
        ..first
    };
    let mut next_source = leg(&second, WebSocketRelayRole::Source).await;
    ping(&mut next_source).await;
    closed(&mut source).await;
    closed(&mut target).await;
    next_source.close(None).await.expect("retire initializer");
    let current = WebSocketRelayRoute {
        previous_proof: None,
        ..second.clone()
    };
    let mut waiting_target = leg(&current, WebSocketRelayRole::Target).await;
    ping(&mut waiting_target).await;
    let third = WebSocketRelayRoute {
        epoch: 3,
        proof: RouteProof::new([9; 32]),
        previous_proof: Some(second.proof),
        ..second
    };
    let mut third_source = leg(&third, WebSocketRelayRole::Source).await;
    ping(&mut third_source).await;
    closed(&mut waiting_target).await;
}
