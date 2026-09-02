//! The Home reaching a box, over a real relay.
//!
//! `crate::tokenwright`'s unit tests prove the derivations agree with the box's
//! own. This proves the half they cannot: that a leg dialled from *this* process
//! splices, that the pin is enforced, and that a claim comes back sealed with
//! neither capability having passed through a browser.
//!
//! The far end is a stub rather than a real TokenWright box — a box is a
//! separate repository — so what this holds is the transport and the claim
//! contract. `crates/app/tests/account.rs` holds the sealing.

use base64::Engine as _;
use gaugedesk_relay_transport::test_relay::TestRelay;
use gaugedesk_relay_transport::{serve_home_forever, HomeRelayConfig, TlsIdentity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use gaugedesk_app::tokenwright::{
    claim, claim_route_token, parse_invite, pin_bytes, request, Invite,
};

const ROUTE: &str = "F8E0l3whZo41YL6B8yzSJAQdF8E0l3whZo41YL6B8yw";

fn invite_for(endpoint: &str, code: &str, fingerprint: &str) -> String {
    let body = serde_json::json!({
        "v": 1, "r": endpoint, "c": code, "f": fingerprint,
    })
    .to_string();
    format!(
        "tw1_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body.as_bytes())
    )
}

/// A box, built the way a box is: a plain HTTP listener on loopback, and a
/// relay leg parked on the claim-code handle that splices to it.
///
/// `serve_home_forever` is the shipped parker, so this test exercises the same
/// splice a real box does rather than a hand-rolled stand-in.
async fn park_a_box(endpoint: &str, token: [u8; 32], identity: &TlsIdentity, answer: &'static str) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("stub");
    let address = listener.local_addr().expect("stub addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                let _ = stream.read(&mut buffer).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    answer.len(),
                    answer,
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    // The handle a box parks on is derived from the claim code, not minted —
    // that is what makes finding the box and guessing the code one problem.
    let derived =
        gaugedesk_relay_transport::one_shot_websocket_route(endpoint, token).expect("route");
    let config = HomeRelayConfig {
        endpoint: endpoint.to_owned(),
        handle: derived.handle.clone(),
        proof: derived.proof.to_base64url(),
        previous_proof: None,
        route_epoch: derived.epoch,
    };
    let route = config.relay_route(identity).expect("route");
    let parked = identity.clone();
    tokio::spawn(async move {
        if let Err(error) = serve_home_forever(route, address, parked).await {
            eprintln!("[box] the leg stopped: {error}");
        }
    });
    // The leg must exist before a client joins, or the relay refuses the join
    // rather than waiting for a peer that has not arrived.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
}

#[tokio::test]
async fn the_home_dials_a_box_and_claims_it() {
    let relay = TestRelay::bind().await.expect("relay");
    let identity = TlsIdentity::generate().expect("identity");
    let fingerprint = format!("sha256:{}", hex::encode(identity.fingerprint()));
    let code = "ABCD-EFGH-JKMN-PQRS-TVWX";

    let answer = concat!(
        r#"{"paired":{"home":"home_a","paired_at":"2026-09-01T20:00:00Z","#,
        r#""fingerprint":"FINGERPRINT","route":"ROUTE"},"#,
        r#""key":{"id":"key_c30f","name":"paired-home","secret":"tw_secret"}}"#
    );
    let answer: &'static str = Box::leak(
        answer
            .replace("FINGERPRINT", &fingerprint)
            .replace("ROUTE", ROUTE)
            .into_boxed_str(),
    );

    park_a_box(relay.endpoint(), claim_route_token(code), &identity, answer).await;

    let invite = parse_invite(&invite_for(relay.endpoint(), code, &fingerprint)).expect("invite");
    let claimed = claim(&invite, "home_a", "home-key").await.expect("claim");

    assert_eq!(claimed.route, ROUTE, "the durable route must come back");
    assert_eq!(claimed.key, "tw_secret");
    assert_eq!(claimed.fingerprint, fingerprint);
}

#[tokio::test]
async fn a_box_presenting_another_certificate_is_refused() {
    // The pin is the box's whole identity here — no chain is built and no name
    // is checked — so a mismatch must end the handshake before any application
    // byte crosses, not be reported after a reply is read.
    let relay = TestRelay::bind().await.expect("relay");
    let real = TlsIdentity::generate().expect("identity");
    let impostor = TlsIdentity::generate().expect("impostor");
    let code = "ABCD-EFGH-JKMN-PQRS-TVWX";

    park_a_box(
        relay.endpoint(),
        claim_route_token(code),
        &impostor,
        r#"{"paired":{},"key":{}}"#,
    )
    .await;

    let invite = Invite {
        relay_endpoint: relay.endpoint().to_owned(),
        claim_code: code.to_owned(),
        fingerprint: format!("sha256:{}", hex::encode(real.fingerprint())),
    };
    let error = claim(&invite, "home_a", "home-key")
        .await
        .expect_err("an impostor must be refused");
    assert!(error.to_string().contains("certificate"), "said: {error}",);
}

#[tokio::test]
async fn a_box_that_hands_over_no_route_is_refused() {
    // Storing this would work until the box's next restart and then fail with
    // nothing to look at: the claim code is spent and the box has moved.
    let relay = TestRelay::bind().await.expect("relay");
    let identity = TlsIdentity::generate().expect("identity");
    let fingerprint = format!("sha256:{}", hex::encode(identity.fingerprint()));
    let code = "ABCD-EFGH-JKMN-PQRS-TVWX";

    let answer: &'static str = Box::leak(
        serde_json::json!({
            "paired": { "fingerprint": fingerprint, "paired_at": "" },
            "key": { "id": "k", "secret": "s" },
        })
        .to_string()
        .into_boxed_str(),
    );

    park_a_box(relay.endpoint(), claim_route_token(code), &identity, answer).await;

    let invite = parse_invite(&invite_for(relay.endpoint(), code, &fingerprint)).expect("invite");
    let error = claim(&invite, "home_a", "home-key")
        .await
        .expect_err("a box with no route must be refused");
    assert!(
        error.to_string().contains("newer TokenWright"),
        "said: {error}"
    );
}

#[tokio::test]
async fn a_box_that_is_not_there_fails_rather_than_hanging() {
    // A box that is off and a relay that never splices look identical from
    // here, and both must fail a request handler rather than hold it.
    let relay = TestRelay::bind().await.expect("relay");
    let identity = TlsIdentity::generate().expect("identity");
    let error = request(
        relay.endpoint(),
        claim_route_token("ABCD-EFGH-JKMN-PQRS-TVWX"),
        pin_bytes(&hex::encode(identity.fingerprint())).expect("pin"),
        "GET",
        "/v1/models",
        &std::collections::BTreeMap::new(),
        None,
    )
    .await
    .expect_err("nothing is parked on that route");
    assert!(!error.to_string().is_empty());
}
