use super::*;
use gaugedesk_core::project_host_registration::{verify_possession, HostClaim};

fn signer(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}

fn studio() -> HomeIdentity {
    HomeIdentity {
        home_id: "home:studio".into(),
        tenant_id: "tenant:acme".into(),
        route: "https://studio.example:8443".into(),
        route_epoch: Some(9),
        transport_pin: "sha256:abcd".into(),
    }
}

fn challenge() -> PossessionChallenge {
    PossessionChallenge {
        version: REGISTRATION_VERSION,
        challenge_id: "op-1".into(),
        nonce: "nonce-possess".into(),
        issued_at: 100,
        expires_at: 900,
    }
}

fn claim_matching(identity: &HomeIdentity, signer: &SigningKey) -> HostClaim {
    HostClaim {
        version: REGISTRATION_VERSION,
        home_id: identity.home_id.clone(),
        governance_pubkey: signer.public_key().as_str().to_owned(),
        tenant_id: identity.tenant_id.clone(),
        challenge_id: "op-1".into(),
        challenge_nonce: "nonce-mint".into(),
        route: identity.route.clone(),
        route_epoch: identity.route_epoch.unwrap_or(0),
        transport_pin: identity.transport_pin.clone(),
        capabilities: vec!["accept-handoff".into(), "carry-project-home".into()],
        issued_at: 100,
        expires_at: 900,
    }
}

#[test]
fn an_answer_verifies_against_the_claim_it_restates() {
    let home = signer(1);
    let identity = studio();
    let answer = answer_possession(&home, &identity, &challenge());
    let claim = claim_matching(&identity, &home);

    assert_eq!(
        verify_possession(&answer, &claim, &challenge(), None, 300),
        Ok(())
    );
    // The signature is over the identity, not the nonce alone. Rewriting the
    // route after signing breaks it, which is what makes a substituted route
    // detectable rather than merely discouraged.
    let mut moved = answer.clone();
    moved.route = "https://elsewhere.example".into();
    assert!(verify_possession(&moved, &claim, &challenge(), None, 300).is_err());
}

#[test]
fn a_home_without_a_relay_epoch_asserts_zero_and_is_not_fenced_by_it() {
    let home = signer(1);
    let mut unversioned = studio();
    unversioned.route_epoch = None;
    let answer = answer_possession(&home, &unversioned, &challenge());
    assert_eq!(answer.route_epoch, 0);

    // A claim from the same Home agrees, so the exchange completes. ADR 0174
    // records such a route as unversioned; the stale-epoch fence is what does
    // not apply to it, and that is the verifier's record to keep.
    let claim = claim_matching(&unversioned, &home);
    assert_eq!(
        verify_possession(&answer, &claim, &challenge(), None, 300),
        Ok(())
    );
}

#[tokio::test]
async fn one_request_in_one_response_out_and_the_stream_carries_nothing_else() {
    let (mut asker, mut responder) = tokio::io::duplex(64 * 1024);
    let home = signer(1);
    let identity = studio();

    let served = identity.clone();
    let serving = tokio::spawn(async move {
        serve_possession(&mut responder, &signer(1), &served)
            .await
            .unwrap();
    });

    write_frame(&mut asker, &challenge()).await.unwrap();
    let answer: PossessionAnswer = read_frame(&mut asker).await.unwrap();
    serving.await.unwrap();

    let claim = claim_matching(&studio(), &home);
    assert_eq!(
        verify_possession(&answer, &claim, &challenge(), None, 300),
        Ok(())
    );
}

#[tokio::test]
async fn an_oversized_declared_length_is_refused_before_anything_is_allocated() {
    let (mut asker, mut peer) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let oversized = (MAX_POSSESSION_FRAME as u32 + 1).to_be_bytes();
        let _ = peer.write_all(&oversized).await;
        let _ = peer.flush().await;
        // Deliberately sends no body: a verifier that trusted the length would
        // now be waiting on bytes that are never coming, holding the buffer it
        // allocated on a stranger's say-so.
        std::future::pending::<()>().await;
    });

    let result = read_frame::<_, PossessionAnswer>(&mut asker).await;
    assert!(
        matches!(result, Err(PossessionError::Malformed(_))),
        "expected a refusal, got {result:?}"
    );
}

#[tokio::test]
async fn a_frame_that_is_not_a_possession_answer_is_a_refusal_not_a_hang() {
    let (mut asker, mut peer) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let body = br#"{"not":"an answer"}"#;
        let _ = peer.write_all(&(body.len() as u32).to_be_bytes()).await;
        let _ = peer.write_all(body).await;
        let _ = peer.flush().await;
    });

    let result = read_frame::<_, PossessionAnswer>(&mut asker).await;
    assert!(matches!(result, Err(PossessionError::Malformed(_))));
}

#[test]
fn a_route_is_dialable_or_it_is_refused() {
    assert_eq!(
        dial_address("https://studio.example:8443").as_deref(),
        Some("studio.example:8443")
    );
    assert_eq!(
        dial_address("studio.example").as_deref(),
        Some("studio.example:443")
    );
    // A route with a path is not a dial target: the claim names where a Home
    // answers, not a URL to fetch.
    assert_eq!(
        dial_address("https://studio.example:8443/somewhere").as_deref(),
        Some("studio.example:8443")
    );
    assert_eq!(dial_address("https://"), None);
    assert_eq!(dial_address("   "), None);
}

#[tokio::test]
async fn an_unusable_pin_or_route_never_reaches_the_network() {
    let challenge = challenge();
    assert!(matches!(
        ask_possession(
            "https://studio.example:8443",
            "not-hex",
            "home:a",
            &challenge
        )
        .await,
        Err(PossessionError::UnusablePin)
    ));
    assert!(matches!(
        ask_possession("https://", "sha256:abcd", "home:a", &challenge).await,
        Err(PossessionError::UnusableRoute)
    ));
}
