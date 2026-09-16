use super::*;
use crate::signature::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}

fn challenge() -> RegistrationChallenge {
    RegistrationChallenge {
        version: REGISTRATION_VERSION,
        challenge_id: "op-register-1".into(),
        tenant_id: "tenant:acme".into(),
        initiating_actor: "authority:owner".into(),
        proposed_label: "Studio Mac".into(),
        nonce: "nonce-mint-1".into(),
        issued_at: 100,
        expires_at: 900,
    }
}

fn claim_for(signer: &SigningKey, challenge: &RegistrationChallenge) -> HostClaim {
    HostClaim {
        version: REGISTRATION_VERSION,
        home_id: "home:studio".into(),
        governance_pubkey: signer.public_key().as_str().to_owned(),
        tenant_id: challenge.tenant_id.clone(),
        challenge_id: challenge.challenge_id.clone(),
        challenge_nonce: challenge.nonce.clone(),
        route: "https://studio.example:8443".into(),
        route_epoch: 7,
        transport_pin: "sha256:abcd".into(),
        capabilities: vec!["accept-handoff".into(), "carry-project-home".into()],
        issued_at: 110,
        expires_at: 800,
    }
}

fn possession(signer: &SigningKey, claim: &HostClaim, nonce: &str) -> PossessionAnswer {
    let mut answer = PossessionAnswer {
        version: REGISTRATION_VERSION,
        challenge_id: claim.challenge_id.clone(),
        nonce: nonce.to_owned(),
        home_id: claim.home_id.clone(),
        governance_pubkey: claim.governance_pubkey.clone(),
        tenant_id: claim.tenant_id.clone(),
        route: claim.route.clone(),
        route_epoch: claim.route_epoch,
        transport_pin: claim.transport_pin.clone(),
        signature: crate::signature::Signature::new(Vec::new()),
    };
    answer.signature = signer.sign(&possession_signing_bytes(&answer));
    answer
}

fn possession_challenge(nonce: &str) -> PossessionChallenge {
    PossessionChallenge {
        version: REGISTRATION_VERSION,
        challenge_id: "op-register-1".into(),
        nonce: nonce.to_owned(),
        issued_at: 200,
        expires_at: 900,
    }
}

#[test]
fn a_claim_signed_for_this_challenge_verifies_and_is_still_not_an_admission() {
    let home = key(1);
    let challenge = challenge();
    let signed = sign_claim(&home, claim_for(&home, &challenge)).unwrap();
    assert_eq!(verify_claim(&signed, &challenge, 300), Ok(()));

    // Verifying the signature is half the ceremony. The claim asserts a route;
    // only answering on that route proves the Home is there.
    let answer = possession(&home, &signed.claim, "nonce-possess-1");
    assert_eq!(
        verify_possession(
            &answer,
            &signed.claim,
            &possession_challenge("nonce-possess-1"),
            None,
            300
        ),
        Ok(())
    );
}

#[test]
fn a_claim_is_bound_to_the_exact_challenge_tenant_and_key() {
    let home = key(1);
    let challenge = challenge();
    let signed = sign_claim(&home, claim_for(&home, &challenge)).unwrap();

    // A claim minted for one tenant cannot register into another, even when the
    // Home genuinely holds the key.
    let mut other_tenant = challenge.clone();
    other_tenant.tenant_id = "tenant:other".into();
    assert_eq!(
        verify_claim(&signed, &other_tenant, 300),
        Err(RegistrationError::TenantMismatch)
    );

    // A replayed claim against a freshly minted challenge answers the wrong
    // nonce, which is what makes the challenge single-use.
    let mut reminted = challenge.clone();
    reminted.nonce = "nonce-mint-2".into();
    assert_eq!(
        verify_claim(&signed, &reminted, 300),
        Err(RegistrationError::ChallengeMismatch)
    );

    // The window the tenant opened is the window the ceremony has.
    assert_eq!(
        verify_claim(&signed, &challenge, 901),
        Err(RegistrationError::Expired)
    );

    // Taking a genuine claim and relabelling whose Home it is fails: the
    // preimage covers the id, so the signature cannot survive the swap.
    let impostor = key(2);
    let mut forged = claim_for(&home, &challenge);
    forged.governance_pubkey = impostor.public_key().as_str().to_owned();
    forged.home_id = "home:impostor".into();
    let mut swapped = sign_claim(&impostor, forged).unwrap();
    swapped.claim.home_id = "home:studio".into();
    assert_eq!(
        verify_claim(&swapped, &challenge, 300),
        Err(RegistrationError::Signature)
    );
}

#[test]
fn a_capability_outside_the_closed_set_is_refused_rather_than_ignored() {
    let home = key(1);
    let challenge = challenge();
    for capabilities in [
        vec![
            "carry-project-home".to_owned(),
            "become-tenant-owner".to_owned(),
        ],
        Vec::new(),
        // Unsorted, so two claims asserting the same set cannot produce two
        // different preimages.
        vec!["carry-project-home".to_owned(), "accept-handoff".to_owned()],
    ] {
        let mut claim = claim_for(&home, &challenge);
        claim.capabilities = capabilities.clone();
        assert_eq!(
            sign_claim(&home, claim).unwrap_err(),
            RegistrationError::UnadmittedCapability,
            "{capabilities:?}"
        );
    }
}

#[test]
fn possession_must_come_back_from_the_route_the_claim_named() {
    let home = key(1);
    let challenge = challenge();
    let signed = sign_claim(&home, claim_for(&home, &challenge)).unwrap();
    let nonce = "nonce-possess-1";

    // Substituting any part of the identity is refused even though the
    // signature over the substituted statement is genuine. Signing only an
    // opaque nonce is what would have let this through.
    let mutations: [fn(&mut PossessionAnswer); 5] = [
        |answer| answer.route = "https://elsewhere.example".into(),
        |answer| answer.transport_pin = "sha256:9999".into(),
        |answer| answer.home_id = "home:other".into(),
        |answer| answer.tenant_id = "tenant:other".into(),
        |answer| answer.route_epoch = 6,
    ];
    for mutate in mutations {
        let mut answer = possession(&home, &signed.claim, nonce);
        mutate(&mut answer);
        answer.signature = home.sign(&possession_signing_bytes(&answer));
        assert_eq!(
            verify_possession(
                &answer,
                &signed.claim,
                &possession_challenge(nonce),
                None,
                300
            ),
            Err(RegistrationError::RouteSubstituted)
        );
    }

    // A different Home answering on the claimed route does not pass: the key
    // must be the one the claim named.
    let other = key(2);
    let mut answer = possession(&other, &signed.claim, nonce);
    answer.governance_pubkey = signed.claim.governance_pubkey.clone();
    assert_eq!(
        verify_possession(
            &answer,
            &signed.claim,
            &possession_challenge(nonce),
            None,
            300
        ),
        Err(RegistrationError::Signature)
    );

    // An answer to a nonce we did not just mint is a replay.
    let stale = possession(&home, &signed.claim, "nonce-possess-0");
    assert_eq!(
        verify_possession(
            &stale,
            &signed.claim,
            &possession_challenge(nonce),
            None,
            300
        ),
        Err(RegistrationError::NonceMismatch)
    );
}

#[test]
fn a_route_epoch_that_does_not_advance_cannot_readmit_a_moved_route() {
    let home = key(1);
    let challenge = challenge();
    let signed = sign_claim(&home, claim_for(&home, &challenge)).unwrap();
    let nonce = "nonce-possess-1";
    let answer = possession(&home, &signed.claim, nonce);

    // The Home has already been admitted at epoch 7 or later, so this answer
    // describes a route that has since moved on.
    for known in [7, 8] {
        assert_eq!(
            verify_possession(
                &answer,
                &signed.claim,
                &possession_challenge(nonce),
                Some(known),
                300
            ),
            Err(RegistrationError::StaleEpoch)
        );
    }
    assert_eq!(
        verify_possession(
            &answer,
            &signed.claim,
            &possession_challenge(nonce),
            Some(6),
            300
        ),
        Ok(())
    );
}
