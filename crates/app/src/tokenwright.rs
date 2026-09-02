//! Reaching a TokenWright box, from the Home.
//!
//! A box is a model server the person owns — in ADR 0158's words, the thing that
//! "takes the place of `api.openai.com` for that Home". It is reached over a
//! relay leg it dials out to, with end-to-end TLS pinned to its certificate.
//!
//! ## Why this is here and not in the browser
//!
//! It was in the browser first, and that was wrong. The wasm tunnel exists for
//! one purpose (ADR 0130): letting a page reach **a Home that is not publicly
//! addressable**. Every tunnel the workbench opens is keyed by Home id. A box is
//! not a Home; it is a peer of one, exactly like every other provider.
//!
//! The mistake was reaching for the tool that matched the *wire* — relay plus
//! certificate pin, which only the wasm tunnel spoke — instead of asking what
//! the topology was. The credential settles it: a box's route and key are sealed
//! in the person's account store, which this control plane serves, and a sealed
//! credential is used by the thing that holds it. That is how `resolve_token`
//! works for every other provider, and there is no reason a box differs.
//!
//! So the browser asks the Home to claim a box and to carry requests to it, and
//! the two capabilities never leave this process.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gaugedesk_relay_transport::{
    connect_pinned, connect_websocket_stream, one_shot_websocket_route, WebSocketRelayRole,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The alphabet a claim code is printed in — Crockford-style, with the
/// characters that are misread or misheard removed. Kept in step with the box's
/// own `pairing.ALPHABET`: a code is normalised into this set before hashing, so
/// a disagreement here is a proof neither side can explain.
const CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Domain separators. Each derivation from the claim code is distinct, so the
/// relay — which necessarily sees the handle — learns nothing that would let it
/// claim the box.
const HANDLE_DOMAIN: &[u8] = b"tokenwright/relay-handle/v1";
const CLAIM_PROOF_DOMAIN: &[u8] = b"tokenwright/claim-proof/v1";

const INVITE_PREFIX: &str = "tw1_";

/// How long the whole claim may take. A box that is off and a relay that never
/// splices look the same from here, and both must fail rather than hang a
/// request handler.
const CLAIM_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug)]
pub struct BoxError(pub String);

impl std::fmt::Display for BoxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BoxError {}

fn fail<T>(message: impl Into<String>) -> Result<T, BoxError> {
    Err(BoxError(message.into()))
}

/// What a pairing string carries. Three things, because a tunnel needs all
/// three: somewhere to rendezvous, a certificate to trust, and proof you may
/// take the box.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub relay_endpoint: String,
    pub claim_code: String,
    /// `sha256:<64 hex>`, the spelling the box's own documents use.
    pub fingerprint: String,
}

/// Every field optional so a *missing* one is diagnosed by name below rather
/// than collapsing into "damaged". A string with no pin and a string that was
/// half-copied are different problems and send a person to different places.
#[derive(Deserialize)]
struct InviteWire {
    #[serde(default)]
    v: u32,
    #[serde(default)]
    r: String,
    #[serde(default)]
    c: String,
    #[serde(default)]
    f: String,
}

/// One spelling of a code. The person reading it aloud is not the one hashing
/// it, so case and the printed hyphens must not change a derivation.
pub fn normalize_claim_code(code: &str) -> String {
    code.to_ascii_uppercase()
        .bytes()
        .filter(|byte| CODE_ALPHABET.contains(byte))
        .map(char::from)
        .collect()
}

/// Read a pairing string, or say which part of it is wrong.
///
/// Every failure is a person having mistyped or half-copied something, so each
/// names the thing to look at. **None echo the token**: it contains a live claim
/// code, and a message quoting it lands in whatever log the caller writes.
pub fn parse_invite(token: &str) -> Result<Invite, BoxError> {
    let token = token.trim();
    if token.is_empty() {
        return fail("paste the pairing string printed on the box");
    }
    let Some(body) = token.strip_prefix(INVITE_PREFIX) else {
        return fail(format!(
            "that is not a TokenWright pairing string — they begin with {INVITE_PREFIX:?}"
        ));
    };
    // The alphabet is checked before decoding. A decoder that skips unknown
    // characters makes `x!!` a second spelling of `x`, and the relay matches
    // legs by comparing handle *strings*.
    if body.is_empty()
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return fail("that pairing string is damaged; copy the whole line from the box");
    }
    let Ok(raw) = URL_SAFE_NO_PAD.decode(body) else {
        return fail("that pairing string is damaged; copy the whole line from the box");
    };
    let Ok(wire) = serde_json::from_slice::<InviteWire>(&raw) else {
        return fail("that pairing string is damaged; copy the whole line from the box");
    };
    if wire.v != 1 {
        return fail(format!(
            "that pairing string is version {}, which this version of GaugeDesk does not read",
            wire.v
        ));
    }
    if wire.r.trim().is_empty() {
        return fail("that pairing string carries no relay endpoint");
    }
    if normalize_claim_code(&wire.c).is_empty() {
        return fail("that pairing string carries no claim code");
    }
    let hex = wire.f.strip_prefix("sha256:").unwrap_or(&wire.f);
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        // Its own message: without a pin there is no handshake to attempt, and
        // "connection failed" would send someone to look at their network.
        return fail("the certificate fingerprint in that pairing string is not a SHA-256 digest");
    }
    Ok(Invite {
        relay_endpoint: wire.r,
        claim_code: wire.c,
        fingerprint: format!("sha256:{}", hex.to_ascii_lowercase()),
    })
}

/// The value a box pins as "the Home that claimed me".
///
/// One-way from the account key, so a compromised box learns nothing that opens
/// anything here — and deterministic, because the box refuses a later claim
/// presenting a different key, and a value that changed between claims would
/// make re-pairing fail for a reason nobody could see.
pub fn home_key_for(account_key: [u8; 32]) -> String {
    hex::encode(digest(b"gaugedesk/tokenwright-home-key/v1", &account_key))
}

fn digest(domain: &[u8], rest: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(rest);
    hasher.finalize().into()
}

/// The 32-byte rendezvous token an unclaimed box parks on.
pub fn claim_route_token(code: &str) -> [u8; 32] {
    digest(HANDLE_DOMAIN, normalize_claim_code(code).as_bytes())
}

/// What the box compares, in constant time, before it will admit a claim.
///
/// A *separate* derivation from the handle: the relay sees the handle, so a
/// proof derivable from it would let the relay claim every box it carries.
pub fn claim_proof(code: &str) -> String {
    hex::encode(digest(
        CLAIM_PROOF_DOMAIN,
        normalize_claim_code(code).as_bytes(),
    ))
}

/// Decode a `sha256:<hex>` or bare-hex pin into the 32 bytes the verifier wants.
pub fn pin_bytes(fingerprint: &str) -> Result<[u8; 32], BoxError> {
    let hex_part = fingerprint
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(fingerprint.trim());
    let Ok(raw) = hex::decode(hex_part) else {
        return fail("the certificate fingerprint is not hex");
    };
    raw.try_into()
        .map_err(|_| BoxError("the certificate fingerprint is not 32 bytes".to_owned()))
}

/// Decode a base64url rendezvous token.
pub fn route_bytes(route: &str) -> Result<[u8; 32], BoxError> {
    let Ok(raw) = URL_SAFE_NO_PAD.decode(route.trim()) else {
        return fail("the stored route is not base64url");
    };
    raw.try_into()
        .map_err(|_| BoxError("a relay token is 32 bytes".to_owned()))
}

/// One request to a box, over a leg dialled for it.
///
/// A leg per request rather than a pool. The relay refuses a third leg on a
/// route, and a pooled leg held open by this process would make the *next*
/// request — from any device — wait for a splice that cannot happen. Boxes are
/// managed occasionally; the cost of a fresh dial is the right trade against a
/// stuck route.
pub async fn request(
    endpoint: &str,
    token: [u8; 32],
    pin: [u8; 32],
    method: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), BoxError> {
    // The canonical derivation, not a local copy of it. The relay matches legs
    // by comparing the handle it is given, so a second implementation of
    // "handle and proof from a token" is a second chance to disagree with the
    // thing it has to agree with.
    let route = one_shot_websocket_route(endpoint, token)
        .map_err(|error| BoxError(format!("that relay endpoint cannot be used: {error}")))?;
    let carrier = connect_websocket_stream(&route, WebSocketRelayRole::Client)
        .await
        .map_err(|error| BoxError(format!("could not reach the box: {error}")))?;
    let mut tls = connect_pinned(carrier, pin).await.map_err(|error| {
        BoxError(format!(
            "the box did not present the expected certificate: {error}"
        ))
    })?;

    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: box\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!(
            "Content-Length: {}\r\nContent-Type: application/json\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    tls.write_all(request.as_bytes())
        .await
        .map_err(|error| BoxError(format!("writing to the box: {error}")))?;
    if let Some(body) = body {
        tls.write_all(body)
            .await
            .map_err(|error| BoxError(format!("writing to the box: {error}")))?;
    }
    tls.flush()
        .await
        .map_err(|error| BoxError(format!("writing to the box: {error}")))?;

    let mut raw = Vec::new();
    // `Connection: close` above is what ends this read. Parsing framing well
    // enough to keep the leg alive would buy nothing: the leg is per request.
    tls.read_to_end(&mut raw)
        .await
        .map_err(|error| BoxError(format!("reading from the box: {error}")))?;
    split_response(&raw)
}

fn split_response(raw: &[u8]) -> Result<(u16, Vec<u8>), BoxError> {
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return fail("the box's answer had no headers");
    };
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.split("\r\n");
    let Some(status_line) = lines.next() else {
        return fail("the box's answer had no status line");
    };
    let Some(code) = status_line.split_whitespace().nth(1) else {
        return fail("the box's answer had no status code");
    };
    let Ok(status) = code.parse::<u16>() else {
        return fail("the box's answer had no status code");
    };
    Ok((status, raw[split + 4..].to_vec()))
}

/// What a successful claim yields. The two capabilities are here exactly long
/// enough to be sealed.
#[derive(Clone, Debug, Serialize)]
pub struct ClaimedBox {
    pub fingerprint: String,
    pub route: String,
    pub key: String,
    pub key_id: String,
    pub relay_endpoint: String,
    pub paired_at: String,
    pub home_id: String,
}

#[derive(Deserialize)]
struct ClaimAnswer {
    paired: Option<ClaimPaired>,
    key: Option<ClaimKey>,
}

#[derive(Deserialize)]
struct ClaimPaired {
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    route: String,
    #[serde(default)]
    paired_at: String,
}

#[derive(Deserialize)]
struct ClaimKey {
    #[serde(default)]
    id: String,
    #[serde(default)]
    secret: String,
}

/// Claim a box, over a leg this process dials.
///
/// The claim code is single-use and expires in fifteen minutes, so the address
/// used here is dead within the hour; the route the box returns is how it is
/// reached from then on, and the box sends it exactly once.
pub async fn claim(invite: &Invite, home_id: &str, home_key: &str) -> Result<ClaimedBox, BoxError> {
    let pin = pin_bytes(&invite.fingerprint)?;
    let body = serde_json::json!({
        "proof": claim_proof(&invite.claim_code),
        "home": { "id": home_id, "key": home_key },
    })
    .to_string();

    let answer = tokio::time::timeout(
        CLAIM_TIMEOUT,
        request(
            &invite.relay_endpoint,
            claim_route_token(&invite.claim_code),
            pin,
            "POST",
            "/pair/claim",
            &BTreeMap::new(),
            Some(body.as_bytes()),
        ),
    )
    .await
    .map_err(|_| {
        BoxError(
            "the box did not answer in time; it may be switched off, or the relay may be \
             unreachable from here"
                .to_owned(),
        )
    })??;

    let (status, raw) = answer;
    if status == 409 {
        return fail(
            "this box has already been claimed; unpair it on the box to get a new pairing string",
        );
    }
    if status != 200 {
        return fail(format!("the box refused the claim ({status})"));
    }
    let Ok(parsed) = serde_json::from_slice::<ClaimAnswer>(&raw) else {
        return fail("the box's answer to the claim could not be read");
    };
    let (Some(paired), Some(key)) = (parsed.paired, parsed.key) else {
        return fail("the box did not answer the claim");
    };
    if paired.fingerprint != invite.fingerprint {
        // Two different layers: a claim in a JSON body, and the certificate the
        // handshake actually verified. Agreement is the point of pinning.
        return fail("the box reported a different certificate than the pairing string named");
    }
    if paired.route.is_empty() {
        return fail(
            "this box handed over no route to reach it again; it needs a newer TokenWright",
        );
    }
    route_bytes(&paired.route)?;
    if key.secret.is_empty() {
        return fail("the box did not return a key");
    }
    Ok(ClaimedBox {
        fingerprint: paired.fingerprint,
        route: paired.route,
        key: key.secret,
        key_id: key.id,
        relay_endpoint: invite.relay_endpoint.clone(),
        paired_at: paired.paired_at,
        home_id: home_id.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors produced by the box itself (`tokenwright.pairing`,
    /// `tokenwright.invite`), not by this implementation.
    ///
    /// These are the only tests here that can catch the failure that matters:
    /// the two sides deriving different bytes from one code. It has no good
    /// symptom — the relay pairs nobody, or the box refuses a proof it cannot
    /// explain — so it has to be caught by agreeing with a recorded answer
    /// rather than with ourselves.
    const VECTORS: &[(&str, &str, &str, &str)] = &[
        // (code, normalized, handle, claim proof)
        (
            "ABCD-EFGH-JKMN-PQRS-TVWX",
            "ABCDEFGHJKMNPQRSTVWX",
            "ARcI4-5AsZGNAe-NBaNL6EZlJPEfd8IcKB-npdUgGs8",
            "d4a1a5a6d21543d10ff53f7f172413541d565901af544f5dae0b0435d8b0c908",
        ),
        (
            "abcd-efgh-jkmn-pqrs-tvwx",
            "ABCDEFGHJKMNPQRSTVWX",
            "ARcI4-5AsZGNAe-NBaNL6EZlJPEfd8IcKB-npdUgGs8",
            "d4a1a5a6d21543d10ff53f7f172413541d565901af544f5dae0b0435d8b0c908",
        ),
        (
            "0000-0000-0000-0000-0000",
            "00000000000000000000",
            "Tt2MVbAtg9jFAI9TQMVyFaIp3U4rdkwW07VO7YqhIlM",
            "b92055e66bb196ce39c0ff8a0bbafb343f907bc0a119527fe700d8522e443bfe",
        ),
        (
            "M W 1 7-J81G-WEBE-ZD0C-MQJ3",
            "MW17J81GWEBEZD0CMQJ3",
            "ftvdZ6DlLNxDiOqTJ4WtQuJUKzu4bRbQkdHy9U-2mNo",
            "7ab90489b88e09a49f20f2f5700901aa66ec1c0c5c167a8cdcdad3d5230e25df",
        ),
    ];

    /// Produced by the box's own `tokenwright.invite.encode`.
    const INVITE: &str = "tw1_eyJ2IjoxLCJyIjoid3NzOi8vcmVsYXkuZXhhbXBsZTo0NDMvciIsImMiOiJBQkNELUVGR0gtSktNTi1QUVJTLVRWV1giLCJmIjoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifQ";

    #[test]
    fn the_derivations_agree_with_the_box() {
        for (code, normalized, handle, proof) in VECTORS {
            assert_eq!(
                &normalize_claim_code(code),
                normalized,
                "normalising {code}"
            );
            assert_eq!(
                &URL_SAFE_NO_PAD.encode(claim_route_token(code)),
                handle,
                "handle for {code}",
            );
            assert_eq!(&claim_proof(code), proof, "claim proof for {code}");
        }
    }

    #[test]
    fn the_claim_proof_is_not_the_relay_proof() {
        // The relay sees the handle and its proof. If the claim proof could be
        // derived from either, the relay could claim every box it carries.
        let code = VECTORS[0].0;
        let route = one_shot_websocket_route("wss://relay.example", claim_route_token(code))
            .expect("route");
        assert_ne!(claim_proof(code), route.proof.to_base64url());
        assert_ne!(claim_proof(code), route.handle);
    }

    #[test]
    fn a_pairing_string_the_box_produced_reads_back() {
        let invite = parse_invite(INVITE).expect("parse");
        assert_eq!(invite.relay_endpoint, "wss://relay.example:443/r");
        assert_eq!(invite.claim_code, "ABCD-EFGH-JKMN-PQRS-TVWX");
        assert_eq!(invite.fingerprint, format!("sha256:{}", "ab".repeat(32)));
    }

    #[test]
    fn every_refusal_names_the_part_to_look_at() {
        let cases: &[(&str, &str)] = &[
            ("   ", "paste the pairing string"),
            // The likeliest wrong paste: printed directly above the pairing
            // string and looks like the thing you want.
            ("ABCD-EFGH-JKMN-PQRS-TVWX", "tw1_"),
            ("https://gaugedesk.example/boxes/1", "tw1_"),
            (&INVITE[..40], "damaged"),
            // A second spelling of the same bytes. `+` is not base64url.
            ("tw1_ab+cd", "damaged"),
        ];
        for (input, expected) in cases {
            let error = parse_invite(input).expect_err(&format!("must refuse {input:?}"));
            assert!(
                error.to_string().contains(expected),
                "refusing {input:?} said {error:?}, wanted {expected:?}",
            );
        }
    }

    #[test]
    fn no_refusal_echoes_the_token() {
        // It carries a live claim code, and a message quoting it lands in
        // whatever log the caller happens to write.
        for damaged in [&INVITE[..40], "ABCD-EFGH-JKMN-PQRS-TVWX"] {
            let error = parse_invite(damaged).expect_err("must refuse").to_string();
            assert!(
                !error.contains(damaged),
                "the message echoed the token: {error}"
            );
        }
    }

    #[test]
    fn a_missing_pin_says_so_rather_than_failing_to_connect_later() {
        // Without a pin there is no handshake to attempt, and "connection
        // failed" would send someone to look at their network.
        let body = serde_json::json!({"v": 1, "r": "wss://r", "c": "ABCD"}).to_string();
        let token = format!("tw1_{}", URL_SAFE_NO_PAD.encode(body));
        let error = parse_invite(&token).expect_err("must refuse").to_string();
        assert!(error.contains("fingerprint"), "said: {error}");
    }

    #[test]
    fn a_version_this_build_does_not_read_is_refused() {
        let body = serde_json::json!({
            "v": 9, "r": "wss://r", "c": "ABCD", "f": format!("sha256:{}", "ab".repeat(32)),
        })
        .to_string();
        let token = format!("tw1_{}", URL_SAFE_NO_PAD.encode(body));
        assert!(parse_invite(&token)
            .expect_err("must refuse")
            .to_string()
            .contains("version"));
    }

    #[test]
    fn the_home_key_is_stable_and_not_the_account_key() {
        // The box pins this at claim and refuses a later claim presenting a
        // different one, so anything random here would make re-pairing an
        // already-paired box impossible to explain.
        let key = [7u8; 32];
        assert_eq!(home_key_for(key), home_key_for(key));
        assert_ne!(home_key_for(key), home_key_for([8u8; 32]));
        assert_ne!(home_key_for(key), hex::encode(key));
    }

    #[test]
    fn a_pin_is_read_in_either_spelling_and_refused_otherwise() {
        let hex_pin = "ab".repeat(32);
        assert_eq!(
            pin_bytes(&format!("sha256:{hex_pin}")).expect("prefixed"),
            pin_bytes(&hex_pin).expect("bare"),
        );
        assert!(pin_bytes("sha256:short").is_err());
        assert!(pin_bytes("not-hex").is_err());
    }

    #[test]
    fn a_response_is_split_at_its_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(split_response(raw).expect("split"), (200, b"{}".to_vec()));
        assert!(split_response(b"no headers here").is_err());
    }
}
