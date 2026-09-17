//! The possession half of Project Host registration (ADR 0174).
//!
//! A verifier that has checked a claim's governance signature still knows only
//! that someone holding that key said something. This is the part that asks the
//! route named in the claim to say it again, live: one framed request and one
//! framed response over the same pinned TLS session the rest of the product
//! uses, against the fingerprint the claim carries as its transport pin.
//!
//! Both halves live here so the wire form has one definition. The responder is
//! the Home; the asker is the operated verifier in `gaugewright-cloud`, which
//! reaches it through this crate.
//!
//! The responder answers possession and nothing else. It reads no project and
//! admits no session, because a Home part-way through registration has not
//! agreed to anything else yet.

use std::sync::Arc;
use std::time::Duration;

use gaugedesk_core::ids::AuthorityId;
use gaugedesk_core::project_host_registration::{
    possession_signing_bytes, PossessionAnswer, PossessionChallenge, REGISTRATION_VERSION,
};
use gaugedesk_core::signature::{Signature, SigningKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::net_server::{CertFingerprint, PinnedTlsClientConfig};
use crate::net_tls::tls_connect;

/// A possession frame is a nonce and a restatement of one Home's identity. It
/// has no reason to be large, and a bound here is what stops a route that
/// answers with a gigabyte from being the verifier's problem.
pub const MAX_POSSESSION_FRAME: usize = 16 * 1024;

/// How long the whole exchange may take. A route that is reachable but silent
/// is unreachable for this purpose; waiting longer does not make it more
/// registrable.
pub const POSSESSION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum PossessionError {
    /// The claim's transport pin is not a fingerprint this can pin against.
    UnusablePin,
    /// The claim's route is not a host and port this can dial.
    UnusableRoute,
    /// Could not reach the route, could not complete the pinned handshake, or
    /// the exchange timed out. Retryable: none of it is evidence about the
    /// Home's identity.
    Unreachable(String),
    /// The route answered with something that is not a possession frame.
    Malformed(String),
}

impl std::fmt::Display for PossessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnusablePin => write!(f, "claim carries no usable transport pin"),
            Self::UnusableRoute => write!(f, "claim carries no dialable route"),
            Self::Unreachable(why) => write!(f, "route unreachable: {why}"),
            Self::Malformed(why) => write!(f, "route answered with {why}"),
        }
    }
}

/// What a Home needs to know about itself to answer. Supplied by the caller
/// rather than read here: this module does not decide who a Home is.
#[derive(Clone, Debug)]
pub struct HomeIdentity {
    pub home_id: String,
    pub tenant_id: String,
    pub route: String,
    /// The relay locator's epoch, or `None` for a Home reachable only at a
    /// direct endpoint. ADR 0174 has such a Home assert none rather than a
    /// synthesised zero, so its route is recorded as unversioned instead of
    /// being fenced by a number with no rotation behind it.
    pub route_epoch: Option<u64>,
    pub transport_pin: String,
}

/// Answer one possession challenge. The Home signs a restatement of its own
/// identity, not the bare nonce: an answer that only proved "I saw this nonce"
/// would be equally true from a route that had substituted itself.
pub fn answer_possession(
    signer: &SigningKey,
    identity: &HomeIdentity,
    challenge: &PossessionChallenge,
) -> PossessionAnswer {
    let mut answer = PossessionAnswer {
        version: REGISTRATION_VERSION,
        challenge_id: challenge.challenge_id.clone(),
        nonce: challenge.nonce.clone(),
        home_id: identity.home_id.clone(),
        governance_pubkey: signer.public_key().as_str().to_owned(),
        tenant_id: identity.tenant_id.clone(),
        route: identity.route.clone(),
        route_epoch: identity.route_epoch.unwrap_or(0),
        transport_pin: identity.transport_pin.clone(),
        signature: Signature::new(Vec::new()),
    };
    answer.signature = signer.sign(&possession_signing_bytes(&answer));
    answer
}

/// Serve one possession exchange on an already-accepted, already-TLS stream.
///
/// One request in, one response out, then done. The connection carries nothing
/// else and is not a session.
pub async fn serve_possession<S>(
    stream: &mut S,
    signer: &SigningKey,
    identity: &HomeIdentity,
) -> Result<(), PossessionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let challenge: PossessionChallenge = read_frame(stream).await?;
    let answer = answer_possession(signer, identity, &challenge);
    write_frame(stream, &answer).await
}

/// Dial the route a claim names, with its certificate pinned, and ask.
///
/// The pin comes from the claim, so this cannot be pointed at a host of
/// anyone's choosing: a route that presents a different certificate fails the
/// handshake before any frame is written.
pub async fn ask_possession(
    route: &str,
    transport_pin: &str,
    home_id: &str,
    challenge: &PossessionChallenge,
) -> Result<PossessionAnswer, PossessionError> {
    let fingerprint = hex::decode(transport_pin.trim().trim_start_matches("sha256:"))
        .map_err(|_| PossessionError::UnusablePin)?;
    if fingerprint.is_empty() {
        return Err(PossessionError::UnusablePin);
    }
    let address = dial_address(route).ok_or(PossessionError::UnusableRoute)?;

    let authority = AuthorityId::new(home_id.to_owned());
    let mut pins = PinnedTlsClientConfig::new();
    pins.pin(authority.clone(), CertFingerprint::new(fingerprint));

    let exchange = async {
        let tcp = TcpStream::connect(&address)
            .await
            .map_err(|error| PossessionError::Unreachable(error.to_string()))?;
        let mut tls = tls_connect(tcp, &authority, Arc::new(pins))
            .await
            .map_err(|error| PossessionError::Unreachable(error.to_string()))?;
        write_frame(&mut tls, challenge).await?;
        read_frame::<_, PossessionAnswer>(&mut tls).await
    };

    match tokio::time::timeout(POSSESSION_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_) => Err(PossessionError::Unreachable("exchange timed out".into())),
    }
}

/// `https://host:port` or `host:port` to something `TcpStream` can dial.
fn dial_address(route: &str) -> Option<String> {
    let rest = route
        .trim()
        .strip_prefix("https://")
        .unwrap_or_else(|| route.trim());
    let rest = rest.split('/').next()?;
    if rest.is_empty() {
        return None;
    }
    Some(if rest.contains(':') {
        rest.to_owned()
    } else {
        format!("{rest}:443")
    })
}

async fn write_frame<S, T>(stream: &mut S, value: &T) -> Result<(), PossessionError>
where
    S: tokio::io::AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PossessionError::Malformed(format!("unencodable frame: {error}")))?;
    let len = u32::try_from(bytes.len())
        .ok()
        .filter(|len| *len as usize <= MAX_POSSESSION_FRAME)
        .ok_or_else(|| PossessionError::Malformed("an oversized frame".into()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|error| PossessionError::Unreachable(error.to_string()))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| PossessionError::Unreachable(error.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|error| PossessionError::Unreachable(error.to_string()))
}

async fn read_frame<S, T>(stream: &mut S) -> Result<T, PossessionError>
where
    S: tokio::io::AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|error| PossessionError::Unreachable(error.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // Checked before allocating, so a declared length is not itself a way to
    // make the verifier reserve memory on a stranger's say-so.
    if len > MAX_POSSESSION_FRAME {
        return Err(PossessionError::Malformed("an oversized frame".into()));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|error| PossessionError::Unreachable(error.to_string()))?;
    serde_json::from_slice(&buf)
        .map_err(|error| PossessionError::Malformed(format!("an undecodable frame: {error}")))
}

#[cfg(test)]
#[path = "possession_exchange_tests.rs"]
mod tests;
