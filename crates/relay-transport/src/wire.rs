//! The portable half of the relay fabric: what a leg *says*, and what it will
//! *accept* — with no opinion about how bytes move (DESK-1, ADR 0130).
//!
//! Everything here is sans-io and target-independent: the handshake framing, the
//! route/proof/epoch rules, and the certificate pin. It holds no socket, spawns
//! no task, and touches no filesystem, so the same bytes and the same pin are
//! produced by a native carrier over TCP and by a browser carrier over a
//! `WebSocket`. That is the point: one implementation of the frame and the pin,
//! three carriers.
//!
//! The crypto provider is *injected* rather than selected here, so a carrier
//! supplies it. In practice every target supplies `ring` — including `wasm32`,
//! through ring's own `wasm32_unknown_unknown_js` feature — so the browser adds
//! no new crypto trust surface ([ADR 0130](../../../specs/decisions/0130-browser-thin-client-tunnels-the-relay-fabric-in-wasm.md)
//! §4). Nothing in this module names one.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

pub const TOKEN_LEN: usize = 32;
pub const WSS_PROTOCOL_VERSION: u16 = 1;
pub const WSS_MAX_FRAME_BYTES: usize = 64 * 1024;
pub const WSS_STREAM_BUFFER_BYTES: usize = 256 * 1024;
pub const WSS_HANDSHAKE_LEN: usize = 84;
pub(crate) const WSS_HANDSHAKE_MAGIC: [u8; 8] = *b"GWRWSS1\n";
pub(crate) const WSS_READY: [u8; 8] = *b"GWRREADY";
pub(crate) const WSS_DATA: u8 = 0;
pub(crate) const WSS_FIN: u8 = 1;
pub(crate) const WSS_FIN_ACK: u8 = 2;
/// The pinned session authenticates by certificate fingerprint, never by name,
/// so the SNI is a fixed placeholder rather than a resolvable host.
pub(crate) const PIN_SNI: &str = "gaugewright-home";

/// The four roles admitted by the one WSS relay fabric. A route family is
/// fixed by its first admitted leg, so durable Home/client traffic can never
/// pair with a one-shot enrollment or federation leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WebSocketRelayRole {
    Home = 1,
    Client = 2,
    Source = 3,
    Target = 4,
}

/// Which side of a bounded one-shot rendezvous is expected to park first.
/// This is transport ordering only; it grants no source/target authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OneShotLeg {
    Initializer,
    Joiner,
}

impl WebSocketRelayRole {
    pub fn is_initializer(self) -> bool {
        matches!(self, Self::Home | Self::Source)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteProof([u8; 32]);

impl RouteProof {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_base64url(value: &str) -> std::io::Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| invalid_data("relay route proof is not base64url"))?;
        Ok(Self(bytes.try_into().map_err(|_| {
            invalid_data("relay route proof must contain 32 bytes")
        })?))
    }

    pub fn to_base64url(self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Canonical WSS locator. `handle` selects one hibernatable object, while the
/// epoch and proof are checked inside that object before it will pair a leg.
/// Possession grants reachability only; carried TLS and Home admission remain
/// the work-authority gates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketRelayRoute {
    pub endpoint: String,
    pub handle: String,
    pub epoch: u64,
    pub proof: RouteProof,
    /// Only an initializer may advance exactly one epoch, proving continuity
    /// with the prior proof while installing the new proof.
    pub previous_proof: Option<RouteProof>,
}

impl WebSocketRelayRoute {
    pub fn validate(&self) -> std::io::Result<()> {
        let production = self
            .endpoint
            .strip_prefix("wss://")
            .is_some_and(valid_origin_authority);
        let loopback_test = self
            .endpoint
            .strip_prefix("ws://")
            .and_then(|authority| authority.parse::<SocketAddr>().ok())
            .is_some_and(|address| address.ip().is_loopback());
        if (!production && !loopback_test)
            || self.endpoint.ends_with('/')
            || self.endpoint.contains('#')
            || self.endpoint.contains('?')
        {
            return Err(invalid_data(
                "relay endpoint must be a canonical wss:// origin (or a loopback ws:// test origin)",
            ));
        }
        let handle = URL_SAFE_NO_PAD
            .decode(&self.handle)
            .map_err(|_| invalid_data("relay route handle is not base64url"))?;
        if handle.len() != 32 {
            return Err(invalid_data("relay route handle must contain 32 bytes"));
        }
        if self.epoch == 0 {
            return Err(invalid_data("relay route epoch must be positive"));
        }
        Ok(())
    }

    /// The edge object's URL. Carriers dial this; it is the only place the
    /// locator becomes an address.
    pub fn url(&self) -> std::io::Result<String> {
        self.validate()?;
        Ok(format!("{}/v1/relay/{}", self.endpoint, self.handle))
    }
}

fn valid_origin_authority(authority: &str) -> bool {
    !authority.is_empty()
        && !authority.contains('/')
        && !authority.contains('@')
        && !authority.chars().any(char::is_whitespace)
}

pub fn websocket_handshake(
    route: &WebSocketRelayRoute,
    role: WebSocketRelayRole,
) -> std::io::Result<[u8; WSS_HANDSHAKE_LEN]> {
    route.validate()?;
    if !role.is_initializer() && route.previous_proof.is_some() {
        return Err(invalid_data(
            "only an initializer may present a previous route proof",
        ));
    }
    let mut frame = [0u8; WSS_HANDSHAKE_LEN];
    frame[..8].copy_from_slice(&WSS_HANDSHAKE_MAGIC);
    frame[8..10].copy_from_slice(&WSS_PROTOCOL_VERSION.to_be_bytes());
    frame[10] = role as u8;
    frame[11] = u8::from(route.previous_proof.is_some());
    frame[12..20].copy_from_slice(&route.epoch.to_be_bytes());
    frame[20..52].copy_from_slice(route.proof.as_bytes());
    if let Some(previous) = route.previous_proof {
        frame[52..84].copy_from_slice(previous.as_bytes());
    }
    Ok(frame)
}

/// Derive the edge object's opaque handle and proof from a 32-byte rendezvous
/// capability. This preserves the established one-shot ticket wire while moving
/// its outer transport to WSS; neither derived value grants work authority.
pub fn one_shot_websocket_route(
    endpoint: &str,
    token: [u8; TOKEN_LEN],
) -> std::io::Result<WebSocketRelayRoute> {
    let mut proof_hasher = Sha256::new();
    proof_hasher.update(b"gaugewright-relay-proof-v1\0");
    proof_hasher.update(token);
    let proof: [u8; 32] = proof_hasher.finalize().into();
    let route = WebSocketRelayRoute {
        endpoint: endpoint.to_string(),
        handle: URL_SAFE_NO_PAD.encode(token),
        epoch: 1,
        proof: RouteProof::new(proof),
        previous_proof: None,
    };
    route.validate()?;
    Ok(route)
}

pub type CertFingerprint = [u8; 32];

pub fn fingerprint(cert: &CertificateDer<'_>) -> CertFingerprint {
    Sha256::digest(cert.as_ref()).into()
}

/// Authenticates the Home by **exact end-entity fingerprint**, never by PKI.
///
/// Intermediates, server name, OCSP, and the clock are all deliberately unused:
/// the route carries the pin, so there is no chain to build and no validity
/// window to check. That is what lets this verifier run unchanged in a browser,
/// where no root store or trustworthy clock is available.
#[derive(Debug)]
pub struct PinnedVerifier {
    expected: CertFingerprint,
    provider: Arc<CryptoProvider>,
}

impl PinnedVerifier {
    pub fn new(expected: CertFingerprint, provider: Arc<CryptoProvider>) -> Self {
        Self { expected, provider }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if fingerprint(end_entity) == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "Home certificate does not match the route pin".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The pinned client configuration for one Home, over an injected provider.
/// Carriers differ; this configuration does not.
pub fn pinned_client_config(
    expected: CertFingerprint,
    provider: Arc<CryptoProvider>,
) -> std::io::Result<ClientConfig> {
    // The pin ignores time entirely, so the time source only feeds rustls' own
    // bookkeeping. Native takes rustls' default; a browser has a clock, it just
    // is not `SystemTime`, so it supplies one explicitly (DESK-2).
    #[cfg(not(target_arch = "wasm32"))]
    let builder = ClientConfig::builder_with_provider(provider.clone());
    #[cfg(target_arch = "wasm32")]
    let builder =
        ClientConfig::builder_with_details(provider.clone(), Arc::new(BrowserTimeProvider));

    let mut config = builder
        .with_safe_default_protocol_versions()
        .map_err(|error| other(format!("relay TLS client: {error}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(expected, provider)))
        .with_no_client_auth();
    config.enable_early_data = false;
    Ok(config)
}

/// `wasm32-unknown-unknown` has no `SystemTime`, but a page has `Date.now()`.
#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub struct BrowserTimeProvider;

#[cfg(target_arch = "wasm32")]
impl rustls::time_provider::TimeProvider for BrowserTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(
            core::time::Duration::from_millis(js_sys::Date::now() as u64),
        ))
    }
}

/// Frame ciphertext as the relay's binary `DATA` record. Pure framing, so it is
/// shared by every carrier and exercised by native tests rather than only in a
/// browser.
pub fn data_frame(ciphertext: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ciphertext.len() + 1);
    frame.push(WSS_DATA);
    frame.extend_from_slice(ciphertext);
    frame
}

/// What a received relay frame means to the carrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayFrame {
    Ready,
    Data(Vec<u8>),
    Fin,
    FinAck,
}

/// Classify one binary frame from the relay, fail-closed on anything else.
pub fn classify_frame(bytes: &[u8]) -> std::io::Result<RelayFrame> {
    if bytes == WSS_READY {
        return Ok(RelayFrame::Ready);
    }
    if bytes.is_empty() || bytes.len() > WSS_MAX_FRAME_BYTES {
        return Err(invalid_data("relay frame out of bounds"));
    }
    match bytes[0] {
        WSS_DATA => Ok(RelayFrame::Data(bytes[1..].to_vec())),
        WSS_FIN => Ok(RelayFrame::Fin),
        WSS_FIN_ACK => Ok(RelayFrame::FinAck),
        _ => Err(invalid_data("relay frame has an unknown kind")),
    }
}

pub(crate) fn invalid_data(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

pub(crate) fn other(message: String) -> std::io::Error {
    std::io::Error::other(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> WebSocketRelayRoute {
        WebSocketRelayRoute {
            endpoint: "wss://relay.example".to_owned(),
            handle: URL_SAFE_NO_PAD.encode([7u8; 32]),
            epoch: 3,
            proof: RouteProof::new([9u8; 32]),
            previous_proof: None,
        }
    }

    #[test]
    fn handshake_is_the_fixed_84_byte_frame() {
        let frame = websocket_handshake(&route(), WebSocketRelayRole::Client).expect("handshake");
        assert_eq!(frame.len(), WSS_HANDSHAKE_LEN);
        assert_eq!(&frame[..8], &WSS_HANDSHAKE_MAGIC);
        assert_eq!(&frame[8..10], &WSS_PROTOCOL_VERSION.to_be_bytes());
        assert_eq!(frame[10], WebSocketRelayRole::Client as u8);
        assert_eq!(frame[11], 0);
        assert_eq!(&frame[12..20], &3u64.to_be_bytes());
        assert_eq!(&frame[20..52], &[9u8; 32]);
    }

    #[test]
    fn only_an_initializer_may_present_a_previous_proof() {
        let mut rotating = route();
        rotating.previous_proof = Some(RouteProof::new([1u8; 32]));
        assert!(websocket_handshake(&rotating, WebSocketRelayRole::Client).is_err());
        assert!(websocket_handshake(&rotating, WebSocketRelayRole::Target).is_err());
        let frame =
            websocket_handshake(&rotating, WebSocketRelayRole::Home).expect("initializer rotates");
        assert_eq!(frame[11], 1);
        assert_eq!(&frame[52..84], &[1u8; 32]);
    }

    #[test]
    fn home_and_source_are_the_initializers() {
        assert!(WebSocketRelayRole::Home.is_initializer());
        assert!(WebSocketRelayRole::Source.is_initializer());
        assert!(!WebSocketRelayRole::Client.is_initializer());
        assert!(!WebSocketRelayRole::Target.is_initializer());
    }

    #[test]
    fn a_zero_epoch_or_short_handle_is_refused() {
        let mut zero = route();
        zero.epoch = 0;
        assert!(zero.validate().is_err());
        let mut short = route();
        short.handle = URL_SAFE_NO_PAD.encode([1u8; 16]);
        assert!(short.validate().is_err());
    }

    #[test]
    fn only_canonical_origins_validate() {
        for endpoint in [
            "https://relay.example",
            "wss://relay.example/",
            "wss://relay.example?x=1",
            "wss://relay.example#x",
            "ws://93.184.216.34:443",
        ] {
            let mut bad = route();
            bad.endpoint = endpoint.to_owned();
            assert!(bad.validate().is_err(), "{endpoint} must not validate");
        }
        let mut loopback = route();
        loopback.endpoint = "ws://127.0.0.1:9443".to_owned();
        assert!(loopback.validate().is_ok());
    }

    #[test]
    fn the_url_is_the_edge_object_path() {
        assert_eq!(
            route().url().expect("url"),
            format!("wss://relay.example/v1/relay/{}", route().handle),
        );
    }

    #[test]
    fn proof_round_trips_through_base64url() {
        let proof = RouteProof::new([5u8; 32]);
        assert_eq!(
            RouteProof::from_base64url(&proof.to_base64url()).expect("round trip"),
            proof,
        );
        assert!(RouteProof::from_base64url("not base64!").is_err());
        assert!(RouteProof::from_base64url(&URL_SAFE_NO_PAD.encode([1u8; 16])).is_err());
    }

    #[test]
    fn one_shot_route_derives_a_stable_proof_from_its_token() {
        let first =
            one_shot_websocket_route("wss://relay.example", [3u8; TOKEN_LEN]).expect("route");
        let again =
            one_shot_websocket_route("wss://relay.example", [3u8; TOKEN_LEN]).expect("route");
        assert_eq!(first, again);
        assert_eq!(first.epoch, 1);
        assert_eq!(first.handle, URL_SAFE_NO_PAD.encode([3u8; TOKEN_LEN]));
        let other =
            one_shot_websocket_route("wss://relay.example", [4u8; TOKEN_LEN]).expect("route");
        assert_ne!(first.proof, other.proof);
    }

    #[test]
    fn frames_classify_fail_closed() {
        assert_eq!(classify_frame(&WSS_READY).unwrap(), RelayFrame::Ready);
        assert_eq!(classify_frame(&[WSS_FIN]).unwrap(), RelayFrame::Fin);
        assert_eq!(classify_frame(&[WSS_FIN_ACK]).unwrap(), RelayFrame::FinAck);
        assert_eq!(
            classify_frame(&[WSS_DATA, 1, 2, 3]).unwrap(),
            RelayFrame::Data(vec![1, 2, 3])
        );
        assert!(classify_frame(&[]).is_err());
        assert!(classify_frame(&[9, 1]).is_err());
        assert!(classify_frame(&vec![WSS_DATA; WSS_MAX_FRAME_BYTES + 1]).is_err());
    }

    #[test]
    fn a_data_frame_carries_its_kind_byte() {
        assert_eq!(data_frame(&[7, 8]), vec![WSS_DATA, 7, 8]);
    }
}
