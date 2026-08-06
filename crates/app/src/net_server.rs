//! Non-loopback network server seam (`SERVE-1`): the bind + governance-key auth
//! middleware the cross-machine [`FederationRelay`](crate::federation_relay)
//! attaches behind (ADR 0020).
//!
//! Two thin pieces, both **scaffold for the real network path**:
//!
//! 1. [`bind_net_server`] — binds a `TcpListener` to a **non-loopback** address
//!    (default `0.0.0.0:<ephemeral>`). The co-resident control plane in
//!    [`crate::open_runtime::open_serve`] binds loopback-only on purpose (single-user, no network);
//!    a federation relay must instead accept connections from another authority's
//!    machine, so it binds a routable interface. Here that is still the local box
//!    (no NAT, no rendezvous) — the real cross-machine relay
//!    (`RENDEZVOUS-STUB-1`) attaches the same listener behind this seam.
//!
//! 2. [`GovernanceAuth`] — governance-key authentication middleware. Every
//!    cross-authority call presents an [`AuthAttempt`]: the scope it targets and a
//!    signature over a canonical challenge. The server resolves the scope's owning
//!    authority via [`determine_scope_authority`] (the `SCOPE-AUTH-1` seam) and
//!    verifies the signature against that authority's **registered** governance key
//!    with the pure [`verify_signature`] predicate — **real P-256 ECDSA**,
//!    fail-closed (`gaugedesk_core::signature`; the old `SIGN-1` length-only stub was
//!    replaced by P256-STUB-1). An unregistered authority or a bad signature is
//!    rejected; a forged signature cannot authenticate (CONF-4, verified stale).
//!
//! The auth boundary parses the untrusted request into typed identities at the
//! shell and hands the core only validated values (`principles.md` "Contracts at
//! the boundary").

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use gaugedesk_core::determine_scope_authority;
use gaugedesk_core::ids::{AuthorityId, EngagementId, PublicKey};
use gaugedesk_core::signature::{verify_signature, Signature, SigningKey};

use crate::session::SessionStore;

/// The default non-loopback bind address: every interface, ephemeral port. A
/// federation relay must be reachable from another authority's machine, so —
/// unlike the loopback-only control plane — it binds a routable interface.
pub const DEFAULT_NET_BIND: &str = "0.0.0.0:0";

/// Bind a `TcpListener` for the federation relay on a **non-loopback** address,
/// returning the bound socket address (the ephemeral port resolved).
///
/// Rejects a loopback address: this is the seam for cross-authority reachability,
/// and the loopback-only control plane already covers the single-user path. Real
/// cross-machine transport (NAT traversal, rendezvous) attaches the returned
/// listener behind [`crate::federation_relay::FederationRelay`] (`RENDEZVOUS-STUB-1`).
pub async fn bind_net_server(addr: &str) -> std::io::Result<(tokio::net::TcpListener, SocketAddr)> {
    let parsed: SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    if parsed.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "federation relay must bind a non-loopback address (loopback is the control plane's)",
        ));
    }
    let listener = tokio::net::TcpListener::bind(parsed).await?;
    let local = listener.local_addr()?;
    Ok((listener, local))
}

/// One authenticated cross-authority request as parsed at the shell: the scope it
/// targets plus a governance-key signature over the server's challenge.
#[derive(Clone, Debug)]
pub struct AuthAttempt {
    /// The scope the caller wants to act on. Its owning authority (resolved by
    /// [`determine_scope_authority`]) is the one whose governance key must sign.
    pub scope: String,
    /// The signature over the canonical challenge bytes.
    pub signature: Signature,
}

/// A fresh, single-use challenge the server issues at the start of a
/// challenge/response handshake (`CHALLENGE-AUTH-1`). The caller signs exactly
/// these bytes with its governance key; the server then verifies the response
/// against the challenge it issued and **consumes** it, so a captured response
/// can never be replayed (the challenge is gone after one use).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Challenge(Vec<u8>);

impl Challenge {
    /// The canonical bytes the caller must sign.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Why a governance-key authentication attempt was refused (distinct from a
/// transport error): no key registered for the resolved authority, the
/// signature did not verify, or the challenge was unknown/already spent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthRejection {
    /// No governance key is registered for the scope's owning authority.
    UnknownAuthority(AuthorityId),
    /// The signature did not verify under the authority's governance key.
    BadSignature(AuthorityId),
    /// The response named a challenge the server never issued, or one already
    /// consumed by an earlier response — the anti-replay guard of the handshake.
    StaleChallenge,
}

impl std::fmt::Display for AuthRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthRejection::UnknownAuthority(a) => write!(f, "unknown authority: {a}"),
            AuthRejection::BadSignature(a) => write!(f, "bad signature for authority: {a}"),
            AuthRejection::StaleChallenge => {
                write!(f, "unknown or already-consumed challenge")
            }
        }
    }
}

/// The governance-key auth middleware (`SERVE-1`): a registry of each authority's
/// governance public key, plus a server challenge the caller signs.
///
/// `authenticate` resolves the target scope to its owning authority, looks up that
/// authority's registered governance key, and verifies the presented signature over
/// the challenge with the pure [`verify_signature`] predicate — **real P-256
/// ECDSA**, fail-closed. The wiring (scope → authority → key → verify) and the
/// crypto are both real; only key *storage* (a `KeyStore` trait) defers per
/// deployment.
#[derive(Clone, Debug, Default)]
pub struct GovernanceAuth {
    keys: BTreeMap<AuthorityId, PublicKey>,
    challenge: Vec<u8>,
    /// Challenges issued by [`issue_challenge`] and not yet spent. A response is
    /// only accepted against a challenge still in this set, and accepting one
    /// removes it — the single-use, anti-replay core of the handshake.
    outstanding: BTreeSet<Challenge>,
    /// Monotonic counter folded into each issued challenge so successive
    /// handshakes never collide on the same nonce. (Real deployments seed the
    /// nonce from a CSPRNG; the loopback stub uses a deterministic counter.)
    issued: u64,
}

impl GovernanceAuth {
    /// A fresh auth context over `challenge` — the canonical bytes a caller must
    /// sign to prove control of an authority's governance key. (Real deployments
    /// issue a fresh per-session nonce here; the loopback stub uses a fixed one.)
    pub fn new(challenge: impl Into<Vec<u8>>) -> Self {
        Self {
            keys: BTreeMap::new(),
            challenge: challenge.into(),
            outstanding: BTreeSet::new(),
            issued: 0,
        }
    }

    /// Register an authority's governance public key. The shell calls this from
    /// the authority's published keyset before accepting its calls.
    pub fn register(&mut self, authority: AuthorityId, governance_key: PublicKey) {
        self.keys.insert(authority, governance_key);
    }

    /// The challenge bytes a caller must sign.
    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }

    /// Authenticate a cross-authority request: resolve the scope's owning
    /// authority, look up its governance key, and verify the signature over the
    /// challenge. On success returns the authenticated [`AuthorityId`] — the value
    /// the relay then trusts for permission checks (`MINT-1` mints under it).
    pub fn authenticate(&self, attempt: &AuthAttempt) -> Result<AuthorityId, AuthRejection> {
        let authority = determine_scope_authority(&attempt.scope);
        let key = self
            .keys
            .get(&authority)
            .ok_or_else(|| AuthRejection::UnknownAuthority(authority.clone()))?;
        match verify_signature(&self.challenge, &attempt.signature, key) {
            Ok(true) => Ok(authority),
            _ => Err(AuthRejection::BadSignature(authority)),
        }
    }

    /// Begin a challenge/response handshake (`CHALLENGE-AUTH-1`): mint a fresh,
    /// single-use [`Challenge`], record it as outstanding, and hand it to the
    /// caller to sign. Each call yields distinct bytes (a monotonic counter is
    /// folded in) so a signature captured from one handshake cannot satisfy the
    /// next.
    pub fn issue_challenge(&mut self) -> Challenge {
        self.issued += 1;
        // The challenge nonce is unguessable (16 CSPRNG bytes) so a captured
        // response cannot be precomputed against a predictable future challenge; the
        // monotonic counter is folded in only as a collision backstop (D-REMOTE
        // hardens the deterministic-counter loopback scaffold this method noted).
        let mut bytes = self.challenge.clone();
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.issued.to_be_bytes().as_slice());
        bytes.extend_from_slice(&crate::session::random_bytes::<16>());
        let challenge = Challenge(bytes);
        self.outstanding.insert(challenge.clone());
        challenge
    }

    /// Complete a challenge/response handshake: verify `signature` (over `scope`'s
    /// owning authority's governance key) against the bytes of an outstanding
    /// `challenge`, then **consume** that challenge so the same response can never
    /// be replayed.
    ///
    /// Order matters for the verdict: a challenge the server never issued (or one
    /// already spent) is [`AuthRejection::StaleChallenge`] regardless of the
    /// signature, and it is never consumed by a failed attempt — only a fully
    /// successful response retires the challenge.
    pub fn respond(
        &mut self,
        scope: &str,
        challenge: &Challenge,
        signature: &Signature,
    ) -> Result<AuthorityId, AuthRejection> {
        if !self.outstanding.contains(challenge) {
            return Err(AuthRejection::StaleChallenge);
        }
        let authority = determine_scope_authority(scope);
        let key = self
            .keys
            .get(&authority)
            .ok_or_else(|| AuthRejection::UnknownAuthority(authority.clone()))?;
        match verify_signature(challenge.as_bytes(), signature, key) {
            Ok(true) => {
                self.outstanding.remove(challenge);
                Ok(authority)
            }
            _ => Err(AuthRejection::BadSignature(authority)),
        }
    }
}

/// The pinned fingerprint of a federation relay's server certificate
/// (`CERT-PIN-1`): the bytes a client compares a presented certificate against
/// before trusting the connection. In the loopback stub this is an opaque digest
/// (e.g. a SHA-256 of the cert's DER); the real TLS path (`RENDEZVOUS-STUB-1` /
/// `D-CRYPTO`) fills it from `rustls`' leaf certificate with no change to the
/// pin/verify wiring here.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CertFingerprint(Vec<u8>);

impl CertFingerprint {
    /// Construct from an already-computed digest (parsed/hashed at the shell).
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
    /// The raw fingerprint bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Why a pinned-TLS connection was refused before any application traffic: the
/// dialed authority has no pin on file, or the certificate it presented did not
/// match the pin (a possible interception — fail closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinRejection {
    /// No certificate is pinned for the authority being dialed — the client has
    /// nothing to trust, so it refuses rather than trust-on-use silently.
    NoPin(AuthorityId),
    /// The presented certificate's fingerprint did not match the pin for this
    /// authority — the connection is refused (possible man-in-the-middle).
    PinMismatch(AuthorityId),
}

impl std::fmt::Display for PinRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinRejection::NoPin(a) => write!(f, "no pinned certificate for authority: {a}"),
            PinRejection::PinMismatch(a) => {
                write!(
                    f,
                    "presented certificate does not match pin for authority: {a}"
                )
            }
        }
    }
}

/// Cert-pinned TLS client config (`CERT-PIN-1`): the client-side counterpart to
/// [`bind_net_server`]'s server bind. A federation client dialing another
/// authority's relay must not accept any CA-chained certificate — there is no
/// shared web PKI across authorities — so it instead **pins** each authority's
/// expected server-certificate fingerprint and refuses a connection whose
/// certificate does not match (fail-closed, like the bridge-grant pins the
/// source's public key in [`crate::federation_relay`]).
///
/// The fingerprint compare is the stub for loopback; real certificate-chain
/// validation over `rustls` attaches behind [`verify_peer`] in
/// `RENDEZVOUS-STUB-1` / `D-CRYPTO` with no change to the pin registry or the
/// fail-closed contract.
#[derive(Clone, Debug, Default)]
pub struct PinnedTlsClientConfig {
    pins: BTreeMap<AuthorityId, CertFingerprint>,
}

impl PinnedTlsClientConfig {
    /// An empty client config — no authority is trusted until its certificate is
    /// pinned. (Dialing an unpinned authority is [`PinRejection::NoPin`].)
    pub fn new() -> Self {
        Self {
            pins: BTreeMap::new(),
        }
    }

    /// Pin the certificate fingerprint a client expects from `authority`'s relay.
    /// The shell sets this from the authority's published keyset / pairing ticket
    /// (trust-on-first-use), exactly where [`GovernanceAuth::register`] sets the
    /// server-side governance key.
    pub fn pin(&mut self, authority: AuthorityId, fingerprint: CertFingerprint) {
        self.pins.insert(authority, fingerprint);
    }

    /// Drop the pin for `authority` (`ITGOV-2` bridge revoke): a later handshake from it
    /// is then [`PinRejection::NoPin`], fail-closed. Idempotent — a no-op if not pinned.
    pub fn unpin(&mut self, authority: &AuthorityId) {
        self.pins.remove(authority);
    }

    /// Verify the certificate a relay presented when dialing `authority`: accept
    /// only if a fingerprint is pinned for that authority **and** the presented
    /// one matches it. Any other outcome refuses the connection (fail-closed) —
    /// the client never trusts a certificate it did not pin.
    pub fn verify_peer(
        &self,
        authority: &AuthorityId,
        presented: &CertFingerprint,
    ) -> Result<(), PinRejection> {
        match self.pins.get(authority) {
            None => Err(PinRejection::NoPin(authority.clone())),
            Some(pinned) if pinned == presented => Ok(()),
            Some(_) => Err(PinRejection::PinMismatch(authority.clone())),
        }
    }
}

// --- SERVE-1 over the wire: the challenge/response handshake served on a real
// TCP connection. The middleware above (`GovernanceAuth` + `SessionStore`) is the
// logic; the functions below carry it across a socket so a client on another
// machine can authenticate. The wire form is a small length-prefixed frame; the
// server never trusts anything it reads beyond what the pure verify admits.

/// The wire protocol the served handshake speaks (`SERVE-1`). Three frames cross
/// one connection: the client's [`ClientHello`] (the scope it wants), the
/// server's [`ServerChallenge`] (fresh bytes to sign), and the client's
/// [`ClientResponse`] (its governance signature). The server replies with an
/// [`AuthResult`]: a session token on success, a typed refusal otherwise.
///
/// The frames carry only handles/credentials, never payload — this is the
/// authentication boundary, parsed into typed values before the core sees them.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClientHello {
    /// The scope the client wants to act on; its owning authority must sign.
    pub scope: String,
}

/// The server's fresh, single-use challenge bytes for the client to sign.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ServerChallenge {
    /// The canonical bytes the client signs with its governance key.
    pub challenge: Vec<u8>,
}

/// The client's signature over the issued challenge.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClientResponse {
    /// The governance-key signature over the [`ServerChallenge`] bytes.
    pub signature: Signature,
}

/// The server's verdict at the end of the handshake: a session token bound to
/// the authenticated `(engagement, authority)`, or a typed refusal.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum AuthResult {
    /// Authentication succeeded: the bearer token for subsequent calls, plus the
    /// authority the client authenticated as.
    Session {
        /// The opaque bearer token bytes (echoed back on later requests).
        token: Vec<u8>,
        /// The authenticated authority (the value the relay trusts).
        authority: String,
    },
    /// Authentication was refused — bad/absent signature, unknown authority, or a
    /// stale challenge. The string is the human-readable reason (the typed
    /// [`AuthRejection`] does not cross the wire; the verdict does).
    Refused(String),
}

/// A transport or protocol error from the served handshake (distinct from an
/// [`AuthResult::Refused`], which is a verdict the server deliberately returned).
#[derive(Debug)]
pub enum ServeError {
    /// A socket-level failure (accept, read, write, connect).
    Io(std::io::Error),
    /// A frame that could not be decoded.
    Protocol(String),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeError::Io(e) => write!(f, "serve io: {e}"),
            ServeError::Protocol(s) => write!(f, "serve protocol: {s}"),
        }
    }
}

impl std::error::Error for ServeError {}

impl From<std::io::Error> for ServeError {
    fn from(e: std::io::Error) -> Self {
        ServeError::Io(e)
    }
}

/// Frame `bytes` as a 4-byte big-endian length prefix followed by the bytes.
async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

/// Read one length-prefixed frame.
async fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn send_json<T: serde::Serialize>(
    stream: &mut TcpStream,
    value: &T,
) -> Result<(), ServeError> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| ServeError::Protocol(format!("encode: {e}")))?;
    write_frame(stream, &bytes).await?;
    Ok(())
}

async fn recv_json<T: serde::de::DeserializeOwned>(
    stream: &mut TcpStream,
) -> Result<T, ServeError> {
    let bytes = read_frame(stream).await?;
    serde_json::from_slice(&bytes).map_err(|e| ServeError::Protocol(format!("decode: {e}")))
}

/// **Server half** of the served handshake (`SERVE-1`): handle one accepted
/// connection end to end. Reads the client's [`ClientHello`], issues a fresh
/// challenge from `auth`, reads the client's signed [`ClientResponse`], verifies
/// it with [`GovernanceAuth::respond`], and — on success — opens a session in
/// `sessions` for `(engagement, authenticated authority)` and returns the token.
///
/// An unauthenticated or bad-signature client is refused: the server replies
/// [`AuthResult::Refused`] and no session is minted. The challenge is consumed
/// only by a successful response (the anti-replay guard lives in `GovernanceAuth`).
///
/// `auth` and `sessions` are borrowed mutably because the handshake mutates the
/// outstanding-challenge set and the session table; a real server holds them
/// behind a lock and serves many connections, exactly as the loopback control
/// plane serializes admission.
pub async fn serve_auth_connection(
    stream: &mut TcpStream,
    auth: &mut GovernanceAuth,
    sessions: &mut SessionStore,
    engagement: &EngagementId,
) -> Result<AuthResult, ServeError> {
    let hello: ClientHello = recv_json(stream).await?;

    // Issue a fresh, single-use challenge and send it for the client to sign.
    let challenge = auth.issue_challenge();
    send_json(
        stream,
        &ServerChallenge {
            challenge: challenge.as_bytes().to_vec(),
        },
    )
    .await?;

    let response: ClientResponse = recv_json(stream).await?;

    // Verify the signature over the issued challenge against the scope's owning
    // authority's governance key. Only a fully successful response mints a token.
    let result = match auth.respond(&hello.scope, &challenge, &response.signature) {
        Ok(authority) => {
            let token = sessions.open(engagement.clone(), authority.clone());
            AuthResult::Session {
                token: token.as_bytes().to_vec(),
                authority: authority.to_string(),
            }
        }
        Err(rejection) => AuthResult::Refused(rejection.to_string()),
    };
    send_json(stream, &result).await?;
    Ok(result)
}

/// **Client half** of the served handshake (`SERVE-1`): dial `addr`, present
/// `scope`, sign the server's challenge with `signing_key`, and return the
/// server's [`AuthResult`] (a session token on success, a typed refusal
/// otherwise). The client signs with its own [`KeyStore`](crate::key_store)
/// key — the server verifies against the registered public key, so a client
/// without the matching key cannot authenticate.
pub async fn dial_and_authenticate(
    addr: SocketAddr,
    scope: &str,
    signing_key: &SigningKey,
) -> Result<AuthResult, ServeError> {
    let mut stream = TcpStream::connect(addr).await?;
    send_json(
        &mut stream,
        &ClientHello {
            scope: scope.to_string(),
        },
    )
    .await?;

    let challenge: ServerChallenge = recv_json(&mut stream).await?;
    let signature = signing_key.sign(&challenge.challenge);
    send_json(&mut stream, &ClientResponse { signature }).await?;

    recv_json(&mut stream).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_store::{KeyStore, LoopbackKeyStore};

    /// A well-formed P-256-sized but bogus signature — used only where the call is
    /// refused *before* verification (unknown authority, stale challenge), so the
    /// bytes are never checked.
    fn good_sig() -> Signature {
        Signature::new(vec![0u8; 64])
    }

    /// The real governance signing key for an authority (loopback store).
    fn key_for(authority: &str) -> gaugedesk_core::signature::SigningKey {
        LoopbackKeyStore.signing_key(&AuthorityId::new(authority))
    }

    #[tokio::test]
    async fn bind_listens_on_a_non_loopback_address() {
        let (_listener, addr) = bind_net_server(DEFAULT_NET_BIND).await.unwrap();
        // The kernel resolved an ephemeral port, and the bound interface is the
        // routable (non-loopback) one the relay needs — not 127.0.0.1.
        assert_ne!(addr.port(), 0, "an ephemeral port was assigned");
        assert!(!addr.ip().is_loopback(), "bound a non-loopback interface");
    }

    #[tokio::test]
    async fn bind_refuses_a_loopback_address() {
        // Loopback is the co-resident control plane's; the relay seam must reach
        // another machine, so binding 127.0.0.1 here is a configuration error.
        let err = bind_net_server("127.0.0.1:0").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn authenticates_a_signed_call_under_the_scopes_authority() {
        let key = key_for("acme");
        let mut auth = GovernanceAuth::new(b"gaugewright-federation-challenge".to_vec());
        auth.register(AuthorityId::new("acme"), key.public_key());
        // The scope resolves to `acme`, whose registered key verifies a real
        // signature over the challenge.
        let attempt = AuthAttempt {
            scope: "scope:acme:run-1".into(),
            signature: key.sign(auth.challenge()),
        };
        assert_eq!(auth.authenticate(&attempt), Ok(AuthorityId::new("acme")));
    }

    #[test]
    fn rejects_a_call_for_an_unregistered_authority() {
        // The challenge is signed fine, but no governance key is on file for the
        // scope's owning authority — the call is refused before any verify.
        let auth = GovernanceAuth::new(b"c".to_vec());
        let attempt = AuthAttempt {
            scope: "scope:stranger:x".into(),
            signature: good_sig(),
        };
        assert_eq!(
            auth.authenticate(&attempt),
            Err(AuthRejection::UnknownAuthority(AuthorityId::new(
                "stranger"
            ))),
        );
    }

    #[test]
    fn rejects_a_malformed_signature_for_a_known_authority() {
        let mut auth = GovernanceAuth::new(b"c".to_vec());
        auth.register(AuthorityId::new("acme"), PublicKey::new("04acme"));
        // A wrong-length signature fails the (stub) verify even though the
        // authority is known — a bad credential, not an unknown party.
        let attempt = AuthAttempt {
            scope: "scope:acme:x".into(),
            signature: Signature::new(vec![0u8; 32]),
        };
        assert_eq!(
            auth.authenticate(&attempt),
            Err(AuthRejection::BadSignature(AuthorityId::new("acme"))),
        );
    }

    #[test]
    fn rejects_when_the_challenge_is_empty() {
        // The stub verify rejects an empty message, so an empty challenge can
        // never authenticate — the server must issue a real challenge first.
        let mut auth = GovernanceAuth::new(Vec::new());
        auth.register(AuthorityId::new("acme"), PublicKey::new("04acme"));
        let attempt = AuthAttempt {
            scope: "scope:acme:x".into(),
            signature: good_sig(),
        };
        assert_eq!(
            auth.authenticate(&attempt),
            Err(AuthRejection::BadSignature(AuthorityId::new("acme"))),
        );
    }

    // --- CHALLENGE-AUTH-1: challenge/response handshake ---

    #[test]
    fn issues_a_distinct_challenge_each_round() {
        // Successive handshakes get distinct challenge bytes (a monotonic
        // counter is folded in), so a response to one never matches the next.
        let mut auth = GovernanceAuth::new(b"gaugewright-federation".to_vec());
        let first = auth.issue_challenge();
        let second = auth.issue_challenge();
        assert_ne!(first, second, "each issued challenge is distinct");
    }

    #[test]
    fn responds_to_an_outstanding_challenge() {
        let key = key_for("acme");
        let mut auth = GovernanceAuth::new(b"gaugewright-federation".to_vec());
        auth.register(AuthorityId::new("acme"), key.public_key());
        let challenge = auth.issue_challenge();
        // A real governance signature over the issued challenge, for a scope owned
        // by the registered authority, authenticates.
        let sig = key.sign(challenge.as_bytes());
        assert_eq!(
            auth.respond("scope:acme:run-1", &challenge, &sig),
            Ok(AuthorityId::new("acme")),
        );
    }

    #[test]
    fn rejects_a_replayed_response_over_a_consumed_challenge() {
        let key = key_for("acme");
        let mut auth = GovernanceAuth::new(b"c".to_vec());
        auth.register(AuthorityId::new("acme"), key.public_key());
        let challenge = auth.issue_challenge();
        let sig = key.sign(challenge.as_bytes());
        // First response succeeds and consumes the challenge.
        assert_eq!(
            auth.respond("scope:acme:x", &challenge, &sig),
            Ok(AuthorityId::new("acme")),
        );
        // Replaying the same (challenge, signature) is rejected: the challenge is
        // spent — the anti-replay guard of the handshake.
        assert_eq!(
            auth.respond("scope:acme:x", &challenge, &sig),
            Err(AuthRejection::StaleChallenge),
        );
    }

    #[test]
    fn rejects_a_response_to_a_never_issued_challenge() {
        let mut auth = GovernanceAuth::new(b"c".to_vec());
        auth.register(AuthorityId::new("acme"), PublicKey::new("04acme"));
        // The server never minted this challenge, so even a well-formed signature
        // cannot authenticate — the verdict is stale-challenge, not bad-signature.
        let forged = auth.issue_challenge();
        let mut auth2 = GovernanceAuth::new(b"c".to_vec());
        auth2.register(AuthorityId::new("acme"), PublicKey::new("04acme"));
        assert_eq!(
            auth2.respond("scope:acme:x", &forged, &good_sig()),
            Err(AuthRejection::StaleChallenge),
        );
    }

    #[test]
    fn a_failed_response_leaves_the_challenge_spendable() {
        let key = key_for("acme");
        let mut auth = GovernanceAuth::new(b"c".to_vec());
        auth.register(AuthorityId::new("acme"), key.public_key());
        let challenge = auth.issue_challenge();
        // A malformed signature fails verification but must NOT consume the
        // challenge — the caller can retry the handshake with a good signature.
        assert_eq!(
            auth.respond("scope:acme:x", &challenge, &Signature::new(vec![0u8; 32])),
            Err(AuthRejection::BadSignature(AuthorityId::new("acme"))),
        );
        assert_eq!(
            auth.respond("scope:acme:x", &challenge, &key.sign(challenge.as_bytes())),
            Ok(AuthorityId::new("acme")),
        );
    }

    // --- CERT-PIN-1: cert-pinned TLS client config ---

    #[test]
    fn accepts_a_relay_whose_certificate_matches_the_pin() {
        let mut client = PinnedTlsClientConfig::new();
        client.pin(
            AuthorityId::new("acme"),
            CertFingerprint::new(vec![0xab; 32]),
        );
        // The relay presents the exact certificate the client pinned for `acme`.
        assert_eq!(
            client.verify_peer(
                &AuthorityId::new("acme"),
                &CertFingerprint::new(vec![0xab; 32])
            ),
            Ok(()),
        );
    }

    #[test]
    fn refuses_a_relay_whose_certificate_does_not_match_the_pin() {
        let mut client = PinnedTlsClientConfig::new();
        client.pin(
            AuthorityId::new("acme"),
            CertFingerprint::new(vec![0xab; 32]),
        );
        // A different certificate for a pinned authority is a possible
        // interception — the client fails closed rather than trust it.
        assert_eq!(
            client.verify_peer(
                &AuthorityId::new("acme"),
                &CertFingerprint::new(vec![0xcd; 32])
            ),
            Err(PinRejection::PinMismatch(AuthorityId::new("acme"))),
        );
    }

    #[test]
    fn refuses_to_dial_an_authority_with_no_pin() {
        // With no certificate pinned, there is nothing to trust — the client
        // refuses rather than accept any CA-chained cert (no cross-authority PKI).
        let client = PinnedTlsClientConfig::new();
        assert_eq!(
            client.verify_peer(
                &AuthorityId::new("stranger"),
                &CertFingerprint::new(vec![0u8; 32])
            ),
            Err(PinRejection::NoPin(AuthorityId::new("stranger"))),
        );
    }

    // --- SERVE-1 over the wire: the served challenge/response handshake over a
    // real ephemeral TCP port (the net_relay tests prove loopback sockets work in
    // this env). A client dials, signs the server's challenge with its KeyStore
    // key, and the server verifies + issues a session token — or refuses.

    use crate::session::{SessionStore, SessionToken};
    use gaugedesk_core::ids::EngagementId;

    /// Run one served handshake end to end over a fresh ephemeral TCP port:
    /// build a `GovernanceAuth` + `SessionStore`, accept the client's connection,
    /// and drive the server half concurrently with the client half. Returns the
    /// server's verdict, the client's verdict, and the server's session store so a
    /// test can assert the minted token actually authorizes.
    async fn run_served_handshake(
        auth: GovernanceAuth,
        scope: &str,
        client_key: SigningKey,
    ) -> (AuthResult, AuthResult, SessionStore, EngagementId) {
        let mut auth = auth;
        let mut sessions = SessionStore::new();
        let engagement = EngagementId::new("eng-serve-1");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server half: accept one connection and run the handshake against the
        // mutable auth + session state.
        let server = async {
            let (mut conn, _peer) = listener.accept().await.unwrap();
            serve_auth_connection(&mut conn, &mut auth, &mut sessions, &engagement)
                .await
                .unwrap()
        };
        // Client half: dial out and authenticate with its own signing key.
        let client = dial_and_authenticate(addr, scope, &client_key);

        let (server_verdict, client_verdict) = tokio::join!(server, client);
        (
            server_verdict,
            client_verdict.unwrap(),
            sessions,
            engagement,
        )
    }

    #[tokio::test]
    async fn a_client_with_the_right_key_authenticates_over_tcp_and_gets_a_session() {
        // The server registers acme's real governance public key; the client holds
        // the matching signing key from the same loopback KeyStore.
        let acme = AuthorityId::new("acme");
        let client_key = LoopbackKeyStore.signing_key(&acme);
        let mut auth = GovernanceAuth::new(b"gaugewright-federation-challenge".to_vec());
        auth.register(acme.clone(), client_key.public_key());

        let (server_verdict, client_verdict, sessions, engagement) =
            run_served_handshake(auth, "scope:acme:run-1", client_key).await;

        // Both halves agree the same session was issued, for the same authority.
        assert_eq!(server_verdict, client_verdict);
        let (token_bytes, authority) = match client_verdict {
            AuthResult::Session { token, authority } => (token, authority),
            other => panic!("expected a session, got {other:?}"),
        };
        assert_eq!(authority, "acme");
        assert!(!token_bytes.is_empty(), "a real token was minted");

        // The token the client received actually authorizes calls on the server's
        // session store for the (engagement, authority) it authenticated as —
        // proving the wire token is the one the server bound, not a placebo.
        let token = SessionToken::from_bytes(token_bytes);
        assert_eq!(sessions.authorize(&engagement, &acme, &token), Ok(acme));
    }

    #[tokio::test]
    async fn a_client_signing_with_the_wrong_key_is_refused_over_tcp() {
        // The server expects acme's key, but the client signs with a *different*
        // authority's key — a wrong credential. The signature will not verify.
        let acme = AuthorityId::new("acme");
        let mut auth = GovernanceAuth::new(b"gaugewright-federation-challenge".to_vec());
        auth.register(
            acme.clone(),
            LoopbackKeyStore.signing_key(&acme).public_key(),
        );
        let attacker_key = LoopbackKeyStore.signing_key(&AuthorityId::new("attacker"));

        let (server_verdict, client_verdict, sessions, engagement) =
            run_served_handshake(auth, "scope:acme:run-1", attacker_key).await;

        // Both halves see a refusal; the verdict names a bad signature.
        assert_eq!(server_verdict, client_verdict);
        match client_verdict {
            AuthResult::Refused(reason) => {
                assert!(reason.contains("bad signature"), "got: {reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // No session was opened, so no token can authorize this engagement.
        let forged = SessionToken::from_bytes(
            b"gaugewright-session:\x00\x00\x00\x00\x00\x00\x00\x01".to_vec(),
        );
        assert_eq!(
            sessions.authorize(&engagement, &acme, &forged),
            Err(crate::session::SessionRejection::UnknownToken),
        );
    }

    #[tokio::test]
    async fn a_client_for_an_unregistered_authority_is_refused_over_tcp() {
        // No governance key is registered for the scope's owning authority, so the
        // server refuses before any signature could matter — an unauthenticated
        // client cannot obtain a session.
        let auth = GovernanceAuth::new(b"gaugewright-federation-challenge".to_vec());
        let stranger_key = LoopbackKeyStore.signing_key(&AuthorityId::new("stranger"));

        let (server_verdict, client_verdict, _sessions, _engagement) =
            run_served_handshake(auth, "scope:stranger:x", stranger_key).await;

        assert_eq!(server_verdict, client_verdict);
        match client_verdict {
            AuthResult::Refused(reason) => {
                assert!(reason.contains("unknown authority"), "got: {reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
