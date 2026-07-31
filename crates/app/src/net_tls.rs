//! Cert-pinned TLS for the federation relay legs (D-REMOTE / ADR 0041).
//!
//! Two paired authorities have **no shared web PKI** (`INV-7`: federation relates
//! scopes pairwise, never through a global directory), so the legs do not trust
//! CA-chained certificates. Instead each authority generates a **self-signed**
//! certificate, publishes its **fingerprint** (SHA-256 of the DER) in the pairing
//! ticket, and the dialing side **pins** it — refusing any certificate whose
//! fingerprint it did not pin (fail-closed, exactly like the bridge grant pins the
//! source's governance key in [`crate::federation_relay`]).
//!
//! The TLS session runs **end-to-end between the two legs, tunnelled through the
//! blind rendezvous broker**: the broker splices opaque bytes, so it carries only
//! ciphertext and the encrypted handshake — it terminates nothing and holds no key
//! (`RELAY_NO_PAYLOAD_ACCESS` / `INV-10`). The connecting (source) leg is the TLS
//! client and pins the receiving (target) leg's certificate; the receiver is the
//! TLS server. Authority *authentication* still rides the governance-key handshake
//! ([`crate::net_server`]) on top — TLS provides the encrypted, identity-pinned
//! channel; the signature provides who-said-it.
//!
//! The pin compare reuses the fail-closed registry that
//! [`crate::net_server::PinnedTlsClientConfig`] already proves: this module fills
//! in the *real* certificate (rcgen + rustls) the `CERT-PIN-1` stub reserved.

use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};

use gaugewright_core::ids::AuthorityId;

use crate::net_server::{CertFingerprint, PinRejection, PinnedTlsClientConfig};

/// The dummy SNI name both legs use. Identity is established by the **pinned
/// fingerprint**, not the hostname, so the name is a fixed placeholder the
/// verifier ignores — there is no DNS in the rendezvous path.
const PIN_SNI: &str = "gaugewright-peer";

/// A control plane's own TLS identity: its self-signed certificate, the matching
/// private key, and the fingerprint a peer pins. Generated once per authority and
/// persisted under the state root so the fingerprint a peer pinned stays stable
/// across restarts (re-pairing on rotation, never a silent new cert).
#[derive(Clone, Debug)]
pub struct TlsIdentity {
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
    fingerprint: CertFingerprint,
}

impl TlsIdentity {
    /// Generate a fresh self-signed identity (rcgen, P-256 under the `ring`
    /// backend). The certificate carries the placeholder [`PIN_SNI`] name; trust is
    /// the fingerprint, not the name.
    pub fn generate() -> std::io::Result<Self> {
        let certified = rcgen::generate_simple_self_signed(vec![PIN_SNI.to_string()])
            .map_err(|e| std::io::Error::other(format!("rcgen self-signed: {e}")))?;
        let cert_der = certified.cert.der().clone();
        let key_der = certified.key_pair.serialize_der();
        let fingerprint = fingerprint_of(&cert_der);
        Ok(Self {
            cert_der,
            key_der,
            fingerprint,
        })
    }

    /// Load the identity persisted under `dir` (a `tls.crt` + `tls.key` DER pair),
    /// generating + persisting a fresh one **only when both files are genuinely
    /// absent** (a first run) — so a peer's pin stays valid across restarts. Any
    /// other outcome — one file present without the other, or an unreadable
    /// file — fails closed rather than silently regenerating and breaking every
    /// established pairing (DR-0054; same contract as relay-transport's
    /// `TlsIdentity::load_or_generate` fixed in Phase A).
    pub fn load_or_generate(dir: &Path) -> std::io::Result<Self> {
        let cert_path = dir.join("tls.crt");
        let key_path = dir.join("tls.key");
        match (std::fs::read(&cert_path), std::fs::read(&key_path)) {
            (Ok(cert), Ok(key)) => {
                let cert_der = CertificateDer::from(cert);
                let fingerprint = fingerprint_of(&cert_der);
                Ok(Self {
                    cert_der,
                    key_der: key,
                    fingerprint,
                })
            }
            (Err(cert_error), Err(key_error))
                if cert_error.kind() == std::io::ErrorKind::NotFound
                    && key_error.kind() == std::io::ErrorKind::NotFound =>
            {
                let identity = Self::generate()?;
                std::fs::create_dir_all(dir)?;
                std::fs::write(&cert_path, identity.cert_der.as_ref())?;
                std::fs::write(&key_path, &identity.key_der)?;
                Ok(identity)
            }
            (Err(error), _) | (_, Err(error)) => Err(std::io::Error::other(format!(
                "TLS identity in {} is unreadable ({error}); refusing to regenerate \
                 over an identity that peers may have pinned",
                dir.display()
            ))),
        }
    }

    /// The fingerprint a peer pins (published in this authority's pairing ticket).
    pub fn fingerprint(&self) -> &CertFingerprint {
        &self.fingerprint
    }

    /// A rustls [`ServerConfig`] presenting this identity — server-auth only (the
    /// authority authentication rides the governance-key handshake on top, so the
    /// TLS layer does not also do client-cert auth).
    fn server_config(&self) -> std::io::Result<ServerConfig> {
        let key = PrivatePkcs8KeyDer::from(self.key_der.clone());
        ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::other(format!("tls server versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![self.cert_der.clone()], key.into())
        .map_err(|e| std::io::Error::other(format!("tls server cert: {e}")))
    }
}

/// SHA-256 of a certificate's DER — the value pinned and compared (`CERT-PIN-1`).
fn fingerprint_of(cert: &CertificateDer<'_>) -> CertFingerprint {
    CertFingerprint::new(Sha256::digest(cert.as_ref()).to_vec())
}

/// The rustls server-certificate verifier that **pins by fingerprint**: it accepts
/// a presented leaf certificate only if its SHA-256 matches the fingerprint pinned
/// for the dialed authority, delegating that decision to the same fail-closed
/// [`PinnedTlsClientConfig`] the `CERT-PIN-1` stub proved. Signature verification of
/// the handshake itself still runs through the crypto provider — so a matching
/// fingerprint cannot rubber-stamp a handshake the peer's key did not actually sign.
#[derive(Debug)]
struct PinnedServerCertVerifier {
    pins: Arc<PinnedTlsClientConfig>,
    authority: AuthorityId,
    provider: Arc<tokio_rustls::rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let presented = fingerprint_of(end_entity);
        match self.pins.verify_peer(&self.authority, &presented) {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(PinRejection::NoPin(a)) => Err(tokio_rustls::rustls::Error::General(format!(
                "no pinned certificate for authority {a} (fail-closed: no cross-authority PKI)"
            ))),
            Err(PinRejection::PinMismatch(a)) => {
                Err(tokio_rustls::rustls::Error::General(format!(
                "presented certificate does not match the pin for authority {a} (possible MITM)"
            )))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
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
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
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

/// **Client leg**: wrap an already-connected (and session-token-announced) TCP
/// stream in a TLS client session that **pins** `authority`'s certificate via
/// `pins`. Returns the encrypted stream the frame protocol then runs over. A
/// presented certificate that does not match the pin fails the handshake
/// (fail-closed) — the connection never carries application bytes.
pub async fn tls_connect<S>(
    tcp: S,
    authority: &AuthorityId,
    pins: Arc<PinnedTlsClientConfig>,
) -> std::io::Result<client::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedServerCertVerifier {
        pins,
        authority: authority.clone(),
        provider: provider.clone(),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::other(format!("tls client versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let server_name = ServerName::try_from(PIN_SNI)
        .map_err(|e| std::io::Error::other(format!("tls server name: {e}")))?;
    TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
}

/// **Server leg**: wrap an already-connected (and session-token-announced) TCP
/// stream in a TLS server session presenting `identity`'s certificate. The client
/// pins this certificate's fingerprint; the server does not authenticate the
/// client at the TLS layer (the governance-key handshake does that on top).
pub async fn tls_accept<S>(tcp: S, identity: &TlsIdentity) -> std::io::Result<server::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = identity.server_config()?;
    TlsAcceptor::from(Arc::new(config)).accept(tcp).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// A generated identity has a stable 32-byte (SHA-256) fingerprint, and a
    /// reload from disk yields the *same* fingerprint (a peer's pin survives a
    /// restart).
    #[test]
    fn identity_fingerprint_is_stable_across_reload() {
        let dir = std::env::temp_dir().join(format!("gaugewright-tls-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = TlsIdentity::load_or_generate(&dir).unwrap();
        let reloaded = TlsIdentity::load_or_generate(&dir).unwrap();
        assert_eq!(first.fingerprint(), reloaded.fingerprint());
        assert_eq!(first.fingerprint().as_bytes().len(), 32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// DR-0054 (Phase A residual): a half-present identity — one of
    /// `tls.crt`/`tls.key` missing or unreadable — must fail closed, never be
    /// silently regenerated: peers pinned this certificate's fingerprint, and a
    /// regeneration would break every established pairing. The surviving half
    /// stays on disk untouched, so the identity remains recoverable.
    #[test]
    fn a_half_present_identity_fails_closed_instead_of_regenerating() {
        let dir = tempfile::tempdir().unwrap();
        let first = TlsIdentity::load_or_generate(dir.path()).unwrap();
        let cert_bytes = std::fs::read(dir.path().join("tls.crt")).unwrap();
        std::fs::remove_file(dir.path().join("tls.key")).unwrap();

        let error = TlsIdentity::load_or_generate(dir.path())
            .expect_err("a half-present identity must never be silently regenerated");
        assert!(
            error.to_string().contains("refusing to regenerate"),
            "unexpected error: {error}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("tls.crt")).unwrap(),
            cert_bytes,
            "the surviving certificate is untouched, so the fingerprint {:x?} peers pinned stays recoverable",
            first.fingerprint().as_bytes(),
        );
    }

    /// End-to-end over a real loopback socket pair: the server presents its
    /// identity, the client pins the *correct* fingerprint, the handshake
    /// completes, and application bytes round-trip over the encrypted channel.
    #[tokio::test]
    async fn a_correctly_pinned_client_completes_the_handshake_and_exchanges_bytes() {
        let identity = TlsIdentity::generate().unwrap();
        let peer = AuthorityId::new("node-b");
        let mut pins = PinnedTlsClientConfig::new();
        pins.pin(peer.clone(), identity.fingerprint().clone());
        let pins = Arc::new(pins);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_identity = identity.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = tls_accept(tcp, &server_identity).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"world").await.unwrap();
            tls.flush().await.unwrap();
            buf
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = tls_connect(tcp, &peer, pins).await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut reply = [0u8; 5];
        tls.read_exact(&mut reply).await.unwrap();

        assert_eq!(&reply, b"world");
        assert_eq!(&server.await.unwrap(), b"hello");
    }

    /// A recording splice with the broker's exact semantics (`copy_bidirectional`
    /// over two legs) but which **captures every byte it forwards**, so a test can
    /// assert the broker carried only ciphertext. The real
    /// The managed WSS object is even blinder (it retains no carried bytes);
    /// this stand-in is a strictly stronger observer.
    async fn recording_splice(
        a: TcpStream,
        b: TcpStream,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<u8>>> {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut ar, mut aw) = a.into_split();
        let (mut br, mut bw) = b.into_split();
        let cap = captured.clone();
        let fwd = async move {
            let mut buf = vec![0u8; 8192];
            while let Ok(n) = ar.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                cap.lock().unwrap().extend_from_slice(&buf[..n]);
                if bw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = bw.shutdown().await;
        };
        let back = async move {
            let _ = tokio::io::copy(&mut br, &mut aw).await;
            let _ = aw.shutdown().await;
        };
        tokio::join!(fwd, back);
        captured
    }

    /// The whole point of M3: a TLS session runs **end-to-end through the blind
    /// broker splice**, and a recognizable secret in the application payload never
    /// appears in the bytes the broker forwarded — the broker carried only
    /// ciphertext (`RELAY_NO_PAYLOAD_ACCESS` / `INV-10`), while the peer decrypted
    /// the cleartext.
    #[tokio::test]
    async fn a_tls_session_tunnels_through_the_broker_carrying_only_ciphertext() {
        const SECRET: &[u8] = b"ctx-method-SECRET-HANDLE";

        let identity = TlsIdentity::generate().unwrap();
        let peer = AuthorityId::new("node-b");
        let mut pins = PinnedTlsClientConfig::new();
        pins.pin(peer.clone(), identity.fingerprint().clone());
        let pins = Arc::new(pins);

        // A two-leg broker: accept both legs, then splice (recording the bytes).
        let broker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let broker_addr = broker.local_addr().unwrap();
        let broker_task = tokio::spawn(async move {
            let (leg1, _) = broker.accept().await.unwrap();
            let (leg2, _) = broker.accept().await.unwrap();
            recording_splice(leg1, leg2).await
        });

        // Target leg (TLS server) dials the broker and accepts the pinned session.
        let server_identity = identity.clone();
        let target = tokio::spawn(async move {
            let tcp = TcpStream::connect(broker_addr).await.unwrap();
            let mut tls = tls_accept(tcp, &server_identity).await.unwrap();
            let mut got = vec![0u8; SECRET.len()];
            tls.read_exact(&mut got).await.unwrap();
            tls.write_all(b"admitted").await.unwrap();
            tls.flush().await.unwrap();
            got
        });

        // Source leg (TLS client) dials the broker, pins the target, sends SECRET.
        // A tiny stagger so the broker accepts the server leg first (deterministic).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let tcp = TcpStream::connect(broker_addr).await.unwrap();
        let mut tls = tls_connect(tcp, &peer, pins).await.unwrap();
        tls.write_all(SECRET).await.unwrap();
        tls.flush().await.unwrap();
        let mut verdict = [0u8; 8];
        tls.read_exact(&mut verdict).await.unwrap();
        tls.shutdown().await.unwrap();

        let decrypted = target.await.unwrap();
        let captured = broker_task.await.unwrap();
        let captured = captured.lock().unwrap();

        // The peer decrypted the real secret…
        assert_eq!(decrypted, SECRET, "the peer decrypted the cleartext");
        assert_eq!(&verdict, b"admitted");
        // …but the broker forwarded only ciphertext: the secret never appears in
        // the bytes it carried, even though it carried plenty of them.
        assert!(
            !captured.is_empty(),
            "the broker did forward the encrypted traffic"
        );
        assert!(
            !contains_subslice(&captured, SECRET),
            "RELAY_NO_PAYLOAD_ACCESS: the secret must not appear in the broker's bytes"
        );
    }

    /// True iff `haystack` contains `needle` as a contiguous subslice.
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// A client that pins a *different* fingerprint than the server presents must
    /// fail the handshake (fail-closed) — a possible MITM is refused, no
    /// application bytes cross.
    #[tokio::test]
    async fn a_mismatched_pin_refuses_the_handshake() {
        let server_identity = TlsIdentity::generate().unwrap();
        // The client pins some *other* certificate's fingerprint for node-b.
        let wrong = TlsIdentity::generate().unwrap();
        let peer = AuthorityId::new("node-b");
        let mut pins = PinnedTlsClientConfig::new();
        pins.pin(peer.clone(), wrong.fingerprint().clone());
        let pins = Arc::new(pins);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // The accept may error once the client aborts the handshake — that is
            // the server's view of the client's fail-closed refusal.
            let _ = tls_accept(tcp, &server_identity).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let result = tls_connect(tcp, &peer, pins).await;
        assert!(
            result.is_err(),
            "a mismatched pin must refuse the handshake (fail-closed)"
        );
        let _ = srv.await;
    }
}
