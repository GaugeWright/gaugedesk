//! Transparent SNI-filtering proxy (CORE-5 / RF-B3) — the enforcement *heart* of
//! the [`Network::Filtered`](crate::sandbox::Network::Filtered) posture under the
//! **transparent** transport (ADR 0079; supersedes the `CONNECT`/`HTTPS_PROXY`
//! design in [`crate::egress_proxy`]).
//!
//! The agent connects **directly** to e.g. `api.openai.com:443`; the sandbox netns
//! DNATs every `tcp dport 443` to this proxy (see [`crate::sandbox`]). The proxy
//! reads the TLS `ClientHello` — the **plaintext** `server_name` (SNI) extension,
//! no decryption — checks it against the exact-match allowlist (reusing
//! [`crate::egress_proxy::host_allowed`]), and only then opens the upstream to the
//! *SNI host* on 443, replays the buffered `ClientHello` verbatim, and blind-copies
//! bytes both ways. TLS stays end-to-end between the agent and the endpoint; the
//! proxy never terminates it. A `ClientHello` whose SNI is absent, malformed, or
//! off the allowlist gets **no upstream** — the connection is dropped.
//!
//! This is load-bearing only because it is the netns's **sole** outbound path: the
//! netns default-drops every route except loopback and the proxy address, and DNATs
//! 443 here, so a host off the allowlist is unreachable even if the agent ignores
//! all proxy env — bun/the agent runtime need not cooperate. On its own (reachable
//! beside an open route) it would be honor-system only; the non-bypassable routing
//! is the netns's job (`crate::sandbox`).
//!
//! Because the upstream is dialed by the *SNI host* (re-resolved on the host), a
//! forged SNI cannot reach an arbitrary IP: the bytes go to whatever the allowed
//! SNI resolves to. Residual risks (documented, follow-ups): **domain fronting**
//! (an allowed SNI fronting a different `Host:` on a shared CDN) and **DNS
//! tunnelling** (DNS to the resolver is permitted so the agent can resolve names) —
//! a captive-DNS hardening is tracked separately.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::egress_proxy::host_allowed;

/// TLS `ContentType` for a handshake record (RFC 8446 §5.1).
const TLS_HANDSHAKE: u8 = 0x16;
/// Handshake message type for `ClientHello` (RFC 8446 §4).
const TLS_CLIENT_HELLO: u8 = 0x01;
/// Extension type for `server_name` / SNI (RFC 6066 §3).
const EXT_SERVER_NAME: u16 = 0x0000;
/// `NameType` for `host_name` inside the SNI extension (RFC 6066 §3).
const SNI_HOST_NAME: u8 = 0x00;
/// The port every transparent egress connection targets. Only 443 is DNATed to the
/// proxy (model endpoints are HTTPS); the proxy always dials the SNI host on 443.
const UPSTREAM_PORT: u16 = 443;
/// Max bytes of the first TLS record body we will buffer. A `ClientHello` is a few
/// hundred bytes to low single-KiB; a legal TLS record body is ≤ 2^14. Anything
/// larger — or a `ClientHello` fragmented across records — is refused (fail closed:
/// no SNI parsed ⇒ no tunnel), never buffered without bound.
const MAX_RECORD_BODY: usize = 16 * 1024;

/// A minimal forward-only byte reader with bounds-checked primitives, so the SNI
/// parse can never index out of range on a truncated or hostile `ClientHello`.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    /// The next `n` bytes, advancing the cursor — `None` if fewer than `n` remain.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

/// Parse the SNI `host_name` out of the raw bytes of the first TLS record — i.e.
/// the `ClientHello`, **record header included** (starting with the `0x16`
/// handshake byte), exactly as read off the wire. Pure and total: it **never
/// panics** and returns `None` for anything that is not a well-formed
/// `ClientHello` carrying a `host_name` SNI — non-TLS bytes, a truncated record, a
/// `ClientHello` with no SNI, or a `ClientHello` fragmented across records (the
/// declared handshake length exceeds this record's body). `None` is the
/// fail-closed signal: the caller drops the connection.
pub fn parse_sni(record: &[u8]) -> Option<String> {
    let mut r = Reader::new(record);
    // TLS record header: type(1) | legacy_version(2) | length(2).
    if r.u8()? != TLS_HANDSHAKE {
        return None; // not a TLS handshake record
    }
    r.skip(2)?; // legacy record version — not load-bearing
    let record_len = r.u16()? as usize;
    // The whole record body must be present in this buffer; a ClientHello
    // fragmented across records fails the parse (and thus fails closed).
    let body = r.take(record_len)?;

    let mut h = Reader::new(body);
    // Handshake header: msg_type(1) | length(3).
    if h.u8()? != TLS_CLIENT_HELLO {
        return None;
    }
    let len_hi = h.u8()? as usize;
    let len_mid = h.u8()? as usize;
    let len_lo = h.u8()? as usize;
    let hello_len = (len_hi << 16) | (len_mid << 8) | len_lo;
    // The ClientHello body must fit within this record (else it is fragmented).
    let hello = h.take(hello_len)?;

    let mut c = Reader::new(hello);
    c.skip(2)?; // legacy_version
    c.skip(32)?; // random
    let sid_len = c.u8()? as usize;
    c.skip(sid_len)?; // legacy_session_id
    let cs_len = c.u16()? as usize;
    c.skip(cs_len)?; // cipher_suites
    let comp_len = c.u8()? as usize;
    c.skip(comp_len)?; // legacy_compression_methods
                       // extensions: total length(2), then a sequence of type(2)|len(2)|data.
    let ext_total = c.u16()? as usize;
    let exts = c.take(ext_total)?;

    let mut e = Reader::new(exts);
    while e.remaining() >= 4 {
        let ext_type = e.u16()?;
        let ext_len = e.u16()? as usize;
        let ext_data = e.take(ext_len)?;
        if ext_type == EXT_SERVER_NAME {
            return parse_server_name(ext_data);
        }
    }
    None
}

/// The `server_name` extension body: `ServerNameList` = list_len(2), then entries
/// of `name_type(1) | host_name<2>`. Returns the first `host_name` as a `String`.
fn parse_server_name(data: &[u8]) -> Option<String> {
    let mut s = Reader::new(data);
    let list_len = s.u16()? as usize;
    let list = s.take(list_len)?;
    let mut l = Reader::new(list);
    while l.remaining() >= 3 {
        let name_type = l.u8()?;
        let name_len = l.u16()? as usize;
        let name = l.take(name_len)?;
        if name_type == SNI_HOST_NAME {
            // Hostnames are ASCII (IDNA-encoded); reject non-UTF-8 rather than lossily.
            return std::str::from_utf8(name).ok().map(str::to_owned);
        }
    }
    None
}

/// A running transparent SNI proxy: its bound loopback address, plus a drop-guard
/// on the accept task so it is torn down when the handle is dropped.
pub struct SniProxy {
    addr: SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

impl SniProxy {
    /// Bind an accept loop on `127.0.0.1:0` and start serving. Returns once the
    /// listener is bound (so [`Self::addr`] is immediately usable). Must run on a
    /// tokio runtime.
    pub async fn start(allowlist: Vec<String>) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let allow = Arc::new(allowlist);
        let task = tokio::spawn(async move { serve(listener, allow).await });
        Ok(Self { addr, _task: task })
    }

    /// The loopback address the proxy listens on (the netns DNATs 443 here, via
    /// pasta's host-loopback map).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Accept connections forever, each on its own task. A per-connection error never
/// takes the loop down — one misbehaving client must not close the checkpoint.
async fn serve(listener: TcpListener, allow: Arc<Vec<String>>) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let allow = allow.clone();
                tokio::spawn(async move {
                    let _ = handle_conn(stream, &allow).await;
                });
            }
            Err(_) => continue, // transient accept error (fd pressure) must not wedge us
        }
    }
}

/// One connection: read the first TLS record, rule on its SNI, and — only on an
/// allowlisted `host_name` — dial that host on 443, replay the buffered
/// `ClientHello`, and blind-tunnel. Anything else drops with no upstream opened.
async fn handle_conn(mut inbound: TcpStream, allow: &[String]) -> io::Result<()> {
    // Read the 5-byte TLS record header. A short read / EOF here is a client that
    // is not speaking TLS — drop it.
    let mut header = [0u8; 5];
    inbound.read_exact(&mut header).await?;
    if header[0] != TLS_HANDSHAKE || header[1] != 0x03 {
        return Ok(()); // not a TLS 1.x handshake record
    }
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len == 0 || record_len > MAX_RECORD_BODY {
        return Ok(()); // empty or over-large record body — refuse rather than buffer
    }
    // Read exactly the declared record body (bounded — never an unbounded read).
    let mut body = vec![0u8; record_len];
    inbound.read_exact(&mut body).await?;

    // Reassemble the exact bytes the client sent, to replay upstream untouched.
    let mut hello = Vec::with_capacity(5 + record_len);
    hello.extend_from_slice(&header);
    hello.extend_from_slice(&body);

    // THE CHECK: parse the plaintext SNI and require an exact allowlist match.
    // No SNI / malformed / off-list ⇒ no upstream is ever opened.
    let host = match parse_sni(&hello) {
        Some(h) if host_allowed(&h, allow) => h,
        _ => return Ok(()),
    };

    // Allowed: dial the SNI host itself on 443 (re-resolved here on the host, so a
    // forged SNI cannot redirect to an arbitrary IP). A connect failure just drops.
    let mut outbound = match TcpStream::connect((host.as_str(), UPSTREAM_PORT)).await {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    // Replay the buffered ClientHello verbatim, then blind-copy — TLS is end-to-end.
    outbound.write_all(&hello).await?;
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    Ok(())
}

/// A **synchronous** owner of a running [`SniProxy`], for callers with no tokio
/// runtime (e.g. the sync [`PiProcess::spawn`](crate) path). It owns a dedicated OS
/// thread running a current-thread runtime that drives the proxy; the proxy lives
/// exactly as long as this guard, and is shut down when the guard is dropped (the
/// thread's runtime unwinds, aborting the accept task). Hold it beside the
/// sandboxed process so egress filtering is up for the whole life of the turn.
pub struct SniProxyGuard {
    addr: SocketAddr,
    /// Dropping this sender wakes the proxy thread's `recv`, ending its runtime.
    shutdown: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SniProxyGuard {
    /// Start the proxy on a dedicated OS thread with its own current-thread tokio
    /// runtime, blocking only until the listener is bound (its address comes back
    /// over a channel). Synchronous: usable from a non-async caller.
    pub fn spawn(allowlist: Vec<String>) -> io::Result<Self> {
        // `addr_tx` carries the bind result back; `shutdown_rx` parks the thread
        // (holding the runtime alive so the accept task runs) until the guard drops.
        let (addr_tx, addr_rx) = std::sync::mpsc::channel::<io::Result<SocketAddr>>();
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("gw-sni-proxy".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = addr_tx.send(Err(e));
                        return;
                    }
                };
                rt.block_on(async move {
                    let proxy = match SniProxy::start(allowlist).await {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = addr_tx.send(Err(e));
                            return;
                        }
                    };
                    if addr_tx.send(Ok(proxy.addr())).is_err() {
                        return; // the guard was dropped before it observed the addr
                    }
                    // Park here (driving the accept task via block_on) until the
                    // guard drops its sender — a blocking recv on an async-runtime
                    // thread is fine: this thread exists solely to host the proxy.
                    let _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()).await;
                    // `proxy` drops here → its accept task is aborted.
                });
            })?;
        let addr = addr_rx
            .recv()
            .map_err(|_| io::Error::other("sni proxy thread died at startup"))??;
        Ok(Self {
            addr,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    /// The loopback address the proxy listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for SniProxyGuard {
    fn drop(&mut self) {
        // Signal shutdown (drop the sender), then join so the proxy is fully torn
        // down before we return — the egress checkpoint never outlives the process.
        drop(self.shutdown.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but well-formed TLS `ClientHello` record carrying `sni`
    /// (or none when `sni` is `None`), so the parser is exercised on realistic
    /// bytes without capturing a live handshake.
    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length 0
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len 2, TLS_AES_128
        body.extend_from_slice(&[0x01, 0x00]); // compression: len 1, null

        let mut exts = Vec::new();
        if let Some(name) = sni {
            let name = name.as_bytes();
            let mut sni_ext = Vec::new();
            // ServerNameList: list_len, name_type=host_name, name_len, name.
            let entry_len = 1 + 2 + name.len();
            sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
            sni_ext.push(SNI_HOST_NAME);
            sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
            sni_ext.extend_from_slice(name);
            exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            exts.extend_from_slice(&sni_ext);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        // Handshake header: ClientHello + 3-byte length.
        let mut hs = Vec::new();
        hs.push(TLS_CLIENT_HELLO);
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        // Record header: handshake, TLS 1.0 record version, length.
        let mut rec = Vec::new();
        rec.push(TLS_HANDSHAKE);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_sni_from_a_valid_client_hello() {
        let rec = client_hello(Some("api.openai.com"));
        assert_eq!(parse_sni(&rec).as_deref(), Some("api.openai.com"));
    }

    #[test]
    fn client_hello_without_sni_yields_none() {
        let rec = client_hello(None);
        assert_eq!(parse_sni(&rec), None);
    }

    #[test]
    fn truncated_client_hello_yields_none_never_panics() {
        let rec = client_hello(Some("example.com"));
        // Every prefix must parse to None (incomplete) without panicking — this is
        // the fail-closed property on a hostile/partial record.
        for cut in 0..rec.len() {
            assert_eq!(
                parse_sni(&rec[..cut]),
                None,
                "prefix len {cut} must be None"
            );
        }
        // The full record still parses (the loop stops one short of full length).
        assert_eq!(parse_sni(&rec).as_deref(), Some("example.com"));
    }

    #[test]
    fn non_tls_bytes_yield_none() {
        assert_eq!(parse_sni(b""), None);
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
        // A record that claims to be handshake but is garbage past the header.
        assert_eq!(
            parse_sni(&[0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5]),
            None
        );
    }

    #[test]
    fn a_declared_record_longer_than_the_buffer_fails_closed() {
        let mut rec = client_hello(Some("example.com"));
        // Inflate the record-length field so the declared body exceeds what's here;
        // the parser must refuse (None), never read past the slice.
        rec[3] = 0xff;
        rec[4] = 0xff;
        assert_eq!(parse_sni(&rec), None);
    }

    // ---- proxy over real localhost TCP ------------------------------------
    //
    // Drive the drop paths end to end: a real client socket sends a ClientHello to
    // a real bound proxy, and a disallowed / SNI-less / non-TLS client is dropped
    // with no upstream. The allow-and-tunnel path is proven by the gated sandbox
    // integration test (real `curl` to an allowlisted host through the real proxy).

    #[tokio::test]
    async fn disallowed_sni_opens_no_upstream() {
        let proxy = SniProxy::start(vec!["api.openai.com".to_string()])
            .await
            .unwrap();
        let mut client = TcpStream::connect(proxy.addr()).await.unwrap();
        // A well-formed ClientHello for a host NOT on the allowlist.
        client
            .write_all(&client_hello(Some("evil.example")))
            .await
            .unwrap();
        // The proxy drops the connection with no upstream: the read returns EOF.
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "a disallowed SNI must get no bytes and be dropped");
    }

    #[tokio::test]
    async fn sni_less_client_hello_opens_no_upstream() {
        let proxy = SniProxy::start(vec!["api.openai.com".to_string()])
            .await
            .unwrap();
        let mut client = TcpStream::connect(proxy.addr()).await.unwrap();
        client.write_all(&client_hello(None)).await.unwrap();
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "a ClientHello with no SNI must be dropped");
    }

    #[tokio::test]
    async fn non_tls_client_opens_no_upstream() {
        let proxy = SniProxy::start(vec!["api.openai.com".to_string()])
            .await
            .unwrap();
        let mut client = TcpStream::connect(proxy.addr()).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "a non-TLS client must be dropped");
    }

    #[test]
    fn the_sync_guard_binds_and_reports_a_loopback_addr() {
        let guard = SniProxyGuard::spawn(vec!["example.com".to_string()]).unwrap();
        assert!(guard.addr().ip().is_loopback());
        assert_ne!(guard.addr().port(), 0);
        // Dropping the guard tears the proxy down (no hang — Drop joins the thread).
    }

    /// THE NON-BYPASS PROOF (CORE-5, ADR 0079). Spin the real SNI proxy with a
    /// one-host allowlist and run `curl` **inside the full sandbox**
    /// (pasta + nft + bwrap) — the transparent composition the Pi bridge builds —
    /// asserting egress is possible ONLY to the allowlisted host, and only via the
    /// proxy: a non-allowlisted SNI is dropped by the proxy, and direct egress that
    /// never reaches the proxy (raw IP, non-443) is dropped by nft. Gated to run
    /// only where pasta+bwrap+nft+curl exist and work, and where the host itself has
    /// egress; skips with a log otherwise.
    ///
    /// It deliberately still uses the real `example.com` over the real internet. A
    /// loopback TLS endpoint would remove the network dependency, but the proxy dials
    /// the SNI host on a hardcoded 443 (and the netns DNATs only 443), so a local
    /// stand-in would need a privileged bind plus a trusted cert or a
    /// verification-disabling client flag — a test-only seam through the enforcement
    /// heart, in exchange for a weaker proof. The live dependency is kept and made
    /// self-diagnosing instead: see `allow_path_must_succeed` below, which is how a
    /// transient resolver failure is prevented from reading as an egress regression.
    #[cfg(target_os = "linux")]
    #[test]
    fn transparent_sni_egress_is_non_bypassable_end_to_end() {
        use crate::sandbox::{filtered_wrap, SandboxPolicy};
        use std::process::Command;

        fn on_path(bin: &str) -> bool {
            std::env::var_os("PATH")
                .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
                .unwrap_or(false)
        }
        fn ok(cmd: &mut Command) -> bool {
            matches!(cmd.status(), Ok(s) if s.success())
        }
        /// Can the **host itself** reach the allowlisted endpoint right now?
        /// Every *positive* assertion below ("an allowlisted host stays
        /// reachable through the sandbox") only carries information about the
        /// sandbox while this is true at that instant.
        fn host_egress_ok() -> bool {
            ok(Command::new("curl").args([
                "-sS",
                "-o",
                "/dev/null",
                "--max-time",
                "15",
                "https://example.com",
            ]))
        }

        if !["pasta", "bwrap", "nft", "curl"].iter().all(|b| on_path(b)) {
            eprintln!("skip: transparent-egress e2e needs pasta+bwrap+nft+curl on PATH");
            return;
        }
        // bwrap must actually work here (user namespaces), and pasta must be able to
        // stand up a netns — some CI sandboxes forbid both.
        if !ok(Command::new("bwrap").args(["--ro-bind", "/", "/", "--", "true"])) {
            eprintln!("skip: bwrap unusable here (no user namespaces)");
            return;
        }
        if !ok(Command::new("pasta").args(["--config-net", "--ipv4-only", "--", "true"])) {
            eprintln!("skip: pasta cannot create a netns here");
            return;
        }
        // No point asserting "allowed host reachable" if the host itself is offline.
        if !host_egress_ok() {
            eprintln!("skip: host has no egress to example.com (offline)");
            return;
        }

        /// Drive a *positive* (liveness) probe that must succeed, distinguishing a
        /// broken egress path from a machine that transiently lost its own name
        /// resolution. `probe` returns `Err(diagnostic)` when the allow-path attempt
        /// did not succeed.
        ///
        /// MEASURED (2026-09-14, 20-core host under heavy build load): `example.com`
        /// intermittently fails to resolve — `curl: (6) Could not resolve host` — for
        /// the **host and the sandbox alike**, in roughly 1 run in 25. The preflight
        /// above establishes host egress once, but these assertions land up to thirty
        /// seconds later and the record's TTL is shorter than this test, so a resolver
        /// blip inside that window used to fail the whole `rust` section with a
        /// message that reads exactly like a genuine egress regression.
        ///
        /// So a failed attempt is not a verdict on its own: ask the host the same
        /// question. If the host can reach the endpoint and the sandboxed path cannot,
        /// that IS the regression this test exists to catch and it fails immediately,
        /// with a better message than before. If the host cannot reach it either, the
        /// attempt says nothing about the sandbox and is retried until the host's own
        /// egress comes back or the budget runs out (then it skips, like the preflight).
        ///
        /// Retrying is sound here *because it is confined to the liveness half*: a
        /// broken proxy, netns, or ruleset fails every attempt while `host_egress_ok()`
        /// keeps returning true, so it still fails deterministically and on the first
        /// attempt. The negative assertions below are deterministic and never retried.
        fn allow_path_must_succeed(label: &str, mut probe: impl FnMut() -> Result<(), String>) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                let last = match probe() {
                    Ok(()) => return,
                    Err(diagnostic) => diagnostic,
                };
                if host_egress_ok() {
                    panic!(
                        "{label}: the host itself reaches https://example.com right now, \
                         so the transparent sandbox failing to is a real egress \
                         regression — {last}"
                    );
                }
                if std::time::Instant::now() >= deadline {
                    eprintln!(
                        "skip ({label}): the host's own egress to example.com stayed down \
                         for the whole retry budget — this run cannot judge the sandbox \
                         (last attempt: {last})"
                    );
                    return;
                }
                // Leave a breadcrumb: a silently-recovered retry would hide the fact
                // that this machine's name resolution is dropping out under load.
                eprintln!(
                    "retry ({label}): the host cannot reach example.com either right \
                     now, so this attempt judges nothing — {last}"
                );
                // Poll interval while the host's own resolver is confirmed down. This
                // is not the fix — the host-side re-check above is; this only spaces
                // the polls so a fast-failing resolver does not burn the budget.
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }

        // The one enforced allowlist entry — the proxy rules on the TLS SNI.
        let proxy = SniProxyGuard::spawn(vec!["example.com".to_string()]).unwrap();

        // Run `curl args…` inside the full transparent composition; return its
        // captured `%{http_code}` (curl writes "000" and exits non-zero when the
        // connection never completes — i.e. when egress was blocked).
        let run = |args: &[&str]| -> (String, bool) {
            let tmp = tempfile::tempdir().unwrap();
            let policy = SandboxPolicy::new(vec![tmp.path().to_path_buf()])
                .filter_egress(vec!["example.com".to_string()]);
            let curl_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let argv = filtered_wrap(&policy, "curl", &curl_args, None, proxy.addr())
                .expect("filtered_wrap builds the composition on Linux");
            let out = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
            let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
            (code, out.status.success())
        };
        // curl flags: silent, discard body, print only the HTTP status, bounded time.
        // (a) allowlisted host over 443 → succeeds through the transparent proxy.
        allow_path_must_succeed("allowlisted https://example.com through the proxy", || {
            let (code_a, ok_a) = run(&[
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "12",
                "https://example.com",
            ]);
            if (code_a.as_str(), ok_a) == ("200", true) {
                Ok(())
            } else {
                Err(format!(
                    "curl in the sandbox gave http_code={code_a:?} success={ok_a}"
                ))
            }
        });

        // (b) non-allowlisted host over 443 → proxy reads the SNI, opens NO
        // upstream, connection dropped.
        let (code_b, _ok_b) = run(&[
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "12",
            "https://api.github.com",
        ]);
        assert_ne!(
            code_b, "200",
            "non-allowlisted https://api.github.com must be BLOCKED (proxy closes on SNI)"
        );

        // (c) direct egress by raw IP over 443 → curl (no SNI on an IP literal) is
        // DNATed to the proxy, which drops it for lack of an allowlisted SNI.
        let (code_c, _ok_c) = run(&[
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "12",
            "--noproxy",
            "*",
            "https://1.1.1.1",
        ]);
        assert_ne!(
            code_c, "200",
            "direct https to a raw IP must be BLOCKED (no allowlisted SNI)"
        );

        // (d) egress on a non-443 port → never DNATed to the proxy, dropped by nft's
        // default-drop. This proves the nft layer blocks independently of the proxy.
        let (code_d, _ok_d) = run(&[
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "12",
            "http://example.com",
        ]);
        assert_ne!(
            code_d, "200",
            "port-80 egress must be BLOCKED by nft (only 443 reaches the proxy)"
        );

        // (e) HOST-LOOPBACK SERVICES must NOT be reachable. pasta maps the host's
        // whole loopback to <map>, so a naive `ip daddr <map> accept` (any port) would
        // let the sandbox dial unrelated host services (the control plane on :7878,
        // etc.) via <map>:<port>. nft accepts <map> ONLY on the proxy port, so this is
        // dropped. Regression for that hole: a host listener on an ephemeral loopback
        // port must be unreachable from inside the sandbox via <map>.
        let host_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let host_port = host_listener.local_addr().unwrap().port();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_reader = stop.clone();
        let responder = std::thread::spawn(move || {
            host_listener.set_nonblocking(true).ok();
            while !stop_reader.load(std::sync::atomic::Ordering::Relaxed) {
                match host_listener.accept() {
                    Ok((mut s, _)) => {
                        use std::io::Write;
                        // The same BSD inheritance the content-vault ledger
                        // fixture was just fixed for: an accepted socket
                        // inherits `O_NONBLOCK` from a non-blocking listener on
                        // macOS and the BSDs, and `std` clears it on no
                        // platform. This test is Linux-only today, where accept
                        // does not inherit, so the line is a no-op here — but
                        // the write is discarded with `let _`, so the day it
                        // runs on a BSD host it would drop this reply silently
                        // rather than fail. One line now, instead of a mystery
                        // later.
                        let _ = s.set_nonblocking(false);
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        let host_url = format!("http://{}:{host_port}/", crate::sandbox::HOST_LOOPBACK_MAP);
        let (code_e, _ok_e) = run(&[
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "8",
            "--noproxy",
            "*",
            host_url.as_str(),
        ]);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = responder.join();
        assert_ne!(
            code_e, "200",
            "host-loopback services (via the pasta map) must be BLOCKED — only the proxy port is accepted"
        );

        // (f) THE AGENT CANNOT TEAR DOWN THE FILTER. The agent has a `bash` tool, so a
        // prompt-injected turn could try `nft flush ruleset` to reopen egress. bwrap
        // runs it in a child user namespace with dropped capabilities, so it has no
        // CAP_NET_ADMIN over pasta's netns: the flush fails and egress to a
        // non-allowlisted host stays blocked. Run a shell that tries to remove the
        // filter and *then* reach a blocked host.
        {
            let tmp = tempfile::tempdir().unwrap();
            let policy = SandboxPolicy::new(vec![tmp.path().to_path_buf()])
                .filter_egress(vec!["example.com".to_string()]);
            let script = "nft flush ruleset 2>/dev/null; \
                          nft delete table inet gw_egress 2>/dev/null; \
                          curl -sS -o /dev/null -w %{http_code} --max-time 8 --noproxy '*' https://api.github.com";
            let argv = filtered_wrap(
                &policy,
                "sh",
                &["-c".to_string(), script.to_string()],
                None,
                proxy.addr(),
            )
            .expect("filtered_wrap builds the composition on Linux");
            let out = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
            let code_f = String::from_utf8_lossy(&out.stdout).trim().to_string();
            assert_ne!(
                code_f, "200",
                "an in-sandbox `nft flush` must NOT reopen egress (no CAP_NET_ADMIN over pasta's netns)"
            );
        }

        // (g) FUNCTIONAL ACCEPTANCE: the AGENT RUNTIME reaches an allowlisted host
        // through the transparent path. The shipped Pi is bun-compiled; because the
        // sandbox is transparent (the client just connects to the host normally — no
        // proxy env, no client cooperation), if bun's `fetch` reaches the allowlisted
        // host here, Pi's model client reaches an allowlisted model endpoint the same
        // way. This is the functional gate for FILTERED_ROUTING_VERIFIED. Gated on bun.
        if on_path("bun") {
            allow_path_must_succeed(
                "the agent runtime (bun fetch) through the transparent sandbox",
                || {
                    let tmp = tempfile::tempdir().unwrap();
                    let policy = SandboxPolicy::new(vec![tmp.path().to_path_buf()])
                        .filter_egress(vec!["example.com".to_string()]);
                    let js = "const r = await fetch('https://example.com'); \
                              process.stdout.write(String(r.status));";
                    let argv = filtered_wrap(
                        &policy,
                        "bun",
                        &["-e".to_string(), js.to_string()],
                        None,
                        proxy.addr(),
                    )
                    .expect("filtered_wrap builds the composition on Linux");
                    // HOME → the writable worktree so bun's cache doesn't hit the
                    // read-only host HOME.
                    let out = Command::new(&argv[0])
                        .args(&argv[1..])
                        .env("HOME", tmp.path())
                        .output()
                        .unwrap();
                    let body = String::from_utf8_lossy(&out.stdout);
                    if body.contains("200") {
                        Ok(())
                    } else {
                        Err(format!(
                            "bun in the sandbox gave stdout={body:?} stderr={:?}",
                            String::from_utf8_lossy(&out.stderr)
                        ))
                    }
                },
            );
        } else {
            eprintln!("skip (g): bun not on PATH — agent-runtime functional check not run");
        }
    }
}
