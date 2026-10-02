//! Many streams over one pinned tunnel (DR-0232).
//!
//! Each client holds an independent pinned crossing. A client that opens several
//! local connections — the phone's WebView, which keeps an event stream open
//! beside its calls — carries those as yamux streams inside its own crossing.
//! Other clients have separate pairs; their TLS and stream state never mix.
//!
//! The two ends agree on this in the TLS handshake, by ALPN: a client that can
//! multiplex offers [`MUX_ALPN`], and a Home that can answers with it. Anything
//! else is the one-connection crossing it always was, in both directions — the
//! browser tunnel offers nothing, an older phone offers nothing, and an older
//! Home answers nothing.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::wire::other;

/// The ALPN identifier a multiplexing client offers and a multiplexing Home
/// selects.
pub const MUX_ALPN: &[u8] = b"gw-mux/1";

/// How long a hung-up crossing may take to deliver what it already answered.
const HANG_UP_FLUSH: std::time::Duration = std::time::Duration::from_secs(5);

/// Streams one crossing may carry at once. A phone opens a handful; this bounds
/// what a misbehaving one can make the Home hold open locally.
const MAX_STREAMS: usize = 64;

fn config() -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(MAX_STREAMS);
    config
}

fn broken(error: yamux::ConnectionError) -> std::io::Error {
    other(format!("multiplexed tunnel: {error}"))
}

/// One carried stream, as tokio I/O.
pub type MuxStream = Compat<yamux::Stream>;

/// The Home's half: serve every stream the client opens on `tunnel` by copying
/// it to `local`, each on its own connection, until the tunnel ends.
pub(crate) async fn serve_streams<T>(tunnel: T, local: SocketAddr) -> std::io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = yamux::Connection::new(tunnel.compat(), config(), yamux::Mode::Server);
    // A stream whose caller the router refused before verifying ends the whole
    // crossing, not only itself: otherwise a stranger who negotiated streams
    // could hold the crossing by opening one refused stream after another.
    let (hang_up, mut hung_up) = mpsc::channel::<()>(1);
    loop {
        let next = tokio::select! {
            next = poll_fn(|cx| connection.poll_next_inbound(cx)) => next,
            _ = hung_up.recv() => {
                // Closed, not dropped: the refusal that asked for this is still
                // queued in the connection, and dropping it would discard the
                // answer along with the crossing.
                let _ = timeout(HANG_UP_FLUSH, poll_fn(|cx| connection.poll_close(cx))).await;
                return Ok(());
            }
        };
        let Some(stream) = next.transpose().map_err(broken)? else {
            return Ok(());
        };
        let hang_up = hang_up.clone();
        tokio::spawn(async move {
            // A stream the router will not take ends here; the others go on.
            let Ok(local) = TcpStream::connect(local).await else {
                return;
            };
            let registered = crate::native::CrossingConnection::register(&local);
            let _ = crate::native::carry_until_home_closes(stream.compat(), local).await;
            if registered.hang_up_requested() {
                let _ = hang_up.try_send(());
            }
        });
    }
}

type Opened = oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>;

/// The client's half: a handle that opens streams on one tunnel.
///
/// The tunnel is driven by a task of its own, which ends when the tunnel does —
/// the Home ending an idle crossing, the relay closing a leg — or when every
/// handle has been dropped, which hangs the tunnel up rather than leaving the
/// Home spliced to a client that has gone.
#[derive(Clone)]
pub struct MuxClient {
    opens: mpsc::Sender<Opened>,
}

impl MuxClient {
    /// Start carrying streams over `tunnel`, which must have negotiated
    /// [`MUX_ALPN`].
    pub fn start<T>(tunnel: T) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (opens, requests) = mpsc::channel(16);
        let connection = yamux::Connection::new(tunnel.compat(), config(), yamux::Mode::Client);
        tokio::spawn(drive_client(connection, requests));
        Self { opens }
    }

    /// Whether the tunnel under this handle has ended. A closed handle opens
    /// nothing; the caller establishes a new tunnel.
    pub fn is_closed(&self) -> bool {
        self.opens.is_closed()
    }

    /// Open one stream to the Home.
    pub async fn open(&self) -> std::io::Result<MuxStream> {
        let (opened, stream) = oneshot::channel();
        let closed = || other("the multiplexed tunnel closed".to_owned());
        self.opens.send(opened).await.map_err(|_| closed())?;
        let stream = stream.await.map_err(|_| closed())?.map_err(broken)?;
        Ok(stream.compat())
    }
}

/// Drive the client's connection: open the streams asked for, and keep reading
/// frames so the streams already open make progress. A client accepts no
/// streams from the Home; one the Home opens is dropped.
async fn drive_client<T>(
    mut connection: yamux::Connection<Compat<T>>,
    mut requests: mpsc::Receiver<Opened>,
) where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut waiting: VecDeque<Opened> = VecDeque::new();
    let mut abandoned = false;
    let hung_up = poll_fn(|cx| {
        if !abandoned {
            loop {
                match requests.poll_recv(cx) {
                    Poll::Ready(Some(request)) => waiting.push_back(request),
                    Poll::Ready(None) => {
                        abandoned = true;
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }
        if abandoned && waiting.is_empty() {
            return Poll::Ready(true);
        }
        while !waiting.is_empty() {
            match connection.poll_new_outbound(cx) {
                Poll::Ready(result) => {
                    if let Some(request) = waiting.pop_front() {
                        let _ = request.send(result);
                    }
                }
                Poll::Pending => break,
            }
        }
        loop {
            match connection.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(unasked))) => drop(unasked),
                Poll::Ready(Some(Err(_)) | None) => return Poll::Ready(false),
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await;
    if hung_up {
        let _ = poll_fn(|cx| connection.poll_close(cx)).await;
    }
}
