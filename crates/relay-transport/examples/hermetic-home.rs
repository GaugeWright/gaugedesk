//! The hermetic end of DESK-7's browser lane.
//!
//! Stands up everything a browser needs to be driven through the real journey —
//! resolve a project to its Home, tunnel to it, admit, and verify the Home is
//! the one the route named — with no cloud, no provisioned identity, and no
//! network beyond loopback:
//!
//!   * a blind WSS relay (`test_relay`),
//!   * a Home leg parked on it under a freshly generated TLS identity,
//!   * a stub behind that leg answering `POST /home/admissions`,
//!   * and a **config endpoint on a fixed port** describing all of it.
//!
//! The config endpoint is the part that is not obvious. `TestRelay::bind()`
//! takes an ephemeral port, and a `wasm-bindgen-test` binary is compiled before
//! this process exists, so it cannot be told the endpoint through the
//! environment. The browser fetches it instead, which is why this serves CORS.

use std::sync::Arc;

use gaugedesk_relay_transport::{
    serve_home_forever, test_relay::TestRelay, HomeRelayConfig, TlsIdentity,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The one fixed value in the harness, so the browser knows where to ask.
const CONFIG_ADDR: &str = "127.0.0.1:7908";

/// The Home this harness serves. The browser asserts the responding Home is
/// exactly this, which is the identity check the journey exists to prove.
const HOME_ID: &str = "home:hermetic";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let relay = TestRelay::bind().await?;
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = TlsIdentity::load_or_generate(directory.path())?;
    let config = HomeRelayConfig::load_or_mint(directory.path(), relay.endpoint())?;
    let route = config.relay_route(&identity)?;

    // Behind the pinned tunnel sits an ordinary HTTP responder — the smallest
    // thing that can answer the admission the pool performs.
    let stub = TcpListener::bind("127.0.0.1:0").await?;
    let stub_addr = stub.local_addr()?;
    tokio::spawn(serve_admissions(stub));

    let parked = route.clone();
    tokio::spawn(async move {
        if let Err(error) = serve_home_forever(parked, stub_addr, identity).await {
            eprintln!("[hermetic-home] the Home leg stopped: {error}");
        }
    });

    let body = format!(
        concat!(
            r#"{{"relay_endpoint":"{}","handle":"{}","proof":"{}","route_epoch":{},"#,
            r#""home_fingerprint":"{}","home_id":"{}"}}"#,
        ),
        route.endpoint,
        route.handle,
        route.proof.to_base64url(),
        route.epoch,
        hex::encode(route.home_fingerprint),
        HOME_ID,
    );
    eprintln!("[hermetic-home] config on http://{CONFIG_ADDR} — {body}");
    serve_config(TcpListener::bind(CONFIG_ADDR).await?, Arc::new(body)).await
}

/// Answer the one call the journey makes, as the Home the route names.
async fn serve_admissions(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            let body = if request.starts_with("POST /home/admissions") {
                format!(r#"{{"home":"{HOME_ID}","admission":"hermetic-admission"}}"#)
            } else {
                // Anything else is a mistake in the test, and saying so beats a
                // silent 200 that makes a broken journey look complete.
                r#"{"error":"the hermetic Home serves admissions only"}"#.to_owned()
            };
            let status = if request.starts_with("POST /home/admissions") { "201 Created" } else { "404 Not Found" };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len(),
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        });
    }
}

/// Serve the harness description to the test page. CORS is open because the
/// page is served from the test runner's own ephemeral origin.
async fn serve_config(listener: TcpListener, body: Arc<String>) -> std::io::Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let body = Arc::clone(&body);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            let _ = stream.read(&mut buffer).await;
            let response = format!(
                concat!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                    "access-control-allow-origin: *\r\ncontent-length: {}\r\n\r\n{}",
                ),
                body.len(),
                body,
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        });
    }
}
