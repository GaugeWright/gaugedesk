use gaugedesk_relay_transport::test_relay;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let address = gaugedesk_env::var("TEST_RELAY_ADDR").unwrap_or_else(|| "127.0.0.1:7900".into());
    let listener = TcpListener::bind(&address).await?;
    eprintln!("[test-wss-relay] listening on ws://{address}");
    test_relay::serve(listener).await
}
