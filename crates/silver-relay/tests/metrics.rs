//! The metrics endpoint over plain HTTP on its own listener: the text
//! format, the content type, and numbers that move when the relay does.

use std::sync::Arc;
use std::time::Duration;

use silver_relay::RelayState;
use silver_relay::metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn get_metrics(addr: std::net::SocketAddr) -> (String, String) {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8(response).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").expect("an HTTP response");
    (head.to_owned(), body.to_owned())
}

#[tokio::test]
async fn the_endpoint_serves_the_text_format_and_follows_the_relay() {
    let state = RelayState::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(metrics::serve(listener, state.clone(), None));

    let (head, body) = get_metrics(addr).await;
    assert!(
        head.starts_with("HTTP/1.0 200") || head.starts_with("HTTP/1.1 200"),
        "{head}"
    );
    assert!(
        head.to_lowercase()
            .contains(&format!("content-type: {}", metrics::CONTENT_TYPE_TEXT)),
        "{head}"
    );
    assert!(body.contains("silver_relay_auth_failures_total 0\n"));
    assert!(body.contains("silver_relay_identities 0\n"));

    // A refused login shows up on the next scrape, without its address.
    state.note_auth_failure("203.0.113.7".parse().unwrap());
    let (_, body) = get_metrics(addr).await;
    assert!(body.contains("silver_relay_auth_failures_total 1\n"));
    assert!(body.contains("silver_relay_auth_failure_addresses 1\n"));
    assert!(body.contains("silver_relay_auth_failures_max_per_address 1\n"));
    assert!(!body.contains("203.0.113.7"));

    // Only /metrics exists on this listener.
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).contains(" 404 "));
    drop(Arc::clone(&state));
}
