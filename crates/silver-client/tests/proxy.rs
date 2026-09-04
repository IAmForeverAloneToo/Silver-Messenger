//! The client reaches the relay through an HTTP CONNECT proxy.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use silver_client::{Client, ClientEvent, ConnectOptions};
use silver_protocol::Identity;
use silver_relay::RelayState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

async fn start_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(silver_relay::serve(
        listener,
        RelayState::new(),
        std::future::pending(),
    ));
    format!("ws://{addr}/ws")
}

/// A minimal CONNECT proxy. Records every request line it sees; if `allow`
/// is false it answers 403 instead of tunnelling.
async fn start_proxy(allow: bool) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let log = log.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let request_line = head.lines().next().unwrap_or_default().to_owned();
                log.lock().unwrap().push(request_line.clone());
                if !allow {
                    let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                    return;
                }
                let target = request_line.split_whitespace().nth(1).unwrap().to_owned();
                let mut upstream = TcpStream::connect(&target).await.unwrap();
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (url, seen)
}

async fn wait_for(
    rx: &mut mpsc::Receiver<ClientEvent>,
    what: &str,
    mut pred: impl FnMut(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .unwrap_or_else(|| panic!("client stopped while waiting for {what}"));
        if pred(&ev) {
            return ev;
        }
    }
}

#[tokio::test]
async fn connects_through_a_connect_proxy() {
    let relay_url = start_relay().await;
    let (proxy_url, seen) = start_proxy(true).await;
    let alice = Arc::new(Identity::generate());
    let options = ConnectOptions {
        extra_ca_certs: vec![],
        proxy: Some(proxy_url),
    };
    let (client, mut events) = Client::spawn(relay_url.clone(), alice.clone(), options).unwrap();
    wait_for(&mut events, "connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    assert!(client.lookup(alice.user_id()).await.unwrap().is_some());

    let relay_host_port = relay_url
        .trim_start_matches("ws://")
        .trim_end_matches("/ws")
        .to_owned();
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen, vec![format!("CONNECT {relay_host_port} HTTP/1.1")]);
    client.shutdown().await;
}

#[tokio::test]
async fn a_refusing_proxy_is_reported() {
    let relay_url = start_relay().await;
    let (proxy_url, _) = start_proxy(false).await;
    let options = ConnectOptions {
        extra_ca_certs: vec![],
        proxy: Some(proxy_url),
    };
    let (client, mut events) =
        Client::spawn(relay_url, Arc::new(Identity::generate()), options).unwrap();
    let ev = wait_for(&mut events, "refusal", |e| {
        matches!(e, ClientEvent::Disconnected { .. })
    })
    .await;
    let ClientEvent::Disconnected { reason, .. } = ev else {
        unreachable!()
    };
    assert!(reason.contains("proxy refused CONNECT"), "{reason}");
    assert!(reason.contains("403"), "{reason}");
    client.shutdown().await;
}
