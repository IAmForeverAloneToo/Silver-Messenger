//! The client speaks wss:// to a TLS-terminated relay and verifies its certificate.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use silver_client::{Client, ClientEvent, ConnectOptions};
use silver_protocol::Identity;
use silver_relay::RelayState;
use tokio::sync::mpsc;

/// Start the relay behind TLS with a fresh self-signed certificate for
/// `localhost`. Returns the port and a PEM file holding the certificate.
async fn start_tls_relay() -> (u16, tempfile::NamedTempFile) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.signing_key.serialize_pem();
    let config = RustlsConfig::from_pem(cert_pem.clone().into_bytes(), key_pem.into_bytes())
        .await
        .unwrap();

    let handle = Handle::new();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let router = silver_relay::router(RelayState::new());
    tokio::spawn(
        axum_server::bind_rustls(addr, config)
            .handle(handle.clone())
            .serve(router.into_make_service()),
    );
    let bound = handle.listening().await.expect("server bound");

    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(cert_pem.as_bytes()).unwrap();
    (bound.port(), ca)
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
async fn wss_with_a_trusted_ca_connects() {
    let (port, ca) = start_tls_relay().await;
    let alice = Arc::new(Identity::generate());
    let options = ConnectOptions {
        extra_ca_certs: vec![ca.path().to_path_buf()],
        ..Default::default()
    };
    let (client, mut events) =
        Client::spawn(format!("wss://localhost:{port}/ws"), alice.clone(), options).unwrap();
    wait_for(&mut events, "connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    assert!(client.lookup(alice.user_id()).await.unwrap().is_some());
    client.shutdown().await;
}

#[tokio::test]
async fn wss_with_an_unknown_ca_is_rejected() {
    let (port, _ca) = start_tls_relay().await;
    let alice = Arc::new(Identity::generate());
    let (client, mut events) = Client::spawn(
        format!("wss://localhost:{port}/ws"),
        alice,
        ConnectOptions::default(),
    )
    .unwrap();
    let ev = wait_for(&mut events, "rejection", |e| {
        matches!(e, ClientEvent::Disconnected { .. })
    })
    .await;
    let ClientEvent::Disconnected { reason, .. } = ev else {
        unreachable!()
    };
    assert!(
        reason.to_lowercase().contains("certificate"),
        "unexpected reason: {reason}"
    );
    client.shutdown().await;
}

#[test]
fn unreadable_ca_file_is_an_error_up_front() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let options = ConnectOptions {
        extra_ca_certs: vec!["/nonexistent/ca.pem".into()],
        ..Default::default()
    };
    let result = Client::spawn(
        "wss://localhost:1/ws".into(),
        Arc::new(Identity::generate()),
        options,
    );
    assert!(result.is_err());
}
