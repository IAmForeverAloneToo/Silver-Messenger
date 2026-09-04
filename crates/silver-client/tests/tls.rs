//! The client speaks wss:// to a TLS-terminated relay and verifies its certificate.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use silver_client::{Client, ClientEvent, ConnectOptions, Pin};
use silver_protocol::Identity;
use silver_relay::RelayState;
use tokio::sync::mpsc;

/// Start the relay behind TLS with a fresh self-signed certificate for
/// `localhost`. Returns the port, a PEM file holding the certificate, and
/// the pin of its key.
async fn start_tls_relay() -> (u16, tempfile::NamedTempFile, Pin) {
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
    let pin = Pin::of(certified.cert.der()).unwrap();
    (bound.port(), ca, pin)
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
    let (port, ca, _) = start_tls_relay().await;
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
    let (port, _ca, _) = start_tls_relay().await;
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

/// The reason the first disconnection gives.
async fn first_rejection(port: u16, options: ConnectOptions) -> String {
    let alice = Arc::new(Identity::generate());
    let (client, mut events) =
        Client::spawn(format!("wss://localhost:{port}/ws"), alice, options).unwrap();
    let ev = wait_for(&mut events, "rejection", |e| {
        matches!(e, ClientEvent::Disconnected { .. })
    })
    .await;
    client.shutdown().await;
    let ClientEvent::Disconnected { reason, .. } = ev else {
        unreachable!()
    };
    reason
}

#[tokio::test]
async fn a_pinned_relay_must_present_the_pinned_key() {
    let (port, ca, pin) = start_tls_relay().await;
    let other = Pin::parse(&"77".repeat(32)).unwrap();

    // The right pin, with the chain trusted, connects; an extra unrelated
    // pin in the list does no harm.
    let alice = Arc::new(Identity::generate());
    let options = ConnectOptions {
        extra_ca_certs: vec![ca.path().to_path_buf()],
        pins: vec![other, pin],
        ..Default::default()
    };
    let (client, mut events) =
        Client::spawn(format!("wss://localhost:{port}/ws"), alice.clone(), options).unwrap();
    wait_for(&mut events, "connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    client.shutdown().await;

    // A wrong pin is refused even though the chain is trusted, and the
    // message says what key was seen.
    let reason = first_rejection(
        port,
        ConnectOptions {
            extra_ca_certs: vec![ca.path().to_path_buf()],
            pins: vec![other],
            ..Default::default()
        },
    )
    .await;
    assert!(reason.contains("pin mismatch"), "{reason}");
    assert!(reason.contains(&pin.to_hex()), "{reason}");

    // A pin does not replace chain validation: the right pin with an
    // untrusted chain is still refused.
    let reason = first_rejection(
        port,
        ConnectOptions {
            pins: vec![pin],
            ..Default::default()
        },
    )
    .await;
    assert!(reason.to_lowercase().contains("certificate"), "{reason}");
    assert!(!reason.contains("pin mismatch"), "{reason}");
}

#[tokio::test]
async fn observing_a_relay_reports_its_pin_and_trust() {
    let (port, ca, pin) = start_tls_relay().await;
    let url = format!("wss://localhost:{port}/ws");
    let seen = silver_client::observe_relay(&url, &ConnectOptions::default())
        .await
        .unwrap();
    assert_eq!(seen.pins, vec![pin]);
    assert!(seen.trusted.is_err(), "self-signed, not trusted by default");

    let seen = silver_client::observe_relay(
        &url,
        &ConnectOptions {
            extra_ca_certs: vec![ca.path().to_path_buf()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(seen.pins, vec![pin]);
    assert_eq!(seen.trusted, Ok(()));

    let err = silver_client::observe_relay(
        &format!("ws://localhost:{port}/ws"),
        &ConnectOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("wss://"), "{err}");
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
