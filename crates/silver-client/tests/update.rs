//! `--check-release` asks a releases page over TLS and reads the answer.

use std::io::Write;
use std::net::SocketAddr;

use axum::Router;
use axum::routing::get;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use silver_client::ConnectOptions;
use silver_client::update::latest_release;

/// A stand-in for the releases API behind TLS with a self-signed
/// certificate for `localhost`; returns the port and the certificate.
async fn start_releases_page(answer: &'static str) -> (u16, tempfile::NamedTempFile) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.signing_key.serialize_pem();
    let config = RustlsConfig::from_pem(cert_pem.clone().into_bytes(), key_pem.into_bytes())
        .await
        .unwrap();
    let router = Router::new()
        .route(
            "/repos/a/b/releases/latest",
            get(move || async move { answer }),
        )
        .route(
            "/gone",
            get(|| async { (axum::http::StatusCode::NOT_FOUND, "{}") }),
        );
    let handle = Handle::new();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
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

#[tokio::test]
async fn the_newest_release_is_read_over_verified_tls() {
    let (port, ca) =
        start_releases_page(r#"{"tag_name":"v9.9.9","html_url":"https://example/r/v9.9.9"}"#).await;
    let trusted = ConnectOptions {
        extra_ca_certs: vec![ca.path().to_path_buf()],
        ..Default::default()
    };
    let url = format!("https://localhost:{port}/repos/a/b/releases/latest");
    let release = latest_release(&url, &trusted).await.unwrap();
    assert_eq!(release.tag, "v9.9.9");
    assert_eq!(release.version(), "9.9.9");
    assert_eq!(release.url, "https://example/r/v9.9.9");

    // An untrusted certificate is refused before any request is sent.
    let err = latest_release(&url, &ConnectOptions::default())
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").to_lowercase().contains("certificate"),
        "{err:#}"
    );

    // A pin meant for the relay does not get in the way here.
    let pinned = ConnectOptions {
        pins: vec![silver_client::Pin::parse(&"11".repeat(32)).unwrap()],
        ..trusted.clone()
    };
    assert_eq!(latest_release(&url, &pinned).await.unwrap().tag, "v9.9.9");

    // A page that is not there is an error that says so.
    let err = latest_release(&format!("https://localhost:{port}/gone"), &trusted)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("404"), "{err}");
}
