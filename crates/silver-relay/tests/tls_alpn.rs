//! The relay's TLS listener: a normal client gets the current certificate,
//! an ACME validator that announces `acme-tls/1` gets the challenge
//! certificate for the name it asks for and nothing for any other name,
//! and the certificate can be swapped while connections keep coming.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use silver_relay::RelayState;
use silver_relay::tls::{self, CertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Accepts any certificate: these tests look at what was presented, not
/// whether it chains anywhere.
#[derive(Debug)]
struct Anything;

impl ServerCertVerifier for Anything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn self_signed(name: &str) -> rustls::sign::CertifiedKey {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    tls::certified(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap()
}

async fn start(store: Arc<CertStore>) -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = tls::server_config(store).unwrap();
    tokio::spawn(tls::serve_tls(
        listener,
        config,
        RelayState::new(),
        std::future::pending(),
    ));
    addr
}

/// Handshake with `addr` as `server_name`, offering `alpn`; the leaf
/// certificate presented, or the handshake error.
async fn presented(
    addr: SocketAddr,
    server_name: &str,
    alpn: &[&[u8]],
) -> Result<CertificateDer<'static>, String> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Anything))
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let name = ServerName::try_from(server_name.to_owned()).unwrap();
    let tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let (_, connection) = tls.get_ref();
    let leaf = connection
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or("no certificate")?;
    Ok(leaf.clone().into_owned())
}

#[tokio::test]
async fn a_validator_gets_the_challenge_certificate_and_everyone_else_the_real_one() {
    let store = CertStore::new();
    store.set_current(self_signed("relay.example"));
    let addr = start(store.clone()).await;

    // Nobody is being validated yet: the ALPN offer changes nothing.
    let plain = presented(addr, "relay.example", &[]).await.unwrap();
    assert_eq!(tls::dns_names(&plain), vec!["relay.example"]);
    let http = presented(addr, "relay.example", &[b"h2", b"http/1.1"])
        .await
        .unwrap();
    assert_eq!(tls::dns_names(&http), vec!["relay.example"]);
    assert!(
        presented(addr, "relay.example", &[tls::ACME_TLS_ALPN])
            .await
            .is_err(),
        "a validator with no challenge pending must get nothing"
    );

    // During validation the challenge certificate goes to the validator
    // for that name only; clients still see the real one.
    let digest = [0x42u8; 32];
    store.set_challenge(
        "relay.example",
        tls::challenge_certificate("relay.example", &digest).unwrap(),
    );
    let challenge = presented(addr, "RELAY.example", &[tls::ACME_TLS_ALPN])
        .await
        .unwrap();
    assert_eq!(tls::dns_names(&challenge), vec!["relay.example"]);
    assert_ne!(challenge, plain);
    assert!(
        presented(addr, "other.example", &[tls::ACME_TLS_ALPN])
            .await
            .is_err()
    );
    assert_eq!(presented(addr, "relay.example", &[]).await.unwrap(), plain);
    store.clear_challenge("relay.example");
    assert!(
        presented(addr, "relay.example", &[tls::ACME_TLS_ALPN])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_certificate_can_be_replaced_under_a_running_listener() {
    let store = CertStore::new();
    let addr = start(store.clone()).await;
    // No certificate yet: a handshake fails rather than hanging.
    let err = presented(addr, "relay.example", &[]).await.unwrap_err();
    assert!(!err.is_empty());

    store.set_current(self_signed("first.example"));
    assert_eq!(
        tls::dns_names(&presented(addr, "first.example", &[]).await.unwrap()),
        vec!["first.example"]
    );
    store.set_current(self_signed("second.example"));
    assert_eq!(
        tls::dns_names(&presented(addr, "second.example", &[]).await.unwrap()),
        vec!["second.example"]
    );

    // The HTTP side is the same router the plain listener serves.
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Anything))
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("second.example").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(b"GET /healthz HTTP/1.0\r\nHost: second.example\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut response))
        .await
        .unwrap()
        .ok();
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.0 200") || text.starts_with("HTTP/1.1 200"),
        "{text}"
    );
    assert!(text.ends_with("ok"), "{text}");
}
