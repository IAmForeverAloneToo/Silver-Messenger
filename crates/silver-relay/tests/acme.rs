//! The whole ACME flow against Pebble, Let's Encrypt's test server: the
//! relay creates an account, answers the TLS-ALPN-01 challenge on its own
//! listener, gets a certificate chaining to Pebble's root, serves it, and
//! keeps the account, key and chain in its cache.
//!
//! Runs only when `SILVER_PEBBLE` names the `pebble` binary (CI installs
//! it with `go install github.com/letsencrypt/pebble/v2/cmd/pebble`);
//! without it the test says so and passes, so a developer without Go
//! loses nothing but this check.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use silver_relay::RelayState;
use silver_relay::acme::{self, AcmeConfig};
use silver_relay::tls::{self, CertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A CA and a `localhost` certificate for Pebble's own HTTPS listeners.
fn pebble_tls(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "pebble test root");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let cert = params.signed_by(&key, &issuer).unwrap();

    let ca_path = dir.join("pebble-ca.pem");
    let cert_path = dir.join("pebble-cert.pem");
    let key_path = dir.join("pebble-key.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (ca_path, cert_path, key_path)
}

fn root_store(pem_paths: &[&Path]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for path in pem_paths {
        for cert in CertificateDer::pem_file_iter(path).unwrap() {
            roots.add(cert.unwrap()).unwrap();
        }
    }
    roots
}

/// `GET path` over TLS to `addr` as `server_name`, trusting `roots`.
async fn https_get(
    addr: SocketAddr,
    server_name: &str,
    roots: RootCertStore,
    path: &str,
) -> anyhow::Result<(String, Vec<CertificateDer<'static>>)> {
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await?;
    let mut tls = connector
        .connect(ServerName::try_from(server_name.to_owned())?, tcp)
        .await?;
    let chain: Vec<CertificateDer<'static>> = tls
        .get_ref()
        .1
        .peer_certificates()
        .map(|c| c.iter().map(|c| c.clone().into_owned()).collect())
        .unwrap_or_default();
    // Pebble, like Let's Encrypt, refuses requests without a User-Agent.
    tls.write_all(
        format!(
            "GET {path} HTTP/1.0\r\nHost: {server_name}\r\nUser-Agent: silver-relay-test\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await?;
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut response)).await;
    let text = String::from_utf8_lossy(&response).into_owned();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((body, chain))
}

#[tokio::test]
async fn a_certificate_is_obtained_from_pebble_and_served() {
    let Some(pebble) = std::env::var_os("SILVER_PEBBLE") else {
        eprintln!("SILVER_PEBBLE is not set; skipping the ACME test");
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (ca, cert, key) = pebble_tls(dir.path());

    // Pebble validates TLS-ALPN-01 by connecting to <name>:tlsPort, so the
    // relay's listener is the port Pebble is told about.
    let relay_port = free_port();
    let dir_port = free_port();
    let mgmt_port = free_port();
    let config = format!(
        r#"{{"pebble": {{"listenAddress": "127.0.0.1:{dir_port}", "managementListenAddress": "127.0.0.1:{mgmt_port}", "certificate": "{}", "privateKey": "{}", "httpPort": 5002, "tlsPort": {relay_port}, "ocspResponderURL": "", "externalAccountBindingRequired": false}}}}"#,
        cert.display(),
        key.display()
    );
    let config_path = dir.path().join("pebble.json");
    std::fs::write(&config_path, config).unwrap();
    let mut child = tokio::process::Command::new(pebble)
        .arg("-config")
        .arg(&config_path)
        .arg("-strict")
        .env("PEBBLE_VA_NOSLEEP", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("SILVER_PEBBLE names a runnable pebble binary");

    // Wait for the directory.
    let dir_addr: SocketAddr = format!("127.0.0.1:{dir_port}").parse().unwrap();
    let started = Instant::now();
    loop {
        let last = match https_get(dir_addr, "localhost", root_store(&[&ca]), "/dir").await {
            Ok((body, _)) if body.contains("newOrder") => break,
            Ok((body, _)) => format!("directory without newOrder: {body}"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "pebble did not come up; last attempt: {last}"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "pebble exited before serving its directory"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // The relay: listener first, then the ACME task that fills the store.
    let store = CertStore::new();
    let listener = TcpListener::bind(("127.0.0.1", relay_port)).unwrap();
    tokio::spawn(tls::serve_tls(
        listener,
        tls::server_config(store.clone()).unwrap(),
        RelayState::new(),
        std::future::pending(),
    ));
    let cache = dir.path().join("acme");
    tokio::spawn(acme::run(
        AcmeConfig {
            domains: vec!["localhost".to_owned()],
            directory: format!("https://localhost:{dir_port}/dir"),
            contact: Some("relay@example.org".to_owned()),
            cache: cache.clone(),
            root: Some(ca.clone()),
        },
        store.clone(),
    ));
    let started = Instant::now();
    while !store.has_certificate() {
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "no certificate after 90 s"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // What the relay serves chains to Pebble's root and names localhost.
    let mgmt_addr: SocketAddr = format!("127.0.0.1:{mgmt_port}").parse().unwrap();
    let (root_pem, _) = https_get(mgmt_addr, "localhost", root_store(&[&ca]), "/roots/0")
        .await
        .unwrap();
    let root_path = dir.path().join("issuer-root.pem");
    std::fs::write(&root_path, &root_pem).unwrap();
    let relay_addr: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();
    let (body, chain) = https_get(
        relay_addr,
        "localhost",
        root_store(&[&root_path]),
        "/healthz",
    )
    .await
    .expect("the relay's certificate verifies against the issuing root");
    assert_eq!(body, "ok");
    assert!(
        chain.len() >= 2,
        "leaf and intermediate expected, got {}",
        chain.len()
    );
    assert_eq!(tls::dns_names(&chain[0]), vec!["localhost"]);
    assert!(tls::not_after(&chain[0]).unwrap() > std::time::SystemTime::now());

    // The cache holds what a restart needs, for the relay's user only.
    for name in ["account.json", "key.pem", "chain.pem"] {
        let path = cache.join(name);
        assert!(path.exists(), "{name} missing from the cache");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600,
                "{name}"
            );
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    // The served chain is the cached one, under the cached key.
    let cached: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(cache.join("chain.pem"))
            .unwrap()
            .map(|c| c.unwrap())
            .collect();
    assert_eq!(cached[0], chain[0]);
    let cached_key =
        rcgen::KeyPair::from_pem(&std::fs::read_to_string(cache.join("key.pem")).unwrap()).unwrap();
    assert!(
        tls::certified(
            cached.clone(),
            rustls_pki_types::PrivateKeyDer::Pkcs8(cached_key.serialize_der().into())
        )
        .is_ok()
    );
    child.kill().await.ok();
}
