//! TLS inside the relay: a certificate store the rustls server asks on
//! every handshake, so that the certificate can be replaced while the
//! relay runs (a renewal, or a file the operator changed) and the ACME
//! TLS-ALPN-01 challenge can be answered on the same port that serves
//! clients.
//!
//! The store holds one *current* certificate for the relay's names and,
//! while a certificate is being requested, one *challenge* certificate per
//! name. A validation server announces itself with the ALPN protocol
//! `acme-tls/1` (RFC 8737) and gets the challenge certificate for the name
//! it asked for; everyone else gets the current one. Nothing else changes:
//! axum-server terminates TLS and hands the connection to the same router
//! the plain listener uses, so the client address is the socket's peer and
//! no `X-Forwarded-For` is involved.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{error, info};

use crate::RelayState;

/// ALPN protocol name of the TLS-ALPN-01 challenge (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// How often certificate files given on the command line are checked for
/// a change.
pub const FILE_CHECK_EVERY: Duration = Duration::from_secs(60);

/// The certificates a running relay presents.
#[derive(Default)]
pub struct CertStore {
    current: RwLock<Option<Arc<CertifiedKey>>>,
    /// Challenge certificates by lower-case name, while an ACME order is
    /// being validated.
    challenges: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Attempts to obtain or renew a certificate that failed, for the
    /// metrics.
    acme_failures: std::sync::atomic::AtomicU64,
}

impl CertStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn note_acme_failure(&self) {
        self.acme_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn acme_failures(&self) -> u64 {
        self.acme_failures
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Present `key` to every client from now on.
    pub fn set_current(&self, key: CertifiedKey) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(key));
    }

    pub fn current(&self) -> Option<Arc<CertifiedKey>> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn has_certificate(&self) -> bool {
        self.current().is_some()
    }

    /// Answer the TLS-ALPN-01 challenge for `name` with `key` until
    /// [`clear_challenge`](Self::clear_challenge).
    pub fn set_challenge(&self, name: &str, key: CertifiedKey) {
        self.challenges
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.to_ascii_lowercase(), Arc::new(key));
    }

    pub fn clear_challenge(&self, name: &str) {
        self.challenges
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&name.to_ascii_lowercase());
    }
}

impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertStore")
            .field("has_certificate", &self.has_certificate())
            .field(
                "challenges",
                &self
                    .challenges
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .len(),
            )
            .finish()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let validating = hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN));
        if validating {
            // RFC 8737: the challenge certificate for the name asked for and
            // nothing else; a validator naming another host, or none, is
            // refused rather than shown the real certificate.
            let name = hello.server_name()?.to_ascii_lowercase();
            return self
                .challenges
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&name)
                .cloned();
        }
        self.current()
    }
}

/// A rustls server configuration that asks `store` for its certificate.
pub fn server_config(store: Arc<CertStore>) -> anyhow::Result<Arc<ServerConfig>> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions")?
            .with_no_client_auth()
            .with_cert_resolver(store);
    // A validator offers only acme-tls/1; an HTTP client that offers ALPN
    // gets HTTP/1.1, which is what the router speaks; a client that offers
    // nothing negotiates nothing, which is fine too.
    config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A certificate chain and its private key, checked to belong together.
pub fn certified(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<CertifiedKey> {
    let certified = certified_unchecked(certs, key)?;
    certified
        .keys_match()
        .context("the certificate does not belong to the private key")?;
    Ok(certified)
}

/// The same without the match check, which parses the certificate the
/// way a verifier would and so refuses one with an unknown critical
/// extension, as the ACME challenge certificate has.
fn certified_unchecked(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<CertifiedKey> {
    if certs.is_empty() {
        bail!("no certificate");
    }
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .context("the private key is of a kind the relay cannot use")?;
    Ok(CertifiedKey::new(certs, signing))
}

/// Read a PEM certificate chain and a PEM private key from files.
pub fn load_pem(cert_path: &Path, key_path: &Path) -> anyhow::Result<CertifiedKey> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("{} is not a PEM certificate chain", cert_path.display()))?;
    if certs.is_empty() {
        bail!("{} holds no certificate", cert_path.display());
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("{} is not a PEM private key", key_path.display()))?;
    certified(certs, key)
}

fn parse<'a>(
    cert: &'a CertificateDer<'_>,
) -> anyhow::Result<x509_parser::certificate::X509Certificate<'a>> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("the certificate is not valid X.509")?;
    Ok(parsed)
}

fn system_time(seconds: i64) -> anyhow::Result<SystemTime> {
    let seconds = u64::try_from(seconds).context("a certificate date before 1970")?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

/// When `cert` starts being valid.
pub fn not_before(cert: &CertificateDer<'_>) -> anyhow::Result<SystemTime> {
    system_time(parse(cert)?.validity().not_before.timestamp())
}

/// When `cert` stops being valid.
pub fn not_after(cert: &CertificateDer<'_>) -> anyhow::Result<SystemTime> {
    system_time(parse(cert)?.validity().not_after.timestamp())
}

/// The DNS names `cert` is for, for logs.
pub fn dns_names(cert: &CertificateDer<'_>) -> Vec<String> {
    use x509_parser::extensions::GeneralName;
    parse(cert)
        .ok()
        .and_then(|c| {
            c.subject_alternative_name().ok().flatten().map(|ext| {
                ext.value
                    .general_names
                    .iter()
                    .filter_map(|n| match n {
                        GeneralName::DNSName(name) => Some((*name).to_owned()),
                        _ => None,
                    })
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// The self-signed certificate that answers a TLS-ALPN-01 challenge for
/// `name`: its only name is `name`, and it carries the SHA-256 digest of
/// the key authorization in the critical `acmeIdentifier` extension
/// (RFC 8737 section 3).
pub fn challenge_certificate(name: &str, digest: &[u8]) -> anyhow::Result<CertifiedKey> {
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()])
        .context("the name is not a valid certificate subject")?;
    params
        .custom_extensions
        .push(rcgen::CustomExtension::new_acme_identifier(digest));
    let key = rcgen::KeyPair::generate().context("generating the challenge key")?;
    let cert = params
        .self_signed(&key)
        .context("signing the challenge certificate")?;
    // The key was made here for this certificate; no match check needed,
    // and none possible (see `certified_unchecked`).
    certified_unchecked(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
}

fn modified(cert: &Path, key: &Path) -> (Option<SystemTime>, Option<SystemTime>) {
    let stamp = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    (stamp(cert), stamp(key))
}

/// Re-read the certificate files whenever either changes on disk, so a
/// renewal written by certbot or a colleague's script takes effect without
/// a restart. A file that fails to load leaves the previous certificate in
/// place and is reported.
pub async fn watch_files(store: Arc<CertStore>, cert: PathBuf, key: PathBuf, every: Duration) {
    let mut last = modified(&cert, &key);
    loop {
        tokio::time::sleep(every).await;
        let now = modified(&cert, &key);
        if now == last {
            continue;
        }
        last = now;
        match load_pem(&cert, &key) {
            Ok(certified) => {
                info!(
                    "certificate files changed; now serving a certificate for {} until {}",
                    dns_names(&certified.cert[0]).join(", "),
                    expiry_text(&certified.cert[0])
                );
                store.set_current(certified);
            }
            Err(e) => error!(
                "certificate files changed but cannot be used, keeping the previous certificate: {e:#}"
            ),
        }
    }
}

/// `2026-09-04` for a certificate's expiry, or `unknown`.
pub fn expiry_text(cert: &CertificateDer<'_>) -> String {
    match not_after(cert) {
        Ok(when) => {
            let secs = when
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Civil date from days since the epoch (Howard Hinnant's
            // algorithm), enough for a log line.
            let days = (secs / 86_400) as i64;
            let z = days + 719_468;
            let era = z.div_euclid(146_097);
            let doe = z.rem_euclid(146_097);
            let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            let y = yoe + era * 400 + i64::from(m <= 2);
            format!("{y:04}-{m:02}-{d:02}")
        }
        Err(_) => "unknown".into(),
    }
}

/// Serve the relay over TLS until `shutdown` resolves.
pub async fn serve_tls(
    listener: std::net::TcpListener,
    config: Arc<ServerConfig>,
    state: Arc<RelayState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    listener.set_nonblocking(true)?;
    let handle = Handle::new();
    let stop = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        stop.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    axum_server::from_tcp_rustls(listener, RustlsConfig::from_config(config))?
        .handle(handle)
        .serve(crate::router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(name: &str) -> (CertifiedKey, String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certified = certified(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
        (certified, cert.pem(), key.serialize_pem())
    }

    #[test]
    fn a_challenge_certificate_names_the_host_and_carries_the_digest() {
        let digest = [7u8; 32];
        let certified = challenge_certificate("Relay.Example", &digest).unwrap();
        let leaf = &certified.cert[0];
        assert_eq!(dns_names(leaf), vec!["Relay.Example".to_owned()]);
        let parsed = parse(leaf).unwrap();
        let acme = parsed
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("acmeIdentifier extension");
        assert!(acme.critical);
        // The extension value is an OCTET STRING holding the digest.
        assert_eq!(&acme.value[2..], &digest);
        assert!(not_after(leaf).unwrap() > SystemTime::now());
        assert_ne!(expiry_text(leaf), "unknown");
    }

    #[test]
    fn files_load_and_a_mismatched_pair_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cert_pem, key_pem) = self_signed("localhost");
        let (_, _, other_key) = self_signed("localhost");
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, &cert_pem).unwrap();
        std::fs::write(&key, &key_pem).unwrap();
        let loaded = load_pem(&cert, &key).unwrap();
        assert_eq!(dns_names(&loaded.cert[0]), vec!["localhost".to_owned()]);

        std::fs::write(&key, &other_key).unwrap();
        let err = load_pem(&cert, &key).unwrap_err();
        assert!(err.to_string().contains("does not belong"), "{err:#}");
        std::fs::write(&cert, "not a certificate").unwrap();
        assert!(load_pem(&cert, &key).is_err());
        assert!(load_pem(&dir.path().join("missing.pem"), &key).is_err());
    }

    #[test]
    fn the_store_swaps_certificates_and_clears_challenges() {
        let store = CertStore::new();
        assert!(!store.has_certificate());
        let (first, _, _) = self_signed("a.example");
        store.set_current(first);
        assert_eq!(
            dns_names(&store.current().unwrap().cert[0]),
            vec!["a.example"]
        );
        let (second, _, _) = self_signed("b.example");
        store.set_current(second);
        assert_eq!(
            dns_names(&store.current().unwrap().cert[0]),
            vec!["b.example"]
        );

        store.set_challenge(
            "B.Example",
            challenge_certificate("b.example", &[1; 32]).unwrap(),
        );
        assert_eq!(
            store
                .challenges
                .read()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["b.example"]
        );
        store.clear_challenge("b.example");
        assert!(store.challenges.read().unwrap().is_empty());
        assert!(format!("{store:?}").contains("has_certificate: true"));
    }

    #[tokio::test]
    async fn changed_files_are_picked_up_and_bad_ones_are_kept_out() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cert_pem, key_pem) = self_signed("first.example");
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, &cert_pem).unwrap();
        std::fs::write(&key, &key_pem).unwrap();
        let store = CertStore::new();
        store.set_current(load_pem(&cert, &key).unwrap());
        tokio::spawn(watch_files(
            store.clone(),
            cert.clone(),
            key.clone(),
            Duration::from_millis(20),
        ));

        // A broken write leaves the old certificate in place.
        tokio::time::sleep(Duration::from_millis(30)).await;
        std::fs::write(&cert, "garbage").unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            dns_names(&store.current().unwrap().cert[0]),
            vec!["first.example"]
        );
        // A good pair replaces it.
        let (_, cert2, key2) = self_signed("second.example");
        std::fs::write(&key, &key2).unwrap();
        std::fs::write(&cert, &cert2).unwrap();
        let mut swapped = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if dns_names(&store.current().unwrap().cert[0]) == ["second.example"] {
                swapped = true;
                break;
            }
        }
        assert!(swapped, "the new certificate was not picked up");
    }
}
