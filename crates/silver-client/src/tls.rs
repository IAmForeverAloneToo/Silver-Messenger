//! TLS configuration for `wss://` relays.
//!
//! The trust store is the operating system's certificate store plus Mozilla's
//! root bundle, so the client works both on machines whose organisation
//! inspects TLS with its own root and on minimal systems without a store.
//! Extra PEM files can be trusted for relays behind a private CA.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio_tungstenite::Connector;

/// Options controlling how the client reaches the relay.
#[derive(Clone, Debug, Default)]
pub struct ConnectOptions {
    /// PEM files whose certificates are trusted as additional roots.
    pub extra_ca_certs: Vec<PathBuf>,
    /// An HTTP CONNECT proxy URL to reach the relay through.
    pub proxy: Option<String>,
}

pub(crate) fn connector(options: &ConnectOptions) -> anyhow::Result<Connector> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let native = rustls_native_certs::load_native_certs();
    for err in &native.errors {
        tracing::debug!("native certificate store: {err}");
    }
    roots.add_parsable_certificates(native.certs);

    for path in &options.extra_ca_certs {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
            .with_context(|| format!("reading {}", path.display()))?
            .collect::<Result<_, _>>()
            .with_context(|| format!("parsing {}", path.display()))?;
        if certs.is_empty() {
            anyhow::bail!("no certificates found in {}", path.display());
        }
        for cert in certs {
            roots
                .add(cert)
                .with_context(|| format!("adding certificate from {}", path.display()))?;
        }
    }

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}
