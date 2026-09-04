//! TLS configuration for `wss://` relays, and the connection options.
//!
//! The trust store is the operating system's certificate store plus Mozilla's
//! root bundle, so the client works both on machines whose organisation
//! inspects TLS with its own root and on minimal systems without a store.
//! Extra PEM files can be trusted for relays behind a private CA.

use std::path::PathBuf;
use std::sync::Arc;

use crate::sessions::SharedSessions;
use crate::vault::FileCipher;

use anyhow::Context;
use rustls::RootCertStore;
use rustls::client::Resumption;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio_tungstenite::Connector;

/// Options controlling how the client reaches the relay.
#[derive(Clone, Default)]
pub struct ConnectOptions {
    /// PEM files whose certificates are trusted as additional roots.
    pub extra_ca_certs: Vec<PathBuf>,
    /// An HTTP CONNECT proxy URL to reach the relay through.
    pub proxy: Option<String>,
    /// Where to keep envelopes the relay has not accepted yet, so they
    /// survive a restart of the client. `None` keeps them in memory only.
    pub outbox_path: Option<PathBuf>,
    /// Encrypts the outbox file when the data directory has a passphrase.
    pub outbox_cipher: Option<Arc<FileCipher>>,
    /// Invite token for relays that only register invited identities.
    pub invite_token: Option<String>,
    /// Forward-secret sessions and prekeys. Without one the client speaks
    /// protocol v1 only: it publishes no prekeys and cannot read messages
    /// sent under a session.
    pub sessions: Option<SharedSessions>,
    /// Refuse to use the relay's anonymous submission connection even when
    /// it offers one, and submit on the authenticated connection instead.
    pub submit_authenticated: bool,
}

impl std::fmt::Debug for ConnectOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectOptions")
            .field("extra_ca_certs", &self.extra_ca_certs)
            .field("proxy", &self.proxy)
            .field("outbox_path", &self.outbox_path)
            .field("outbox_cipher", &self.outbox_cipher.is_some())
            .field("invite_token", &self.invite_token.is_some())
            .field("sessions", &self.sessions.is_some())
            .field("submit_authenticated", &self.submit_authenticated)
            .finish()
    }
}

/// TLS connectors for the two kinds of connection a client opens.
#[derive(Clone)]
pub(crate) struct Connectors {
    /// For the authenticated connection.
    pub(crate) main: Connector,
    /// For anonymous submission: no session resumption, so the relay cannot
    /// tie it to the authenticated connection through a resumed TLS
    /// session.
    pub(crate) anonymous: Connector,
}

pub(crate) fn connectors(options: &ConnectOptions) -> anyhow::Result<Connectors> {
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
    let mut anonymous = config.clone();
    anonymous.resumption = Resumption::disabled();
    Ok(Connectors {
        main: Connector::Rustls(Arc::new(config)),
        anonymous: Connector::Rustls(Arc::new(anonymous)),
    })
}
