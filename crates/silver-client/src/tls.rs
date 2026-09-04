//! TLS configuration for `wss://` relays, and the connection options.
//!
//! The trust store is the operating system's certificate store plus Mozilla's
//! root bundle, so the client works both on machines whose organisation
//! inspects TLS with its own root and on minimal systems without a store.
//! Extra PEM files can be trusted for relays behind a private CA, and a
//! *pin* ties the relay to one public key on top of that, so that no
//! certificate authority, trusted or planted, can stand in for it.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::sessions::SharedSessions;
use crate::vault::FileCipher;

use anyhow::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use silver_protocol::encoding::{from_base64, to_base64};
use tokio_tungstenite::Connector;
use webpki::EndEntityCert;

/// Options controlling how the client reaches the relay.
#[derive(Clone, Default)]
pub struct ConnectOptions {
    /// PEM files whose certificates are trusted as additional roots.
    pub extra_ca_certs: Vec<PathBuf>,
    /// A proxy URL to reach the relay through: `http://` for an HTTP
    /// CONNECT proxy, `socks5://` for SOCKS5 (Tor, say).
    pub proxy: Option<String>,
    /// Public-key pins for the relay's certificate chain (see [`Pin`]).
    /// When any are set, a `wss://` connection is refused unless one of
    /// them matches a certificate the relay presents.
    pub pins: Vec<Pin>,
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
            .field("pins", &self.pins)
            .field("outbox_path", &self.outbox_path)
            .field("outbox_cipher", &self.outbox_cipher.is_some())
            .field("invite_token", &self.invite_token.is_some())
            .field("sessions", &self.sessions.is_some())
            .field("submit_authenticated", &self.submit_authenticated)
            .finish()
    }
}

/// The SHA-256 of a certificate's public key (its DER `SubjectPublicKeyInfo`),
/// as HTTP public key pinning (RFC 7469) defines it. It names the key, not
/// the certificate, so it survives a renewal that keeps the key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pin([u8; 32]);

impl Pin {
    /// Parse `sha256:<64 hex>` or `sha256/<base64>`; the `sha256` prefix
    /// and colons between hex pairs (as `openssl` prints them) are optional.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let text = text.trim();
        let text = text
            .strip_prefix("sha256:")
            .or_else(|| text.strip_prefix("sha256/"))
            .or_else(|| text.strip_prefix("SHA256:"))
            .unwrap_or(text);
        let hex: String = text.chars().filter(|c| *c != ':').collect();
        if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut out = [0u8; 32];
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex checked");
            }
            return Ok(Self(out));
        }
        if let Ok(bytes) = from_base64(text)
            && bytes.len() == 32
        {
            return Ok(Self(bytes.try_into().expect("length checked")));
        }
        anyhow::bail!(
            "a pin is the SHA-256 of the relay's public key, as sha256:<64 hex digits> or sha256/<base64>"
        )
    }

    /// The pin of a certificate's public key.
    pub fn of(cert: &CertificateDer<'_>) -> anyhow::Result<Self> {
        let parsed = EndEntityCert::try_from(cert).context("parsing certificate")?;
        let spki = parsed.subject_public_key_info();
        Ok(Self(Sha256::digest(spki.as_ref()).into()))
    }

    /// `sha256:<hex>`.
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(71);
        s.push_str("sha256:");
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// `sha256/<base64>`, the HPKP spelling.
    pub fn to_base64(self) -> String {
        format!("sha256/{}", to_base64(&self.0))
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Display for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::str::FromStr for Pin {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
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

/// The TLS configuration the options describe: the trust store (plus any
/// extra roots) and, when `pins` is not empty, the pin check on top.
pub(crate) fn tls_config(
    options: &ConnectOptions,
    pins: &[Pin],
) -> anyhow::Result<rustls::ClientConfig> {
    let verifier: Arc<dyn ServerCertVerifier> = if pins.is_empty() {
        chain_verifier(options)?
    } else {
        Arc::new(PinnedVerifier {
            inner: chain_verifier(options)?,
            pins: pins.to_vec(),
        })
    };
    Ok(client_config(verifier))
}

pub(crate) fn connectors(options: &ConnectOptions) -> anyhow::Result<Connectors> {
    let config = tls_config(options, &options.pins)?;
    let mut anonymous = config.clone();
    anonymous.resumption = Resumption::disabled();
    Ok(Connectors {
        main: Connector::Rustls(Arc::new(config)),
        anonymous: Connector::Rustls(Arc::new(anonymous)),
    })
}

/// A connector that accepts whatever certificate it is shown and records
/// it, for looking at a relay's key before deciding to pin it. Only for
/// [`crate::connection::observe_relay`]: nothing is sent over the
/// connection it opens.
pub(crate) fn observing_connector(
    options: &ConnectOptions,
) -> anyhow::Result<(Connector, Arc<Mutex<Option<Observed>>>)> {
    let seen = Arc::new(Mutex::new(None));
    let verifier = Arc::new(ObservingVerifier {
        inner: chain_verifier(options)?,
        seen: seen.clone(),
    });
    Ok((Connector::Rustls(Arc::new(client_config(verifier))), seen))
}

/// What the observing verifier saw of a relay's certificate.
#[derive(Clone, Debug)]
pub struct Observed {
    /// The pin of the relay's own certificate, then of each intermediate
    /// it sent.
    pub pins: Vec<Pin>,
    /// Whether the chain validated against the trust store, else why not.
    pub trusted: Result<(), String>,
}

fn chain_verifier(options: &ConnectOptions) -> anyhow::Result<Arc<WebPkiServerVerifier>> {
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
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .context("building the certificate verifier")
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn client_config(verifier: Arc<dyn ServerCertVerifier>) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// Chain validation as usual, then one of the pins must name a key in the
/// chain.
#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: Vec<Pin>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let mut presented = Vec::with_capacity(1 + intermediates.len());
        for cert in std::iter::once(end_entity).chain(intermediates) {
            let pin = Pin::of(cert).map_err(|e| rustls::Error::General(e.to_string()))?;
            if self.pins.contains(&pin) {
                return Ok(verified);
            }
            presented.push(pin);
        }
        Err(rustls::Error::General(format!(
            "certificate pin mismatch: the relay's key is {}, which is not one of the pinned keys; \
             if the relay's key really changed, set the new pin, otherwise something is in the way",
            presented[0]
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Records the chain and whether it validates, and lets the handshake go on
/// either way.
#[derive(Debug)]
struct ObservingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    seen: Arc<Mutex<Option<Observed>>>,
}

impl ServerCertVerifier for ObservingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let trusted = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .map(|_| ())
            .map_err(|e| e.to_string());
        let pins = std::iter::once(end_entity)
            .chain(intermediates)
            .map(Pin::of)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(Observed { pins, trusted });
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_parse_in_every_spelling_and_print_back() {
        let hex = "sha256:".to_owned() + &"ab".repeat(32);
        let pin = Pin::parse(&hex).unwrap();
        assert_eq!(pin.to_hex(), hex);
        assert!(Pin::parse(&"AB:".repeat(31)).is_err());
        let colons = "AB:".repeat(32);
        assert_eq!(Pin::parse(colons.trim_end_matches(':')).unwrap(), pin);
        assert_eq!(Pin::parse(&pin.to_base64()).unwrap(), pin);
        assert_eq!(Pin::parse(&"ab".repeat(32)).unwrap(), pin);
        assert!(Pin::parse("sha256:abc").is_err());
        assert!(Pin::parse("").is_err());
        assert!(Pin::parse(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn a_pin_names_the_key_not_the_certificate() {
        let key = rcgen::KeyPair::generate().unwrap();
        let one = rcgen::CertificateParams::new(vec!["a.example".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let two = rcgen::CertificateParams::new(vec!["b.example".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["a.example".to_owned()]).unwrap();
        let pin_one = Pin::of(one.der()).unwrap();
        assert_eq!(pin_one, Pin::of(two.der()).unwrap());
        assert_ne!(pin_one, Pin::of(other.cert.der()).unwrap());
        // The same digest `openssl` would print for the public key.
        use rcgen::PublicKeyData;
        let spki = key.subject_public_key_info();
        assert_eq!(pin_one.0, <[u8; 32]>::from(Sha256::digest(&spki)));
    }
}
