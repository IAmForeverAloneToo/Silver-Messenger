//! Certificates from an ACME certificate authority (RFC 8555), obtained
//! and renewed by the relay itself, with the TLS-ALPN-01 challenge
//! (RFC 8737) answered on the port that serves clients. No second port, no
//! web server in front, no cron job.
//!
//! The cache directory, readable by the relay's user only, holds the
//! account credentials (`account.json`), the certificate's private key
//! (`key.pem`) and the last chain (`chain.pem`). The key is generated once
//! and reused for every renewal, so that clients that pin the relay's key
//! (`silver --pin`) keep working across renewals; deleting `key.pem` makes
//! the next renewal use a fresh one.
//!
//! Renewal: the certificate authority is asked for its suggested renewal
//! window (ACME Renewal Information, RFC 9773) and the certificate is
//! replaced once the window opens; a certificate authority without that
//! information gets the certificate replaced when a third of its lifetime
//! is left, which is what Let's Encrypt asks of clients. A failed attempt
//! is retried with backoff while the old certificate keeps being served.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeType,
    Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, error, info};

use crate::tls::{self, CertStore};

/// The default certificate authority.
pub const DEFAULT_DIRECTORY: &str = LetsEncrypt::Production.url();

/// How long between looks at whether the certificate is due, at most.
pub const CHECK_EVERY: Duration = Duration::from_secs(12 * 3600);
/// A first failure is usually a name that does not point here yet or a
/// port that is not open yet, with the operator watching: try again soon,
/// then ever less often.
const RETRY_FIRST: Duration = Duration::from_secs(60);
const RETRY_LONGEST: Duration = Duration::from_secs(12 * 3600);

#[derive(Clone, Debug)]
pub struct AcmeConfig {
    /// The names the certificate is for; the relay must be reachable at
    /// each of them on port 443.
    pub domains: Vec<String>,
    /// The ACME directory URL.
    pub directory: String,
    /// A contact address the certificate authority may write to about
    /// the certificate, with or without `mailto:`.
    pub contact: Option<String>,
    /// Where the account, key and certificate are kept.
    pub cache: PathBuf,
    /// A root certificate (PEM) to trust for the directory, for a private
    /// certificate authority or a test one.
    pub root: Option<PathBuf>,
}

/// Keep `store` supplied with a certificate for the configured names,
/// forever. Runs as a task next to the listener, which must already be
/// accepting connections, since validation connects to it.
pub async fn run(config: AcmeConfig, store: Arc<CertStore>) {
    let mut retry = RETRY_FIRST;
    loop {
        match ensure(&config, &store).await {
            Ok(next) => {
                retry = RETRY_FIRST;
                tokio::time::sleep(next).await;
            }
            Err(e) => {
                error!(
                    "ACME for {}: {e:#}; trying again in {} minute{}",
                    config.domains.join(", "),
                    retry.as_secs() / 60,
                    if retry.as_secs() == 60 { "" } else { "s" }
                );
                tokio::time::sleep(retry).await;
                retry = (retry * 2).min(RETRY_LONGEST);
            }
        }
    }
}

/// Serve what the cache holds, order a certificate when there is none or
/// it is due, and say how long to wait before looking again.
async fn ensure(config: &AcmeConfig, store: &Arc<CertStore>) -> anyhow::Result<Duration> {
    prepare_cache(&config.cache)?;
    let key = load_or_create_key(&config.cache)?;
    let mut chain = load_chain(&config.cache)?;
    if let Some(certs) = &chain
        && !store.has_certificate()
    {
        install(store, certs, &key)?;
        info!(
            "serving the cached certificate for {} until {}",
            tls::dns_names(&certs[0]).join(", "),
            tls::expiry_text(&certs[0])
        );
    }
    let account = account(config).await?;
    let due = match &chain {
        Some(certs) => renewal_due(&account, certs, SystemTime::now()).await,
        None => true,
    };
    if due {
        let certs = order(config, &account, &key, store).await?;
        save_chain(&config.cache, &certs)?;
        install(store, &certs, &key)?;
        info!(
            "certificate for {} obtained from {}; valid until {}",
            tls::dns_names(&certs[0]).join(", "),
            config.directory,
            tls::expiry_text(&certs[0])
        );
        chain = Some(certs);
    }
    Ok(next_check(chain.as_deref(), SystemTime::now()))
}

fn prepare_cache(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", dir.display()))?;
    }
    Ok(())
}

/// Write `bytes` to `path`, readable by the owner only, replacing any
/// previous file in one step.
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

fn load_or_create_key(dir: &Path) -> anyhow::Result<rcgen::KeyPair> {
    let path = dir.join("key.pem");
    match std::fs::read_to_string(&path) {
        Ok(pem) => rcgen::KeyPair::from_pem(&pem)
            .with_context(|| format!("{} is not a usable private key", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = rcgen::KeyPair::generate().context("generating the certificate key")?;
            write_private(&path, key.serialize_pem().as_bytes())?;
            info!("new certificate key written to {}", path.display());
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn load_chain(dir: &Path) -> anyhow::Result<Option<Vec<CertificateDer<'static>>>> {
    let path = dir.join("chain.pem");
    if !path.exists() {
        return Ok(None);
    }
    let certs = CertificateDer::pem_file_iter(&path)
        .with_context(|| format!("reading {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("{} is not a PEM certificate chain", path.display()))?;
    Ok((!certs.is_empty()).then_some(certs))
}

/// `der` as a PEM block of the given kind, 64 columns wide.
fn to_pem(kind: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {kind}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {kind}-----\n"));
    out
}

fn save_chain(dir: &Path, certs: &[CertificateDer<'static>]) -> anyhow::Result<()> {
    let pem: String = certs
        .iter()
        .map(|c| to_pem("CERTIFICATE", c.as_ref()))
        .collect();
    write_private(&dir.join("chain.pem"), pem.as_bytes())
}

fn install(
    store: &CertStore,
    certs: &[CertificateDer<'static>],
    key: &rcgen::KeyPair,
) -> anyhow::Result<()> {
    let certified = tls::certified(
        certs.to_vec(),
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .context("the cached certificate does not fit the key")?;
    store.set_current(certified);
    Ok(())
}

async fn account(config: &AcmeConfig) -> anyhow::Result<Account> {
    let builder = match &config.root {
        Some(pem) => Account::builder_with_root(pem)
            .with_context(|| format!("reading the ACME root {}", pem.display()))?,
        None => Account::builder().context("preparing the ACME client")?,
    };
    let path = config.cache.join("account.json");
    match std::fs::read(&path) {
        Ok(bytes) => {
            let credentials: AccountCredentials = serde_json::from_slice(&bytes)
                .with_context(|| format!("{} is unreadable", path.display()))?;
            return builder
                .from_credentials(credentials)
                .await
                .context("using the saved ACME account");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    let contact: Vec<String> = config
        .contact
        .iter()
        .map(|c| {
            if c.starts_with("mailto:") {
                c.clone()
            } else {
                format!("mailto:{c}")
            }
        })
        .collect();
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    // Using an ACME certificate authority means agreeing to its terms; the
    // operator did so by pointing the relay at it (the README says so).
    let (account, credentials) = builder
        .create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            config.directory.clone(),
            None,
        )
        .await
        .with_context(|| format!("creating an ACME account at {}", config.directory))?;
    write_private(&path, &serde_json::to_vec_pretty(&credentials)?)?;
    info!("ACME account created at {}", config.directory);
    Ok(account)
}

/// Whether `certs` should be replaced now: by the certificate authority's
/// renewal window when it publishes one, else when a third of the
/// lifetime is left, and always once it has expired or cannot be read.
async fn renewal_due(
    account: &Account,
    certs: &[CertificateDer<'static>],
    now: SystemTime,
) -> bool {
    let leaf = &certs[0];
    let (Ok(not_before), Ok(not_after)) = (tls::not_before(leaf), tls::not_after(leaf)) else {
        return true;
    };
    if now >= not_after {
        return true;
    }
    if let Ok(id) = CertificateIdentifier::try_from(leaf) {
        match account.renewal_info(&id).await {
            Ok((info, _retry_after)) => {
                let start = info.suggested_window.start.unix_timestamp();
                let start = SystemTime::UNIX_EPOCH + Duration::from_secs(start.max(0) as u64);
                return now >= start;
            }
            Err(e) => debug!(
                "no renewal information from the certificate authority ({e}); going by the dates"
            ),
        }
    }
    due_by_dates(not_before, not_after, now)
}

/// The dates-only rule: due once a third of the lifetime is left.
fn due_by_dates(not_before: SystemTime, not_after: SystemTime, now: SystemTime) -> bool {
    let lifetime = not_after
        .duration_since(not_before)
        .unwrap_or(Duration::ZERO);
    now + lifetime / 3 >= not_after
}

/// How long to wait before the next look: until the dates-only rule would
/// make the certificate due, but never more than [`CHECK_EVERY`] and never
/// less than a minute.
fn next_check(certs: Option<&[CertificateDer<'static>]>, now: SystemTime) -> Duration {
    let Some(leaf) = certs.and_then(|c| c.first()) else {
        return Duration::from_secs(60);
    };
    let (Ok(not_before), Ok(not_after)) = (tls::not_before(leaf), tls::not_after(leaf)) else {
        return Duration::from_secs(60);
    };
    let lifetime = not_after
        .duration_since(not_before)
        .unwrap_or(Duration::ZERO);
    let due_at = not_after - lifetime / 3;
    due_at
        .duration_since(now)
        .unwrap_or(Duration::ZERO)
        .clamp(Duration::from_secs(60), CHECK_EVERY)
}

fn csr(domains: &[String], key: &rcgen::KeyPair) -> anyhow::Result<Vec<u8>> {
    let params = rcgen::CertificateParams::new(domains.to_vec())
        .context("the names are not valid certificate subjects")?;
    let request = params
        .serialize_request(key)
        .context("building the certificate request")?;
    Ok(request.der().as_ref().to_vec())
}

/// One order: answer every TLS-ALPN-01 challenge through `store`, wait
/// for validation, finalize with the reused key and fetch the chain.
async fn order(
    config: &AcmeConfig,
    account: &Account,
    key: &rcgen::KeyPair,
    store: &CertStore,
) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let identifiers: Vec<Identifier> = config
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("placing the order")?;

    let mut answered = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authorization = result.context("reading an authorization")?;
        match authorization.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => bail!("an authorization is {other:?} before validation"),
        }
        let name = match authorization.identifier().identifier {
            Identifier::Dns(name) => name.clone(),
            other => bail!("the certificate authority authorized {other:?}, not a DNS name"),
        };
        let mut challenge = authorization
            .challenge(ChallengeType::TlsAlpn01)
            .context("the certificate authority offers no TLS-ALPN-01 challenge; the relay answers no other kind")?;
        let key_authorization = challenge.key_authorization();
        let digest = key_authorization.digest();
        store.set_challenge(&name, tls::challenge_certificate(&name, digest.as_ref())?);
        answered.push(name);
        challenge
            .set_ready()
            .await
            .context("asking the certificate authority to validate")?;
    }

    let issued = async {
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .context("waiting for validation")?;
        if status != OrderStatus::Ready {
            bail!("the order is {status:?} after validation");
        }
        order
            .finalize_csr(&csr(&config.domains, key)?)
            .await
            .context("finalizing the order")?;
        order
            .poll_certificate(&RetryPolicy::default())
            .await
            .context("waiting for the certificate")
    }
    .await;
    for name in &answered {
        store.clear_challenge(name);
    }
    let pem = issued?;
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("the certificate authority returned something other than a PEM chain")?;
    if certs.is_empty() {
        bail!("the certificate authority returned an empty chain");
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(86_400);

    #[test]
    fn a_certificate_is_due_when_a_third_of_its_life_is_left() {
        let start = SystemTime::UNIX_EPOCH + 1_800_000_000 * Duration::from_secs(1);
        let end = start + 90 * DAY;
        assert!(!due_by_dates(start, end, start));
        assert!(!due_by_dates(start, end, start + 59 * DAY));
        assert!(due_by_dates(start, end, start + 60 * DAY));
        assert!(due_by_dates(start, end, end + DAY));
        // A short-lived certificate follows the same rule.
        let short = start + 6 * DAY;
        assert!(!due_by_dates(start, short, start + 3 * DAY));
        assert!(due_by_dates(start, short, start + 4 * DAY));
    }

    #[test]
    fn the_next_look_is_bounded() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["a.example".to_owned()]).unwrap();
        let now = SystemTime::now();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        let chain = vec![cert.der().clone()];
        assert_eq!(next_check(Some(&chain), now), CHECK_EVERY);
        assert_eq!(next_check(None, now), Duration::from_secs(60));
        let mut soon = rcgen::CertificateParams::new(vec!["a.example".to_owned()]).unwrap();
        soon.not_before = rcgen::date_time_ymd(2020, 1, 1);
        soon.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let expired = vec![soon.self_signed(&key).unwrap().der().clone()];
        assert_eq!(next_check(Some(&expired), now), Duration::from_secs(60));
    }

    #[test]
    fn the_key_is_created_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_key(dir.path()).unwrap();
        let again = load_or_create_key(dir.path()).unwrap();
        assert_eq!(first.serialize_der(), again.serialize_der());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(dir.path().join("key.pem"), "not a key").unwrap();
        assert!(load_or_create_key(dir.path()).is_err());
    }

    #[test]
    fn a_chain_round_trips_through_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_chain(dir.path()).unwrap().is_none());
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["a.example".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let chain = vec![cert.der().clone(), cert.der().clone()];
        save_chain(dir.path(), &chain).unwrap();
        assert_eq!(load_chain(dir.path()).unwrap().unwrap(), chain);
        let store = CertStore::new();
        install(&store, &chain, &key).unwrap();
        assert!(store.has_certificate());
        let other = rcgen::KeyPair::generate().unwrap();
        assert!(install(&store, &chain, &other).is_err());
        let request = csr(&["a.example".to_owned()], &key).unwrap();
        assert!(!request.is_empty());
    }
}
