//! Asking the releases page what exists, and replacing this binary with it.
//!
//! Only ever on request (`silver --check-release`, `silver update`): a
//! request tells the release host this computer's address and that it
//! runs Silver Messenger, so the client never makes one by itself unless
//! the `update-check` setting says to.
//!
//! Requests are plain HTTP/1.0 `GET`s over the same TLS configuration the
//! relay connection uses (the system trust store, extra roots, an HTTP or
//! SOCKS5 proxy), minus the relay's key pins, which belong to the relay
//! alone. Reaching the release host directly from a machine whose relay
//! traffic goes over Tor would say plainly that this address runs Silver
//! Messenger, which is the one thing the proxy is there to prevent.
//!
//! What an update is checked against, in order, before anything on disk
//! is touched (docs/design/updates.md):
//!
//!   1. the SHA-256 the release API gave for that asset, which arrives
//!      from a different origin than the bytes;
//!   2. the same hash in `SHA256SUMS`, so this agrees with what a person
//!      checking by hand would compute;
//!   3. the project's minisign signature over `SHA256SUMS`, against the
//!      public key compiled in from `minisign.pub`;
//!   4. the downloaded binary printing the version that was expected.
//!
//! [`install`] does the replacing, which is a rename and never a write
//! over the running file.

pub mod install;

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use rustls_pki_types::ServerName;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::Proxy;
use crate::tls::{ConnectOptions, tls_config};

/// Where the newest release is described.
pub const RELEASES_API: &str =
    "https://api.github.com/repos/IAmForeverAloneToo/Silver-Messenger/releases/latest";

/// Where a release is described by its tag; `{tag}` is filled in.
pub const RELEASE_BY_TAG_API: &str =
    "https://api.github.com/repos/IAmForeverAloneToo/Silver-Messenger/releases/tags/{tag}";

const TIMEOUT: Duration = Duration::from_secs(20);
/// A whole download may take this long, however fast it arrives.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
/// More than any release description needs; a bound on what is read.
const MAX_RESPONSE: u64 = 256 * 1024;
/// `SHA256SUMS` and its signature are lists of short lines.
const MAX_SUMS: u64 = 1024 * 1024;
/// No release binary comes near this; a bound on what is written to disk.
pub const MAX_BINARY: u64 = 128 * 1024 * 1024;
/// A redirect chain longer than this is a loop or a joke.
const MAX_REDIRECTS: usize = 5;

/// The project's public signing key, from `minisign.pub` at the
/// repository root at build time (see `build.rs`). Empty in a checkout
/// that publishes no key, which makes an update refuse rather than
/// accept whatever the release host serves.
///
/// That last sentence was written before the code did it: until 0.15.0 an
/// empty key skipped the signature and installed the binary anyway,
/// saying so in a line printed after the swap. The other two checks are
/// no substitute, both being answers from the host serving the bytes.
/// [`download_client`] now refuses before it fetches anything, and
/// [`verify`] refuses again at the point of use.
pub const MINISIGN_PUB: &str = env!("SILVER_MINISIGN_PUB");

/// The target this binary was built for, which names its release asset.
pub const fn target_triple() -> &'static str {
    // Written out rather than taken from a build script: these are the
    // five targets the release workflow builds, and a client built for
    // anything else has no asset to fetch and should say so.
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-musl"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-musl"
    } else {
        ""
    }
}

/// What the client's own asset is called in a release of `version`.
pub fn client_asset_name(version: &str) -> String {
    let exe = if cfg!(windows) { ".exe" } else { "" };
    format!("silver-v{version}-{}{exe}", target_triple())
}

/// One file on a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    /// The `sha256:...` digest the API reports, without its prefix.
    ///
    /// It comes from the API host and the bytes come from the asset
    /// store, so a tampered file has to be matched by a tampered answer.
    /// `None` for an asset uploaded before the API reported digests.
    pub digest: Option<String>,
    pub url: String,
}

/// What the releases page said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// The tag, e.g. `v0.6.0`.
    pub tag: String,
    /// Where a person can read about it.
    pub url: String,
    /// Its files, in the order the API listed them.
    pub assets: Vec<Asset>,
}

impl Release {
    /// The version the tag names, without its `v`.
    pub fn version(&self) -> &str {
        self.tag.strip_prefix('v').unwrap_or(&self.tag)
    }

    /// The asset called `name`, if the release has one.
    pub fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name == name)
    }
}

/// Fetch the newest release from `api_url` (normally [`RELEASES_API`]; a
/// test points it elsewhere).
pub async fn latest_release(api_url: &str, options: &ConnectOptions) -> anyhow::Result<Release> {
    tokio::time::timeout(TIMEOUT, fetch(api_url, options))
        .await
        .map_err(|_| anyhow::anyhow!("no answer from {api_url} within {TIMEOUT:?}"))?
}

/// Fetch one release by its tag, for `silver update --to`.
pub async fn release_by_tag(
    api_template: &str,
    tag: &str,
    options: &ConnectOptions,
) -> anyhow::Result<Release> {
    // The tag reaches a URL, so it may hold only what a tag may hold.
    if tag.is_empty()
        || !tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
    {
        bail!("{tag:?} is not a version");
    }
    let url = api_template.replace("{tag}", tag);
    tokio::time::timeout(TIMEOUT, fetch(&url, options))
        .await
        .map_err(|_| anyhow::anyhow!("no answer from {url} within {TIMEOUT:?}"))?
}

async fn fetch(api_url: &str, options: &ConnectOptions) -> anyhow::Result<Release> {
    let body = get(api_url, options, MAX_RESPONSE, None).await?;
    parse_release(&body)
}

/// Is `host` one a release lives on?
fn release_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "github.com"
        || host == "api.github.com"
        || host.ends_with(".github.com")
        || host == "githubusercontent.com"
        || host.ends_with(".githubusercontent.com")
}

/// May a redirect from `from` to `to` be followed?
///
/// Staying on the host the request started on is always allowed: that is
/// no more than the caller already asked for. Moving between hosts is
/// allowed only within the release host's own names, because the API
/// hands out `github.com` links that land on the asset store. Anything
/// else ends the download -- a redirect is otherwise a way to make this
/// client fetch, and possibly install, from somewhere nobody chose.
fn may_follow(from: &str, to: &str) -> bool {
    let (from, to) = (
        from.trim_end_matches('.').to_ascii_lowercase(),
        to.trim_end_matches('.').to_ascii_lowercase(),
    );
    from == to || (release_host(&from) && release_host(&to))
}

/// One `GET`, following redirects, returning the body.
///
/// `limit` bounds what is read. With `sink`, the body is written there as
/// it arrives instead of being returned, and the returned vector is
/// empty -- a binary should not be held in memory to be written out
/// again.
async fn get(
    url: &str,
    options: &ConnectOptions,
    limit: u64,
    mut sink: Option<&mut (dyn Sink + Send)>,
) -> anyhow::Result<Vec<u8>> {
    let mut url = url.to_owned();
    // Where this started: a redirect may not wander off it.
    let origin = split_https_url(&url)?.0;
    for _ in 0..=MAX_REDIRECTS {
        let (host, port, path) = split_https_url(&url)?;
        let stream = match options.proxy.as_deref() {
            Some(proxy) => Proxy::parse(proxy)?.connect(&host, port).await?,
            None => TcpStream::connect((host.as_str(), port))
                .await
                .with_context(|| format!("connecting to {host}:{port}"))?,
        };
        // The relay's pins are for the relay; here only the chain counts.
        let config = Arc::new(tls_config(options, &[])?);
        let name = ServerName::try_from(host.clone()).context("host name")?;
        let mut tls = tokio_rustls::TlsConnector::from(config)
            .connect(name, stream)
            .await
            .with_context(|| format!("TLS to {host}"))?;

        // HTTP/1.0 keeps the answer simple: no chunking, the server closes.
        let request = format!(
            "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: silver-messenger\r\n\
             Accept: application/vnd.github+json, application/octet-stream\r\n\
             Connection: close\r\n\r\n"
        );
        tls.write_all(request.as_bytes()).await?;

        let head = read_headers(&mut tls).await?;
        let status = head.status;
        if (300..400).contains(&status) {
            let location = head
                .location
                .ok_or_else(|| anyhow::anyhow!("the releases page redirected to nowhere"))?;
            url = if location.starts_with("https://") {
                location
            } else if location.starts_with('/') {
                // The port travels with the host: a relative redirect
                // stays on the same listener, not on 443.
                if port == 443 {
                    format!("https://{host}{location}")
                } else {
                    format!("https://{host}:{port}{location}")
                }
            } else {
                bail!("the releases page redirected to {location:?}, which is not https");
            };
            let next = split_https_url(&url)?.0;
            if !may_follow(&origin, &next) {
                bail!(
                    "the releases page redirected from {origin} to {next}, which is not part \
                     of it; nothing was downloaded"
                );
            }
            continue;
        }
        if status != 200 {
            // The status line is the server's, and this error reaches a
            // terminal that is not the interface.
            bail!(
                "the releases page answered: {}",
                crate::files::one_line(&head.status_line)
            );
        }

        // What arrived with the headers, then the rest.
        let mut taken = 0u64;
        let mut body = Vec::new();
        let write = |chunk: &[u8],
                     taken: &mut u64,
                     body: &mut Vec<u8>,
                     sink: &mut Option<&mut (dyn Sink + Send)>|
         -> anyhow::Result<()> {
            *taken += chunk.len() as u64;
            if *taken > limit {
                bail!("the answer is longer than the {limit} bytes allowed for it");
            }
            match sink {
                Some(s) => s.write(chunk)?,
                None => body.extend_from_slice(chunk),
            }
            Ok(())
        };
        write(&head.rest, &mut taken, &mut body, &mut sink)?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match tls.read(&mut buf).await {
                Ok(n) => n,
                // The body ends when the server closes the connection
                // (HTTP/1.0, Connection: close). A server, or a TLS proxy
                // in front of it, may close the socket without first
                // sending TLS close_notify; rustls reports that as
                // UnexpectedEof. For a body that ends at the close, that
                // is the end of the answer, not a fault -- corporate
                // middleboxes routinely close this way. A truncated
                // answer is still caught: a release must parse as JSON,
                // and a download must match SHA256SUMS and its signature.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e).context("reading the answer"),
            };
            if n == 0 {
                break;
            }
            write(&buf[..n], &mut taken, &mut body, &mut sink)?;
        }
        return Ok(body);
    }
    bail!("the releases page redirected more than {MAX_REDIRECTS} times")
}

/// Somewhere the body goes as it arrives.
pub trait Sink {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<()>;
}

/// A file, and the SHA-256 of everything written to it.
struct HashingFile {
    file: std::io::BufWriter<std::fs::File>,
    hash: Sha256,
}

impl Sink for HashingFile {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<()> {
        use std::io::Write;
        self.hash.update(chunk);
        self.file.write_all(chunk).context("writing the download")
    }
}

struct Head {
    status: u16,
    status_line: String,
    location: Option<String>,
    /// Body bytes that came in the same read as the headers.
    rest: Vec<u8>,
}

/// Read up to the blank line that ends the headers, and no further.
async fn read_headers<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Head> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    // Headers are small; a server that sends 64 KiB of them is not one.
    while buf.len() < 64 * 1024 {
        let n = match reader.read(&mut byte).await {
            Ok(n) => n,
            // A close without TLS close_notify surfaces as UnexpectedEof;
            // treat it as the end of the stream. Headers left incomplete
            // then fall through to the "no header end" error below.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("reading the answer"),
        };
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(parse_head(&buf));
        }
    }
    bail!("malformed answer (no header end)")
}

/// Pull the status and the redirect target out of a complete header
/// block.
///
/// Kept apart from the reading above so that it can be fuzzed: this is
/// the half that interprets bytes somebody else chose, and the reader is
/// only a loop looking for a blank line. `bytes` is everything up to and
/// including that blank line.
fn parse_head(bytes: &[u8]) -> Head {
    let head = String::from_utf8_lossy(bytes).into_owned();
    let status_line = head.lines().next().unwrap_or_default().to_owned();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let location = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("location:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_owned())
        .filter(|v| !v.is_empty());
    Head {
        status,
        status_line,
        location,
        rest: Vec::new(),
    }
}

/// `https://host[:port]/path` into its parts.
fn split_https_url(url: &str) -> anyhow::Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("the releases address must be https://, got {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h, p.parse::<u16>().context("port")?)
        }
        _ => (authority, 443),
    };
    if !is_host_name(host) {
        bail!("the releases address does not name a host: {url}");
    }
    Ok((host.to_owned(), port, path.to_owned()))
}

/// Is `host` a name a host could actually have?
///
/// This has to be checked here rather than left to whatever resolves the
/// name, because [`release_host`] asks whether the host *ends with* one
/// of the release service's domains — and a string ending in
/// `.github.com` is not the same thing as a name inside it.
/// `evil.test@api.github.com` and `\0onto.github.com` both end that way
/// and are read by a person as something else entirely. Nothing resolves
/// either, so this failed closed rather than wrongly; but a check and a
/// connection looking at different things is the shape of the bug, not
/// its consequence today.
///
/// Whole labels, letters, digits and hyphens, which is what a host name
/// is. A trailing dot is allowed, being the same name written absolutely,
/// and `may_follow` already trims it.
fn is_host_name(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Exposed for the fuzz target: this parses an answer from a host, before
/// any signature has been checked, so it is as network-facing as anything
/// in the protocol.
#[doc(hidden)]
pub fn parse_release_for_fuzzing(bytes: &[u8]) -> anyhow::Result<Release> {
    parse_release(bytes)
}

/// Exposed for the fuzz target; see [`parse_release_for_fuzzing`].
#[doc(hidden)]
pub fn sums_line_for_fuzzing(sums: &[u8], name: &str) -> Option<String> {
    sums_line(sums, name)
}

/// Exposed for the fuzz target: the status and the redirect target, as
/// read out of a header block a host chose.
///
/// Returns the status, the status line as it would be printed, and the
/// `Location:` value if there is one.
#[doc(hidden)]
pub fn parse_head_for_fuzzing(bytes: &[u8]) -> (u16, String, Option<String>) {
    let head = parse_head(bytes);
    (head.status, head.status_line, head.location)
}

/// Exposed for the fuzz target: where a redirect is allowed to go.
///
/// `split_https_url` decides which host a request is made to and
/// `may_follow` decides whether a redirect may reach it, so between them
/// they are what keeps an answer from the release host from sending the
/// updater somewhere else.
#[doc(hidden)]
pub fn redirect_target_for_fuzzing(url: &str, from: &str) -> Option<(String, u16, String, bool)> {
    let (host, port, path) = split_https_url(url).ok()?;
    let allowed = may_follow(from, &host);
    Some((host, port, path, allowed))
}

fn parse_release(bytes: &[u8]) -> anyhow::Result<Release> {
    let body: serde_json::Value =
        serde_json::from_slice(bytes).context("the answer is not JSON")?;
    let tag = body
        .get("tag_name")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow::anyhow!("the answer names no release"))?;
    let url = body
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    // Everything here is whatever the server put in the JSON, and most of
    // it is printed straight to a terminal. Filtered once, here, so no
    // caller has to remember.
    let assets = body
        .get("assets")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|a| {
                    let name = a.get("name")?.as_str()?;
                    let url = a.get("browser_download_url")?.as_str()?;
                    // A name reaches a file path and a URL; only a plain
                    // file name may, and never one that walks anywhere.
                    if name.is_empty()
                        || name.len() > 255
                        || !name.chars().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+')
                        })
                        || name.starts_with('.')
                    {
                        return None;
                    }
                    let digest = a
                        .get("digest")
                        .and_then(|v| v.as_str())
                        .and_then(|d| d.strip_prefix("sha256:"))
                        .filter(|d| d.len() == 64 && d.chars().all(|c| c.is_ascii_hexdigit()))
                        .map(|d| d.to_ascii_lowercase());
                    Some(Asset {
                        name: name.to_owned(),
                        digest,
                        url: crate::files::one_line(url),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Release {
        tag: crate::files::one_line(tag),
        url: crate::files::one_line(url),
        assets,
    })
}

/// What a checked-out download turned out to be.
#[derive(Debug)]
pub struct Downloaded {
    /// Where it is, in the same directory as the binary it replaces.
    pub path: PathBuf,
    /// Its SHA-256, lower-case hex.
    pub sha256: String,
}

/// Fetch the client for this platform out of `release`, check it every
/// way there is, and leave it beside `next_to` for [`install::swap`].
///
/// Nothing outside `dir` is touched, and a failure anywhere leaves the
/// running binary alone.
pub async fn download_client(
    release: &Release,
    options: &ConnectOptions,
    dir: &Path,
) -> anyhow::Result<Downloaded> {
    download_client_with_key(release, options, dir, MINISIGN_PUB).await
}

/// [`download_client`] against a given signing key rather than the one
/// compiled in.
///
/// Only so the tests can hold a private key and check that a correct
/// signature is *accepted*: with the project's own key they can check
/// refusals and nothing else, since minting a signature it would accept
/// is what the key exists to prevent.
#[doc(hidden)]
pub async fn download_client_with_key(
    release: &Release,
    options: &ConnectOptions,
    dir: &Path,
    key: &str,
) -> anyhow::Result<Downloaded> {
    let version = release.version();
    if target_triple().is_empty() {
        bail!(
            "this client was built for a platform the releases page does not carry, \
             so it cannot update itself"
        );
    }
    // Before a single byte is fetched. Without the key there is nothing
    // to check a release against that the release host does not also
    // serve: the digest on the page and the digest in SHA256SUMS come
    // from whoever is answering, so both agree with each other for any
    // binary that host cares to hand out. This used to download, install
    // and run it, and print a line saying no signature had been checked
    // -- which is a note in the log of a machine that is already running
    // someone else's code.
    if key.is_empty() {
        bail!(
            "this client was built from a checkout with no minisign.pub, so it has no key to \
             check a release against and will not install one; build from a checkout that \
             publishes the key, or install the new version by hand from {}",
            release.url
        );
    }
    let name = client_asset_name(version);
    let asset = release.asset(&name).ok_or_else(|| {
        anyhow::anyhow!(
            "release {} carries no {name}; releases before 0.12.0 published only the archives, \
             so this one has to be installed by hand from {}",
            release.tag,
            release.url
        )
    })?;

    let path = dir.join(format!(".{name}.new"));
    let sha256 = tokio::time::timeout(
        DOWNLOAD_TIMEOUT,
        download_to(&asset.url, options, &path, MAX_BINARY),
    )
    .await
    .map_err(|_| {
        let _ = std::fs::remove_file(&path);
        anyhow::anyhow!("the download did not finish within {DOWNLOAD_TIMEOUT:?}")
    })??;

    // A downloaded file is not executable, and the last check before a
    // swap is running it. Done here, where the file is made, rather than
    // left to the swap, which happens after that check: the mode the
    // binary finally keeps is the replaced one's, which `install::swap`
    // copies over this.
    if let Err(e) = make_runnable(&path) {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }

    // From here on a failure must not leave the download lying about.
    match verify(release, options, asset, &sha256, key).await {
        Ok(()) => Ok(Downloaded { path, sha256 }),
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            Err(e)
        }
    }
}

/// Let the downloaded file be run, so it can be asked its version.
///
/// Only the owner: this sits in the directory the binary will replace,
/// which may be a shared one, and it is there for seconds.
fn make_runnable(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut mode = std::fs::metadata(path)
            .with_context(|| format!("reading {}", path.display()))?
            .permissions();
        mode.set_mode(0o700);
        std::fs::set_permissions(path, mode)
            .with_context(|| format!("making {} runnable", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The three checks that do not involve running anything. All three, or
/// an error: there is no longer a way for this to return having skipped
/// the signature.
async fn verify(
    release: &Release,
    options: &ConnectOptions,
    asset: &Asset,
    sha256: &str,
    key: &str,
) -> anyhow::Result<()> {
    // 1. Against the digest the API gave, which came from another origin.
    match &asset.digest {
        Some(want) if want != sha256 => bail!(
            "the download is not what the releases page describes\n  \
             expected {want}\n  received {sha256}"
        ),
        Some(_) => {}
        None => bail!(
            "the releases page gives no checksum for {}, so what arrived cannot be checked",
            asset.name
        ),
    }

    // 2. Against SHA256SUMS, which is what a person checks by hand.
    let sums_asset = release
        .asset("SHA256SUMS")
        .ok_or_else(|| anyhow::anyhow!("release {} publishes no SHA256SUMS", release.tag))?;
    let sums = get(&sums_asset.url, options, MAX_SUMS, None)
        .await
        .context("fetching SHA256SUMS")?;
    let listed = sums_line(&sums, &asset.name).ok_or_else(|| {
        anyhow::anyhow!(
            "SHA256SUMS does not list {}",
            crate::files::one_line(&asset.name)
        )
    })?;
    if listed != sha256 {
        bail!(
            "SHA256SUMS and the releases page disagree about {}\n  \
             SHA256SUMS says {listed}\n  the page says   {sha256}",
            asset.name
        );
    }

    // 3. Against the project's signature over SHA256SUMS. `download_client`
    // refuses an empty key before it gets here; this is the same rule at
    // the place that would otherwise have to be trusted to have applied
    // it, so that no path through this function ends without a signature.
    if key.is_empty() {
        bail!("this client has no signing key compiled in, so it cannot check a release");
    }
    let sig_asset = release.asset("SHA256SUMS.minisig").ok_or_else(|| {
        anyhow::anyhow!(
            "release {} is not signed, and this client will not install an unsigned one",
            release.tag
        )
    })?;
    let sig = get(&sig_asset.url, options, MAX_SUMS, None)
        .await
        .context("fetching SHA256SUMS.minisig")?;
    verify_minisign(&sums, &sig, key).context("checking the signature over SHA256SUMS")?;
    Ok(())
}

/// The hash `SHA256SUMS` lists for `name`, in either coreutils format
/// (`<hex>  <name>`) or BSD's.
fn sums_line(sums: &[u8], name: &str) -> Option<String> {
    for line in String::from_utf8_lossy(sums).lines() {
        let line = line.trim();
        // A line that is not a checksum is skipped, not a reason to stop
        // reading: the list is the release's and may hold anything.
        let Some((hex, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if hex.len() == 64
            && hex.chars().all(|c| c.is_ascii_hexdigit())
            && rest.trim_start_matches(['*', ' ']) == name
        {
            return Some(hex.to_ascii_lowercase());
        }
    }
    None
}

/// Check a minisign signature over `message` against the key compiled in.
fn verify_minisign(message: &[u8], signature: &[u8], key: &str) -> anyhow::Result<()> {
    let key = minisign_verify::PublicKey::from_base64(key).map_err(|e| {
        anyhow::anyhow!("the signing key compiled into this client is not one: {e}")
    })?;
    let text = std::str::from_utf8(signature).context("the signature is not text")?;
    let signature = minisign_verify::Signature::decode(text)
        .map_err(|e| anyhow::anyhow!("the signature is malformed: {e}"))?;
    key.verify(message, &signature, false)
        .map_err(|e| anyhow::anyhow!("the signature is not this project's: {e}"))
}

/// Download `url` to `path`, returning the SHA-256 of what arrived.
async fn download_to(
    url: &str,
    options: &ConnectOptions,
    path: &Path,
    limit: u64,
) -> anyhow::Result<String> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("making room for the download at {}", path.display()))?;
    let mut sink = HashingFile {
        file: std::io::BufWriter::new(file),
        hash: Sha256::new(),
    };
    let result = get(url, options, limit, Some(&mut sink)).await;
    use std::io::Write;
    let flushed = sink.file.flush().context("finishing the download");
    // The bytes must be on the disk before anything is renamed over a
    // working binary, so this is not left to the operating system.
    let synced = sink
        .file
        .get_ref()
        .sync_all()
        .context("writing the download to disk");
    if let Err(e) = result.and(flushed).and(synced) {
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(hex(&sink.hash.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `major.minor.patch` out of `1.2.3`, `v1.2.3` or `1.2.3-rc1`.
pub fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let text = text.trim().strip_prefix('v').unwrap_or(text.trim());
    let core = text.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let major = parts.next()??;
    let minor = parts.next().unwrap_or(Some(0))?;
    let patch = parts.next().unwrap_or(Some(0))?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// How `latest` compares with `current`; `None` when either does not parse.
pub fn compare(latest: &str, current: &str) -> Option<Ordering> {
    Some(parse_version(latest)?.cmp(&parse_version(current)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_compare() {
        assert_eq!(parse_version("v0.6.0"), Some((0, 6, 0)));
        assert_eq!(parse_version("1.2"), Some((1, 2, 0)));
        assert_eq!(parse_version("1.2.3-rc1"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("x"), None);
        assert_eq!(compare("v0.6.0", "0.5.0"), Some(Ordering::Greater));
        assert_eq!(compare("v0.5.0", "0.5.0"), Some(Ordering::Equal));
        assert_eq!(compare("v0.4.9", "0.5.0"), Some(Ordering::Less));
        assert_eq!(compare("latest", "0.5.0"), None);
    }

    #[test]
    fn urls_split_and_answers_parse() {
        assert_eq!(
            split_https_url("https://api.github.com/repos/a/b/releases/latest").unwrap(),
            (
                "api.github.com".into(),
                443,
                "/repos/a/b/releases/latest".into()
            )
        );
        assert_eq!(
            split_https_url("https://localhost:8443").unwrap(),
            ("localhost".into(), 8443, "/".into())
        );
        assert!(split_https_url("http://x/").is_err());
        assert!(split_https_url("https://:1/").is_err());

        // Anything that is not a host name is refused rather than taken
        // as one. Read as hosts, all of these *end with* `.github.com`,
        // so `may_follow` would wave them through while a person reading
        // the line sees something else first. Nothing resolves such a
        // name, so this failed closed -- but the check and the connection
        // must not be looking at different things. The second of these
        // came from the fuzz target rather than from thinking of it.
        assert!(split_https_url("https://evil.test@api.github.com/x").is_err());
        assert!(split_https_url("https://\u{0}onto.github.com/x").is_err());
        assert!(split_https_url("https://api.github.com@evil.test/x").is_err());
        assert!(split_https_url("https://user:pass@api.github.com:443/x").is_err());
        assert!(split_https_url("https://what ever.github.com/x").is_err());
        assert!(split_https_url("https://..github.com/x").is_err());
        assert!(split_https_url("https://-nope.github.com/x").is_err());
        // And a real name still is one, trailing dot and all.
        assert_eq!(
            split_https_url("https://objects.githubusercontent.com./x")
                .unwrap()
                .0,
            "objects.githubusercontent.com."
        );

        let ok = br#"{"tag_name":"v9.9.9","html_url":"https://x/r"}"#;
        let release = parse_release(ok).unwrap();
        assert_eq!(release.tag, "v9.9.9");
        assert_eq!(release.url, "https://x/r");
        assert_eq!(release.version(), "9.9.9");
        assert!(release.assets.is_empty());
        assert!(parse_release(b"{}").is_err());
        assert!(parse_release(b"not json").is_err());
    }

    #[test]
    fn assets_carry_their_digest_and_odd_names_are_dropped() {
        let body = br#"{"tag_name":"v1.0.0","html_url":"u","assets":[
            {"name":"silver-v1.0.0-x86_64-unknown-linux-musl",
             "digest":"sha256:AABBCCDDEEFF00112233445566778899aabbccddeeff00112233445566778899",
             "browser_download_url":"https://github.com/a"},
            {"name":"SHA256SUMS","browser_download_url":"https://github.com/b"},
            {"name":"../escape","digest":"sha256:x","browser_download_url":"https://github.com/c"},
            {"name":".hidden","browser_download_url":"https://github.com/d"},
            {"name":"bad-digest","digest":"sha256:short","browser_download_url":"https://github.com/e"}
        ]}"#;
        let r = parse_release(body).unwrap();
        let names: Vec<_> = r.assets.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "silver-v1.0.0-x86_64-unknown-linux-musl",
                "SHA256SUMS",
                "bad-digest"
            ]
        );
        // Lower-cased, so it compares with what we compute.
        assert_eq!(
            r.assets[0].digest.as_deref(),
            Some("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
        );
        // No digest at all rather than a malformed one.
        assert_eq!(r.assets[1].digest, None);
        assert_eq!(r.assets[2].digest, None);
        assert!(r.asset("SHA256SUMS").is_some());
        assert!(r.asset("nothing").is_none());
    }

    #[test]
    fn only_the_release_host_is_followed() {
        assert!(release_host("github.com"));
        assert!(release_host("api.github.com"));
        assert!(release_host("objects.githubusercontent.com"));
        assert!(release_host("release-assets.githubusercontent.com"));
        assert!(
            release_host("GitHub.com"),
            "the comparison is case-insensitive"
        );
        assert!(
            release_host("github.com."),
            "a trailing dot is the same host"
        );
        assert!(!release_host("github.com.evil.test"));
        assert!(!release_host("notgithub.com"));
        assert!(!release_host("githubusercontent.com.evil.test"));
        assert!(!release_host("evil.test"));
    }

    #[test]
    fn a_download_is_made_runnable_by_its_owner_alone() {
        // The last check before a swap runs the downloaded file, and that
        // happens before anything copies the replaced binary's mode over
        // it. A download left as it was created is not runnable, which is
        // how `silver update` shipped in 0.12.0 unable to install
        // anything.
        let dir = std::env::temp_dir().join(format!("silver-runnable-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("download");
        std::fs::write(&path, b"#!/bin/sh\ntrue\n").unwrap();
        make_runnable(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert!(mode & 0o100 != 0, "not runnable by its owner: {mode:o}");
            // It sits in the directory the binary will replace, which may
            // be shared, so nobody else gets to read or run it.
            assert_eq!(mode & 0o077, 0, "readable by others: {mode:o}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_redirect_may_not_wander_off_the_host_it_started_on() {
        // What a real download does: the API hands out a github.com link,
        // which lands on the asset store.
        assert!(may_follow("api.github.com", "github.com"));
        assert!(may_follow("github.com", "objects.githubusercontent.com"));
        assert!(may_follow(
            "github.com",
            "release-assets.githubusercontent.com"
        ));
        // Staying on the host the request started on is always allowed:
        // it is no more than the caller asked for.
        assert!(may_follow("localhost", "localhost"));
        assert!(may_follow("example.test", "example.test"));
        assert!(may_follow("GitHub.com", "github.com."));
        // Off the release host, or off wherever this started, is not.
        assert!(!may_follow("github.com", "evil.test"));
        assert!(!may_follow("github.com", "github.com.evil.test"));
        assert!(!may_follow("github.com", "notgithub.com"));
        assert!(!may_follow(
            "api.github.com",
            "githubusercontent.com.evil.test"
        ));
        assert!(!may_follow("localhost", "github.com"));
        assert!(!may_follow("example.test", "evil.test"));
    }

    #[test]
    fn a_checksum_list_is_read_the_way_sha256sum_writes_it() {
        let sums = b"aa\n                     0000000000000000000000000000000000000000000000000000000000000001  silver\n                     0000000000000000000000000000000000000000000000000000000000000002 *silver.exe\n                     not-a-hash  silver-relay\n";
        assert_eq!(
            sums_line(sums, "silver").as_deref(),
            Some("0000000000000000000000000000000000000000000000000000000000000001")
        );
        // The binary-mode star is not part of the name.
        assert_eq!(
            sums_line(sums, "silver.exe").as_deref(),
            Some("0000000000000000000000000000000000000000000000000000000000000002")
        );
        assert_eq!(sums_line(sums, "silver-relay"), None);
        assert_eq!(sums_line(sums, "absent"), None);
        // A name that is a prefix of a listed one does not match it.
        assert_eq!(sums_line(sums, "silve"), None);
    }

    #[test]
    fn the_asset_name_follows_the_platform() {
        let name = client_asset_name("1.2.3");
        assert!(name.starts_with("silver-v1.2.3-"), "{name}");
        if !target_triple().is_empty() {
            assert!(name.contains(target_triple()), "{name}");
        }
        assert_eq!(name.ends_with(".exe"), cfg!(windows), "{name}");
    }

    #[test]
    fn a_signature_is_checked_against_the_key_compiled_in() {
        // The repository publishes a key, so a client built from it must
        // require a signature rather than take a release on trust.
        if MINISIGN_PUB.is_empty() {
            return;
        }
        assert!(
            minisign_verify::PublicKey::from_base64(MINISIGN_PUB).is_ok(),
            "minisign.pub does not parse: {MINISIGN_PUB}"
        );
        // Nothing verifies against it but a real signature.
        assert!(verify_minisign(b"message", b"not a signature", MINISIGN_PUB).is_err());
        let wrong = "untrusted comment: x\n                     RUQxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n                     trusted comment: x\n                     xxxx\n";
        assert!(verify_minisign(b"message", wrong.as_bytes(), MINISIGN_PUB).is_err());
        // And an empty key verifies nothing at all, whatever it is given.
        assert!(verify_minisign(b"message", wrong.as_bytes(), "").is_err());
    }
}
