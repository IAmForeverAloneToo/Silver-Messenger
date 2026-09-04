//! Asking the releases page whether a newer version exists.
//!
//! Only ever on request (`silver --check-release`): the request tells the
//! release host this computer's address and that it runs Silver Messenger,
//! so the client never does it by itself. The answer is compared with the
//! version compiled in; nothing is downloaded or installed.
//!
//! The request is a plain HTTP/1.0 `GET` over the same TLS configuration
//! the relay connection uses (the system trust store, extra roots, an
//! HTTP or SOCKS5 proxy), minus the relay's key pins, which belong to the
//! relay alone.

use std::cmp::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::Proxy;
use crate::tls::{ConnectOptions, tls_config};

/// Where the newest release is described.
pub const RELEASES_API: &str =
    "https://api.github.com/repos/IAmForeverAloneToo/Silver-Messenger/releases/latest";

const TIMEOUT: Duration = Duration::from_secs(20);
/// More than any release description needs; a bound on what is read.
const MAX_RESPONSE: u64 = 256 * 1024;

/// What the releases page said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// The tag, e.g. `v0.6.0`.
    pub tag: String,
    /// Where a person can read about it.
    pub url: String,
}

impl Release {
    /// The version the tag names, without its `v`.
    pub fn version(&self) -> &str {
        self.tag.strip_prefix('v').unwrap_or(&self.tag)
    }
}

/// Fetch the newest release from `api_url` (normally [`RELEASES_API`]; a
/// test points it elsewhere).
pub async fn latest_release(api_url: &str, options: &ConnectOptions) -> anyhow::Result<Release> {
    tokio::time::timeout(TIMEOUT, fetch(api_url, options))
        .await
        .map_err(|_| anyhow::anyhow!("no answer from {api_url} within {TIMEOUT:?}"))?
}

async fn fetch(api_url: &str, options: &ConnectOptions) -> anyhow::Result<Release> {
    let (host, port, path) = split_https_url(api_url)?;
    let stream = match options.proxy.as_deref() {
        Some(url) => Proxy::parse(url)?.connect(&host, port).await?,
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
         Accept: application/vnd.github+json\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    tls.take(MAX_RESPONSE)
        .read_to_end(&mut response)
        .await
        .context("reading the answer")?;
    parse_response(&response)
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
    if host.is_empty() {
        bail!("the releases address has no host: {url}");
    }
    Ok((host.to_owned(), port, path.to_owned()))
}

fn parse_response(bytes: &[u8]) -> anyhow::Result<Release> {
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed answer (no header end)"))?;
    let head = String::from_utf8_lossy(&bytes[..split]);
    let status_line = head.lines().next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if status != 200 {
        bail!("the releases page answered: {status_line}");
    }
    let body: serde_json::Value =
        serde_json::from_slice(&bytes[split + 4..]).context("the answer is not JSON")?;
    let tag = body
        .get("tag_name")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow::anyhow!("the answer names no release"))?;
    let url = body
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    Ok(Release {
        tag: tag.to_owned(),
        url: url.to_owned(),
    })
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

        let ok = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"tag_name\":\"v9.9.9\",\"html_url\":\"https://x/r\"}";
        assert_eq!(
            parse_response(ok).unwrap(),
            Release {
                tag: "v9.9.9".into(),
                url: "https://x/r".into()
            }
        );
        assert_eq!(parse_response(ok).unwrap().version(), "9.9.9");
        let err = parse_response(b"HTTP/1.0 403 Forbidden\r\n\r\n{}").unwrap_err();
        assert!(err.to_string().contains("403"), "{err}");
        assert!(parse_response(b"HTTP/1.0 200 OK\r\n\r\n{}").is_err());
        assert!(parse_response(b"HTTP/1.0 200 OK\r\n\r\nnot json").is_err());
        assert!(parse_response(b"garbage").is_err());
    }
}
