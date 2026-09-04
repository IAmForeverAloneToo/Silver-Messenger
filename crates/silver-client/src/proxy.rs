//! Reaching the relay through an HTTP `CONNECT` proxy, the kind `HTTPS_PROXY`
//! points at on many corporate networks.

use anyhow::{Context, bail};
use silver_protocol::encoding::to_base64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_RESPONSE_HEAD: usize = 8 * 1024;

/// An HTTP proxy that accepts `CONNECT` requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
    /// Basic-auth credentials, if the URL carried `user:password@`.
    pub auth: Option<(String, String)>,
}

impl Proxy {
    /// Parse `http://[user:password@]host[:port]`; a bare `host:port` works too.
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let rest = url.trim();
        if rest.starts_with("https://") || rest.starts_with("socks") {
            bail!("only http:// CONNECT proxies are supported, got {url}");
        }
        let rest = rest.strip_prefix("http://").unwrap_or(rest);
        let rest = rest.split('/').next().unwrap_or_default();
        let (auth, host_port) = match rest.rsplit_once('@') {
            Some((auth, host_port)) => (Some(auth), host_port),
            None => (None, rest),
        };
        let auth = auth.map(|a| {
            let (user, password) = a.split_once(':').unwrap_or((a, ""));
            (percent_decode(user), percent_decode(password))
        });
        let (host, port) = match host_port.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => (
                host,
                port.parse::<u16>().context("proxy port out of range")?,
            ),
            _ => (host_port, 80),
        };
        let host = host.trim_matches(|c| c == '[' || c == ']');
        if host.is_empty() {
            bail!("proxy URL has no host: {url}");
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            auth,
        })
    }

    /// The proxy URL the environment asks for (`HTTPS_PROXY`), if any.
    pub fn url_from_env() -> Option<String> {
        ["HTTPS_PROXY", "https_proxy"]
            .iter()
            .find_map(|key| std::env::var(key).ok())
            .filter(|v| !v.trim().is_empty())
    }

    /// Open a raw tunnel to `host:port` through the proxy.
    pub async fn connect(&self, host: &str, port: u16) -> anyhow::Result<TcpStream> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .with_context(|| format!("connecting to proxy {}:{}", self.host, self.port))?;

        let mut request = format!(
            "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: Keep-Alive\r\n"
        );
        if let Some((user, password)) = &self.auth {
            let token = to_base64(format!("{user}:{password}").as_bytes());
            request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;

        // Read exactly the response head; nothing follows it until we speak.
        let mut head = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await? == 0 {
                bail!("proxy closed the connection during CONNECT");
            }
            head.push(byte[0]);
            if head.len() > MAX_RESPONSE_HEAD {
                bail!("proxy CONNECT response too large");
            }
        }
        let head = String::from_utf8_lossy(&head);
        let status_line = head.lines().next().unwrap_or_default().trim().to_owned();
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if status != 200 {
            bail!("proxy refused CONNECT to {host}:{port}: {status_line}");
        }
        Ok(stream)
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(v) = s
                .get(i + 1..i + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proxy_urls() {
        let p = Proxy::parse("http://127.0.0.1:41945").unwrap();
        assert_eq!(
            (p.host.as_str(), p.port, p.auth),
            ("127.0.0.1", 41945, None)
        );

        let p = Proxy::parse("http://user:p%40ss@proxy.local:3128/").unwrap();
        assert_eq!(p.host, "proxy.local");
        assert_eq!(p.port, 3128);
        assert_eq!(p.auth, Some(("user".into(), "p@ss".into())));

        let p = Proxy::parse("proxy.local").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("proxy.local", 80));

        assert!(Proxy::parse("socks5://x:1").is_err());
        assert!(Proxy::parse("http://:8080").is_err());
    }
}
