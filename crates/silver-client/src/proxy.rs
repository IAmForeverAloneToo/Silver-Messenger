//! Reaching the relay through a proxy: an HTTP `CONNECT` proxy, the kind
//! `HTTPS_PROXY` points at on many corporate networks, or a SOCKS5 proxy
//! such as Tor's.
//!
//! Through SOCKS5 the relay's host name is handed to the proxy to resolve
//! (never looked up locally, which would tell the local resolver where the
//! relay is), and, unless the URL carries credentials, every connection
//! logs in with fresh random ones. Tor puts connections with different
//! SOCKS credentials on different circuits, so the authenticated and the
//! anonymous connection reach the relay from different exit addresses and
//! the relay cannot pair them by address.

use std::net::IpAddr;

use anyhow::{Context, bail};
use silver_protocol::encoding::to_base64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_RESPONSE_HEAD: usize = 8 * 1024;

const SOCKS_VERSION: u8 = 5;
const SOCKS_NO_AUTH: u8 = 0x00;
const SOCKS_USER_PASS: u8 = 0x02;
const SOCKS_NO_ACCEPTABLE: u8 = 0xff;
const SOCKS_CONNECT: u8 = 0x01;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

/// What protocol the proxy speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// HTTP `CONNECT` (`http://`).
    Http,
    /// SOCKS5 with the proxy resolving names (`socks5://`, `socks5h://`).
    Socks5,
}

/// A proxy the relay is reached through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxy {
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    /// Credentials, if the URL carried `user:password@`: HTTP basic
    /// authentication, or SOCKS5 username/password (RFC 1929).
    pub auth: Option<(String, String)>,
}

impl Proxy {
    /// Parse `http://[user:password@]host[:port]` or
    /// `socks5://[user:password@]host[:port]` (`socks5h://` means the
    /// same: names are always resolved by the proxy). A bare `host:port` is
    /// an HTTP proxy.
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let rest = url.trim();
        let (kind, rest, default_port) = if let Some(rest) = rest.strip_prefix("http://") {
            (Kind::Http, rest, 80)
        } else if let Some(rest) = rest
            .strip_prefix("socks5h://")
            .or_else(|| rest.strip_prefix("socks5://"))
        {
            (Kind::Socks5, rest, 1080)
        } else if rest.contains("://") {
            bail!("only http:// CONNECT and socks5:// proxies are supported, got {url}");
        } else {
            (Kind::Http, rest, 80)
        };
        let rest = rest.split('/').next().unwrap_or_default();
        let (auth, host_port) = match rest.rsplit_once('@') {
            Some((auth, host_port)) => (Some(auth), host_port),
            None => (None, rest),
        };
        let auth = auth.map(|a| {
            let (user, password) = a.split_once(':').unwrap_or((a, ""));
            (percent_decode(user), percent_decode(password))
        });
        if let Some((user, password)) = &auth
            && kind == Kind::Socks5
            && (user.len() > 255 || password.len() > 255)
        {
            bail!("SOCKS5 credentials are at most 255 bytes each");
        }
        let (host, port) = match host_port.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => (
                host,
                port.parse::<u16>().context("proxy port out of range")?,
            ),
            _ => (host_port, default_port),
        };
        let host = host.trim_matches(|c| c == '[' || c == ']');
        if host.is_empty() {
            bail!("proxy URL has no host: {url}");
        }
        Ok(Self {
            kind,
            host: host.to_owned(),
            port,
            auth,
        })
    }

    /// The proxy URL the environment asks for (`HTTPS_PROXY`, else
    /// `ALL_PROXY`), if any.
    pub fn url_from_env() -> Option<String> {
        ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
            .iter()
            .find_map(|key| std::env::var(key).ok())
            .filter(|v| !v.trim().is_empty())
    }

    /// Whether connections through this proxy each get their own SOCKS
    /// credentials, and so their own Tor circuit.
    pub fn isolates_connections(&self) -> bool {
        self.kind == Kind::Socks5 && self.auth.is_none()
    }

    /// Open a raw tunnel to `host:port` through the proxy.
    pub async fn connect(&self, host: &str, port: u16) -> anyhow::Result<TcpStream> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .with_context(|| format!("connecting to proxy {}:{}", self.host, self.port))?;
        match self.kind {
            Kind::Http => self.connect_http(&mut stream, host, port).await?,
            Kind::Socks5 => self.connect_socks5(&mut stream, host, port).await?,
        }
        Ok(stream)
    }

    async fn connect_http(
        &self,
        stream: &mut TcpStream,
        host: &str,
        port: u16,
    ) -> anyhow::Result<()> {
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
        Ok(())
    }

    /// RFC 1928 with RFC 1929 username/password.
    async fn connect_socks5(
        &self,
        stream: &mut TcpStream,
        host: &str,
        port: u16,
    ) -> anyhow::Result<()> {
        // Greeting: we can log in, or not; the proxy chooses. Tor picks the
        // login when offered, which is what isolates circuits.
        stream
            .write_all(&[SOCKS_VERSION, 2, SOCKS_NO_AUTH, SOCKS_USER_PASS])
            .await?;
        let mut choice = [0u8; 2];
        stream.read_exact(&mut choice).await?;
        if choice[0] != SOCKS_VERSION {
            bail!("proxy does not speak SOCKS5 (version byte {})", choice[0]);
        }
        match choice[1] {
            SOCKS_NO_AUTH => {}
            SOCKS_USER_PASS => {
                let (user, password) = match &self.auth {
                    Some(auth) => auth.clone(),
                    None => fresh_credentials(),
                };
                let mut login = vec![1, user.len() as u8];
                login.extend_from_slice(user.as_bytes());
                login.push(password.len() as u8);
                login.extend_from_slice(password.as_bytes());
                stream.write_all(&login).await?;
                let mut status = [0u8; 2];
                stream.read_exact(&mut status).await?;
                if status[1] != 0 {
                    bail!("proxy refused the SOCKS5 login");
                }
            }
            SOCKS_NO_ACCEPTABLE => bail!("proxy accepts none of our SOCKS5 login methods"),
            other => bail!("proxy chose an unknown SOCKS5 login method ({other})"),
        }

        // The request: the name goes to the proxy as it is, unless it is an
        // address already.
        let mut request = vec![SOCKS_VERSION, SOCKS_CONNECT, 0];
        match host
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<IpAddr>()
        {
            Ok(IpAddr::V4(v4)) => {
                request.push(SOCKS_ATYP_IPV4);
                request.extend_from_slice(&v4.octets());
            }
            Ok(IpAddr::V6(v6)) => {
                request.push(SOCKS_ATYP_IPV6);
                request.extend_from_slice(&v6.octets());
            }
            Err(_) => {
                if host.is_empty() || host.len() > 255 {
                    bail!("host name too long for SOCKS5: {host}");
                }
                request.push(SOCKS_ATYP_DOMAIN);
                request.push(host.len() as u8);
                request.extend_from_slice(host.as_bytes());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        if head[0] != SOCKS_VERSION {
            bail!("proxy answered with SOCKS version {}", head[0]);
        }
        if head[1] != 0 {
            bail!(
                "proxy refused the connection to {host}:{port}: {}",
                socks5_reply(head[1])
            );
        }
        // The bound address, of no use to us but part of the reply.
        let skip = match head[3] {
            SOCKS_ATYP_IPV4 => 4 + 2,
            SOCKS_ATYP_IPV6 => 16 + 2,
            SOCKS_ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                len[0] as usize + 2
            }
            other => bail!("proxy answered with an unknown address type ({other})"),
        };
        let mut bound = vec![0u8; skip];
        stream.read_exact(&mut bound).await?;
        Ok(())
    }
}

/// Credentials no other connection uses, so that a Tor proxy gives this
/// connection a circuit of its own.
fn fresh_credentials() -> (String, String) {
    let user: [u8; 12] = rand::random();
    let password: [u8; 12] = rand::random();
    (to_base64(&user), to_base64(&password))
}

fn socks5_reply(code: u8) -> &'static str {
    match code {
        0x01 => "general failure",
        0x02 => "not allowed by the proxy's rules",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
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
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[test]
    fn parses_proxy_urls() {
        let p = Proxy::parse("http://127.0.0.1:41945").unwrap();
        assert_eq!(
            (p.kind, p.host.as_str(), p.port, p.auth),
            (Kind::Http, "127.0.0.1", 41945, None)
        );

        let p = Proxy::parse("http://user:p%40ss@proxy.local:3128/").unwrap();
        assert_eq!(p.host, "proxy.local");
        assert_eq!(p.port, 3128);
        assert_eq!(p.auth, Some(("user".into(), "p@ss".into())));

        let p = Proxy::parse("proxy.local").unwrap();
        assert_eq!(
            (p.kind, p.host.as_str(), p.port),
            (Kind::Http, "proxy.local", 80)
        );

        let p = Proxy::parse("socks5://127.0.0.1:9050").unwrap();
        assert_eq!(
            (p.kind, p.host.as_str(), p.port, p.auth.clone()),
            (Kind::Socks5, "127.0.0.1", 9050, None)
        );
        assert!(p.isolates_connections());
        let p = Proxy::parse("socks5h://tor:pass@[::1]").unwrap();
        assert_eq!(
            (p.kind, p.host.as_str(), p.port),
            (Kind::Socks5, "::1", 1080)
        );
        assert_eq!(p.auth, Some(("tor".into(), "pass".into())));
        assert!(!p.isolates_connections());

        assert!(Proxy::parse("socks4://x:1").is_err());
        assert!(Proxy::parse("https://x:1").is_err());
        assert!(Proxy::parse("http://:8080").is_err());
        assert!(Proxy::parse(&format!("socks5://{}:x@h", "u".repeat(256))).is_err());
    }

    /// What a SOCKS5 server saw of one connection.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Seen {
        method: u8,
        login: Option<(String, String)>,
        atyp: u8,
        host: String,
        port: u16,
    }

    /// A small SOCKS5 server: it accepts the login when offered, records
    /// what it was asked for, and pipes every connection to `target`
    /// whatever the name; `refuse` makes it answer "connection refused".
    async fn socks5_server(
        target: std::net::SocketAddr,
        refuse: bool,
    ) -> (u16, Arc<Mutex<Vec<Seen>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let (mut client, _) = listener.accept().await.unwrap();
                let log = log.clone();
                tokio::spawn(async move {
                    let mut head = [0u8; 2];
                    client.read_exact(&mut head).await.unwrap();
                    assert_eq!(head[0], SOCKS_VERSION);
                    let mut methods = vec![0u8; head[1] as usize];
                    client.read_exact(&mut methods).await.unwrap();
                    let method = if methods.contains(&SOCKS_USER_PASS) {
                        SOCKS_USER_PASS
                    } else {
                        SOCKS_NO_AUTH
                    };
                    client.write_all(&[SOCKS_VERSION, method]).await.unwrap();
                    let mut login = None;
                    if method == SOCKS_USER_PASS {
                        let mut v = [0u8; 2];
                        client.read_exact(&mut v).await.unwrap();
                        let mut user = vec![0u8; v[1] as usize];
                        client.read_exact(&mut user).await.unwrap();
                        let mut plen = [0u8; 1];
                        client.read_exact(&mut plen).await.unwrap();
                        let mut pass = vec![0u8; plen[0] as usize];
                        client.read_exact(&mut pass).await.unwrap();
                        login = Some((
                            String::from_utf8(user).unwrap(),
                            String::from_utf8(pass).unwrap(),
                        ));
                        client.write_all(&[1, 0]).await.unwrap();
                    }
                    let mut req = [0u8; 4];
                    client.read_exact(&mut req).await.unwrap();
                    assert_eq!(&req[..3], &[SOCKS_VERSION, SOCKS_CONNECT, 0]);
                    let host = match req[3] {
                        SOCKS_ATYP_IPV4 => {
                            let mut a = [0u8; 4];
                            client.read_exact(&mut a).await.unwrap();
                            std::net::Ipv4Addr::from(a).to_string()
                        }
                        SOCKS_ATYP_DOMAIN => {
                            let mut len = [0u8; 1];
                            client.read_exact(&mut len).await.unwrap();
                            let mut name = vec![0u8; len[0] as usize];
                            client.read_exact(&mut name).await.unwrap();
                            String::from_utf8(name).unwrap()
                        }
                        other => panic!("unexpected address type {other}"),
                    };
                    let mut p = [0u8; 2];
                    client.read_exact(&mut p).await.unwrap();
                    log.lock().unwrap().push(Seen {
                        method,
                        login,
                        atyp: req[3],
                        host,
                        port: u16::from_be_bytes(p),
                    });
                    if refuse {
                        client
                            .write_all(&[SOCKS_VERSION, 0x05, 0, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                            .await
                            .unwrap();
                        return;
                    }
                    let mut upstream = TcpStream::connect(target).await.unwrap();
                    // A domain-typed bound address, to exercise that branch.
                    client
                        .write_all(&[SOCKS_VERSION, 0, 0, SOCKS_ATYP_DOMAIN, 2, b'o', b'k', 0, 0])
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (port, seen)
    }

    async fn echo_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn socks5_tunnels_by_name_with_fresh_credentials_per_connection() {
        let echo = echo_server().await;
        let (port, seen) = socks5_server(echo, false).await;
        let proxy = Proxy::parse(&format!("socks5://127.0.0.1:{port}")).unwrap();

        for _ in 0..2 {
            let mut stream = proxy.connect("relay.example", 443).await.unwrap();
            stream.write_all(b"hello through socks").await.unwrap();
            let mut back = [0u8; 19];
            stream.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"hello through socks");
        }
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        for s in &seen {
            // The name went to the proxy as a name, and it was asked to log in.
            assert_eq!(
                (s.atyp, s.host.as_str(), s.port),
                (SOCKS_ATYP_DOMAIN, "relay.example", 443)
            );
            assert_eq!(s.method, SOCKS_USER_PASS);
            assert!(s.login.is_some());
        }
        assert_ne!(
            seen[0].login, seen[1].login,
            "each connection gets its own circuit"
        );
    }

    #[tokio::test]
    async fn socks5_refusals_and_configured_logins_are_reported() {
        let echo = echo_server().await;
        let (port, seen) = socks5_server(echo, false).await;
        // An address literal goes as an address; configured credentials
        // are used as they are.
        let proxy = Proxy::parse(&format!("socks5://me:secret@127.0.0.1:{port}")).unwrap();
        let mut stream = proxy.connect("127.0.0.1", 7777).await.unwrap();
        stream.write_all(b"x").await.unwrap();
        let mut back = [0u8; 1];
        stream.read_exact(&mut back).await.unwrap();
        let last = seen.lock().unwrap().last().cloned().unwrap();
        assert_eq!(last.login, Some(("me".into(), "secret".into())));
        assert_eq!(
            (last.atyp, last.host.as_str(), last.port),
            (SOCKS_ATYP_IPV4, "127.0.0.1", 7777)
        );

        let (port, _) = socks5_server(echo, true).await;
        let proxy = Proxy::parse(&format!("socks5://127.0.0.1:{port}")).unwrap();
        let err = proxy.connect("relay.example", 443).await.unwrap_err();
        assert!(err.to_string().contains("connection refused"), "{err:#}");
    }
}
