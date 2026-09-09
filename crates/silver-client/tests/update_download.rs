//! `silver update` fetches a binary and refuses everything it should.
//!
//! A stand-in releases page behind TLS serves a release, an asset, a
//! `SHA256SUMS` and a signature, and each test breaks one of them. The
//! checks are the real ones: nothing here reaches inside the client to
//! decide the answer.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use sha2::{Digest, Sha256};
use silver_client::ConnectOptions;
use silver_client::update::{self, MINISIGN_PUB, client_asset_name, target_triple};

/// What the stand-in serves, so each test can spoil one part of it.
#[derive(Clone)]
struct Page {
    /// The bytes of the client asset.
    binary: Vec<u8>,
    /// The digest the API reports, which a test may make disagree.
    api_digest: String,
    /// The `SHA256SUMS` body.
    sums: String,
    /// The signature body, when the release has one.
    signature: Option<String>,
    /// Where the asset URL points, for the redirect tests.
    asset_path: String,
    /// Filled in once the server is listening; the handlers need it to
    /// write absolute URLs into the release description.
    port: Arc<std::sync::OnceLock<u16>>,
}

impl Page {
    fn port(&self) -> u16 {
        *self.port.get().expect("the server is listening")
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A working release, which each test then spoils in one way.
fn good_page(version: &str) -> Page {
    // A "binary" that really runs: a script that prints a version the way
    // the client does. The download has to be runnable by the time the
    // caller asks it its version, and a fake that is never executed
    // cannot show that -- which is how a download left at 0644 shipped in
    // 0.12.0 and made every update fail at that step.
    let binary = format!("#!/bin/sh\necho 'silver {version}'\n").into_bytes();
    let digest = sha256_hex(&binary);
    let name = client_asset_name(version);
    Page {
        api_digest: digest.clone(),
        sums: format!(
            "{digest}  {name}\n\
             {}  silver-messenger-v{version}-{}.tar.gz\n",
            "0".repeat(64),
            target_triple()
        ),
        binary,
        signature: None,
        asset_path: "/asset".into(),
        port: Arc::new(std::sync::OnceLock::new()),
    }
}

async fn serve(page: Page) -> (u16, tempfile::NamedTempFile, Arc<Page>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.signing_key.serialize_pem();
    let config = RustlsConfig::from_pem(cert_pem.clone().into_bytes(), key_pem.into_bytes())
        .await
        .unwrap();

    let handle = Handle::new();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    // The handlers need the port to write absolute URLs, and the port is
    // only known once the server is listening, so it is shared and
    // filled in below -- before any request can arrive.
    let port_cell = page.port.clone();
    let state = Arc::new(page);

    let router = Router::new()
        .route(
            "/releases/latest",
            get(|State(p): State<Arc<Page>>| async move {
                let name = client_asset_name("9.9.9");
                let mut assets = vec![format!(
                    r#"{{"name":"{name}","digest":"sha256:{}","browser_download_url":"https://localhost:{}{}"}}"#,
                    p.api_digest, p.port(), p.asset_path
                ), format!(
                    r#"{{"name":"SHA256SUMS","browser_download_url":"https://localhost:{}/sums"}}"#,
                    p.port()
                )];
                if p.signature.is_some() {
                    assets.push(format!(
                        r#"{{"name":"SHA256SUMS.minisig","browser_download_url":"https://localhost:{}/sig"}}"#,
                        p.port()
                    ));
                }
                format!(
                    r#"{{"tag_name":"v9.9.9","html_url":"https://localhost/r","assets":[{}]}}"#,
                    assets.join(",")
                )
            }),
        )
        .route(
            "/asset",
            get(|State(p): State<Arc<Page>>| async move { p.binary.clone() }),
        )
        .route(
            "/sums",
            get(|State(p): State<Arc<Page>>| async move { p.sums.clone() }),
        )
        .route(
            "/sig",
            get(|State(p): State<Arc<Page>>| async move {
                p.signature.clone().unwrap_or_default()
            }),
        )
        // A redirect that stays here, and one that leaves.
        .route(
            "/redirect-local",
            get(|| async { Redirect::temporary("/asset").into_response() }),
        )
        .route(
            "/redirect-away",
            get(|| async {
                Redirect::temporary("https://example.invalid/asset").into_response()
            }),
        )
        .with_state(state.clone());

    tokio::spawn(
        axum_server::bind_rustls(addr, config)
            .handle(handle.clone())
            .serve(router.into_make_service()),
    );
    let bound = handle.listening().await.expect("server bound");
    let port = bound.port();
    let _ = port_cell.set(port);

    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(cert_pem.as_bytes()).unwrap();
    (port, ca, state)
}

struct Fixture {
    options: ConnectOptions,
    url: String,
    dir: tempfile::TempDir,
    _ca: tempfile::NamedTempFile,
}

async fn fixture(page: Page) -> Fixture {
    let (port, ca, _state) = serve(page).await;
    Fixture {
        options: ConnectOptions {
            extra_ca_certs: vec![ca.path().to_path_buf()],
            ..Default::default()
        },
        url: format!("https://localhost:{port}/releases/latest"),
        dir: tempfile::tempdir().unwrap(),
        _ca: ca,
    }
}

/// Fetch and check, returning whatever the client decided.
///
/// Against the key compiled in, which is the project's own: these can
/// show that a release is refused and never that one is accepted, since
/// producing a signature this key accepts is the thing it exists to
/// prevent. [`try_download_with`] is for the accepting half.
async fn try_download(f: &Fixture) -> anyhow::Result<update::Downloaded> {
    let release = update::latest_release(&f.url, &f.options).await?;
    update::download_client(&release, &f.options, f.dir.path()).await
}

/// Fetch and check against `key` instead.
async fn try_download_with(f: &Fixture, key: &str) -> anyhow::Result<update::Downloaded> {
    let release = update::latest_release(&f.url, &f.options).await?;
    update::download_client_with_key(&release, &f.options, f.dir.path(), key).await
}

/// A minisign key pair, so a test can sign what it serves.
///
/// minisign is Ed25519 over BLAKE2b-512 of the message, with the halves
/// wrapped in its own small format: the public key is
/// `alg || key_id || public`, the signature file is a comment, then
/// `alg || key_id || signature`, then a trusted comment, then a signature
/// over the first signature and that comment.
struct SigningKey {
    signing: ed25519_dalek::SigningKey,
    key_id: [u8; 8],
}

impl SigningKey {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let mut key_id = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key_id);
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(&seed),
            key_id,
        }
    }

    /// The `minisign.pub` body: what would be compiled in.
    fn public(&self) -> String {
        let mut bin = Vec::with_capacity(42);
        bin.extend_from_slice(b"ED");
        bin.extend_from_slice(&self.key_id);
        bin.extend_from_slice(self.signing.verifying_key().as_bytes());
        base64(&bin)
    }

    /// A `.minisig` over `message`.
    fn sign(&self, message: &[u8]) -> String {
        use blake2::Digest as _;
        use ed25519_dalek::Signer as _;
        let hashed = blake2::Blake2b512::digest(message);
        let signature = self.signing.sign(&hashed).to_bytes();

        let mut bin = Vec::with_capacity(74);
        bin.extend_from_slice(b"ED");
        bin.extend_from_slice(&self.key_id);
        bin.extend_from_slice(&signature);

        let trusted = "trusted comment: signed by the test";
        let mut global = Vec::new();
        global.extend_from_slice(&signature);
        global.extend_from_slice(trusted.trim_start_matches("trusted comment: ").as_bytes());
        let global_signature = self.signing.sign(&global).to_bytes();

        format!(
            "untrusted comment: minisign signature\n{}\n{trusted}\n{}\n",
            base64(&bin),
            base64(&global_signature)
        )
    }
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 0x3f] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Nothing may be left behind by a refusal.
fn nothing_left(f: &Fixture) {
    let left: Vec<_> = std::fs::read_dir(f.dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "a refused update left {left:?} behind");
}

#[tokio::test]
async fn a_good_release_is_fetched_and_checked() {
    let key = SigningKey::new();
    let mut page = good_page("9.9.9");
    page.signature = Some(key.sign(page.sums.as_bytes()));
    let want = sha256_hex(&page.binary);
    let f = fixture(page).await;

    let got = try_download_with(&f, &key.public()).await.unwrap();
    assert_eq!(got.sha256, want);
    assert!(got.path.exists());

    // The download must be runnable where it lands: the last check before
    // a swap is running it, and that happens before anything copies the
    // replaced binary's mode over it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&got.path).unwrap().permissions().mode();
        assert!(mode & 0o100 != 0, "the download is not runnable: {mode:o}");
        assert!(
            mode & 0o077 == 0,
            "the download is readable by others: {mode:o}"
        );
    }
    let out = std::process::Command::new(&got.path)
        .arg("--version")
        .output();
    let out = out.expect("the download runs");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("9.9.9"),
        "the download reports its version: {out:?}"
    );
}

/// A build with no `minisign.pub` has nothing to check a release
/// against: the digest on the releases page and the digest in
/// `SHA256SUMS` are both answers from the host serving the bytes, so they
/// agree with each other for anything that host cares to hand out. This
/// used to download it, run it, swap it in, and print a line afterwards
/// saying no signature had been checked -- a note in the log of a machine
/// already running someone else's code. The comment on `MINISIGN_PUB`
/// said it refused; now it does, and before it fetches anything.
#[tokio::test]
async fn a_build_with_no_signing_key_refuses_to_update() {
    let key = SigningKey::new();
    let mut page = good_page("9.9.9");
    // Everything else about the release is in order, including a
    // signature -- there is just no key here to check it with.
    page.signature = Some(key.sign(page.sums.as_bytes()));
    let f = fixture(page).await;

    let err = try_download_with(&f, "").await.unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("no minisign.pub") && text.contains("will not install"),
        "a keyless build should refuse and say why, got: {text}"
    );
    nothing_left(&f);
}

/// The signature has to be the one this client's key made, not merely a
/// well-formed one: a release host that can serve the binary can serve a
/// signature over it too.
#[tokio::test]
async fn a_signature_by_another_key_is_refused() {
    let theirs = SigningKey::new();
    let mut page = good_page("9.9.9");
    page.signature = Some(theirs.sign(page.sums.as_bytes()));
    let f = fixture(page).await;

    let ours = SigningKey::new();
    let err = try_download_with(&f, &ours.public()).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("signature"),
        "a signature by the wrong key should be refused, got: {err:#}"
    );
    nothing_left(&f);
}

/// A signature over something else does not carry to this release.
#[tokio::test]
async fn a_signature_over_other_bytes_is_refused() {
    let key = SigningKey::new();
    let mut page = good_page("9.9.9");
    page.signature = Some(key.sign(b"some other SHA256SUMS entirely"));
    let f = fixture(page).await;

    let err = try_download_with(&f, &key.public()).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("signature"),
        "a signature over other bytes should be refused, got: {err:#}"
    );
    nothing_left(&f);
}

#[tokio::test]
async fn an_unsigned_release_is_refused_when_a_key_is_compiled_in() {
    if MINISIGN_PUB.is_empty() {
        return;
    }
    let f = fixture(good_page("9.9.9")).await;
    let err = try_download(&f).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("not signed"),
        "an unsigned release should be refused, got: {err:#}"
    );
    nothing_left(&f);
}

#[tokio::test]
async fn a_digest_the_page_disagrees_with_is_refused() {
    let mut page = good_page("9.9.9");
    // The API says one thing; the bytes are another.
    page.api_digest = "1".repeat(64);
    let f = fixture(page).await;
    let err = try_download(&f).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("not what the releases page describes"),
        "{err:#}"
    );
    nothing_left(&f);
}

#[tokio::test]
async fn a_checksum_file_that_disagrees_with_the_page_is_refused() {
    let mut page = good_page("9.9.9");
    // The API digest matches the bytes, but SHA256SUMS does not: one of
    // the two has been tampered with and there is no way to tell which.
    page.sums = format!("{}  {}\n", "2".repeat(64), client_asset_name("9.9.9"));
    let f = fixture(page).await;
    let err = try_download(&f).await.unwrap_err();
    assert!(format!("{err:#}").contains("disagree"), "{err:#}");
    nothing_left(&f);
}

#[tokio::test]
async fn a_release_that_lists_no_checksum_for_the_asset_is_refused() {
    let mut page = good_page("9.9.9");
    page.sums = "nothing about this asset\n".into();
    let f = fixture(page).await;
    let err = try_download(&f).await.unwrap_err();
    assert!(format!("{err:#}").contains("does not list"), "{err:#}");
    nothing_left(&f);
}

#[tokio::test]
async fn a_redirect_off_the_host_is_refused_and_one_that_stays_is_followed() {
    // Away: nothing is downloaded.
    let mut page = good_page("9.9.9");
    page.asset_path = "/redirect-away".into();
    let f = fixture(page).await;
    let err = try_download(&f).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("not part of it"),
        "a redirect off the host should be refused, got: {err:#}"
    );
    nothing_left(&f);

    // Here: followed, and the bytes arrive.
    let mut page = good_page("9.9.9");
    page.asset_path = "/redirect-local".into();
    let want = sha256_hex(&page.binary);
    let f = fixture(page).await;
    match try_download(&f).await {
        Ok(got) => assert_eq!(got.sha256, want),
        // With a key compiled in this stops at the missing signature,
        // which is after the redirect was followed.
        Err(e) => assert!(format!("{e:#}").contains("not signed"), "{e:#}"),
    }
}

#[tokio::test]
async fn a_release_without_the_asset_for_this_platform_says_so() {
    let page = good_page("9.9.9");
    let f = fixture(page).await;
    // Ask for a version whose asset name is not the one served.
    let mut release = update::latest_release(&f.url, &f.options).await.unwrap();
    release.tag = "v8.8.8".into();
    let err = update::download_client(&release, &f.options, f.dir.path())
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("carries no silver-v8.8.8"),
        "{err:#}"
    );
    nothing_left(&f);
}

#[tokio::test]
async fn the_asset_list_survives_a_page_that_lists_nothing() {
    let f = fixture(good_page("9.9.9")).await;
    let release = update::latest_release(&f.url, &f.options).await.unwrap();
    assert_eq!(release.tag, "v9.9.9");
    assert!(release.asset("SHA256SUMS").is_some());
    assert!(release.asset("nothing-like-this").is_none());
}

/// A releases page (or a TLS proxy in front of one) that ends the body by
/// closing the socket without first sending TLS close_notify. rustls
/// reports that close as an `UnexpectedEof`; the client must take it as
/// the end of the answer it already received, not a failure. Corporate
/// middleboxes close this way, and it left `silver update` unable to even
/// check for a release from behind one.
#[tokio::test]
async fn a_close_without_close_notify_is_the_end_of_the_answer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_pem = certified.cert.pem();
    let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        // Read the request up to its blank line, then answer.
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while !seen.ends_with(b"\r\n\r\n") {
            if tls.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            seen.push(byte[0]);
        }
        let body = br#"{"tag_name":"v9.9.9","html_url":"https://localhost/r","assets":[]}"#;
        let mut answer = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n".to_vec();
        answer.extend_from_slice(body);
        tls.write_all(&answer).await.unwrap();
        tls.flush().await.unwrap();
        // Drop without shutdown: no close_notify is sent, so the client
        // sees the TCP close as an abrupt end. This is the case under test.
        drop(tls);
    });

    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(cert_pem.as_bytes()).unwrap();
    let options = ConnectOptions {
        extra_ca_certs: vec![ca.path().to_path_buf()],
        ..Default::default()
    };
    let url = format!("https://localhost:{port}/releases/latest");
    let release = update::latest_release(&url, &options)
        .await
        .expect("an answer that ends at an unclean close is still an answer");
    assert_eq!(release.tag, "v9.9.9");
}
