//! Administration over a local Unix socket: `silver-relay admin ...` talks
//! HTTP to a running relay through a socket file that only its owner and
//! root can open, so nothing about administration is reachable from the
//! network and no credential is involved beyond file permissions.
//!
//! What it offers is what an operator needs and no more: the counters and
//! the store's numbers, the identities under their log pseudonyms with
//! mailbox sizes and prekey deposits, eviction, bans on addresses and
//! identities, and the invite token. Nothing here reads a message or a
//! key: the store holds only ciphertext and public keys, and the listing
//! shows what the relay already knows about each identity.

use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::tls::{self, CertStore};
use crate::{BanRow, BanTarget, CounterSnapshot, IdentityRow, RelayState, Removed, Stats};

/// Where the installer puts the socket; `silver-relay admin` looks there
/// unless told otherwise.
pub const DEFAULT_SOCKET: &str = "/run/silver-relay/admin.sock";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub uptime_secs: u64,
    pub online: usize,
    pub counters: CounterSnapshot,
    pub stats: Stats,
    pub auth_failures: u64,
    pub anonymous_submissions: u64,
    pub invite_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsStatus {
    /// Unix milliseconds; `None` while no certificate is being served.
    pub certificate_expires_at_ms: Option<u64>,
    pub acme_failures: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evicted {
    pub who: String,
    pub removed: Removed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteToken {
    pub token: Option<String>,
}

#[derive(Clone)]
struct AdminState {
    state: Arc<RelayState>,
    tls: Option<Arc<CertStore>>,
}

type Failure = (StatusCode, String);

fn internal(e: anyhow::Error) -> Failure {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
}

fn status(state: &RelayState, tls: Option<&CertStore>) -> Status {
    Status {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_secs: state.uptime().as_secs(),
        online: state.online_count(),
        counters: state.counters(),
        stats: state.stats(),
        auth_failures: state.auth_failures().total(),
        anonymous_submissions: state.anonymous_submission_count(),
        invite_required: state.invite_token().is_some(),
        tls: tls.map(|store| TlsStatus {
            certificate_expires_at_ms: store
                .current()
                .and_then(|k| tls::not_after(&k.cert[0]).ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64),
            acme_failures: store.acme_failures(),
        }),
    }
}

async fn get_status(State(a): State<AdminState>) -> Json<Status> {
    Json(status(&a.state, a.tls.as_deref()))
}

async fn get_identities(State(a): State<AdminState>) -> Result<Json<Vec<IdentityRow>>, Failure> {
    a.state.identities().map(Json).map_err(internal)
}

fn resolve(state: &RelayState, who: &str) -> Result<crate::UserId, Failure> {
    match state.resolve(who).map_err(internal)? {
        Some(user) => Ok(user),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("no identity is known as {who}"),
        )),
    }
}

async fn post_evict(
    State(a): State<AdminState>,
    UrlPath(who): UrlPath<String>,
) -> Result<Json<Evicted>, Failure> {
    let user = resolve(&a.state, &who)?;
    let removed = a.state.evict(&user).map_err(internal)?;
    Ok(Json(Evicted {
        who: a.state.who(&user),
        removed,
    }))
}

fn target(state: &RelayState, kind: &str, key: &str) -> Result<BanTarget, Failure> {
    match kind {
        "address" => key.parse().map(BanTarget::Address).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!("{key} is not an IP address"),
            )
        }),
        "identity" => resolve(state, key).map(BanTarget::Identity),
        other => Err((
            StatusCode::BAD_REQUEST,
            format!("a ban is on an address or an identity, not {other}"),
        )),
    }
}

async fn get_bans(State(a): State<AdminState>) -> Result<Json<Vec<BanRow>>, Failure> {
    a.state.bans().map(Json).map_err(internal)
}

async fn post_ban(
    State(a): State<AdminState>,
    UrlPath((kind, key)): UrlPath<(String, String)>,
    note: String,
) -> Result<StatusCode, Failure> {
    let target = target(&a.state, &kind, &key)?;
    a.state.ban(&target, note.trim()).map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_ban(
    State(a): State<AdminState>,
    UrlPath((kind, key)): UrlPath<(String, String)>,
) -> Result<StatusCode, Failure> {
    let target = target(&a.state, &kind, &key)?;
    match a.state.unban(&target).map_err(internal)? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err((
            StatusCode::NOT_FOUND,
            format!("{} is not banned", target.key()),
        )),
    }
}

/// Twenty-four characters from the operating system's randomness, in the
/// alphabet an invite link can carry.
fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 18];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Require the token in the body from now on, or a fresh random one when
/// the body is empty.
async fn post_invite(
    State(a): State<AdminState>,
    body: String,
) -> Result<Json<InviteToken>, Failure> {
    let token = match body.trim() {
        "" => random_token(),
        given => given.to_owned(),
    };
    a.state
        .set_invite_token(Some(token.clone()))
        .map_err(internal)?;
    Ok(Json(InviteToken { token: Some(token) }))
}

/// Require no token from now on.
async fn delete_invite(State(a): State<AdminState>) -> Result<Json<InviteToken>, Failure> {
    a.state.set_invite_token(None).map_err(internal)?;
    Ok(Json(InviteToken { token: None }))
}

/// Forget the runtime choice; the command line's token applies.
async fn reset_invite(State(a): State<AdminState>) -> Result<Json<InviteToken>, Failure> {
    a.state.forget_invite_token().map_err(internal)?;
    Ok(Json(InviteToken {
        token: a.state.invite_token(),
    }))
}

/// The routes, for the socket server and for tests.
pub fn router(state: Arc<RelayState>, tls: Option<Arc<CertStore>>) -> Router {
    Router::new()
        .route("/status", get(get_status))
        .route("/identities", get(get_identities))
        .route("/evict/{who}", post(post_evict))
        .route("/bans", get(get_bans))
        .route("/bans/{kind}/{key}", post(post_ban).delete(delete_ban))
        .route("/invite", post(post_invite).delete(delete_invite))
        .route("/invite/reset", post(reset_invite))
        .with_state(AdminState { state, tls })
}

/// Serve the administration on a Unix socket at `path`, readable and
/// writable by the relay's user only, until the task is dropped.
#[cfg(unix)]
pub async fn serve_unix(
    path: std::path::PathBuf,
    state: Arc<RelayState>,
    tls: Option<Arc<CertStore>>,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // A socket file left by an earlier run would refuse the bind.
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing the old {}", path.display())),
    }
    let listener = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("binding the admin socket {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;
    axum::serve(listener, router(state, tls)).await?;
    Ok(())
}

/// One request to the relay's admin socket: the status code and the body,
/// as JSON when the relay sent JSON and as a string otherwise.
#[cfg(unix)]
pub async fn request(
    socket: &Path,
    method: &str,
    path: &str,
    body: &str,
) -> anyhow::Result<(u16, serde_json::Value)> {
    use anyhow::Context as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| {
            format!(
                "connecting to the admin socket {} (is the relay running with --admin-socket, and are you root or its user?)",
                socket.display()
            )
        })?;
    let request = format!(
        "{method} {path} HTTP/1.0\r\nHost: relay\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .context("the relay sent something other than an HTTP response")?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("the relay's response has no status")?;
    let value =
        serde_json::from_str(body).unwrap_or_else(|_| serde_json::Value::String(body.to_owned()));
    Ok((status, value))
}

#[cfg(not(unix))]
pub async fn request(
    _socket: &Path,
    _method: &str,
    _path: &str,
    _body: &str,
) -> anyhow::Result<(u16, serde_json::Value)> {
    anyhow::bail!("the admin socket is a Unix socket; this build has none")
}
