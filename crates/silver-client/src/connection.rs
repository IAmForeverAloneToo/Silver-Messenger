//! Background relay connection with reconnect, auth and envelope handling.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use silver_protocol::wire::{ClientFrame, ErrorCode, ServerFrame, auth_signature, feature};

use crate::CAPABILITIES;
use crate::files::{self, FileInfo};
use crate::outbox::Outbox;
use crate::proxy::Proxy;
use crate::sessions::{SessionError, SessionInfo, SharedSessions};
use crate::submitter::{SubmitEvent, Submitter};
use crate::tls::{ConnectOptions, Connectors, connectors};
use silver_protocol::{
    Body, Content, Envelope, Identity, KeyBundle, Message, ProtocolError, Sequence, UserId, now_ms,
    open_bytes, seal_bytes,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use tracing::{debug, info, warn};

pub const DEFAULT_RELAY_URL: &str = "ws://127.0.0.1:7777/ws";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// How long to wait before resending the outbox after the relay rate-limits us.
const RATE_LIMIT_RETRY: Duration = Duration::from_secs(5);
/// How often to look a v1 contact up again in case they now publish prekeys.
const UPGRADE_CHECK: Duration = Duration::from_secs(3600);
/// Publishes per connection in answer to a low prekey deposit.
const MAX_REPUBLISH: u32 = 2;

/// Things the connection task reports to the front end.
#[derive(Debug)]
pub enum ClientEvent {
    /// Authenticated and our key bundle is published.
    Connected { relay_url: String },
    /// The connection dropped or could not be made; another attempt follows
    /// after `retry_in`.
    Disconnected { reason: String, retry_in: Duration },
    /// A decrypted, signature-verified incoming message.
    Message(Box<Message>),
    /// A forward-secret session with `peer` came into being.
    SessionEstablished { peer: UserId, initiated_by_us: bool },
    /// An envelope from `from` was authentic but its session-encrypted body
    /// could not be read, usually because one side lost its session state.
    /// Sending them a message starts a fresh session.
    Undecryptable {
        from: UserId,
        id: String,
        reason: String,
    },
    /// The relay accepted the envelope with this id.
    Sent { id: String },
    /// The relay refused the envelope with this id for good (for example the
    /// recipient's mailbox is full); it has been dropped from the outbox.
    Rejected { id: String, reason: String },
    /// A non-fatal problem worth surfacing (undecryptable envelope, relay error).
    Error(String),
}

/// Ids of envelopes the relay has not accepted yet, shared with the front end.
type PendingIds = Arc<Mutex<Vec<String>>>;

fn sync_pending(pending: &PendingIds, outbox: &Outbox) {
    *pending.lock().unwrap_or_else(|e| e.into_inner()) = outbox.ids();
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("not connected to relay")]
    NotConnected,
    #[error("relay error: {0}")]
    Relay(String),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("{0}")]
    Session(#[from] SessionError),
    #[error("they have not published a key yet (they need to run Silver Messenger once)")]
    NoKey,
    #[error("{0}")]
    File(String),
    #[error("file transfer failed: {0}")]
    Blob(String),
    #[error("timed out waiting for relay")]
    Timeout,
    #[error("client task has stopped")]
    Stopped,
}

enum Command {
    Send {
        envelope: Envelope,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    Lookup {
        user_id: UserId,
        reply: oneshot::Sender<Result<Option<KeyBundle>, ClientError>>,
    },
    /// Put every chunk of an encrypted file on the relay.
    Upload {
        blob: String,
        chunks: Vec<Vec<u8>>,
        progress: Option<mpsc::Sender<Progress>>,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    /// Fetch every chunk of an encrypted file from the relay.
    Download {
        blob: String,
        total: u32,
        progress: Option<mpsc::Sender<Progress>>,
        reply: oneshot::Sender<Result<Vec<Vec<u8>>, ClientError>>,
    },
    Shutdown,
}

/// How far a file transfer has got, in chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub done: u32,
    pub total: u32,
}

/// Chunks in flight per upload before waiting for acknowledgements.
const UPLOAD_WINDOW: usize = 4;
/// Longest a file transfer may take before it is given up.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);

struct Upload {
    chunks: Vec<Vec<u8>>,
    /// Chunks handed to the transport so far.
    sent: usize,
    acked: usize,
    progress: Option<mpsc::Sender<Progress>>,
    reply: oneshot::Sender<Result<(), ClientError>>,
}

struct Download {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    /// The request has not gone out yet (the anonymous connection was not
    /// ready); sent on `Ready`.
    requested: bool,
    progress: Option<mpsc::Sender<Progress>>,
    reply: oneshot::Sender<Result<Vec<Vec<u8>>, ClientError>>,
}

/// File transfers in progress. They outlive one connection: a transfer
/// asked for while disconnected, or before the relay has taken our bundle,
/// waits, and one cut off by a disconnect carries on over the next
/// connection.
#[derive(Default)]
struct Transfers {
    uploads: HashMap<String, Upload>,
    downloads: HashMap<String, Download>,
}

impl Transfers {
    fn queue_upload(
        &mut self,
        blob: String,
        chunks: Vec<Vec<u8>>,
        progress: Option<mpsc::Sender<Progress>>,
        reply: oneshot::Sender<Result<(), ClientError>>,
    ) {
        self.uploads.insert(
            blob,
            Upload {
                chunks,
                sent: 0,
                acked: 0,
                progress,
                reply,
            },
        );
    }

    fn queue_download(
        &mut self,
        blob: String,
        total: u32,
        progress: Option<mpsc::Sender<Progress>>,
        reply: oneshot::Sender<Result<Vec<Vec<u8>>, ClientError>>,
    ) {
        self.downloads.insert(
            blob,
            Download {
                chunks: vec![None; total as usize],
                received: 0,
                requested: false,
                progress,
                reply,
            },
        );
    }
}

fn report(progress: &Option<mpsc::Sender<Progress>>, done: usize, total: usize) {
    if let Some(tx) = progress {
        let _ = tx.try_send(Progress {
            done: done as u32,
            total: total as u32,
        });
    }
}

/// What [`Client::send_message`] did.
#[derive(Debug)]
pub struct Delivery {
    pub envelope: Envelope,
    /// The bundle the message was sealed for; pin it.
    pub bundle: KeyBundle,
    /// The relay served a different long-term key than the pinned one.
    pub key_changed: bool,
    pub forward_secret: bool,
}

/// Cheap-to-clone handle to the connection task.
#[derive(Clone)]
pub struct Client {
    identity: Arc<Identity>,
    cmd_tx: mpsc::Sender<Command>,
    ev_tx: mpsc::Sender<ClientEvent>,
    pending: PendingIds,
    sessions: Option<SharedSessions>,
    /// When each v1 contact was last checked for an upgrade to prekeys.
    upgrade_checks: Arc<Mutex<HashMap<UserId, Instant>>>,
    /// Features the relay advertised on the last handshake.
    relay_features: Arc<Mutex<Vec<String>>>,
}

impl Client {
    /// Start the connection task. Events arrive on the returned receiver.
    /// Fails only if the options cannot be applied (an unreadable CA file,
    /// a corrupt outbox file); connection problems are reported as events.
    pub fn spawn(
        relay_url: String,
        identity: Arc<Identity>,
        options: ConnectOptions,
    ) -> anyhow::Result<(Self, mpsc::Receiver<ClientEvent>)> {
        let connectors = connectors(&options)?;
        let proxy = options.proxy.as_deref().map(Proxy::parse).transpose()?;
        let outbox = Outbox::load(options.outbox_path.clone(), options.outbox_cipher.clone())?;
        let pending: PendingIds = Arc::new(Mutex::new(outbox.ids()));
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (ev_tx, ev_rx) = mpsc::channel(256);
        let relay_features = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(run(
            Setup {
                relay_url,
                identity: identity.clone(),
                connectors,
                proxy,
                invite_token: options.invite_token.clone(),
                sessions: options.sessions.clone(),
                submit_authenticated: options.submit_authenticated,
                relay_features: relay_features.clone(),
            },
            outbox,
            pending.clone(),
            cmd_rx,
            ev_tx.clone(),
        ));
        Ok((
            Self {
                identity,
                cmd_tx,
                ev_tx,
                pending,
                sessions: options.sessions,
                upgrade_checks: Arc::new(Mutex::new(HashMap::new())),
                relay_features,
            },
            ev_rx,
        ))
    }

    /// Whether the relay advertised a feature (see
    /// [`silver_protocol::wire::feature`]) on the last handshake.
    pub fn relay_supports(&self, feature: &str) -> bool {
        self.relay_features
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|f| f == feature)
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn user_id(&self) -> UserId {
        self.identity.user_id()
    }

    /// Ids of outgoing envelopes the relay has not accepted yet.
    pub fn pending_ids(&self) -> Vec<String> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// The forward-secret session in use with `peer`, if any.
    pub fn session_info(&self, peer: &UserId) -> Option<SessionInfo> {
        self.sessions
            .as_ref()?
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .session_info(peer)
    }

    /// Drop every session with `peer`, for example after a key change.
    pub fn forget_sessions(&self, peer: &UserId) {
        if let Some(sessions) = &self.sessions {
            if let Err(e) = sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .forget(peer)
            {
                warn!("could not drop sessions with {peer}: {e:#}");
            }
        }
    }

    /// Fetch and verify someone's key bundle from the relay.
    pub async fn lookup(&self, user_id: UserId) -> Result<Option<KeyBundle>, ClientError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Lookup { user_id, reply: tx })
            .await
            .map_err(|_| ClientError::Stopped)?;
        let bundle = tokio::time::timeout(REQUEST_TIMEOUT, rx)
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|_| ClientError::NotConnected)??;
        if let Some(b) = &bundle {
            if b.user_id != user_id {
                return Err(ClientError::Relay(
                    "relay returned a bundle for the wrong user".into(),
                ));
            }
            b.verify()?;
        }
        Ok(bundle)
    }

    /// Seal `text` for `to` and queue it for the relay. Resolves once the
    /// envelope is in the outbox, connected or not; [`ClientEvent::Sent`] or
    /// [`ClientEvent::Rejected`] follows once the relay has answered.
    ///
    /// With a session store and a bundle that carries prekeys the message
    /// goes out under a forward-secret session; otherwise as protocol v1.
    pub async fn send_text(&self, to: &KeyBundle, text: String) -> Result<Envelope, ClientError> {
        self.send_text_sequenced(to, text, Sequence::default())
            .await
    }

    /// Like [`Client::send_text`], numbered with `sequence` so the recipient
    /// can detect replays and gaps.
    pub async fn send_text_sequenced(
        &self,
        to: &KeyBundle,
        text: String,
        sequence: Sequence,
    ) -> Result<Envelope, ClientError> {
        self.send_content_sequenced(to, Content::Text { body: text }, sequence)
            .await
    }

    /// Seal any content for `to` and queue it. Every body advertises this
    /// client's [`CAPABILITIES`].
    pub async fn send_content_sequenced(
        &self,
        to: &KeyBundle,
        content: Content,
        sequence: Sequence,
    ) -> Result<Envelope, ClientError> {
        let plain = Body::plain_with_caps(content, now_ms(), sequence, CAPABILITIES).encode()?;
        let body = match &self.sessions {
            Some(sessions) if to.supports_sessions() => {
                let ratchet = sessions.lock().unwrap_or_else(|e| e.into_inner()).encrypt(
                    &self.identity,
                    to,
                    &plain,
                    now_ms(),
                )?;
                if ratchet.init.is_some() && ratchet.message.header.n == 0 {
                    let _ = self
                        .ev_tx
                        .send(ClientEvent::SessionEstablished {
                            peer: to.user_id,
                            initiated_by_us: true,
                        })
                        .await;
                }
                Body::Ratchet(ratchet).encode()?
            }
            _ => plain,
        };
        let envelope = seal_bytes(&self.identity, to, &body)?;
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Send {
                envelope: envelope.clone(),
                reply: tx,
            })
            .await
            .map_err(|_| ClientError::Stopped)?;
        rx.await.map_err(|_| ClientError::NotConnected)??;
        Ok(envelope)
    }

    /// Send `text` to `peer`, fetching their current bundle from the relay
    /// when that is needed: when nothing is pinned, when a forward-secret
    /// session has to be started (it needs fresh prekeys), or now and then
    /// for a contact who did not publish prekeys last time. Falls back to
    /// the pinned bundle when the relay cannot be asked.
    pub async fn send_message(
        &self,
        peer: UserId,
        pinned: Option<KeyBundle>,
        text: String,
        sequence: Sequence,
    ) -> Result<Delivery, ClientError> {
        self.send_content(peer, pinned, Content::Text { body: text }, sequence)
            .await
    }

    /// [`Client::send_message`] for any content.
    pub async fn send_content(
        &self,
        peer: UserId,
        pinned: Option<KeyBundle>,
        content: Content,
        sequence: Sequence,
    ) -> Result<Delivery, ClientError> {
        let needs_fresh = match (&self.sessions, &pinned) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(sessions), Some(bundle)) => {
                let has_session = sessions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .has_session(&peer);
                if has_session {
                    false
                } else if bundle.supports_sessions() {
                    true
                } else {
                    self.upgrade_check_due(&peer)
                }
            }
        };
        let mut bundle = pinned.clone();
        if needs_fresh {
            match self.lookup(peer).await {
                Ok(Some(fresh)) => bundle = Some(fresh),
                Ok(None) => {}
                Err(e) if bundle.is_none() => return Err(e),
                Err(e) => debug!("using the pinned bundle for {peer}: lookup failed: {e}"),
            }
        }
        let bundle = bundle.ok_or(ClientError::NoKey)?;
        let key_changed = pinned
            .as_ref()
            .is_some_and(|p| p.dh_public != bundle.dh_public);
        if key_changed {
            // Sessions were agreed with the old key; they cannot continue.
            self.forget_sessions(&peer);
        }
        let envelope = self
            .send_content_sequenced(&bundle, content, sequence)
            .await?;
        let forward_secret = self.session_info(&peer).is_some();
        Ok(Delivery {
            envelope,
            bundle,
            key_changed,
            forward_secret,
        })
    }

    /// Encrypt the file at `path` and park it on the relay. The returned
    /// description is what to send the recipient (as `Content::File`);
    /// `progress` gets a note per chunk acknowledged.
    pub async fn upload_file(
        &self,
        path: &Path,
        progress: Option<mpsc::Sender<Progress>>,
    ) -> Result<FileInfo, ClientError> {
        if !self.relay_supports(feature::BLOBS) {
            return Err(ClientError::Blob(
                "the relay does not store files (it needs Silver Messenger 0.4.0 or later)".into(),
            ));
        }
        let path = path.to_path_buf();
        let (info, chunks) = tokio::task::spawn_blocking(move || files::prepare(&path))
            .await
            .map_err(|e| ClientError::File(e.to_string()))?
            .map_err(|e| ClientError::File(e.to_string()))?;
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Upload {
                blob: info.blob.clone(),
                chunks,
                progress,
                reply: tx,
            })
            .await
            .map_err(|_| ClientError::Stopped)?;
        tokio::time::timeout(TRANSFER_TIMEOUT, rx)
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|_| ClientError::NotConnected)??;
        Ok(info)
    }

    /// Fetch the file `info` describes, check it, and save it into `dir`
    /// under its own name (never overwriting). Returns where it went.
    pub async fn download_file(
        &self,
        info: &FileInfo,
        dir: &Path,
        progress: Option<mpsc::Sender<Progress>>,
    ) -> Result<PathBuf, ClientError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Download {
                blob: info.blob.clone(),
                total: info.chunks,
                progress,
                reply: tx,
            })
            .await
            .map_err(|_| ClientError::Stopped)?;
        let chunks = tokio::time::timeout(TRANSFER_TIMEOUT, rx)
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|_| ClientError::NotConnected)??;
        let info = info.clone();
        let dir = dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let bytes = files::assemble(&info, &chunks)?;
            files::save(&dir, &info.name, &bytes)
        })
        .await
        .map_err(|e| ClientError::File(e.to_string()))?
        .map_err(|e| ClientError::File(e.to_string()))
    }

    fn upgrade_check_due(&self, peer: &UserId) -> bool {
        let mut checks = self
            .upgrade_checks
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let due = checks
            .get(peer)
            .is_none_or(|at| at.elapsed() >= UPGRADE_CHECK);
        if due {
            checks.insert(*peer, Instant::now());
        }
        due
    }

    /// Close the connection and stop the task.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(Command::Shutdown).await;
    }
}

/// Everything the connection task needs that does not change.
struct Setup {
    relay_url: String,
    identity: Arc<Identity>,
    connectors: Connectors,
    proxy: Option<Proxy>,
    invite_token: Option<String>,
    sessions: Option<SharedSessions>,
    submit_authenticated: bool,
    relay_features: Arc<Mutex<Vec<String>>>,
}

enum Exit {
    Shutdown,
    Disconnected(String),
}

async fn run(
    setup: Setup,
    mut outbox: Outbox,
    pending: PendingIds,
    mut cmd_rx: mpsc::Receiver<Command>,
    ev_tx: mpsc::Sender<ClientEvent>,
) {
    let mut backoff = Duration::from_secs(1);
    let mut transfers = Transfers::default();
    loop {
        let outcome = session(
            &setup,
            &mut outbox,
            &pending,
            &mut transfers,
            &mut cmd_rx,
            &ev_tx,
            &mut backoff,
        )
        .await;
        let reason = match outcome {
            Ok(Exit::Shutdown) => return,
            Ok(Exit::Disconnected(reason)) => reason,
            Err(e) => e.to_string(),
        };
        if ev_tx
            .send(ClientEvent::Disconnected {
                reason,
                retry_in: backoff,
            })
            .await
            .is_err()
        {
            return; // front end is gone
        }

        // Sleep before reconnecting. Sends and transfers are queued
        // meanwhile; lookups need the relay and are refused.
        let sleep = tokio::time::sleep(backoff);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                cmd = cmd_rx.recv() => match cmd {
                    Some(Command::Shutdown) | None => return,
                    Some(Command::Send { envelope, reply }) => {
                        outbox.push(envelope);
                        sync_pending(&pending, &outbox);
                        let _ = reply.send(Ok(()));
                    }
                    Some(Command::Lookup { reply, .. }) => {
                        let _ = reply.send(Err(ClientError::NotConnected));
                    }
                    Some(Command::Upload { blob, chunks, progress, reply }) => {
                        transfers.queue_upload(blob, chunks, progress, reply);
                    }
                    Some(Command::Download { blob, total, progress, reply }) => {
                        transfers.queue_download(blob, total, progress, reply);
                    }
                },
            }
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

type Lookups = HashMap<UserId, Vec<oneshot::Sender<Result<Option<KeyBundle>, ClientError>>>>;

/// Where outgoing envelopes go on this connection.
enum Submission {
    /// On the authenticated connection.
    Authenticated,
    /// On the anonymous submission connection, once it is ready.
    Anonymous(Submitter),
}

/// One authenticated connection, from connect to disconnect.
async fn session(
    setup: &Setup,
    outbox: &mut Outbox,
    pending: &PendingIds,
    transfers: &mut Transfers,
    cmd_rx: &mut mpsc::Receiver<Command>,
    ev_tx: &mpsc::Sender<ClientEvent>,
    backoff: &mut Duration,
) -> anyhow::Result<Exit> {
    let relay_url = setup.relay_url.as_str();
    let identity = setup.identity.as_ref();
    debug!("connecting to {relay_url}");
    let ws = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        open_websocket(
            relay_url,
            setup.connectors.main.clone(),
            setup.proxy.as_ref(),
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timed out"))??;
    let (mut sink, mut stream) = ws.split();

    // --- handshake: challenge -> auth -> auth_ok ---------------------------
    let handshake = async {
        let nonce = match read_frame(&mut stream).await? {
            ServerFrame::Challenge { nonce } => nonce,
            other => anyhow::bail!("expected challenge, got {other:?}"),
        };
        let auth = ClientFrame::Auth {
            user_id: identity.user_id(),
            signature: auth_signature(identity, &nonce),
        };
        sink.send(text(&auth)).await?;
        match read_frame(&mut stream).await? {
            ServerFrame::AuthOk { features, .. } => anyhow::Ok(features),
            ServerFrame::Error { code, message } => {
                anyhow::bail!("auth rejected ({code:?}): {message}")
            }
            other => anyhow::bail!("expected auth_ok, got {other:?}"),
        }
    };
    let features = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| anyhow::anyhow!("handshake timed out"))??;
    let anonymous_offered = features.iter().any(|f| f == feature::ANONYMOUS_SEND);
    *setup
        .relay_features
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = features;

    // Publish our bundle. The relay may interleave queued deliveries before it
    // answers, so `Published` is handled in the main loop; only then are we
    // discoverable and report `Connected`.
    sink.send(text(&publish_frame(setup)?)).await?;
    let mut published = false;
    let mut republished = 0u32;

    // --- steady state ------------------------------------------------------
    let mut lookups: Lookups = HashMap::new();
    let Transfers { uploads, downloads } = transfers;
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.tick().await; // first tick fires immediately; skip it
    // Set when the relay rate-limited us; the outbox is resent at that time.
    let mut retry_at: Option<tokio::time::Instant> = None;
    let mut submission = Submission::Authenticated;

    loop {
        let retry = async {
            match retry_at {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending::<()>().await,
            }
        };
        let submit_event = async {
            match &mut submission {
                Submission::Anonymous(submitter) => submitter.next_event().await,
                Submission::Authenticated => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = retry => {
                retry_at = None;
                if !flush_outbox(&mut sink, &mut submission, outbox).await {
                    return Ok(Exit::Disconnected("resend failed".into()));
                }
            }
            cmd = cmd_rx.recv() => match cmd {
                None | Some(Command::Shutdown) => {
                    let _ = sink.close().await;
                    return Ok(Exit::Shutdown);
                }
                Some(Command::Send { envelope, reply }) => {
                    // Queue first: if the write fails the envelope is resent
                    // on the next connection.
                    outbox.push(envelope.clone());
                    sync_pending(pending, outbox);
                    let _ = reply.send(Ok(()));
                    if published && !submit(&mut sink, &mut submission, envelope).await {
                        return Ok(Exit::Disconnected("send failed".into()));
                    }
                }
                Some(Command::Lookup { user_id, reply }) => {
                    if let Err(e) = sink.send(text(&ClientFrame::Lookup { user_id })).await {
                        let _ = reply.send(Err(ClientError::Relay(e.to_string())));
                        return Ok(Exit::Disconnected("send failed".into()));
                    }
                    lookups.entry(user_id).or_default().push(reply);
                }
                // Transfers asked for before `Published` (the relay replays
                // the mailbox first, and a delivered file is fetched at
                // once) wait for it; `Published` resumes them.
                Some(Command::Upload { blob, chunks, progress, reply }) => {
                    uploads.insert(blob.clone(), Upload { chunks, sent: 0, acked: 0, progress, reply });
                    if published && !pump_upload(&mut sink, &mut submission, &blob, uploads).await {
                        return Ok(Exit::Disconnected("send failed".into()));
                    }
                }
                Some(Command::Download { blob, total, progress, reply }) => {
                    downloads.insert(blob, Download {
                        chunks: vec![None; total as usize],
                        received: 0,
                        requested: false,
                        progress,
                        reply,
                    });
                    if published && !request_downloads(&mut sink, &mut submission, downloads).await {
                        return Ok(Exit::Disconnected("send failed".into()));
                    }
                }
            },
            _ = keepalive.tick() => {
                if sink.send(text(&ClientFrame::Ping)).await.is_err() {
                    return Ok(Exit::Disconnected("keepalive failed".into()));
                }
            }
            event = submit_event => match event {
                Some(SubmitEvent::Ready) => {
                    if let Submission::Anonymous(s) = &mut submission {
                        s.ready = true;
                    }
                    if !flush_outbox(&mut sink, &mut submission, outbox).await
                        || !resume_transfers(&mut sink, &mut submission, uploads, downloads).await
                    {
                        return Ok(Exit::Disconnected("resend failed".into()));
                    }
                }
                Some(SubmitEvent::Blob(frame)) => {
                    if !handle_blob_frame(*frame, &mut sink, &mut submission, uploads, downloads).await {
                        return Ok(Exit::Disconnected("send failed".into()));
                    }
                }
                Some(SubmitEvent::Down { reason }) => {
                    debug!("anonymous submission down: {reason}");
                    if let Submission::Anonymous(s) = &mut submission {
                        s.ready = false;
                    }
                }
                Some(SubmitEvent::Refused) | None => {
                    warn!("submitting on the authenticated connection instead");
                    submission = Submission::Authenticated;
                    if !flush_outbox(&mut sink, &mut submission, outbox).await
                        || !resume_transfers(&mut sink, &mut submission, uploads, downloads).await
                    {
                        return Ok(Exit::Disconnected("resend failed".into()));
                    }
                }
                Some(SubmitEvent::Sent { id }) => {
                    accepted(id, outbox, pending, ev_tx).await;
                }
                Some(SubmitEvent::Rejected { id, code, message }) => {
                    refused(id, code, message, outbox, pending, ev_tx, &mut retry_at).await;
                }
            },
            frame = read_frame(&mut stream) => {
                let frame = match frame {
                    Ok(f) => f,
                    Err(e) => return Ok(Exit::Disconnected(e.to_string())),
                };
                match frame {
                    ServerFrame::Deliver { envelope } => {
                        let id = envelope.id.clone();
                        debug!(%id, "envelope delivered by the relay");
                        deliver(setup, envelope, ev_tx).await;
                        debug!(%id, "envelope handed to the front end; acknowledging");
                        // Ack either way so a poison envelope cannot wedge the mailbox.
                        if sink.send(text(&ClientFrame::Ack { id })).await.is_err() {
                            return Ok(Exit::Disconnected("ack failed".into()));
                        }
                    }
                    ServerFrame::Sent { id } => {
                        accepted(id, outbox, pending, ev_tx).await;
                    }
                    ServerFrame::Rejected { id, code, message } => {
                        refused(id, code, message, outbox, pending, ev_tx, &mut retry_at).await;
                    }
                    ServerFrame::LookupResult { user_id, bundle } => {
                        for reply in lookups.remove(&user_id).unwrap_or_default() {
                            let _ = reply.send(Ok(bundle.clone()));
                        }
                    }
                    frame @ (ServerFrame::BlobAck { .. }
                    | ServerFrame::BlobRejected { .. }
                    | ServerFrame::BlobChunk { .. }) => {
                        if !handle_blob_frame(frame, &mut sink, &mut submission, uploads, downloads).await {
                            return Ok(Exit::Disconnected("send failed".into()));
                        }
                    }
                    ServerFrame::Error { code, message } if !published => {
                        // Our Publish was refused: this connection is useless.
                        return Ok(Exit::Disconnected(format!("{message} ({code:?})")));
                    }
                    ServerFrame::Error { code: ErrorCode::RateLimited, message } => {
                        // A lookup was refused; its caller times out. Say why.
                        let _ = ev_tx
                            .send(ClientEvent::Error(format!("relay: {message}")))
                            .await;
                    }
                    ServerFrame::Error { code, message } => {
                        let _ = ev_tx
                            .send(ClientEvent::Error(format!("relay: {message} ({code:?})")))
                            .await;
                    }
                    ServerFrame::Published => {
                        if !published {
                            published = true;
                            info!("connected to {relay_url} as {}", identity.user_id());
                            *backoff = Duration::from_secs(1);
                            let _ = ev_tx
                                .send(ClientEvent::Connected {
                                    relay_url: relay_url.to_owned(),
                                })
                                .await;
                            if anonymous_offered && !setup.submit_authenticated {
                                submission = Submission::Anonymous(Submitter::spawn(
                                    relay_url.to_owned(),
                                    setup.connectors.anonymous.clone(),
                                    setup.proxy.clone(),
                                ));
                            }
                            // Resend everything the relay has not accepted
                            // yet; it ignores ids it already holds. Transfers
                            // that waited for this connection start now (or
                            // once the anonymous connection is ready).
                            if !flush_outbox(&mut sink, &mut submission, outbox).await
                                || !resume_transfers(&mut sink, &mut submission, uploads, downloads).await
                            {
                                return Ok(Exit::Disconnected("resend failed".into()));
                            }
                        }
                    }
                    ServerFrame::PrekeyStatus { one_time_remaining, consumed } => {
                        let republish = match &setup.sessions {
                            Some(sessions) => sessions
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .apply_prekey_status(one_time_remaining, &consumed, now_ms())
                                .unwrap_or_else(|e| {
                                    warn!("could not record prekey status: {e:#}");
                                    false
                                }),
                            None => false,
                        };
                        if republish && republished < MAX_REPUBLISH {
                            republished += 1;
                            debug!("one-time prekeys ran low ({one_time_remaining} left); publishing more");
                            if sink.send(text(&publish_frame(setup)?)).await.is_err() {
                                return Ok(Exit::Disconnected("publish failed".into()));
                            }
                        }
                    }
                    ServerFrame::Pong => {}
                    ServerFrame::Challenge { .. } | ServerFrame::AuthOk { .. } => {
                        debug!("ignoring unexpected handshake frame mid-session");
                    }
                }
            }
        }
    }
}

/// Our bundle, with prekeys when we keep sessions.
fn publish_frame(setup: &Setup) -> anyhow::Result<ClientFrame> {
    let bundle = match &setup.sessions {
        Some(sessions) => {
            let prekeys = sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .prekeys_for_publish(&setup.identity, now_ms())?;
            setup.identity.key_bundle_with(prekeys)
        }
        None => setup.identity.key_bundle(),
    };
    Ok(ClientFrame::Publish {
        bundle,
        invite: setup.invite_token.clone(),
    })
}

/// What became of a frame handed to [`send_frame`].
#[derive(PartialEq, Eq)]
enum Handed {
    /// Written to a connection.
    Sent,
    /// The anonymous connection is not ready; try again on `Ready`.
    Waiting,
    /// The authenticated connection is broken.
    Broken,
}

/// Hand a frame to the relay on whichever connection submits.
async fn send_frame(sink: &mut WsSink, submission: &mut Submission, frame: ClientFrame) -> Handed {
    match submission {
        Submission::Anonymous(submitter) => {
            if !submitter.ready {
                return Handed::Waiting;
            }
            if submitter.submit(frame).await {
                Handed::Sent
            } else {
                // The task is gone; fall back for good.
                *submission = Submission::Authenticated;
                Handed::Waiting // resent on the next flush
            }
        }
        Submission::Authenticated => {
            if sink.send(text(&frame)).await.is_ok() {
                Handed::Sent
            } else {
                Handed::Broken
            }
        }
    }
}

/// Hand one envelope to the relay on whichever connection submits. `false`
/// means the authenticated connection is broken.
async fn submit(sink: &mut WsSink, submission: &mut Submission, envelope: Envelope) -> bool {
    send_frame(sink, submission, ClientFrame::Send { envelope }).await != Handed::Broken
}

/// Send the next chunks of an upload, keeping [`UPLOAD_WINDOW`] in flight.
/// `false` means the authenticated connection is broken.
async fn pump_upload(
    sink: &mut WsSink,
    submission: &mut Submission,
    blob: &str,
    uploads: &mut HashMap<String, Upload>,
) -> bool {
    let Some(upload) = uploads.get_mut(blob) else {
        return true;
    };
    let total = upload.chunks.len();
    while upload.sent < total && upload.sent - upload.acked < UPLOAD_WINDOW {
        let frame = ClientFrame::BlobPut {
            blob: blob.to_owned(),
            index: upload.sent as u32,
            total: total as u32,
            data: upload.chunks[upload.sent].clone(),
        };
        match send_frame(sink, submission, frame).await {
            Handed::Sent => upload.sent += 1,
            Handed::Waiting => return true,
            Handed::Broken => return false,
        }
    }
    true
}

/// Send `BlobGet` for downloads that have not asked yet.
async fn request_downloads(
    sink: &mut WsSink,
    submission: &mut Submission,
    downloads: &mut HashMap<String, Download>,
) -> bool {
    for (blob, download) in downloads.iter_mut().filter(|(_, d)| !d.requested) {
        let frame = ClientFrame::BlobGet { blob: blob.clone() };
        match send_frame(sink, submission, frame).await {
            Handed::Sent => download.requested = true,
            Handed::Waiting => return true,
            Handed::Broken => return false,
        }
    }
    true
}

/// After the submitting connection changed, push transfers along again.
/// Chunks sent but not acknowledged are sent once more, and every unfinished
/// download is asked for again; the relay ignores duplicate chunks and the
/// client ignores chunks it already has.
async fn resume_transfers(
    sink: &mut WsSink,
    submission: &mut Submission,
    uploads: &mut HashMap<String, Upload>,
    downloads: &mut HashMap<String, Download>,
) -> bool {
    let blobs: Vec<String> = uploads.keys().cloned().collect();
    for blob in blobs {
        if let Some(upload) = uploads.get_mut(&blob) {
            upload.sent = upload.acked;
        }
        if !pump_upload(sink, submission, &blob, uploads).await {
            return false;
        }
    }
    for download in downloads.values_mut() {
        download.requested = false;
    }
    request_downloads(sink, submission, downloads).await
}

/// Apply a relay answer about a blob to the transfer it belongs to.
async fn handle_blob_frame(
    frame: ServerFrame,
    sink: &mut WsSink,
    submission: &mut Submission,
    uploads: &mut HashMap<String, Upload>,
    downloads: &mut HashMap<String, Download>,
) -> bool {
    match frame {
        ServerFrame::BlobAck { blob, complete, .. } => {
            let Some(upload) = uploads.get_mut(&blob) else {
                return true;
            };
            upload.acked += 1;
            let total = upload.chunks.len();
            report(&upload.progress, upload.acked, total);
            if complete || upload.acked >= total {
                if let Some(upload) = uploads.remove(&blob) {
                    let _ = upload.reply.send(Ok(()));
                }
                return true;
            }
            pump_upload(sink, submission, &blob, uploads).await
        }
        ServerFrame::BlobRejected {
            blob,
            code,
            message,
        } => {
            let error = || ClientError::Blob(format!("{message} ({code:?})"));
            if let Some(upload) = uploads.remove(&blob) {
                let _ = upload.reply.send(Err(error()));
            }
            if let Some(download) = downloads.remove(&blob) {
                let _ = download.reply.send(Err(error()));
            }
            true
        }
        ServerFrame::BlobChunk {
            blob,
            index,
            total,
            data,
        } => {
            let Some(download) = downloads.get_mut(&blob) else {
                return true;
            };
            let expected = download.chunks.len();
            if total as usize != expected || index as usize >= expected {
                if let Some(download) = downloads.remove(&blob) {
                    let _ = download.reply.send(Err(ClientError::Blob(
                        "the relay's chunk count does not match the message".into(),
                    )));
                }
                return true;
            }
            let slot = &mut download.chunks[index as usize];
            if slot.is_none() {
                *slot = Some(data);
                download.received += 1;
            }
            report(&download.progress, download.received, expected);
            if download.received == expected {
                if let Some(download) = downloads.remove(&blob) {
                    let chunks = download.chunks.into_iter().flatten().collect();
                    let _ = download.reply.send(Ok(chunks));
                }
            }
            true
        }
        _ => true,
    }
}

/// Resend everything the relay has not accepted yet. It ignores ids it
/// already holds, so this is safe to do after every reconnect.
async fn flush_outbox(sink: &mut WsSink, submission: &mut Submission, outbox: &Outbox) -> bool {
    let queued: Vec<Envelope> = outbox.iter().cloned().collect();
    for envelope in queued {
        if !submit(sink, submission, envelope).await {
            return false;
        }
    }
    true
}

async fn accepted(
    id: String,
    outbox: &mut Outbox,
    pending: &PendingIds,
    ev_tx: &mpsc::Sender<ClientEvent>,
) {
    outbox.remove(&id);
    sync_pending(pending, outbox);
    let _ = ev_tx.send(ClientEvent::Sent { id }).await;
}

async fn refused(
    id: String,
    code: ErrorCode,
    message: String,
    outbox: &mut Outbox,
    pending: &PendingIds,
    ev_tx: &mpsc::Sender<ClientEvent>,
    retry_at: &mut Option<tokio::time::Instant>,
) {
    if code == ErrorCode::RateLimited {
        // Not a verdict on the message: keep it and try again.
        if retry_at.is_none() {
            *retry_at = Some(tokio::time::Instant::now() + RATE_LIMIT_RETRY);
            let _ = ev_tx
                .send(ClientEvent::Error(format!(
                    "the relay is rate limiting; retrying {} queued message(s) in {}s",
                    outbox.iter().count(),
                    RATE_LIMIT_RETRY.as_secs()
                )))
                .await;
        }
        debug!("rate limited on envelope {id}");
        return;
    }
    outbox.remove(&id);
    sync_pending(pending, outbox);
    let _ = ev_tx
        .send(ClientEvent::Rejected {
            id,
            reason: format!("{message} ({code:?})"),
        })
        .await;
}

/// Open an incoming envelope and report what it held.
async fn deliver(setup: &Setup, envelope: Envelope, ev_tx: &mpsc::Sender<ClientEvent>) {
    let id = envelope.id.clone();
    let opened = match open_bytes(&setup.identity, &envelope) {
        Ok(opened) => opened,
        Err(e) => {
            warn!("dropping undecryptable envelope {id}: {e}");
            let _ = ev_tx
                .send(ClientEvent::Error(format!(
                    "could not open envelope {id}: {e}"
                )))
                .await;
            return;
        }
    };
    let from = opened.from;
    let (plain, forward_secret) = match Body::decode(&opened.body) {
        Ok(Body::Plain {
            sent_at_ms,
            sequence,
            content,
            caps,
        }) => {
            let _ = ev_tx
                .send(ClientEvent::Message(Box::new(Message {
                    id,
                    from,
                    to: opened.to,
                    sent_at_ms,
                    sequence,
                    content,
                    forward_secret: false,
                    caps,
                })))
                .await;
            return;
        }
        Ok(Body::Ratchet(body)) => {
            let Some(sessions) = &setup.sessions else {
                let _ = ev_tx
                    .send(ClientEvent::Undecryptable {
                        from,
                        id,
                        reason:
                            "it was sent under a forward-secret session but this client keeps none"
                                .into(),
                    })
                    .await;
                return;
            };
            let result = sessions.lock().unwrap_or_else(|e| e.into_inner()).decrypt(
                &setup.identity,
                from,
                &body,
                now_ms(),
            );
            match result {
                Ok((plain, established)) => {
                    if established {
                        let _ = ev_tx
                            .send(ClientEvent::SessionEstablished {
                                peer: from,
                                initiated_by_us: false,
                            })
                            .await;
                    }
                    (plain, true)
                }
                Err(e) => {
                    warn!("undecryptable session message {id} from {from}: {e}");
                    let _ = ev_tx
                        .send(ClientEvent::Undecryptable {
                            from,
                            id,
                            reason: e.to_string(),
                        })
                        .await;
                    return;
                }
            }
        }
        Err(e) => {
            warn!("malformed body in envelope {id} from {from}: {e}");
            let _ = ev_tx
                .send(ClientEvent::Error(format!(
                    "could not read envelope {id}: {e}"
                )))
                .await;
            return;
        }
    };
    match Body::decode(&plain) {
        Ok(Body::Plain {
            sent_at_ms,
            sequence,
            content,
            caps,
        }) => {
            let _ = ev_tx
                .send(ClientEvent::Message(Box::new(Message {
                    id,
                    from,
                    to: opened.to,
                    sent_at_ms,
                    sequence,
                    content,
                    forward_secret,
                    caps,
                })))
                .await;
        }
        Ok(Body::Ratchet(_)) => {
            let _ = ev_tx
                .send(ClientEvent::Error(format!(
                    "envelope {id} nests a session inside a session; dropped"
                )))
                .await;
        }
        Err(e) => {
            let _ = ev_tx
                .send(ClientEvent::Error(format!(
                    "could not read envelope {id}: {e}"
                )))
                .await;
        }
    }
}

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = futures_util::stream::SplitSink<Ws, WsMessage>;

/// Open the WebSocket, directly or through a CONNECT proxy. TLS (for
/// `wss://`) is always negotiated end to end with the relay by us.
pub(crate) async fn open_websocket(
    url: &str,
    connector: Connector,
    proxy: Option<&Proxy>,
) -> anyhow::Result<Ws> {
    let Some(proxy) = proxy else {
        let (ws, _) =
            tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
                .await
                .map_err(describe_connect_error)?;
        return Ok(ws);
    };
    let request = url.into_client_request().map_err(describe_connect_error)?;
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("relay URL has no host"))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("wss") => 443,
        _ => 80,
    });
    debug!(
        "tunnelling to {host}:{port} via proxy {}:{}",
        proxy.host, proxy.port
    );
    let stream = proxy.connect(&host, port).await?;
    let (ws, _) =
        tokio_tungstenite::client_async_tls_with_config(request, stream, None, Some(connector))
            .await
            .map_err(describe_connect_error)?;
    Ok(ws)
}

/// Turn a failed WebSocket connect into a message a person can act on. An
/// HTTP status instead of an upgrade usually means a proxy or firewall on the
/// path answered instead of the relay, so include what it said.
fn describe_connect_error(err: tokio_tungstenite::tungstenite::Error) -> anyhow::Error {
    use tokio_tungstenite::tungstenite::Error as WsError;
    match err {
        WsError::Http(response) => {
            let status = response.status();
            let excerpt = response
                .body()
                .as_deref()
                .map(|body| text_excerpt(&String::from_utf8_lossy(body), 200))
                .unwrap_or_default();
            if excerpt.is_empty() {
                anyhow::anyhow!(
                    "HTTP {status} instead of a WebSocket upgrade (a proxy or firewall may be intercepting)"
                )
            } else {
                anyhow::anyhow!("HTTP {status} instead of a WebSocket upgrade: {excerpt}")
            }
        }
        other => anyhow::Error::new(other),
    }
}

/// The readable text of an HTML page: tags, scripts and styles removed,
/// whitespace collapsed, at most `max` characters.
fn text_excerpt(html: &str, max: usize) -> String {
    let lower = html.to_ascii_lowercase();
    let mut out = String::new();
    let mut count = 0;
    let mut last_space = true;
    let mut i = 0;
    while i < html.len() {
        if html[i..].starts_with('<') {
            let rest = &lower[i..];
            let block_end = if rest.starts_with("<script") {
                Some("</script>")
            } else if rest.starts_with("<style") {
                Some("</style>")
            } else {
                None
            };
            if let Some(close) = block_end {
                match rest.find(close) {
                    Some(end) => i += end + close.len(),
                    None => break,
                }
            } else {
                match html[i..].find('>') {
                    Some(end) => i += end + 1,
                    None => break,
                }
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            }
            continue;
        }
        let ch = html[i..].chars().next().expect("in bounds");
        i += ch.len_utf8();
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
            count += 1;
            if count >= max {
                out.push('…');
                break;
            }
        }
    }
    out.trim().to_owned()
}

fn text(frame: &ClientFrame) -> WsMessage {
    WsMessage::Text(frame.encode().into())
}

pub(crate) type WsStream = futures_util::stream::SplitStream<Ws>;

/// Read the next server frame, skipping control frames. Errors on close.
pub(crate) async fn read_frame(stream: &mut WsStream) -> anyhow::Result<ServerFrame> {
    loop {
        let msg = match stream.next().await {
            Some(Ok(m)) => m,
            Some(Err(e)) => anyhow::bail!("websocket error: {e}"),
            None => anyhow::bail!("connection closed"),
        };
        let text = match msg {
            WsMessage::Text(t) => t.as_str().to_owned(),
            WsMessage::Binary(b) => String::from_utf8(b.to_vec())?,
            WsMessage::Close(_) => anyhow::bail!("relay closed the connection"),
            WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_) => continue,
        };
        return Ok(ServerFrame::decode(&text)?);
    }
}

#[cfg(test)]
mod tests {
    use super::text_excerpt;

    #[test]
    fn block_page_becomes_readable_text() {
        let html = "<html><head><title>Blocked</title><style>h1{color:red}</style>\
                    <script>var x = 1;</script></head><body><h1>Sorry,</h1> company \n\
                    policy   <b>prohibits</b> this action.</body></html>";
        assert_eq!(
            text_excerpt(html, 200),
            "Blocked Sorry, company policy prohibits this action."
        );
        assert_eq!(text_excerpt("abcdef", 3), "abc…");
        assert_eq!(text_excerpt("", 10), "");
    }
}
