#![forbid(unsafe_code)]
//! The Silver Messenger relay.
//!
//! The relay is deliberately dumb: it authenticates clients by challenge
//! signature, stores signed public-key bundles and one-time prekeys, and
//! queues opaque [`Envelope`]s per recipient until the recipient acknowledges
//! them. It never sees plaintext, and envelopes carry no sender field. A
//! sender may also submit envelopes on a connection that never
//! authenticates, so the relay cannot pair an envelope with an identity;
//! what it can still infer from connections and timing is described in
//! docs/THREAT_MODEL.md.
//!
//! Bundles, prekeys and mailboxes live in an embedded database ([`store`]),
//! so restarts lose nothing; only the set of connected sessions is in memory.

pub mod store;

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rand::rngs::OsRng;
use silver_protocol::blob::{MAX_CHUNK_CIPHERTEXT, MAX_CHUNKS, is_valid_blob_id};
use silver_protocol::wire::{
    ClientFrame, ErrorCode, MAX_FRAME_BYTES, ServerFrame, feature, verify_auth,
};
use silver_protocol::{Envelope, KeyBundle, MAX_CIPHERTEXT_BYTES, UserId, now_ms};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub use store::{BlobLimits, BlobMeta, BlobPut, Enqueue, Limits, Stats, Store};

pub const DEFAULT_LISTEN: &str = "0.0.0.0:7777";

/// Served at `/`; the AGPL asks network services to point users at their source.
pub const SOURCE_NOTICE: &str = concat!(
    "Silver Messenger relay ",
    env!("CARGO_PKG_VERSION"),
    ". Source code (AGPL-3.0): ",
    env!("CARGO_PKG_REPOSITORY"),
    "\n"
);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Default time an unacknowledged envelope is kept.
pub const DEFAULT_MESSAGE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// One-time prekeys a client may have on deposit at once.
pub const MAX_ONE_TIME_PREKEYS: usize = 200;

/// Abuse controls applied per connection, plus the registration policy.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Envelopes one authenticated connection may submit per minute (burst
    /// of the same size).
    pub sends_per_minute: u32,
    /// Key lookups one connection may make per minute.
    pub lookups_per_minute: u32,
    /// When set, an identity not yet known to the relay must present this
    /// token with its first `Publish`.
    pub invite_token: Option<String>,
    /// Envelopes a connection that never authenticates may submit per
    /// minute. Zero refuses such connections altogether.
    pub anonymous_sends_per_minute: u32,
    /// Largest encrypted file the relay stores, in MiB. Zero turns file
    /// storage off.
    pub max_blob_mib: u32,
    /// Encrypted file bytes the relay keeps in total, in MiB.
    pub blob_storage_mib: u32,
    /// File chunks (64 KiB each) one connection may put or get per minute.
    pub blob_chunks_per_minute: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            sends_per_minute: 60,
            lookups_per_minute: 30,
            invite_token: None,
            anonymous_sends_per_minute: 30,
            max_blob_mib: 16,
            blob_storage_mib: 1024,
            blob_chunks_per_minute: 600,
        }
    }
}

impl Policy {
    fn blob_limits(&self) -> BlobLimits {
        BlobLimits {
            // Each chunk carries a 16-byte authentication tag.
            max_blob_bytes: u64::from(self.max_blob_mib) * 1024 * 1024 + u64::from(MAX_CHUNKS) * 16,
            max_total_bytes: u64::from(self.blob_storage_mib) * 1024 * 1024,
        }
    }
}

/// A token bucket: `burst` tokens, refilled at `per_minute / 60` per second.
struct Bucket {
    tokens: f64,
    burst: f64,
    per_second: f64,
    last: Instant,
}

impl Bucket {
    fn per_minute(per_minute: u32) -> Self {
        let burst = f64::from(per_minute.max(1));
        Self {
            tokens: burst,
            burst,
            per_second: burst / 60.0,
            last: Instant::now(),
        }
    }

    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-connection state for an authenticated client.
struct Conn {
    sends: Bucket,
    lookups: Bucket,
    blobs: Bucket,
    /// The client published prekeys, so it speaks protocol v2: it gets
    /// prekey status reports and one-time prekeys with its lookups.
    prekeys: bool,
}

impl Conn {
    fn new(policy: &Policy) -> Self {
        Self {
            sends: Bucket::per_minute(policy.sends_per_minute),
            lookups: Bucket::per_minute(policy.lookups_per_minute),
            blobs: Bucket::per_minute(policy.blob_chunks_per_minute),
            prekeys: false,
        }
    }
}

/// Everything the relay knows. Shared between connections.
pub struct RelayState {
    store: Store,
    limits: Limits,
    policy: Policy,
    online: Mutex<HashMap<UserId, Session>>,
    next_session: AtomicU64,
    anonymous_submissions: AtomicU64,
}

struct Session {
    id: u64,
    tx: mpsc::UnboundedSender<Outbound>,
}

enum Outbound {
    Frame(Box<ServerFrame>),
    /// A newer session for the same user replaced this one.
    Close,
}

/// Why the relay refused a client frame.
type Rejection = (ErrorCode, &'static str);

/// What a client that published prekeys is told afterwards.
struct PrekeyReport {
    one_time_remaining: u32,
    consumed: Vec<u32>,
}

impl RelayState {
    /// State kept only in memory; for tests and `--ephemeral`.
    pub fn new() -> Arc<Self> {
        Self::with_store(
            Store::in_memory().expect("in-memory store"),
            Limits::default(),
        )
    }

    /// State persisted in the database file at `path`.
    pub fn open(path: &Path, limits: Limits) -> anyhow::Result<Arc<Self>> {
        Ok(Self::with_store(Store::open(path)?, limits))
    }

    pub fn open_with(path: &Path, limits: Limits, policy: Policy) -> anyhow::Result<Arc<Self>> {
        Ok(Self::with_store_and_policy(
            Store::open(path)?,
            limits,
            policy,
        ))
    }

    pub fn with_store(store: Store, limits: Limits) -> Arc<Self> {
        Self::with_store_and_policy(store, limits, Policy::default())
    }

    pub fn with_store_and_policy(store: Store, limits: Limits, policy: Policy) -> Arc<Self> {
        Arc::new(Self {
            store,
            limits,
            policy,
            online: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(0),
            anonymous_submissions: AtomicU64::new(0),
        })
    }

    pub fn online_count(&self) -> usize {
        self.online().len()
    }

    /// Envelopes submitted on connections that never authenticated.
    pub fn anonymous_submission_count(&self) -> u64 {
        self.anonymous_submissions.load(Ordering::Relaxed)
    }

    pub fn queued_for(&self, user: &UserId) -> usize {
        self.store.queued_count(user).unwrap_or(0) as usize
    }

    /// The stored bundle: the signed prekey included, one-time keys not.
    pub fn bundle(&self, user: &UserId) -> Option<KeyBundle> {
        self.store.bundle(user).unwrap_or_else(|e| {
            error!("reading bundle: {e:#}");
            None
        })
    }

    /// One-time prekeys on deposit for `user`.
    pub fn one_time_prekeys_left(&self, user: &UserId) -> u32 {
        self.store
            .one_time_status(user)
            .map(|(remaining, _)| remaining)
            .unwrap_or(0)
    }

    pub fn stats(&self) -> Stats {
        self.store.stats().unwrap_or_default()
    }

    /// What this relay can do beyond protocol v1.
    pub fn features(&self) -> Vec<String> {
        let mut features = vec![feature::PREKEYS.to_owned()];
        if self.policy.anonymous_sends_per_minute > 0 {
            features.push(feature::ANONYMOUS_SEND.to_owned());
        }
        if self.policy.max_blob_mib > 0 {
            features.push(feature::BLOBS.to_owned());
        }
        features
    }

    /// Delete unacknowledged envelopes and file blobs older than `ttl`.
    /// Returns how many of each.
    pub fn expire(&self, ttl: Duration) -> (usize, usize) {
        let cutoff = now_ms().saturating_sub(ttl.as_millis() as u64);
        let messages = self.store.expire(cutoff).unwrap_or_else(|e| {
            error!("expiring messages: {e:#}");
            0
        });
        let blobs = self.store.expire_blobs(cutoff).unwrap_or_else(|e| {
            error!("expiring blobs: {e:#}");
            0
        });
        (messages, blobs)
    }

    /// Store one chunk of an encrypted file; the reply for the uploader.
    fn put_blob(
        &self,
        blob: String,
        index: u32,
        total: u32,
        data: &[u8],
        bucket: &mut Bucket,
    ) -> ServerFrame {
        if self.policy.max_blob_mib == 0 {
            return blob_rejected(
                &blob,
                ErrorCode::Forbidden,
                "this relay does not store files",
            );
        }
        if !is_valid_blob_id(&blob) {
            return blob_rejected(
                &blob,
                ErrorCode::Malformed,
                "blob id must be 32 hex characters",
            );
        }
        if total == 0 || total > MAX_CHUNKS || data.len() > MAX_CHUNK_CIPHERTEXT {
            return blob_rejected(&blob, ErrorCode::TooLarge, "chunk or file too large");
        }
        if !bucket.try_take() {
            return blob_rejected(&blob, ErrorCode::RateLimited, "too many chunks; slow down");
        }
        match self.store.put_blob_chunk(
            &blob,
            index,
            total,
            data,
            now_ms(),
            self.policy.blob_limits(),
        ) {
            Ok(BlobPut::Stored { complete }) => ServerFrame::BlobAck {
                blob,
                index,
                complete,
            },
            Ok(BlobPut::Duplicate) => {
                let complete = self
                    .store
                    .blob_meta(&blob)
                    .ok()
                    .flatten()
                    .is_some_and(|m| m.is_complete());
                ServerFrame::BlobAck {
                    blob,
                    index,
                    complete,
                }
            }
            Ok(BlobPut::Mismatch) => blob_rejected(
                &blob,
                ErrorCode::Malformed,
                "chunk does not fit the file as first announced",
            ),
            Ok(BlobPut::TooLarge) => blob_rejected(
                &blob,
                ErrorCode::TooLarge,
                "the file is larger than this relay allows",
            ),
            Ok(BlobPut::StorageFull) => blob_rejected(
                &blob,
                ErrorCode::StorageFull,
                "the relay has no room for more files right now",
            ),
            Err(e) => {
                error!("storing blob chunk: {e:#}");
                blob_rejected(&blob, ErrorCode::Internal, "storage error")
            }
        }
    }

    /// Every chunk of a complete blob, or one rejection.
    fn get_blob(&self, blob: &str, bucket: &mut Bucket) -> Vec<ServerFrame> {
        if !is_valid_blob_id(blob) {
            return vec![blob_rejected(
                blob,
                ErrorCode::Malformed,
                "blob id must be 32 hex characters",
            )];
        }
        let meta = match self.store.blob_meta(blob) {
            Ok(Some(meta)) if meta.is_complete() => meta,
            Ok(_) => {
                return vec![blob_rejected(
                    blob,
                    ErrorCode::NotFound,
                    "no such file on this relay (it may have expired)",
                )];
            }
            Err(e) => {
                error!("reading blob: {e:#}");
                return vec![blob_rejected(blob, ErrorCode::Internal, "storage error")];
            }
        };
        let mut frames = Vec::with_capacity(meta.total as usize);
        for index in 0..meta.total {
            if !bucket.try_take() {
                return vec![blob_rejected(
                    blob,
                    ErrorCode::RateLimited,
                    "too many chunks; slow down",
                )];
            }
            match self.store.blob_chunk(blob, index) {
                Ok(Some(data)) => frames.push(ServerFrame::BlobChunk {
                    blob: blob.to_owned(),
                    index,
                    total: meta.total,
                    data,
                }),
                Ok(None) => {
                    return vec![blob_rejected(
                        blob,
                        ErrorCode::NotFound,
                        "file is incomplete",
                    )];
                }
                Err(e) => {
                    error!("reading blob chunk: {e:#}");
                    return vec![blob_rejected(blob, ErrorCode::Internal, "storage error")];
                }
            }
        }
        frames
    }

    fn online(&self) -> std::sync::MutexGuard<'_, HashMap<UserId, Session>> {
        self.online.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a freshly authenticated session, replacing any older one for
    /// the same user, and replay all unacknowledged envelopes into it.
    fn register(&self, user: UserId, tx: mpsc::UnboundedSender<Outbound>) -> u64 {
        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        let queued = self.store.queued(&user).unwrap_or_else(|e| {
            error!("reading mailbox: {e:#}");
            Vec::new()
        });
        let mut online = self.online();
        if let Some(old) = online.insert(user, Session { id, tx: tx.clone() }) {
            let _ = old.tx.send(Outbound::Close);
        }
        for envelope in queued {
            let _ = tx.send(Outbound::Frame(Box::new(ServerFrame::Deliver { envelope })));
        }
        id
    }

    fn unregister(&self, user: &UserId, session_id: u64) {
        let mut online = self.online();
        if online.get(user).is_some_and(|s| s.id == session_id) {
            online.remove(user);
        }
    }

    /// Store a bundle. With prekeys, the one-time keys go to their own
    /// table and the report says how the deposit stands.
    fn publish(
        &self,
        me: &UserId,
        mut bundle: KeyBundle,
        invite: Option<&str>,
    ) -> Result<Option<PrekeyReport>, Rejection> {
        if bundle.user_id != *me {
            return Err((
                ErrorCode::Forbidden,
                "bundle user_id does not match authenticated user",
            ));
        }
        if bundle.verify().is_err() {
            return Err((ErrorCode::BadSignature, "bundle signature is invalid"));
        }
        if let Some(token) = &self.policy.invite_token {
            let known = self.bundle(me).is_some();
            if !known && invite != Some(token.as_str()) {
                return Err((
                    ErrorCode::InviteRequired,
                    "this relay requires an invite token to register a new identity",
                ));
            }
        }
        let one_time = bundle
            .prekeys
            .as_mut()
            .map(|p| std::mem::take(&mut p.one_time));
        if one_time
            .as_ref()
            .is_some_and(|k| k.len() > MAX_ONE_TIME_PREKEYS)
        {
            return Err((ErrorCode::TooLarge, "too many one-time prekeys"));
        }
        let storage = |e: anyhow::Error| {
            error!("storing bundle: {e:#}");
            (ErrorCode::Internal, "storage error")
        };
        self.store.put_bundle(&bundle).map_err(storage)?;
        let Some(keys) = one_time else {
            return Ok(None);
        };
        self.store
            .set_one_time_prekeys(me, &keys)
            .map_err(storage)?;
        let (one_time_remaining, consumed) = self.store.one_time_status(me).map_err(storage)?;
        Ok(Some(PrekeyReport {
            one_time_remaining,
            consumed,
        }))
    }

    /// A bundle for a lookup by a v2 client: one one-time prekey attached,
    /// if the owner has any left.
    fn bundle_with_one_time_prekey(&self, user: &UserId) -> Option<KeyBundle> {
        let mut bundle = self.bundle(user)?;
        if let Some(prekeys) = bundle.prekeys.as_mut() {
            match self.store.take_one_time_prekey(user) {
                Ok(taken) => prekeys.one_time = taken.into_iter().collect(),
                Err(e) => error!("taking one-time prekey: {e:#}"),
            }
        }
        Some(bundle)
    }

    /// Queue an envelope for its recipient and push it if they are online.
    fn route(&self, envelope: Envelope) -> Result<(), Rejection> {
        if envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err((ErrorCode::TooLarge, "ciphertext too large"));
        }
        let outcome = self
            .store
            .enqueue(&envelope, now_ms(), self.limits)
            .map_err(|e| {
                error!("storing envelope: {e:#}");
                (ErrorCode::Internal, "storage error")
            })?;
        match outcome {
            Enqueue::Stored => {
                let id = envelope.id.clone();
                match self.online().get(&envelope.to) {
                    Some(session) => {
                        debug!(%id, "queued and pushed to the recipient's connection");
                        let _ = session
                            .tx
                            .send(Outbound::Frame(Box::new(ServerFrame::Deliver { envelope })));
                    }
                    None => debug!(%id, "queued; recipient offline"),
                }
                Ok(())
            }
            // A resend of something already queued: nothing to do, the
            // recipient will get (or has got) the original.
            Enqueue::Duplicate => Ok(()),
            Enqueue::MailboxFull => Err((ErrorCode::MailboxFull, "recipient mailbox is full")),
        }
    }

    /// Rate-limit and route a submitted envelope; the reply for the sender.
    fn submit(&self, envelope: Envelope, bucket: &mut Bucket, who: Option<&UserId>) -> ServerFrame {
        let id = envelope.id.clone();
        if !bucket.try_take() {
            match who {
                Some(me) => warn!(%me, "send rate limit hit"),
                None => warn!("send rate limit hit on an anonymous connection"),
            }
            return ServerFrame::Rejected {
                id,
                code: ErrorCode::RateLimited,
                message: "too many messages; slow down".into(),
            };
        }
        match self.route(envelope) {
            Ok(()) => ServerFrame::Sent { id },
            Err((code, message)) => ServerFrame::Rejected {
                id,
                code,
                message: message.into(),
            },
        }
    }

    fn ack(&self, me: &UserId, id: &str) {
        if let Err(e) = self.store.ack(me, id) {
            error!("acknowledging envelope: {e:#}");
        }
    }
}

fn blob_rejected(blob: &str, code: ErrorCode, message: &str) -> ServerFrame {
    ServerFrame::BlobRejected {
        blob: blob.to_owned(),
        code,
        message: message.to_owned(),
    }
}

/// Periodically delete envelopes and blobs older than `ttl`, forever.
pub async fn expire_periodically(state: Arc<RelayState>, ttl: Duration, every: Duration) {
    loop {
        let (messages, blobs) = state.expire(ttl);
        if messages > 0 || blobs > 0 {
            info!(
                "expired {messages} unacknowledged envelopes and {blobs} files older than {ttl:?}"
            );
        }
        tokio::time::sleep(every).await;
    }
}

/// Build the HTTP router: `GET /healthz` and the WebSocket endpoint at `/ws`.
pub fn router(state: Arc<RelayState>) -> Router {
    Router::new()
        // AGPL section 13: people who use the relay over the network can get
        // its source from here.
        .route("/", get(|| async { SOURCE_NOTICE }))
        .route("/healthz", get(|| async { "ok" }))
        .route(silver_protocol::wire::WS_PATH, get(ws_handler))
        .with_state(state)
}

/// Serve until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    state: Arc<RelayState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RelayState>>,
) -> impl IntoResponse {
    ws.max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, state))
}

type Sink = SplitSink<WebSocket, Message>;
type Stream = SplitStream<WebSocket>;

async fn handle_socket(socket: WebSocket, state: Arc<RelayState>) {
    let (mut sink, mut stream) = socket.split();

    // --- challenge / response -------------------------------------------
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    if send(&mut sink, &ServerFrame::Challenge { nonce })
        .await
        .is_err()
    {
        return;
    }

    let first = tokio::time::timeout(AUTH_TIMEOUT, next_frame(&mut stream)).await;
    let user = match first {
        Ok(Some(Ok(ClientFrame::Auth { user_id, signature }))) => {
            if verify_auth(&user_id, &nonce, &signature).is_err() {
                let _ = send(
                    &mut sink,
                    &ServerFrame::error(ErrorCode::BadSignature, "challenge signature invalid"),
                )
                .await;
                return;
            }
            user_id
        }
        Ok(Some(Ok(
            frame @ (ClientFrame::Send { .. }
            | ClientFrame::BlobPut { .. }
            | ClientFrame::BlobGet { .. }),
        ))) if state.policy.anonymous_sends_per_minute > 0 => {
            anonymous_session(sink, stream, &state, frame).await;
            return;
        }
        Ok(Some(Ok(_))) => {
            let _ = send(
                &mut sink,
                &ServerFrame::error(ErrorCode::Unauthenticated, "expected auth frame"),
            )
            .await;
            return;
        }
        Ok(Some(Err(e))) => {
            let _ = send(&mut sink, &ServerFrame::error(ErrorCode::Malformed, e)).await;
            return;
        }
        Ok(None) => return,
        Err(_) => {
            debug!("client did not authenticate within {AUTH_TIMEOUT:?}");
            return;
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut conn = Conn::new(&state.policy);
    let session_id = state.register(user, tx.clone());
    info!(%user, session_id, "client authenticated");
    let auth_ok = ServerFrame::AuthOk {
        user_id: user,
        features: state.features(),
    };
    if send(&mut sink, &auth_ok).await.is_err() {
        state.unregister(&user, session_id);
        return;
    }

    // --- main loop --------------------------------------------------------
    loop {
        tokio::select! {
            outbound = rx.recv() => match outbound {
                Some(Outbound::Frame(frame)) => {
                    if let Err(e) = send(&mut sink, &frame).await {
                        debug!(%user, session_id, "write failed ({e}); closing");
                        break;
                    }
                }
                Some(Outbound::Close) => {
                    debug!(%user, session_id, "replaced by a newer session");
                    let _ = sink.close().await;
                    return; // the newer session owns the registry entry now
                }
                None => break,
            },
            inbound = next_frame(&mut stream) => match inbound {
                Some(Ok(frame)) => {
                    for reply in handle_frame(&state, &user, frame, &mut conn) {
                        let _ = tx.send(Outbound::Frame(Box::new(reply)));
                    }
                }
                Some(Err(e)) => {
                    let _ = tx.send(Outbound::Frame(Box::new(ServerFrame::error(
                        ErrorCode::Malformed,
                        e,
                    ))));
                }
                None => break,
            },
        }
    }

    state.unregister(&user, session_id);
    info!(%user, session_id, "client disconnected");
}

/// A connection that only submits envelopes and moves file chunks, and
/// never says who it is. It gets its own, stricter rate limits and nothing
/// else: no mailbox, no lookups, no bundle.
async fn anonymous_session(
    mut sink: Sink,
    mut stream: Stream,
    state: &RelayState,
    first: ClientFrame,
) {
    debug!("anonymous submission session opened");
    let mut bucket = Bucket::per_minute(state.policy.anonymous_sends_per_minute);
    let mut blobs = Bucket::per_minute(state.policy.blob_chunks_per_minute);
    let mut next = Some(first);
    loop {
        let frame = match next.take() {
            Some(frame) => frame,
            None => match next_frame(&mut stream).await {
                Some(Ok(frame)) => frame,
                Some(Err(e)) => {
                    if send(&mut sink, &ServerFrame::error(ErrorCode::Malformed, e))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
                None => break,
            },
        };
        let replies = match frame {
            ClientFrame::Send { envelope } => {
                state.anonymous_submissions.fetch_add(1, Ordering::Relaxed);
                vec![state.submit(envelope, &mut bucket, None)]
            }
            ClientFrame::BlobPut {
                blob,
                index,
                total,
                data,
            } => vec![state.put_blob(blob, index, total, &data, &mut blobs)],
            ClientFrame::BlobGet { blob } => state.get_blob(&blob, &mut blobs),
            ClientFrame::Ping => vec![ServerFrame::Pong],
            _ => vec![ServerFrame::error(
                ErrorCode::Unauthenticated,
                "this connection only accepts send, file chunks and ping",
            )],
        };
        for reply in replies {
            if send(&mut sink, &reply).await.is_err() {
                return;
            }
        }
    }
    debug!("anonymous submission session closed");
}

fn handle_frame(
    state: &RelayState,
    me: &UserId,
    frame: ClientFrame,
    conn: &mut Conn,
) -> Vec<ServerFrame> {
    match frame {
        ClientFrame::Auth { .. } => vec![ServerFrame::error(
            ErrorCode::Malformed,
            "already authenticated",
        )],
        ClientFrame::Publish { bundle, invite } => {
            match state.publish(me, bundle, invite.as_deref()) {
                Ok(report) => {
                    let mut replies = vec![ServerFrame::Published];
                    if let Some(report) = report {
                        conn.prekeys = true;
                        replies.push(ServerFrame::PrekeyStatus {
                            one_time_remaining: report.one_time_remaining,
                            consumed: report.consumed,
                        });
                    }
                    replies
                }
                Err((code, message)) => vec![ServerFrame::error(code, message)],
            }
        }
        ClientFrame::Lookup { user_id } => {
            if !conn.lookups.try_take() {
                warn!(%me, "lookup rate limit hit");
                return vec![ServerFrame::error(
                    ErrorCode::RateLimited,
                    "too many lookups; slow down",
                )];
            }
            // Only a client that can use a one-time prekey gets one.
            let bundle = if conn.prekeys {
                state.bundle_with_one_time_prekey(&user_id)
            } else {
                state.bundle(&user_id)
            };
            vec![ServerFrame::LookupResult { user_id, bundle }]
        }
        ClientFrame::Send { envelope } => vec![state.submit(envelope, &mut conn.sends, Some(me))],
        ClientFrame::Ack { id } => {
            state.ack(me, &id);
            Vec::new()
        }
        ClientFrame::BlobPut {
            blob,
            index,
            total,
            data,
        } => vec![state.put_blob(blob, index, total, &data, &mut conn.blobs)],
        ClientFrame::BlobGet { blob } => state.get_blob(&blob, &mut conn.blobs),
        ClientFrame::Ping => vec![ServerFrame::Pong],
    }
}

async fn send(sink: &mut Sink, frame: &ServerFrame) -> Result<(), axum::Error> {
    sink.send(Message::Text(frame.encode().into())).await
}

/// Read the next JSON frame. `None` means the socket closed.
async fn next_frame(stream: &mut Stream) -> Option<Result<ClientFrame, String>> {
    loop {
        let msg = match stream.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                debug!("websocket error: {e}");
                return None;
            }
            None => return None,
        };
        let text = match &msg {
            Message::Text(t) => t.as_str().to_owned(),
            Message::Binary(b) => match std::str::from_utf8(b) {
                Ok(s) => s.to_owned(),
                Err(_) => return Some(Err("binary frame is not UTF-8".into())),
            },
            Message::Close(_) => return None,
            Message::Ping(_) | Message::Pong(_) => continue,
        };
        return Some(ClientFrame::decode(&text).map_err(|e| {
            warn!("malformed client frame: {e}");
            format!("malformed frame: {e}")
        }));
    }
}
