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
//!
//! The relay can terminate TLS itself ([`tls`]), with a certificate from
//! files or one it obtains and renews from an ACME certificate authority
//! ([`acme`]); a TLS front such as Caddy remains an option.

pub mod acme;
pub mod metrics;
pub mod store;
pub mod tls;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rand::rngs::OsRng;
use silver_protocol::blob::{MAX_CHUNK_CIPHERTEXT, MAX_CHUNKS, is_valid_blob_id};
use silver_protocol::wire::{
    ClientFrame, ErrorCode, MAX_FRAME_BYTES, ServerFrame, feature, normalize_host, verify_auth,
    verify_auth_bound,
};
use silver_protocol::{Envelope, KeyBundle, MAX_CIPHERTEXT_BYTES, UserId, now_ms};
use subtle::ConstantTimeEq;
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
/// One-time ML-KEM keys a client may have on deposit at once; fewer, as
/// each is 1.2 KB and a publish has to fit in one frame.
pub const MAX_PQ_ONE_TIME_PREKEYS: usize = 50;

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
    /// Open connections one client address may hold at once.
    pub connections_per_address: u32,
    /// Open connections in total.
    pub max_connections: u32,
    /// A connection that sends nothing for this long is closed. Clients
    /// ping every 30 seconds.
    pub idle_timeout: Duration,
    /// New identities one address may register per hour.
    pub registrations_per_hour: u32,
    /// Identities the relay keeps at most; 0 for no cap.
    pub max_identities: u64,
    /// File bytes one address may upload per hour, in MiB.
    pub blob_mib_per_address_per_hour: u32,
    /// Addresses of TLS fronts (Caddy, nginx) whose `X-Forwarded-For`
    /// header names the real client. Empty means the loopback addresses,
    /// where the installer puts the front.
    pub trusted_proxies: Vec<IpAddr>,
    /// Write user ids into the log as they are. Off, the log shows a
    /// pseudonym that holds for this run of the relay only, so the log
    /// still tells one client from another without being a record of who
    /// used the relay.
    pub log_ids: bool,
    /// Refuse the v1 login (a signature over the nonce alone), which a
    /// hostile relay could collect and replay here. Off, both kinds are
    /// accepted so clients from before 0.6.0 can still connect.
    pub require_bound_auth: bool,
    /// One-time prekeys handed out for one user per hour, at most; lookups
    /// beyond that get the bundle without one, so nobody can drain a
    /// deposit by looking someone up in a loop.
    pub one_time_prekeys_per_user_per_hour: u32,
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
            connections_per_address: 16,
            max_connections: 4096,
            idle_timeout: Duration::from_secs(120),
            registrations_per_hour: 20,
            max_identities: 100_000,
            blob_mib_per_address_per_hour: 256,
            trusted_proxies: Vec::new(),
            log_ids: false,
            require_bound_auth: false,
            one_time_prekeys_per_user_per_hour: 30,
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
    fn new(burst: f64, per_second: f64) -> Self {
        Self {
            tokens: burst,
            burst,
            per_second,
            last: Instant::now(),
        }
    }

    fn per_minute(per_minute: u32) -> Self {
        let burst = f64::from(per_minute.max(1));
        Self::new(burst, burst / 60.0)
    }

    /// `per_hour` units an hour, all of them available at once.
    fn per_hour(per_hour: f64) -> Self {
        let burst = per_hour.max(1.0);
        Self::new(burst, burst / 3600.0)
    }

    fn try_take(&mut self) -> bool {
        self.try_take_n(1.0)
    }

    fn try_take_n(&mut self, amount: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.burst);
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

/// Per-connection state for an authenticated client.
struct Conn {
    addr: IpAddr,
    sends: Bucket,
    lookups: Bucket,
    blobs: Bucket,
    /// The client published prekeys, so it speaks protocol v2: it gets
    /// prekey status reports and one-time prekeys with its lookups.
    prekeys: bool,
}

impl Conn {
    fn new(policy: &Policy, addr: IpAddr) -> Self {
        Self {
            addr,
            sends: Bucket::per_minute(policy.sends_per_minute),
            lookups: Bucket::per_minute(policy.lookups_per_minute),
            blobs: Bucket::per_minute(policy.blob_chunks_per_minute),
            prekeys: false,
        }
    }
}

/// What one client address is doing, for the limits that go by address
/// rather than by connection.
struct AddressState {
    connections: u32,
    registrations: Bucket,
    blob_bytes: Bucket,
    last_seen: Instant,
}

impl AddressState {
    fn new(policy: &Policy) -> Self {
        Self {
            connections: 0,
            registrations: Bucket::per_hour(f64::from(policy.registrations_per_hour)),
            blob_bytes: Bucket::per_hour(
                f64::from(policy.blob_mib_per_address_per_hour) * 1024.0 * 1024.0,
            ),
            last_seen: Instant::now(),
        }
    }
}

/// How often the limits said no; for the hourly summary and for tests.
#[derive(Default)]
struct Counters {
    refused_connections: AtomicU64,
    refused_registrations: AtomicU64,
    refused_uploads: AtomicU64,
    idle_closed: AtomicU64,
}

/// A copy of the counters plus what is open right now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub open_connections: u32,
    pub addresses: usize,
    pub refused_connections: u64,
    pub refused_registrations: u64,
    pub refused_uploads: u64,
    pub idle_closed: u64,
}

/// Holds one connection's place in the counts; dropping it gives the
/// place back.
struct ConnectionGuard {
    state: Arc<RelayState>,
    addr: IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.state.connections.fetch_sub(1, Ordering::Relaxed);
        let mut addresses = self.state.addresses();
        if let Some(entry) = addresses.get_mut(&self.addr) {
            entry.connections = entry.connections.saturating_sub(1);
            entry.last_seen = Instant::now();
        }
    }
}

/// Everything the relay knows. Shared between connections.
pub struct RelayState {
    store: Store,
    limits: Limits,
    policy: Policy,
    online: Mutex<HashMap<UserId, Session>>,
    addresses: Mutex<HashMap<IpAddr, AddressState>>,
    /// How many one-time prekeys each user has had handed out lately.
    handouts: Mutex<HashMap<UserId, Bucket>>,
    connections: AtomicU32,
    counters: Counters,
    next_session: AtomicU64,
    anonymous_submissions: AtomicU64,
    auth_failures: metrics::AuthFailures,
    started: Instant,
    /// Salt for the pseudonyms in the log; new every run.
    log_salt: [u8; 16],
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
    pq_one_time_remaining: u32,
    pq_consumed: Vec<u32>,
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
            addresses: Mutex::new(HashMap::new()),
            handouts: Mutex::new(HashMap::new()),
            connections: AtomicU32::new(0),
            counters: Counters::default(),
            next_session: AtomicU64::new(0),
            anonymous_submissions: AtomicU64::new(0),
            auth_failures: metrics::AuthFailures::default(),
            started: Instant::now(),
            log_salt: {
                let mut salt = [0u8; 16];
                OsRng.fill_bytes(&mut salt);
                salt
            },
        })
    }

    pub fn online_count(&self) -> usize {
        self.online().len()
    }

    /// How a user is named in the log: the id itself with `log_ids`, else
    /// twelve hex digits of a salted hash that mean nothing after this run.
    pub fn who(&self, user: &UserId) -> String {
        if self.policy.log_ids {
            return user.to_string();
        }
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.log_salt);
        hasher.update(user.to_string().as_bytes());
        let digest = hasher.finalize();
        digest[..6].iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    fn addresses(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, AddressState>> {
        self.addresses.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The address a connection counts under: what the socket says, or
    /// what a trusted front says the client was.
    pub fn client_address(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> IpAddr {
        let peer = peer.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let trusted = if self.policy.trusted_proxies.is_empty() {
            peer.is_loopback()
        } else {
            self.policy.trusted_proxies.contains(&peer)
        };
        if trusted {
            // The front appends the client to whatever it was handed, so the
            // last entry is the one it saw itself.
            let forwarded = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|v| v.trim().parse::<IpAddr>().ok());
            if let Some(forwarded) = forwarded {
                return forwarded;
            }
        }
        peer
    }

    /// Take a place for a connection from `addr`, or say why not.
    fn connect(self: &Arc<Self>, addr: IpAddr) -> Result<ConnectionGuard, &'static str> {
        if self.connections.load(Ordering::Relaxed) >= self.policy.max_connections {
            self.counters
                .refused_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err("the relay has as many connections as it takes; try again shortly");
        }
        let mut addresses = self.addresses();
        let entry = addresses
            .entry(addr)
            .or_insert_with(|| AddressState::new(&self.policy));
        if entry.connections >= self.policy.connections_per_address {
            self.counters
                .refused_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err("too many connections from this address");
        }
        entry.connections += 1;
        entry.last_seen = Instant::now();
        drop(addresses);
        self.connections.fetch_add(1, Ordering::Relaxed);
        Ok(ConnectionGuard {
            state: self.clone(),
            addr,
        })
    }

    /// Whether `addr` may register one more new identity this hour.
    fn registration_allowed(&self, addr: IpAddr) -> bool {
        let mut addresses = self.addresses();
        let entry = addresses
            .entry(addr)
            .or_insert_with(|| AddressState::new(&self.policy));
        entry.last_seen = Instant::now();
        entry.registrations.try_take()
    }

    /// Whether `addr` may upload `bytes` more this hour.
    fn upload_allowed(&self, addr: IpAddr, bytes: usize) -> bool {
        let mut addresses = self.addresses();
        let entry = addresses
            .entry(addr)
            .or_insert_with(|| AddressState::new(&self.policy));
        entry.last_seen = Instant::now();
        entry.blob_bytes.try_take_n(bytes as f64)
    }

    /// Forget addresses with nothing open that have been quiet for an hour
    /// (their buckets are full again by then), and hand-out buckets that
    /// are full again.
    pub fn sweep_addresses(&self) {
        let cutoff = Duration::from_secs(3600);
        self.addresses()
            .retain(|_, a| a.connections > 0 || a.last_seen.elapsed() < cutoff);
        self.handouts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, b| b.last.elapsed() < cutoff);
    }

    /// Whether one more one-time prekey of `user`'s may be handed out now.
    fn handout_allowed(&self, user: &UserId) -> bool {
        let mut handouts = self.handouts.lock().unwrap_or_else(|e| e.into_inner());
        handouts
            .entry(*user)
            .or_insert_with(|| {
                Bucket::per_hour(f64::from(self.policy.one_time_prekeys_per_user_per_hour))
            })
            .try_take()
    }

    pub fn counters(&self) -> CounterSnapshot {
        CounterSnapshot {
            open_connections: self.connections.load(Ordering::Relaxed),
            addresses: self.addresses().len(),
            refused_connections: self.counters.refused_connections.load(Ordering::Relaxed),
            refused_registrations: self.counters.refused_registrations.load(Ordering::Relaxed),
            refused_uploads: self.counters.refused_uploads.load(Ordering::Relaxed),
            idle_closed: self.counters.idle_closed.load(Ordering::Relaxed),
        }
    }

    /// Envelopes submitted on connections that never authenticated.
    pub fn anonymous_submission_count(&self) -> u64 {
        self.anonymous_submissions.load(Ordering::Relaxed)
    }

    /// Failed logins, for the metrics.
    pub fn auth_failures(&self) -> &metrics::AuthFailures {
        &self.auth_failures
    }

    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// A login from `addr` was refused. The address is named in the log
    /// once its failures in an hour reach the warning level, so an
    /// operator alerting on the journal sees the address; the metrics
    /// carry only the counts.
    pub fn note_auth_failure(&self, addr: IpAddr) {
        if let Some(count) = self.auth_failures.note(addr, Instant::now()) {
            warn!(%addr, "{count} failed logins from one address within an hour");
        }
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
        let mut features = vec![feature::PREKEYS.to_owned(), feature::PQ_PREKEYS.to_owned()];
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
        addr: IpAddr,
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
        if !self.upload_allowed(addr, data.len()) {
            self.counters
                .refused_uploads
                .fetch_add(1, Ordering::Relaxed);
            return blob_rejected(
                &blob,
                ErrorCode::RateLimited,
                "this address has uploaded its share of files for the hour",
            );
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
        addr: IpAddr,
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
        // A new identity: the invite token, the registration rate for the
        // address, and the room left all have a say.
        if self.bundle(me).is_none() {
            if let Some(token) = &self.policy.invite_token {
                let given = invite.unwrap_or_default();
                let matches: bool = token.as_bytes().ct_eq(given.as_bytes()).into();
                if !matches {
                    return Err((
                        ErrorCode::InviteRequired,
                        "this relay requires an invite token to register a new identity",
                    ));
                }
            }
            if self.policy.max_identities > 0 && self.stats().bundles >= self.policy.max_identities
            {
                self.counters
                    .refused_registrations
                    .fetch_add(1, Ordering::Relaxed);
                return Err((
                    ErrorCode::Forbidden,
                    "this relay has all the identities it takes",
                ));
            }
            if !self.registration_allowed(addr) {
                self.counters
                    .refused_registrations
                    .fetch_add(1, Ordering::Relaxed);
                return Err((
                    ErrorCode::RateLimited,
                    "too many new identities from this address; try again later",
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
        let pq_one_time = bundle
            .prekeys
            .as_mut()
            .map(|p| std::mem::take(&mut p.pq_one_time));
        if pq_one_time
            .as_ref()
            .is_some_and(|k| k.len() > MAX_PQ_ONE_TIME_PREKEYS)
        {
            return Err((ErrorCode::TooLarge, "too many one-time ML-KEM prekeys"));
        }
        let storage = |e: anyhow::Error| {
            error!("storing bundle: {e:#}");
            (ErrorCode::Internal, "storage error")
        };
        self.store.put_bundle(&bundle).map_err(storage)?;
        let (Some(keys), Some(pq_keys)) = (one_time, pq_one_time) else {
            return Ok(None);
        };
        self.store
            .set_one_time_prekeys(me, &keys)
            .map_err(storage)?;
        // An empty list here is a client that publishes no ML-KEM keys
        // (or stopped): whatever it deposited before is dropped with it.
        self.store
            .set_pq_one_time_prekeys(me, &pq_keys)
            .map_err(storage)?;
        let (one_time_remaining, consumed) = self.store.one_time_status(me).map_err(storage)?;
        let (pq_one_time_remaining, pq_consumed) =
            self.store.pq_one_time_status(me).map_err(storage)?;
        Ok(Some(PrekeyReport {
            one_time_remaining,
            consumed,
            pq_one_time_remaining,
            pq_consumed,
        }))
    }

    /// A bundle for a lookup by a v2 client: one one-time prekey attached,
    /// if the owner has any left and they are not being handed out faster
    /// than the policy allows.
    fn bundle_with_one_time_prekey(&self, user: &UserId) -> Option<KeyBundle> {
        let mut bundle = self.bundle(user)?;
        if let Some(prekeys) = bundle.prekeys.as_mut() {
            if !self.handout_allowed(user) {
                debug!("one-time prekeys for one user are being asked for quickly; serving none");
                return Some(bundle);
            }
            match self.store.take_one_time_prekey(user) {
                Ok(taken) => prekeys.one_time = taken.into_iter().collect(),
                Err(e) => error!("taking one-time prekey: {e:#}"),
            }
            match self.store.take_pq_one_time_prekey(user) {
                Ok(taken) => prekeys.pq_one_time = taken.into_iter().collect(),
                Err(e) => error!("taking one-time ML-KEM prekey: {e:#}"),
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
                Some(me) => warn!(who = %self.who(me), "send rate limit hit"),
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

/// Periodically delete envelopes and blobs older than `ttl`, forever, and
/// say how the limits have been doing.
pub async fn expire_periodically(state: Arc<RelayState>, ttl: Duration, every: Duration) {
    loop {
        let (messages, blobs) = state.expire(ttl);
        if messages > 0 || blobs > 0 {
            info!(
                "expired {messages} unacknowledged envelopes and {blobs} files older than {ttl:?}"
            );
        }
        state.sweep_addresses();
        let c = state.counters();
        info!(
            "{} connections open from {} addresses; refused so far: {} connections, {} registrations, {} uploads, {} logins; {} closed idle",
            c.open_connections,
            c.addresses,
            c.refused_connections,
            c.refused_registrations,
            c.refused_uploads,
            state.auth_failures().total(),
            c.idle_closed
        );
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
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RelayState>>,
    // Absent when the router is served without connection info, as the
    // TLS tests do; every connection then counts under one address.
    peer: Result<ConnectInfo<SocketAddr>, axum::extract::rejection::ExtensionRejection>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let addr = state.client_address(peer.ok().map(|p| p.0.ip()), &headers);
    // What the client connected to, for the bound login; a TLS front
    // passes the header through.
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(normalize_host)
        .filter(|h| !h.is_empty());
    ws.max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, state, addr, host))
}

type Sink = SplitSink<WebSocket, Message>;
type Stream = SplitStream<WebSocket>;

async fn handle_socket(
    socket: WebSocket,
    state: Arc<RelayState>,
    addr: IpAddr,
    our_host: Option<String>,
) {
    let (mut sink, mut stream) = socket.split();

    // --- a place among the connections ----------------------------------
    let _place = match state.connect(addr) {
        Ok(guard) => guard,
        Err(why) => {
            debug!(%addr, "connection refused: {why}");
            let _ = send(&mut sink, &ServerFrame::error(ErrorCode::RateLimited, why)).await;
            let _ = sink.close().await;
            return;
        }
    };

    // --- challenge / response -------------------------------------------
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    if send(&mut sink, &ServerFrame::Challenge { nonce, bound: true })
        .await
        .is_err()
    {
        return;
    }

    let first = tokio::time::timeout(AUTH_TIMEOUT, next_frame(&mut stream)).await;
    let user = match first {
        Ok(Some(Ok(ClientFrame::Auth {
            user_id,
            signature,
            host,
        }))) => {
            let verdict = match host {
                // The bound login: the signature must cover the host the
                // client reached us as, and that host must be ours.
                Some(host) => {
                    let host = normalize_host(&host);
                    if our_host.as_deref() != Some(host.as_str()) {
                        Err((
                            ErrorCode::BadSignature,
                            "the login names a host this relay was not reached as",
                        ))
                    } else {
                        verify_auth_bound(&user_id, &host, &nonce, &signature)
                            .map_err(|_| (ErrorCode::BadSignature, "challenge signature invalid"))
                    }
                }
                None if state.policy.require_bound_auth => Err((
                    ErrorCode::Unauthenticated,
                    "this relay requires the bound login (a client from 0.6.0 on)",
                )),
                None => verify_auth(&user_id, &nonce, &signature)
                    .map_err(|_| (ErrorCode::BadSignature, "challenge signature invalid")),
            };
            if let Err((code, message)) = verdict {
                state.note_auth_failure(addr);
                let _ = send(&mut sink, &ServerFrame::error(code, message)).await;
                return;
            }
            user_id
        }
        Ok(Some(Ok(
            frame @ (ClientFrame::Send { .. }
            | ClientFrame::BlobPut { .. }
            | ClientFrame::BlobGet { .. }),
        ))) if state.policy.anonymous_sends_per_minute > 0 => {
            anonymous_session(sink, stream, &state, frame, addr).await;
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
    let mut conn = Conn::new(&state.policy, addr);
    let session_id = state.register(user, tx.clone());
    let who = state.who(&user);
    info!(%who, session_id, "client authenticated");
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
                        debug!(%who, session_id, "write failed ({e}); closing");
                        break;
                    }
                }
                Some(Outbound::Close) => {
                    debug!(%who, session_id, "replaced by a newer session");
                    let _ = sink.close().await;
                    return; // the newer session owns the registry entry now
                }
                None => break,
            },
            inbound = tokio::time::timeout(state.policy.idle_timeout, next_frame(&mut stream)) => match inbound {
                Ok(Some(Ok(frame))) => {
                    for reply in handle_frame(&state, &user, frame, &mut conn) {
                        let _ = tx.send(Outbound::Frame(Box::new(reply)));
                    }
                }
                Ok(Some(Err(e))) => {
                    let _ = tx.send(Outbound::Frame(Box::new(ServerFrame::error(
                        ErrorCode::Malformed,
                        e,
                    ))));
                }
                Ok(None) => break,
                Err(_) => {
                    debug!(%who, session_id, "closing an idle connection");
                    state.counters.idle_closed.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            },
        }
    }

    state.unregister(&user, session_id);
    info!(%who, session_id, "client disconnected");
}

/// A connection that only submits envelopes and moves file chunks, and
/// never says who it is. It gets its own, stricter rate limits and nothing
/// else: no mailbox, no lookups, no bundle.
async fn anonymous_session(
    mut sink: Sink,
    mut stream: Stream,
    state: &RelayState,
    first: ClientFrame,
    addr: IpAddr,
) {
    debug!("anonymous submission session opened");
    let mut bucket = Bucket::per_minute(state.policy.anonymous_sends_per_minute);
    let mut blobs = Bucket::per_minute(state.policy.blob_chunks_per_minute);
    let mut next = Some(first);
    loop {
        let frame = match next.take() {
            Some(frame) => frame,
            None => match tokio::time::timeout(state.policy.idle_timeout, next_frame(&mut stream))
                .await
            {
                Ok(Some(Ok(frame))) => frame,
                Ok(Some(Err(e))) => {
                    if send(&mut sink, &ServerFrame::error(ErrorCode::Malformed, e))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
                Ok(None) => break,
                Err(_) => {
                    debug!("closing an idle anonymous connection");
                    state.counters.idle_closed.fetch_add(1, Ordering::Relaxed);
                    break;
                }
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
            } => vec![state.put_blob(blob, index, total, &data, &mut blobs, addr)],
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
            match state.publish(me, bundle, invite.as_deref(), conn.addr) {
                Ok(report) => {
                    let mut replies = vec![ServerFrame::Published];
                    if let Some(report) = report {
                        conn.prekeys = true;
                        replies.push(ServerFrame::PrekeyStatus {
                            one_time_remaining: report.one_time_remaining,
                            consumed: report.consumed,
                            pq_one_time_remaining: Some(report.pq_one_time_remaining),
                            pq_consumed: report.pq_consumed,
                        });
                    }
                    replies
                }
                Err((code, message)) => vec![ServerFrame::error(code, message)],
            }
        }
        ClientFrame::Lookup { user_id } => {
            if !conn.lookups.try_take() {
                warn!(who = %state.who(me), "lookup rate limit hit");
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
        } => vec![state.put_blob(blob, index, total, &data, &mut conn.blobs, conn.addr)],
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
