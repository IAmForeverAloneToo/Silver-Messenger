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
pub mod admin;
pub mod backup;
pub mod metrics;
pub mod store;
pub mod tls;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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
use silver_protocol::{
    DeviceRevocation, Envelope, KeyBundle, LogEntry, LogHead, LogPosition, MAX_CIPHERTEXT_BYTES,
    Revocation, Succession, UserId, now_ms,
};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub use store::{
    Ban, BlobLimits, BlobMeta, BlobPut, Enqueue, GroupSweep, Limits, Removed, SCHEMA_VERSION,
    SchemaTooNew, Sequenced, Stats, Store,
};

/// The admin setting that holds an invite token changed at runtime; an
/// empty value means "no token needed", chosen over the command line.
const INVITE_SETTING: &str = "invite_token";

/// Who may not connect or log in, as the administrator decided.
#[derive(Default)]
struct Bans {
    addresses: HashSet<IpAddr>,
    users: HashSet<UserId>,
}

impl Bans {
    fn load(store: &Store) -> Self {
        let mut bans = Self::default();
        match store.bans() {
            Ok(list) => {
                for (key, _) in list {
                    match BanTarget::from_key(&key) {
                        Some(BanTarget::Address(addr)) => {
                            bans.addresses.insert(canonical_address(addr));
                        }
                        Some(BanTarget::Identity(user)) => {
                            bans.users.insert(user);
                        }
                        None => warn!("ignoring an unreadable ban entry {key}"),
                    }
                }
            }
            Err(e) => error!("reading the bans: {e:#}"),
        }
        bans
    }
}

/// What a ban applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BanTarget {
    Address(IpAddr),
    Identity(UserId),
}

impl BanTarget {
    /// The store key: `address:<ip>` or `identity:<id>`.
    pub fn key(&self) -> String {
        match self {
            Self::Address(addr) => format!("address:{addr}"),
            Self::Identity(user) => format!("identity:{user}"),
        }
    }

    fn from_key(key: &str) -> Option<Self> {
        let (kind, value) = key.split_once(':')?;
        match kind {
            "address" => value.parse().ok().map(Self::Address),
            "identity" => value.parse().ok().map(Self::Identity),
            _ => None,
        }
    }
}

/// One identity as the administrator sees it: by its log pseudonym unless
/// `--log-ids` is set, never by anything the relay cannot see anyway.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdentityRow {
    pub who: String,
    pub online: bool,
    pub banned: bool,
    pub messages: u64,
    pub bytes: u64,
    pub one_time_prekeys: u32,
    pub pq_one_time_prekeys: u32,
    pub signed_prekey_at_ms: Option<u64>,
    pub post_quantum: bool,
}

/// A ban as listed to the administrator.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BanRow {
    /// `address:<ip>`, or `identity:<pseudonym>` as in the log.
    pub target: String,
    pub since_ms: u64,
    pub note: String,
}

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
/// A group's sequencer entry that no commit has moved for this long is
/// dropped; a live group refreshes its entry with every commit, and a
/// member of a dropped one re-creates it (`docs/PROTOCOL.md` section 13).
pub const GROUP_IDLE_TTL: Duration = Duration::from_secs(180 * 24 * 60 * 60);
/// How long a retired sequencer entry is kept as a headstone: the epoch
/// and token hash it died at, and nothing else. Only a member of the group
/// at that epoch can raise it, so an id that has been used cannot be taken
/// over by a stranger — or by somebody the group removed — for this long
/// after the group stops. Once it is up the headstone goes and the id is
/// free, as an id nobody has ever used is (`docs/PROTOCOL.md` section 13.5).
pub const GROUP_HEADSTONE_TTL: Duration = Duration::from_secs(180 * 24 * 60 * 60);
/// Key package deposits one connection may make per minute: one, since a
/// deposit replaces the whole list and a client has no reason to repeat
/// it.
const KEY_PACKAGE_DEPOSITS_PER_MINUTE: u32 = 1;
/// Bundle publishes one connection may make per minute. A client
/// publishes once on connecting, and twice more when it links or renames
/// a device; six leaves room for that and for a reconnect.
const PUBLISHES_PER_MINUTE: u32 = 6;
/// Acknowledgements one connection may make per minute. A client draining
/// a full mailbox acknowledges as fast as it reads, so this is well above
/// the per-recipient message cap.
const ACKS_PER_MINUTE: u32 = 4000;
/// What a blob chunk is charged against an address's upload budget at
/// least, whatever it holds. A chunk costs a database entry and a key
/// however small it is, so charging bytes alone let a client fill the
/// store with empty chunks that no budget ever noticed.
const CHUNK_OVERHEAD_BYTES: usize = 1024;
/// Envelopes the relay will have delivered to one connection and not yet
/// seen acknowledged. A client acknowledges every envelope it is handed,
/// so a mailbox drains a page at a time at the speed the client reads it;
/// what the window buys is that the relay never holds more than this much
/// of a mailbox in memory, however much is waiting and however many
/// connections are open at once.
const DELIVERY_WINDOW: usize = 16;
/// Frames one connection's outbound queue holds. Only deliveries and the
/// close notice go through it, and deliveries are already held to
/// [`DELIVERY_WINDOW`], so the margin is for the close notice to have
/// somewhere to sit.
const OUTBOUND_QUEUE: usize = DELIVERY_WINDOW + 16;
/// How long one frame may take to reach the client before the relay gives
/// up on the connection. Without it a peer that opens a socket and then
/// stops reading holds a task, a queue and the memory in it for as long as
/// it likes: the idle timeout does not fire, because the connection is not
/// idle from the relay's side, it is blocked.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// The names this relay answers to, normalised as `normalize_host`
    /// leaves them: its ACME domains, the names in its certificate, and
    /// whatever `--host` adds. A bound login (7.1) is accepted only for a
    /// name in this list.
    ///
    /// Empty means the relay has no idea what it is called, and falls back
    /// to comparing the signed host with the `Host` header of the upgrade
    /// request. Whoever connects chooses that header, so the fallback does
    /// not stop a relay in the middle from collecting a login under its own
    /// name and presenting it here; the relay says so at start.
    pub hosts: Vec<String>,
    /// One-time prekeys handed out for one user per hour, at most; lookups
    /// beyond that get the bundle without one, so nobody can drain a
    /// deposit by looking someone up in a loop. Key packages share the
    /// budget: past it, the last-resort one is handed out.
    pub one_time_prekeys_per_user_per_hour: u32,
    /// Group sequencer entries the relay keeps at most; 0 for no cap.
    pub max_groups: u64,
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
            hosts: Vec::new(),
            one_time_prekeys_per_user_per_hour: 30,
            max_groups: 100_000,
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

/// One address, written one way. A dual-stack listener hands an IPv4 peer
/// over as `::ffff:a.b.c.d`, which is the same client as `a.b.c.d` and
/// must count, be banned and be trusted as one: otherwise a loopback front
/// is not recognised (so every client behind it collapses to one address
/// and shares the per-address connection cap), and a ban on the IPv4 form
/// does not match the mapped one.
pub fn canonical_address(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// A token bucket: `burst` tokens, refilled at `per_minute / 60` per second.
///
/// A rate of zero turns the thing off: it refuses everything, rather than
/// allowing a trickle. That is the convention across this relay's limits
/// -- `--lookups-per-minute 0` stops lookups, `--max-blob-mib 0` stops
/// file transfer, `--anonymous-sends-per-minute 0` stops anonymous
/// submission -- and `max_identities`, which is a cap rather than a rate,
/// is the documented exception at zero meaning no cap.
///
/// `per_hour` did not follow it. It clamped its rate up to 1.0, so a zero
/// became one an hour: an operator who closed registration with
/// `--registrations-per-hour 0` got a relay that still let an address
/// register an identity every hour, which is the footgun pointing the
/// wrong way -- registration looked closed and was not. Steady traffic at
/// exactly the refill rate walks through such a bucket indefinitely.
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
        // Zero means none: an operator who sets a limit to zero is turning
        // the thing off, not asking for one an hour.
        let burst = f64::from(per_minute);
        Self::new(burst, burst / 60.0)
    }

    /// `per_hour` units an hour, all of them available at once. Zero is
    /// none, as everywhere else; it used to become one an hour.
    fn per_hour(per_hour: f64) -> Self {
        let burst = per_hour.max(0.0);
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
    /// The client deposited key packages, so it may ask for others'.
    key_packages: bool,
    deposits: Bucket,
    /// Bundle publishes. A publish verifies a bundle's worth of
    /// signatures, writes three durable transactions and, when the bundle
    /// differs from the last, appends a transparency-log entry that is
    /// never pruned; a fresh signed prekey makes it differ every time.
    /// Sized for what a client legitimately does: one on connecting, and
    /// two more when it links or renames a device.
    publishes: Bucket,
    /// Acknowledgements, which are durable writes. Sized well above a
    /// full mailbox drain, so an honest client never meets it.
    acks: Bucket,
    /// The client's bundle advertises the `devices` capability, so it
    /// seals per device: its lookups get the linked devices' bundles, one
    /// prekey popped from each. A client that does not would waste them.
    devices: bool,
}

impl Conn {
    fn new(policy: &Policy, addr: IpAddr) -> Self {
        Self {
            addr,
            sends: Bucket::per_minute(policy.sends_per_minute),
            lookups: Bucket::per_minute(policy.lookups_per_minute),
            blobs: Bucket::per_minute(policy.blob_chunks_per_minute),
            prekeys: false,
            key_packages: false,
            deposits: Bucket::per_minute(KEY_PACKAGE_DEPOSITS_PER_MINUTE),
            publishes: Bucket::per_minute(PUBLISHES_PER_MINUTE),
            acks: Bucket::per_minute(ACKS_PER_MINUTE),
            devices: false,
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
    slow_closed: AtomicU64,
    group_commits: AtomicU64,
    group_rejections: AtomicU64,
}

/// A copy of the counters plus what is open right now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CounterSnapshot {
    pub open_connections: u32,
    pub addresses: usize,
    pub refused_connections: u64,
    pub refused_registrations: u64,
    pub refused_uploads: u64,
    pub idle_closed: u64,
    /// Connections closed because the client stopped reading and a frame
    /// could not be written within the write timeout.
    #[serde(default)]
    pub slow_closed: u64,
    /// Commits the group sequencer accepted, and ones it refused.
    #[serde(default)]
    pub group_commits: u64,
    #[serde(default)]
    pub group_rejections: u64,
}

/// What one sweep of the expiry loop deleted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Expired {
    pub messages: usize,
    pub blobs: usize,
    pub key_packages: usize,
    /// Group sequencer entries retired for sitting still, and headstones
    /// dropped after their grace period.
    pub groups: GroupSweep,
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
    /// Addresses and identities the operator has banned; read on every
    /// connection and every login, so kept in memory next to the store.
    bans: RwLock<Bans>,
    /// The invite token in force: the one set at runtime if any, else the
    /// command line's.
    invite: RwLock<Option<String>>,
    /// Salt for the pseudonyms in the log; new every run.
    log_salt: [u8; 16],
}

/// A logged-in connection, as the rest of the relay sees it.
///
/// The registry owns the only sender: the connection's own task keeps just
/// the receiver. So taking a session out of the registry drops the sender,
/// the queue ends, and the task winds up — an eviction cannot be lost
/// behind a queue that a client has stopped reading.
struct Session {
    id: u64,
    tx: mpsc::Sender<Outbound>,
    /// The next mailbox position to deliver from. Everything below it has
    /// been handed to this connection already.
    next: u64,
    /// Envelope ids delivered to this connection and not yet acknowledged,
    /// at most [`DELIVERY_WINDOW`] of them.
    in_flight: HashSet<String>,
}

enum Outbound {
    Frame(Box<ServerFrame>),
    /// The relay ends this session, and says why for the log: a newer
    /// session for the same user replaced it, or the administrator evicted
    /// or banned the identity. Whoever sent this took the session's place
    /// in the registry already.
    Close(&'static str),
}

/// Why the relay refused a client frame.
type Rejection = (ErrorCode, &'static str);

/// What the relay has to say back to one client frame.
enum Answer {
    /// Frames already in hand, written in order.
    Frames(Vec<ServerFrame>),
    /// A stored file, read out of the store and written a chunk at a
    /// time. The checks and the rate limit are already done
    /// ([`RelayState::open_blob`]); what is left is the reading.
    Blob { blob: String, total: u32 },
}

impl From<ServerFrame> for Answer {
    fn from(frame: ServerFrame) -> Self {
        Self::Frames(vec![frame])
    }
}

impl From<Vec<ServerFrame>> for Answer {
    fn from(frames: Vec<ServerFrame>) -> Self {
        Self::Frames(frames)
    }
}

/// What a client that published prekeys is told afterwards.
#[derive(Debug)]
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
        let bans = Bans::load(&store);
        let invite = match store.admin_setting(INVITE_SETTING) {
            Ok(Some(token)) => (!token.is_empty()).then_some(token),
            Ok(None) => policy.invite_token.clone(),
            Err(e) => {
                error!("reading the admin settings: {e:#}");
                policy.invite_token.clone()
            }
        };
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
            bans: RwLock::new(bans),
            invite: RwLock::new(invite),
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

    /// The store itself. Public for tests that make the relay misbehave
    /// (a key served but never logged); not part of the operator surface.
    #[doc(hidden)]
    pub fn store(&self) -> &Store {
        &self.store
    }

    fn addresses(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, AddressState>> {
        self.addresses.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The address a connection counts under: what the socket says, or
    /// what a trusted front says the client was. Canonical, so that one
    /// client is one address however it reached the socket.
    pub fn client_address(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> IpAddr {
        let peer = canonical_address(peer.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
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
                return canonical_address(forwarded);
            }
        }
        peer
    }

    /// Take a place for a connection from `addr`, or say why not.
    fn connect(self: &Arc<Self>, addr: IpAddr) -> Result<ConnectionGuard, &'static str> {
        if self.address_banned(addr) {
            self.counters
                .refused_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err("this address is banned from this relay");
        }
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
            slow_closed: self.counters.slow_closed.load(Ordering::Relaxed),
            group_commits: self.counters.group_commits.load(Ordering::Relaxed),
            group_rejections: self.counters.group_rejections.load(Ordering::Relaxed),
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

    // --- administration --------------------------------------------------------

    /// The invite token new identities must present, if any.
    pub fn invite_token(&self) -> Option<String> {
        self.invite
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Change the invite token while the relay runs. `Some(token)` requires
    /// it from now on; `None` requires none. Both are remembered in the
    /// store and win over `--invite-token` at later starts, until
    /// [`forget_invite_token`](Self::forget_invite_token).
    pub fn set_invite_token(&self, token: Option<String>) -> anyhow::Result<()> {
        self.store
            .set_admin_setting(INVITE_SETTING, Some(token.as_deref().unwrap_or("")))?;
        *self.invite.write().unwrap_or_else(|e| e.into_inner()) = token;
        Ok(())
    }

    /// Drop the runtime choice: the command line's token applies again,
    /// now and at later starts.
    pub fn forget_invite_token(&self) -> anyhow::Result<()> {
        self.store.set_admin_setting(INVITE_SETTING, None)?;
        *self.invite.write().unwrap_or_else(|e| e.into_inner()) = self.policy.invite_token.clone();
        Ok(())
    }

    pub fn address_banned(&self, addr: IpAddr) -> bool {
        self.bans
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .addresses
            .contains(&canonical_address(addr))
    }

    pub fn user_banned(&self, user: &UserId) -> bool {
        self.bans
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .users
            .contains(user)
    }

    /// Refuse `target` from now on, across restarts; a banned identity
    /// that is online is disconnected.
    pub fn ban(&self, target: &BanTarget, note: &str) -> anyhow::Result<()> {
        self.store.set_ban(
            &target.key(),
            &Ban {
                since_ms: now_ms(),
                note: note.to_owned(),
            },
        )?;
        {
            let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
            match target {
                BanTarget::Address(addr) => {
                    bans.addresses.insert(canonical_address(*addr));
                }
                BanTarget::Identity(user) => {
                    bans.users.insert(*user);
                }
            }
        }
        if let BanTarget::Identity(user) = target {
            self.disconnect(user, "banned by the administrator");
        }
        Ok(())
    }

    /// Whether there was a ban to lift.
    pub fn unban(&self, target: &BanTarget) -> anyhow::Result<bool> {
        let was = self.store.remove_ban(&target.key())?;
        let mut bans = self.bans.write().unwrap_or_else(|e| e.into_inner());
        match target {
            BanTarget::Address(addr) => {
                bans.addresses.remove(&canonical_address(*addr));
            }
            BanTarget::Identity(user) => {
                bans.users.remove(user);
            }
        }
        Ok(was)
    }

    pub fn bans(&self) -> anyhow::Result<Vec<BanRow>> {
        let mut rows: Vec<BanRow> = self
            .store
            .bans()?
            .into_iter()
            .map(|(key, ban)| BanRow {
                target: match BanTarget::from_key(&key) {
                    Some(BanTarget::Identity(user)) => format!("identity:{}", self.who(&user)),
                    _ => key,
                },
                since_ms: ban.since_ms,
                note: ban.note,
            })
            .collect();
        rows.sort_by(|a, b| a.target.cmp(&b.target));
        Ok(rows)
    }

    /// The identity `who` names: a full id, or the pseudonym the log and
    /// the admin listings use for it.
    pub fn resolve(&self, who: &str) -> anyhow::Result<Option<UserId>> {
        if let Ok(user) = who.parse::<UserId>() {
            return Ok(Some(user));
        }
        let banned: Vec<UserId> = self
            .bans
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .users
            .iter()
            .copied()
            .collect();
        Ok(self
            .store
            .users()?
            .into_iter()
            .chain(banned)
            .find(|user| self.who(user) == who))
    }

    /// Every identity with a bundle, largest mailbox first.
    pub fn identities(&self) -> anyhow::Result<Vec<IdentityRow>> {
        let mut rows = Vec::new();
        for user in self.store.users()? {
            let (messages, bytes) = self.store.usage(&user)?;
            let (one_time_prekeys, _) = self.store.one_time_status(&user)?;
            let (pq_one_time_prekeys, _) = self.store.pq_one_time_status(&user)?;
            let prekeys = self.store.bundle(&user)?.and_then(|b| b.prekeys);
            rows.push(IdentityRow {
                who: self.who(&user),
                online: self.online().contains_key(&user),
                banned: self.user_banned(&user),
                messages,
                bytes,
                one_time_prekeys,
                pq_one_time_prekeys,
                signed_prekey_at_ms: prekeys.as_ref().map(|p| p.signed.created_at_ms),
                post_quantum: prekeys.as_ref().is_some_and(|p| p.supports_post_quantum()),
            });
        }
        rows.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.who.cmp(&b.who)));
        Ok(rows)
    }

    /// Delete everything kept for `user` and disconnect them. Their
    /// identity is not banned: they can register again unless it is.
    pub fn evict(&self, user: &UserId) -> anyhow::Result<Removed> {
        self.disconnect(user, "evicted by the administrator");
        self.store.remove_user(user)
    }

    /// Take `user`'s session out of the registry and tell it to close.
    ///
    /// The notice is a courtesy: it says why in the log and closes the
    /// socket politely. Taking the session out of the registry is what
    /// actually ends it, so a client that has stopped reading — and whose
    /// queue is therefore full — goes just the same.
    fn disconnect(&self, user: &UserId, why: &'static str) {
        if let Some(session) = self.online().remove(user) {
            let _ = session.tx.try_send(Outbound::Close(why));
        }
    }

    /// [`disconnect`](Self::disconnect), with `why` sent to the client
    /// first, so a device learns from its relay that it is no longer one.
    fn close_with(&self, user: &UserId, why: &'static str) {
        if let Some(session) = self.online().remove(user) {
            let _ = session
                .tx
                .try_send(Outbound::Frame(Box::new(ServerFrame::error(
                    ErrorCode::Forbidden,
                    why,
                ))));
            let _ = session.tx.try_send(Outbound::Close(why));
        }
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
        let mut features = vec![
            feature::PREKEYS.to_owned(),
            feature::PQ_PREKEYS.to_owned(),
            feature::LIFECYCLE.to_owned(),
            feature::TRANSPARENCY.to_owned(),
        ];
        if self.policy.anonymous_sends_per_minute > 0 {
            features.push(feature::ANONYMOUS_SEND.to_owned());
        }
        if self.policy.max_blob_mib > 0 {
            features.push(feature::BLOBS.to_owned());
        }
        features.push(feature::GROUPS.to_owned());
        features.push(feature::DEVICES.to_owned());
        features
    }

    /// A group id for the log: hashed with the run's salt, as identities
    /// are, so the log does not list groups.
    fn group_label(&self, group: &silver_protocol::GroupId) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.log_salt);
        hasher.update(group.as_bytes());
        let digest = hasher.finalize();
        digest[..6].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Store `me`'s key package deposit (`docs/PROTOCOL.md` section 13);
    /// the reply.
    fn deposit_key_packages(
        &self,
        me: &UserId,
        packages: Vec<silver_protocol::wire::KeyPackageDeposit>,
        last_resort: Option<silver_protocol::wire::KeyPackageDeposit>,
        conn: &mut Conn,
    ) -> ServerFrame {
        use silver_protocol::group::{MAX_KEY_PACKAGE_BYTES, MAX_KEY_PACKAGES};
        if !conn.deposits.try_take() {
            return ServerFrame::error(
                ErrorCode::RateLimited,
                "key packages were deposited a moment ago; wait a minute",
            );
        }
        if packages.len() > MAX_KEY_PACKAGES {
            return ServerFrame::error(ErrorCode::TooLarge, "too many key packages");
        }
        let now = now_ms();
        for package in packages.iter().chain(last_resort.iter()) {
            if package.data.is_empty() || package.data.len() > MAX_KEY_PACKAGE_BYTES {
                return ServerFrame::error(ErrorCode::TooLarge, "a key package is too large");
            }
            if package.expires_at_ms <= now {
                return ServerFrame::error(
                    ErrorCode::Malformed,
                    "a key package has expired already",
                );
            }
        }
        if self.bundle(me).is_none() {
            return ServerFrame::error(ErrorCode::Forbidden, "publish a bundle first");
        }
        let stored = self
            .store
            .set_key_packages(me, &packages, last_resort.as_ref())
            .and_then(|()| self.store.key_package_status(me));
        match stored {
            Ok((remaining, consumed)) => {
                conn.key_packages = true;
                ServerFrame::KeyPackageStatus {
                    remaining,
                    consumed: consumed
                        .into_iter()
                        .map(silver_protocol::wire::KeyPackageRef)
                        .collect(),
                }
            }
            Err(e) => {
                error!("storing key packages: {e:#}");
                ServerFrame::error(ErrorCode::Internal, "storage error")
            }
        }
    }

    /// One of `user`'s key packages for a client that deposited its own:
    /// from the deposit while the handout budget lasts, the last-resort
    /// one after; `null` when the identity has none.
    fn key_package_for(&self, user: UserId, conn: &mut Conn) -> ServerFrame {
        if !conn.key_packages {
            return ServerFrame::error(
                ErrorCode::Forbidden,
                "deposit your own key packages before asking for others'",
            );
        }
        if !conn.lookups.try_take() {
            return ServerFrame::error(ErrorCode::RateLimited, "too many lookups; slow down");
        }
        let now = now_ms();
        let handed = if self.handout_allowed(&user) {
            self.store.take_key_package(&user, now)
        } else {
            debug!(
                "key packages for one user are being asked for quickly; serving the last resort"
            );
            self.store
                .last_resort_key_package(&user, now)
                .map(|p| p.map(|p| (p, true)))
        };
        match handed {
            Ok(Some((package, last_resort))) => ServerFrame::KeyPackageResult {
                user_id: user,
                package: Some(package),
                last_resort,
            },
            Ok(None) => ServerFrame::KeyPackageResult {
                user_id: user,
                package: None,
                last_resort: false,
            },
            Err(e) => {
                error!("taking a key package: {e:#}");
                ServerFrame::error(ErrorCode::Internal, "storage error")
            }
        }
    }

    /// Create a group's sequencer entry; on any kind of connection, against
    /// its `send` budget and the address's registration budget.
    fn group_create(
        &self,
        group: silver_protocol::GroupId,
        epoch: u64,
        next: [u8; 32],
        sends: &mut Bucket,
        addr: IpAddr,
    ) -> ServerFrame {
        let refuse =
            |code: ErrorCode, epoch: Option<u64>| ServerFrame::GroupRejected { group, code, epoch };
        if !sends.try_take() || !self.registration_allowed(addr) {
            return refuse(ErrorCode::RateLimited, None);
        }
        // The cap is on new entries; an existing one is still answered, so
        // a member re-creating a group after a restore gets its answer.
        let exists = self.store.group_epoch(&group).unwrap_or(None).is_some();
        if !exists
            && self.policy.max_groups > 0
            && self.store.group_count().unwrap_or(0) >= self.policy.max_groups
        {
            return refuse(ErrorCode::Forbidden, None);
        }
        match self.store.group_create(&group, epoch, next, now_ms()) {
            Ok(Sequenced::Stands(epoch)) => {
                debug!(group = %self.group_label(&group), epoch, "group sequencer entry created");
                ServerFrame::GroupState { group, epoch }
            }
            Ok(Sequenced::Exists(epoch)) => refuse(ErrorCode::Exists, Some(epoch)),
            Ok(other) => {
                error!("group create answered {other:?}");
                refuse(ErrorCode::Internal, None)
            }
            Err(e) => {
                error!("creating a group entry: {e:#}");
                refuse(ErrorCode::Internal, None)
            }
        }
    }

    /// Move a group's sequencer entry on; on any kind of connection,
    /// against its `send` budget.
    fn group_commit(
        &self,
        group: silver_protocol::GroupId,
        epoch: u64,
        token: [u8; 32],
        next: [u8; 32],
        sends: &mut Bucket,
    ) -> ServerFrame {
        let refuse =
            |code: ErrorCode, epoch: Option<u64>| ServerFrame::GroupRejected { group, code, epoch };
        if !sends.try_take() {
            return refuse(ErrorCode::RateLimited, None);
        }
        let outcome = self
            .store
            .group_commit(&group, epoch, &token, next, now_ms());
        match outcome {
            Ok(Sequenced::Stands(epoch)) => {
                self.counters.group_commits.fetch_add(1, Ordering::Relaxed);
                debug!(group = %self.group_label(&group), epoch, "group moved on");
                ServerFrame::GroupState { group, epoch }
            }
            Ok(rejected) => {
                self.counters
                    .group_rejections
                    .fetch_add(1, Ordering::Relaxed);
                debug!(group = %self.group_label(&group), ?rejected, "group commit refused");
                match rejected {
                    Sequenced::Stale(epoch) => refuse(ErrorCode::Stale, Some(epoch)),
                    Sequenced::NotFound => refuse(ErrorCode::NotFound, None),
                    Sequenced::Forbidden => refuse(ErrorCode::Forbidden, None),
                    Sequenced::Exists(epoch) => refuse(ErrorCode::Exists, Some(epoch)),
                    Sequenced::Stands(_) => unreachable!("handled above"),
                }
            }
            Err(e) => {
                error!("moving a group entry: {e:#}");
                refuse(ErrorCode::Internal, None)
            }
        }
    }

    /// Store a self-signed revocation for its identity: the identity is
    /// dead. Verified by its own signature, so no connection auth is needed
    /// (the key may be lost). A revoked identity that is online is
    /// disconnected and cannot publish again, and so are its linked
    /// devices, whose certificates name a dead account.
    ///
    /// Only an identity registered here can be revoked here, so the store
    /// holds at most one statement per identity it already knows and nobody
    /// can fill it with revocations of throwaway keys; and each statement
    /// costs `addr` one of its hourly registrations, since a statement that
    /// authenticates itself is otherwise free to send.
    pub fn apply_revocation(&self, revocation: Revocation, addr: IpAddr) -> Result<(), Rejection> {
        if !self.registration_allowed(addr) {
            return Err((
                ErrorCode::RateLimited,
                "this address has made its share of identity changes for the hour",
            ));
        }
        if revocation.verify().is_err() {
            return Err((ErrorCode::BadSignature, "revocation signature is invalid"));
        }
        let Some(bundle) = self.bundle(&revocation.identity) else {
            return Err((ErrorCode::Forbidden, "no such identity on this relay"));
        };
        self.store.set_revocation(&revocation).map_err(|e| {
            error!("storing revocation: {e:#}");
            (ErrorCode::Internal, "storage error")
        })?;
        self.disconnect(&revocation.identity, "revoked by its owner");
        for device in &bundle.devices {
            self.close_with(&device.device, "this device's account has been revoked");
        }
        Ok(())
    }

    /// Store an account's revocation of one of its devices
    /// (`docs/PROTOCOL.md` section 14), sent by `me`, the account, on its
    /// own connection: the device is cut off (disconnected, its mailbox
    /// and deposits dropped, its later logins and publishes refused), the
    /// statement is logged and served on lookups of the device and of the
    /// account. A device already revoked is left as it was and the frame
    /// still answered, so a client that lost the reply may repeat itself.
    ///
    /// Only a device the relay knows as this account's can be revoked: one
    /// on the account's published list, or one whose own bundle carries
    /// the account's certificate. Otherwise any account could cut off any
    /// identity by calling it a device of its own. Each statement costs
    /// `addr` one of its hourly registrations.
    pub fn apply_device_revocation(
        &self,
        me: &UserId,
        revocation: DeviceRevocation,
        addr: IpAddr,
    ) -> Result<(), Rejection> {
        if !self.registration_allowed(addr) {
            return Err((
                ErrorCode::RateLimited,
                "this address has made its share of identity changes for the hour",
            ));
        }
        if revocation.account != *me {
            return Err((
                ErrorCode::Forbidden,
                "a device is revoked by its own account",
            ));
        }
        if revocation.verify().is_err() {
            return Err((
                ErrorCode::BadSignature,
                "device revocation signature is invalid",
            ));
        }
        let Some(mine) = self.bundle(me) else {
            return Err((ErrorCode::Forbidden, "publish a bundle first"));
        };
        let listed = mine.devices.iter().any(|d| d.device == revocation.device);
        let published = self.bundle(&revocation.device);
        let claims_me = published.as_ref().is_some_and(|b| b.account() == Some(me));
        // A key that published a bundle of its own that does not claim this
        // account is an identity in its own right, and no list of this
        // account's makes it otherwise: taking the statement would cut a
        // stranger off for good. A listed key that has published nothing
        // here is still this account's to cancel; it is the state a device
        // is in between registering and claiming (section 14.6), and the
        // statement binds nothing until a bundle claims this account.
        if !claims_me && !(listed && published.is_none()) {
            return Err((
                ErrorCode::Forbidden,
                "that is not a device of this account on this relay",
            ));
        }
        let new = self.store.set_device_revocation(&revocation).map_err(|e| {
            error!("storing device revocation: {e:#}");
            (ErrorCode::Internal, "storage error")
        })?;
        // Only a device that claims this account is cut off: for one that
        // published nothing there is nothing to drop, and the id may yet
        // belong to somebody who is nobody's device.
        if claims_me {
            if new {
                match self.store.cut_off(&revocation.device) {
                    Ok(removed) => info!(
                        device = %self.who(&revocation.device),
                        "device revoked by its account; {} queued envelopes and {} prekeys dropped",
                        removed.messages,
                        removed.prekeys
                    ),
                    Err(e) => error!("dropping a revoked device's mailbox: {e:#}"),
                }
            }
            self.close_with(
                &revocation.device,
                "this device has been revoked by its account",
            );
        }
        Ok(())
    }

    /// Undo a device revocation: the statement is dropped, so the id is
    /// refused nothing on its strength and may publish, log in and receive
    /// again. The log entry stays, as everything in an append-only log
    /// does; a client reads it against the statement the relay serves, and
    /// there is none once this returns. For an operator putting right a
    /// revocation that should not have been taken.
    pub fn unrevoke_device(&self, device: &UserId) -> anyhow::Result<bool> {
        self.store.remove_device_revocation(device)
    }

    /// Whether `host`, as the client signed it, is a name this relay
    /// answers to.
    ///
    /// The point of the bound login (`docs/PROTOCOL.md` section 7.1) is
    /// that a relay in the middle cannot forward this relay's challenge
    /// under its own name and use the answer here. So the name must be
    /// checked against what this relay *is*, from its configuration, and
    /// not against the `Host` header of the upgrade request, which
    /// whoever connects writes: with the header alone the attacker's own
    /// name matches on both sides and the login travels. With no names
    /// configured there is nothing else to compare with, so the header
    /// stands in and the relay says at start that logins are not really
    /// bound.
    fn host_is_ours(&self, host: &str, reached_as: Option<&str>) -> bool {
        if self.policy.hosts.is_empty() {
            return reached_as == Some(host);
        }
        self.policy.hosts.iter().any(|ours| ours == host)
    }

    /// The account whose device `user` is here: the certificate in the
    /// bundle it published, which the account signed and which was checked
    /// on publish. An identity that published no claim is nobody's device,
    /// whatever anyone else's list says about it.
    fn device_account(&self, user: &UserId) -> Option<UserId> {
        self.bundle(user)?.account().copied()
    }

    /// Whether the relay holds `account`'s revocation of `device`.
    fn revoked_by(&self, account: &UserId, device: &UserId) -> bool {
        match self.store.device_revocation(device) {
            Ok(held) => held.is_some_and(|r| r.account == *account),
            Err(e) => {
                error!("reading device revocation: {e:#}");
                false
            }
        }
    }

    /// Whether `user` is cut off as a revoked device: the relay holds a
    /// revocation for it from the very account its own bundle claims.
    ///
    /// A statement about an id that claims nobody, or that claims someone
    /// else, binds nothing here; otherwise any account could cut any
    /// identity off by naming it a device of its own and revoking it, and
    /// the victim would never register, publish or receive again.
    fn is_revoked_device(&self, user: &UserId) -> bool {
        match self.device_account(user) {
            Some(account) => self.revoked_by(&account, user),
            None => false,
        }
    }

    /// Why `user` may not log in, if it may not: it is revoked, its
    /// account revoked it, or its account is dead. `None` for anyone else.
    ///
    /// A revoked identity is dead everywhere else — it cannot publish, and
    /// its contacts drop it — so it does not go on reading and
    /// acknowledging the mailbox either. Whoever holds a key that was
    /// revoked because it was compromised is exactly who this refuses.
    pub fn login_refusal(&self, user: &UserId) -> Option<&'static str> {
        if self.is_revoked(user) {
            return Some("this identity has been revoked");
        }
        if self.is_revoked_device(user) {
            return Some("this device has been revoked by its account");
        }
        let account = self.bundle(user)?.account().copied()?;
        self.is_revoked(&account)
            .then_some("this device's account has been revoked")
    }

    /// The linked devices' bundles to attach to a lookup of `account`
    /// whose bundle is `bundle`: every device on the list that has a
    /// bundle claiming the account and is not revoked, a one-time prekey
    /// popped from each as on its own lookup.
    fn device_bundles(&self, account: &UserId, bundle: Option<&KeyBundle>) -> Vec<KeyBundle> {
        let Some(bundle) = bundle else {
            return Vec::new();
        };
        bundle
            .devices
            .iter()
            .filter(|device| !self.revoked_by(account, &device.device))
            .filter_map(|device| {
                let mut bundle = self.bundle(&device.device)?;
                if bundle.account() != Some(account) {
                    return None;
                }
                self.pop_one_time_prekeys(&mut bundle);
                Some(bundle)
            })
            .collect()
    }

    /// The device revocations to attach to a lookup of `user`: every one
    /// it issued as an account, and its own if it is a revoked device.
    fn device_revocations(&self, user: &UserId) -> Vec<DeviceRevocation> {
        let mut out = self.store.device_revocations_by(user).unwrap_or_else(|e| {
            error!("reading device revocations: {e:#}");
            Vec::new()
        });
        match self.store.device_revocation(user) {
            Ok(Some(own)) => out.push(own),
            Ok(None) => {}
            Err(e) => error!("reading device revocation: {e:#}"),
        }
        out
    }

    /// Store a cross-signed succession, keyed by the old identity. The old
    /// identity must be registered here and not revoked: a dead key cannot
    /// hand over, so a succession cannot undo a revocation. The successor
    /// must not be a revoked key either.
    pub fn apply_succession(&self, succession: Succession, addr: IpAddr) -> Result<(), Rejection> {
        if !self.registration_allowed(addr) {
            return Err((
                ErrorCode::RateLimited,
                "this address has made its share of identity changes for the hour",
            ));
        }
        if succession.verify().is_err() {
            return Err((ErrorCode::BadSignature, "succession signature is invalid"));
        }
        if self.bundle(&succession.old).is_none() {
            return Err((ErrorCode::Forbidden, "no such identity on this relay"));
        }
        if self.is_revoked(&succession.old) {
            return Err((
                ErrorCode::Forbidden,
                "that identity has been revoked and cannot hand over",
            ));
        }
        if self.is_revoked(&succession.new) {
            return Err((ErrorCode::Forbidden, "the successor has been revoked"));
        }
        self.store.set_succession(&succession).map_err(|e| {
            error!("storing succession: {e:#}");
            (ErrorCode::Internal, "storage error")
        })?;
        Ok(())
    }

    fn is_revoked(&self, user: &UserId) -> bool {
        self.store.is_revoked(user).unwrap_or_else(|e| {
            error!("reading revocation: {e:#}");
            false
        })
    }

    /// Where the transparency log stands.
    pub fn log_head(&self) -> LogHead {
        self.store.log_head().unwrap_or_else(|e| {
            error!("reading the log head: {e:#}");
            LogHead::EMPTY
        })
    }

    /// The log head and where `user` last appears in the log, for a
    /// lookup result.
    pub fn log_view(&self, user: &UserId) -> (Option<LogHead>, Option<LogPosition>) {
        let logged = self.store.log_latest(user).unwrap_or_else(|e| {
            error!("reading the log: {e:#}");
            None
        });
        (Some(self.log_head()), logged)
    }

    /// A page of log entries after `index`, and the head.
    pub fn log_since(&self, index: u64) -> (Vec<LogEntry>, LogHead) {
        let entries = self
            .store
            .log_since(index, silver_protocol::transparency::LOG_PAGE)
            .unwrap_or_else(|e| {
                error!("reading the log: {e:#}");
                Vec::new()
            });
        (entries, self.log_head())
    }

    /// The lifecycle statements the relay holds for `user`, to attach to a
    /// lookup result. A revocation is final: once one is held, no succession
    /// is served for the identity, whichever came first.
    pub fn lifecycle(&self, user: &UserId) -> (Option<Revocation>, Option<Succession>) {
        let revocation = self.store.revocation(user).unwrap_or_else(|e| {
            error!("reading revocation: {e:#}");
            None
        });
        if revocation.is_some() {
            return (revocation, None);
        }
        let succession = self.store.succession(user).unwrap_or_else(|e| {
            error!("reading succession: {e:#}");
            None
        });
        (revocation, succession)
    }

    /// Delete unacknowledged envelopes and file blobs older than `ttl` and
    /// key packages past their lifetime; retire group sequencer entries
    /// idle for [`GROUP_IDLE_TTL`] and drop headstones older than
    /// [`GROUP_HEADSTONE_TTL`]. Returns how many of each.
    pub fn expire(&self, ttl: Duration) -> Expired {
        let now = now_ms();
        let cutoff = now.saturating_sub(ttl.as_millis() as u64);
        let messages = self.store.expire(cutoff).unwrap_or_else(|e| {
            error!("expiring messages: {e:#}");
            0
        });
        let blobs = self.store.expire_blobs(cutoff).unwrap_or_else(|e| {
            error!("expiring blobs: {e:#}");
            0
        });
        let key_packages = self.store.expire_key_packages(now).unwrap_or_else(|e| {
            error!("expiring key packages: {e:#}");
            0
        });
        let idle_cutoff = now.saturating_sub(GROUP_IDLE_TTL.as_millis() as u64);
        let grace_cutoff = now.saturating_sub(GROUP_HEADSTONE_TTL.as_millis() as u64);
        let groups = self
            .store
            .expire_groups(now, idle_cutoff, grace_cutoff)
            .unwrap_or_else(|e| {
                error!("expiring group entries: {e:#}");
                GroupSweep::default()
            });
        Expired {
            messages,
            blobs,
            key_packages,
            groups,
        }
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
        // A chunk costs a database entry whatever it holds, so a tiny one
        // is charged for the entry: otherwise a client fills the store
        // with zero-byte chunks that no byte budget ever notices.
        let charge = data.len().max(CHUNK_OVERHEAD_BYTES);
        if !bucket.try_take() {
            return blob_rejected(&blob, ErrorCode::RateLimited, "too many chunks; slow down");
        }
        if !self.upload_allowed(addr, charge) {
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
    /// Answer a `blob_get`: the checks and the whole request's cost, then
    /// the file's chunks left in the store for the connection to stream.
    ///
    /// A file is up to 16 MiB and the relay serves whoever asks; reading
    /// one into a reply in one go would mean holding a copy per reader,
    /// which is the same mistake as pushing a whole mailbox into a queue.
    fn open_blob(&self, blob: &str, bucket: &mut Bucket) -> Answer {
        let reject = |code, message| Answer::from(blob_rejected(blob, code, message));
        if !is_valid_blob_id(blob) {
            return reject(ErrorCode::Malformed, "blob id must be 32 hex characters");
        }
        let meta = match self.store.blob_meta(blob) {
            Ok(Some(meta)) if meta.is_complete() => meta,
            Ok(_) => {
                return reject(
                    ErrorCode::NotFound,
                    "no such file on this relay (it may have expired)",
                );
            }
            Err(e) => {
                error!("reading blob: {e:#}");
                return reject(ErrorCode::Internal, "storage error");
            }
        };
        // The whole file's worth of budget, taken before a byte is read:
        // a download either goes out entire or is refused, as before.
        if !bucket.try_take_n(f64::from(meta.total)) {
            return reject(ErrorCode::RateLimited, "too many chunks; slow down");
        }
        Answer::Blob {
            blob: blob.to_owned(),
            total: meta.total,
        }
    }

    /// One chunk of a stored file, for [`Answer::Blob`] to stream.
    fn blob_chunk(&self, blob: &str, index: u32, total: u32) -> ServerFrame {
        match self.store.blob_chunk(blob, index) {
            Ok(Some(data)) => ServerFrame::BlobChunk {
                blob: blob.to_owned(),
                index,
                total,
                data,
            },
            // Expiry can take a file out from under a download; the
            // reader is told rather than left waiting for the rest.
            Ok(None) => blob_rejected(blob, ErrorCode::NotFound, "file is incomplete"),
            Err(e) => {
                error!("reading blob chunk: {e:#}");
                blob_rejected(blob, ErrorCode::Internal, "storage error")
            }
        }
    }

    fn online(&self) -> std::sync::MutexGuard<'_, HashMap<UserId, Session>> {
        self.online.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a freshly authenticated session, replacing any older one
    /// for the same user, and start replaying its unacknowledged mail.
    fn register(&self, user: UserId, tx: mpsc::Sender<Outbound>) -> u64 {
        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        {
            let mut online = self.online();
            let session = Session {
                id,
                tx,
                next: 0,
                in_flight: HashSet::new(),
            };
            if let Some(old) = online.insert(user, session) {
                let _ = old
                    .tx
                    .try_send(Outbound::Close("replaced by a newer session"));
            }
        }
        self.deliver_more(&user);
        id
    }

    /// Fill `user`'s connection back up to the delivery window from their
    /// mailbox: the only path an envelope takes to a client.
    ///
    /// Everything is read from the store in mailbox order and the session
    /// remembers where it got to, so a client is never handed the same
    /// envelope twice within a session, whether the envelope arrived while
    /// it was connected or was waiting when it logged in.
    fn deliver_more(&self, user: &UserId) {
        // What to read, decided under the lock and then let go of: the
        // store is not touched with the registry held, so one slow read
        // cannot hold up every other connection.
        let (session_id, from, want) = {
            let online = self.online();
            let Some(session) = online.get(user) else {
                return;
            };
            let want = DELIVERY_WINDOW.saturating_sub(session.in_flight.len());
            if want == 0 {
                return;
            }
            (session.id, session.next, want)
        };
        let page = match self.store.queued_from(user, from, want) {
            Ok(page) => page,
            Err(e) => {
                error!("reading mailbox: {e:#}");
                return;
            }
        };
        if page.is_empty() {
            return;
        }
        let mut online = self.online();
        let Some(session) = online.get_mut(user) else {
            return;
        };
        // Another delivery got there first: it read the same page and sent
        // it, so this one is stale and sending it would repeat envelopes.
        if session.id != session_id || session.next != from {
            return;
        }
        for (at, envelope) in page {
            let id = envelope.id.clone();
            if session
                .tx
                .try_send(Outbound::Frame(Box::new(ServerFrame::Deliver { envelope })))
                .is_err()
            {
                // The queue is full or the connection has gone. Either way
                // the position is not advanced, so whatever is left goes
                // out on the next acknowledgement or the next login.
                break;
            }
            session.next = at + 1;
            session.in_flight.insert(id);
        }
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
        // A revoked identity is dead: it cannot be published again. Nor can
        // a revoked device, under the claim it makes now or the one it
        // made before; a revocation by an account this key never claimed
        // is somebody else's statement and binds nothing.
        if self.is_revoked(me) {
            return Err((ErrorCode::Forbidden, "this identity has been revoked"));
        }
        let claims_now = bundle.device_of.as_ref().map(|c| c.account);
        if claims_now.is_some_and(|account| self.revoked_by(&account, me))
            || self.is_revoked_device(me)
        {
            return Err((
                ErrorCode::Forbidden,
                "this device has been revoked by its account",
            ));
        }
        // A device's claim to an account is checked here as a courtesy to
        // clients, which check it again: the certificate verified above,
        // and the account must be one this relay knows and still serves.
        if let Some(certificate) = &bundle.device_of {
            if self.bundle(&certificate.account).is_none() {
                return Err((
                    ErrorCode::Forbidden,
                    "the account this device claims is not on this relay",
                ));
            }
            if self.is_revoked(&certificate.account) {
                return Err((
                    ErrorCode::Forbidden,
                    "the account this device claims has been revoked",
                ));
            }
        }
        // The list verified as signed and within its cap; a device this
        // account revoked cannot be listed back in. Another account's
        // revocation is not this list's business.
        if bundle
            .devices
            .iter()
            .any(|device| self.revoked_by(me, &device.device))
        {
            return Err((
                ErrorCode::Forbidden,
                "the device list names a device that has been revoked",
            ));
        }
        // Nor may a list name an identity that is already another
        // account's device here. A key that has published nothing, or a
        // plain bundle of its own, is still listable: that is the state a
        // device is in between registering and claiming the account
        // (section 14.6), so the list is published before the claim.
        if bundle.devices.iter().any(|device| {
            self.device_account(&device.device)
                .is_some_and(|a| a != *me)
        }) {
            return Err((
                ErrorCode::Forbidden,
                "the device list names another account's device",
            ));
        }
        // A new identity: the invite token, the registration rate for the
        // address, and the room left all have a say.
        if self.bundle(me).is_none() {
            if let Some(token) = self.invite_token() {
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
        self.pop_one_time_prekeys(&mut bundle);
        Some(bundle)
    }

    /// Put one one-time prekey of each kind into `bundle`, from its owner's
    /// deposit, if the owner has any left and they are not being handed out
    /// faster than the policy allows.
    fn pop_one_time_prekeys(&self, bundle: &mut KeyBundle) {
        let user = bundle.user_id;
        if let Some(prekeys) = bundle.prekeys.as_mut() {
            if !self.handout_allowed(&user) {
                debug!("one-time prekeys for one user are being asked for quickly; serving none");
                return;
            }
            match self.store.take_one_time_prekey(&user) {
                Ok(taken) => prekeys.one_time = taken.into_iter().collect(),
                Err(e) => error!("taking one-time prekey: {e:#}"),
            }
            match self.store.take_pq_one_time_prekey(&user) {
                Ok(taken) => prekeys.pq_one_time = taken.into_iter().collect(),
                Err(e) => error!("taking one-time ML-KEM prekey: {e:#}"),
            }
        }
    }

    /// Queue an envelope for its recipient and push it if they are online.
    fn route(&self, envelope: Envelope) -> Result<(), Rejection> {
        if envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err((ErrorCode::TooLarge, "ciphertext too large"));
        }
        // A revoked device is gone: the refusal tells a sender that its
        // copy of the recipient's device list is stale.
        if self.is_revoked_device(&envelope.to) {
            return Err((
                ErrorCode::NotFound,
                "the recipient device has been revoked by its account",
            ));
        }
        // Somebody who has published nothing here has no mailbox here.
        // Everyone a client legitimately seals to has a bundle: a contact,
        // a device of theirs, a member of a group. Without this a stranger
        // could fill the disk with envelopes for keys nobody holds, which
        // nobody is there to acknowledge and which only go when the
        // message lifetime runs out.
        if self.bundle(&envelope.to).is_none() {
            return Err((ErrorCode::NotFound, "no such recipient on this relay"));
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
                if self.online().contains_key(&envelope.to) {
                    debug!(id = %envelope.id, "queued and pushed to the recipient's connection");
                    // From the store, not from here: the recipient may
                    // have a backlog in front of this one, and everything
                    // reaches a client in mailbox order or not at all.
                    self.deliver_more(&envelope.to);
                } else {
                    debug!(id = %envelope.id, "queued; recipient offline");
                }
                Ok(())
            }
            // A resend of something already queued: nothing to do, the
            // recipient will get (or has got) the original.
            Enqueue::Duplicate => Ok(()),
            Enqueue::MailboxFull => Err((ErrorCode::MailboxFull, "recipient mailbox is full")),
            Enqueue::StorageFull => Err((
                ErrorCode::StorageFull,
                "this relay is holding as much queued mail as it will",
            )),
        }
    }

    /// Rate-limit and route a submitted envelope; the reply for the sender.
    fn submit(&self, envelope: Envelope, bucket: &mut Bucket, who: Option<&UserId>) -> ServerFrame {
        let id = envelope.id.clone();
        // The id becomes a key in the store and reaches the recipient's
        // client and its log, so it follows the rule every message id
        // follows (protocol section 4) rather than being whatever the
        // sender put there: empty, enormous, or full of control
        // characters.
        if !silver_protocol::envelope::is_valid_message_id(&id) {
            return ServerFrame::Rejected {
                id: String::new(),
                code: ErrorCode::Malformed,
                message: "envelope id must be 1 to 64 printable ASCII characters".into(),
            };
        }
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

    /// An envelope the client says it has. It leaves the mailbox, its
    /// place in the delivery window is freed, and the next page — if the
    /// window was full and mail is still waiting — goes out.
    fn ack(&self, me: &UserId, id: &str) {
        if let Err(e) = self.store.ack(me, id) {
            error!("acknowledging envelope: {e:#}");
        }
        let freed = self
            .online()
            .get_mut(me)
            .is_some_and(|session| session.in_flight.remove(id));
        if freed {
            self.deliver_more(me);
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
        let expired = state.expire(ttl);
        if expired != Expired::default() {
            info!(
                "expired {} unacknowledged envelopes and {} files older than {ttl:?} and {} key packages past their lifetime; retired {} group entries idle for {GROUP_IDLE_TTL:?} and dropped {} retired for {GROUP_HEADSTONE_TTL:?}",
                expired.messages,
                expired.blobs,
                expired.key_packages,
                expired.groups.retired,
                expired.groups.dropped
            );
        }
        state.sweep_addresses();
        let c = state.counters();
        info!(
            "{} connections open from {} addresses; refused so far: {} connections, {} registrations, {} uploads, {} logins; {} closed idle, {} closed for not reading",
            c.open_connections,
            c.addresses,
            c.refused_connections,
            c.refused_registrations,
            c.refused_uploads,
            state.auth_failures().total(),
            c.idle_closed,
            c.slow_closed
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
    let handle = axum_server::Handle::new();
    let stop = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        stop.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    let mut server = axum_server::from_tcp(listener.into_std()?)?;
    set_http_timeouts(server.http_builder());
    server
        .handle(handle)
        .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

/// How long a connection may take to send its request line and headers.
///
/// A WebSocket connection is counted, timed and rate-limited from the
/// upgrade on; before that it is an HTTP request like any other. Hyper has
/// a default for this but discards it when no timer is installed, which is
/// what the server builders do by default, so without this a connection
/// that says nothing holds a socket and a task until the process runs out
/// of file descriptors, below every limit the relay counts.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn set_http_timeouts(
    builder: &mut hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor>,
) {
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
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
                    if !state.host_is_ours(&host, our_host.as_deref()) {
                        Err((
                            ErrorCode::BadSignature,
                            "the login names a host this relay does not answer to",
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
            if state.user_banned(&user_id) {
                let _ = send(
                    &mut sink,
                    &ServerFrame::error(
                        ErrorCode::Forbidden,
                        "this identity is banned from this relay",
                    ),
                )
                .await;
                return;
            }
            // A revoked identity, a device its account revoked, or one
            // whose account is dead: told so, and given no session. The
            // mailbox is not theirs to read.
            if let Some(why) = state.login_refusal(&user_id) {
                let _ = send(&mut sink, &ServerFrame::error(ErrorCode::Forbidden, why)).await;
                return;
            }
            user_id
        }
        // A revocation or a succession authenticates itself, so the relay
        // takes it without a login: a revoked key may be lost and unable to
        // log in. It is a one-shot; the connection then closes.
        Ok(Some(Ok(ClientFrame::Revoke { revocation }))) => {
            let reply = match state.apply_revocation(revocation, addr) {
                Ok(()) => ServerFrame::Published,
                Err((code, message)) => ServerFrame::error(code, message),
            };
            let _ = send(&mut sink, &reply).await;
            return;
        }
        Ok(Some(Ok(ClientFrame::Succeed { succession }))) => {
            let reply = match state.apply_succession(succession, addr) {
                Ok(()) => ServerFrame::Published,
                Err((code, message)) => ServerFrame::error(code, message),
            };
            let _ = send(&mut sink, &reply).await;
            return;
        }
        Ok(Some(Ok(
            frame @ (ClientFrame::Send { .. }
            | ClientFrame::BlobPut { .. }
            | ClientFrame::BlobGet { .. }
            | ClientFrame::GroupCreate { .. }
            | ClientFrame::GroupCommit { .. }),
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

    let (tx, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
    let mut conn = Conn::new(&state.policy, addr);
    // The sender goes to the registry and is not kept here: the queue
    // ending is how this task learns its session was replaced or evicted.
    let session_id = state.register(user, tx);
    let who = state.who(&user);
    info!(%who, session_id, "client authenticated");
    let auth_ok = ServerFrame::AuthOk {
        user_id: user,
        features: state.features(),
        head: Some(state.log_head()),
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
                    if let Err(e) = write(&mut sink, &frame, &state).await {
                        debug!(%who, session_id, "write failed ({e}); closing");
                        break;
                    }
                }
                Some(Outbound::Close(why)) => {
                    debug!(%who, session_id, "closing: {why}");
                    let _ = sink.close().await;
                    return; // whoever sent this owns the registry entry now
                }
                // The registry let go of this session: it was replaced by
                // a newer one, or the administrator took it away.
                None => break,
            },
            inbound = tokio::time::timeout(state.policy.idle_timeout, next_frame(&mut stream)) => match inbound {
                Ok(Some(Ok(frame))) => {
                    // Replies go straight to the socket rather than round
                    // the queue: the queue is for what the relay pushes,
                    // and an answer must not sit behind a mailbox drain.
                    let replies = handle_frame(&state, &user, frame, &mut conn);
                    if let Err(e) = answer(&mut sink, &state, replies).await {
                        debug!(%who, session_id, "write failed ({e}); closing");
                        break;
                    }
                }
                Ok(Some(Err(e))) => {
                    let reply = ServerFrame::error(ErrorCode::Malformed, e);
                    if write(&mut sink, &reply, &state).await.is_err() {
                        break;
                    }
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
        let replies: Vec<ServerFrame> = match frame {
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
            ClientFrame::BlobGet { blob } => {
                if answer(&mut sink, state, state.open_blob(&blob, &mut blobs))
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
            ClientFrame::GroupCreate { group, epoch, next } => {
                vec![state.group_create(group, epoch, next, &mut bucket, addr)]
            }
            ClientFrame::GroupCommit {
                group,
                epoch,
                token,
                next,
            } => vec![state.group_commit(group, epoch, token, next, &mut bucket)],
            ClientFrame::Ping => vec![ServerFrame::Pong],
            _ => vec![ServerFrame::error(
                ErrorCode::Unauthenticated,
                "this connection only accepts send, file chunks, group sequencing and ping",
            )],
        };
        for reply in &replies {
            if write(&mut sink, reply, state).await.is_err() {
                return;
            }
        }
    }
    debug!("anonymous submission session closed");
}

fn handle_frame(state: &RelayState, me: &UserId, frame: ClientFrame, conn: &mut Conn) -> Answer {
    let replies: Vec<ServerFrame> = match frame {
        ClientFrame::Auth { .. } => vec![ServerFrame::error(
            ErrorCode::Malformed,
            "already authenticated",
        )],
        ClientFrame::Publish { bundle, invite } => {
            // Before the signatures are verified and the writes made: a
            // publish is the most expensive frame there is, and the only
            // one that leaves something behind for good (a transparency
            // entry, which a fresh signed prekey makes different every
            // time).
            if !conn.publishes.try_take() {
                warn!(who = %state.who(me), "publish rate limit hit");
                return Answer::from(ServerFrame::error(
                    ErrorCode::RateLimited,
                    "too many bundle publishes; slow down",
                ));
            }
            let devices = bundle
                .caps
                .iter()
                .any(|c| c == silver_protocol::bundle::capability::DEVICES);
            match state.publish(me, bundle, invite.as_deref(), conn.addr) {
                Ok(report) => {
                    conn.devices = devices;
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
        ClientFrame::LogSince { index } => {
            if !conn.lookups.try_take() {
                warn!(who = %state.who(me), "lookup rate limit hit");
                return Answer::from(ServerFrame::error(
                    ErrorCode::RateLimited,
                    "too many lookups; slow down",
                ));
            }
            let (entries, head) = state.log_since(index);
            vec![ServerFrame::LogEntries { entries, head }]
        }
        ClientFrame::Lookup { user_id } => {
            if !conn.lookups.try_take() {
                warn!(who = %state.who(me), "lookup rate limit hit");
                return Answer::from(ServerFrame::error(
                    ErrorCode::RateLimited,
                    "too many lookups; slow down",
                ));
            }
            // Only a client that can use a one-time prekey gets one.
            let bundle = if conn.prekeys {
                state.bundle_with_one_time_prekey(&user_id)
            } else {
                state.bundle(&user_id)
            };
            let (revocation, succession) = state.lifecycle(&user_id);
            let (head, logged) = state.log_view(&user_id);
            // Only a client that seals per device gets the devices' bundles
            // (and costs them a prekey each); the revocations are cheap and
            // go to everyone.
            let device_bundles = if conn.devices {
                state.device_bundles(&user_id, bundle.as_ref())
            } else {
                Vec::new()
            };
            let device_revocations = state.device_revocations(&user_id);
            vec![ServerFrame::LookupResult {
                user_id,
                bundle,
                revocation,
                succession,
                head,
                logged,
                device_bundles,
                device_revocations,
            }]
        }
        ClientFrame::Revoke { revocation } => match state.apply_revocation(revocation, conn.addr) {
            Ok(()) => vec![ServerFrame::Published],
            Err((code, message)) => vec![ServerFrame::error(code, message)],
        },
        ClientFrame::Succeed { succession } => {
            match state.apply_succession(succession, conn.addr) {
                Ok(()) => vec![ServerFrame::Published],
                Err((code, message)) => vec![ServerFrame::error(code, message)],
            }
        }
        ClientFrame::RevokeDevice { revocation } => {
            match state.apply_device_revocation(me, revocation, conn.addr) {
                Ok(()) => vec![ServerFrame::Published],
                Err((code, message)) => vec![ServerFrame::error(code, message)],
            }
        }
        ClientFrame::Send { envelope } => vec![state.submit(envelope, &mut conn.sends, Some(me))],
        ClientFrame::Ack { id } => {
            if !silver_protocol::envelope::is_valid_message_id(&id) {
                return Answer::from(ServerFrame::error(
                    ErrorCode::Malformed,
                    "envelope id must be 1 to 64 printable ASCII characters",
                ));
            }
            if !conn.acks.try_take() {
                warn!(who = %state.who(me), "ack rate limit hit");
                return Answer::from(ServerFrame::error(
                    ErrorCode::RateLimited,
                    "too many acknowledgements; slow down",
                ));
            }
            state.ack(me, &id);
            Vec::new()
        }
        ClientFrame::BlobPut {
            blob,
            index,
            total,
            data,
        } => vec![state.put_blob(blob, index, total, &data, &mut conn.blobs, conn.addr)],
        ClientFrame::BlobGet { blob } => return state.open_blob(&blob, &mut conn.blobs),
        ClientFrame::KeyPackages {
            packages,
            last_resort,
        } => vec![state.deposit_key_packages(me, packages, last_resort, conn)],
        ClientFrame::KeyPackage { user_id } => vec![state.key_package_for(user_id, conn)],
        ClientFrame::GroupCreate { group, epoch, next } => {
            vec![state.group_create(group, epoch, next, &mut conn.sends, conn.addr)]
        }
        ClientFrame::GroupCommit {
            group,
            epoch,
            token,
            next,
        } => vec![state.group_commit(group, epoch, token, next, &mut conn.sends)],
        ClientFrame::Ping => vec![ServerFrame::Pong],
    };
    Answer::Frames(replies)
}

/// Why a frame did not reach the client.
enum SendError {
    Socket(axum::Error),
    /// The client stopped reading: the write did not go in
    /// [`WRITE_TIMEOUT`], so the connection is given up on.
    TooSlow,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(e) => write!(f, "{e}"),
            Self::TooSlow => write!(f, "the client did not read for {WRITE_TIMEOUT:?}"),
        }
    }
}

/// Write one frame to the client, giving up after [`WRITE_TIMEOUT`].
async fn send(sink: &mut Sink, frame: &ServerFrame) -> Result<(), SendError> {
    let write = sink.send(Message::Text(frame.encode().into()));
    match tokio::time::timeout(WRITE_TIMEOUT, write).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(SendError::Socket(e)),
        Err(_) => Err(SendError::TooSlow),
    }
}

/// [`send`], counting a client that stopped reading so an operator sees
/// how often it happens.
async fn write(sink: &mut Sink, frame: &ServerFrame, state: &RelayState) -> Result<(), SendError> {
    let out = send(sink, frame).await;
    if matches!(out, Err(SendError::TooSlow)) {
        state.counters.slow_closed.fetch_add(1, Ordering::Relaxed);
    }
    out
}

/// Write everything one client frame is answered with. A file's chunks
/// are read from the store one at a time, so the relay holds a chunk per
/// reader rather than a file.
async fn answer(sink: &mut Sink, state: &RelayState, answer: Answer) -> Result<(), SendError> {
    match answer {
        Answer::Frames(frames) => {
            for frame in &frames {
                write(sink, frame, state).await?;
            }
        }
        Answer::Blob { blob, total } => {
            for index in 0..total {
                let frame = state.blob_chunk(&blob, index, total);
                let done = !matches!(frame, ServerFrame::BlobChunk { .. });
                write(sink, &frame, state).await?;
                if done {
                    break;
                }
            }
        }
    }
    Ok(())
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
            // Serde's message quotes the input that failed, with the JSON
            // escapes already decoded, so logging it lets anyone who can
            // open a socket write a line of their choosing into the log --
            // a forged line in a text-format log, before authenticating.
            // The kind of error and where it was are what a reader needs.
            debug!(
                "malformed client frame: {:?} at line {} column {}",
                e.classify(),
                e.line(),
                e.column()
            );
            // The client gets the detail: it is their own input.
            format!("malformed frame: {e}")
        }));
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use silver_protocol::Identity;

    fn addr(n: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, n])
    }

    #[test]
    fn lifecycle_statements_are_kept_for_registered_identities_only() {
        let state = RelayState::new();
        let alice = Identity::generate();
        let here = addr(1);
        // Nobody the relay knows: refused, and nothing is stored, so the
        // store cannot be filled with statements about throwaway keys.
        let (code, _) = state
            .apply_revocation(alice.revocation(1), here)
            .unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        assert!(state.lifecycle(&alice.user_id()).0.is_none());
        let successor = Identity::generate();
        let (code, _) = state
            .apply_succession(alice.succeed_to(&successor, 1), here)
            .unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        assert!(state.lifecycle(&alice.user_id()).1.is_none());

        // Once registered, both are taken.
        state.store.put_bundle(&alice.key_bundle()).unwrap();
        state
            .apply_succession(alice.succeed_to(&successor, 2), here)
            .unwrap();
        assert!(state.lifecycle(&alice.user_id()).1.is_some());
        state.apply_revocation(alice.revocation(3), here).unwrap();
        assert!(state.lifecycle(&alice.user_id()).0.is_some());
        // A bad signature is refused whoever the identity is.
        let mut forged = alice.revocation(4);
        forged.identity = Identity::generate().user_id();
        let (code, _) = state.apply_revocation(forged, here).unwrap_err();
        assert!(matches!(code, ErrorCode::BadSignature));
    }

    #[test]
    fn a_revocation_is_final_on_the_relay() {
        let state = RelayState::new();
        let old = Identity::generate();
        let new = Identity::generate();
        let here = addr(2);
        state.store.put_bundle(&old.key_bundle()).unwrap();

        // Succession first, then revocation: the succession is no longer
        // served, whichever came first.
        state
            .apply_succession(old.succeed_to(&new, 1), here)
            .unwrap();
        assert!(state.lifecycle(&old.user_id()).1.is_some());
        state.apply_revocation(old.revocation(2), here).unwrap();
        let (revocation, succession) = state.lifecycle(&old.user_id());
        assert!(revocation.is_some());
        assert!(
            succession.is_none(),
            "a dead key's succession is not served"
        );

        // A dead key cannot hand over, so a compromised key that was
        // revoked cannot name its holder's own successor afterwards.
        let (code, _) = state
            .apply_succession(old.succeed_to(&Identity::generate(), 3), here)
            .unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        // Nor can anyone hand over *to* a revoked key.
        let other = Identity::generate();
        state.store.put_bundle(&other.key_bundle()).unwrap();
        let (code, _) = state
            .apply_succession(other.succeed_to(&old, 4), here)
            .unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        assert!(state.lifecycle(&other.user_id()).1.is_none());
    }

    #[test]
    fn one_client_is_one_address_however_it_arrives() {
        use std::net::Ipv6Addr;
        // A dual-stack listener hands an IPv4 peer over mapped into IPv6.
        // It is the same client: it counts as one address, a ban on either
        // form matches it, and a loopback front is recognised as trusted.
        let mapped: IpAddr = IpAddr::V6("::ffff:1.2.3.4".parse::<Ipv6Addr>().unwrap());
        let plain: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(canonical_address(mapped), plain);
        assert_eq!(canonical_address(plain), plain);
        let six: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical_address(six), six, "a real IPv6 address is left");

        let state = RelayState::new();
        state.ban(&BanTarget::Address(plain), "test").expect("ban");
        assert!(state.address_banned(plain));
        assert!(
            state.address_banned(mapped),
            "the mapped form is the same client"
        );

        // And the mapped loopback is loopback, so a front on it is trusted.
        let loopback: IpAddr = IpAddr::V6("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap());
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        assert_eq!(
            state.client_address(Some(loopback), &headers),
            "9.9.9.9".parse::<IpAddr>().unwrap(),
        );
    }

    /// A rate of zero turns the thing off, for hourly limits as well as
    /// per-minute ones.
    ///
    /// `per_hour` clamped its rate up to one, so zero became one an hour.
    /// An operator closing registration with `--registrations-per-hour 0`
    /// got a relay that still let each address register an identity every
    /// hour: the limit read as closed and was not, which is the direction
    /// a limit must never be wrong in. The per-minute constructor already
    /// did this correctly, and its comment says why.
    #[test]
    fn a_rate_of_zero_turns_the_limit_off_by_the_hour_too() {
        let mut hourly = Bucket::per_hour(0.0);
        assert!(!hourly.try_take(), "zero an hour let one through");
        // And it does not refill into one, however long is waited: the
        // rate is zero, so the bucket never fills.
        hourly.last = Instant::now() - std::time::Duration::from_secs(4 * 3600);
        assert!(!hourly.try_take(), "zero an hour refilled to one an hour");

        // The per-minute side has always been this, and stays it.
        let mut minutely = Bucket::per_minute(0);
        assert!(!minutely.try_take(), "zero a minute let one through");

        // A real hourly limit still works, and still refills.
        let mut two = Bucket::per_hour(2.0);
        assert!(two.try_take());
        assert!(two.try_take());
        assert!(!two.try_take(), "a limit of two an hour is two");
        two.last = Instant::now() - std::time::Duration::from_secs(3600);
        assert!(two.try_take(), "and an hour later there are more");
    }

    #[test]
    fn an_envelope_id_is_one_a_message_id_may_be() {
        let state = RelayState::new();
        let alice = Identity::generate();
        let bob = Identity::generate();
        state.store.put_bundle(&bob.key_bundle()).unwrap();
        let mut bucket = Bucket::per_minute(60);
        let good = silver_protocol::seal(
            &alice,
            &bob.key_bundle(),
            silver_protocol::Content::text("hi"),
            0,
        )
        .unwrap();
        assert!(matches!(
            state.submit(good.clone(), &mut bucket, None),
            ServerFrame::Sent { .. }
        ));
        // The id becomes a key in the store and reaches the recipient's
        // client and log, so it is not whatever the sender put there.
        for bad in ["", "with space", "line\nbreak", &"x".repeat(65)] {
            let mut envelope = good.clone();
            envelope.id = bad.to_owned();
            assert!(
                matches!(
                    state.submit(envelope, &mut bucket, None),
                    ServerFrame::Rejected {
                        code: ErrorCode::Malformed,
                        ..
                    }
                ),
                "{bad:?} is not an envelope id"
            );
        }
    }

    #[test]
    fn the_sequencer_stops_at_the_last_epoch_rather_than_panicking() {
        let state = RelayState::new();
        let group = silver_protocol::GroupId::generate();
        let token = [7u8; 32];
        let next = silver_protocol::group::token_hash(&token);
        // An anonymous connection may create an entry at any epoch. The
        // last one has no successor: the commit is refused, and the
        // increment that would panic under overflow checks never runs.
        assert!(matches!(
            state.store.group_create(&group, u64::MAX, next, 1).unwrap(),
            Sequenced::Stands(_)
        ));
        assert!(matches!(
            state
                .store
                .group_commit(&group, u64::MAX, &token, [9; 32], 2)
                .unwrap(),
            Sequenced::Stale(e) if e == u64::MAX
        ));
    }

    #[test]
    fn a_revoked_identity_does_not_log_in() {
        let state = RelayState::new();
        let here = addr(9);
        let alice = Identity::generate();
        let me = alice.user_id();
        assert!(state.publish(&me, alice.key_bundle(), None, here).is_ok());
        assert_eq!(state.login_refusal(&me), None);
        state.apply_revocation(alice.revocation(1), here).unwrap();
        // The key is dead: it does not publish, and it does not read the
        // mailbox it used to own either.
        assert!(state.publish(&me, alice.key_bundle(), None, here).is_err());
        assert_eq!(
            state.login_refusal(&me),
            Some("this identity has been revoked")
        );
    }

    /// A mailbox reaches a connection a page at a time, and the page moves
    /// as the client acknowledges: the relay never holds more of it than
    /// the delivery window, whatever is waiting, and nothing is skipped or
    /// repeated on the way.
    #[test]
    fn a_mailbox_is_delivered_a_page_at_a_time() {
        use silver_protocol::{Content, seal};
        let state = RelayState::new();
        let here = addr(10);
        let alice = Identity::generate();
        let bob = Identity::generate();
        state
            .publish(&alice.user_id(), alice.key_bundle(), None, here)
            .unwrap();
        state
            .publish(&bob.user_id(), bob.key_bundle(), None, here)
            .unwrap();
        // More waiting than a window holds, queued before bob connects.
        let waiting = DELIVERY_WINDOW * 2 + 3;
        let mut ids = Vec::new();
        for n in 0..waiting {
            let envelope = seal(
                &alice,
                &bob.key_bundle(),
                Content::text(format!("message {n}")),
                n as u64,
            )
            .unwrap();
            ids.push(envelope.id.clone());
            state.route(envelope).unwrap();
        }
        let (tx, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        state.register(bob.user_id(), tx);
        let delivered = |rx: &mut mpsc::Receiver<Outbound>| match rx.try_recv() {
            Ok(Outbound::Frame(frame)) => match *frame {
                ServerFrame::Deliver { envelope } => Some(envelope.id),
                other => panic!("expected a delivery, got {other:?}"),
            },
            _ => None,
        };
        // One window's worth on logging in, in mailbox order, and no more.
        for id in ids.iter().take(DELIVERY_WINDOW) {
            assert_eq!(delivered(&mut rx).as_ref(), Some(id));
        }
        assert_eq!(delivered(&mut rx), None);
        // Each acknowledgement lets exactly one more through, in order,
        // until the mailbox is empty.
        for (n, id) in ids.iter().enumerate() {
            state.ack(&bob.user_id(), id);
            assert_eq!(delivered(&mut rx).as_ref(), ids.get(n + DELIVERY_WINDOW));
        }
        assert_eq!(state.queued_for(&bob.user_id()), 0);
        // And mail that arrives while the client is caught up goes out at
        // once, still from the mailbox and still in order.
        let last = seal(&alice, &bob.key_bundle(), Content::text("after"), 99).unwrap();
        let id = last.id.clone();
        state.route(last).unwrap();
        assert_eq!(delivered(&mut rx), Some(id));
    }

    /// A stored file is answered as chunks left in the store, read one at
    /// a time, and the whole download is charged before the first is read.
    #[test]
    fn a_file_is_answered_a_chunk_at_a_time() {
        let state = RelayState::new();
        let here = addr(12);
        let id = "a".repeat(32);
        let mut puts = Bucket::per_minute(60);
        for index in 0..3u32 {
            let reply = state.put_blob(id.clone(), index, 3, &[index as u8; 8], &mut puts, here);
            assert!(matches!(reply, ServerFrame::BlobAck { .. }));
        }
        // Nothing of the file is in the answer: only what to read next.
        let mut gets = Bucket::per_minute(60);
        let Answer::Blob { blob, total } = state.open_blob(&id, &mut gets) else {
            panic!("expected a file to stream");
        };
        assert_eq!((blob.as_str(), total), (id.as_str(), 3));
        for index in 0..3u32 {
            match state.blob_chunk(&id, index, 3) {
                ServerFrame::BlobChunk { data, .. } => assert_eq!(data, vec![index as u8; 8]),
                other => panic!("expected chunk {index}, got {other:?}"),
            }
        }
        // A file that went while it was being read stops the reader.
        assert!(matches!(
            state.blob_chunk(&id, 3, 3),
            ServerFrame::BlobRejected {
                code: ErrorCode::NotFound,
                ..
            }
        ));
        // The budget is for the whole file, taken before anything is read.
        let mut small = Bucket::per_minute(2);
        assert!(matches!(
            state.open_blob(&id, &mut small),
            Answer::Frames(frames) if matches!(
                frames.as_slice(),
                [ServerFrame::BlobRejected { code: ErrorCode::RateLimited, .. }]
            )
        ));
    }

    /// A client that stops reading cannot keep its session: the relay holds
    /// the only sender, so taking the session out of the registry ends the
    /// connection whether or not the notice fits in the queue.
    #[tokio::test]
    async fn a_session_ends_even_when_the_client_has_stopped_reading() {
        use silver_protocol::{Content, seal};
        let state = RelayState::new();
        let here = addr(11);
        let alice = Identity::generate();
        let bob = Identity::generate();
        state
            .publish(&alice.user_id(), alice.key_bundle(), None, here)
            .unwrap();
        state
            .publish(&bob.user_id(), bob.key_bundle(), None, here)
            .unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        state.register(bob.user_id(), tx);
        // Bob reads nothing, so his queue fills at the first envelope and
        // the window stops the rest reaching it.
        for n in 0..DELIVERY_WINDOW * 4 {
            let envelope = seal(
                &alice,
                &bob.key_bundle(),
                Content::text(format!("message {n}")),
                n as u64,
            )
            .unwrap();
            state.route(envelope).unwrap();
        }
        state.evict(&bob.user_id()).unwrap();
        // The queue ends after what was already in it: no notice fitted,
        // and the connection winds up all the same.
        let mut frames = 0;
        while let Some(outbound) = rx.recv().await {
            assert!(matches!(outbound, Outbound::Frame(_)));
            frames += 1;
        }
        assert_eq!(frames, 1);
    }

    #[test]
    fn a_device_revocation_takes_only_a_device_of_the_account() {
        let state = RelayState::new();
        let here = addr(5);
        let alice = Identity::generate();
        let laptop = Identity::generate();
        let stranger = Identity::generate();
        let revoke = |by: &Identity, device: &Identity, at| {
            state.apply_device_revocation(
                &by.user_id(),
                by.revoke_device(&device.user_id(), at),
                here,
            )
        };
        // An account with no bundle here has no devices here.
        let (code, _) = revoke(&alice, &laptop, 1).unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        state.store.put_bundle(&alice.key_bundle()).unwrap();
        state.store.put_bundle(&stranger.key_bundle()).unwrap();
        // A device the relay does not know as alice's: refused, so that no
        // account can cut an identity off by calling it a device of its own.
        let (code, _) = revoke(&alice, &laptop, 1).unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        assert!(!state.store.is_device_revoked(&laptop.user_id()).unwrap());
        // Nor by listing a registered identity as one of its devices. The
        // list is taken: a device is listed while it still has a bundle of
        // its own, between registering and claiming the account (section
        // 14.6), and the relay cannot tell that apart from this. The
        // statement is what is refused, so the stranger keeps its account:
        // nothing is refused it on the strength of somebody else's list.
        let listing = alice
            .key_bundle()
            .with_devices(
                &alice,
                vec![
                    alice
                        .certify_device(&stranger.user_id(), "not mine", 1)
                        .unwrap(),
                ],
            )
            .unwrap();
        state
            .publish(&alice.user_id(), listing, None, here)
            .unwrap();
        let (code, _) = revoke(&alice, &stranger, 1).unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        assert!(!state.store.is_device_revoked(&stranger.user_id()).unwrap());
        assert_eq!(state.login_refusal(&stranger.user_id()), None);
        assert!(
            state
                .route(
                    silver_protocol::seal(
                        &alice,
                        &stranger.key_bundle(),
                        silver_protocol::Content::text("still here"),
                        0,
                    )
                    .unwrap()
                )
                .is_ok()
        );
        state.store.put_bundle(&alice.key_bundle()).unwrap();
        // The laptop claims alice. Alice's statement on someone else's
        // connection, someone else's statement, and a forged one are all
        // refused.
        let certificate = alice
            .certify_device(&laptop.user_id(), "laptop", 1)
            .unwrap();
        state
            .store
            .put_bundle(&laptop.key_bundle().as_device_of(certificate))
            .unwrap();
        let (code, _) = state
            .apply_device_revocation(
                &stranger.user_id(),
                alice.revoke_device(&laptop.user_id(), 2),
                here,
            )
            .unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        let (code, _) = revoke(&stranger, &laptop, 2).unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        let mut forged = alice.revoke_device(&laptop.user_id(), 2);
        forged.created_at_ms += 1;
        let (code, _) = state
            .apply_device_revocation(&alice.user_id(), forged, here)
            .unwrap_err();
        assert!(matches!(code, ErrorCode::BadSignature));
        assert!(!state.store.is_device_revoked(&laptop.user_id()).unwrap());
        // Alice's own is taken, and served for the account and the device.
        revoke(&alice, &laptop, 2).unwrap();
        assert!(state.is_revoked_device(&laptop.user_id()));
        assert_eq!(state.device_revocations(&alice.user_id()).len(), 1);
        assert_eq!(state.device_revocations(&laptop.user_id()).len(), 1);
        assert_eq!(state.device_revocations(&stranger.user_id()).len(), 0);
        // Said again: answered, and nothing doubled.
        let logged = state.store.log_len().unwrap();
        revoke(&alice, &laptop, 3).unwrap();
        assert_eq!(state.device_revocations(&alice.user_id()).len(), 1);
        assert_eq!(state.store.log_len().unwrap(), logged);
        // A device on the published list that never published a bundle of
        // its own (a link that did not finish) is alice's to revoke too.
        let phone = Identity::generate();
        let certificate = alice.certify_device(&phone.user_id(), "phone", 4).unwrap();
        state
            .store
            .put_bundle(
                &alice
                    .key_bundle()
                    .with_devices(&alice, vec![certificate])
                    .unwrap(),
            )
            .unwrap();
        revoke(&alice, &phone, 5).unwrap();
        assert!(state.store.is_device_revoked(&phone.user_id()).unwrap());
        assert_eq!(state.device_revocations(&alice.user_id()).len(), 2);
        // It binds nothing while the key claims nobody: whoever holds it
        // is refused neither a login nor a bundle of its own. It bites the
        // moment that bundle claims alice.
        assert!(!state.is_revoked_device(&phone.user_id()));
        assert_eq!(state.login_refusal(&phone.user_id()), None);
        let (code, _) = state
            .publish(
                &phone.user_id(),
                phone
                    .key_bundle()
                    .as_device_of(alice.certify_device(&phone.user_id(), "phone", 4).unwrap()),
                None,
                here,
            )
            .unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        state
            .publish(&phone.user_id(), phone.key_bundle(), None, here)
            .unwrap();
        // The operator can put a revocation right; the id is then refused
        // nothing, and can claim the account again.
        assert!(state.unrevoke_device(&laptop.user_id()).unwrap());
        assert!(!state.unrevoke_device(&laptop.user_id()).unwrap());
        assert_eq!(state.login_refusal(&laptop.user_id()), None);
        assert_eq!(state.device_revocations(&laptop.user_id()).len(), 0);
        assert_eq!(state.device_revocations(&alice.user_id()).len(), 1);
    }

    #[test]
    fn a_revoked_device_is_cut_off_for_good() {
        use silver_protocol::{Content, seal};
        let state = RelayState::new();
        let here = addr(6);
        let alice = Identity::generate();
        let laptop = Identity::generate();
        let certificate = alice
            .certify_device(&laptop.user_id(), "laptop", 1)
            .unwrap();
        state.store.put_bundle(&alice.key_bundle()).unwrap();
        state
            .publish(
                &laptop.user_id(),
                laptop.key_bundle().as_device_of(certificate.clone()),
                None,
                here,
            )
            .unwrap();
        assert_eq!(state.stats().devices, 1);
        let to_laptop =
            |text: &str| seal(&alice, &laptop.key_bundle(), Content::text(text), 0).unwrap();
        // Online, with mail waiting.
        let (tx, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        state.register(laptop.user_id(), tx);
        state.route(to_laptop("one")).unwrap();
        assert_eq!(state.queued_for(&laptop.user_id()), 1);
        assert!(matches!(
            rx.try_recv(),
            Ok(Outbound::Frame(frame)) if matches!(*frame, ServerFrame::Deliver { .. })
        ));

        state
            .apply_device_revocation(
                &alice.user_id(),
                alice.revoke_device(&laptop.user_id(), 2),
                here,
            )
            .unwrap();
        // Told why, then closed; the mailbox is gone.
        assert!(matches!(
            rx.try_recv(),
            Ok(Outbound::Frame(frame)) if matches!(*frame, ServerFrame::Error { code: ErrorCode::Forbidden, .. })
        ));
        assert!(matches!(rx.try_recv(), Ok(Outbound::Close(_))));
        assert!(state.online().get(&laptop.user_id()).is_none());
        assert_eq!(state.queued_for(&laptop.user_id()), 0);
        // No login, no publish, no mail, and not back on the list.
        assert_eq!(
            state.login_refusal(&laptop.user_id()),
            Some("this device has been revoked by its account")
        );
        let (code, _) = state
            .publish(&laptop.user_id(), laptop.key_bundle(), None, here)
            .unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        let (code, _) = state.route(to_laptop("two")).unwrap_err();
        assert!(matches!(code, ErrorCode::NotFound));
        let (code, _) = state
            .publish(
                &alice.user_id(),
                alice
                    .key_bundle()
                    .with_devices(&alice, vec![certificate])
                    .unwrap(),
                None,
                here,
            )
            .unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        // The bundle the log covers is still served, with the statement.
        assert!(state.bundle(&laptop.user_id()).is_some());
        assert_eq!(state.device_revocations(&laptop.user_id()).len(), 1);
        assert_eq!(state.stats().devices, 1);
        assert_eq!(state.stats().device_revocations, 1);
    }

    #[test]
    fn a_device_claim_needs_a_live_account_here() {
        let state = RelayState::new();
        let here = addr(7);
        let alice = Identity::generate();
        let laptop = Identity::generate();
        let certificate = alice
            .certify_device(&laptop.user_id(), "laptop", 1)
            .unwrap();
        let claim = || laptop.key_bundle().as_device_of(certificate.clone());
        // An account the relay does not know.
        let (code, _) = state
            .publish(&laptop.user_id(), claim(), None, here)
            .unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        state.store.put_bundle(&alice.key_bundle()).unwrap();
        state
            .publish(&laptop.user_id(), claim(), None, here)
            .unwrap();
        assert_eq!(state.login_refusal(&laptop.user_id()), None);
        // The account dies: the device is told, and refused from then on.
        let (tx, mut rx) = mpsc::channel(OUTBOUND_QUEUE);
        state.register(laptop.user_id(), tx);
        state
            .store
            .put_bundle(
                &alice
                    .key_bundle()
                    .with_devices(&alice, vec![certificate.clone()])
                    .unwrap(),
            )
            .unwrap();
        state.apply_revocation(alice.revocation(2), here).unwrap();
        assert!(matches!(rx.try_recv(), Ok(Outbound::Frame(_))));
        assert!(matches!(rx.try_recv(), Ok(Outbound::Close(_))));
        assert_eq!(
            state.login_refusal(&laptop.user_id()),
            Some("this device's account has been revoked")
        );
        let (code, _) = state
            .publish(&laptop.user_id(), claim(), None, here)
            .unwrap_err();
        assert!(matches!(code, ErrorCode::Forbidden));
        // An identity that is no device is refused nothing.
        assert_eq!(state.login_refusal(&Identity::generate().user_id()), None);
    }

    #[test]
    fn device_bundles_ride_along_with_the_account() {
        use silver_protocol::{PrekeySecret, Prekeys};
        let state = RelayState::new();
        let alice = Identity::generate();
        let laptop = Identity::generate();
        let phone = Identity::generate();
        let ghost = Identity::generate();
        let certificates: Vec<_> = [&laptop, &phone, &ghost]
            .iter()
            .map(|d| alice.certify_device(&d.user_id(), "", 1).unwrap())
            .collect();
        // The laptop is linked and has a prekey on deposit; the phone
        // registered but never claimed the account; the ghost never came.
        let signed = PrekeySecret::generate(1, 0).signed_by(&laptop);
        let one_time = PrekeySecret::generate(2, 0).one_time();
        state
            .store
            .put_bundle(
                &laptop
                    .key_bundle_with(Prekeys::classical(signed, Vec::new()))
                    .as_device_of(certificates[0].clone()),
            )
            .unwrap();
        state
            .store
            .set_one_time_prekeys(&laptop.user_id(), &[one_time])
            .unwrap();
        state.store.put_bundle(&phone.key_bundle()).unwrap();
        let account = alice
            .key_bundle()
            .with_devices(&alice, certificates)
            .unwrap();
        state.store.put_bundle(&account).unwrap();

        let served = state.device_bundles(&alice.user_id(), Some(&account));
        assert_eq!(served.len(), 1, "the laptop alone");
        assert_eq!(served[0].user_id, laptop.user_id());
        assert_eq!(
            served[0].prekeys.as_ref().unwrap().one_time.len(),
            1,
            "a prekey popped as on its own lookup"
        );
        assert_eq!(state.one_time_prekeys_left(&laptop.user_id()), 0);
        assert!(state.device_bundles(&alice.user_id(), None).is_empty());
        // Revoked: no longer along.
        state
            .apply_device_revocation(
                &alice.user_id(),
                alice.revoke_device(&laptop.user_id(), 3),
                addr(8),
            )
            .unwrap();
        assert!(
            state
                .device_bundles(&alice.user_id(), Some(&account))
                .is_empty()
        );
    }

    #[test]
    fn lifecycle_statements_draw_on_the_address_registration_budget() {
        let state = RelayState::new();
        let here = addr(3);
        let alice = Identity::generate();
        state.store.put_bundle(&alice.key_bundle()).unwrap();
        for _ in 0..state.policy.registrations_per_hour {
            state.apply_revocation(alice.revocation(1), here).unwrap();
        }
        let (code, _) = state
            .apply_revocation(alice.revocation(1), here)
            .unwrap_err();
        assert!(matches!(code, ErrorCode::RateLimited));
        // Another address has its own budget.
        state
            .apply_revocation(alice.revocation(1), addr(4))
            .unwrap();
    }
}
