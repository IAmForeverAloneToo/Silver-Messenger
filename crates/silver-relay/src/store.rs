//! Durable relay state: published key bundles, one-time prekeys and
//! per-recipient mailboxes.
//!
//! Backed by an embedded [`redb`] database so an update or reboot loses
//! nothing. Every mailbox entry is `received_at_ms (8 bytes BE) || envelope
//! JSON`, kept until the recipient acknowledges it or it expires.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Context;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use silver_protocol::encoding::b64_array;
use silver_protocol::group::{GroupId, token_hash};
use silver_protocol::prekey::OneTimePrekey;
use silver_protocol::transparency::{EntryKind, Hash, LogEntry, LogHead, LogPosition, subject};
use silver_protocol::wire::KeyPackageDeposit;
use silver_protocol::{
    DeviceRevocation, DhPublic, Envelope, KeyBundle, Revocation, SignedPqPrekey, Succession,
    UserId, now_ms,
};
use subtle::ConstantTimeEq;

/// A deposit of one-time keys: `(owner, key id) -> encoded public key` for
/// keys not yet handed out.
type DepositTable = TableDefinition<'static, (&'static [u8], u32), &'static [u8]>;
/// `(owner, key id)` for keys handed out that the owner may still list on
/// its next publish; forgotten once the owner stops listing them.
type UsedTable = TableDefinition<'static, (&'static [u8], u32), ()>;

// The tables. A backup ([`crate::backup`]) walks every one of them, so a
// table added here is added there too.

/// `owner -> bundle JSON` (the signed prekeys included, one-time keys not).
pub(crate) const BUNDLES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bundles");
/// One-time X25519 prekeys, the raw 32-byte public key each.
pub(crate) const ONE_TIME: DepositTable = TableDefinition::new("one_time_prekeys");
pub(crate) const ONE_TIME_USED: UsedTable = TableDefinition::new("one_time_used");
/// One-time ML-KEM keys (protocol v3), each stored as the JSON of its
/// signed form so it is handed out signature and all.
pub(crate) const PQ_ONE_TIME: DepositTable = TableDefinition::new("pq_one_time_prekeys");
pub(crate) const PQ_ONE_TIME_USED: UsedTable = TableDefinition::new("pq_one_time_used");
/// `(recipient, sequence) -> stored entry`; the sequence gives delivery order.
pub(crate) const MAILBOX: TableDefinition<(&[u8], u64), &[u8]> = TableDefinition::new("mailbox");
/// `envelope id -> (recipient, sequence)` so acknowledgements are O(log n).
pub(crate) const BY_ID: TableDefinition<&str, (&[u8], u64)> = TableDefinition::new("by_id");
/// `recipient -> (message count, total bytes)` for quota checks.
pub(crate) const USAGE: TableDefinition<&[u8], (u64, u64)> = TableDefinition::new("usage");
/// Counters and the schema version.
pub(crate) const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const NEXT_SEQ: &str = "next_seq";
/// `"address:<ip>"` or `"identity:<id>"` -> [`Ban`] JSON, set by the
/// administrator and enforced until removed.
pub(crate) const BANS: TableDefinition<&str, &[u8]> = TableDefinition::new("bans");
/// Settings the administrator changed while the relay ran, which win over
/// the command line at the next start: the invite token, for one.
pub(crate) const ADMIN: TableDefinition<&str, &str> = TableDefinition::new("admin");
/// `identity -> Revocation JSON`: a self-signed statement that the identity
/// is dead, served on lookups so contacts learn of it.
pub(crate) const REVOCATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("revocations");
/// `old identity -> Succession JSON`: a cross-signed statement that the
/// identity moved to a new one, served on lookups of the old identity.
pub(crate) const SUCCESSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("successions");
/// `index -> LogEntry JSON`: the transparency log, one entry per bundle
/// change or lifecycle statement, each hashing the one before
/// (`docs/PROTOCOL.md` section 11). Append-only; nothing removes from it.
pub(crate) const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("transparency_log");
/// `subject -> Latest JSON`: where each identity last appears in the log
/// and the leaf of its last logged bundle, so a republished, unchanged
/// bundle adds no entry.
pub(crate) const LOG_LATEST: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("transparency_latest");
/// `blob id -> BlobMeta JSON` for encrypted file chunks on deposit.
pub(crate) const BLOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");
/// `(blob id, chunk index) -> ciphertext`.
pub(crate) const BLOB_CHUNKS: TableDefinition<(&str, u32), &[u8]> =
    TableDefinition::new("blob_chunks");
/// Bytes of chunks stored in total, for the storage cap.
const BLOB_BYTES: &str = "blob_bytes";
/// `(owner, deposit sequence) -> KeyPackageDeposit JSON`: key packages not
/// yet handed out, in the order they were deposited (`docs/PROTOCOL.md`
/// section 13). The relay never parses them.
pub(crate) const KEY_PACKAGES: TableDefinition<(&[u8], u64), &[u8]> =
    TableDefinition::new("key_packages");
/// `(owner, key package ref)` for packages handed out that the owner may
/// still list on its next deposit; forgotten once it stops listing them.
pub(crate) const KEY_PACKAGES_USED: TableDefinition<(&[u8], &[u8]), ()> =
    TableDefinition::new("key_packages_used");
/// `owner -> KeyPackageDeposit JSON`: the last-resort package, handed out
/// again and again once the deposit is empty.
pub(crate) const KEY_PACKAGE_LAST_RESORT: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("key_package_last_resort");
/// `group id -> GroupEntry JSON`: the epoch sequencer, one counter and one
/// token hash per group the relay knows nothing else about.
pub(crate) const GROUPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("groups");
/// `device id -> DeviceRevocation JSON`: an account's signed statement
/// that the device is no longer its own (`docs/PROTOCOL.md` section 14),
/// served on lookups of the device and of the account, and kept for good
/// like an identity's revocation.
pub(crate) const DEVICE_REVOCATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("device_revocations");
/// `(account, device)` for every device revocation, so an account's lookup
/// finds the ones it issued without a walk of the table.
pub(crate) const DEVICE_REVOCATIONS_BY_ACCOUNT: TableDefinition<(&[u8], &[u8]), ()> =
    TableDefinition::new("device_revocations_by_account");
/// The next deposit sequence number for key packages.
const NEXT_KEY_PACKAGE: &str = "next_key_package";
/// Bundles that carry `device_of`: linked devices, counted for the
/// metrics as bundles come and go rather than by a walk at every scrape.
const DEVICES: &str = "devices";

/// The layout of the tables, stamped into the database. It moves when a
/// change needs more than opening a table that was not there before, with
/// a step in [`migrate`] to bring older databases along; a database
/// stamped with a higher version was written by a newer relay and is
/// refused rather than misread.
pub const SCHEMA_VERSION: u64 = 3;
pub(crate) const SCHEMA: &str = "schema";

/// The database was written by a newer relay than this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaTooNew {
    pub found: u64,
    pub supported: u64,
}

impl std::fmt::Display for SchemaTooNew {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the database has schema version {}, newer than the {} this silver-relay {} knows; run the relay that wrote it, or restore a backup taken by this version",
            self.found,
            self.supported,
            env!("CARGO_PKG_VERSION")
        )
    }
}

impl std::error::Error for SchemaTooNew {}

/// One step of the schema, from `from` to `from + 1`. The caller has
/// opened, and so created, every table already; a version whose only
/// change is a new table has nothing left to do here.
pub(crate) fn migrate(txn: &redb::WriteTransaction, from: u64) -> anyhow::Result<()> {
    match from {
        // 0 is the unstamped layout of 0.6.0 and before; 1 added the bans
        // and admin tables.
        0 => Ok(()),
        // 2 added the transparency log. Every bundle and lifecycle statement
        // the relay already holds is logged now, in one entry each, so that
        // from here on nothing it serves is missing from the log. The
        // version moves so that an older relay, which would serve changes
        // without logging them, refuses this database instead.
        1 => seed_log(txn),
        // 3 added the key package deposit, the group sequencer and the
        // device revocation tables, which opening creates. The version
        // moves so that an older relay, which would leave deposits to go
        // stale, every group without a sequencer and every revoked device
        // alive, refuses this database instead of half-serving it.
        2 => Ok(()),
        other => anyhow::bail!("no migration from schema version {other}"),
    }
}

/// Log everything already stored: bundles first, in key order, then
/// revocations and successions. A database that already has a log (a
/// backup taken with one but stamped older, say) is left alone: seeding
/// it again would enter every statement twice.
fn seed_log(txn: &redb::WriteTransaction) -> anyhow::Result<()> {
    if head_in(&txn.open_table(LOG)?)?.index > 0 {
        return Ok(());
    }
    let at_ms = now_ms();
    let bundles: Vec<KeyBundle> = txn
        .open_table(BUNDLES)?
        .iter()?
        .map(|item| Ok(serde_json::from_slice(item?.1.value())?))
        .collect::<anyhow::Result<_>>()?;
    for bundle in &bundles {
        log_bundle_in(txn, bundle, at_ms)?;
    }
    let revocations: Vec<Revocation> = txn
        .open_table(REVOCATIONS)?
        .iter()?
        .map(|item| Ok(serde_json::from_slice(item?.1.value())?))
        .collect::<anyhow::Result<_>>()?;
    for revocation in &revocations {
        append_log(
            txn,
            subject(&revocation.identity),
            EntryKind::Revocation,
            revocation.transparency_leaf(),
            at_ms,
        )?;
    }
    let successions: Vec<Succession> = txn
        .open_table(SUCCESSIONS)?
        .iter()?
        .map(|item| Ok(serde_json::from_slice(item?.1.value())?))
        .collect::<anyhow::Result<_>>()?;
    for succession in &successions {
        append_log(
            txn,
            subject(&succession.old),
            EntryKind::Succession,
            succession.transparency_leaf(),
            at_ms,
        )?;
    }
    Ok(())
}

/// Where an identity last appears in the log, and the leaf of its last
/// logged bundle (which a later statement entry does not replace).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Latest {
    position: LogPosition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle_leaf: Option<Hash>,
}

fn read_latest(txn: &redb::WriteTransaction, subject: &Hash) -> anyhow::Result<Option<Latest>> {
    Ok(match txn.open_table(LOG_LATEST)?.get(subject.as_slice())? {
        Some(guard) => Some(serde_json::from_slice(guard.value())?),
        None => None,
    })
}

fn head_in<T: ReadableTable<u64, &'static [u8]>>(log: &T) -> anyhow::Result<LogHead> {
    Ok(match log.last()? {
        Some((_, guard)) => serde_json::from_slice::<LogEntry>(guard.value())?.head(),
        None => LogHead::EMPTY,
    })
}

/// Append one entry after the current head and note it as the subject's
/// latest. For a bundle the leaf is also kept as the subject's last
/// bundle leaf.
fn append_log(
    txn: &redb::WriteTransaction,
    subject: Hash,
    kind: EntryKind,
    leaf: Hash,
    at_ms: u64,
) -> anyhow::Result<LogEntry> {
    let mut log = txn.open_table(LOG)?;
    let head = head_in(&log)?;
    let entry = LogEntry::after(&head, subject, kind, leaf, at_ms);
    log.insert(entry.index, serde_json::to_vec(&entry)?.as_slice())?;
    let previous = read_latest(txn, &subject)?.unwrap_or_default();
    let latest = Latest {
        position: LogPosition {
            index: entry.index,
            leaf,
        },
        bundle_leaf: match kind {
            EntryKind::Bundle => Some(leaf),
            _ => previous.bundle_leaf,
        },
    };
    txn.open_table(LOG_LATEST)?
        .insert(subject.as_slice(), serde_json::to_vec(&latest)?.as_slice())?;
    Ok(entry)
}

/// Log `bundle` unless its leaf is the one already logged for its owner.
fn log_bundle_in(
    txn: &redb::WriteTransaction,
    bundle: &KeyBundle,
    at_ms: u64,
) -> anyhow::Result<Option<LogEntry>> {
    let subject = subject(&bundle.user_id);
    let leaf = bundle.transparency_leaf();
    if read_latest(txn, &subject)?.and_then(|l| l.bundle_leaf) == Some(leaf) {
        return Ok(None);
    }
    append_log(txn, subject, EntryKind::Bundle, leaf, at_ms).map(Some)
}

/// Limits applied to each recipient's mailbox.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_messages: u64,
    pub max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_messages: 1000,
            max_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Outcome of storing an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueue {
    Stored,
    /// An envelope with this id is already queued; nothing changed.
    Duplicate,
    MailboxFull,
}

/// A ban on an address or an identity, as the administrator set it.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ban {
    pub since_ms: u64,
    #[serde(default)]
    pub note: String,
}

/// What [`Store::remove_user`] deleted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Removed {
    pub had_bundle: bool,
    pub messages: u64,
    pub bytes: u64,
    pub prekeys: u64,
    /// Key packages on deposit, the last-resort one included.
    #[serde(default)]
    pub key_packages: u64,
}

/// Aggregate numbers for logs and health output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Stats {
    pub bundles: u64,
    pub mailboxes: u64,
    pub messages: u64,
    pub bytes: u64,
    pub blobs: u64,
    pub blob_bytes: u64,
    /// Key packages on deposit, last-resort ones not counted.
    #[serde(default)]
    pub key_packages: u64,
    /// Groups with a sequencer entry.
    #[serde(default)]
    pub groups: u64,
    /// Linked devices: bundles that carry a device certificate.
    #[serde(default)]
    pub devices: u64,
    /// Device revocations held, which nothing removes.
    #[serde(default)]
    pub device_revocations: u64,
}

/// What the epoch sequencer says to a create or a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sequenced {
    /// Accepted; the entry now stands at this epoch.
    Stands(u64),
    /// A commit named an epoch the entry is not at; it stands here.
    Stale(u64),
    /// A create for an entry that exists with other values; it stands here.
    Exists(u64),
    /// A commit for a group with no entry.
    NotFound,
    /// The token does not hash to what the entry holds.
    Forbidden,
}

/// One group's sequencer entry.
#[derive(serde::Serialize, serde::Deserialize)]
struct GroupEntry {
    epoch: u64,
    /// The hash of the token that moves the group on.
    #[serde(with = "b64_array")]
    next: [u8; 32],
    created_at_ms: u64,
    updated_at_ms: u64,
}

/// Caps on encrypted file storage.
#[derive(Clone, Copy, Debug)]
pub struct BlobLimits {
    /// Largest blob, in bytes of ciphertext.
    pub max_blob_bytes: u64,
    /// Ciphertext bytes the relay keeps in total.
    pub max_total_bytes: u64,
}

impl Default for BlobLimits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 16 * 1024 * 1024 + 256 * 16,
            max_total_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// What the relay knows about a blob.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlobMeta {
    pub total: u32,
    pub received: u32,
    pub bytes: u64,
    pub created_at_ms: u64,
}

impl BlobMeta {
    pub fn is_complete(&self) -> bool {
        self.received == self.total
    }
}

/// Outcome of storing a chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobPut {
    Stored {
        complete: bool,
    },
    /// This chunk is already there; nothing changed.
    Duplicate,
    /// `total` or `index` do not fit the blob as first announced.
    Mismatch,
    /// The blob would exceed the per-blob cap.
    TooLarge,
    /// The relay's blob storage is full.
    StorageFull,
}

pub struct Store {
    pub(crate) db: Database,
}

impl Store {
    /// Open (or create) the database file at `path`. The directory and the
    /// file are readable by the relay's user only: the database holds every
    /// mailbox and every key bundle.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
            Self::private(parent, 0o700);
        }
        let db = Database::create(path).with_context(|| format!("opening {}", path.display()))?;
        Self::private(path, 0o600);
        Self::init(db)
    }

    /// A database that lives only in memory, for tests and `--ephemeral`.
    pub fn in_memory() -> anyhow::Result<Self> {
        let db = Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::init(db)
    }

    /// Keep `path` to its owner on Unix; other systems keep their defaults.
    fn private(path: &Path, mode: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        }
        #[cfg(not(unix))]
        {
            let _ = (path, mode);
        }
    }

    /// Create the tables that are missing, bring an older layout up to
    /// [`SCHEMA_VERSION`] and stamp it, or refuse a newer one. All in one
    /// transaction: a refused database is left exactly as it was.
    fn init(db: Database) -> anyhow::Result<Self> {
        let txn = db.begin_write()?;
        // A database with no tables at all is new. One with tables but no
        // version was written before 0.7.0, when the layout was not
        // stamped: that is version 0.
        let fresh = txn.list_tables()?.next().is_none();
        Self::open_tables(&txn)?;
        let stamped = txn.open_table(META)?.get(SCHEMA)?.map(|g| g.value());
        let from = match stamped {
            Some(found) if found > SCHEMA_VERSION => {
                return Err(SchemaTooNew {
                    found,
                    supported: SCHEMA_VERSION,
                }
                .into());
            }
            Some(found) => found,
            None if fresh => SCHEMA_VERSION,
            None => 0,
        };
        for version in from..SCHEMA_VERSION {
            migrate(&txn, version)?;
        }
        if stamped != Some(SCHEMA_VERSION) {
            txn.open_table(META)?.insert(SCHEMA, SCHEMA_VERSION)?;
        }
        txn.commit()?;
        if from < SCHEMA_VERSION {
            tracing::info!("database schema brought from version {from} to {SCHEMA_VERSION}");
        }
        Ok(Self { db })
    }

    /// Open every table, which creates the ones not there yet.
    pub(crate) fn open_tables(txn: &redb::WriteTransaction) -> anyhow::Result<()> {
        txn.open_table(BUNDLES)?;
        txn.open_table(ONE_TIME)?;
        txn.open_table(ONE_TIME_USED)?;
        txn.open_table(PQ_ONE_TIME)?;
        txn.open_table(PQ_ONE_TIME_USED)?;
        txn.open_table(MAILBOX)?;
        txn.open_table(BY_ID)?;
        txn.open_table(USAGE)?;
        txn.open_table(META)?;
        txn.open_table(BLOBS)?;
        txn.open_table(BLOB_CHUNKS)?;
        txn.open_table(BANS)?;
        txn.open_table(ADMIN)?;
        txn.open_table(REVOCATIONS)?;
        txn.open_table(SUCCESSIONS)?;
        txn.open_table(LOG)?;
        txn.open_table(LOG_LATEST)?;
        txn.open_table(KEY_PACKAGES)?;
        txn.open_table(KEY_PACKAGES_USED)?;
        txn.open_table(KEY_PACKAGE_LAST_RESORT)?;
        txn.open_table(GROUPS)?;
        txn.open_table(DEVICE_REVOCATIONS)?;
        txn.open_table(DEVICE_REVOCATIONS_BY_ACCOUNT)?;
        Ok(())
    }

    /// The layout the database is stamped with.
    pub fn schema_version(&self) -> anyhow::Result<u64> {
        let txn = self.db.begin_read()?;
        Ok(txn
            .open_table(META)?
            .get(SCHEMA)?
            .map(|g| g.value())
            .unwrap_or(0))
    }

    /// Pretend the database was written by another relay: `None` for one
    /// from before the layout was stamped.
    #[cfg(test)]
    pub(crate) fn stamp_schema(&self, version: Option<u64>) -> anyhow::Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            match version {
                Some(v) => {
                    meta.insert(SCHEMA, v)?;
                }
                None => {
                    meta.remove(SCHEMA)?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    // --- administration --------------------------------------------------------

    /// Every identity with a bundle.
    pub fn users(&self) -> anyhow::Result<Vec<UserId>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BUNDLES)?;
        let mut users = Vec::new();
        for item in table.iter()? {
            let (key, _) = item?;
            let bytes: [u8; 32] = key
                .value()
                .try_into()
                .context("a bundle key that is not a user id")?;
            users.push(UserId::from_bytes(bytes)?);
        }
        Ok(users)
    }

    /// Queued envelopes and their bytes for `user`.
    pub fn usage(&self, user: &UserId) -> anyhow::Result<(u64, u64)> {
        let txn = self.db.begin_read()?;
        Ok(txn
            .open_table(USAGE)?
            .get(user.as_bytes().as_slice())?
            .map(|guard| guard.value())
            .unwrap_or((0, 0)))
    }

    /// Delete everything kept for `user`: the bundle, prekeys of both
    /// kinds, the mailbox. Blobs belong to nobody and expire on their own.
    pub fn remove_user(&self, user: &UserId) -> anyhow::Result<Removed> {
        let key = user.as_bytes().as_slice();
        let txn = self.db.begin_write()?;
        let mut removed = Removed::default();
        {
            let mut bundles = txn.open_table(BUNDLES)?;
            let was_device = bundles
                .get(key)?
                .map(|g| serde_json::from_slice::<KeyBundle>(g.value()))
                .transpose()?
                .is_some_and(|b| b.device_of.is_some());
            removed.had_bundle = bundles.remove(key)?.is_some();
            drop(bundles);
            if was_device {
                adjust_count(&mut txn.open_table(META)?, DEVICES, -1)?;
            }
            remove_user_data(&txn, key, &mut removed)?;
        }
        txn.commit()?;
        Ok(removed)
    }

    /// Delete everything kept for `user` but the bundle: the mailbox and
    /// the deposits of prekeys and key packages. What a device loses when
    /// its account revokes it; its bundle stays, as a revoked identity's
    /// does, so a lookup still answers with the bundle the log covers.
    pub fn cut_off(&self, user: &UserId) -> anyhow::Result<Removed> {
        let txn = self.db.begin_write()?;
        let mut removed = Removed::default();
        remove_user_data(&txn, user.as_bytes().as_slice(), &mut removed)?;
        txn.commit()?;
        Ok(removed)
    }

    pub fn set_ban(&self, key: &str, ban: &Ban) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(ban)?;
        let txn = self.db.begin_write()?;
        txn.open_table(BANS)?.insert(key, bytes.as_slice())?;
        txn.commit()?;
        Ok(())
    }

    /// Whether there was one.
    pub fn remove_ban(&self, key: &str) -> anyhow::Result<bool> {
        let txn = self.db.begin_write()?;
        let was = txn.open_table(BANS)?.remove(key)?.is_some();
        txn.commit()?;
        Ok(was)
    }

    pub fn bans(&self) -> anyhow::Result<Vec<(String, Ban)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BANS)?;
        let mut bans = Vec::new();
        for item in table.iter()? {
            let (key, value) = item?;
            bans.push((
                key.value().to_owned(),
                serde_json::from_slice(value.value())?,
            ));
        }
        Ok(bans)
    }

    // --- identity lifecycle ----------------------------------------------------

    /// Record a self-signed revocation for its identity, logging it in the
    /// same transaction.
    pub fn set_revocation(&self, revocation: &Revocation) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(revocation)?;
        let txn = self.db.begin_write()?;
        txn.open_table(REVOCATIONS)?
            .insert(revocation.identity.as_bytes().as_slice(), bytes.as_slice())?;
        append_log(
            &txn,
            subject(&revocation.identity),
            EntryKind::Revocation,
            revocation.transparency_leaf(),
            now_ms(),
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn revocation(&self, user: &UserId) -> anyhow::Result<Option<Revocation>> {
        let txn = self.db.begin_read()?;
        match txn
            .open_table(REVOCATIONS)?
            .get(user.as_bytes().as_slice())?
        {
            Some(guard) => Ok(Some(serde_json::from_slice(guard.value())?)),
            None => Ok(None),
        }
    }

    /// Whether the identity has been revoked.
    pub fn is_revoked(&self, user: &UserId) -> anyhow::Result<bool> {
        let txn = self.db.begin_read()?;
        Ok(txn
            .open_table(REVOCATIONS)?
            .get(user.as_bytes().as_slice())?
            .is_some())
    }

    /// Record a cross-signed succession, keyed by the old identity, logging
    /// it in the same transaction.
    pub fn set_succession(&self, succession: &Succession) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(succession)?;
        let txn = self.db.begin_write()?;
        txn.open_table(SUCCESSIONS)?
            .insert(succession.old.as_bytes().as_slice(), bytes.as_slice())?;
        append_log(
            &txn,
            subject(&succession.old),
            EntryKind::Succession,
            succession.transparency_leaf(),
            now_ms(),
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn succession(&self, user: &UserId) -> anyhow::Result<Option<Succession>> {
        let txn = self.db.begin_read()?;
        match txn
            .open_table(SUCCESSIONS)?
            .get(user.as_bytes().as_slice())?
        {
            Some(guard) => Ok(Some(serde_json::from_slice(guard.value())?)),
            None => Ok(None),
        }
    }

    // --- devices ---------------------------------------------------------------

    /// Record an account's revocation of one of its devices, keyed by the
    /// device, indexed by the account, and logged in the same transaction
    /// as a revocation entry whose subject is the device. A device already
    /// revoked stays as it was, whatever the new statement says: `false`
    /// then, and nothing is written or logged.
    pub fn set_device_revocation(&self, revocation: &DeviceRevocation) -> anyhow::Result<bool> {
        let bytes = serde_json::to_vec(revocation)?;
        let device = revocation.device.as_bytes().as_slice();
        let account = revocation.account.as_bytes().as_slice();
        let txn = self.db.begin_write()?;
        let new = {
            let mut table = txn.open_table(DEVICE_REVOCATIONS)?;
            if table.get(device)?.is_some() {
                false
            } else {
                table.insert(device, bytes.as_slice())?;
                txn.open_table(DEVICE_REVOCATIONS_BY_ACCOUNT)?
                    .insert((account, device), ())?;
                true
            }
        };
        if new {
            append_log(
                &txn,
                subject(&revocation.device),
                EntryKind::Revocation,
                revocation.transparency_leaf(),
                now_ms(),
            )?;
        }
        txn.commit()?;
        Ok(new)
    }

    /// The revocation of `device`, if its account issued one.
    pub fn device_revocation(&self, device: &UserId) -> anyhow::Result<Option<DeviceRevocation>> {
        let txn = self.db.begin_read()?;
        match txn
            .open_table(DEVICE_REVOCATIONS)?
            .get(device.as_bytes().as_slice())?
        {
            Some(guard) => Ok(Some(serde_json::from_slice(guard.value())?)),
            None => Ok(None),
        }
    }

    /// Whether `device` has been revoked by its account.
    pub fn is_device_revoked(&self, device: &UserId) -> anyhow::Result<bool> {
        let txn = self.db.begin_read()?;
        Ok(txn
            .open_table(DEVICE_REVOCATIONS)?
            .get(device.as_bytes().as_slice())?
            .is_some())
    }

    /// Every device revocation `account` issued, in device id order.
    pub fn device_revocations_by(&self, account: &UserId) -> anyhow::Result<Vec<DeviceRevocation>> {
        let account = account.as_bytes().as_slice();
        let txn = self.db.begin_read()?;
        let index = txn.open_table(DEVICE_REVOCATIONS_BY_ACCOUNT)?;
        let table = txn.open_table(DEVICE_REVOCATIONS)?;
        let mut out = Vec::new();
        for item in index.range((account, REF_LOW)..=(account, REF_HIGH))? {
            let (key, _) = item?;
            if let Some(guard) = table.get(key.value().1)? {
                out.push(serde_json::from_slice(guard.value())?);
            }
        }
        Ok(out)
    }

    pub fn admin_setting(&self, key: &str) -> anyhow::Result<Option<String>> {
        let txn = self.db.begin_read()?;
        Ok(txn
            .open_table(ADMIN)?
            .get(key)?
            .map(|guard| guard.value().to_owned()))
    }

    /// `None` removes the setting.
    pub fn set_admin_setting(&self, key: &str, value: Option<&str>) -> anyhow::Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ADMIN)?;
            match value {
                Some(value) => {
                    table.insert(key, value)?;
                }
                None => {
                    table.remove(key)?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    }
}

/// Everything kept for `key` but its bundle: the mailbox, the prekey
/// deposits of both kinds, the key packages; counted into `removed`.
fn remove_user_data(
    txn: &redb::WriteTransaction,
    key: &[u8],
    removed: &mut Removed,
) -> anyhow::Result<()> {
    let mut mailbox = txn.open_table(MAILBOX)?;
    let mut by_id = txn.open_table(BY_ID)?;
    let entries = mailbox
        .range((key, 0u64)..=(key, u64::MAX))?
        .map(|item| {
            let (k, v) = item?;
            let (_, envelope) = decode_entry(v.value())?;
            Ok((k.value().1, envelope.id, v.value().len() as u64))
        })
        .collect::<anyhow::Result<Vec<(u64, String, u64)>>>()?;
    for (seq, id, size) in entries {
        mailbox.remove((key, seq))?;
        by_id.remove(id.as_str())?;
        removed.messages += 1;
        removed.bytes += size;
    }
    txn.open_table(USAGE)?.remove(key)?;
    for (deposit, used) in [(ONE_TIME, ONE_TIME_USED), (PQ_ONE_TIME, PQ_ONE_TIME_USED)] {
        let mut table = txn.open_table(deposit)?;
        let ids = table
            .range((key, 0u32)..=(key, u32::MAX))?
            .map(|item| item.map(|(k, _)| k.value().1))
            .collect::<Result<Vec<u32>, _>>()?;
        for id in ids {
            table.remove((key, id))?;
            removed.prekeys += 1;
        }
        let mut table = txn.open_table(used)?;
        let ids = table
            .range((key, 0u32)..=(key, u32::MAX))?
            .map(|item| item.map(|(k, _)| k.value().1))
            .collect::<Result<Vec<u32>, _>>()?;
        for id in ids {
            table.remove((key, id))?;
        }
    }
    let mut packages = txn.open_table(KEY_PACKAGES)?;
    let seqs = packages
        .range((key, 0u64)..=(key, u64::MAX))?
        .map(|item| item.map(|(k, _)| k.value().1))
        .collect::<Result<Vec<u64>, _>>()?;
    for seq in seqs {
        packages.remove((key, seq))?;
        removed.key_packages += 1;
    }
    let mut used = txn.open_table(KEY_PACKAGES_USED)?;
    let refs = used
        .range((key, REF_LOW)..=(key, REF_HIGH))?
        .map(|item| item.map(|(k, _)| k.value().1.to_vec()))
        .collect::<Result<Vec<Vec<u8>>, _>>()?;
    for r in refs {
        used.remove((key, r.as_slice()))?;
    }
    if txn
        .open_table(KEY_PACKAGE_LAST_RESORT)?
        .remove(key)?
        .is_some()
    {
        removed.key_packages += 1;
    }
    Ok(())
}

impl Store {
    // --- blobs ---------------------------------------------------------------

    /// Store one chunk of a blob, creating the blob on its first chunk.
    pub fn put_blob_chunk(
        &self,
        blob: &str,
        index: u32,
        total: u32,
        data: &[u8],
        now_ms: u64,
        limits: BlobLimits,
    ) -> anyhow::Result<BlobPut> {
        let txn = self.db.begin_write()?;
        let outcome = {
            let mut blobs = txn.open_table(BLOBS)?;
            let mut chunks = txn.open_table(BLOB_CHUNKS)?;
            let mut meta_table = txn.open_table(META)?;
            let mut meta: BlobMeta = match blobs.get(blob)? {
                Some(guard) => serde_json::from_slice(guard.value())?,
                None => BlobMeta {
                    total,
                    received: 0,
                    bytes: 0,
                    created_at_ms: now_ms,
                },
            };
            let stored = meta_table.get(BLOB_BYTES)?.map(|g| g.value()).unwrap_or(0);
            if meta.total != total || index >= total {
                BlobPut::Mismatch
            } else if chunks.get((blob, index))?.is_some() {
                BlobPut::Duplicate
            } else if meta.bytes + data.len() as u64 > limits.max_blob_bytes {
                BlobPut::TooLarge
            } else if stored + data.len() as u64 > limits.max_total_bytes {
                BlobPut::StorageFull
            } else {
                chunks.insert((blob, index), data)?;
                meta.received += 1;
                meta.bytes += data.len() as u64;
                blobs.insert(blob, serde_json::to_vec(&meta)?.as_slice())?;
                meta_table.insert(BLOB_BYTES, stored + data.len() as u64)?;
                BlobPut::Stored {
                    complete: meta.is_complete(),
                }
            }
        };
        txn.commit()?;
        Ok(outcome)
    }

    pub fn blob_meta(&self, blob: &str) -> anyhow::Result<Option<BlobMeta>> {
        let txn = self.db.begin_read()?;
        match txn.open_table(BLOBS)?.get(blob)? {
            Some(guard) => Ok(Some(serde_json::from_slice(guard.value())?)),
            None => Ok(None),
        }
    }

    pub fn blob_chunk(&self, blob: &str, index: u32) -> anyhow::Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read()?;
        Ok(txn
            .open_table(BLOB_CHUNKS)?
            .get((blob, index))?
            .map(|g| g.value().to_vec()))
    }

    /// Delete blobs created before `cutoff_ms`, complete or not. Returns
    /// how many.
    pub fn expire_blobs(&self, cutoff_ms: u64) -> anyhow::Result<usize> {
        let victims: Vec<(String, BlobMeta)> = {
            let txn = self.db.begin_read()?;
            let table = txn.open_table(BLOBS)?;
            let mut victims = Vec::new();
            for item in table.iter()? {
                let (key, value) = item?;
                let meta: BlobMeta = serde_json::from_slice(value.value())?;
                if meta.created_at_ms < cutoff_ms {
                    victims.push((key.value().to_owned(), meta));
                }
            }
            victims
        };
        if victims.is_empty() {
            return Ok(0);
        }
        let txn = self.db.begin_write()?;
        {
            let mut blobs = txn.open_table(BLOBS)?;
            let mut chunks = txn.open_table(BLOB_CHUNKS)?;
            let mut meta_table = txn.open_table(META)?;
            let mut stored = meta_table.get(BLOB_BYTES)?.map(|g| g.value()).unwrap_or(0);
            for (blob, meta) in &victims {
                for index in 0..meta.total {
                    chunks.remove((blob.as_str(), index))?;
                }
                blobs.remove(blob.as_str())?;
                stored = stored.saturating_sub(meta.bytes);
            }
            meta_table.insert(BLOB_BYTES, stored)?;
        }
        txn.commit()?;
        Ok(victims.len())
    }

    /// Store `bundle` and, if it differs from the owner's last logged one,
    /// log it in the same transaction, so nothing served is ever missing
    /// from the log.
    pub fn put_bundle(&self, bundle: &KeyBundle) -> anyhow::Result<()> {
        let txn = self.db.begin_write()?;
        store_bundle_in(&txn, bundle)?;
        log_bundle_in(&txn, bundle, now_ms())?;
        txn.commit()?;
        Ok(())
    }

    /// Store `bundle` *without* logging it: what a relay lying to one client
    /// would do. For tests of the client's checks only.
    #[doc(hidden)]
    pub fn put_bundle_unlogged(&self, bundle: &KeyBundle) -> anyhow::Result<()> {
        let txn = self.db.begin_write()?;
        store_bundle_in(&txn, bundle)?;
        txn.commit()?;
        Ok(())
    }

    // --- transparency log --------------------------------------------------------

    /// Where the log stands.
    pub fn log_head(&self) -> anyhow::Result<LogHead> {
        let txn = self.db.begin_read()?;
        head_in(&txn.open_table(LOG)?)
    }

    /// Where `user` last appears in the log, if anywhere.
    pub fn log_latest(&self, user: &UserId) -> anyhow::Result<Option<LogPosition>> {
        let txn = self.db.begin_read()?;
        Ok(
            match txn.open_table(LOG_LATEST)?.get(subject(user).as_slice())? {
                Some(guard) => Some(serde_json::from_slice::<Latest>(guard.value())?.position),
                None => None,
            },
        )
    }

    /// Up to `limit` entries after `index`, in order.
    pub fn log_since(&self, index: u64, limit: usize) -> anyhow::Result<Vec<LogEntry>> {
        let txn = self.db.begin_read()?;
        txn.open_table(LOG)?
            .range(index.saturating_add(1)..)?
            .take(limit)
            .map(|item| Ok(serde_json::from_slice(item?.1.value())?))
            .collect()
    }

    /// How many entries the log has.
    pub fn log_len(&self) -> anyhow::Result<u64> {
        Ok(self.log_head()?.index)
    }

    pub fn bundle(&self, user: &UserId) -> anyhow::Result<Option<KeyBundle>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BUNDLES)?;
        match table.get(user.as_bytes().as_slice())? {
            Some(guard) => Ok(Some(serde_json::from_slice(guard.value())?)),
            None => Ok(None),
        }
    }

    // --- one-time prekeys -----------------------------------------------------

    /// Replace `user`'s one-time prekeys with `keys`, the full list the
    /// client still holds. Keys already handed out are not stored again
    /// even if listed; keys no longer listed are forgotten.
    pub fn set_one_time_prekeys(
        &self,
        user: &UserId,
        keys: &[OneTimePrekey],
    ) -> anyhow::Result<()> {
        let keys: Vec<(u32, Vec<u8>)> = keys.iter().map(|k| (k.id, k.public.0.to_vec())).collect();
        self.replace_deposit((ONE_TIME, ONE_TIME_USED), user, &keys)
    }

    /// Hand out one of `user`'s one-time prekeys, never to be handed out
    /// again. `None` when there are none left.
    pub fn take_one_time_prekey(&self, user: &UserId) -> anyhow::Result<Option<OneTimePrekey>> {
        self.take_from_deposit((ONE_TIME, ONE_TIME_USED), user)?
            .map(|(id, public)| {
                let bytes: [u8; 32] = public
                    .as_slice()
                    .try_into()
                    .context("stored one-time prekey has the wrong length")?;
                Ok(OneTimePrekey {
                    id,
                    public: DhPublic(bytes),
                })
            })
            .transpose()
    }

    /// How many one-time prekeys `user` has left, and the ids handed out
    /// that the user has not dropped from its list yet.
    pub fn one_time_status(&self, user: &UserId) -> anyhow::Result<(u32, Vec<u32>)> {
        self.deposit_status((ONE_TIME, ONE_TIME_USED), user)
    }

    /// The same three operations for one-time ML-KEM keys.
    pub fn set_pq_one_time_prekeys(
        &self,
        user: &UserId,
        keys: &[SignedPqPrekey],
    ) -> anyhow::Result<()> {
        let keys = keys
            .iter()
            .map(|k| Ok((k.id, serde_json::to_vec(k)?)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.replace_deposit((PQ_ONE_TIME, PQ_ONE_TIME_USED), user, &keys)
    }

    pub fn take_pq_one_time_prekey(&self, user: &UserId) -> anyhow::Result<Option<SignedPqPrekey>> {
        self.take_from_deposit((PQ_ONE_TIME, PQ_ONE_TIME_USED), user)?
            .map(|(_, json)| {
                serde_json::from_slice(&json).context("stored one-time ML-KEM key is unreadable")
            })
            .transpose()
    }

    pub fn pq_one_time_status(&self, user: &UserId) -> anyhow::Result<(u32, Vec<u32>)> {
        self.deposit_status((PQ_ONE_TIME, PQ_ONE_TIME_USED), user)
    }

    fn replace_deposit(
        &self,
        (deposit, used_keys): (DepositTable, UsedTable),
        user: &UserId,
        keys: &[(u32, Vec<u8>)],
    ) -> anyhow::Result<()> {
        let user = user.as_bytes().as_slice();
        let listed: HashSet<u32> = keys.iter().map(|(id, _)| *id).collect();
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(deposit)?;
            let mut used = txn.open_table(used_keys)?;
            let mut stale = Vec::new();
            for item in table.range((user, 0u32)..=(user, u32::MAX))? {
                let (key, _) = item?;
                let id = key.value().1;
                if !listed.contains(&id) {
                    stale.push(id);
                }
            }
            for id in stale {
                table.remove((user, id))?;
            }
            let mut stale_used = Vec::new();
            for item in used.range((user, 0u32)..=(user, u32::MAX))? {
                let (key, _) = item?;
                let id = key.value().1;
                if !listed.contains(&id) {
                    stale_used.push(id);
                }
            }
            for id in stale_used {
                used.remove((user, id))?;
            }
            for (id, encoded) in keys {
                if used.get((user, *id))?.is_some() || table.get((user, *id))?.is_some() {
                    continue;
                }
                table.insert((user, *id), encoded.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    fn take_from_deposit(
        &self,
        (deposit, used): (DepositTable, UsedTable),
        user: &UserId,
    ) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let user = user.as_bytes().as_slice();
        let txn = self.db.begin_write()?;
        let taken = {
            let mut table = txn.open_table(deposit)?;
            let first = table
                .range((user, 0u32)..=(user, u32::MAX))?
                .next()
                .transpose()?
                .map(|(key, value)| (key.value().1, value.value().to_vec()));
            if let Some((id, _)) = &first {
                table.remove((user, *id))?;
                txn.open_table(used)?.insert((user, *id), ())?;
            }
            first
        };
        txn.commit()?;
        Ok(taken)
    }

    fn deposit_status(
        &self,
        (deposit, used_keys): (DepositTable, UsedTable),
        user: &UserId,
    ) -> anyhow::Result<(u32, Vec<u32>)> {
        let user = user.as_bytes().as_slice();
        let txn = self.db.begin_read()?;
        let mut remaining = 0u32;
        for item in txn
            .open_table(deposit)?
            .range((user, 0u32)..=(user, u32::MAX))?
        {
            item?;
            remaining += 1;
        }
        let mut used = Vec::new();
        for item in txn
            .open_table(used_keys)?
            .range((user, 0u32)..=(user, u32::MAX))?
        {
            let (key, _) = item?;
            used.push(key.value().1);
        }
        Ok((remaining, used))
    }

    // --- key packages ---------------------------------------------------------

    /// Replace `user`'s key package deposit with `packages`, the full list
    /// the client still holds, and its last-resort package (`None` drops
    /// it). Packages already on deposit keep their place in the queue; ones
    /// handed out are not stored again even if listed; ones no longer
    /// listed are forgotten.
    pub fn set_key_packages(
        &self,
        user: &UserId,
        packages: &[KeyPackageDeposit],
        last_resort: Option<&KeyPackageDeposit>,
    ) -> anyhow::Result<()> {
        let user = user.as_bytes().as_slice();
        let listed: HashSet<[u8; 32]> = packages.iter().map(|p| p.r#ref).collect();
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(KEY_PACKAGES)?;
            let mut used = txn.open_table(KEY_PACKAGES_USED)?;
            let mut present = HashSet::new();
            let mut stale = Vec::new();
            for item in table.range((user, 0u64)..=(user, u64::MAX))? {
                let (key, value) = item?;
                let deposit: KeyPackageDeposit = serde_json::from_slice(value.value())
                    .context("stored key package is unreadable")?;
                if listed.contains(&deposit.r#ref) {
                    present.insert(deposit.r#ref);
                } else {
                    stale.push(key.value().1);
                }
            }
            for seq in stale {
                table.remove((user, seq))?;
            }
            let mut stale_used = Vec::new();
            for item in used.range((user, REF_LOW)..=(user, REF_HIGH))? {
                let (key, _) = item?;
                let r = key.value().1.to_vec();
                let known = <[u8; 32]>::try_from(r.as_slice()).is_ok_and(|r| listed.contains(&r));
                if !known {
                    stale_used.push(r);
                }
            }
            for r in stale_used {
                used.remove((user, r.as_slice()))?;
            }
            let mut meta = txn.open_table(META)?;
            for package in packages {
                if present.contains(&package.r#ref)
                    || used.get((user, package.r#ref.as_slice()))?.is_some()
                {
                    continue;
                }
                let seq = meta.get(NEXT_KEY_PACKAGE)?.map(|g| g.value()).unwrap_or(0);
                meta.insert(NEXT_KEY_PACKAGE, seq + 1)?;
                table.insert((user, seq), serde_json::to_vec(package)?.as_slice())?;
                present.insert(package.r#ref);
            }
            let mut last = txn.open_table(KEY_PACKAGE_LAST_RESORT)?;
            match last_resort {
                Some(package) => {
                    last.insert(user, serde_json::to_vec(package)?.as_slice())?;
                }
                None => {
                    last.remove(user)?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Hand out one of `user`'s key packages: the oldest on deposit that
    /// has not expired, removed as it goes and remembered as handed out;
    /// failing that, the last-resort one, which stays (`true` says so).
    /// `None` when the identity has nothing on deposit. Expired packages
    /// met on the way are dropped.
    pub fn take_key_package(
        &self,
        user: &UserId,
        now_ms: u64,
    ) -> anyhow::Result<Option<(KeyPackageDeposit, bool)>> {
        let user = user.as_bytes().as_slice();
        let txn = self.db.begin_write()?;
        let taken = {
            let mut table = txn.open_table(KEY_PACKAGES)?;
            let mut expired = Vec::new();
            let mut found = None;
            for item in table.range((user, 0u64)..=(user, u64::MAX))? {
                let (key, value) = item?;
                let deposit: KeyPackageDeposit = serde_json::from_slice(value.value())
                    .context("stored key package is unreadable")?;
                if deposit.expires_at_ms <= now_ms {
                    expired.push(key.value().1);
                    continue;
                }
                found = Some((key.value().1, deposit));
                break;
            }
            for seq in expired {
                table.remove((user, seq))?;
            }
            match found {
                Some((seq, deposit)) => {
                    table.remove((user, seq))?;
                    txn.open_table(KEY_PACKAGES_USED)?
                        .insert((user, deposit.r#ref.as_slice()), ())?;
                    Some((deposit, false))
                }
                None => last_resort_in(&txn, user, now_ms)?.map(|d| (d, true)),
            }
        };
        txn.commit()?;
        Ok(taken)
    }

    /// The last-resort package alone, for handouts past the rate limit.
    pub fn last_resort_key_package(
        &self,
        user: &UserId,
        now_ms: u64,
    ) -> anyhow::Result<Option<KeyPackageDeposit>> {
        let txn = self.db.begin_write()?;
        let package = last_resort_in(&txn, user.as_bytes(), now_ms)?;
        txn.commit()?;
        Ok(package)
    }

    /// How many key packages `user` has on deposit (the last-resort one
    /// not counted), and the refs handed out that the user has not dropped
    /// from its list yet.
    pub fn key_package_status(&self, user: &UserId) -> anyhow::Result<(u32, Vec<[u8; 32]>)> {
        let user = user.as_bytes().as_slice();
        let txn = self.db.begin_read()?;
        let mut remaining = 0u32;
        for item in txn
            .open_table(KEY_PACKAGES)?
            .range((user, 0u64)..=(user, u64::MAX))?
        {
            item?;
            remaining += 1;
        }
        let mut used = Vec::new();
        for item in txn
            .open_table(KEY_PACKAGES_USED)?
            .range((user, REF_LOW)..=(user, REF_HIGH))?
        {
            let (key, _) = item?;
            if let Ok(r) = <[u8; 32]>::try_from(key.value().1) {
                used.push(r);
            }
        }
        Ok((remaining, used))
    }

    /// Drop every key package whose lifetime ended. Returns how many.
    pub fn expire_key_packages(&self, now_ms: u64) -> anyhow::Result<usize> {
        let txn = self.db.begin_write()?;
        let mut dropped = 0;
        {
            let mut table = txn.open_table(KEY_PACKAGES)?;
            let mut victims = Vec::new();
            for item in table.iter()? {
                let (key, value) = item?;
                let deposit: KeyPackageDeposit = serde_json::from_slice(value.value())
                    .context("stored key package is unreadable")?;
                if deposit.expires_at_ms <= now_ms {
                    let (user, seq) = key.value();
                    victims.push((user.to_vec(), seq));
                }
            }
            for (user, seq) in &victims {
                table.remove((user.as_slice(), *seq))?;
            }
            dropped += victims.len();
            let mut last = txn.open_table(KEY_PACKAGE_LAST_RESORT)?;
            let mut victims = Vec::new();
            for item in last.iter()? {
                let (key, value) = item?;
                let deposit: KeyPackageDeposit = serde_json::from_slice(value.value())
                    .context("stored key package is unreadable")?;
                if deposit.expires_at_ms <= now_ms {
                    victims.push(key.value().to_vec());
                }
            }
            for user in &victims {
                last.remove(user.as_slice())?;
            }
            dropped += victims.len();
        }
        txn.commit()?;
        Ok(dropped)
    }

    // --- the group epoch sequencer ---------------------------------------------

    /// Create the sequencer entry for `group` at `epoch`, `next` being the
    /// hash of the token that moves it on. Idempotent for the same values.
    pub fn group_create(
        &self,
        group: &GroupId,
        epoch: u64,
        next: [u8; 32],
        now_ms: u64,
    ) -> anyhow::Result<Sequenced> {
        let key = group.as_bytes().as_slice();
        let txn = self.db.begin_write()?;
        let outcome = {
            let mut table = txn.open_table(GROUPS)?;
            let existing = table.get(key)?.map(|g| g.value().to_vec());
            match existing {
                Some(json) => {
                    let entry: GroupEntry = serde_json::from_slice(&json)
                        .context("stored group entry is unreadable")?;
                    if entry.epoch == epoch && entry.next == next {
                        Sequenced::Stands(epoch)
                    } else {
                        Sequenced::Exists(entry.epoch)
                    }
                }
                None => {
                    let entry = GroupEntry {
                        epoch,
                        next,
                        created_at_ms: now_ms,
                        updated_at_ms: now_ms,
                    };
                    table.insert(key, serde_json::to_vec(&entry)?.as_slice())?;
                    Sequenced::Stands(epoch)
                }
            }
        };
        txn.commit()?;
        Ok(outcome)
    }

    /// Move `group` from `epoch` to `epoch + 1` if it stands at `epoch` and
    /// `token` hashes to what the entry holds; `next` is the hash of the
    /// token for the epoch after.
    pub fn group_commit(
        &self,
        group: &GroupId,
        epoch: u64,
        token: &[u8; 32],
        next: [u8; 32],
        now_ms: u64,
    ) -> anyhow::Result<Sequenced> {
        let key = group.as_bytes().as_slice();
        let txn = self.db.begin_write()?;
        let outcome = {
            let mut table = txn.open_table(GROUPS)?;
            let existing = table.get(key)?.map(|g| g.value().to_vec());
            match existing {
                None => Sequenced::NotFound,
                Some(json) => {
                    let mut entry: GroupEntry = serde_json::from_slice(&json)
                        .context("stored group entry is unreadable")?;
                    if entry.epoch != epoch {
                        Sequenced::Stale(entry.epoch)
                    } else if !bool::from(token_hash(token).ct_eq(&entry.next)) {
                        Sequenced::Forbidden
                    } else {
                        entry.epoch += 1;
                        entry.next = next;
                        entry.updated_at_ms = now_ms;
                        table.insert(key, serde_json::to_vec(&entry)?.as_slice())?;
                        Sequenced::Stands(entry.epoch)
                    }
                }
            }
        };
        txn.commit()?;
        Ok(outcome)
    }

    /// Where `group`'s sequencer entry stands, if it has one.
    pub fn group_epoch(&self, group: &GroupId) -> anyhow::Result<Option<u64>> {
        let txn = self.db.begin_read()?;
        txn.open_table(GROUPS)?
            .get(group.as_bytes().as_slice())?
            .map(|g| {
                let entry: GroupEntry = serde_json::from_slice(g.value())
                    .context("stored group entry is unreadable")?;
                Ok(entry.epoch)
            })
            .transpose()
    }

    /// How many groups have a sequencer entry.
    pub fn group_count(&self) -> anyhow::Result<u64> {
        Ok(self.db.begin_read()?.open_table(GROUPS)?.len()?)
    }

    /// Drop sequencer entries not moved since `cutoff_ms`. Returns how many.
    pub fn expire_groups(&self, cutoff_ms: u64) -> anyhow::Result<usize> {
        let txn = self.db.begin_write()?;
        let victims = {
            let table = txn.open_table(GROUPS)?;
            let mut victims = Vec::new();
            for item in table.iter()? {
                let (key, value) = item?;
                let entry: GroupEntry = serde_json::from_slice(value.value())
                    .context("stored group entry is unreadable")?;
                if entry.updated_at_ms < cutoff_ms {
                    victims.push(key.value().to_vec());
                }
            }
            victims
        };
        {
            let mut table = txn.open_table(GROUPS)?;
            for group in &victims {
                table.remove(group.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(victims.len())
    }

    /// Queue an envelope for its recipient.
    pub fn enqueue(
        &self,
        envelope: &Envelope,
        now_ms: u64,
        limits: Limits,
    ) -> anyhow::Result<Enqueue> {
        let mut value = now_ms.to_be_bytes().to_vec();
        serde_json::to_writer(&mut value, envelope)?;
        let size = value.len() as u64;
        let user = envelope.to.as_bytes().as_slice();

        let txn = self.db.begin_write()?;
        let outcome = {
            let mut by_id = txn.open_table(BY_ID)?;
            if by_id.get(envelope.id.as_str())?.is_some() {
                Enqueue::Duplicate
            } else {
                let mut usage = txn.open_table(USAGE)?;
                let (count, bytes) = usage.get(user)?.map(|g| g.value()).unwrap_or((0, 0));
                if count >= limits.max_messages || bytes + size > limits.max_bytes {
                    Enqueue::MailboxFull
                } else {
                    let mut meta = txn.open_table(META)?;
                    let seq = meta.get(NEXT_SEQ)?.map(|g| g.value()).unwrap_or(0);
                    meta.insert(NEXT_SEQ, seq + 1)?;
                    txn.open_table(MAILBOX)?
                        .insert((user, seq), value.as_slice())?;
                    by_id.insert(envelope.id.as_str(), (user, seq))?;
                    usage.insert(user, (count + 1, bytes + size))?;
                    Enqueue::Stored
                }
            }
        };
        txn.commit()?;
        Ok(outcome)
    }

    /// Everything waiting for `user`, oldest first.
    pub fn queued(&self, user: &UserId) -> anyhow::Result<Vec<Envelope>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(MAILBOX)?;
        let user = user.as_bytes().as_slice();
        let mut out = Vec::new();
        for item in table.range((user, 0u64)..=(user, u64::MAX))? {
            let (_, value) = item?;
            out.push(decode_entry(value.value())?.1);
        }
        Ok(out)
    }

    pub fn queued_count(&self, user: &UserId) -> anyhow::Result<u64> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(USAGE)?;
        Ok(table
            .get(user.as_bytes().as_slice())?
            .map(|g| g.value().0)
            .unwrap_or(0))
    }

    /// Drop an envelope from `user`'s mailbox. Returns whether it was there.
    pub fn ack(&self, user: &UserId, id: &str) -> anyhow::Result<bool> {
        let txn = self.db.begin_write()?;
        let removed = {
            let mut by_id = txn.open_table(BY_ID)?;
            let target = by_id.get(id)?.map(|g| {
                let (owner, seq) = g.value();
                (owner.to_vec(), seq)
            });
            match target {
                Some((owner, seq)) if owner.as_slice() == user.as_bytes() => {
                    by_id.remove(id)?;
                    let mut mailbox = txn.open_table(MAILBOX)?;
                    let size = mailbox
                        .remove((owner.as_slice(), seq))?
                        .map(|g| g.value().len() as u64)
                        .unwrap_or(0);
                    let mut usage = txn.open_table(USAGE)?;
                    adjust_usage(&mut usage, &owner, 1, size)?;
                    true
                }
                _ => false,
            }
        };
        txn.commit()?;
        Ok(removed)
    }

    /// Delete every envelope received before `cutoff_ms`. Returns how many.
    pub fn expire(&self, cutoff_ms: u64) -> anyhow::Result<usize> {
        let victims: Vec<(Vec<u8>, u64, String, u64)> = {
            let txn = self.db.begin_read()?;
            let table = txn.open_table(MAILBOX)?;
            let mut victims = Vec::new();
            for item in table.iter()? {
                let (key, value) = item?;
                let (received_at, envelope) = decode_entry(value.value())?;
                if received_at < cutoff_ms {
                    let (owner, seq) = key.value();
                    victims.push((owner.to_vec(), seq, envelope.id, value.value().len() as u64));
                }
            }
            victims
        };
        if victims.is_empty() {
            return Ok(0);
        }
        let txn = self.db.begin_write()?;
        {
            let mut mailbox = txn.open_table(MAILBOX)?;
            let mut by_id = txn.open_table(BY_ID)?;
            let mut usage = txn.open_table(USAGE)?;
            for (owner, seq, id, size) in &victims {
                mailbox.remove((owner.as_slice(), *seq))?;
                by_id.remove(id.as_str())?;
                adjust_usage(&mut usage, owner, 1, *size)?;
            }
        }
        txn.commit()?;
        Ok(victims.len())
    }

    pub fn stats(&self) -> anyhow::Result<Stats> {
        let txn = self.db.begin_read()?;
        let bundles = txn.open_table(BUNDLES)?.len()?;
        let blobs = txn.open_table(BLOBS)?.len()?;
        let blob_bytes = txn
            .open_table(META)?
            .get(BLOB_BYTES)?
            .map(|g| g.value())
            .unwrap_or(0);
        let usage = txn.open_table(USAGE)?;
        let key_packages = txn.open_table(KEY_PACKAGES)?.len()?;
        let groups = txn.open_table(GROUPS)?.len()?;
        let devices = txn
            .open_table(META)?
            .get(DEVICES)?
            .map(|g| g.value())
            .unwrap_or(0);
        let device_revocations = txn.open_table(DEVICE_REVOCATIONS)?.len()?;
        let mut stats = Stats {
            bundles,
            blobs,
            blob_bytes,
            key_packages,
            groups,
            devices,
            device_revocations,
            ..Stats::default()
        };
        for item in usage.iter()? {
            let (_, value) = item?;
            let (count, bytes) = value.value();
            stats.mailboxes += 1;
            stats.messages += count;
            stats.bytes += bytes;
        }
        Ok(stats)
    }
}

/// The range of key package refs under one owner: every ref is 32 bytes.
const REF_LOW: &[u8] = &[];
const REF_HIGH: &[u8] = &[0xff; 33];

/// `user`'s last-resort key package, dropped if its lifetime ended.
fn last_resort_in(
    txn: &redb::WriteTransaction,
    user: &[u8],
    now_ms: u64,
) -> anyhow::Result<Option<KeyPackageDeposit>> {
    let mut last = txn.open_table(KEY_PACKAGE_LAST_RESORT)?;
    let Some(json) = last.get(user)?.map(|g| g.value().to_vec()) else {
        return Ok(None);
    };
    let deposit: KeyPackageDeposit =
        serde_json::from_slice(&json).context("stored key package is unreadable")?;
    if deposit.expires_at_ms <= now_ms {
        last.remove(user)?;
        return Ok(None);
    }
    Ok(Some(deposit))
}

/// Store `bundle` under its owner, keeping the count of linked devices
/// right: one more when a bundle gains `device_of`, one fewer when a
/// bundle loses it.
fn store_bundle_in(txn: &redb::WriteTransaction, bundle: &KeyBundle) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(bundle)?;
    let key = bundle.user_id.as_bytes().as_slice();
    let mut bundles = txn.open_table(BUNDLES)?;
    let was_device = bundles
        .get(key)?
        .map(|g| serde_json::from_slice::<KeyBundle>(g.value()))
        .transpose()?
        .is_some_and(|b| b.device_of.is_some());
    bundles.insert(key, bytes.as_slice())?;
    drop(bundles);
    let change = i64::from(bundle.device_of.is_some()) - i64::from(was_device);
    if change != 0 {
        adjust_count(&mut txn.open_table(META)?, DEVICES, change)?;
    }
    Ok(())
}

/// Move a counter in the meta table by `by`, never below zero.
fn adjust_count(meta: &mut redb::Table<'_, &str, u64>, key: &str, by: i64) -> anyhow::Result<()> {
    let count = meta.get(key)?.map(|g| g.value()).unwrap_or(0);
    let next = if by < 0 {
        count.saturating_sub(by.unsigned_abs())
    } else {
        count.saturating_add(by as u64)
    };
    meta.insert(key, next)?;
    Ok(())
}

fn adjust_usage(
    usage: &mut redb::Table<'_, &[u8], (u64, u64)>,
    owner: &[u8],
    fewer_messages: u64,
    fewer_bytes: u64,
) -> anyhow::Result<()> {
    let (count, bytes) = usage.get(owner)?.map(|g| g.value()).unwrap_or((0, 0));
    let next = (
        count.saturating_sub(fewer_messages),
        bytes.saturating_sub(fewer_bytes),
    );
    if next.0 == 0 {
        usage.remove(owner)?;
    } else {
        usage.insert(owner, next)?;
    }
    Ok(())
}

fn decode_entry(bytes: &[u8]) -> anyhow::Result<(u64, Envelope)> {
    let (stamp, json) = bytes
        .split_first_chunk::<8>()
        .context("mailbox entry shorter than its timestamp")?;
    Ok((u64::from_be_bytes(*stamp), serde_json::from_slice(json)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::{Content, Identity, PqPrekeySecret, seal};

    fn package(n: u8, expires_at_ms: u64) -> KeyPackageDeposit {
        KeyPackageDeposit {
            r#ref: [n; 32],
            expires_at_ms,
            data: vec![n; 10],
        }
    }

    #[test]
    fn key_packages_are_deposited_handed_out_oldest_first_and_reported() {
        let store = Store::in_memory().unwrap();
        let bob = Identity::generate().user_id();
        assert_eq!(store.take_key_package(&bob, 0).unwrap(), None);
        store
            .set_key_packages(
                &bob,
                &[package(1, 100), package(2, 100), package(3, 5)],
                Some(&package(9, 100)),
            )
            .unwrap();
        assert_eq!(store.key_package_status(&bob).unwrap(), (3, vec![]));
        assert_eq!(store.stats().unwrap().key_packages, 3);
        // Oldest first, remembered as handed out.
        let (taken, last_resort) = store.take_key_package(&bob, 10).unwrap().unwrap();
        assert_eq!((taken.r#ref, last_resort), ([1; 32], false));
        assert_eq!(store.key_package_status(&bob).unwrap(), (2, vec![[1; 32]]));
        assert_eq!(
            store.take_key_package(&bob, 10).unwrap().unwrap().0.r#ref,
            [2; 32]
        );
        // The expired one is dropped when met; the last resort follows and
        // stays.
        let (taken, last_resort) = store.take_key_package(&bob, 10).unwrap().unwrap();
        assert_eq!((taken.r#ref, last_resort), ([9; 32], true));
        assert_eq!(
            store.key_package_status(&bob).unwrap(),
            (0, vec![[1; 32], [2; 32]])
        );
        assert_eq!(
            store.take_key_package(&bob, 10).unwrap().unwrap().0.r#ref,
            [9; 32]
        );
        // A re-deposit: a handed-out package listed again is not stored
        // again, an unlisted handed-out one is forgotten, new ones queue.
        store
            .set_key_packages(
                &bob,
                &[package(2, 100), package(4, 100)],
                Some(&package(9, 100)),
            )
            .unwrap();
        assert_eq!(store.key_package_status(&bob).unwrap(), (1, vec![[2; 32]]));
        // Packages keep their place across re-deposits.
        store
            .set_key_packages(
                &bob,
                &[package(6, 100), package(4, 100), package(5, 100)],
                Some(&package(9, 100)),
            )
            .unwrap();
        let mut order = Vec::new();
        for _ in 0..3 {
            order.push(store.take_key_package(&bob, 10).unwrap().unwrap().0.r#ref[0]);
        }
        assert_eq!(order, vec![4, 6, 5]);
        // Dropping everything, including the last resort.
        store.set_key_packages(&bob, &[], None).unwrap();
        assert_eq!(store.take_key_package(&bob, 10).unwrap(), None);
        assert_eq!(store.key_package_status(&bob).unwrap(), (0, vec![]));
        // An expired last resort is dropped when asked for.
        store
            .set_key_packages(&bob, &[], Some(&package(8, 5)))
            .unwrap();
        assert_eq!(store.last_resort_key_package(&bob, 10).unwrap(), None);
        assert_eq!(store.stats().unwrap().key_packages, 0);
    }

    #[test]
    fn key_packages_expire_and_go_with_their_owner() {
        let store = Store::in_memory().unwrap();
        let bob = Identity::generate();
        store.put_bundle(&bob.key_bundle()).unwrap();
        store
            .set_key_packages(
                &bob.user_id(),
                &[package(1, 50), package(2, 100)],
                Some(&package(9, 50)),
            )
            .unwrap();
        assert_eq!(store.expire_key_packages(60).unwrap(), 2);
        assert_eq!(
            store.key_package_status(&bob.user_id()).unwrap(),
            (1, vec![])
        );
        assert_eq!(
            store.last_resort_key_package(&bob.user_id(), 60).unwrap(),
            None
        );
        store
            .set_key_packages(
                &bob.user_id(),
                &[package(2, 100), package(3, 100)],
                Some(&package(9, 100)),
            )
            .unwrap();
        store.take_key_package(&bob.user_id(), 60).unwrap();
        let removed = store.remove_user(&bob.user_id()).unwrap();
        assert!(removed.had_bundle);
        assert_eq!(
            removed.key_packages, 2,
            "one on deposit and the last resort"
        );
        assert_eq!(
            store.key_package_status(&bob.user_id()).unwrap(),
            (0, vec![])
        );
        assert_eq!(store.stats().unwrap().key_packages, 0);
    }

    #[test]
    fn the_sequencer_orders_commits_and_refuses_the_rest() {
        let store = Store::in_memory().unwrap();
        let group = GroupId([1; 32]);
        let (t0, t1, t2) = ([10u8; 32], [11u8; 32], [12u8; 32]);
        assert_eq!(
            store
                .group_commit(&group, 0, &t0, token_hash(&t1), 1)
                .unwrap(),
            Sequenced::NotFound
        );
        assert_eq!(
            store.group_create(&group, 0, token_hash(&t0), 1).unwrap(),
            Sequenced::Stands(0)
        );
        // Idempotent for the same values, refused for others.
        assert_eq!(
            store.group_create(&group, 0, token_hash(&t0), 2).unwrap(),
            Sequenced::Stands(0)
        );
        assert_eq!(
            store.group_create(&group, 1, token_hash(&t0), 2).unwrap(),
            Sequenced::Exists(0)
        );
        assert_eq!(
            store
                .group_commit(&group, 1, &t0, token_hash(&t1), 3)
                .unwrap(),
            Sequenced::Stale(0)
        );
        assert_eq!(
            store
                .group_commit(&group, 0, &t1, token_hash(&t1), 3)
                .unwrap(),
            Sequenced::Forbidden
        );
        assert_eq!(
            store
                .group_commit(&group, 0, &t0, token_hash(&t1), 3)
                .unwrap(),
            Sequenced::Stands(1)
        );
        assert_eq!(store.group_epoch(&group).unwrap(), Some(1));
        // The second committer built on epoch 0 loses.
        assert_eq!(
            store
                .group_commit(&group, 0, &t0, token_hash(&t2), 4)
                .unwrap(),
            Sequenced::Stale(1)
        );
        assert_eq!(
            store
                .group_commit(&group, 1, &t1, token_hash(&t2), 4)
                .unwrap(),
            Sequenced::Stands(2)
        );
        assert_eq!(store.group_count().unwrap(), 1);
        assert_eq!(store.stats().unwrap().groups, 1);
        // Entries expire by their last move; a member re-creates one.
        assert_eq!(store.expire_groups(4).unwrap(), 0);
        assert_eq!(store.expire_groups(5).unwrap(), 1);
        assert_eq!(store.group_epoch(&group).unwrap(), None);
        assert_eq!(
            store.group_commit(&group, 2, &t2, [0; 32], 6).unwrap(),
            Sequenced::NotFound
        );
        assert_eq!(
            store.group_create(&group, 2, token_hash(&t2), 6).unwrap(),
            Sequenced::Stands(2)
        );
    }

    #[test]
    fn a_version_two_database_gains_the_group_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.redb");
        let alice = Identity::generate();
        {
            let store = Store::open(&path).unwrap();
            store.put_bundle(&alice.key_bundle()).unwrap();
            // As 0.8.0 left it: no group or device tables, schema 2.
            let txn = store.db.begin_write().unwrap();
            txn.delete_table(KEY_PACKAGES).unwrap();
            txn.delete_table(KEY_PACKAGES_USED).unwrap();
            txn.delete_table(KEY_PACKAGE_LAST_RESORT).unwrap();
            txn.delete_table(GROUPS).unwrap();
            txn.delete_table(DEVICE_REVOCATIONS).unwrap();
            txn.delete_table(DEVICE_REVOCATIONS_BY_ACCOUNT).unwrap();
            txn.commit().unwrap();
            store.stamp_schema(Some(2)).unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(store.bundle(&alice.user_id()).unwrap().is_some());
        assert_eq!(
            store.key_package_status(&alice.user_id()).unwrap(),
            (0, vec![])
        );
        assert_eq!(store.group_count().unwrap(), 0);
        assert!(!store.is_device_revoked(&alice.user_id()).unwrap());
        assert_eq!(store.stats().unwrap().device_revocations, 0);
        assert_eq!(store.log_head().unwrap().index, 1, "the log is untouched");
    }

    #[test]
    fn device_revocations_are_kept_once_indexed_by_account_and_logged() {
        use silver_protocol::transparency::{EntryKind, subject};
        let store = Store::in_memory().unwrap();
        let alice = Identity::generate();
        let laptop = Identity::generate();
        let phone = Identity::generate();
        store.put_bundle(&alice.key_bundle()).unwrap();
        assert!(!store.is_device_revoked(&laptop.user_id()).unwrap());
        assert!(
            store
                .device_revocation(&laptop.user_id())
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .device_revocations_by(&alice.user_id())
                .unwrap()
                .is_empty()
        );

        let first = alice.revoke_device(&laptop.user_id(), 10);
        assert!(store.set_device_revocation(&first).unwrap());
        assert!(store.is_device_revoked(&laptop.user_id()).unwrap());
        assert_eq!(
            store.device_revocation(&laptop.user_id()).unwrap(),
            Some(first.clone())
        );
        // Logged under the device, as a revocation, with the device leaf.
        let entries = store.log_since(0, 10).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].kind, EntryKind::Revocation);
        assert_eq!(entries[1].subject, subject(&laptop.user_id()));
        assert_eq!(entries[1].leaf, first.transparency_leaf());
        assert_eq!(
            store.log_latest(&laptop.user_id()).unwrap().unwrap().index,
            2
        );
        // A second statement about the same device changes nothing.
        let again = alice.revoke_device(&laptop.user_id(), 11);
        assert!(!store.set_device_revocation(&again).unwrap());
        assert_eq!(
            store.device_revocation(&laptop.user_id()).unwrap(),
            Some(first.clone())
        );
        assert_eq!(store.log_head().unwrap().index, 2);
        // The account's lookup finds every one it issued, in device order,
        // and another account's finds none of them.
        let second = alice.revoke_device(&phone.user_id(), 12);
        assert!(store.set_device_revocation(&second).unwrap());
        let mut expected = vec![first, second];
        expected.sort_by_key(|revocation| revocation.device);
        assert_eq!(
            store.device_revocations_by(&alice.user_id()).unwrap(),
            expected
        );
        assert!(
            store
                .device_revocations_by(&laptop.user_id())
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.stats().unwrap().device_revocations, 2);
        // A revocation outlives the device's bundle, as an identity's does.
        store.put_bundle(&laptop.key_bundle()).unwrap();
        store.remove_user(&laptop.user_id()).unwrap();
        assert!(store.is_device_revoked(&laptop.user_id()).unwrap());
    }

    #[test]
    fn a_cut_off_device_keeps_its_bundle_and_loses_the_rest() {
        let store = Store::in_memory().unwrap();
        let alice = Identity::generate();
        let laptop = Identity::generate();
        let certificate = alice
            .certify_device(&laptop.user_id(), "laptop", 1)
            .unwrap();
        store
            .put_bundle(&laptop.key_bundle().as_device_of(certificate))
            .unwrap();
        store
            .set_one_time_prekeys(
                &laptop.user_id(),
                &[silver_protocol::PrekeySecret::generate(2, 0).one_time()],
            )
            .unwrap();
        store
            .set_key_packages(
                &laptop.user_id(),
                &[package(1, 100)],
                Some(&package(9, 100)),
            )
            .unwrap();
        store
            .enqueue(&envelope(&alice, &laptop, "hello"), 1, Limits::default())
            .unwrap();
        assert_eq!(store.stats().unwrap().devices, 1);

        let removed = store.cut_off(&laptop.user_id()).unwrap();
        assert_eq!(
            removed,
            Removed {
                had_bundle: false,
                messages: 1,
                bytes: removed.bytes,
                prekeys: 1,
                key_packages: 2,
            }
        );
        assert!(removed.bytes > 0);
        assert!(store.bundle(&laptop.user_id()).unwrap().is_some());
        assert!(store.queued(&laptop.user_id()).unwrap().is_empty());
        assert_eq!(
            store.one_time_status(&laptop.user_id()).unwrap(),
            (0, vec![])
        );
        assert_eq!(
            store.key_package_status(&laptop.user_id()).unwrap(),
            (0, vec![])
        );
        assert_eq!(store.stats().unwrap().devices, 1, "still a device");
        // The count follows the bundles: a device that drops its certificate
        // or goes altogether is one fewer; a plain identity is none.
        store.put_bundle(&laptop.key_bundle()).unwrap();
        assert_eq!(store.stats().unwrap().devices, 0);
        store.put_bundle(&alice.key_bundle()).unwrap();
        let phone = Identity::generate();
        let certificate = alice.certify_device(&phone.user_id(), "phone", 2).unwrap();
        store
            .put_bundle(&phone.key_bundle().as_device_of(certificate.clone()))
            .unwrap();
        store
            .put_bundle(&phone.key_bundle().as_device_of(certificate))
            .unwrap();
        assert_eq!(
            store.stats().unwrap().devices,
            1,
            "republished, not doubled"
        );
        store.remove_user(&phone.user_id()).unwrap();
        assert_eq!(store.stats().unwrap().devices, 0);
    }

    #[test]
    fn a_user_is_removed_from_every_table_and_nobody_else_is() {
        let store = Store::in_memory().unwrap();
        let bob = Identity::generate();
        let carol = Identity::generate();
        for who in [&bob, &carol] {
            let signed = silver_protocol::PrekeySecret::generate(1, 0);
            store
                .put_bundle(&who.key_bundle_with(silver_protocol::Prekeys::classical(
                    signed.signed_by(who),
                    vec![silver_protocol::PrekeySecret::generate(2, 0).one_time()],
                )))
                .unwrap();
            store
                .set_one_time_prekeys(
                    &who.user_id(),
                    &[silver_protocol::PrekeySecret::generate(2, 0).one_time()],
                )
                .unwrap();
            store
                .set_pq_one_time_prekeys(
                    &who.user_id(),
                    &[PqPrekeySecret::generate(3, 0).signed_by(who)],
                )
                .unwrap();
            let alice = Identity::generate();
            for text in ["one", "two"] {
                store
                    .enqueue(&envelope(&alice, who, text), 1, Limits::default())
                    .unwrap();
            }
        }
        store.take_one_time_prekey(&bob.user_id()).unwrap();
        assert_eq!(store.users().unwrap().len(), 2);
        let (count, bytes) = store.usage(&bob.user_id()).unwrap();
        assert_eq!(count, 2);
        assert!(bytes > 0);

        let removed = store.remove_user(&bob.user_id()).unwrap();
        assert!(removed.had_bundle);
        assert_eq!(removed.messages, 2);
        assert_eq!(removed.bytes, bytes);
        assert_eq!(
            removed.prekeys, 1,
            "the pq one; the x25519 one was handed out"
        );
        assert!(store.bundle(&bob.user_id()).unwrap().is_none());
        assert_eq!(store.usage(&bob.user_id()).unwrap(), (0, 0));
        assert!(store.queued(&bob.user_id()).unwrap().is_empty());
        assert_eq!(store.one_time_status(&bob.user_id()).unwrap(), (0, vec![]));
        assert_eq!(
            store.pq_one_time_status(&bob.user_id()).unwrap(),
            (0, vec![])
        );
        assert_eq!(store.users().unwrap(), vec![carol.user_id()]);
        assert_eq!(store.queued(&carol.user_id()).unwrap().len(), 2);
        assert_eq!(store.stats().unwrap().messages, 2);
        // Removing again is a harmless no-op.
        assert_eq!(
            store.remove_user(&bob.user_id()).unwrap(),
            Removed::default()
        );
    }

    #[test]
    fn lifecycle_statements_round_trip_and_outlive_the_user() {
        let store = Store::in_memory().unwrap();
        let old = Identity::generate();
        let new = Identity::generate();
        assert!(!store.is_revoked(&old.user_id()).unwrap());
        assert!(store.revocation(&old.user_id()).unwrap().is_none());

        let revocation = old.revocation(1000);
        store.set_revocation(&revocation).unwrap();
        assert!(store.is_revoked(&old.user_id()).unwrap());
        assert_eq!(store.revocation(&old.user_id()).unwrap(), Some(revocation));

        let succession = old.succeed_to(&new, 2000);
        store.set_succession(&succession).unwrap();
        assert_eq!(
            store.succession(&old.user_id()).unwrap(),
            Some(succession.clone())
        );
        // Keyed by the old identity; the successor is not "the one who moved".
        assert!(store.succession(&new.user_id()).unwrap().is_none());

        // A revocation is permanent: removing the user does not lift it, so a
        // revoked key can never be re-registered.
        store.remove_user(&old.user_id()).unwrap();
        assert!(store.is_revoked(&old.user_id()).unwrap());
        assert_eq!(store.succession(&old.user_id()).unwrap(), Some(succession));
    }

    #[test]
    fn the_log_records_each_change_once_and_pages_in_order() {
        use silver_protocol::transparency::{EntryKind, LogHead};
        let store = Store::in_memory().unwrap();
        assert_eq!(store.log_head().unwrap(), LogHead::EMPTY);
        let alice = Identity::generate();
        let bundle = |prekey_id| {
            alice.key_bundle_with(silver_protocol::Prekeys::classical(
                silver_protocol::PrekeySecret::generate(prekey_id, 0).signed_by(&alice),
                Vec::new(),
            ))
        };
        let b1 = bundle(1);
        store.put_bundle(&b1).unwrap();
        store.put_bundle(&b1).unwrap(); // the same again: nothing new to log
        assert_eq!(store.log_head().unwrap().index, 1);
        let b2 = bundle(2);
        store.put_bundle(&b2).unwrap();
        assert_eq!(store.log_head().unwrap().index, 2);
        let latest = store.log_latest(&alice.user_id()).unwrap().unwrap();
        assert_eq!(latest.index, 2);
        assert_eq!(latest.leaf, b2.transparency_leaf());
        assert!(
            store
                .log_latest(&Identity::generate().user_id())
                .unwrap()
                .is_none()
        );

        // Statements are logged too, and do not count as a bundle change.
        store.set_revocation(&alice.revocation(5)).unwrap();
        assert_eq!(store.log_head().unwrap().index, 3);
        assert_eq!(
            store.log_latest(&alice.user_id()).unwrap().unwrap().index,
            3
        );
        store.put_bundle(&b2).unwrap();
        assert_eq!(store.log_head().unwrap().index, 3);

        // Pages chain, in order.
        let page = store.log_since(0, 2).unwrap();
        assert_eq!(page.len(), 2);
        assert!(page[0].follows(&LogHead::EMPTY));
        assert!(page[1].follows(&page[0].head()));
        assert_eq!(page[0].kind, EntryKind::Bundle);
        let rest = store.log_since(2, 10).unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].kind, EntryKind::Revocation);
        assert_eq!(rest[0].head(), store.log_head().unwrap());
        assert!(store.log_since(3, 10).unwrap().is_empty());

        // Append-only: removing the user removes nothing from it.
        store.remove_user(&alice.user_id()).unwrap();
        assert_eq!(store.log_head().unwrap().index, 3);
        assert_eq!(store.log_len().unwrap(), 3);
    }

    #[test]
    fn an_older_database_gets_its_log_seeded_on_opening() {
        use silver_protocol::transparency::EntryKind;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.redb");
        let alice = Identity::generate();
        let bob = Identity::generate();
        let successor = Identity::generate();
        {
            let store = Store::open(&path).unwrap();
            store.put_bundle(&alice.key_bundle()).unwrap();
            store.put_bundle(&bob.key_bundle()).unwrap();
            store
                .set_succession(&bob.succeed_to(&successor, 1))
                .unwrap();
            // As a relay before the log left it: no log tables, schema 1.
            let txn = store.db.begin_write().unwrap();
            txn.delete_table(LOG).unwrap();
            txn.delete_table(LOG_LATEST).unwrap();
            txn.commit().unwrap();
            store.stamp_schema(Some(1)).unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(
            store.log_head().unwrap().index,
            3,
            "two bundles, one succession"
        );
        let entries = store.log_since(0, 10).unwrap();
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.kind == EntryKind::Bundle)
                .count(),
            2
        );
        assert_eq!(entries[2].kind, EntryKind::Succession);
        assert_eq!(
            store.log_latest(&alice.user_id()).unwrap().unwrap().leaf,
            alice.key_bundle().transparency_leaf()
        );
        // Republishing an unchanged bundle after seeding adds nothing.
        store.put_bundle(&alice.key_bundle()).unwrap();
        assert_eq!(store.log_head().unwrap().index, 3);
    }

    #[test]
    fn a_new_database_is_stamped_and_an_unstamped_one_is_brought_along() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.redb");
        let bob = Identity::generate();
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
            store.put_bundle(&bob.key_bundle()).unwrap();
            // As 0.6.0 left it: tables, data, no version.
            store.stamp_schema(None).unwrap();
            assert_eq!(store.schema_version().unwrap(), 0);
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(store.bundle(&bob.user_id()).unwrap().is_some());
        assert!(Store::in_memory().unwrap().schema_version().unwrap() == SCHEMA_VERSION);
    }

    #[test]
    fn a_database_from_a_newer_relay_is_refused_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.redb");
        let bob = Identity::generate();
        {
            let store = Store::open(&path).unwrap();
            store.put_bundle(&bob.key_bundle()).unwrap();
            store.stamp_schema(Some(SCHEMA_VERSION + 1)).unwrap();
        }
        let err = Store::open(&path).err().expect("refused");
        assert_eq!(
            err.downcast_ref::<SchemaTooNew>(),
            Some(&SchemaTooNew {
                found: SCHEMA_VERSION + 1,
                supported: SCHEMA_VERSION
            })
        );
        assert!(err.to_string().contains("newer"), "{err}");
        // Still as the newer relay left it, for that relay to open.
        let db = Database::open(&path).unwrap();
        let txn = db.begin_read().unwrap();
        let version = txn
            .open_table(META)
            .unwrap()
            .get(SCHEMA)
            .unwrap()
            .map(|g| g.value());
        assert_eq!(version, Some(SCHEMA_VERSION + 1));
    }

    #[test]
    fn bans_and_settings_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.redb");
        {
            let store = Store::open(&path).unwrap();
            store
                .set_ban(
                    "address:203.0.113.9",
                    &Ban {
                        since_ms: 5,
                        note: "flood".into(),
                    },
                )
                .unwrap();
            store.set_ban("identity:abc", &Ban::default()).unwrap();
            assert!(store.remove_ban("identity:abc").unwrap());
            assert!(!store.remove_ban("identity:abc").unwrap());
            store
                .set_admin_setting("invite_token", Some("new-token"))
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.bans().unwrap(),
            vec![(
                "address:203.0.113.9".to_owned(),
                Ban {
                    since_ms: 5,
                    note: "flood".into()
                }
            )]
        );
        assert_eq!(
            store.admin_setting("invite_token").unwrap().as_deref(),
            Some("new-token")
        );
        store.set_admin_setting("invite_token", None).unwrap();
        assert_eq!(store.admin_setting("invite_token").unwrap(), None);
    }

    #[test]
    fn one_time_ml_kem_keys_are_handed_out_once_signature_and_all() {
        let store = Store::in_memory().unwrap();
        let bob = Identity::generate();
        let me = bob.user_id();
        let keys: Vec<_> = (1..=3)
            .map(|i| PqPrekeySecret::generate(i, 0).signed_by(&bob))
            .collect();
        store.set_pq_one_time_prekeys(&me, &keys).unwrap();
        assert_eq!(store.pq_one_time_status(&me).unwrap(), (3, vec![]));
        // The classical deposit is a different one.
        assert_eq!(store.one_time_status(&me).unwrap(), (0, vec![]));

        let first = store.take_pq_one_time_prekey(&me).unwrap().unwrap();
        assert_eq!(first, keys[0]);
        assert!(first.verify(&me).is_ok());
        assert_eq!(store.pq_one_time_status(&me).unwrap(), (2, vec![1]));
        // Relisting the handed-out key does not bring it back; dropping it
        // from the list is the client acknowledging the handout.
        store.set_pq_one_time_prekeys(&me, &keys).unwrap();
        assert_eq!(store.pq_one_time_status(&me).unwrap(), (2, vec![1]));
        store.set_pq_one_time_prekeys(&me, &keys[1..]).unwrap();
        assert_eq!(store.pq_one_time_status(&me).unwrap(), (2, vec![]));
        assert_eq!(store.take_pq_one_time_prekey(&me).unwrap().unwrap().id, 2);
        assert_eq!(store.take_pq_one_time_prekey(&me).unwrap().unwrap().id, 3);
        assert!(store.take_pq_one_time_prekey(&me).unwrap().is_none());
        // A client that stops publishing ML-KEM keys leaves none behind.
        store.set_pq_one_time_prekeys(&me, &keys).unwrap();
        store.set_pq_one_time_prekeys(&me, &[]).unwrap();
        assert_eq!(store.pq_one_time_status(&me).unwrap(), (0, vec![]));
    }

    fn envelope(from: &Identity, to: &Identity, text: &str) -> Envelope {
        seal(from, &to.key_bundle(), Content::text(text), 0).unwrap()
    }

    #[test]
    fn bundles_round_trip() {
        let store = Store::in_memory().unwrap();
        let id = Identity::generate();
        assert!(store.bundle(&id.user_id()).unwrap().is_none());
        store.put_bundle(&id.key_bundle()).unwrap();
        assert_eq!(store.bundle(&id.user_id()).unwrap(), Some(id.key_bundle()));
        assert_eq!(store.stats().unwrap().bundles, 1);
    }

    #[test]
    fn one_time_prekeys_are_handed_out_once_and_reconciled() {
        use silver_protocol::PrekeySecret;
        let store = Store::in_memory().unwrap();
        let bob = Identity::generate();
        let keys: Vec<OneTimePrekey> = (1..=3)
            .map(|i| PrekeySecret::generate(i, 0).one_time())
            .collect();
        store.set_one_time_prekeys(&bob.user_id(), &keys).unwrap();
        assert_eq!(store.one_time_status(&bob.user_id()).unwrap(), (3, vec![]));

        // Handed out in id order, each exactly once.
        let first = store.take_one_time_prekey(&bob.user_id()).unwrap().unwrap();
        assert_eq!(first, keys[0]);
        assert_eq!(store.one_time_status(&bob.user_id()).unwrap(), (2, vec![1]));

        // Bob republishes the same list (he does not know yet): id 1 is not
        // stored again, a new id 4 is.
        let mut relisted = keys.clone();
        relisted.push(PrekeySecret::generate(4, 0).one_time());
        store
            .set_one_time_prekeys(&bob.user_id(), &relisted)
            .unwrap();
        assert_eq!(store.one_time_status(&bob.user_id()).unwrap(), (3, vec![1]));

        // Once Bob drops id 1 and 2 from his list, both are forgotten.
        store
            .set_one_time_prekeys(&bob.user_id(), &relisted[2..])
            .unwrap();
        assert_eq!(store.one_time_status(&bob.user_id()).unwrap(), (2, vec![]));
        assert_eq!(
            store
                .take_one_time_prekey(&bob.user_id())
                .unwrap()
                .unwrap()
                .id,
            3
        );
        assert_eq!(
            store
                .take_one_time_prekey(&bob.user_id())
                .unwrap()
                .unwrap()
                .id,
            4
        );
        assert!(
            store
                .take_one_time_prekey(&bob.user_id())
                .unwrap()
                .is_none()
        );
        // Other users are untouched.
        assert!(
            store
                .take_one_time_prekey(&Identity::generate().user_id())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn blob_chunks_are_stored_once_capped_and_expired() {
        let store = Store::in_memory().unwrap();
        let limits = BlobLimits {
            max_blob_bytes: 10,
            max_total_bytes: 15,
        };
        let id = "a".repeat(32);
        assert_eq!(
            store
                .put_blob_chunk(&id, 0, 2, b"12345", 1, limits)
                .unwrap(),
            BlobPut::Stored { complete: false }
        );
        assert_eq!(
            store
                .put_blob_chunk(&id, 0, 2, b"12345", 1, limits)
                .unwrap(),
            BlobPut::Duplicate
        );
        assert_eq!(
            store.put_blob_chunk(&id, 1, 3, b"1", 1, limits).unwrap(),
            BlobPut::Mismatch
        );
        assert_eq!(
            store.put_blob_chunk(&id, 2, 2, b"1", 1, limits).unwrap(),
            BlobPut::Mismatch
        );
        assert_eq!(
            store
                .put_blob_chunk(&id, 1, 2, b"123456", 1, limits)
                .unwrap(),
            BlobPut::TooLarge
        );
        assert_eq!(
            store
                .put_blob_chunk(&id, 1, 2, b"12345", 1, limits)
                .unwrap(),
            BlobPut::Stored { complete: true }
        );
        let meta = store.blob_meta(&id).unwrap().unwrap();
        assert!(meta.is_complete() && meta.bytes == 10);
        assert_eq!(store.blob_chunk(&id, 1).unwrap().unwrap(), b"12345");
        assert!(store.blob_chunk(&id, 2).unwrap().is_none());
        // The relay-wide cap counts every blob.
        let other = "b".repeat(32);
        assert_eq!(
            store
                .put_blob_chunk(&other, 0, 1, b"123456", 2, limits)
                .unwrap(),
            BlobPut::StorageFull
        );
        assert_eq!(
            store
                .put_blob_chunk(&other, 0, 1, b"12345", 2, limits)
                .unwrap(),
            BlobPut::Stored { complete: true }
        );
        let stats = store.stats().unwrap();
        assert_eq!((stats.blobs, stats.blob_bytes), (2, 15));
        // Expiry frees the space.
        assert_eq!(store.expire_blobs(2).unwrap(), 1);
        assert!(store.blob_meta(&id).unwrap().is_none());
        assert!(store.blob_chunk(&id, 0).unwrap().is_none());
        assert_eq!(store.stats().unwrap().blob_bytes, 5);
    }

    #[test]
    fn mailbox_keeps_order_and_acks_by_id() {
        let store = Store::in_memory().unwrap();
        let (alice, bob, carol) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let first = envelope(&alice, &bob, "first");
        let second = envelope(&alice, &bob, "second");
        assert_eq!(
            store.enqueue(&first, 1, Limits::default()).unwrap(),
            Enqueue::Stored
        );
        assert_eq!(
            store.enqueue(&second, 2, Limits::default()).unwrap(),
            Enqueue::Stored
        );
        assert_eq!(
            store.enqueue(&first, 3, Limits::default()).unwrap(),
            Enqueue::Duplicate
        );

        let queued = store.queued(&bob.user_id()).unwrap();
        assert_eq!(queued, vec![first.clone(), second.clone()]);
        assert_eq!(store.queued_count(&bob.user_id()).unwrap(), 2);
        assert!(store.queued(&carol.user_id()).unwrap().is_empty());

        // Only the owner can acknowledge, and only once.
        assert!(!store.ack(&carol.user_id(), &first.id).unwrap());
        assert!(store.ack(&bob.user_id(), &first.id).unwrap());
        assert!(!store.ack(&bob.user_id(), &first.id).unwrap());
        assert_eq!(store.queued(&bob.user_id()).unwrap(), vec![second.clone()]);
        assert!(store.ack(&bob.user_id(), &second.id).unwrap());
        assert_eq!(store.stats().unwrap(), Stats::default());
    }

    #[test]
    fn limits_are_enforced() {
        let store = Store::in_memory().unwrap();
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let two = Limits {
            max_messages: 2,
            max_bytes: u64::MAX,
        };
        assert_eq!(
            store.enqueue(&envelope(&alice, &bob, "a"), 0, two).unwrap(),
            Enqueue::Stored
        );
        assert_eq!(
            store.enqueue(&envelope(&alice, &bob, "b"), 0, two).unwrap(),
            Enqueue::Stored
        );
        assert_eq!(
            store.enqueue(&envelope(&alice, &bob, "c"), 0, two).unwrap(),
            Enqueue::MailboxFull
        );

        let tiny = Limits {
            max_messages: u64::MAX,
            max_bytes: 10,
        };
        let store = Store::in_memory().unwrap();
        assert_eq!(
            store
                .enqueue(&envelope(&alice, &bob, "a"), 0, tiny)
                .unwrap(),
            Enqueue::MailboxFull
        );
    }

    #[test]
    fn expiry_removes_old_entries_only() {
        let store = Store::in_memory().unwrap();
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let old = envelope(&alice, &bob, "old");
        let fresh = envelope(&alice, &bob, "fresh");
        store.enqueue(&old, 100, Limits::default()).unwrap();
        store.enqueue(&fresh, 200, Limits::default()).unwrap();
        assert_eq!(store.expire(150).unwrap(), 1);
        assert_eq!(store.queued(&bob.user_id()).unwrap(), vec![fresh.clone()]);
        assert_eq!(store.stats().unwrap().messages, 1);
        // The expired id is forgotten, so a resend is stored again.
        assert_eq!(
            store.enqueue(&old, 300, Limits::default()).unwrap(),
            Enqueue::Stored
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_database_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("relay.redb");
        let _store = Store::open(&path).unwrap();
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!((dir_mode, file_mode), (0o700, 0o600));
    }

    #[test]
    fn data_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.redb");
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let env = envelope(&alice, &bob, "persist me");
        {
            let store = Store::open(&path).unwrap();
            store.put_bundle(&bob.key_bundle()).unwrap();
            store.enqueue(&env, 1, Limits::default()).unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.bundle(&bob.user_id()).unwrap(),
            Some(bob.key_bundle())
        );
        assert_eq!(store.queued(&bob.user_id()).unwrap(), vec![env]);
    }
}
