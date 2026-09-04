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
use silver_protocol::prekey::OneTimePrekey;
use silver_protocol::{DhPublic, Envelope, KeyBundle, SignedPqPrekey, UserId};

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
/// `blob id -> BlobMeta JSON` for encrypted file chunks on deposit.
pub(crate) const BLOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");
/// `(blob id, chunk index) -> ciphertext`.
pub(crate) const BLOB_CHUNKS: TableDefinition<(&str, u32), &[u8]> =
    TableDefinition::new("blob_chunks");
/// Bytes of chunks stored in total, for the storage cap.
const BLOB_BYTES: &str = "blob_bytes";

/// The layout of the tables, stamped into the database. It moves when a
/// change needs more than opening a table that was not there before, with
/// a step in [`migrate`] to bring older databases along; a database
/// stamped with a higher version was written by a newer relay and is
/// refused rather than misread.
pub const SCHEMA_VERSION: u64 = 1;
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
pub(crate) fn migrate(_txn: &redb::WriteTransaction, from: u64) -> anyhow::Result<()> {
    match from {
        // 0 is the unstamped layout of 0.6.0 and before; 1 added the bans
        // and admin tables.
        0 => Ok(()),
        other => anyhow::bail!("no migration from schema version {other}"),
    }
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
            removed.had_bundle = txn.open_table(BUNDLES)?.remove(key)?.is_some();
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
        }
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

    pub fn put_bundle(&self, bundle: &KeyBundle) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(bundle)?;
        let txn = self.db.begin_write()?;
        txn.open_table(BUNDLES)?
            .insert(bundle.user_id.as_bytes().as_slice(), bytes.as_slice())?;
        txn.commit()?;
        Ok(())
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
        let mut stats = Stats {
            bundles,
            blobs,
            blob_bytes,
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
        seal(
            from,
            &to.key_bundle(),
            Content::Text { body: text.into() },
            0,
        )
        .unwrap()
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
