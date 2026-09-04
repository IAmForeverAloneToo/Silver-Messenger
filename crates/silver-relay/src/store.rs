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
use silver_protocol::{DhPublic, Envelope, KeyBundle, UserId};

/// `owner -> bundle JSON` (the signed prekey included, one-time keys not).
const BUNDLES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bundles");
/// `(owner, prekey id) -> public key` for one-time prekeys not yet handed out.
const ONE_TIME: TableDefinition<(&[u8], u32), &[u8]> = TableDefinition::new("one_time_prekeys");
/// `(owner, prekey id)` for one-time prekeys handed out that the owner may
/// still list on its next publish; forgotten once the owner stops listing them.
const ONE_TIME_USED: TableDefinition<(&[u8], u32), ()> = TableDefinition::new("one_time_used");
/// `(recipient, sequence) -> stored entry`; the sequence gives delivery order.
const MAILBOX: TableDefinition<(&[u8], u64), &[u8]> = TableDefinition::new("mailbox");
/// `envelope id -> (recipient, sequence)` so acknowledgements are O(log n).
const BY_ID: TableDefinition<&str, (&[u8], u64)> = TableDefinition::new("by_id");
/// `recipient -> (message count, total bytes)` for quota checks.
const USAGE: TableDefinition<&[u8], (u64, u64)> = TableDefinition::new("usage");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const NEXT_SEQ: &str = "next_seq";
/// `blob id -> BlobMeta JSON` for encrypted file chunks on deposit.
const BLOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");
/// `(blob id, chunk index) -> ciphertext`.
const BLOB_CHUNKS: TableDefinition<(&str, u32), &[u8]> = TableDefinition::new("blob_chunks");
/// Bytes of chunks stored in total, for the storage cap.
const BLOB_BYTES: &str = "blob_bytes";

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

/// Aggregate numbers for logs and health output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    db: Database,
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

    fn init(db: Database) -> anyhow::Result<Self> {
        let txn = db.begin_write()?;
        {
            txn.open_table(BUNDLES)?;
            txn.open_table(ONE_TIME)?;
            txn.open_table(ONE_TIME_USED)?;
            txn.open_table(MAILBOX)?;
            txn.open_table(BY_ID)?;
            txn.open_table(USAGE)?;
            txn.open_table(META)?;
            txn.open_table(BLOBS)?;
            txn.open_table(BLOB_CHUNKS)?;
        }
        txn.commit()?;
        Ok(Self { db })
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
        let user = user.as_bytes().as_slice();
        let listed: HashSet<u32> = keys.iter().map(|k| k.id).collect();
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ONE_TIME)?;
            let mut used = txn.open_table(ONE_TIME_USED)?;
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
            for key in keys {
                if used.get((user, key.id))?.is_some() || table.get((user, key.id))?.is_some() {
                    continue;
                }
                table.insert((user, key.id), key.public.0.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Hand out one of `user`'s one-time prekeys, never to be handed out
    /// again. `None` when there are none left.
    pub fn take_one_time_prekey(&self, user: &UserId) -> anyhow::Result<Option<OneTimePrekey>> {
        let user = user.as_bytes().as_slice();
        let txn = self.db.begin_write()?;
        let taken = {
            let mut table = txn.open_table(ONE_TIME)?;
            let first = table
                .range((user, 0u32)..=(user, u32::MAX))?
                .next()
                .transpose()?
                .map(|(key, value)| (key.value().1, value.value().to_vec()));
            match first {
                Some((id, public)) => {
                    table.remove((user, id))?;
                    txn.open_table(ONE_TIME_USED)?.insert((user, id), ())?;
                    let bytes: [u8; 32] = public
                        .as_slice()
                        .try_into()
                        .context("stored one-time prekey has the wrong length")?;
                    Some(OneTimePrekey {
                        id,
                        public: DhPublic(bytes),
                    })
                }
                None => None,
            }
        };
        txn.commit()?;
        Ok(taken)
    }

    /// How many one-time prekeys `user` has left, and the ids handed out
    /// that the user has not dropped from its list yet.
    pub fn one_time_status(&self, user: &UserId) -> anyhow::Result<(u32, Vec<u32>)> {
        let user = user.as_bytes().as_slice();
        let txn = self.db.begin_read()?;
        let mut remaining = 0u32;
        for item in txn
            .open_table(ONE_TIME)?
            .range((user, 0u32)..=(user, u32::MAX))?
        {
            item?;
            remaining += 1;
        }
        let mut used = Vec::new();
        for item in txn
            .open_table(ONE_TIME_USED)?
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
    use silver_protocol::{Content, Identity, seal};

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
