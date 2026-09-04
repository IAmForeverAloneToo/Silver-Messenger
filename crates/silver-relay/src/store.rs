//! Durable relay state: published key bundles and per-recipient mailboxes.
//!
//! Backed by an embedded [`redb`] database so an update or reboot loses
//! nothing. Every mailbox entry is `received_at_ms (8 bytes BE) || envelope
//! JSON`, kept until the recipient acknowledges it or it expires.

use std::path::Path;

use anyhow::Context;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use silver_protocol::{Envelope, KeyBundle, UserId};

const BUNDLES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bundles");
/// `(recipient, sequence) -> stored entry`; the sequence gives delivery order.
const MAILBOX: TableDefinition<(&[u8], u64), &[u8]> = TableDefinition::new("mailbox");
/// `envelope id -> (recipient, sequence)` so acknowledgements are O(log n).
const BY_ID: TableDefinition<&str, (&[u8], u64)> = TableDefinition::new("by_id");
/// `recipient -> (message count, total bytes)` for quota checks.
const USAGE: TableDefinition<&[u8], (u64, u64)> = TableDefinition::new("usage");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const NEXT_SEQ: &str = "next_seq";

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
}

pub struct Store {
    db: Database,
}

impl Store {
    /// Open (or create) the database file at `path`.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let db = Database::create(path).with_context(|| format!("opening {}", path.display()))?;
        Self::init(db)
    }

    /// A database that lives only in memory, for tests and `--ephemeral`.
    pub fn in_memory() -> anyhow::Result<Self> {
        let db = Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::init(db)
    }

    fn init(db: Database) -> anyhow::Result<Self> {
        let txn = db.begin_write()?;
        {
            txn.open_table(BUNDLES)?;
            txn.open_table(MAILBOX)?;
            txn.open_table(BY_ID)?;
            txn.open_table(USAGE)?;
            txn.open_table(META)?;
        }
        txn.commit()?;
        Ok(Self { db })
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
        let usage = txn.open_table(USAGE)?;
        let mut stats = Stats {
            bundles,
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
