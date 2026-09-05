//! Key transparency, small edition (`docs/PROTOCOL.md` section 11).
//!
//! The relay keeps an append-only, hash-chained log with one entry per
//! change it serves: a bundle that differs from the identity's last logged
//! one, a revocation, a succession. Clients tail the log, check that what a
//! lookup showed them is what the log says, and carry the log head inside
//! their encrypted messages, so two contacts compare the relay's story to
//! each of them without reading numbers aloud. A relay that shows one
//! person a stale bundle, hides a statement from them, or keeps two
//! versions of its log is caught by the next message between two people
//! it treated differently.
//!
//! This module holds what relay and client must agree on: the hash of an
//! entry, the hash of a bundle or statement (its *leaf*), and the hashed
//! *subject* an entry is filed under. The log itself lives on the relay and
//! the checking on the client.
//!
//! The user id is the identity key and every bundle field is signed by it,
//! so a relay cannot substitute an identity or a key; what the log catches
//! is freshness and equivocation, which signatures alone cannot.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bundle::KeyBundle;
use crate::encoding::b64_array;
use crate::identity::UserId;
use crate::lifecycle::{Revocation, Succession};

/// Domain of the hash an entry is filed under.
pub const SUBJECT_DOMAIN: &[u8] = b"silver-messenger/v4/transparency-subject";
/// Domain of an entry's hash.
pub const ENTRY_DOMAIN: &[u8] = b"silver-messenger/v4/transparency-entry";
/// Domain of a bundle's leaf.
pub const BUNDLE_LEAF_DOMAIN: &[u8] = b"silver-messenger/v4/transparency-bundle";
/// Domain of a revocation's leaf.
pub const REVOCATION_LEAF_DOMAIN: &[u8] = b"silver-messenger/v4/transparency-revocation";
/// Domain of a succession's leaf.
pub const SUCCESSION_LEAF_DOMAIN: &[u8] = b"silver-messenger/v4/transparency-succession";

/// Most entries a relay hands out per `LogSince`.
pub const LOG_PAGE: usize = 256;

/// A SHA-256 output.
pub type Hash = [u8; 32];

/// Where a log stands: how many entries it has and the hash of the last.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogHead {
    /// The number of entries; the last entry's index.
    pub index: u64,
    #[serde(with = "b64_array")]
    pub hash: Hash,
}

impl LogHead {
    /// The head of an empty log: no entries, an all-zero hash.
    pub const EMPTY: LogHead = LogHead {
        index: 0,
        hash: [0; 32],
    };
}

impl Default for LogHead {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// What an entry records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// The identity published a bundle whose leaf differs from its last.
    Bundle,
    /// The identity was revoked.
    Revocation,
    /// The identity handed over to a successor.
    Succession,
}

impl EntryKind {
    fn byte(self) -> u8 {
        match self {
            Self::Bundle => 1,
            Self::Revocation => 2,
            Self::Succession => 3,
        }
    }
}

/// One entry of the log. Its hash covers everything in it and the hash of
/// the entry before, so the head commits to the whole log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// 1 for the first entry.
    pub index: u64,
    /// The hash of the entry before, or [`LogHead::EMPTY`]'s for the first.
    #[serde(with = "b64_array")]
    pub prev: Hash,
    /// [`subject`] of the identity the entry is about.
    #[serde(with = "b64_array")]
    pub subject: Hash,
    pub kind: EntryKind,
    /// The leaf of the bundle or statement.
    #[serde(with = "b64_array")]
    pub leaf: Hash,
    pub at_ms: u64,
}

impl LogEntry {
    /// The entry that follows `head`.
    pub fn after(head: &LogHead, subject: Hash, kind: EntryKind, leaf: Hash, at_ms: u64) -> Self {
        Self {
            index: head.index + 1,
            prev: head.hash,
            subject,
            kind,
            leaf,
            at_ms,
        }
    }

    /// `SHA-256(domain || prev || index || subject || kind || leaf || at_ms)`,
    /// integers big-endian.
    pub fn hash(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(ENTRY_DOMAIN);
        h.update(self.prev);
        h.update(self.index.to_be_bytes());
        h.update(self.subject);
        h.update([self.kind.byte()]);
        h.update(self.leaf);
        h.update(self.at_ms.to_be_bytes());
        h.finalize().into()
    }

    /// The head of a log whose last entry this is.
    pub fn head(&self) -> LogHead {
        LogHead {
            index: self.index,
            hash: self.hash(),
        }
    }

    /// Whether this entry is the one right after `head`.
    pub fn follows(&self, head: &LogHead) -> bool {
        self.index == head.index.wrapping_add(1) && self.prev == head.hash
    }
}

/// Where an identity last appears in the log: the entry's index and leaf.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogPosition {
    pub index: u64,
    #[serde(with = "b64_array")]
    pub leaf: Hash,
}

/// The hash an identity's entries are filed under. Ids are 32 random
/// bytes, so a reader of the log learns nothing about whom an entry
/// concerns unless it already knows the id; a contact computes the subject
/// of the ids it has pinned and finds their entries.
pub fn subject(user: &UserId) -> Hash {
    let mut h = Sha256::new();
    h.update(SUBJECT_DOMAIN);
    h.update(user.as_bytes());
    h.finalize().into()
}

fn put_var(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u32).to_be_bytes());
    h.update(bytes);
}

impl KeyBundle {
    /// The bundle's leaf: a hash over everything in it that its owner
    /// signed, in a fixed byte layout, so relay and client compute the
    /// same value whatever version serialised the bundle. One-time prekeys
    /// are not in it: they change with every lookup and are not part of
    /// the stored bundle.
    pub fn transparency_leaf(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(BUNDLE_LEAF_DOMAIN);
        h.update(self.user_id.as_bytes());
        h.update(self.dh_public.0);
        h.update(self.signature);
        match &self.prekeys {
            None => h.update([0u8]),
            Some(prekeys) => {
                h.update([1u8]);
                h.update(prekeys.signed.id.to_be_bytes());
                h.update(prekeys.signed.public.0);
                h.update(prekeys.signed.created_at_ms.to_be_bytes());
                h.update(prekeys.signed.signature);
                match &prekeys.pq_signed {
                    None => h.update([0u8]),
                    Some(pq) => {
                        h.update([1u8]);
                        h.update(pq.id.to_be_bytes());
                        put_var(&mut h, &pq.public.0);
                        h.update(pq.created_at_ms.to_be_bytes());
                        h.update(pq.signature);
                    }
                }
            }
        }
        h.update((self.caps.len() as u32).to_be_bytes());
        for cap in &self.caps {
            put_var(&mut h, cap.as_bytes());
        }
        match &self.caps_signature {
            None => h.update([0u8]),
            Some(signature) => {
                h.update([1u8]);
                h.update(signature);
            }
        }
        h.finalize().into()
    }
}

impl Revocation {
    /// The statement's leaf.
    pub fn transparency_leaf(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(REVOCATION_LEAF_DOMAIN);
        h.update(self.identity.as_bytes());
        h.update(self.created_at_ms.to_be_bytes());
        h.update(self.signature);
        h.finalize().into()
    }
}

impl Succession {
    /// The statement's leaf.
    pub fn transparency_leaf(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(SUCCESSION_LEAF_DOMAIN);
        h.update(self.old.as_bytes());
        h.update(self.new.as_bytes());
        h.update(self.created_at_ms.to_be_bytes());
        h.update(self.old_signature);
        h.update(self.new_signature);
        h.finalize().into()
    }
}

/// Replay `entries` from `head`, checking each continues the last, and
/// return the head they end at. Fails on a gap, a wrong `prev`, or a
/// `head` the entries do not reach when `expected` is given.
pub fn replay(
    head: &LogHead,
    entries: &[LogEntry],
    expected: Option<&LogHead>,
) -> Result<LogHead, ReplayError> {
    let mut at = *head;
    for entry in entries {
        if !entry.follows(&at) {
            return Err(ReplayError::Broken {
                at: at.index,
                found: entry.index,
            });
        }
        at = entry.head();
    }
    if let Some(expected) = expected
        && at.index == expected.index
        && at.hash != expected.hash
    {
        return Err(ReplayError::Fork { at: at.index });
    }
    Ok(at)
}

/// Why a page of entries could not be replayed onto a head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// The entries do not continue the head: a gap, or a `prev` that is
    /// not the hash before it.
    #[error("log entries do not continue the chain at {at} (got {found})")]
    Broken { at: u64, found: u64 },
    /// The entries reach the expected index with a different hash: two
    /// versions of the log exist.
    #[error("the log forks at entry {at}")]
    Fork { at: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::prekey::{PrekeySecret, Prekeys};

    fn chain(n: u64) -> (Vec<LogEntry>, LogHead) {
        let mut head = LogHead::EMPTY;
        let mut entries = Vec::new();
        for i in 1..=n {
            let entry = LogEntry::after(
                &head,
                subject(&Identity::generate().user_id()),
                EntryKind::Bundle,
                [i as u8; 32],
                i * 10,
            );
            head = entry.head();
            entries.push(entry);
        }
        (entries, head)
    }

    #[test]
    fn the_leaf_covers_what_is_signed_and_ignores_one_time_keys() {
        let alice = Identity::generate();
        let signed = PrekeySecret::generate(1, 5).signed_by(&alice);
        let with_two = alice.key_bundle_with(Prekeys::classical(
            signed.clone(),
            vec![
                PrekeySecret::generate(2, 0).one_time(),
                PrekeySecret::generate(3, 0).one_time(),
            ],
        ));
        let with_none = alice.key_bundle_with(Prekeys::classical(signed.clone(), Vec::new()));
        assert_eq!(with_two.transparency_leaf(), with_none.transparency_leaf());
        assert_eq!(
            with_two.without_prekeys().transparency_leaf(),
            alice.key_bundle().transparency_leaf()
        );
        // Serialising and parsing changes nothing.
        let parsed: KeyBundle =
            serde_json::from_str(&serde_json::to_string(&with_two).unwrap()).unwrap();
        assert_eq!(parsed.transparency_leaf(), with_two.transparency_leaf());

        // A rotated signed prekey, a capability, or no prekeys at all each
        // give a different leaf.
        let rotated = alice.key_bundle_with(Prekeys::classical(
            PrekeySecret::generate(9, 6).signed_by(&alice),
            Vec::new(),
        ));
        assert_ne!(rotated.transparency_leaf(), with_none.transparency_leaf());
        let capable = with_none
            .clone()
            .with_caps(&alice, vec!["pq_ratchet".into()]);
        assert_ne!(capable.transparency_leaf(), with_none.transparency_leaf());
        assert_ne!(
            alice.key_bundle().transparency_leaf(),
            with_none.transparency_leaf()
        );
        // And another identity's bundle is another leaf.
        assert_ne!(
            Identity::generate().key_bundle().transparency_leaf(),
            alice.key_bundle().transparency_leaf()
        );
    }

    #[test]
    fn statement_leaves_and_subjects_are_distinct_and_stable() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_eq!(subject(&a.user_id()), subject(&a.user_id()));
        assert_ne!(subject(&a.user_id()), subject(&b.user_id()));
        assert_ne!(subject(&a.user_id()), *a.user_id().as_bytes());

        let r1 = a.revocation(1).transparency_leaf();
        let r2 = a.revocation(2).transparency_leaf();
        assert_ne!(r1, r2);
        let s = a.succeed_to(&b, 1).transparency_leaf();
        assert_ne!(s, r1);
        assert_ne!(s, b.succeed_to(&a, 1).transparency_leaf());
    }

    #[test]
    fn the_chain_commits_to_every_entry() {
        let (entries, head) = chain(4);
        assert_eq!(head.index, 4);
        assert!(entries[0].follows(&LogHead::EMPTY));
        assert!(entries[1].follows(&entries[0].head()));
        assert!(!entries[2].follows(&entries[0].head()));
        assert_eq!(replay(&LogHead::EMPTY, &entries, Some(&head)), Ok(head));
        assert_eq!(replay(&entries[1].head(), &entries[2..], None), Ok(head));

        // Changing anything in an earlier entry changes the head.
        let mut altered = entries.clone();
        altered[1].leaf[0] ^= 1;
        assert_ne!(altered[1].hash(), entries[1].hash());
        assert_eq!(
            replay(&LogHead::EMPTY, &altered, None),
            Err(ReplayError::Broken { at: 2, found: 3 })
        );
        // A page with a gap does not replay.
        assert_eq!(
            replay(&LogHead::EMPTY, &entries[1..], None),
            Err(ReplayError::Broken { at: 0, found: 2 })
        );
        // A different log of the same length is a fork.
        let (other, other_head) = chain(4);
        assert_ne!(other_head, head);
        assert_eq!(
            replay(&LogHead::EMPTY, &other, Some(&head)),
            Err(ReplayError::Fork { at: 4 })
        );
        // Not reaching the expected head is not a fork.
        assert_eq!(
            replay(&LogHead::EMPTY, &entries[..2], Some(&head)),
            Ok(entries[1].head())
        );
    }

    #[test]
    fn entries_and_heads_round_trip_as_json() {
        let (entries, head) = chain(2);
        let text = serde_json::to_string(&entries[1]).unwrap();
        assert!(text.contains("\"kind\":\"bundle\""));
        let back: LogEntry = serde_json::from_str(&text).unwrap();
        assert_eq!(back, entries[1]);
        assert_eq!(back.hash(), head.hash);
        let head_back: LogHead =
            serde_json::from_str(&serde_json::to_string(&head).unwrap()).unwrap();
        assert_eq!(head_back, head);
        assert_eq!(LogHead::default(), LogHead::EMPTY);
    }
}
