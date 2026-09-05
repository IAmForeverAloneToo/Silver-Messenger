//! Client side of key transparency (`docs/PROTOCOL.md` section 11).
//!
//! The relay keeps a hash-chained log of every bundle and lifecycle
//! statement it serves ([`silver_protocol::transparency`]). This client
//! *tails* it: it fetches the entries after the head it last verified,
//! replays the chain, and keeps the head, a set of checkpoints (the hash at
//! an index) and, per identity, where that identity last appears. With
//! that it checks two things:
//!
//! * a lookup: the bundle it was shown must be the identity's latest logged
//!   bundle, and a logged revocation or succession must not be missing from
//!   the answer;
//! * a contact's head, carried inside every encrypted message: it must lie
//!   on the chain this client replayed, so a relay that shows two people
//!   two different logs is caught by the next message between them.
//!
//! The state is a small file in the data directory, encrypted like the
//! outbox when the directory has a passphrase.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use silver_protocol::encoding::b64_array;
use silver_protocol::transparency::{
    EntryKind, Hash, LogEntry, LogHead, LogPosition, ReplayError, subject,
};
use silver_protocol::{KeyBundle, Revocation, Succession, UserId};
use tracing::warn;

use crate::vault::FileCipher;

/// The file name, bound into its encryption.
pub const LOG_NAME: &str = "transparency.json";

/// Every hash of the last this many entries is kept as a checkpoint...
pub(crate) const DENSE: u64 = 4096;
/// ...and every this many-th before that, so an old head a contact sends
/// can be checked by fetching the entries between the checkpoints on
/// either side of it.
pub(crate) const SPARSE: u64 = 256;

/// The hash the log had at an index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub index: u64,
    #[serde(with = "b64_array")]
    pub hash: Hash,
}

impl Checkpoint {
    fn head(&self) -> LogHead {
        LogHead {
            index: self.index,
            hash: self.hash,
        }
    }
}

/// Where an identity last appears in the log we replayed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Latest {
    /// Its latest entry of any kind.
    pub last: LogPosition,
    pub kind: Option<EntryKind>,
    /// Its latest bundle entry, which a later statement does not replace.
    pub bundle: Option<LogPosition>,
    /// Its latest revocation entry, if any: final.
    pub revocation: Option<LogPosition>,
    /// Its latest succession entry, if any.
    pub succession: Option<LogPosition>,
}

/// What this client knows about the relay's log.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogState {
    pub head: LogHead,
    /// Sorted by index.
    #[serde(default)]
    pub checkpoints: Vec<Checkpoint>,
    /// By subject (base64), for every identity that appears in the log.
    #[serde(default)]
    pub latest: HashMap<String, Latest>,
    /// When the head was last confirmed against the relay, in ms.
    #[serde(default)]
    pub verified_at_ms: u64,
}

/// Something a lookup showed that the log does not bear out.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Discrepancy {
    /// The relay served a bundle for an identity the log never records.
    #[error("the relay showed a key for them that its log does not contain")]
    UnloggedBundle,
    /// The relay served a bundle other than the identity's latest logged
    /// one: an old one, or one it never logged.
    #[error("the relay showed a key for them that is not the latest in its log (entry {logged})")]
    NotLatestBundle { logged: u64 },
    /// The relay's own claim of where the identity last appears does not
    /// match the log it showed us.
    #[error(
        "the relay's claim about its log (entry {claimed}) does not match the log it showed (entry {seen})"
    )]
    ClaimMismatch { claimed: u64, seen: u64 },
    /// The log records a revocation the relay left out of the answer.
    #[error("the relay is hiding a revocation of their identity (log entry {logged})")]
    WithheldRevocation { logged: u64 },
    /// The log records a succession the relay left out of the answer.
    #[error("the relay is hiding a handover of their identity (log entry {logged})")]
    WithheldSuccession { logged: u64 },
    /// The relay served a statement other than the logged one.
    #[error("the relay showed a statement about them that is not the one in its log")]
    UnloggedStatement,
}

/// How a contact's head compares with the chain we replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadCheck {
    /// It is on our chain.
    Consistent,
    /// Same index, different hash: two logs.
    Fork { at: u64 },
    /// Below our head but not at a checkpoint we hold: fetch the entries
    /// after `from` and replay them through the head's index up to
    /// `until`, the next checkpoint we hold. The segment must reach
    /// `until`'s hash, or the relay handed back a doctored one; only then
    /// does the hash it gives at the head's index mean anything.
    NeedEntries { from: LogHead, until: LogHead },
    /// Beyond our head: tail to it and compare.
    Ahead,
}

/// The log as this client has replayed it, with its file.
pub struct LogStore {
    state: LogState,
    path: Option<PathBuf>,
    cipher: Option<Arc<FileCipher>>,
}

/// The store shared between the client task and the front end.
pub type SharedLog = Arc<Mutex<LogStore>>;

impl LogStore {
    /// Load from `path` (a missing file is an empty log). Without a path
    /// the state lives in memory only.
    pub fn load(path: Option<PathBuf>, cipher: Option<Arc<FileCipher>>) -> anyhow::Result<Self> {
        let state = match &path {
            Some(p) if p.exists() => read(p, cipher.as_deref())?,
            _ => LogState::default(),
        };
        Ok(Self {
            state,
            path,
            cipher,
        })
    }

    /// In memory only.
    pub fn ephemeral() -> Self {
        Self {
            state: LogState::default(),
            path: None,
            cipher: None,
        }
    }

    pub fn shared(self) -> SharedLog {
        Arc::new(Mutex::new(self))
    }

    pub fn head(&self) -> LogHead {
        self.state.head
    }

    pub fn verified_at_ms(&self) -> u64 {
        self.state.verified_at_ms
    }

    /// Where `user` last appears in the log we replayed.
    pub fn latest(&self, user: &UserId) -> Option<Latest> {
        self.state.latest.get(&key(&subject(user))).copied()
    }

    /// Replay `entries` onto our head, keep what they say, and return the
    /// new head. Nothing changes on an error.
    pub fn apply(&mut self, entries: &[LogEntry], now_ms: u64) -> Result<LogHead, ReplayError> {
        // Check the whole page first, so a bad page leaves the state as it
        // was.
        let mut at = self.state.head;
        for entry in entries {
            if !entry.follows(&at) {
                return Err(ReplayError::Broken {
                    at: at.index,
                    found: entry.index,
                });
            }
            at = entry.head();
        }
        for entry in entries {
            let position = LogPosition {
                index: entry.index,
                leaf: entry.leaf,
            };
            let latest = self.state.latest.entry(key(&entry.subject)).or_default();
            latest.last = position;
            latest.kind = Some(entry.kind);
            match entry.kind {
                EntryKind::Bundle => latest.bundle = Some(position),
                EntryKind::Revocation => latest.revocation = Some(position),
                EntryKind::Succession => latest.succession = Some(position),
            }
            self.note_checkpoint(entry.head());
        }
        self.state.head = at;
        self.state.verified_at_ms = now_ms;
        self.persist();
        Ok(at)
    }

    /// Note that the head was confirmed against the relay just now.
    pub fn confirm(&mut self, now_ms: u64) {
        self.state.verified_at_ms = now_ms;
        self.persist();
    }

    /// Forget everything, to replay the relay's log from the start: after
    /// the relay's log went backwards or contradicted ours, which is
    /// reported loudly before this is called.
    pub fn reset(&mut self) {
        self.state = LogState::default();
        self.persist();
    }

    /// The hash we hold for `index`: our head's, or a checkpoint's.
    pub fn hash_at(&self, index: u64) -> Option<Hash> {
        if index == 0 {
            return Some(LogHead::EMPTY.hash);
        }
        if index == self.state.head.index {
            return Some(self.state.head.hash);
        }
        self.state
            .checkpoints
            .binary_search_by_key(&index, |c| c.index)
            .ok()
            .map(|i| self.state.checkpoints[i].hash)
    }

    /// The highest checkpoint at or below `index`.
    pub fn checkpoint_below(&self, index: u64) -> LogHead {
        let at = self.state.checkpoints.partition_point(|c| c.index <= index);
        at.checked_sub(1)
            .map(|i| self.state.checkpoints[i].head())
            .unwrap_or(LogHead::EMPTY)
    }

    /// The lowest checkpoint at or above `index`, or our head.
    pub fn checkpoint_above(&self, index: u64) -> LogHead {
        let at = self.state.checkpoints.partition_point(|c| c.index < index);
        self.state
            .checkpoints
            .get(at)
            .map(Checkpoint::head)
            .filter(|c| c.index <= self.state.head.index)
            .unwrap_or(self.state.head)
    }

    /// How a contact's head compares with what we replayed.
    pub fn check_peer_head(&self, head: &LogHead) -> HeadCheck {
        if head.index > self.state.head.index {
            return HeadCheck::Ahead;
        }
        match self.hash_at(head.index) {
            Some(hash) if hash == head.hash => HeadCheck::Consistent,
            Some(_) => HeadCheck::Fork { at: head.index },
            None => HeadCheck::NeedEntries {
                from: self.checkpoint_below(head.index),
                until: self.checkpoint_above(head.index),
            },
        }
    }

    /// What a lookup showed, compared with the log as replayed up to the
    /// relay's head.
    pub fn check_lookup(
        &self,
        user: &UserId,
        bundle: Option<&KeyBundle>,
        revocation: Option<&Revocation>,
        succession: Option<&Succession>,
        claimed: Option<LogPosition>,
    ) -> Result<(), Discrepancy> {
        let latest = self.latest(user);
        if let Some(claimed) = claimed {
            let seen = latest.map(|l| l.last).unwrap_or_default();
            if claimed != seen {
                return Err(Discrepancy::ClaimMismatch {
                    claimed: claimed.index,
                    seen: seen.index,
                });
            }
        }
        if let Some(bundle) = bundle {
            match latest.and_then(|l| l.bundle) {
                None => return Err(Discrepancy::UnloggedBundle),
                Some(logged) if logged.leaf != bundle.transparency_leaf() => {
                    return Err(Discrepancy::NotLatestBundle {
                        logged: logged.index,
                    });
                }
                Some(_) => {}
            }
        }
        if let Some(logged) = latest.and_then(|l| l.revocation) {
            match revocation {
                None => {
                    return Err(Discrepancy::WithheldRevocation {
                        logged: logged.index,
                    });
                }
                Some(r) if r.transparency_leaf() != logged.leaf => {
                    return Err(Discrepancy::UnloggedStatement);
                }
                Some(_) => {}
            }
        } else if revocation.is_some() {
            return Err(Discrepancy::UnloggedStatement);
        }
        // A succession is not served once a revocation is held (a dead key
        // cannot hand over), so it is only expected without one.
        if latest.and_then(|l| l.revocation).is_none() {
            if let Some(logged) = latest.and_then(|l| l.succession) {
                match succession {
                    None => {
                        return Err(Discrepancy::WithheldSuccession {
                            logged: logged.index,
                        });
                    }
                    Some(s) if s.transparency_leaf() != logged.leaf => {
                        return Err(Discrepancy::UnloggedStatement);
                    }
                    Some(_) => {}
                }
            } else if succession.is_some() {
                return Err(Discrepancy::UnloggedStatement);
            }
        }
        Ok(())
    }

    fn note_checkpoint(&mut self, head: LogHead) {
        self.state.checkpoints.push(Checkpoint {
            index: head.index,
            hash: head.hash,
        });
        // Thin out what falls behind the dense window, keeping every
        // SPARSE-th entry.
        let dense_from = head.index.saturating_sub(DENSE);
        self.state
            .checkpoints
            .retain(|c| c.index > dense_from || c.index % SPARSE == 0);
    }

    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Err(e) = write(path, self.cipher.as_deref(), &self.state) {
            warn!(
                "could not save the transparency log to {}: {e:#}",
                path.display()
            );
        }
    }
}

fn key(subject: &Hash) -> String {
    subject.iter().map(|b| format!("{b:02x}")).collect()
}

fn read(path: &Path, cipher: Option<&FileCipher>) -> anyhow::Result<LogState> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let plain = if FileCipher::is_encrypted(&bytes) {
        let cipher =
            cipher.context("the transparency log is encrypted but no passphrase was given")?;
        cipher.decrypt(LOG_NAME, &bytes)?.to_vec()
    } else {
        bytes
    };
    serde_json::from_slice(&plain).with_context(|| format!("parsing {}", path.display()))
}

fn write(path: &Path, cipher: Option<&FileCipher>, state: &LogState) -> anyhow::Result<()> {
    let plain = serde_json::to_vec(state)?;
    let out = match cipher {
        Some(c) => c.encrypt(LOG_NAME, &plain),
        None => plain,
    };
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, out).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::Identity;
    use silver_protocol::prekey::{PrekeySecret, Prekeys};

    /// A relay-side log, kept simply, to produce pages from.
    struct FakeLog {
        entries: Vec<LogEntry>,
    }

    impl FakeLog {
        fn new() -> Self {
            Self {
                entries: Vec::new(),
            }
        }

        fn head(&self) -> LogHead {
            self.entries.last().map(LogEntry::head).unwrap_or_default()
        }

        fn add(&mut self, user: &UserId, kind: EntryKind, leaf: Hash) -> LogEntry {
            let entry = LogEntry::after(&self.head(), subject(user), kind, leaf, 1);
            self.entries.push(entry.clone());
            entry
        }

        fn since(&self, index: u64, limit: usize) -> Vec<LogEntry> {
            self.entries
                .iter()
                .filter(|e| e.index > index)
                .take(limit)
                .cloned()
                .collect()
        }
    }

    fn bundle_of(id: &Identity, prekey_id: u32) -> KeyBundle {
        id.key_bundle_with(Prekeys::classical(
            PrekeySecret::generate(prekey_id, 0).signed_by(id),
            Vec::new(),
        ))
    }

    #[test]
    fn tailing_replays_pages_and_keeps_the_latest_per_identity() {
        let mut relay = FakeLog::new();
        let alice = Identity::generate();
        let bob = Identity::generate();
        let a1 = bundle_of(&alice, 1);
        let b1 = bundle_of(&bob, 1);
        relay.add(&alice.user_id(), EntryKind::Bundle, a1.transparency_leaf());
        relay.add(&bob.user_id(), EntryKind::Bundle, b1.transparency_leaf());
        let a2 = bundle_of(&alice, 2);
        relay.add(&alice.user_id(), EntryKind::Bundle, a2.transparency_leaf());

        let mut ours = LogStore::ephemeral();
        // Two pages of two.
        let page = relay.since(0, 2);
        let head = ours.apply(&page, 5).unwrap();
        assert_eq!(head.index, 2);
        let page = relay.since(head.index, 2);
        let head = ours.apply(&page, 6).unwrap();
        assert_eq!(head, relay.head());
        assert_eq!(ours.verified_at_ms(), 6);

        let alice_latest = ours.latest(&alice.user_id()).unwrap();
        assert_eq!(alice_latest.bundle.unwrap().index, 3);
        assert_eq!(alice_latest.bundle.unwrap().leaf, a2.transparency_leaf());
        assert!(alice_latest.revocation.is_none());
        assert_eq!(ours.latest(&bob.user_id()).unwrap().last.index, 2);
        assert!(ours.latest(&Identity::generate().user_id()).is_none());

        // Lookups checked against it.
        assert_eq!(
            ours.check_lookup(&alice.user_id(), Some(&a2), None, None, None),
            Ok(())
        );
        assert_eq!(
            ours.check_lookup(&alice.user_id(), Some(&a1), None, None, None),
            Err(Discrepancy::NotLatestBundle { logged: 3 })
        );
        let carol = Identity::generate();
        assert_eq!(
            ours.check_lookup(
                &carol.user_id(),
                Some(&carol.key_bundle()),
                None,
                None,
                None
            ),
            Err(Discrepancy::UnloggedBundle)
        );
        // A claim that does not match the log is caught even with the
        // right bundle.
        assert_eq!(
            ours.check_lookup(
                &alice.user_id(),
                Some(&a2),
                None,
                None,
                Some(LogPosition {
                    index: 1,
                    leaf: a1.transparency_leaf()
                })
            ),
            Err(Discrepancy::ClaimMismatch {
                claimed: 1,
                seen: 3
            })
        );
        assert_eq!(
            ours.check_lookup(
                &alice.user_id(),
                Some(&a2),
                None,
                None,
                Some(LogPosition {
                    index: 3,
                    leaf: a2.transparency_leaf()
                })
            ),
            Ok(())
        );
        // Nothing served for someone not in the log is fine.
        assert_eq!(
            ours.check_lookup(&carol.user_id(), None, None, None, None),
            Ok(())
        );
    }

    #[test]
    fn statements_must_be_served_when_logged_and_only_when_logged() {
        let mut relay = FakeLog::new();
        let alice = Identity::generate();
        let next = Identity::generate();
        let a1 = bundle_of(&alice, 1);
        relay.add(&alice.user_id(), EntryKind::Bundle, a1.transparency_leaf());
        let succession = alice.succeed_to(&next, 2);
        relay.add(
            &alice.user_id(),
            EntryKind::Succession,
            succession.transparency_leaf(),
        );
        let mut ours = LogStore::ephemeral();
        ours.apply(&relay.since(0, 10), 1).unwrap();

        // The succession must come with the answer, and be the logged one.
        assert_eq!(
            ours.check_lookup(&alice.user_id(), Some(&a1), None, None, None),
            Err(Discrepancy::WithheldSuccession { logged: 2 })
        );
        assert_eq!(
            ours.check_lookup(&alice.user_id(), Some(&a1), None, Some(&succession), None),
            Ok(())
        );
        let other = alice.succeed_to(&Identity::generate(), 3);
        assert_eq!(
            ours.check_lookup(&alice.user_id(), Some(&a1), None, Some(&other), None),
            Err(Discrepancy::UnloggedStatement)
        );
        // A revocation nobody logged is not accepted either.
        assert_eq!(
            ours.check_lookup(
                &alice.user_id(),
                Some(&a1),
                Some(&alice.revocation(4)),
                Some(&succession),
                None
            ),
            Err(Discrepancy::UnloggedStatement)
        );

        // Once revoked, the revocation is required and the succession is
        // no longer expected (a dead key cannot hand over).
        let revocation = alice.revocation(5);
        relay.add(
            &alice.user_id(),
            EntryKind::Revocation,
            revocation.transparency_leaf(),
        );
        ours.apply(&relay.since(ours.head().index, 10), 2).unwrap();
        assert_eq!(
            ours.check_lookup(&alice.user_id(), Some(&a1), None, None, None),
            Err(Discrepancy::WithheldRevocation { logged: 3 })
        );
        assert_eq!(
            ours.check_lookup(&alice.user_id(), Some(&a1), Some(&revocation), None, None),
            Ok(())
        );
    }

    #[test]
    fn a_bad_page_changes_nothing() {
        let mut relay = FakeLog::new();
        let alice = Identity::generate();
        for i in 1..=3 {
            relay.add(&alice.user_id(), EntryKind::Bundle, [i; 32]);
        }
        let mut ours = LogStore::ephemeral();
        ours.apply(&relay.since(0, 1), 1).unwrap();
        // A page that skips an entry.
        let err = ours.apply(&relay.since(1, 10)[1..], 2).unwrap_err();
        assert_eq!(err, ReplayError::Broken { at: 1, found: 3 });
        assert_eq!(ours.head().index, 1);
        assert_eq!(ours.latest(&alice.user_id()).unwrap().last.index, 1);
        // A page with a tampered entry.
        let mut page = relay.since(1, 10);
        page[0].leaf[0] ^= 1;
        assert!(ours.apply(&page, 2).is_err());
        assert_eq!(ours.head().index, 1);
        // The good page still applies.
        ours.apply(&relay.since(1, 10), 3).unwrap();
        assert_eq!(ours.head(), relay.head());
    }

    #[test]
    fn a_contacts_head_is_checked_against_our_chain() {
        let mut relay = FakeLog::new();
        let alice = Identity::generate();
        for i in 1..=6u8 {
            relay.add(&alice.user_id(), EntryKind::Bundle, [i; 32]);
        }
        let mut ours = LogStore::ephemeral();
        ours.apply(&relay.since(0, 10), 1).unwrap();

        // Every recent head is a checkpoint.
        let at4 = relay.entries[3].head();
        assert_eq!(ours.check_peer_head(&at4), HeadCheck::Consistent);
        assert_eq!(ours.check_peer_head(&relay.head()), HeadCheck::Consistent);
        assert_eq!(ours.check_peer_head(&LogHead::EMPTY), HeadCheck::Consistent);
        // The same index with another hash is a fork.
        let mut forked = at4;
        forked.hash[0] ^= 1;
        assert_eq!(ours.check_peer_head(&forked), HeadCheck::Fork { at: 4 });
        // Beyond us: we must tail first.
        let beyond = LogHead {
            index: 9,
            hash: [9; 32],
        };
        assert_eq!(ours.check_peer_head(&beyond), HeadCheck::Ahead);
    }

    #[test]
    fn old_checkpoints_thin_out_but_a_lower_one_is_always_found() {
        let mut relay = FakeLog::new();
        let alice = Identity::generate();
        let n = DENSE + 3 * SPARSE;
        for i in 1..=n {
            relay.add(&alice.user_id(), EntryKind::Bundle, [(i % 251) as u8; 32]);
        }
        let mut ours = LogStore::ephemeral();
        let mut from = 0;
        loop {
            let page = relay.since(from, 300);
            if page.is_empty() {
                break;
            }
            from = ours.apply(&page, 1).unwrap().index;
        }
        assert_eq!(ours.head(), relay.head());
        // Dense window: all there.
        assert!(ours.hash_at(n - 1).is_some());
        assert!(ours.hash_at(n - DENSE + 1).is_some());
        // Before it: only multiples of SPARSE.
        assert!(ours.hash_at(SPARSE).is_some());
        assert!(ours.hash_at(SPARSE + 1).is_none());
        let old = relay.entries[(SPARSE + 5 - 1) as usize].head();
        assert_eq!(
            ours.check_peer_head(&old),
            HeadCheck::NeedEntries {
                from: relay.entries[(SPARSE - 1) as usize].head(),
                until: relay.entries[(2 * SPARSE - 1) as usize].head(),
            }
        );
        // The last sparse checkpoint sits at the dense window's edge and is
        // found directly; the entry just below it is bounded by the sparse
        // checkpoints on either side.
        let edge = n - DENSE; // a multiple of SPARSE
        assert_eq!(
            ours.check_peer_head(&relay.entries[edge as usize - 1].head()),
            HeadCheck::Consistent
        );
        let below = relay.entries[edge as usize - 2].head();
        assert_eq!(
            ours.check_peer_head(&below),
            HeadCheck::NeedEntries {
                from: relay.entries[(edge - SPARSE) as usize - 1].head(),
                until: relay.entries[edge as usize - 1].head(),
            }
        );
        assert_eq!(ours.checkpoint_below(3), LogHead::EMPTY);
        assert!(ours.state.checkpoints.len() < n as usize);
    }

    #[test]
    fn the_state_round_trips_through_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOG_NAME);
        let mut relay = FakeLog::new();
        let alice = Identity::generate();
        relay.add(&alice.user_id(), EntryKind::Bundle, [1; 32]);
        let mut ours = LogStore::load(Some(path.clone()), None).unwrap();
        ours.apply(&relay.since(0, 10), 7).unwrap();
        let again = LogStore::load(Some(path), None).unwrap();
        assert_eq!(again.head(), relay.head());
        assert_eq!(again.verified_at_ms(), 7);
        assert_eq!(
            again.latest(&alice.user_id()),
            ours.latest(&alice.user_id())
        );
    }
}
