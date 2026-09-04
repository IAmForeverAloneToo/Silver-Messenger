//! Batching of delivery and read receipts.
//!
//! Receipts are ordinary encrypted messages ([`Content::Receipt`]), so each
//! one costs a relay round trip and a place in the peer's mailbox. The
//! queue collects ids for a moment and sends one receipt per peer and kind,
//! which matters most when a mailbox full of messages is delivered at once.
//!
//! A batch also waits a random while, so that the moment a receipt leaves
//! does not mark the moment a message arrived or was looked at: a relay
//! that sees a small message go back right after a delivery learns less
//! when the gap varies.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use silver_protocol::envelope::ReceiptKind;
use silver_protocol::{Content, UserId};

/// How long ids wait for company before a receipt goes out.
pub const BATCH_DELAY: Duration = Duration::from_millis(400);
/// Most a delivery receipt waits on top of that.
pub const DELIVERED_JITTER: Duration = Duration::from_secs(2);
/// Least and most a read receipt waits on top of that: it says when
/// someone was at the keyboard, so it is blurred more.
pub const READ_JITTER: (Duration, Duration) = (Duration::from_secs(2), Duration::from_secs(12));

#[derive(Default)]
struct Pending {
    delivered: Vec<String>,
    read: Vec<String>,
    due: Option<Instant>,
}

impl Pending {
    /// Let the batch wait at least until `earliest` past `now`, and at most
    /// `latest`, chosen at random.
    fn wait(&mut self, now: Instant, earliest: Duration, latest: Duration) {
        let span = latest.saturating_sub(earliest).as_secs_f64();
        let extra = earliest + Duration::from_secs_f64(span * rand::random::<f64>());
        let due = now + BATCH_DELAY + extra;
        self.due = Some(self.due.map_or(due, |d| d.max(due)));
    }
}

/// Receipts waiting to be sent, per peer.
#[derive(Default)]
pub struct ReceiptQueue {
    peers: HashMap<UserId, Pending>,
}

impl ReceiptQueue {
    /// Note that a message from `peer` was stored.
    pub fn delivered(&mut self, peer: UserId, id: impl Into<String>) {
        self.delivered_at(peer, id, Instant::now());
    }

    fn delivered_at(&mut self, peer: UserId, id: impl Into<String>, now: Instant) {
        let pending = self.peers.entry(peer).or_default();
        let id = id.into();
        if !pending.delivered.contains(&id) && !pending.read.contains(&id) {
            pending.delivered.push(id);
        }
        if pending.due.is_none() {
            pending.wait(now, Duration::ZERO, DELIVERED_JITTER);
        }
    }

    /// Note that a message from `peer` was shown. A read receipt implies
    /// delivery, so a pending delivered receipt for the same id is dropped.
    pub fn read(&mut self, peer: UserId, id: impl Into<String>) {
        self.read_at(peer, id, Instant::now());
    }

    fn read_at(&mut self, peer: UserId, id: impl Into<String>, now: Instant) {
        let pending = self.peers.entry(peer).or_default();
        let id = id.into();
        pending.delivered.retain(|d| *d != id);
        if !pending.read.contains(&id) {
            pending.read.push(id);
            pending.wait(now, READ_JITTER.0, READ_JITTER.1);
        }
    }

    /// Whether anything is waiting.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// The receipts whose wait has passed, ready to send.
    pub fn take_due(&mut self, now: Instant) -> Vec<(UserId, Content)> {
        self.take(|due| due <= now)
    }

    /// Everything, regardless of age (for example before quitting).
    pub fn take_all(&mut self) -> Vec<(UserId, Content)> {
        self.take(|_| true)
    }

    fn take(&mut self, ready: impl Fn(Instant) -> bool) -> Vec<(UserId, Content)> {
        let mut out = Vec::new();
        self.peers.retain(|peer, pending| {
            if !pending.due.is_some_and(&ready) {
                return true;
            }
            if !pending.delivered.is_empty() {
                out.push((
                    *peer,
                    Content::Receipt {
                        kind: ReceiptKind::Delivered,
                        ids: std::mem::take(&mut pending.delivered),
                    },
                ));
            }
            if !pending.read.is_empty() {
                out.push((
                    *peer,
                    Content::Receipt {
                        kind: ReceiptKind::Read,
                        ids: std::mem::take(&mut pending.read),
                    },
                ));
            }
            false
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::Identity;

    #[test]
    fn receipts_batch_per_peer_and_read_supersedes_delivered() {
        let (a, b) = (
            Identity::generate().user_id(),
            Identity::generate().user_id(),
        );
        let mut queue = ReceiptQueue::default();
        let start = Instant::now();
        queue.delivered_at(a, "1", start);
        queue.delivered_at(a, "2", start);
        queue.delivered_at(a, "1", start);
        queue.read_at(a, "2", start);
        queue.delivered_at(b, "9", start);
        assert!(queue.take_due(start).is_empty(), "too early");
        assert!(
            queue.take_due(start + BATCH_DELAY).is_empty(),
            "the batch delay alone is not enough any more"
        );
        // Well past the longest wait, everything is due.
        let mut due =
            queue.take_due(start + BATCH_DELAY + READ_JITTER.1 + Duration::from_millis(1));
        due.sort_by_key(|(peer, _)| *peer);
        let mut expected = vec![
            (
                a,
                Content::Receipt {
                    kind: ReceiptKind::Delivered,
                    ids: vec!["1".into()],
                },
            ),
            (
                a,
                Content::Receipt {
                    kind: ReceiptKind::Read,
                    ids: vec!["2".into()],
                },
            ),
            (
                b,
                Content::Receipt {
                    kind: ReceiptKind::Delivered,
                    ids: vec!["9".into()],
                },
            ),
        ];
        expected.sort_by_key(|(peer, _)| *peer);
        assert_eq!(due, expected);
        assert!(queue.is_empty());

        queue.read(b, "10");
        assert_eq!(queue.take_all().len(), 1);
        assert!(queue.is_empty());
    }

    #[test]
    fn waits_are_random_within_their_bounds() {
        let a = Identity::generate().user_id();
        let start = Instant::now();
        let mut delivered_waits = Vec::new();
        let mut read_waits = Vec::new();
        for _ in 0..40 {
            let mut queue = ReceiptQueue::default();
            queue.delivered_at(a, "1", start);
            delivered_waits.push(queue.peers[&a].due.unwrap() - start);
            let mut queue = ReceiptQueue::default();
            queue.read_at(a, "1", start);
            read_waits.push(queue.peers[&a].due.unwrap() - start);
        }
        for wait in &delivered_waits {
            assert!(
                *wait >= BATCH_DELAY && *wait <= BATCH_DELAY + DELIVERED_JITTER,
                "{wait:?}"
            );
        }
        for wait in &read_waits {
            assert!(
                *wait >= BATCH_DELAY + READ_JITTER.0 && *wait <= BATCH_DELAY + READ_JITTER.1,
                "{wait:?}"
            );
        }
        // Not all the same: forty draws from ten seconds coincide by chance
        // only in a broken generator.
        assert!(read_waits.iter().any(|w| *w != read_waits[0]));
        // A read after a delivered receipt pushes the batch out, never in.
        let mut queue = ReceiptQueue::default();
        queue.delivered_at(a, "1", start);
        let first = queue.peers[&a].due.unwrap();
        queue.read_at(a, "2", start);
        assert!(queue.peers[&a].due.unwrap() >= first);
    }
}
