//! Batching of delivery and read receipts.
//!
//! Receipts are ordinary encrypted messages ([`Content::Receipt`]), so each
//! one costs a relay round trip and a place in the peer's mailbox. The
//! queue collects ids for a moment and sends one receipt per peer and kind,
//! which matters most when a mailbox full of messages is delivered at once.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use silver_protocol::envelope::ReceiptKind;
use silver_protocol::{Content, UserId};

/// How long ids wait for company before a receipt goes out.
pub const BATCH_DELAY: Duration = Duration::from_millis(400);

#[derive(Default)]
struct Pending {
    delivered: Vec<String>,
    read: Vec<String>,
    since: Option<Instant>,
}

/// Receipts waiting to be sent, per peer.
#[derive(Default)]
pub struct ReceiptQueue {
    peers: HashMap<UserId, Pending>,
}

impl ReceiptQueue {
    /// Note that a message from `peer` was stored.
    pub fn delivered(&mut self, peer: UserId, id: impl Into<String>) {
        let pending = self.peers.entry(peer).or_default();
        let id = id.into();
        if !pending.delivered.contains(&id) && !pending.read.contains(&id) {
            pending.delivered.push(id);
        }
        pending.since.get_or_insert_with(Instant::now);
    }

    /// Note that a message from `peer` was shown. A read receipt implies
    /// delivery, so a pending delivered receipt for the same id is dropped.
    pub fn read(&mut self, peer: UserId, id: impl Into<String>) {
        let pending = self.peers.entry(peer).or_default();
        let id = id.into();
        pending.delivered.retain(|d| *d != id);
        if !pending.read.contains(&id) {
            pending.read.push(id);
        }
        pending.since.get_or_insert_with(Instant::now);
    }

    /// Whether anything is waiting.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// The receipts whose batch delay has passed, ready to send.
    pub fn take_due(&mut self, now: Instant) -> Vec<(UserId, Content)> {
        self.take(|since| now.saturating_duration_since(since) >= BATCH_DELAY)
    }

    /// Everything, regardless of age (for example before quitting).
    pub fn take_all(&mut self) -> Vec<(UserId, Content)> {
        self.take(|_| true)
    }

    fn take(&mut self, due: impl Fn(Instant) -> bool) -> Vec<(UserId, Content)> {
        let mut out = Vec::new();
        self.peers.retain(|peer, pending| {
            if !pending.since.is_some_and(&due) {
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
        queue.delivered(a, "1");
        queue.delivered(a, "2");
        queue.delivered(a, "1");
        queue.read(a, "2");
        queue.delivered(b, "9");
        assert!(queue.take_due(start).is_empty(), "too early");
        let mut due = queue.take_due(start + BATCH_DELAY + Duration::from_millis(1));
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
}
