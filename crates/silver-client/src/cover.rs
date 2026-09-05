//! Cover traffic: messages that say nothing, sent at random moments to
//! contacts who do the same, so that a relay watching who talks to whom
//! and when sees traffic between two people whether or not they are
//! talking.
//!
//! It is opt-in and mutual. A client advertises the `cover` capability
//! only while its user has it on, and sends cover only to contacts whose
//! last message advertised it, so both sides have agreed to the cost
//! before a single cover message flows. What a cover message looks like on
//! the wire is what any message looks like: it is numbered, carried in the
//! session, padded in the same steps; the recipient discards it after
//! decrypting, with no history line, receipt or notification.
//!
//! Cover flows only while both sides are around. Hearing from a contact
//! (any message, cover included) opens a window of [`WINDOW`] during which
//! cover goes to them at random intervals of [`INTERVAL`]; their cover
//! keeps our window open and ours keeps theirs, so two running clients
//! cover each other until one of them stops, and the other falls silent
//! within a window. That bounds what piles up in the mailbox of a contact
//! who went offline to a handful of messages. See `docs/THREAT_MODEL.md`
//! for what this hides and what it does not.

use std::collections::HashMap;
use std::ops::Range;
use std::time::{Duration, Instant};

use rand::Rng;
use silver_protocol::envelope::PAD_BLOCK;
use silver_protocol::{Content, UserId};

/// How long after hearing from a contact cover keeps going to them.
pub const WINDOW: Duration = Duration::from_secs(10 * 60);
/// The gap between two cover messages to one contact, drawn uniformly.
pub const INTERVAL: Range<Duration> = Duration::from_secs(30)..Duration::from_secs(180);

/// A cover message: random letters, sized so the padded body lands on the
/// same steps short and medium messages do. The length is drawn in whole
/// padding blocks plus a random remainder: seven in ten add nothing to the
/// framing, two in ten one block, one in ten two.
pub fn message() -> Content {
    message_with(&mut rand::thread_rng())
}

fn message_with<R: Rng>(rng: &mut R) -> Content {
    let blocks = match rng.gen_range(0..10) {
        0..=6 => 0,
        7..=8 => 1,
        _ => 2,
    };
    let len = blocks * PAD_BLOCK + rng.gen_range(0..PAD_BLOCK);
    let pad = (0..len)
        .map(|_| char::from(b'a' + rng.gen_range(0..26u8)))
        .collect();
    Content::Cover { pad }
}

struct Peer {
    heard: Instant,
    due: Instant,
}

/// When cover is due to whom, given who has been heard from lately.
#[derive(Default)]
pub struct CoverSchedule {
    peers: HashMap<UserId, Peer>,
}

impl CoverSchedule {
    /// A contact who advertises cover sent something (cover included):
    /// their window opens or extends, and if they were not being covered
    /// yet, the first cover message is scheduled.
    pub fn heard(&mut self, peer: UserId, now: Instant) {
        self.heard_with(peer, now, &mut rand::thread_rng());
    }

    fn heard_with<R: Rng>(&mut self, peer: UserId, now: Instant, rng: &mut R) {
        match self.peers.get_mut(&peer) {
            Some(p) => p.heard = now,
            None => {
                self.peers.insert(
                    peer,
                    Peer {
                        heard: now,
                        due: now + interval(rng),
                    },
                );
            }
        }
    }

    /// The contacts whose next cover message is due, each rescheduled;
    /// contacts not heard from within [`WINDOW`] are dropped instead.
    pub fn take_due(&mut self, now: Instant) -> Vec<UserId> {
        self.take_due_with(now, &mut rand::thread_rng())
    }

    fn take_due_with<R: Rng>(&mut self, now: Instant, rng: &mut R) -> Vec<UserId> {
        let mut due = Vec::new();
        self.peers.retain(|peer, p| {
            if now.duration_since(p.heard) >= WINDOW {
                return false;
            }
            if p.due <= now {
                due.push(*peer);
                p.due = now + interval(rng);
            }
            true
        });
        due
    }

    /// Stop covering `peer` (they were removed, blocked, or stopped
    /// advertising cover).
    pub fn forget(&mut self, peer: &UserId) {
        self.peers.remove(peer);
    }

    /// Stop covering everyone (cover was turned off).
    pub fn clear(&mut self) {
        self.peers.clear();
    }

    /// Whether anyone is being covered right now.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// How many contacts are being covered right now.
    pub fn len(&self) -> usize {
        self.peers.len()
    }
}

fn interval<R: Rng>(rng: &mut R) -> Duration {
    let span = (INTERVAL.end - INTERVAL.start).as_secs_f64();
    INTERVAL.start + Duration::from_secs_f64(span * rng.gen_range(0.0..1.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use silver_protocol::Identity;
    use silver_protocol::envelope::{Body, Sequence};

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    #[test]
    fn a_heard_contact_is_covered_at_random_intervals_until_the_window_closes() {
        let (a, b) = (
            Identity::generate().user_id(),
            Identity::generate().user_id(),
        );
        let mut rng = rng(1);
        let mut schedule = CoverSchedule::default();
        let start = Instant::now();
        assert!(schedule.is_empty());
        schedule.heard_with(a, start, &mut rng);
        schedule.heard_with(b, start, &mut rng);
        assert_eq!(schedule.len(), 2);
        // Nothing before the shortest interval.
        assert!(
            schedule
                .take_due_with(start + INTERVAL.start - Duration::from_millis(1), &mut rng)
                .is_empty()
        );
        // Everyone by the longest.
        let mut due = schedule.take_due_with(start + INTERVAL.end, &mut rng);
        due.sort();
        let mut both = vec![a, b];
        both.sort();
        assert_eq!(due, both);
        // Rescheduled, not dropped, and not due again at once.
        assert_eq!(schedule.len(), 2);
        assert!(
            schedule
                .take_due_with(start + INTERVAL.end, &mut rng)
                .is_empty()
        );
        // Hearing again extends the window; silence closes it.
        schedule.heard_with(a, start + WINDOW - Duration::from_secs(1), &mut rng);
        let at = start + WINDOW;
        let due = schedule.take_due_with(at, &mut rng);
        assert!(!due.contains(&b), "b was not heard from for a window");
        assert_eq!(schedule.len(), 1);
        assert!(schedule.take_due_with(at + WINDOW, &mut rng).is_empty());
        assert!(schedule.is_empty());
    }

    #[test]
    fn intervals_are_random_within_their_bounds() {
        let a = Identity::generate().user_id();
        let start = Instant::now();
        let mut rng = rng(2);
        let mut dues = Vec::new();
        for _ in 0..40 {
            let mut schedule = CoverSchedule::default();
            schedule.heard_with(a, start, &mut rng);
            dues.push(schedule.peers[&a].due - start);
        }
        for due in &dues {
            assert!(*due >= INTERVAL.start && *due < INTERVAL.end, "{due:?}");
        }
        assert!(dues.iter().any(|d| *d != dues[0]));
    }

    #[test]
    fn forget_and_clear_stop_cover() {
        let (a, b) = (
            Identity::generate().user_id(),
            Identity::generate().user_id(),
        );
        let mut schedule = CoverSchedule::default();
        let start = Instant::now();
        schedule.heard(a, start);
        schedule.heard(b, start);
        schedule.forget(&a);
        assert_eq!(schedule.len(), 1);
        schedule.clear();
        assert!(schedule.is_empty());
        assert!(schedule.take_due(start + INTERVAL.end).is_empty());
    }

    #[test]
    fn cover_messages_land_on_the_same_size_steps_as_short_messages() {
        let mut rng = rng(3);
        let mut blocks = [0usize; 4];
        for _ in 0..400 {
            let content = message_with(&mut rng);
            let Content::Cover { pad } = &content else {
                panic!("not cover");
            };
            assert!(pad.bytes().all(|b| b.is_ascii_lowercase()));
            let encoded = Body::plain(content.clone(), 0, Sequence::default())
                .encode()
                .unwrap();
            assert_eq!(encoded.len() % PAD_BLOCK, 0);
            // The framing alone is under one block, so the body takes the
            // drawn number of blocks plus one, or one more when the
            // remainder crosses a boundary.
            let n = encoded.len() / PAD_BLOCK;
            assert!((1..=4).contains(&n), "{n} blocks");
            blocks[n - 1] += 1;
        }
        // Mostly one or two blocks, some three, a few four: the shape of a
        // conversation, not a constant.
        assert!(blocks[0] + blocks[1] > blocks[2] + blocks[3]);
        assert!(blocks[2] > 0 && blocks[3] > 0);
        // Decodes as what it is.
        let content = message_with(&mut rng);
        let encoded = Body::plain(content.clone(), 0, Sequence::default())
            .encode()
            .unwrap();
        match Body::decode(&encoded).unwrap() {
            Body::Plain { content: c, .. } => assert_eq!(c, content),
            Body::Ratchet(_) => panic!("plain expected"),
        }
    }
}
