//! Checking incoming sequence numbers against what a contact sent before.
//!
//! An envelope's id is outside every AEAD, so a relay can hand the same
//! message back under a fresh id and the ids a client remembers will not
//! catch it. What catches it is the number inside the body, which the
//! sender signs or seals: a message numbered at or below what has already
//! been accepted from that sender is a replay whatever id it arrives
//! under.
//!
//! What is remembered per sender is the highest number accepted, a
//! sixty-four-message window of the ones below it, and where the sender's
//! previous numbering ended. The window is why a message that overtakes
//! its neighbours — the relay may reorder, and a mailbox drains in
//! whatever order it was filled — is not lost: before 0.11.0 anything
//! below the highest was a replay, so a message reported missing and then
//! delivered was dropped rather than shown. The previous epochs are why a
//! relay cannot replay a whole old conversation by claiming the sender
//! reinstalled: numbering that goes back to where it has been before is a
//! replay, and only numbering past it is a fresh start. A few of them are
//! kept, not just the last: with one, a relay holding the mail of two
//! earlier installations could hand the older one back, which no longer
//! matched the single epoch remembered and so passed as a fresh start.

use serde::{Deserialize, Serialize};
use silver_protocol::Sequence;

/// Messages below the highest accepted whose arrival is still remembered.
const WINDOW: u64 = 64;
/// Epochs before the previous one whose end is still remembered.
const EARLIER_EPOCHS: usize = 3;

/// What has been accepted from one sender.
///
/// Serialised as the bare `Sequence` it used to be plus two fields that
/// are absent when they say nothing, so a `contacts.json` written before
/// 0.11.0 reads as "the highest, nothing else known".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    /// The highest sequence accepted in the sender's current epoch.
    #[serde(flatten)]
    pub last: Sequence,
    /// Which of the [`WINDOW`] messages below `last.seq` have arrived:
    /// bit `n` is `last.seq - 1 - n`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub window: u64,
    /// Where the sender's previous epoch had got to when they moved on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Sequence>,
    /// Where the epochs before `previous` had got to, newest first. A
    /// fixed array so that `Seen` stays a plain value; absent from what
    /// was written before it existed, and from what has nothing in it.
    #[serde(default, skip_serializing_if = "no_earlier")]
    pub earlier: [Option<Sequence>; EARLIER_EPOCHS],
}

fn is_zero(window: &u64) -> bool {
    *window == 0
}

fn no_earlier(earlier: &[Option<Sequence>; EARLIER_EPOCHS]) -> bool {
    earlier.iter().all(Option::is_none)
}

impl Seen {
    /// Whether `incoming` falls inside an epoch the sender has already
    /// left, at or below where that epoch ended.
    fn left_behind(&self, incoming: Sequence) -> bool {
        self.previous
            .iter()
            .chain(self.earlier.iter().flatten())
            .any(|ended| ended.epoch == incoming.epoch && incoming.seq <= ended.seq)
    }
}

/// What an incoming message's sequence number says about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceCheck {
    /// The next message in order.
    Fresh,
    /// Below the highest accepted but inside the window and not seen
    /// before: it was reported missing and has now turned up.
    Late,
    /// The sender started counting from scratch (a fresh installation).
    NewEpoch,
    /// Already seen, or older than anything still remembered: a replay,
    /// or a message so late that nothing tells it from one. Drop it.
    Replay,
    /// Later than expected; this many earlier messages have not arrived.
    Gap { missing: u64 },
    /// The sender does not number messages (an older client). Unchecked.
    Legacy,
}

impl SequenceCheck {
    /// Whether the message is to be shown.
    pub fn accepted(self) -> bool {
        !matches!(self, Self::Replay)
    }
}

/// Compare `incoming` with what has been accepted from the same sender.
pub fn check(seen: Option<Seen>, incoming: Sequence) -> SequenceCheck {
    if incoming.seq == 0 {
        return SequenceCheck::Legacy;
    }
    let Some(seen) = seen else {
        return SequenceCheck::Fresh;
    };
    if seen.last.epoch != incoming.epoch {
        // A sender who reinstalls numbers from a fresh epoch. One who
        // goes back to an epoch we have already seen the end of is not
        // reinstalling: that is the shape of a relay handing an old
        // conversation back under new envelope ids.
        return if seen.left_behind(incoming) {
            SequenceCheck::Replay
        } else {
            SequenceCheck::NewEpoch
        };
    }
    // Compared by difference, not by `last + 1`: the number is the
    // sender's to choose, and one who sends the largest there is would
    // otherwise overflow the addition on every message after it.
    match incoming.seq {
        seq if seq == seen.last.seq => SequenceCheck::Replay,
        seq if seq > seen.last.seq && seq - seen.last.seq > 1 => SequenceCheck::Gap {
            missing: seq - seen.last.seq - 1,
        },
        seq if seq > seen.last.seq => SequenceCheck::Fresh,
        seq => match seen.last.seq - seq {
            behind if behind <= WINDOW && seen.window & (1 << (behind - 1)) == 0 => {
                SequenceCheck::Late
            }
            _ => SequenceCheck::Replay,
        },
    }
}

/// Record `incoming`, which [`check`] accepted.
pub fn note(seen: &mut Option<Seen>, incoming: Sequence) {
    if incoming.seq == 0 {
        return;
    }
    let Some(state) = seen else {
        *seen = Some(Seen {
            last: incoming,
            ..Seen::default()
        });
        return;
    };
    if state.last.epoch != incoming.epoch {
        // The one before moves down among the earlier ones, the oldest
        // of which is forgotten.
        let mut earlier = [None; EARLIER_EPOCHS];
        earlier[0] = state.previous;
        earlier[1..].copy_from_slice(&state.earlier[..EARLIER_EPOCHS - 1]);
        *seen = Some(Seen {
            last: incoming,
            window: 0,
            // Where the epoch just left behind had got to, so that
            // numbering cannot come back to it.
            previous: Some(state.last),
            earlier,
        });
        return;
    }
    if incoming.seq > state.last.seq {
        // The window slides up: what was at the top is now `step` places
        // down, and the message that was the highest joins it.
        let step = incoming.seq - state.last.seq;
        state.window = if step >= WINDOW {
            0
        } else {
            (state.window << step) | (1 << (step - 1))
        };
        state.last = incoming;
        return;
    }
    let behind = state.last.seq - incoming.seq;
    if (1..=WINDOW).contains(&behind) {
        state.window |= 1 << (behind - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(epoch: u64, seq: u64) -> Sequence {
        Sequence { epoch, seq }
    }

    fn seen(epoch: u64, seq: u64) -> Option<Seen> {
        let mut state = None;
        note(&mut state, s(epoch, seq));
        state
    }

    #[test]
    fn classifies_sequences() {
        assert_eq!(check(None, s(7, 1)), SequenceCheck::Fresh);
        assert_eq!(check(seen(7, 1), s(7, 2)), SequenceCheck::Fresh);
        assert_eq!(check(seen(7, 2), s(7, 2)), SequenceCheck::Replay);
        assert_eq!(
            check(seen(7, 2), s(7, 5)),
            SequenceCheck::Gap { missing: 2 }
        );
        assert_eq!(check(seen(7, 9), s(8, 1)), SequenceCheck::NewEpoch);
        assert_eq!(check(seen(7, 9), s(0, 0)), SequenceCheck::Legacy);
        assert_eq!(check(None, Sequence::default()), SequenceCheck::Legacy);
    }

    /// A message reported missing and then delivered is shown, not
    /// dropped: the relay may hand a mailbox over in any order it likes.
    #[test]
    fn a_message_that_arrives_late_is_still_a_message() {
        let mut state = None;
        note(&mut state, s(7, 1));
        assert_eq!(check(state, s(7, 4)), SequenceCheck::Gap { missing: 2 });
        note(&mut state, s(7, 4));

        // The two that were missing turn up, in either order.
        assert_eq!(check(state, s(7, 3)), SequenceCheck::Late);
        note(&mut state, s(7, 3));
        assert_eq!(check(state, s(7, 2)), SequenceCheck::Late);
        note(&mut state, s(7, 2));
        // And neither comes twice.
        assert_eq!(check(state, s(7, 3)), SequenceCheck::Replay);
        assert_eq!(check(state, s(7, 2)), SequenceCheck::Replay);
        assert_eq!(check(state, s(7, 1)), SequenceCheck::Replay);

        // Past the window nothing tells a late message from a replay, so
        // it is refused.
        note(&mut state, s(7, 200));
        assert_eq!(check(state, s(7, 199)), SequenceCheck::Late);
        assert_eq!(check(state, s(7, 200 - WINDOW)), SequenceCheck::Late);
        assert_eq!(check(state, s(7, 200 - WINDOW - 1)), SequenceCheck::Replay);
    }

    /// Numbering that goes back to an epoch already finished with is a
    /// relay handing an old conversation back, not a reinstallation.
    #[test]
    fn numbering_does_not_go_back_to_an_epoch_it_has_left() {
        let mut state = None;
        note(&mut state, s(7, 1));
        note(&mut state, s(7, 5));
        assert_eq!(check(state, s(8, 1)), SequenceCheck::NewEpoch);
        note(&mut state, s(8, 1));

        // Everything the old epoch had is refused...
        assert_eq!(check(state, s(7, 5)), SequenceCheck::Replay);
        assert_eq!(check(state, s(7, 1)), SequenceCheck::Replay);
        // ...and a third epoch is still a fresh start.
        assert_eq!(check(state, s(9, 1)), SequenceCheck::NewEpoch);
    }

    /// A sender's number is theirs to choose, the largest there is
    /// included; what follows it in the same epoch is a replay, not an
    /// overflow.
    #[test]
    fn the_largest_sequence_number_does_not_overflow() {
        let mut state = None;
        assert_eq!(check(state, s(7, u64::MAX)), SequenceCheck::Fresh);
        note(&mut state, s(7, u64::MAX));
        assert_eq!(check(state, s(7, 5)), SequenceCheck::Replay);
        assert_eq!(check(state, s(7, u64::MAX)), SequenceCheck::Replay);
        assert_eq!(check(state, s(7, u64::MAX - 1)), SequenceCheck::Late);
        note(&mut state, s(7, u64::MAX - 1));
        assert_eq!(check(state, s(8, 1)), SequenceCheck::NewEpoch);

        let mut state = None;
        note(&mut state, s(7, u64::MAX - 1));
        assert_eq!(check(state, s(7, u64::MAX)), SequenceCheck::Fresh);
        note(&mut state, s(7, 1));
        note(&mut state, s(7, u64::MAX));
        assert_eq!(state.unwrap().last, s(7, u64::MAX));
    }

    /// Going back to an epoch two or three installations ago is no more a
    /// fresh start than going back to the last one.
    #[test]
    fn several_earlier_epochs_stay_closed() {
        let mut state = None;
        for epoch in 1..=5 {
            note(&mut state, s(epoch, 1));
            note(&mut state, s(epoch, 10));
        }
        // Epoch 5 is current; 4 is `previous`, and 3, 2 and 1 earlier.
        for epoch in 1..=4 {
            assert_eq!(check(state, s(epoch, 10)), SequenceCheck::Replay);
            assert_eq!(check(state, s(epoch, 1)), SequenceCheck::Replay);
            // Past where it ended is past anything that can be replayed.
            assert_eq!(check(state, s(epoch, 11)), SequenceCheck::NewEpoch);
        }
        // One more and the oldest is forgotten, as a bound has to.
        note(&mut state, s(6, 1));
        assert_eq!(check(state, s(1, 10)), SequenceCheck::NewEpoch);
        assert_eq!(check(state, s(2, 10)), SequenceCheck::Replay);

        // What is kept round-trips, and is absent when there is nothing.
        let json = serde_json::to_string(&state.unwrap()).unwrap();
        let back: Seen = serde_json::from_str(&json).unwrap();
        assert_eq!(Some(back), state);
        assert!(
            !serde_json::to_string(&seen(7, 1).unwrap())
                .unwrap()
                .contains("earlier")
        );
    }

    /// A `contacts.json` written before the window existed reads as the
    /// highest sequence and nothing else, and its JSON is unchanged when
    /// there is nothing more to say.
    #[test]
    fn what_was_stored_before_the_window_still_reads() {
        let old: Seen = serde_json::from_str(r#"{"epoch":7,"seq":3}"#).unwrap();
        assert_eq!(old.last, s(7, 3));
        assert_eq!(old.window, 0);
        assert_eq!(old.previous, None);
        assert_eq!(
            serde_json::to_string(&old).unwrap(),
            r#"{"epoch":7,"seq":3}"#
        );
        assert_eq!(check(Some(old), s(7, 4)), SequenceCheck::Fresh);
        assert_eq!(check(Some(old), s(7, 3)), SequenceCheck::Replay);
        // Nothing is known about what came before, so the ones below the
        // highest are open until one arrives and closes them.
        assert_eq!(check(Some(old), s(7, 2)), SequenceCheck::Late);
    }
}
