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
//! delivered was dropped rather than shown. The previous epoch is why a
//! relay cannot replay a whole old conversation by claiming the sender
//! reinstalled: numbering that goes back to where it has been before is a
//! replay, and only numbering past it is a fresh start.

use serde::{Deserialize, Serialize};
use silver_protocol::Sequence;

/// Messages below the highest accepted whose arrival is still remembered.
const WINDOW: u64 = 64;

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
}

fn is_zero(window: &u64) -> bool {
    *window == 0
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
        return match seen.previous {
            Some(previous) if previous.epoch == incoming.epoch && incoming.seq <= previous.seq => {
                SequenceCheck::Replay
            }
            _ => SequenceCheck::NewEpoch,
        };
    }
    match incoming.seq {
        seq if seq == seen.last.seq => SequenceCheck::Replay,
        seq if seq > seen.last.seq + 1 => SequenceCheck::Gap {
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
            window: 0,
            previous: None,
        });
        return;
    };
    if state.last.epoch != incoming.epoch {
        *seen = Some(Seen {
            last: incoming,
            window: 0,
            // Where the epoch just left behind had got to, so that
            // numbering cannot come back to it.
            previous: Some(state.last),
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
