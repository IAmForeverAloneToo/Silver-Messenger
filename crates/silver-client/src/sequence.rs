//! Checking incoming sequence numbers against what a contact sent before.

use silver_protocol::Sequence;

/// What an incoming message's sequence number says about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceCheck {
    /// The next message in order.
    Fresh,
    /// The sender started counting from scratch (a fresh installation).
    NewEpoch,
    /// Already seen, or older than what we have: a replay. Drop it.
    Replay,
    /// Later than expected; this many earlier messages have not arrived.
    Gap { missing: u64 },
    /// The sender does not number messages (an older client). Unchecked.
    Legacy,
}

/// Compare `incoming` with the last sequence accepted from the same sender.
pub fn check(last: Option<Sequence>, incoming: Sequence) -> SequenceCheck {
    if incoming.seq == 0 {
        return SequenceCheck::Legacy;
    }
    match last {
        None => SequenceCheck::Fresh,
        Some(last) if last.epoch != incoming.epoch => SequenceCheck::NewEpoch,
        Some(last) if incoming.seq <= last.seq => SequenceCheck::Replay,
        Some(last) if incoming.seq > last.seq + 1 => SequenceCheck::Gap {
            missing: incoming.seq - last.seq - 1,
        },
        Some(_) => SequenceCheck::Fresh,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(epoch: u64, seq: u64) -> Sequence {
        Sequence { epoch, seq }
    }

    #[test]
    fn classifies_sequences() {
        assert_eq!(check(None, s(7, 1)), SequenceCheck::Fresh);
        assert_eq!(check(Some(s(7, 1)), s(7, 2)), SequenceCheck::Fresh);
        assert_eq!(check(Some(s(7, 2)), s(7, 2)), SequenceCheck::Replay);
        assert_eq!(check(Some(s(7, 5)), s(7, 3)), SequenceCheck::Replay);
        assert_eq!(
            check(Some(s(7, 2)), s(7, 5)),
            SequenceCheck::Gap { missing: 2 }
        );
        assert_eq!(check(Some(s(7, 9)), s(8, 1)), SequenceCheck::NewEpoch);
        assert_eq!(check(Some(s(7, 9)), s(0, 0)), SequenceCheck::Legacy);
        assert_eq!(check(None, Sequence::default()), SequenceCheck::Legacy);
    }
}
