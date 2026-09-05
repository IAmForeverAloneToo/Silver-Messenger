//! The everyday privacy features' rules (`docs/design/everyday.md`,
//! `docs/PROTOCOL.md` section 4.7): who may edit or delete a message and
//! until when, when a disappearing message's clock runs out, and how a
//! timer is written and read. Pure functions over plain values, so the
//! terminal client, the store and the tests share one reading of them.

use std::fmt;

use silver_protocol::Content;
use silver_protocol::envelope::{MAX_TIMER_SECONDS, capability};

use crate::store::{Conversation, Direction, HistoryEntry, Store};

/// The in-body capability (`docs/PROTOCOL.md` 4.3) a reader needs for
/// `content`: `edits` for an edit or a deletion, `reactions` for a
/// reaction, `timers` for a timer; `None` for what every client reads,
/// a reply included. A sender uses a kind only towards a contact whose
/// last message advertised its capability, and in a group only when
/// every leaf declares the everyday extension type.
pub fn needs_capability(content: &Content) -> Option<&'static str> {
    match content {
        Content::Edit { .. } | Content::Delete { .. } => Some(capability::EDITS),
        Content::Reaction { .. } => Some(capability::REACTIONS),
        Content::Timer { .. } => Some(capability::TIMERS),
        _ => None,
    }
}

/// The capability `content` needs that `caps`, a contact's advertised
/// ones, lack: `None` when the content can go to them.
pub fn missing_capability(content: &Content, caps: &[String]) -> Option<&'static str> {
    needs_capability(content).filter(|needed| !caps.iter().any(|c| c == needed))
}

/// How long after sending a message its author may edit it or delete it
/// for everyone: a day.
pub const REVISION_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// How long a deletion is remembered for a message that has not arrived,
/// so a late arrival is dropped on arrival: a day.
pub const TOMBSTONE_MS: u64 = 24 * 60 * 60 * 1000;

/// Whether a message sent at `sent_at_ms` may still be edited or deleted
/// for everyone at `now_ms`: within [`REVISION_WINDOW_MS`] of sending. A
/// clock that went backwards counts as within.
pub fn may_revise(now_ms: u64, sent_at_ms: u64) -> bool {
    now_ms.saturating_sub(sent_at_ms) <= REVISION_WINDOW_MS
}

/// When a message with a disappearing-message timer goes: `timer_s`
/// after it was sent, for a sent message; `timer_s` after it was read,
/// for a received one, which is `None` until it is read. A timer of zero
/// is no timer.
pub fn expires_at(
    direction: Direction,
    timestamp_ms: u64,
    read_at_ms: Option<u64>,
    timer_s: u64,
) -> Option<u64> {
    if timer_s == 0 {
        return None;
    }
    let from = match direction {
        Direction::Sent => timestamp_ms,
        Direction::Received => read_at_ms?,
    };
    Some(from.saturating_add(timer_s.saturating_mul(1000)))
}

/// A timer as the user writes it: `off` or `0`, or a number with a unit
/// (`30s`, `5m`, `1h`, `8h`, `1d`, `1w`); a bare number is seconds. At
/// most a year.
pub fn parse_timer(text: &str) -> Result<u64, TimerError> {
    let text = text.trim().to_ascii_lowercase();
    if text.is_empty() {
        return Err(TimerError::Empty);
    }
    if matches!(text.as_str(), "off" | "none" | "never" | "0") {
        return Ok(0);
    }
    let (digits, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(at) => text.split_at(at),
        None => (text.as_str(), "s"),
    };
    let number: u64 = digits.parse().map_err(|_| TimerError::NotATimer)?;
    let unit_s: u64 = match unit.trim() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60 * 60,
        "d" | "day" | "days" => 24 * 60 * 60,
        "w" | "week" | "weeks" => 7 * 24 * 60 * 60,
        _ => return Err(TimerError::NotATimer),
    };
    let seconds = number.checked_mul(unit_s).ok_or(TimerError::TooLong)?;
    if seconds == 0 {
        return Ok(0);
    }
    if seconds > MAX_TIMER_SECONDS {
        return Err(TimerError::TooLong);
    }
    Ok(seconds)
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum TimerError {
    #[error("say how long: 30s, 5m, 1h, 8h, 1d, 1w, or off")]
    Empty,
    #[error("not a timer; say 30s, 5m, 1h, 8h, 1d, 1w, or off")]
    NotATimer,
    #[error("a timer is at most a year")]
    TooLong,
}

/// A timer as it is shown: `off`, or the largest whole unit that divides
/// it (`1 day`, `8 hours`, `90 seconds`).
pub fn describe_timer(seconds: u64) -> String {
    Timer(seconds).to_string()
}

/// [`describe_timer`] as a `Display`.
pub struct Timer(pub u64);

impl fmt::Display for Timer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        if s == 0 {
            return f.write_str("off");
        }
        for (unit, name) in [
            (7 * 24 * 60 * 60, "week"),
            (24 * 60 * 60, "day"),
            (60 * 60, "hour"),
            (60, "minute"),
        ] {
            if s % unit == 0 {
                let n = s / unit;
                return write!(f, "{n} {name}{}", if n == 1 { "" } else { "s" });
            }
        }
        write!(f, "{s} second{}", if s == 1 { "" } else { "s" })
    }
}

/// What the sweeper removed from one conversation.
#[derive(Clone, Debug)]
pub struct Swept {
    pub conversation: Conversation,
    /// The entries as they stood, so the caller can say what went and
    /// which saved files stay.
    pub entries: Vec<HistoryEntry>,
}

/// Remove, from every conversation in `store`, the messages whose timer
/// ran out by `now_ms` ([`expires_at`]); each goes as "delete for me"
/// does, rewritten out with a tombstone. Every device runs its own
/// sweeper from the same facts, so nothing is synced.
pub fn sweep_expired(store: &Store, now_ms: u64) -> anyhow::Result<Vec<Swept>> {
    let mut swept = Vec::new();
    for conversation in store.conversations()? {
        let due: Vec<String> = store
            .load_conversation(&conversation)?
            .into_iter()
            .filter(|e| e.expires_at_ms().is_some_and(|at| at <= now_ms))
            .map(|e| e.id)
            .collect();
        if due.is_empty() {
            continue;
        }
        let entries = store.remove_messages(&conversation, &due)?;
        swept.push(Swept {
            conversation,
            entries,
        });
    }
    Ok(swept)
}

/// How much of a timer is left at `now_ms`, for a status line: `2 hours
/// left`, `40 seconds left`, or `due` once it has run out.
pub fn time_left(expires_at_ms: u64, now_ms: u64) -> String {
    if expires_at_ms <= now_ms {
        return "due".to_owned();
    }
    let left_s = (expires_at_ms - now_ms).div_ceil(1000);
    for (unit, name) in [
        (7 * 24 * 60 * 60, "week"),
        (24 * 60 * 60, "day"),
        (60 * 60, "hour"),
        (60, "minute"),
    ] {
        if left_s >= unit {
            let n = left_s / unit;
            return format!("{n} {name}{} left", if n == 1 { "" } else { "s" });
        }
    }
    format!("{left_s} second{} left", if left_s == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kind_needs_the_capability_that_names_it() {
        let edit = Content::Edit {
            id: "1".into(),
            body: "x".into(),
        };
        let delete = Content::Delete {
            ids: vec!["1".into()],
        };
        let reaction = Content::Reaction {
            id: "1".into(),
            emoji: "👍".into(),
        };
        let timer = Content::Timer { seconds: 60 };
        let reply = Content::Text {
            body: "yes".into(),
            reply_to: Some("1".into()),
        };
        assert_eq!(needs_capability(&edit), Some("edits"));
        assert_eq!(needs_capability(&delete), Some("edits"));
        assert_eq!(needs_capability(&reaction), Some("reactions"));
        assert_eq!(needs_capability(&timer), Some("timers"));
        assert_eq!(needs_capability(&reply), None);
        assert_eq!(needs_capability(&Content::text("plain")), None);

        let older: Vec<String> = vec!["receipts".into(), "files".into()];
        let current: Vec<String> = crate::CAPABILITIES
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        assert_eq!(missing_capability(&edit, &older), Some("edits"));
        assert_eq!(missing_capability(&reaction, &older), Some("reactions"));
        assert_eq!(missing_capability(&timer, &older), Some("timers"));
        assert_eq!(missing_capability(&reply, &older), None);
        for content in [edit, delete, reaction, timer, reply] {
            assert_eq!(missing_capability(&content, &current), None);
        }
    }

    #[test]
    fn a_message_is_revised_within_a_day_of_sending() {
        assert!(may_revise(1_000, 1_000));
        assert!(may_revise(1_000 + REVISION_WINDOW_MS, 1_000));
        assert!(!may_revise(1_001 + REVISION_WINDOW_MS, 1_000));
        // A clock that went backwards is not a reason to refuse.
        assert!(may_revise(500, 1_000));
    }

    #[test]
    fn the_clock_runs_from_sending_or_from_reading() {
        assert_eq!(expires_at(Direction::Sent, 10_000, None, 60), Some(70_000));
        assert_eq!(
            expires_at(Direction::Sent, 10_000, Some(20_000), 60),
            Some(70_000),
            "a sent message goes by when it was sent, whatever else happened"
        );
        assert_eq!(expires_at(Direction::Received, 10_000, None, 60), None);
        assert_eq!(
            expires_at(Direction::Received, 10_000, Some(20_000), 60),
            Some(80_000)
        );
        assert_eq!(expires_at(Direction::Sent, 10_000, None, 0), None);
        assert_eq!(
            expires_at(Direction::Sent, u64::MAX - 5, None, MAX_TIMER_SECONDS),
            Some(u64::MAX)
        );
    }

    #[test]
    fn timers_are_read_and_written_in_units() {
        for (text, seconds) in [
            ("off", 0),
            ("OFF", 0),
            ("none", 0),
            ("0", 0),
            ("0m", 0),
            ("30s", 30),
            ("30", 30),
            ("5m", 300),
            ("5 min", 300),
            ("1h", 3600),
            ("8 hours", 8 * 3600),
            ("1d", 86_400),
            ("1w", 7 * 86_400),
            ("52w", 52 * 7 * 86_400),
        ] {
            assert_eq!(parse_timer(text), Ok(seconds), "{text}");
        }
        assert_eq!(parse_timer(""), Err(TimerError::Empty));
        assert_eq!(parse_timer("soon"), Err(TimerError::NotATimer));
        assert_eq!(parse_timer("5x"), Err(TimerError::NotATimer));
        assert_eq!(parse_timer("-5m"), Err(TimerError::NotATimer));
        assert_eq!(parse_timer("53w"), Err(TimerError::TooLong));
        assert_eq!(
            parse_timer("99999999999999999999d"),
            Err(TimerError::NotATimer)
        );
        assert_eq!(
            parse_timer("18446744073709551615d"),
            Err(TimerError::TooLong)
        );

        assert_eq!(describe_timer(0), "off");
        assert_eq!(describe_timer(1), "1 second");
        assert_eq!(describe_timer(90), "90 seconds");
        assert_eq!(describe_timer(300), "5 minutes");
        assert_eq!(describe_timer(3600), "1 hour");
        assert_eq!(describe_timer(8 * 3600), "8 hours");
        assert_eq!(describe_timer(86_400), "1 day");
        assert_eq!(describe_timer(14 * 86_400), "2 weeks");
    }

    #[test]
    fn the_sweeper_removes_what_is_due_and_leaves_the_unread() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let peer = silver_protocol::Identity::generate().user_id();
        let group = silver_protocol::GroupId::generate();
        let with_timer = |mut e: HistoryEntry, s: u64| {
            e.expire_after_s = s;
            e
        };
        // Sent at 1000 with a minute: due at 61 000.
        store
            .append_history(
                &peer,
                &with_timer(HistoryEntry::new("s1", Direction::Sent, 1_000, "sent"), 60),
            )
            .unwrap();
        // Received, never read: never due.
        store
            .append_history(
                &peer,
                &with_timer(
                    HistoryEntry::new("r1", Direction::Received, 1_000, "unread"),
                    60,
                ),
            )
            .unwrap();
        // Received and read at 50 000: due at 110 000.
        store
            .append_history(
                &peer,
                &with_timer(
                    HistoryEntry::new("r2", Direction::Received, 1_000, "read"),
                    60,
                ),
            )
            .unwrap();
        store
            .append_read(&Conversation::Contact(peer), &["r2".into()], 50_000)
            .unwrap();
        // No timer: stays whatever the clock says.
        store
            .append_history(
                &peer,
                &HistoryEntry::new("s2", Direction::Sent, 1_000, "kept"),
            )
            .unwrap();
        // In a group, sent at 1000 with ten seconds: due at 11 000.
        store
            .append_group_history(
                &group,
                &with_timer(HistoryEntry::new("g1", Direction::Sent, 1_000, "group"), 10),
            )
            .unwrap();

        assert!(sweep_expired(&store, 10_999).unwrap().is_empty());
        let swept = sweep_expired(&store, 61_000).unwrap();
        let mut gone: Vec<(Conversation, String)> = swept
            .iter()
            .flat_map(|s| {
                s.entries
                    .iter()
                    .map(move |e| (s.conversation, e.id.clone()))
            })
            .collect();
        gone.sort_by_key(|(_, id)| id.clone());
        assert_eq!(
            gone,
            vec![
                (Conversation::Group(group), "g1".to_owned()),
                (Conversation::Contact(peer), "s1".to_owned()),
            ]
        );
        let left: Vec<String> = store
            .load_history(&peer)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(left, ["r1", "r2", "s2"]);
        assert!(store.load_group_history(&group).unwrap().is_empty());
        let swept = sweep_expired(&store, 110_000).unwrap();
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0].entries[0].id, "r2");
        assert!(sweep_expired(&store, u64::MAX).unwrap().is_empty());
        let left: Vec<String> = store
            .load_history(&peer)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(left, ["r1", "s2"], "the unread and the untimed stay");
    }

    #[test]
    fn what_is_left_is_said_in_the_largest_unit() {
        assert_eq!(time_left(5_000, 5_000), "due");
        assert_eq!(time_left(5_000, 6_000), "due");
        assert_eq!(time_left(6_000, 5_000), "1 second left");
        assert_eq!(time_left(5_000 + 90_000, 5_000), "1 minute left");
        assert_eq!(time_left(5_000 + 7_200_000, 5_000), "2 hours left");
        assert_eq!(time_left(5_000 + 3 * 86_400_000, 5_000), "3 days left");
        assert_eq!(time_left(5_000 + 21 * 86_400_000, 5_000), "3 weeks left");
        assert_eq!(time_left(5_000 + 999, 5_000), "1 second left", "rounded up");
    }
}
