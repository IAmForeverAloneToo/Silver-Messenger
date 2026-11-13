//! Telling a typed line from a pasted one, for the paste guard
//! ([`App::typed_it_themselves`](super::App)).
//!
//! A terminal without bracketed paste — the Linux console, older Windows
//! consoles, some multiplexer setups — hands a paste over as ordinary
//! keystrokes, so a pasted `hello\r/revoke confirm\r` runs the command
//! and its confirmation in one go. What tells the two apart is when the
//! keys *arrived*, so each one is stamped by the input thread as it is
//! read, before anything else happens to it.
//!
//! The guard this replaces timed the line from its first key to the line
//! being handled and compared that with the length of the trimmed text.
//! Both halves were wrong. Spaces padding a pasted command cost handling
//! time and counted for nothing once trimmed, so twenty thousand of them
//! made any paste look typed; and handling time is not arrival time, so
//! one slow frame did the same. Here nothing is trimmed and nothing is
//! timed from the handling side: a line is judged by the gaps between
//! the keys that built it and by which of them came in one read.

use std::time::{Duration, Instant};

/// When a key event was read, and which read it came in.
///
/// `burst` counts the times the input thread had nothing waiting and had
/// to wait for the terminal: every event read without waiting shares the
/// number of the one before it. A person's keys each wake the thread on
/// their own; a paste is one write by the terminal, read in one go.
#[derive(Clone, Copy, Debug)]
pub struct Arrival {
    pub at: Instant,
    pub burst: u64,
}

/// Two keys this close together were not two presses of a finger. Key
/// repeat is thirty-odd milliseconds a key, two keys rolled together
/// by a fast typist ten or more; a paste is microseconds a key.
const PASTE_GAP: Duration = Duration::from_millis(3);
/// This many such gaps in a row is a paste even when every key came in a
/// read of its own, as from a terminal that feeds a paste out slowly.
/// Short enough that five keys of a command are caught, long enough that
/// a key or two bunched up by a busy machine is not.
const FAST_RUN: usize = 4;

/// The timing of the line being typed.
#[derive(Debug, Default)]
pub(super) struct LineTiming {
    /// The key before this one, whichever line it belonged to: a line
    /// whose first key came in the same read as the Enter that ended the
    /// line before it is the second line of one paste.
    last: Option<Arrival>,
    /// Keys in this line so far, nothing trimmed.
    keys: usize,
    /// Consecutive gaps under [`PASTE_GAP`] ending at the last key, and
    /// whether a run of [`FAST_RUN`] has been seen in this line.
    fast_run: usize,
    rushed: bool,
    /// The last key shares its read with the key before it, in this line.
    same_read: bool,
    /// Something was pasted into the line (bracketed paste, the system
    /// clipboard), or the line began in the read that ended another.
    pasted: bool,
}

impl LineTiming {
    /// A new line begins with the next key: the input is empty.
    pub(super) fn start(&mut self) {
        self.keys = 0;
        self.fast_run = 0;
        self.rushed = false;
        self.same_read = false;
        self.pasted = false;
    }

    /// A key arrived for the line.
    pub(super) fn key(&mut self, at: Arrival) {
        let same_read = self.last.is_some_and(|last| last.burst == at.burst);
        if self.keys == 0 {
            // A line typed after another starts after a pause; one that
            // starts in the very read that ended the last was in the
            // same paste.
            self.pasted |= same_read;
        } else {
            let gap = self.last.map_or(Duration::MAX, |last| {
                at.at.saturating_duration_since(last.at)
            });
            self.fast_run = if gap <= PASTE_GAP {
                self.fast_run + 1
            } else {
                0
            };
            self.rushed |= self.fast_run >= FAST_RUN;
        }
        self.same_read = self.keys > 0 && same_read;
        self.keys += 1;
        self.last = Some(at);
    }

    /// Text went into the line all at once, as a paste: bracketed paste,
    /// or the system clipboard. That is pasted whatever the timing says.
    pub(super) fn paste(&mut self) {
        self.pasted = true;
    }

    /// Whether the line the last key ended was pasted; the next key
    /// starts a new one.
    ///
    /// Pasted when anything went into it as a paste, when it began in the
    /// read that ended the line before, when the key that ends it came
    /// in one read with the key before it — a line and its newline
    /// delivered together — or when [`FAST_RUN`] gaps in a row were
    /// shorter than a finger makes. Padding only adds more fast keys, and
    /// how long the app took over them does not enter into it.
    pub(super) fn judge(&mut self) -> bool {
        let pasted = self.pasted || self.same_read || self.rushed;
        self.start();
        pasted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds keys to a line: `gap` apart, `per_read` of them to a read.
    struct Keyboard {
        at: Instant,
        burst: u64,
        in_read: usize,
    }

    impl Keyboard {
        fn new() -> Self {
            Self {
                at: Instant::now(),
                burst: 0,
                in_read: 0,
            }
        }

        fn type_into(
            &mut self,
            line: &mut LineTiming,
            text: &str,
            gap: Duration,
            per_read: usize,
        ) -> bool {
            for _ in text.chars() {
                self.press(line, gap, per_read);
            }
            // The Enter that ends it, under the same conditions.
            self.press(line, gap, per_read);
            line.judge()
        }

        fn press(&mut self, line: &mut LineTiming, gap: Duration, per_read: usize) {
            self.at += gap;
            if self.in_read == 0 || self.in_read >= per_read {
                self.burst += 1;
                self.in_read = 0;
            }
            self.in_read += 1;
            line.key(Arrival {
                at: self.at,
                burst: self.burst,
            });
        }

        /// A pause before the next key, as between a person's lines.
        fn pause(&mut self) {
            self.at += Duration::from_secs(2);
            self.in_read = 0;
        }
    }

    const TYPED: Duration = Duration::from_millis(90);
    const PASTE: Duration = Duration::from_micros(2);

    #[test]
    fn a_typed_line_is_typed() {
        let mut line = LineTiming::default();
        let mut kb = Keyboard::new();
        assert!(!kb.type_into(&mut line, "/devices link confirm", TYPED, 1));
        kb.pause();
        // A fast typist on a busy machine: a key or two bunched into one
        // read now and then, and runs of quick keys short of a paste.
        assert!(!kb.type_into(&mut line, "/ve", Duration::from_millis(1), 1));
        kb.pause();
        let mut line = LineTiming::default();
        for (i, _) in "/verify".chars().enumerate() {
            kb.press(&mut line, TYPED, if i == 3 { 2 } else { 1 });
        }
        kb.press(&mut line, TYPED, 1);
        assert!(
            !line.judge(),
            "two keys in one read mid-line are not a paste"
        );
    }

    /// The finding this module answers: a pasted command padded with
    /// twenty thousand spaces either side, which the old guard trimmed
    /// away and then timed against what was left.
    #[test]
    fn a_paste_padded_with_spaces_is_still_a_paste() {
        let padded = format!(
            "{}/devices link confirm{}",
            " ".repeat(20_000),
            " ".repeat(20_000)
        );
        // As a terminal delivers it: a kilobyte or so to a read.
        let mut line = LineTiming::default();
        assert!(Keyboard::new().type_into(&mut line, &padded, PASTE, 1024));
        // And as one that feeds it out a key to a read, still far faster
        // than fingers: the gaps alone give it away.
        let mut line = LineTiming::default();
        assert!(Keyboard::new().type_into(&mut line, &padded, PASTE, 1));
    }

    /// Handling time does not enter into it: a paste whose keys were
    /// stamped as they arrived is a paste however long the app then took
    /// to draw a frame per key and get round to judging it.
    #[test]
    fn a_slow_frame_does_not_make_a_paste_look_typed() {
        let mut line = LineTiming::default();
        let mut kb = Keyboard::new();
        for _ in "/rotate".chars() {
            kb.press(&mut line, PASTE, 4096);
            std::thread::sleep(Duration::from_millis(2));
        }
        kb.press(&mut line, PASTE, 4096);
        std::thread::sleep(Duration::from_millis(50));
        assert!(line.judge());
    }

    /// `hello\r/rotate\r` in one paste: the second line is short and its
    /// Enter could even have come in a read of its own, but it began in
    /// the read that ended the first.
    #[test]
    fn a_line_begun_in_the_read_that_ended_another_is_pasted() {
        let mut line = LineTiming::default();
        let mut kb = Keyboard::new();
        assert!(kb.type_into(&mut line, "hello", PASTE, 4096));
        kb.press(&mut line, PASTE, 4096);
        // The rest of the paste reaches the thread in reads of its own.
        kb.in_read = 0;
        for _ in "rotate".chars() {
            kb.press(&mut line, TYPED, 1);
        }
        kb.press(&mut line, TYPED, 1);
        assert!(line.judge());
    }

    /// The line and the newline that sends it in one read is a paste
    /// however short: the Up arrow and Enter, pasted, would re-run the
    /// last command typed.
    #[test]
    fn a_line_and_its_newline_in_one_read_is_pasted() {
        let mut line = LineTiming::default();
        let mut kb = Keyboard::new();
        kb.pause();
        assert!(kb.type_into(&mut line, "x", TYPED, 2));
    }

    #[test]
    fn bracketed_paste_is_always_pasted_and_the_next_line_starts_clean() {
        let mut line = LineTiming::default();
        let mut kb = Keyboard::new();
        line.paste();
        kb.press(&mut line, TYPED, 1);
        assert!(line.judge());
        kb.pause();
        assert!(!kb.type_into(&mut line, "/verify ok", TYPED, 1));
    }
}
