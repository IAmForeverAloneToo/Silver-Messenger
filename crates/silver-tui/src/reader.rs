//! Reader mode's renderer (`docs/design/accessibility.md` section 3): a
//! screen reader needs whole lines arriving at the bottom of a scrolling
//! terminal, in order, with nothing decorative in them. So this prints
//! the app's journal, one event per line, and keeps the compose line last,
//! and that is all: no alternate screen, no box drawing, no attributes,
//! no cursor movement beyond the compose line. The terminal scrolls, and
//! the reader's review keys read what scrolled.

use std::io::{Stdout, Write, stdout};

use unicode_width::UnicodeWidthStr;

use crate::app::App;

pub struct Reader {
    out: Stdout,
    prompt: String,
    input: String,
    /// Columns from the start of the input to the cursor, as last shown.
    cursor: usize,
    started: bool,
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}

impl Reader {
    pub fn new() -> Self {
        Self {
            out: stdout(),
            prompt: String::new(),
            input: String::new(),
            cursor: 0,
            started: false,
        }
    }

    /// Print what happened since the last turn, then the compose line
    /// with the cursor where it is in the text; nothing when nothing
    /// changed. The compose line is erased with a carriage return and an
    /// erase-to-end, each event line ends in a newline, and the cursor is
    /// put back by moving left within the line, so the only movement that
    /// scrolls is the newline.
    pub fn flush(&mut self, app: &mut App) -> std::io::Result<()> {
        let lines = app.take_journal();
        let prompt = app.reader_prompt();
        let input = show(&app.input);
        let before: String = app.input.chars().take(app.cursor).collect();
        let cursor = show(&before).width();
        if self.started
            && lines.is_empty()
            && prompt == self.prompt
            && input == self.input
            && cursor == self.cursor
        {
            return Ok(());
        }
        let mut out = String::from("\r\x1b[K");
        for line in &lines {
            out.push_str(line);
            out.push_str("\r\n");
        }
        out.push_str(&prompt);
        out.push_str(&input);
        let after = input.width().saturating_sub(cursor);
        if after > 0 {
            out.push_str(&format!("\x1b[{after}D"));
        }
        self.out.write_all(out.as_bytes())?;
        self.out.flush()?;
        self.prompt = prompt;
        self.input = input;
        self.cursor = cursor;
        self.started = true;
        Ok(())
    }

    /// Leave the terminal on a fresh line, the compose line gone: what the
    /// journal still holds, then `Bye.` when the user quit (a lock or a
    /// wipe says its own word after this).
    pub fn finish(&mut self, app: &mut App, quitting: bool) -> std::io::Result<()> {
        let mut out = String::from("\r\x1b[K");
        for line in app.take_journal() {
            out.push_str(&line);
            out.push_str("\r\n");
        }
        if quitting {
            out.push_str("Bye.\r\n");
        }
        self.out.write_all(out.as_bytes())?;
        self.out.flush()
    }
}

/// The compose text as one line: a newline typed with Alt-Enter shows as
/// ` / `.
fn show(input: &str) -> String {
    input.replace('\n', " / ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newline_in_the_compose_text_shows_as_a_slash() {
        assert_eq!(show("one\ntwo"), "one / two");
        assert_eq!(show("plain"), "plain");
    }
}
