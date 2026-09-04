//! Getting the user's attention through the terminal: the bell, desktop
//! notifications the terminal itself raises, and the unread count in the
//! window title.
//!
//! Everything here is an escape sequence written to stdout, so it works over
//! SSH and needs no platform code. A terminal that does not know a sequence
//! ignores it. Desktop notifications use OSC 777 (rxvt-unicode, WezTerm,
//! foot), OSC 9 (iTerm2, ConEmu, WezTerm) and OSC 99 (kitty), so most
//! terminals that can raise one do; the message never includes content.

use std::io::{Write, stdout};
use std::time::{Duration, Instant};

/// Announcements closer together than this are folded into the first.
const THROTTLE: Duration = Duration::from_secs(1);
const APP_TITLE: &str = "Silver Messenger";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyMode {
    /// Nothing audible or visible outside the window.
    Off,
    /// The terminal bell only.
    Bell,
    /// The bell plus a desktop notification when the terminal can raise one.
    All,
}

impl NotifyMode {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => Some(Self::Off),
            "bell" => Some(Self::Bell),
            "all" | "on" | "desktop" => Some(Self::All),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Bell => "bell",
            Self::All => "all",
        }
    }
}

pub struct Notifier {
    mode: NotifyMode,
    last: Option<Instant>,
    title_unread: Option<usize>,
}

impl Notifier {
    pub fn new(mode: NotifyMode) -> Self {
        Self {
            mode,
            last: None,
            title_unread: None,
        }
    }

    pub fn mode(&self) -> NotifyMode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: NotifyMode) {
        self.mode = mode;
    }

    /// Ring and, in `All` mode, raise a desktop notification with `summary`.
    /// Announcements within a second of the last are dropped so a burst of
    /// messages makes one noise.
    pub fn announce(&mut self, summary: &str) {
        if self.mode == NotifyMode::Off {
            return;
        }
        if self.last.is_some_and(|at| at.elapsed() < THROTTLE) {
            return;
        }
        self.last = Some(Instant::now());
        let mut out = String::from("\x07");
        if self.mode == NotifyMode::All {
            let text = sanitize(summary);
            out.push_str(&format!("\x1b]777;notify;{APP_TITLE};{text}\x1b\\"));
            out.push_str(&format!("\x1b]9;{APP_TITLE}: {text}\x1b\\"));
            out.push_str(&format!(
                "\x1b]99;i=silver:d=0:p=title;{APP_TITLE}\x1b\\\x1b]99;i=silver:d=1:p=body;{text}\x1b\\"
            ));
        }
        write_raw(&out);
    }

    /// Put the unread count in the window title; a no-op when unchanged.
    pub fn set_unread(&mut self, unread: usize) {
        if self.title_unread == Some(unread) {
            return;
        }
        self.title_unread = Some(unread);
        let title = if unread > 0 {
            format!("{APP_TITLE} ({unread})")
        } else {
            APP_TITLE.to_owned()
        };
        write_raw(&format!("\x1b]2;{title}\x1b\\"));
    }

    /// Save the terminal's title so it can be put back on exit.
    pub fn push_title(&self) {
        write_raw("\x1b[22;2t");
    }

    pub fn pop_title(&self) {
        write_raw("\x1b[23;2t");
    }
}

/// Keep a notification to printable text without the OSC separator.
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == ';' { ',' } else { c })
        .take(120)
        .collect()
}

fn write_raw(bytes: &str) {
    let mut out = stdout();
    let _ = out.write_all(bytes.as_bytes());
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_parse_and_print() {
        assert_eq!(NotifyMode::parse("OFF"), Some(NotifyMode::Off));
        assert_eq!(NotifyMode::parse("bell"), Some(NotifyMode::Bell));
        assert_eq!(NotifyMode::parse("all"), Some(NotifyMode::All));
        assert_eq!(NotifyMode::parse("loud"), None);
        assert_eq!(NotifyMode::All.as_str(), "all");
    }

    #[test]
    fn summaries_are_kept_printable() {
        assert_eq!(sanitize("a;b\x1bc\n"), "a,bc");
    }
}
