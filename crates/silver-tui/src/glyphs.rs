//! The symbols the interface draws, in Unicode or in ASCII for terminals
//! whose fonts lack them. The classic Windows console shows the check marks
//! as boxes with its default fonts; the Linux virtual console has no glyphs
//! for them at all. Everything else (box drawing, the half blocks of the QR
//! code, the ellipsis and the middle dot) is in every monospace font that
//! ships with an operating system.

/// Which symbol set to use, from the config or the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marks {
    /// Decide from the terminal at hand.
    Auto,
    Unicode,
    Ascii,
}

impl Marks {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "unicode" | "utf8" | "utf-8" => Some(Self::Unicode),
            "ascii" | "plain" => Some(Self::Ascii),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Unicode => "unicode",
            Self::Ascii => "ascii",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Glyphs {
    pub ascii: bool,
    /// A sent message the relay has not accepted yet.
    pub pending: &'static str,
    /// The relay accepted it.
    pub accepted: &'static str,
    /// It reached the contact's device (in colour: they read it).
    pub delivered: &'static str,
    /// The relay refused it for good.
    pub failed: &'static str,
    /// A contact whose safety number was compared.
    pub verified: &'static str,
    pub connecting: &'static str,
    pub connected: &'static str,
    pub disconnected: &'static str,
    /// Rows below the visible part of the chat.
    pub more_below: &'static str,
    /// Where a received file was saved.
    pub arrow: &'static str,
    /// The quote of the message a reply answers.
    pub reply: &'static str,
    /// A message with a disappearing-message timer.
    pub timer: &'static str,
}

pub const UNICODE: Glyphs = Glyphs {
    ascii: false,
    pending: "⋯",
    accepted: "✓",
    delivered: "✓✓",
    failed: "✗",
    verified: "✓",
    connecting: "◌",
    connected: "●",
    disconnected: "○",
    more_below: "↓",
    arrow: "→",
    reply: "↳",
    timer: "⧖",
};

pub const ASCII: Glyphs = Glyphs {
    ascii: true,
    pending: "..",
    accepted: "v",
    delivered: "vv",
    failed: "x",
    verified: "v",
    connecting: "~",
    connected: "*",
    disconnected: "o",
    more_below: "v",
    arrow: "->",
    reply: ">",
    timer: "~",
};

impl Glyphs {
    /// The set to draw with, deciding from the environment when asked to.
    pub fn for_marks(marks: Marks) -> Self {
        match marks {
            Marks::Unicode => UNICODE,
            Marks::Ascii => ASCII,
            Marks::Auto => {
                if ascii_is_safer(cfg!(windows), |name| std::env::var(name).ok()) {
                    ASCII
                } else {
                    UNICODE
                }
            }
        }
    }
}

/// Terminals that set one of these are known to have the glyphs.
const CAPABLE_TERMINAL_VARS: &[&str] = &[
    "WT_SESSION",          // Windows Terminal
    "TERM_PROGRAM",        // iTerm2, Terminal.app, VS Code, WezTerm, mintty, Hyper, ...
    "ConEmuANSI",          // ConEmu and cmder
    "ALACRITTY_WINDOW_ID", // Alacritty
    "KITTY_WINDOW_ID",     // kitty
    "WEZTERM_EXECUTABLE",  // WezTerm
    "VTE_VERSION",         // GNOME Terminal and other VTE terminals
    "KONSOLE_VERSION",     // Konsole
    "TMUX",                // tmux only runs inside a terminal of its own
];

/// Whether the terminal, judged from the environment alone, is likelier to
/// lack the Unicode marks than to have them.
///
/// On Windows the classic console is the default host and its fonts lack
/// the marks, so ASCII is used there unless a terminal known to be capable
/// announced itself. Elsewhere only the Linux virtual console and an
/// explicitly non-UTF-8 locale count against Unicode.
fn ascii_is_safer(windows: bool, env: impl Fn(&str) -> Option<String>) -> bool {
    if CAPABLE_TERMINAL_VARS
        .iter()
        .any(|name| env(name).is_some_and(|v| !v.is_empty()))
    {
        return false;
    }
    if windows {
        return true;
    }
    if env("TERM").is_some_and(|t| t == "linux") {
        return true;
    }
    let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|name| env(name).filter(|v| !v.is_empty()));
    match locale {
        Some(locale) => !locale
            .to_ascii_lowercase()
            .replace('-', "")
            .contains("utf8"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn windows_console_gets_ascii_but_windows_terminal_does_not() {
        assert!(ascii_is_safer(true, env(&[])));
        assert!(!ascii_is_safer(true, env(&[("WT_SESSION", "abc")])));
        assert!(!ascii_is_safer(true, env(&[("ConEmuANSI", "ON")])));
        assert!(!ascii_is_safer(true, env(&[("TERM_PROGRAM", "mintty")])));
    }

    #[test]
    fn unix_terminals_get_unicode_unless_the_console_or_locale_says_otherwise() {
        assert!(!ascii_is_safer(false, env(&[("TERM", "xterm-256color")])));
        assert!(!ascii_is_safer(false, env(&[])));
        assert!(ascii_is_safer(false, env(&[("TERM", "linux")])));
        assert!(ascii_is_safer(
            false,
            env(&[("TERM", "xterm"), ("LANG", "C")])
        ));
        assert!(!ascii_is_safer(
            false,
            env(&[("TERM", "xterm"), ("LANG", "C.UTF-8")])
        ));
        assert!(!ascii_is_safer(
            false,
            env(&[("LC_ALL", "en_US.utf8"), ("LANG", "C")])
        ));
        // A capable terminal wins over a bare TERM.
        assert!(!ascii_is_safer(
            false,
            env(&[("TERM", "linux"), ("VTE_VERSION", "7000")])
        ));
    }

    #[test]
    fn marks_parse_and_print() {
        assert_eq!(Marks::parse("ASCII"), Some(Marks::Ascii));
        assert_eq!(Marks::parse("utf-8"), Some(Marks::Unicode));
        assert_eq!(Marks::parse("auto").map(Marks::as_str), Some("auto"));
        assert_eq!(Marks::parse("emoji"), None);
        assert!(Glyphs::for_marks(Marks::Ascii).ascii);
        assert!(!Glyphs::for_marks(Marks::Unicode).ascii);
    }
}
