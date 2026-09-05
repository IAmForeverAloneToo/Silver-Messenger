//! The terminal, entered and left by the client itself
//! (`docs/design/robustness.md` section 3). What was set up is recorded,
//! so the panic hook can undo exactly that before the message prints:
//! the full mode's raw mode, alternate screen, mouse capture, paste and
//! focus reports and pushed title, or reader mode's raw mode and reports.

use std::io::{Write, stdout};
use std::sync::atomic::{AtomicU8, Ordering};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    DisableBracketedPaste, DisableFocusChange, DisableMouseCapture, EnableBracketedPaste,
    EnableFocusChange, EnableMouseCapture,
};
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::crossterm::{execute, queue};
use ratatui::{DefaultTerminal, Terminal};

/// What the terminal was put into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// The shell's own terminal: nothing to undo.
    Plain = 0,
    /// The full screen with the mouse captured.
    Full = 1,
    /// The full screen, the mouse left to the terminal.
    FullNoMouse = 2,
    /// Reader mode: raw mode and the reports only.
    Reader = 3,
}

impl Mode {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Full,
            2 => Self::FullNoMouse,
            3 => Self::Reader,
            _ => Self::Plain,
        }
    }
}

/// The mode in force, for the hook.
static MODE: AtomicU8 = AtomicU8::new(Mode::Plain as u8);

/// Push the window title so it can be put back on exit (xterm and most
/// others; the rest ignore it), and pop it.
const PUSH_TITLE: &str = "\x1b[22;2t";
const POP_TITLE: &str = "\x1b[23;2t";

/// Install, once, the hook that leaves the terminal as it was before the
/// panic message prints. The hook installed before it (the default one,
/// which prints the message) runs after.
pub fn install_panic_hook() {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        leave();
        hook(info);
    }));
}

/// The full mode: raw mode, the alternate screen, paste and focus
/// reports, the title saved, and the mouse captured unless `mouse` is
/// off.
pub fn enter_full(mouse: bool) -> std::io::Result<DefaultTerminal> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    // Best effort: a terminal that lacks one of these just ignores it.
    let _ = execute!(out, EnableBracketedPaste, EnableFocusChange);
    let _ = out
        .write_all(PUSH_TITLE.as_bytes())
        .and_then(|()| out.flush());
    if mouse {
        let _ = execute!(out, EnableMouseCapture);
    }
    MODE.store(
        if mouse { Mode::Full } else { Mode::FullNoMouse } as u8,
        Ordering::SeqCst,
    );
    Terminal::new(CrosstermBackend::new(out))
}

/// Reader mode: raw mode for the keys, paste and focus reports, and
/// nothing else; the screen is the terminal's own scrollback.
pub fn enter_reader() -> std::io::Result<()> {
    enable_raw_mode()?;
    let _ = execute!(stdout(), EnableBracketedPaste, EnableFocusChange);
    MODE.store(Mode::Reader as u8, Ordering::SeqCst);
    Ok(())
}

/// Undo whatever mode is in force; nothing when none is, so it is safe
/// to call twice (the normal exit, then a hook).
pub fn leave() {
    let mode = Mode::from_u8(MODE.swap(Mode::Plain as u8, Ordering::SeqCst));
    if mode == Mode::Plain {
        return;
    }
    let mut out = stdout();
    let _ = leaving(mode, &mut out);
    let _ = out.flush();
    let _ = disable_raw_mode();
}

/// What leaving `mode` writes, in the order that undoes entering it: the
/// mouse, the reports, the title, the alternate screen.
fn leaving(mode: Mode, out: &mut impl Write) -> std::io::Result<()> {
    match mode {
        Mode::Plain => {}
        Mode::Full | Mode::FullNoMouse => {
            if mode == Mode::Full {
                queue!(out, DisableMouseCapture)?;
            }
            queue!(out, DisableFocusChange, DisableBracketedPaste)?;
            out.write_all(POP_TITLE.as_bytes())?;
            queue!(out, LeaveAlternateScreen)?;
        }
        Mode::Reader => queue!(out, DisableFocusChange, DisableBracketedPaste)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(mode: Mode) -> String {
        let mut out = Vec::new();
        leaving(mode, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn leaving_undoes_what_each_mode_set_up() {
        let full = written(Mode::Full);
        for (seq, what) in [
            ("\x1b[?1000l", "the mouse"),
            ("\x1b[?1004l", "focus reports"),
            ("\x1b[?2004l", "bracketed paste"),
            (POP_TITLE, "the title"),
            ("\x1b[?1049l", "the alternate screen"),
        ] {
            assert!(full.contains(seq), "the full mode leaves {what}");
        }
        assert!(
            full.find("\x1b[?1000l") < full.find("\x1b[?1049l"),
            "the mouse goes before the screen"
        );
        let no_mouse = written(Mode::FullNoMouse);
        assert!(!no_mouse.contains("\x1b[?1000l") && no_mouse.contains("\x1b[?1049l"));
        let reader = written(Mode::Reader);
        assert!(reader.contains("\x1b[?1004l") && reader.contains("\x1b[?2004l"));
        assert!(
            !reader.contains("\x1b[?1049")
                && !reader.contains("\x1b[?1000")
                && !reader.contains(POP_TITLE),
            "reader mode never used the screen, the mouse or the title"
        );
        assert!(written(Mode::Plain).is_empty());
    }

    #[test]
    fn modes_round_trip_through_the_static() {
        for mode in [Mode::Plain, Mode::Full, Mode::FullNoMouse, Mode::Reader] {
            assert_eq!(Mode::from_u8(mode as u8), mode);
        }
    }
}
