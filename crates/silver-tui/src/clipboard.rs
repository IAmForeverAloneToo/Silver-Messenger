//! The system clipboard, read and written by the client itself.
//!
//! Terminals differ in what they do with `Ctrl-V`, `Shift-Insert` and a
//! right click once an application has taken the mouse, and the classic
//! Windows console does nothing at all. Reading the clipboard directly
//! (through the OS on Windows, macOS, X11 and Wayland) makes paste work the
//! same everywhere. For copying, a terminal reached over SSH or inside
//! tmux has no clipboard of its own, so the text is handed to the terminal
//! with OSC 52, which most terminals forward to the clipboard of the
//! machine they run on.

use std::io::{Write, stdout};

use base64::Engine;

/// Where a copied text ended up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Copied {
    /// The operating system's clipboard.
    System,
    /// The terminal, by escape sequence; it decides what to do with it.
    Terminal,
}

pub struct Clipboard {
    system: Option<arboard::Clipboard>,
}

impl Clipboard {
    /// Connect to the system clipboard if there is one; otherwise copying
    /// falls back to the terminal and pasting to what the terminal sends.
    pub fn new() -> Self {
        Self {
            system: arboard::Clipboard::new().ok(),
        }
    }

    /// Whether pasting can read the system clipboard.
    pub fn can_read(&self) -> bool {
        self.system.is_some()
    }

    /// The clipboard's text, if it has any.
    pub fn get(&mut self) -> Option<String> {
        self.system
            .as_mut()?
            .get_text()
            .ok()
            .filter(|text| !text.is_empty())
    }

    /// Put `text` on the clipboard.
    pub fn set(&mut self, text: &str) -> Copied {
        if let Some(system) = &mut self.system
            && system.set_text(text.to_owned()).is_ok()
        {
            return Copied::System;
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(text);
        let mut out = stdout();
        let _ = write!(out, "\x1b]52;c;{encoded}\x07");
        let _ = out.flush();
        Copied::Terminal
    }
}
