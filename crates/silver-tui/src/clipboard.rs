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
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::Duration;

use base64::Engine;

/// How long the system clipboard has to answer when the client starts.
/// Connecting is quick or never: under WSL a display that is set but has
/// nothing behind it, or a Wayland compositor without the data-control
/// protocol, used to hold the client at start for good.
const OPEN_WAIT: Duration = Duration::from_secs(2);
/// How long a read or a write has to come back once connected.
const CALL_WAIT: Duration = Duration::from_secs(1);

/// Where a copied text ended up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Copied {
    /// The operating system's clipboard.
    System,
    /// The terminal, by escape sequence; it decides what to do with it.
    Terminal,
}

pub struct Clipboard {
    system: Option<Worker>,
}

enum Request {
    Get,
    Set(String),
}

enum Answer {
    Text(Option<String>),
    Set(bool),
}

/// The system clipboard, on a thread of its own: every call waits a
/// bounded time for it, and one that does not come back in time leaves
/// the clipboard aside for the rest of the run (copying then goes to the
/// terminal), rather than the whole client waiting with it.
struct Worker {
    requests: Sender<Request>,
    answers: Receiver<Answer>,
}

impl Worker {
    fn open() -> Option<Self> {
        let (ready_tx, ready_rx) = channel();
        let (requests, request_rx) = channel::<Request>();
        let (answer_tx, answers) = channel();
        thread::Builder::new()
            .name("clipboard".into())
            .spawn(move || {
                let mut system = match arboard::Clipboard::new() {
                    Ok(system) => system,
                    Err(_) => {
                        let _ = ready_tx.send(false);
                        return;
                    }
                };
                let _ = ready_tx.send(true);
                for request in request_rx {
                    let answer = match request {
                        Request::Get => Answer::Text(system.get_text().ok()),
                        Request::Set(text) => Answer::Set(system.set_text(text).is_ok()),
                    };
                    if answer_tx.send(answer).is_err() {
                        return;
                    }
                }
            })
            .ok()?;
        // A thread still stuck connecting is left to it: it holds nothing.
        matches!(ready_rx.recv_timeout(OPEN_WAIT), Ok(true)).then_some(Self { requests, answers })
    }

    fn call(&self, request: Request) -> Option<Answer> {
        self.requests.send(request).ok()?;
        self.answers.recv_timeout(CALL_WAIT).ok()
    }
}

impl Clipboard {
    /// Connect to the system clipboard if there is one and it answers;
    /// otherwise copying falls back to the terminal and pasting to what
    /// the terminal sends.
    pub fn new() -> Self {
        // Tests leave the clipboard of whoever runs them alone.
        if cfg!(test) {
            return Self { system: None };
        }
        Self {
            system: Worker::open(),
        }
    }

    /// Whether pasting can read the system clipboard.
    pub fn can_read(&self) -> bool {
        self.system.is_some()
    }

    /// The clipboard's text, if it has any.
    pub fn get(&mut self) -> Option<String> {
        match self.system.as_ref()?.call(Request::Get) {
            Some(Answer::Text(text)) => text.filter(|text| !text.is_empty()),
            _ => {
                self.system = None; // it did not answer: not asked again
                None
            }
        }
    }

    /// Put `text` on the clipboard.
    ///
    /// Filtered first: a message is the sender's to write, and what goes
    /// on the clipboard is pasted into a shell as often as into a text
    /// box. Without this a message reading `ok\rcurl … | sh\r`, copied
    /// with /copy or Ctrl-C, runs on the first Enter after the paste —
    /// and by OSC 52 it reaches the *local* terminal through SSH or tmux,
    /// which is a machine this program is not even running on. Line
    /// breaks are kept; nothing else that moves a cursor is.
    pub fn set(&mut self, text: &str) -> Copied {
        let text = &silver_client::files::safe_text(text);
        if let Some(system) = &self.system {
            match system.call(Request::Set(text.to_owned())) {
                Some(Answer::Set(true)) => return Copied::System,
                Some(_) => {}
                None => self.system = None,
            }
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(text);
        let mut out = stdout();
        let _ = write!(out, "\x1b]52;c;{encoded}\x07");
        let _ = out.flush();
        Copied::Terminal
    }
}
