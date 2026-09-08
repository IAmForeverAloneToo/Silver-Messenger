//! Getting the user's attention: the bell, a desktop notification, and the
//! unread count in the window title.
//!
//! A notification says `New message` and nothing else, on every path: the
//! call that raises one takes no text, so no name, id, group or content
//! can reach one. Two paths raise it. The terminal's own, through escape
//! sequences it turns into a toast (OSC 777 for rxvt-unicode, WezTerm and
//! foot; OSC 9 for iTerm2, ConEmu and WezTerm; OSC 99 for kitty), which is
//! the only path that works over SSH; and the operating system's, for the
//! terminals that ignore those sequences, which are most of them. Which
//! path a run takes is decided once from the environment ([`Route`]);
//! `/notify terminal` and `/notify desktop` override it. The decisions are
//! in docs/design/notifications.md.

use std::io::{Write, stdout};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Announcements closer together than this are folded into the first.
const THROTTLE: Duration = Duration::from_secs(1);
/// After the operating system's path fails, how long before it is tried
/// again: a machine without a notification service must not spawn a
/// process, or open a bus connection, for every message.
const RETRY_AFTER: Duration = Duration::from_secs(600);
pub const APP_TITLE: &str = "Silver Messenger";
/// The whole text of every notification, on every path.
pub const TEXT: &str = "New message";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyMode {
    /// Nothing audible or visible outside the window.
    Off,
    /// The terminal bell only.
    Bell,
    /// The bell plus a desktop notification, by whichever path the
    /// terminal calls for ([`Route`]).
    All,
    /// The bell plus the terminal's own notification sequences, whatever
    /// the terminal is.
    Terminal,
    /// The bell plus a notification from the operating system, whatever
    /// the terminal is.
    Desktop,
}

impl NotifyMode {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => Some(Self::Off),
            "bell" => Some(Self::Bell),
            "all" | "on" => Some(Self::All),
            "terminal" => Some(Self::Terminal),
            "desktop" => Some(Self::Desktop),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Bell => "bell",
            Self::All => "all",
            Self::Terminal => "terminal",
            Self::Desktop => "desktop",
        }
    }

    pub const USAGE: &'static str = "all|terminal|desktop|bell|off";
}

/// Where a notification goes in `all` mode, decided once from the
/// environment. Section 3 of the design note is this table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// Write the terminal's notification sequences.
    pub terminal: bool,
    /// Ask the operating system.
    pub desktop: bool,
    /// Inside tmux: the sequences must be wrapped in its passthrough.
    pub tmux: bool,
}

impl Route {
    /// The route for this process.
    pub fn detect() -> Self {
        Self::from_env(cfg!(windows), |name| std::env::var(name).ok())
    }

    /// The route for an environment, `windows` saying which platform it
    /// is on. Pure, so the table can be tested row by row.
    pub fn from_env(windows: bool, env: impl Fn(&str) -> Option<String>) -> Self {
        let set = |name: &str| env(name).is_some_and(|v| !v.is_empty());
        let is = |name: &str, wanted: &[&str]| {
            env(name).is_some_and(|v| wanted.iter().any(|w| v.eq_ignore_ascii_case(w)))
        };
        let starts = |name: &str, prefix: &str| env(name).is_some_and(|v| v.starts_with(prefix));
        let tmux = set("TMUX");

        // Over SSH the desktop is on the other end of the connection: a
        // toast here is a toast nobody sees, whatever the terminal is.
        if set("SSH_CONNECTION") || set("SSH_CLIENT") || set("SSH_TTY") {
            return Self {
                terminal: true,
                desktop: false,
                tmux,
            };
        }
        // tmux hides the outer terminal, so a local session is treated as
        // an unrecognised terminal, with the sequences wrapped for it.
        if tmux {
            return Self {
                terminal: true,
                desktop: true,
                tmux: true,
            };
        }
        // Known to raise one of the sequences: those alone, or the desktop
        // shows the same notification twice.
        let raises = is("TERM_PROGRAM", &["iTerm.app", "WezTerm", "ghostty"])
            || set("KITTY_WINDOW_ID")
            || starts("TERM", "xterm-kitty")
            || set("WEZTERM_EXECUTABLE")
            || starts("TERM", "foot")
            || starts("TERM", "rxvt-unicode")
            || set("ConEmuPID");
        if raises {
            return Self {
                terminal: true,
                desktop: false,
                tmux: false,
            };
        }
        // Known to ignore all three. On Windows the console is the default
        // host and ignores them too, so anything not recognised above is
        // taken to.
        let ignores = set("WT_SESSION")
            || is("TERM_PROGRAM", &["Apple_Terminal", "vscode"])
            || set("VTE_VERSION")
            || set("KONSOLE_VERSION")
            || is("TERM", &["alacritty"])
            || windows;
        if ignores {
            return Self {
                terminal: false,
                desktop: true,
                tmux: false,
            };
        }
        // Unknown: a second toast on a rare terminal is a smaller failure
        // than none on a common one.
        Self {
            terminal: true,
            desktop: true,
            tmux: false,
        }
    }

    /// One line for the System pane on what `all` does here.
    pub fn describe(self) -> &'static str {
        match (self.terminal, self.desktop) {
            (true, false) => "this terminal raises the notification itself",
            (false, true) => "the desktop raises the notification",
            (true, true) => {
                "the terminal and the desktop are both asked, since this terminal is not one the client knows"
            }
            (false, false) => "no notification path",
        }
    }
}

pub struct Notifier {
    mode: NotifyMode,
    route: Route,
    last: Option<Instant>,
    title_unread: Option<usize>,
    /// Leave the window title alone (reader mode: a screen reader would
    /// announce every change, and the unread count is said in lines).
    quiet_titles: bool,
    desktop: Desktop,
}

impl Notifier {
    pub fn new(mode: NotifyMode) -> Self {
        Self::with_route(mode, Route::detect())
    }

    pub fn with_route(mode: NotifyMode, route: Route) -> Self {
        Self {
            mode,
            route,
            last: None,
            title_unread: None,
            quiet_titles: false,
            desktop: Desktop::default(),
        }
    }

    /// Never touch the window title from now on.
    pub fn quiet_titles(&mut self) {
        self.quiet_titles = true;
    }

    pub fn mode(&self) -> NotifyMode {
        self.mode
    }

    pub fn route(&self) -> Route {
        self.route
    }

    pub fn set_mode(&mut self, mode: NotifyMode) {
        self.mode = mode;
    }

    /// Ring and, in every mode but `bell`, raise a notification that says
    /// [`TEXT`]. There is nothing to pass: what a notification says is not
    /// the caller's to decide. Announcements within a second of the last
    /// are dropped, so a burst of messages makes one noise.
    pub fn announce(&mut self) {
        if self.mode == NotifyMode::Off {
            return;
        }
        if self.last.is_some_and(|at| at.elapsed() < THROTTLE) {
            return;
        }
        self.last = Some(Instant::now());
        let (terminal, desktop) = match self.mode {
            NotifyMode::Off | NotifyMode::Bell => (false, false),
            NotifyMode::All => (self.route.terminal, self.route.desktop),
            NotifyMode::Terminal => (true, false),
            NotifyMode::Desktop => (false, true),
        };
        let mut out = String::from("\x07");
        if terminal {
            out.push_str(&terminal_sequences(self.route.tmux));
        }
        write_raw(&out);
        if desktop {
            self.desktop.raise();
        }
    }

    /// Put the unread count in the window title; a no-op when unchanged.
    pub fn set_unread(&mut self, unread: usize) {
        if self.quiet_titles || self.title_unread == Some(unread) {
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
}

/// The three sequences a terminal may turn into a toast, each carrying
/// the title and [`TEXT`], wrapped for tmux when asked.
fn terminal_sequences(tmux: bool) -> String {
    let sequences = [
        format!("\x1b]777;notify;{APP_TITLE};{TEXT}\x1b\\"),
        format!("\x1b]9;{APP_TITLE}: {TEXT}\x1b\\"),
        format!("\x1b]99;i=silver:d=0:p=title;{APP_TITLE}\x1b\\"),
        format!("\x1b]99;i=silver:d=1:p=body;{TEXT}\x1b\\"),
    ];
    sequences
        .iter()
        .map(|s| if tmux { tmux_passthrough(s) } else { s.clone() })
        .collect()
}

/// A sequence wrapped so that tmux hands it to the outer terminal: `DCS
/// tmux ;` then the sequence with every ESC doubled, then `ST`. tmux must
/// have `allow-passthrough` on, which is the user's to set.
fn tmux_passthrough(sequence: &str) -> String {
    format!("\x1bPtmux;{}\x1b\\", sequence.replace('\x1b', "\x1b\x1b"))
}

/// The operating system's path. A failure is remembered, so the path is
/// left alone for a while rather than tried for every message.
#[derive(Clone, Default)]
struct Desktop {
    state: Arc<Mutex<DesktopState>>,
}

#[derive(Default)]
struct DesktopState {
    /// Not before this, after a failure.
    retry_at: Option<Instant>,
    /// What the platform keeps between notifications: a bus connection and
    /// the id to replace on Linux.
    platform: desktop::State,
}

impl Desktop {
    /// Ask the operating system, off the interface's thread; the outcome is
    /// not waited for.
    fn raise(&self) {
        {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.retry_at.is_some_and(|at| Instant::now() < at) {
                return;
            }
        }
        let shared = self.state.clone();
        std::thread::spawn(move || {
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            match desktop::raise(&mut state.platform) {
                Ok(()) => state.retry_at = None,
                Err(e) => {
                    tracing::debug!(
                        "desktop notification: {e}; not trying again for {RETRY_AFTER:?}"
                    );
                    state.retry_at = Some(Instant::now() + RETRY_AFTER);
                }
            }
        });
    }
}

/// Linux: `org.freedesktop.Notifications` on the session bus, through the
/// `zbus` the client already links for the key store. The connection is
/// kept, and the id the service hands back is what the next notification
/// replaces, so the notification area never fills with identical lines.
#[cfg(target_os = "linux")]
mod desktop {
    use std::collections::HashMap;

    use zbus::blocking::{Connection, Proxy};
    use zbus::zvariant::Value;

    use super::{APP_TITLE, TEXT};

    #[derive(Default)]
    pub struct State {
        connection: Option<Connection>,
        replaces: u32,
    }

    pub fn raise(state: &mut State) -> Result<(), String> {
        let connection = match &state.connection {
            Some(c) => c.clone(),
            None => {
                let c = Connection::session().map_err(|e| format!("session bus: {e}"))?;
                state.connection = Some(c.clone());
                c
            }
        };
        let proxy = Proxy::new(
            &connection,
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
        )
        .map_err(|e| format!("notification service: {e}"))?;
        let mut hints: HashMap<&str, Value> = HashMap::new();
        hints.insert("urgency", Value::U8(1));
        let id: u32 = proxy
            .call(
                "Notify",
                &(
                    APP_TITLE,
                    state.replaces,
                    "",
                    TEXT,
                    "",
                    Vec::<&str>::new(),
                    hints,
                    -1i32,
                ),
            )
            .map_err(|e| {
                // A dead connection is dropped so the next try makes a new one.
                state.connection = None;
                format!("Notify: {e}")
            })?;
        state.replaces = id;
        Ok(())
    }
}

/// macOS: a command-line program has no application bundle, so it cannot
/// use the notification framework; `osascript` can, and every Mac has it.
/// The script is a constant with nothing in it to escape.
#[cfg(target_os = "macos")]
mod desktop {
    use std::process::{Command, Stdio};

    #[derive(Default)]
    pub struct State;

    const SCRIPT: &str = concat!(
        "display notification \"",
        "New message",
        "\" with title \"",
        "Silver Messenger",
        "\""
    );

    pub fn raise(_: &mut State) -> Result<(), String> {
        let status = Command::new("osascript")
            .args(["-e", SCRIPT])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("osascript: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("osascript exited with {status}"))
        }
    }
}

/// Windows: a toast through the WinRT API, posted under PowerShell's
/// AppUserModelID because a bare executable has none of its own (the
/// design note says why that is the better of two workarounds).
#[cfg(windows)]
mod desktop {
    use tauri_winrt_notification::Toast;

    use super::{APP_TITLE, TEXT};

    #[derive(Default)]
    pub struct State;

    pub fn raise(_: &mut State) -> Result<(), String> {
        Toast::new(Toast::POWERSHELL_APP_ID)
            .title(APP_TITLE)
            .text1(TEXT)
            .show()
            .map_err(|e| format!("toast: {e}"))
    }
}

/// Elsewhere the operating system's path does not exist; the bell and the
/// terminal's own sequences still do.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod desktop {
    #[derive(Default)]
    pub struct State;

    pub fn raise(_: &mut State) -> Result<(), String> {
        Err("no desktop notification path on this platform".into())
    }
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
        assert_eq!(NotifyMode::parse("terminal"), Some(NotifyMode::Terminal));
        assert_eq!(NotifyMode::parse("Desktop"), Some(NotifyMode::Desktop));
        assert_eq!(NotifyMode::parse("loud"), None);
        for mode in [
            NotifyMode::Off,
            NotifyMode::Bell,
            NotifyMode::All,
            NotifyMode::Terminal,
            NotifyMode::Desktop,
        ] {
            assert_eq!(NotifyMode::parse(mode.as_str()), Some(mode));
        }
    }

    fn route(windows: bool, vars: &[(&str, &str)]) -> Route {
        Route::from_env(windows, |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        })
    }

    #[test]
    fn the_route_follows_the_table() {
        // Over SSH: the terminal alone, even one that would otherwise take
        // the desktop.
        let ssh = route(false, &[("SSH_TTY", "/dev/pts/3"), ("VTE_VERSION", "7400")]);
        assert_eq!((ssh.terminal, ssh.desktop, ssh.tmux), (true, false, false));
        // tmux: both, wrapped.
        let tmux = route(false, &[("TMUX", "/tmp/tmux-1000/default,1,0")]);
        assert_eq!((tmux.terminal, tmux.desktop, tmux.tmux), (true, true, true));
        // Terminals that raise the sequences themselves.
        for vars in [
            vec![("TERM_PROGRAM", "iTerm.app")],
            vec![("TERM_PROGRAM", "WezTerm")],
            vec![("TERM_PROGRAM", "ghostty")],
            vec![("KITTY_WINDOW_ID", "1")],
            vec![("TERM", "xterm-kitty")],
            vec![("WEZTERM_EXECUTABLE", "/usr/bin/wezterm")],
            vec![("TERM", "foot-extra")],
            vec![("TERM", "rxvt-unicode-256color")],
            vec![("ConEmuPID", "1234")],
        ] {
            let r = route(false, &vars);
            assert_eq!((r.terminal, r.desktop), (true, false), "{vars:?}");
        }
        // Terminals that ignore them: the desktop.
        for vars in [
            vec![("WT_SESSION", "abc")],
            vec![("TERM_PROGRAM", "Apple_Terminal")],
            vec![("TERM_PROGRAM", "vscode")],
            vec![("VTE_VERSION", "7400")],
            vec![("KONSOLE_VERSION", "230800")],
            vec![("TERM", "alacritty")],
        ] {
            let r = route(false, &vars);
            assert_eq!((r.terminal, r.desktop), (false, true), "{vars:?}");
        }
        // Windows with nothing recognised: the console, which ignores them.
        let console = route(true, &[]);
        assert_eq!((console.terminal, console.desktop), (false, true));
        // WezTerm on Windows still announces itself.
        let wez = route(true, &[("WEZTERM_EXECUTABLE", "C:\\wezterm.exe")]);
        assert_eq!((wez.terminal, wez.desktop), (true, false));
        // Unknown elsewhere: both.
        let unknown = route(false, &[("TERM", "xterm-256color")]);
        assert_eq!((unknown.terminal, unknown.desktop), (true, true));
    }

    #[test]
    fn the_sequences_say_the_title_and_the_text_and_nothing_else() {
        let plain = terminal_sequences(false);
        assert_eq!(
            plain,
            "\x1b]777;notify;Silver Messenger;New message\x1b\\\
             \x1b]9;Silver Messenger: New message\x1b\\\
             \x1b]99;i=silver:d=0:p=title;Silver Messenger\x1b\\\
             \x1b]99;i=silver:d=1:p=body;New message\x1b\\"
        );
        // Every printable word in them is the title or the text.
        for word in plain
            .split(|c: char| !c.is_alphabetic())
            .filter(|w| !w.is_empty())
        {
            assert!(
                "Silver Messenger New message notify i silver d p title body".contains(word),
                "unexpected word {word:?}"
            );
        }
    }

    #[test]
    fn tmux_gets_the_passthrough_with_escapes_doubled() {
        let wrapped = tmux_passthrough("\x1b]9;x\x1b\\");
        assert_eq!(wrapped, "\x1bPtmux;\x1b\x1b]9;x\x1b\x1b\\\x1b\\");
        let all = terminal_sequences(true);
        assert_eq!(all.matches("\x1bPtmux;").count(), 4);
        // Inside the wrapper every ESC of a sequence is doubled, so the
        // bare form never appears on its own.
        assert_eq!(
            all.matches("\x1b]777").count(),
            all.matches("\x1b\x1b]777").count()
        );
        assert!(all.starts_with("\x1bPtmux;\x1b\x1b]777"));
    }

    #[test]
    fn a_notification_takes_no_text() {
        // The point of the signature: nothing about a message can be handed
        // to it. This compiles, which is the test; it also runs, writing a
        // bell to a test's stdout, which the harness swallows.
        let route = Route {
            terminal: false,
            desktop: false,
            tmux: false,
        };
        let mut n = Notifier::with_route(NotifyMode::Bell, route);
        n.announce();
        n.announce(); // within the throttle: dropped
        assert_eq!(n.mode(), NotifyMode::Bell);
    }
}
