//! The first launch: a walk through everything a new installation needs,
//! before the interface opens, instead of a handful of command-line flags
//! to find afterwards. How it looks; a new identity or this computer
//! linked to one kept elsewhere; the relay and a proxy; how the data is
//! protected at rest (a security key, a passphrase, the key store or
//! nothing); receipts, cover traffic and the idle lock; notifications; and
//! a first backup. Nothing is written until the last screen says so.
//!
//! Full screen, or one question per line in reader mode, from the same
//! questions. The flags (`--add-security-key`, `--set-passphrase`,
//! `--export-backup` and the rest) stay for changing things later.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use silver_client::{Config, Pin, Proxy, Store};
use zeroize::Zeroizing;

use crate::notify::NotifyMode;
use crate::theme::{Theme, ThemeName};

/// What the start knows before asking anything.
#[derive(Clone, Debug)]
pub struct Context {
    /// The relay given on the command line, or the default.
    pub relay: String,
    /// A key store this computer can use, and not refused with
    /// `--no-keystore`.
    pub keystore: bool,
    /// A way to a security key on this system.
    pub security_key: bool,
    /// The theme to start from (`--theme`, `NO_COLOR`).
    pub theme: ThemeName,
}

/// What the person chose.
#[derive(Clone)]
pub struct Answers {
    pub theme: ThemeName,
    pub ascii: bool,
    pub reader: bool,
    pub link: bool,
    pub device_name: String,
    pub relay: String,
    pub proxy: ProxyChoice,
    pub proxy_url: String,
    pub pin: String,
    pub guard: Guard,
    pub secret: Zeroizing<String>,
    pub secret_again: Zeroizing<String>,
    pub key_name: String,
    pub spare: bool,
    pub receipts: bool,
    pub cover: bool,
    pub lock_after: u64,
    pub update_check: bool,
    pub notify: NotifyMode,
    pub backup: bool,
    pub backup_path: String,
    pub backup_secret: Zeroizing<String>,
    pub backup_secret_again: Zeroizing<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyChoice {
    None,
    Tor,
    Other,
}

/// How the data directory is protected at rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard {
    SecurityKey,
    Passphrase,
    Keystore,
    Nothing,
}

/// Tor's SOCKS port, as the Tor daemon opens it.
const TOR: &str = "socks5h://127.0.0.1:9050";
const LOCK_CHOICES: [u64; 4] = [0, 5, 15, 60];
const THEMES: [ThemeName; 4] = [
    ThemeName::Dark,
    ThemeName::Light,
    ThemeName::Mono,
    ThemeName::Contrast,
];
const NOTIFY: [NotifyMode; 5] = [
    NotifyMode::All,
    NotifyMode::Terminal,
    NotifyMode::Desktop,
    NotifyMode::Bell,
    NotifyMode::Off,
];

impl Answers {
    /// The defaults: what a start with no questions does today.
    pub fn new(ctx: &Context) -> Self {
        let config = Config::default();
        Answers {
            theme: ctx.theme,
            ascii: false,
            reader: false,
            link: false,
            device_name: String::new(),
            relay: ctx.relay.clone(),
            proxy: ProxyChoice::None,
            proxy_url: String::new(),
            pin: String::new(),
            guard: if ctx.keystore {
                Guard::Keystore
            } else {
                Guard::Passphrase
            },
            secret: Zeroizing::default(),
            secret_again: Zeroizing::default(),
            key_name: "security key".into(),
            spare: false,
            receipts: config.read_receipts,
            cover: config.cover,
            lock_after: 15,
            update_check: config.update_check,
            notify: NotifyMode::parse(&config.notify).unwrap_or(NotifyMode::All),
            backup: false,
            backup_path: String::new(),
            backup_secret: Zeroizing::default(),
            backup_secret_again: Zeroizing::default(),
        }
    }

    fn locks(&self) -> bool {
        matches!(self.guard, Guard::SecurityKey | Guard::Passphrase)
    }
}

// --- the questions ----------------------------------------------------------

/// One question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum F {
    Theme,
    Marks,
    Reader,
    Start,
    DeviceName,
    Relay,
    Proxy,
    ProxyUrl,
    Pin,
    Guard,
    Secret,
    SecretAgain,
    KeyName,
    Spare,
    Receipts,
    Cover,
    LockAfter,
    UpdateCheck,
    Notify,
    Backup,
    BackupPath,
    BackupSecret,
    BackupSecretAgain,
}

/// What kind of answer a question takes, with its value now.
enum Kind {
    /// One of several: (label, what it means) each, and which is chosen.
    Choice(Vec<(&'static str, &'static str)>, usize),
    Toggle(bool, &'static str),
    Text(String, &'static str),
    Secret(usize),
}

const STEPS: [&str; 8] = [
    "Welcome",
    "This computer",
    "Relay",
    "Protection",
    "Privacy",
    "Notifications",
    "Backup",
    "Review",
];
const REVIEW: usize = STEPS.len() - 1;

fn intro(step: usize, a: &Answers) -> Vec<String> {
    let lines: &[&str] = match step {
        0 => &[
            "Welcome to Silver Messenger: end-to-end encrypted messages through a relay that \
             sees only ciphertext.",
            "A few questions set this computer up. Nothing is written until the last screen, \
             and everything can be changed later.",
        ],
        1 => &[
            "Start an identity of this computer's own, or make it a device of an identity you \
             already use elsewhere: then both get the same contacts and messages.",
        ],
        2 => &[
            "The relay carries encrypted messages between people; it sees ciphertext and who \
             connects. A proxy (Tor, say) keeps your address from the relay.",
            "A pin is the relay's key as its operator published it (sha256:...); with one, a \
             certificate this computer trusts is not enough to stand in for the relay.",
        ],
        3 => &["Your keys, contacts and history are encrypted at rest. What should unlock them?"],
        4 => &["What others can tell from your messages, and when the client locks itself."],
        5 => &["How a message that arrives while you are elsewhere is announced."],
        6 if a.link => &[
            "A linked device's identity is kept on the device it was linked to; back that one \
             up. Nothing to do here.",
        ],
        6 => &[
            "A backup holds your identity and contacts under a passphrase of its own; with it, \
             a lost or broken computer costs nothing. Keep it somewhere else.",
        ],
        _ => &["That is all. Check the choices, then Enter sets this computer up."],
    };
    lines.iter().map(|l| l.to_string()).collect()
}

/// The questions on `step`, as the answers so far shape them.
fn fields(step: usize, a: &Answers, ctx: &Context) -> Vec<F> {
    let mut out = Vec::new();
    match step {
        0 => out.extend([F::Theme, F::Marks, F::Reader]),
        1 => {
            out.push(F::Start);
            if a.link {
                out.push(F::DeviceName);
            }
        }
        2 => {
            out.extend([F::Relay, F::Proxy]);
            if a.proxy == ProxyChoice::Other {
                out.push(F::ProxyUrl);
            }
            out.push(F::Pin);
        }
        3 => {
            out.push(F::Guard);
            match a.guard {
                Guard::SecurityKey => {
                    out.extend([F::Secret, F::SecretAgain, F::KeyName, F::Spare]);
                }
                Guard::Passphrase => out.extend([F::Secret, F::SecretAgain]),
                _ => {}
            }
            let _ = ctx;
        }
        4 => {
            out.extend([F::Receipts, F::Cover]);
            if a.locks() {
                out.push(F::LockAfter);
            }
            out.push(F::UpdateCheck);
        }
        5 => out.push(F::Notify),
        6 if !a.link => {
            out.push(F::Backup);
            if a.backup {
                out.extend([F::BackupPath, F::BackupSecret, F::BackupSecretAgain]);
            }
        }
        _ => {}
    }
    out
}

fn guards(ctx: &Context) -> Vec<Guard> {
    let mut out = Vec::new();
    if ctx.security_key {
        out.push(Guard::SecurityKey);
    }
    out.push(Guard::Passphrase);
    if ctx.keystore {
        out.push(Guard::Keystore);
    }
    out.push(Guard::Nothing);
    out
}

fn guard_text(g: Guard) -> (&'static str, &'static str) {
    match g {
        Guard::SecurityKey => (
            "Security key",
            "A FIDO2 key such as a YubiKey: its PIN and a touch at every start. A stolen \
             computer does not open, even with the key in it. A recovery passphrase comes with \
             it, for when no key can.",
        ),
        Guard::Passphrase => (
            "Passphrase",
            "Asked for at every start; a copy of the directory is only as safe as the \
             passphrase is strong.",
        ),
        Guard::Keystore => (
            "This computer's key store",
            "No question at start: the key is kept in this computer's key store, so a copied \
             directory is useless elsewhere, but anyone using this account can open it.",
        ),
        Guard::Nothing => (
            "Nothing",
            "Plain files. Only where something else protects the disk, such as a server's \
             encrypted volume.",
        ),
    }
}

impl F {
    fn label(self, a: &Answers) -> &'static str {
        match self {
            F::Theme => "Colours",
            F::Marks => "Marks",
            F::Reader => "Reader mode",
            F::Start => "This computer",
            F::DeviceName => "This device's name",
            F::Relay => "Relay",
            F::Proxy => "Proxy",
            F::ProxyUrl => "Proxy URL",
            F::Pin => "Relay key pin",
            F::Guard => "Unlock with",
            F::Secret if a.guard == Guard::SecurityKey => "Recovery passphrase",
            F::Secret => "Passphrase",
            F::SecretAgain => "Repeat it",
            F::KeyName => "The key's name",
            F::Spare => "A spare key",
            F::Receipts => "Read receipts",
            F::Cover => "Cover traffic",
            F::LockAfter => "Lock when idle",
            F::UpdateCheck => "Release check",
            F::Notify => "Announce messages with",
            F::Backup => "Backup",
            F::BackupPath => "Backup file",
            F::BackupSecret => "Backup passphrase",
            F::BackupSecretAgain => "Repeat it",
        }
    }

    fn kind(self, a: &Answers, ctx: &Context) -> Kind {
        match self {
            F::Theme => Kind::Choice(
                vec![
                    ("Dark", "For a dark background."),
                    ("Light", "For a light background."),
                    ("Mono", "No colour at all."),
                    ("High contrast", "Bright bold text on black."),
                ],
                THEMES.iter().position(|t| *t == a.theme).unwrap_or(0),
            ),
            F::Marks => Kind::Choice(
                vec![
                    ("Unicode", "✓ ✓✓ ● → as most terminals draw them."),
                    ("ASCII", "v vv * -> for a terminal or font without them."),
                ],
                usize::from(a.ascii),
            ),
            F::Reader => Kind::Toggle(
                a.reader,
                "One line per event, no boxes or colours, for a screen reader; from the next \
                 screen on.",
            ),
            F::Start => Kind::Choice(
                vec![
                    (
                        "A new identity",
                        "This computer gets an identity of its own.",
                    ),
                    (
                        "Link to an identity I have",
                        "Shows a link and a QR code for /devices link on the computer that \
                         holds your identity.",
                    ),
                ],
                usize::from(a.link),
            ),
            F::DeviceName => Kind::Text(
                a.device_name.clone(),
                "What your other devices call this one, up to 32 characters; empty lets the \
                 other device name it.",
            ),
            F::Relay => Kind::Text(
                a.relay.clone(),
                "wss://host/ws for a relay with TLS; ws:// only for one on this computer.",
            ),
            F::Proxy => Kind::Choice(
                vec![
                    ("None", "Connect directly."),
                    (
                        "Tor",
                        "Through Tor's SOCKS port on this computer (127.0.0.1:9050).",
                    ),
                    ("Another proxy", "A SOCKS5 or HTTP proxy of your own."),
                ],
                match a.proxy {
                    ProxyChoice::None => 0,
                    ProxyChoice::Tor => 1,
                    ProxyChoice::Other => 2,
                },
            ),
            F::ProxyUrl => Kind::Text(
                a.proxy_url.clone(),
                "socks5h://host:port, or http://user:password@host:port.",
            ),
            F::Pin => Kind::Text(
                a.pin.clone(),
                "Optional: the relay's key pin, from its operator. Empty trusts the \
                 certificate as this computer does.",
            ),
            F::Guard => {
                let options = guards(ctx);
                let selected = options.iter().position(|g| *g == a.guard).unwrap_or(0);
                Kind::Choice(options.into_iter().map(guard_text).collect(), selected)
            }
            F::Secret => Kind::Secret(a.secret.chars().count()),
            F::SecretAgain => Kind::Secret(a.secret_again.chars().count()),
            F::KeyName => Kind::Text(
                a.key_name.clone(),
                "What to call this key, so that it can be told apart from a spare.",
            ),
            F::Spare => Kind::Toggle(
                a.spare,
                "Enroll a second key straight after the first, to keep somewhere else.",
            ),
            F::Receipts => Kind::Toggle(
                a.receipts,
                "Tell a sender when you have read their message; you see theirs only if you \
                 send yours.",
            ),
            F::Cover => Kind::Toggle(
                a.cover,
                "Send dummy messages now and then, so that the relay cannot tell when you \
                 really write. Costs a little traffic.",
            ),
            F::LockAfter => Kind::Choice(
                vec![
                    ("Never", "Only /lock locks it."),
                    ("5 minutes", "Idle for 5 minutes, the keys leave memory."),
                    ("15 minutes", "Idle for 15 minutes, the keys leave memory."),
                    ("An hour", "Idle for an hour, the keys leave memory."),
                ],
                LOCK_CHOICES
                    .iter()
                    .position(|m| *m == a.lock_after)
                    .unwrap_or(0),
            ),
            F::UpdateCheck => Kind::Toggle(
                a.update_check,
                "Ask the releases page once a day whether a new version is out. It tells \
                 that host this address runs Silver Messenger, so it is off unless you want it.",
            ),
            F::Notify => Kind::Choice(
                vec![
                    (
                        "Everything",
                        "The terminal's bell and a desktop notification.",
                    ),
                    (
                        "The terminal",
                        "A notification through the terminal, where it can.",
                    ),
                    (
                        "The desktop",
                        "The bell and the operating system's notification.",
                    ),
                    ("The bell", "Only the terminal's bell."),
                    (
                        "Nothing",
                        "Silence; the chat list still counts what is unread.",
                    ),
                ],
                NOTIFY.iter().position(|n| *n == a.notify).unwrap_or(0),
            ),
            F::Backup => Kind::Choice(
                vec![
                    ("Not now", "--export-backup writes one any time."),
                    (
                        "Write one now",
                        "To a file you choose, under a passphrase of its own.",
                    ),
                ],
                usize::from(a.backup),
            ),
            F::BackupPath => Kind::Text(
                a.backup_path.clone(),
                "A file that does not exist yet, best on another disk.",
            ),
            F::BackupSecret => Kind::Secret(a.backup_secret.chars().count()),
            F::BackupSecretAgain => Kind::Secret(a.backup_secret_again.chars().count()),
        }
    }

    /// Sets a choice to its `i`th option.
    fn choose(self, a: &mut Answers, ctx: &Context, i: usize) {
        match self {
            F::Theme => a.theme = THEMES[i % THEMES.len()],
            F::Marks => a.ascii = i == 1,
            F::Start => a.link = i == 1,
            F::Proxy => {
                a.proxy = [ProxyChoice::None, ProxyChoice::Tor, ProxyChoice::Other][i % 3];
            }
            F::Guard => {
                let options = guards(ctx);
                let guard = options[i % options.len()];
                if guard != a.guard {
                    a.secret = Zeroizing::default();
                    a.secret_again = Zeroizing::default();
                }
                a.guard = guard;
            }
            F::LockAfter => a.lock_after = LOCK_CHOICES[i % LOCK_CHOICES.len()],
            F::Notify => a.notify = NOTIFY[i % NOTIFY.len()],
            F::Backup => a.backup = i == 1,
            _ => {}
        }
    }

    fn toggle(self, a: &mut Answers) {
        match self {
            F::Reader => a.reader = !a.reader,
            F::Spare => a.spare = !a.spare,
            F::Receipts => a.receipts = !a.receipts,
            F::Cover => a.cover = !a.cover,
            F::UpdateCheck => a.update_check = !a.update_check,
            _ => {}
        }
    }

    fn text_mut(self, a: &mut Answers) -> Option<&mut String> {
        Some(match self {
            F::DeviceName => &mut a.device_name,
            F::Relay => &mut a.relay,
            F::ProxyUrl => &mut a.proxy_url,
            F::Pin => &mut a.pin,
            F::KeyName => &mut a.key_name,
            F::BackupPath => &mut a.backup_path,
            F::Secret => &mut a.secret,
            F::SecretAgain => &mut a.secret_again,
            F::BackupSecret => &mut a.backup_secret,
            F::BackupSecretAgain => &mut a.backup_secret_again,
            _ => return None,
        })
    }
}

/// Whether the answers on `step` will do; the reason if not.
fn check(step: usize, a: &Answers) -> Result<(), String> {
    match step {
        1 if a.link && a.device_name.chars().count() > 32 => {
            Err("The device's name is longer than 32 characters.".into())
        }
        2 => {
            let relay = a.relay.trim();
            let lower = relay.to_ascii_lowercase();
            let host = lower
                .strip_prefix("wss://")
                .or_else(|| lower.strip_prefix("ws://"))
                .ok_or("The relay's address starts with wss:// (or ws:// on this computer).")?;
            if host.is_empty() || host.starts_with('/') {
                return Err("The relay's address names no host.".into());
            }
            if a.proxy == ProxyChoice::Other {
                Proxy::parse(&a.proxy_url).map_err(|e| format!("The proxy: {e}."))?;
            }
            if !a.pin.trim().is_empty() {
                Pin::parse(&a.pin).map_err(|e| format!("The pin: {e}."))?;
            }
            Ok(())
        }
        3 => {
            if matches!(a.guard, Guard::SecurityKey | Guard::Passphrase) {
                if a.secret.is_empty() {
                    return Err("The passphrase is empty.".into());
                }
                if *a.secret != *a.secret_again {
                    return Err("The two passphrases are not the same.".into());
                }
            }
            if a.guard == Guard::SecurityKey && a.key_name.trim().is_empty() {
                return Err("The key needs a name.".into());
            }
            Ok(())
        }
        6 if a.backup && !a.link => {
            let path = PathBuf::from(a.backup_path.trim());
            if a.backup_path.trim().is_empty() {
                return Err("Which file should the backup go to?".into());
            }
            if path.exists() {
                return Err("That file exists already; choose another.".into());
            }
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
                && !parent.is_dir()
            {
                return Err(format!("There is no folder {}.", parent.display()));
            }
            if a.backup_secret.is_empty() {
                return Err("The backup's passphrase is empty.".into());
            }
            if *a.backup_secret != *a.backup_secret_again {
                return Err("The two backup passphrases are not the same.".into());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The review: one line per choice.
fn summary(a: &Answers) -> Vec<(String, String)> {
    let mut out = vec![
        (
            "Colours".into(),
            format!(
                "{}, {} marks{}",
                a.theme.as_str(),
                if a.ascii { "ASCII" } else { "Unicode" },
                if a.reader { ", reader mode" } else { "" }
            ),
        ),
        (
            "This computer".into(),
            if a.link {
                "linked to an identity you have".into()
            } else {
                "a new identity".into()
            },
        ),
        ("Relay".into(), a.relay.trim().to_owned()),
        (
            "Proxy".into(),
            match a.proxy {
                ProxyChoice::None => "none".into(),
                ProxyChoice::Tor => format!("Tor ({TOR})"),
                ProxyChoice::Other => a.proxy_url.trim().to_owned(),
            },
        ),
    ];
    if !a.pin.trim().is_empty() {
        out.push(("Pin".into(), a.pin.trim().to_owned()));
    }
    out.push((
        "Unlock with".into(),
        match a.guard {
            Guard::SecurityKey => format!(
                "a security key ({}){}, and a recovery passphrase",
                a.key_name.trim(),
                if a.spare { " and a spare" } else { "" }
            ),
            Guard::Passphrase => "a passphrase".into(),
            Guard::Keystore => "this computer's key store".into(),
            Guard::Nothing => "nothing: plain files".into(),
        },
    ));
    let on = |b: bool| if b { "on" } else { "off" };
    out.push((
        "Privacy".into(),
        format!(
            "read receipts {}, cover traffic {}{}, release check {}",
            on(a.receipts),
            on(a.cover),
            if a.locks() {
                match a.lock_after {
                    0 => ", no idle lock".to_owned(),
                    m => format!(", locks after {m} minutes idle"),
                }
            } else {
                String::new()
            },
            on(a.update_check)
        ),
    ));
    out.push(("Notifications".into(), a.notify.as_str().into()));
    if !a.link {
        out.push((
            "Backup".into(),
            if a.backup {
                a.backup_path.trim().to_owned()
            } else {
                "not now".into()
            },
        ));
    }
    out
}

// --- what the answers do ------------------------------------------------------

/// The settings the answers make, on top of `config`.
pub fn configure(a: &Answers, mut config: Config) -> anyhow::Result<Config> {
    config.theme = a.theme.as_str().into();
    config.marks = if a.ascii { "ascii" } else { "auto" }.into();
    config.reader = a.reader;
    config.relay_url = Some(a.relay.trim().to_owned());
    config.proxy = match a.proxy {
        ProxyChoice::None => None,
        ProxyChoice::Tor => Some(TOR.into()),
        ProxyChoice::Other => {
            Proxy::parse(&a.proxy_url)?;
            Some(a.proxy_url.trim().to_owned())
        }
    };
    if !a.pin.trim().is_empty() {
        let pin = Pin::parse(&a.pin)?.to_hex();
        if !config.relay_pins.contains(&pin) {
            config.relay_pins.push(pin);
        }
    }
    config.read_receipts = a.receipts;
    config.cover = a.cover;
    config.lock_after_minutes = if a.locks() { a.lock_after } else { 0 };
    config.update_check = a.update_check;
    config.notify = a.notify.as_str().into();
    // Nothing chosen means nothing: the start must not then put the key
    // in the key store by itself.
    if a.guard == Guard::Nothing {
        config.os_keystore = false;
    }
    Ok(config)
}

/// What the start does next.
pub struct Outcome {
    /// Link this computer to an identity kept elsewhere, under this name
    /// (`None`: the other device names it).
    pub link: Option<Option<String>>,
}

/// Something that went wrong setting up, and the step to go back to.
struct Failed {
    step: usize,
    message: String,
}

/// Sets the directory up as the answers say: the settings, the identity,
/// the protection, the backup. `auth` reaches the security key.
fn apply(
    a: &Answers,
    store: &mut Store,
    auth: &mut dyn FnMut() -> anyhow::Result<Box<dyn silver_key::Authenticator>>,
    between_keys: &mut dyn FnMut(),
) -> Result<Outcome, Failed> {
    let fail = |step: usize| {
        move |e: anyhow::Error| Failed {
            step,
            message: format!("{e:#}"),
        }
    };
    // The protection first, while the directory is still empty: a key that
    // is not touched, or a PIN given up on, leaves nothing behind, and the
    // next start asks again. Everything written after it is written under
    // it. A second try after a later step failed finds it done.
    let protect = store.protection() == silver_client::Protection::None;
    match a.guard {
        _ if !protect => {}
        Guard::SecurityKey => {
            let mut key = auth().map_err(fail(3))?;
            store
                .add_security_key(key.as_mut(), a.key_name.trim(), Some(&a.secret))
                .map_err(fail(3))?;
            if a.spare {
                between_keys();
                let mut key = auth().map_err(fail(3))?;
                let name = format!("{} (spare)", a.key_name.trim());
                if let Err(e) = store.add_security_key(key.as_mut(), &name, None) {
                    // The first key is in and the directory is protected;
                    // a spare can follow with --add-security-key.
                    tracing::warn!("the spare security key was not enrolled: {e:#}");
                }
            }
        }
        Guard::Passphrase => store.set_passphrase(&a.secret).map_err(fail(3))?,
        Guard::Keystore => store.protect_with_keystore().map_err(fail(3))?,
        Guard::Nothing => {}
    }
    let config = store
        .load_config()
        .and_then(|c| configure(a, c))
        .map_err(fail(2))?;
    store.save_config(&config).map_err(fail(2))?;
    store.load_or_create_identity().map_err(fail(1))?;
    if a.backup && !a.link {
        silver_client::export_backup(
            store,
            &PathBuf::from(a.backup_path.trim()),
            &a.backup_secret,
            false,
        )
        .context("writing the backup")
        .map_err(fail(6))?;
    }
    let link = a.link.then(|| {
        let name = a.device_name.trim();
        (!name.is_empty()).then(|| name.to_owned())
    });
    Ok(Outcome { link })
}

/// Whether this start should ask: a new directory, at a terminal, and
/// not one a script is driving.
pub fn wanted(store: &Store, scripted: bool) -> bool {
    !store.has_identity() && !scripted && std::io::stdin().is_terminal()
}

/// Runs the onboarding: full screen, or line by line in reader mode.
/// `None` if the person quit before the end; nothing was written then.
pub fn run(store: &mut Store, ctx: &Context, reader: bool) -> anyhow::Result<Option<Outcome>> {
    if reader {
        lines::run(store, ctx)
    } else {
        screen::run(store, ctx)
    }
}

// --- full screen -------------------------------------------------------------

mod screen {
    use super::*;

    /// Where the wizard is.
    pub(super) struct Wizard {
        pub a: Answers,
        pub ctx: Context,
        pub step: usize,
        pub focus: usize,
        pub error: Option<String>,
        /// The review's answer is being carried out.
        pub busy: Option<String>,
    }

    pub(super) enum Action {
        Stay,
        Quit,
        Apply,
    }

    impl Wizard {
        pub fn new(ctx: &Context) -> Self {
            Wizard {
                a: Answers::new(ctx),
                ctx: ctx.clone(),
                step: 0,
                focus: 0,
                error: None,
                busy: None,
            }
        }

        fn fields(&self) -> Vec<F> {
            fields(self.step, &self.a, &self.ctx)
        }

        fn current(&self) -> Option<F> {
            self.fields().get(self.focus).copied()
        }

        fn next_step(&mut self) -> Action {
            if let Err(e) = check(self.step, &self.a) {
                self.error = Some(e);
                return Action::Stay;
            }
            self.error = None;
            if self.step == REVIEW {
                return Action::Apply;
            }
            self.step += 1;
            self.focus = 0;
            Action::Stay
        }

        fn back(&mut self) {
            self.error = None;
            if self.step > 0 {
                self.step -= 1;
                self.focus = 0;
            }
        }

        pub fn key(&mut self, key: KeyEvent) -> Action {
            if key.kind != KeyEventKind::Press {
                return Action::Stay;
            }
            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q')) {
                return Action::Quit;
            }
            let fields = self.fields();
            let count = fields.len();
            let field = self.current();
            match key.code {
                KeyCode::Esc => self.back(),
                KeyCode::Up | KeyCode::BackTab => self.focus = self.focus.saturating_sub(1),
                KeyCode::Down | KeyCode::Tab => {
                    if self.focus + 1 < count {
                        self.focus += 1;
                    }
                }
                KeyCode::Enter => {
                    if self.focus + 1 < count {
                        self.focus += 1;
                    } else {
                        return self.next_step();
                    }
                }
                KeyCode::PageDown => return self.next_step(),
                KeyCode::PageUp => self.back(),
                KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                    if field.is_some_and(|f| {
                        matches!(
                            f.kind(&self.a, &self.ctx),
                            Kind::Choice(..) | Kind::Toggle(..)
                        )
                    }) =>
                {
                    let f = field.expect("checked");
                    match f.kind(&self.a, &self.ctx) {
                        Kind::Choice(options, i) => {
                            let n = options.len();
                            let next = if key.code == KeyCode::Left {
                                (i + n - 1) % n
                            } else {
                                (i + 1) % n
                            };
                            f.choose(&mut self.a, &self.ctx, next);
                        }
                        Kind::Toggle(..) => f.toggle(&mut self.a),
                        _ => {}
                    }
                }
                KeyCode::Backspace => {
                    if let Some(text) = field.and_then(|f| f.text_mut(&mut self.a)) {
                        text.pop();
                    }
                }
                KeyCode::Char(c) if !ctrl => {
                    if let Some(text) = field.and_then(|f| f.text_mut(&mut self.a)) {
                        text.push(c);
                    } else if let (Some(f), Some(d)) = (field, c.to_digit(10)) {
                        // A number picks an option outright.
                        if let Kind::Choice(options, _) = f.kind(&self.a, &self.ctx)
                            && (1..=options.len()).contains(&(d as usize))
                        {
                            f.choose(&mut self.a, &self.ctx, d as usize - 1);
                        }
                    }
                }
                KeyCode::Char('u') if ctrl => {
                    if let Some(text) = field.and_then(|f| f.text_mut(&mut self.a)) {
                        text.clear();
                    }
                }
                _ => {}
            }
            Action::Stay
        }

        pub fn paste(&mut self, text: &str) {
            if let Some(field) = self.current()
                && let Some(value) = field.text_mut(&mut self.a)
            {
                value.push_str(text.trim_end_matches(['\r', '\n']));
            }
        }
    }

    pub(super) fn draw(frame: &mut ratatui::Frame, w: &Wizard) {
        let theme = Theme::named(w.a.theme);
        let area = frame.area();
        frame.render_widget(Block::new().style(theme.text), area);
        let [head, body, foot] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .areas(area);

        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(
                        "Silver Messenger",
                        theme.accent.add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(
                            "  ·  setting up, step {} of {}: {}",
                            w.step + 1,
                            STEPS.len(),
                            STEPS[w.step]
                        ),
                        theme.dim,
                    ),
                ]),
                Line::from(Span::styled("─".repeat(area.width as usize), theme.dim)),
            ]),
            head,
        );

        let narrow = body.width < 70;
        let [steps_area, main] = Layout::horizontal([
            Constraint::Length(if narrow { 0 } else { 18 }),
            Constraint::Min(30),
        ])
        .areas(body);
        let steps: Vec<Line> = STEPS
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let (mark, style) = if i == w.step {
                    ("▸ ", theme.accent.add_modifier(Modifier::BOLD))
                } else if i < w.step {
                    ("  ", theme.text)
                } else {
                    ("  ", theme.dim)
                };
                Line::from(Span::styled(format!("{mark}{name}"), style))
            })
            .collect();
        frame.render_widget(Paragraph::new(steps), steps_area);

        // Wrapped here rather than by the paragraph, so that a line in
        // the list is a row on the screen and the cursor lands where the
        // field is.
        let main = main.inner(ratatui::layout::Margin::new(1, 0));
        let width = usize::from(main.width.max(20));
        let mut lines: Vec<Line> = Vec::new();
        for text in intro(w.step, &w.a) {
            for row in wrap(&text, width, "") {
                lines.push(Line::from(Span::styled(row, theme.text)));
            }
        }
        lines.push(Line::default());
        let mut cursor = None;
        if w.step == REVIEW {
            for (k, v) in summary(&w.a) {
                for (i, row) in wrap(&v, width.saturating_sub(15), "")
                    .into_iter()
                    .enumerate()
                {
                    let key = if i == 0 { k.as_str() } else { "" };
                    lines.push(Line::from(vec![
                        Span::styled(format!("{key:<15}"), theme.dim),
                        Span::styled(row, theme.text),
                    ]));
                }
            }
        }
        for (i, f) in w.fields().into_iter().enumerate() {
            let focused = i == w.focus;
            let label_style = if focused {
                theme.accent.add_modifier(Modifier::BOLD)
            } else {
                theme.text.add_modifier(Modifier::BOLD)
            };
            let mark = if focused { "▸ " } else { "  " };
            let mut spans = vec![Span::styled(
                format!("{mark}{:<24}", f.label(&w.a)),
                label_style,
            )];
            let mut help = None;
            match f.kind(&w.a, &w.ctx) {
                Kind::Choice(options, selected) => {
                    for (j, (name, means)) in options.iter().enumerate() {
                        let style = if j == selected {
                            if focused {
                                theme.selected
                            } else {
                                theme.accent
                            }
                        } else {
                            theme.dim
                        };
                        spans.push(Span::styled(format!(" {name} "), style));
                        if j == selected {
                            help = Some(*means);
                        }
                    }
                }
                Kind::Toggle(on, means) => {
                    spans.push(Span::styled(
                        if on { " [x] on" } else { " [ ] off" },
                        if focused {
                            theme.selected
                        } else {
                            theme.accent
                        },
                    ));
                    help = Some(means);
                }
                Kind::Text(value, means) => {
                    spans.push(Span::styled(value.clone(), theme.text));
                    if focused {
                        cursor = Some((lines.len(), 26 + value.chars().count()));
                    }
                    help = Some(means);
                }
                Kind::Secret(n) => {
                    let dots = "•".repeat(n);
                    spans.push(Span::styled(dots, theme.text));
                    if focused {
                        cursor = Some((lines.len(), 26 + n));
                    }
                }
            }
            lines.push(Line::from(spans));
            if let Some(help) = help.filter(|_| focused) {
                for row in wrap(help, width, "    ") {
                    lines.push(Line::from(Span::styled(row, theme.dim)));
                }
            }
        }
        if let Some(error) = &w.error {
            lines.push(Line::default());
            for row in wrap(error, width, "") {
                lines.push(Line::from(Span::styled(row, theme.error)));
            }
        }
        frame.render_widget(Paragraph::new(lines), main);
        if let Some((row, col)) = cursor
            && w.busy.is_none()
        {
            let x = main.x + (col as u16).min(main.width.saturating_sub(1));
            let y = main.y + (row as u16).min(main.height.saturating_sub(1));
            frame.set_cursor_position((x, y));
        }

        let hint = if w.step == REVIEW {
            "Enter sets this computer up · Esc goes back · Ctrl-C quits without writing anything"
        } else {
            "↑↓ question · ←→ or Space change · Enter next · Esc back · Ctrl-C quit"
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled("─".repeat(area.width as usize), theme.dim)),
                Line::from(Span::styled(hint, theme.dim)),
            ]),
            foot,
        );

        if let Some(busy) = &w.busy {
            modal(frame, &theme, "Setting up", &[busy.as_str()]);
        }
    }

    /// `text` cut into rows of at most `width` characters at spaces, each
    /// row after `indent`.
    pub(super) fn wrap(text: &str, width: usize, indent: &str) -> Vec<String> {
        let room = width.saturating_sub(indent.chars().count()).max(10);
        let mut rows = Vec::new();
        let mut row = String::new();
        for word in text.split_whitespace() {
            let needed = row.chars().count() + usize::from(!row.is_empty()) + word.chars().count();
            if needed > room && !row.is_empty() {
                rows.push(format!("{indent}{row}"));
                row.clear();
            }
            if !row.is_empty() {
                row.push(' ');
            }
            row.push_str(word);
        }
        if !row.is_empty() || rows.is_empty() {
            rows.push(format!("{indent}{row}"));
        }
        rows
    }

    /// A box in the middle of the screen.
    pub(super) fn modal(frame: &mut ratatui::Frame, theme: &Theme, title: &str, lines: &[&str]) {
        let area = frame.area();
        let width = area.width.min(64);
        let height = (lines.len() as u16 + 4).min(area.height);
        let rect = Rect::new(
            area.x + (area.width - width) / 2,
            area.y + (area.height - height) / 2,
            width,
            height,
        );
        frame.render_widget(Clear, rect);
        let text: Vec<Line> = std::iter::once(Line::default())
            .chain(
                lines
                    .iter()
                    .map(|l| Line::from(Span::styled(*l, theme.text))),
            )
            .collect();
        frame.render_widget(
            Paragraph::new(text).wrap(Wrap { trim: false }).block(
                Block::bordered()
                    .title(Span::styled(format!(" {title} "), theme.accent))
                    .border_style(theme.accent)
                    .style(theme.text),
            ),
            rect,
        );
    }

    /// The security key's questions, asked in a box over the wizard.
    struct ScreenPrompt {
        terminal: Arc<Mutex<DefaultTerminal>>,
        theme: Theme,
    }

    impl ScreenPrompt {
        fn show(&self, title: &str, lines: &[&str]) {
            let mut t = self.terminal.lock().unwrap_or_else(|e| e.into_inner());
            let theme = self.theme;
            let _ = t.draw(|f| {
                f.render_widget(Block::new().style(theme.text), f.area());
                modal(f, &theme, title, lines);
            });
        }

        /// A line read in the box, hidden; `None` on Esc.
        fn read_secret(&self, title: &str, lines: &[&str]) -> Option<Zeroizing<String>> {
            let mut value = Zeroizing::new(String::new());
            loop {
                let shown = format!("> {}", "•".repeat(value.chars().count()));
                let mut all: Vec<&str> = lines.to_vec();
                all.push("");
                all.push(&shown);
                self.show(title, &all);
                match event::read().ok()? {
                    Event::Key(k) if k.kind == KeyEventKind::Press => match k.code {
                        KeyCode::Enter => return Some(value),
                        KeyCode::Esc => return None,
                        KeyCode::Backspace => {
                            value.pop();
                        }
                        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                            return None;
                        }
                        KeyCode::Char(c) => value.push(c),
                        _ => {}
                    },
                    Event::Paste(text) => value.push_str(text.trim_end()),
                    _ => {}
                }
            }
        }
    }

    impl silver_key::Prompt for ScreenPrompt {
        fn pin(&mut self, retries: Option<u32>, wrong: bool) -> Option<Zeroizing<String>> {
            let left = match retries {
                Some(n) if n <= 3 => format!("{n} tries left before the key locks itself."),
                _ => String::new(),
            };
            let first = if wrong {
                "Wrong PIN. Try again."
            } else {
                "The security key's PIN:"
            };
            let pin = self.read_secret("Security key", &[first, &left, "Esc goes back."])?;
            (!pin.is_empty()).then_some(pin)
        }

        fn new_pin(&mut self) -> Option<Zeroizing<String>> {
            loop {
                let first = self.read_secret(
                    "A PIN for the key",
                    &[
                        "This security key has no PIN yet; it gets one now (4 to 63 characters).",
                        "The key asks for it from now on, and locks itself after eight wrong ones.",
                    ],
                )?;
                if first.is_empty() {
                    return None;
                }
                let second = self.read_secret("A PIN for the key", &["Repeat the PIN:"])?;
                if first == second {
                    return Some(first);
                }
                self.show("A PIN for the key", &["They do not match; try again."]);
                std::thread::sleep(std::time::Duration::from_millis(1200));
            }
        }

        fn insert(&mut self) -> bool {
            self.show(
                "Security key",
                &[
                    "Plug in your security key, then press Enter.",
                    "Esc goes back.",
                ],
            );
            loop {
                match event::read() {
                    Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                        KeyCode::Enter => return true,
                        KeyCode::Esc => return false,
                        _ => {}
                    },
                    Ok(_) => {}
                    Err(_) => return false,
                }
            }
        }

        fn touch(&mut self) -> Box<dyn FnMut() + Send> {
            let terminal = self.terminal.clone();
            let theme = self.theme;
            Box::new(move || {
                let mut t = terminal.lock().unwrap_or_else(|e| e.into_inner());
                let _ = t.draw(|f| {
                    f.render_widget(Block::new().style(theme.text), f.area());
                    modal(f, &theme, "Security key", &["Touch your security key now."]);
                });
            })
        }
    }

    pub(super) fn run(store: &mut Store, ctx: &Context) -> anyhow::Result<Option<Outcome>> {
        let terminal = Arc::new(Mutex::new(crate::terminal::enter_full(false)?));
        let result = drive(store, ctx, &terminal);
        crate::terminal::leave();
        result
    }

    fn drive(
        store: &mut Store,
        ctx: &Context,
        terminal: &Arc<Mutex<DefaultTerminal>>,
    ) -> anyhow::Result<Option<Outcome>> {
        let mut w = Wizard::new(ctx);
        loop {
            terminal
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .draw(|f| draw(f, &w))?;
            let action = match event::read()? {
                Event::Key(key) => w.key(key),
                Event::Paste(text) => {
                    w.paste(&text);
                    Action::Stay
                }
                _ => Action::Stay,
            };
            match action {
                Action::Stay => {}
                Action::Quit => return Ok(None),
                Action::Apply => {
                    w.busy = Some(match w.a.guard {
                        Guard::SecurityKey => "Enrolling the security key: its PIN, then a touch, \
                                               twice. Where Windows asks, answer it there."
                            .into(),
                        _ => "Making the identity and protecting it…".into(),
                    });
                    terminal
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .draw(|f| draw(f, &w))?;
                    let theme = Theme::named(w.a.theme);
                    let mut auth = || -> anyhow::Result<Box<dyn silver_key::Authenticator>> {
                        Ok(silver_key::platform(Box::new(ScreenPrompt {
                            terminal: terminal.clone(),
                            theme,
                        }))?)
                    };
                    let prompt = ScreenPrompt {
                        terminal: terminal.clone(),
                        theme,
                    };
                    let mut between = || {
                        prompt.show(
                            "The spare key",
                            &[
                                "The first key is enrolled. Unplug it and plug in the spare,",
                                "then press Enter.",
                            ],
                        );
                        while let Ok(e) = event::read() {
                            if matches!(e, Event::Key(k) if k.kind == KeyEventKind::Press && k.code == KeyCode::Enter)
                            {
                                break;
                            }
                        }
                    };
                    match apply(&w.a, store, &mut auth, &mut between) {
                        Ok(outcome) => return Ok(Some(outcome)),
                        Err(Failed { step, message }) => {
                            w.busy = None;
                            w.step = step;
                            w.focus = 0;
                            w.error = Some(message);
                        }
                    }
                }
            }
        }
    }
}

// --- line by line, for a screen reader ---------------------------------------------

mod lines {
    use super::*;

    fn read_line(prompt: &str) -> anyhow::Result<Option<String>> {
        print!("{prompt}");
        std::io::stdout().flush()?;
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            return Ok(None);
        }
        Ok(Some(line.trim_end_matches(['\r', '\n']).to_owned()))
    }

    /// Asks one question; `false` when input ended.
    fn ask(f: F, a: &mut Answers, ctx: &Context) -> anyhow::Result<bool> {
        let label = f.label(a);
        match f.kind(a, ctx) {
            Kind::Choice(options, selected) => {
                println!("{label}:");
                for (i, (name, means)) in options.iter().enumerate() {
                    println!("  {}. {name}: {means}", i + 1);
                }
                let Some(answer) = read_line(&format!(
                    "Choose 1 to {} [{}]: ",
                    options.len(),
                    selected + 1
                ))?
                else {
                    return Ok(false);
                };
                if let Ok(n) = answer.trim().parse::<usize>()
                    && (1..=options.len()).contains(&n)
                {
                    f.choose(a, ctx, n - 1);
                }
            }
            Kind::Toggle(on, means) => {
                println!("{label}: {means}");
                let Some(answer) =
                    read_line(&format!("{label}? [{}] ", if on { "Y/n" } else { "y/N" }))?
                else {
                    return Ok(false);
                };
                let answer = answer.trim().to_ascii_lowercase();
                if (answer == "y" || answer == "yes") != on && !answer.is_empty() {
                    f.toggle(a);
                }
            }
            Kind::Text(value, means) => {
                println!("{label}: {means}");
                let Some(answer) = read_line(&format!("{label} [{value}]: "))? else {
                    return Ok(false);
                };
                if !answer.trim().is_empty()
                    && let Some(text) = f.text_mut(a)
                {
                    *text = answer.trim().to_owned();
                }
            }
            Kind::Secret(_) => {
                let answer = crate::ask(&format!("{label}: "))?;
                if let Some(text) = f.text_mut(a) {
                    *text = answer.to_string();
                }
            }
        }
        Ok(true)
    }

    pub(super) fn run(store: &mut Store, ctx: &Context) -> anyhow::Result<Option<Outcome>> {
        let mut a = Answers::new(ctx);
        a.reader = true;
        let mut step = 0;
        loop {
            println!();
            println!("Step {} of {}: {}.", step + 1, STEPS.len(), STEPS[step]);
            for line in intro(step, &a) {
                println!("{line}");
            }
            if step == REVIEW {
                for (k, v) in summary(&a) {
                    println!("  {k}: {v}");
                }
                let Some(answer) = read_line("Set this computer up with these? [Y/n] ")? else {
                    return Ok(None);
                };
                if answer.trim().eq_ignore_ascii_case("n") {
                    step = 0;
                    continue;
                }
                let mut auth = || -> anyhow::Result<Box<dyn silver_key::Authenticator>> {
                    Ok(silver_key::platform(Box::new(
                        crate::securitykey::TerminalPrompt {
                            instead: "going back",
                        },
                    ))?)
                };
                let mut between = || {
                    let _ = read_line(
                        "The first key is enrolled. Unplug it, plug in the spare, and press Enter. ",
                    );
                };
                match apply(&a, store, &mut auth, &mut between) {
                    Ok(outcome) => return Ok(Some(outcome)),
                    Err(Failed {
                        step: back,
                        message,
                    }) => {
                        println!("{message}");
                        step = back;
                        continue;
                    }
                }
            }
            // Fields can appear as earlier ones are answered (a proxy's
            // URL once "another proxy" is chosen), so they are asked in
            // order, the list taken afresh after each.
            let mut i = 0;
            while let Some(f) = fields(step, &a, ctx).get(i).copied() {
                if !ask(f, &mut a, ctx)? {
                    return Ok(None);
                }
                i += 1;
            }
            match check(step, &a) {
                Ok(()) => step += 1,
                Err(e) => println!("{e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::screen::{Action, Wizard};
    use super::*;

    fn ctx() -> Context {
        Context {
            relay: "wss://relay.example/ws".into(),
            keystore: true,
            security_key: true,
            theme: ThemeName::Dark,
        }
    }

    fn press(w: &mut Wizard, code: KeyCode) -> Action {
        w.key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn typed(w: &mut Wizard, text: &str) {
        for c in text.chars() {
            press(w, KeyCode::Char(c));
        }
    }

    #[test]
    fn the_defaults_are_what_a_start_without_questions_does() {
        let a = Answers::new(&ctx());
        assert_eq!(a.guard, Guard::Keystore);
        let config = configure(&a, Config::default()).unwrap();
        let plain = Config::default();
        assert_eq!(config.read_receipts, plain.read_receipts);
        assert_eq!(config.cover, plain.cover);
        assert!(!config.update_check);
        assert!(config.os_keystore);
        assert_eq!(
            config.lock_after_minutes, 0,
            "no idle lock without a passphrase or key"
        );
        assert_eq!(config.relay_url.as_deref(), Some("wss://relay.example/ws"));
        let no_store = Context {
            keystore: false,
            ..ctx()
        };
        assert_eq!(Answers::new(&no_store).guard, Guard::Passphrase);
        assert!(!guards(&no_store).contains(&Guard::Keystore));
    }

    #[test]
    fn the_answers_become_settings() {
        let mut a = Answers::new(&ctx());
        a.theme = ThemeName::Light;
        a.ascii = true;
        a.proxy = ProxyChoice::Tor;
        a.guard = Guard::Passphrase;
        a.lock_after = 5;
        a.receipts = false;
        a.cover = true;
        a.notify = NotifyMode::Bell;
        a.pin = "sha256:".to_owned() + &"ab".repeat(32);
        let config = configure(&a, Config::default()).unwrap();
        assert_eq!(config.theme, "light");
        assert_eq!(config.marks, "ascii");
        assert_eq!(config.proxy.as_deref(), Some(TOR));
        assert_eq!(config.lock_after_minutes, 5);
        assert!(!config.read_receipts && config.cover);
        assert_eq!(config.notify, "bell");
        assert_eq!(config.relay_pins.len(), 1);
        a.guard = Guard::Nothing;
        assert!(!configure(&a, Config::default()).unwrap().os_keystore);
    }

    #[test]
    fn a_step_will_not_pass_with_answers_that_will_not_do() {
        let mut a = Answers::new(&ctx());
        a.relay = "https://relay.example".into();
        assert!(check(2, &a).is_err());
        a.relay = "wss://".into();
        assert!(check(2, &a).is_err());
        a.relay = "wss://relay.example/ws".into();
        assert!(check(2, &a).is_ok());
        a.pin = "not a pin".into();
        assert!(check(2, &a).is_err());
        a.pin.clear();
        a.proxy = ProxyChoice::Other;
        a.proxy_url = "gopher://x".into();
        assert!(check(2, &a).is_err());

        a.guard = Guard::SecurityKey;
        assert!(check(3, &a).is_err(), "no recovery passphrase");
        *a.secret = "words".into();
        *a.secret_again = "other".into();
        assert!(check(3, &a).is_err(), "not the same");
        *a.secret_again = "words".into();
        assert!(check(3, &a).is_ok());
        a.key_name = " ".into();
        assert!(check(3, &a).is_err(), "no name");

        a.backup = true;
        assert!(check(6, &a).is_err(), "no file");
        a.link = true;
        assert!(
            check(6, &a).is_ok(),
            "a linked device has nothing to back up"
        );
    }

    #[test]
    fn the_questions_follow_the_answers() {
        let mut a = Answers::new(&ctx());
        assert_eq!(fields(3, &a, &ctx()), [F::Guard]);
        a.guard = Guard::SecurityKey;
        assert_eq!(
            fields(3, &a, &ctx()),
            [F::Guard, F::Secret, F::SecretAgain, F::KeyName, F::Spare]
        );
        assert!(!fields(4, &Answers::new(&ctx()), &ctx()).contains(&F::LockAfter));
        assert!(fields(4, &a, &ctx()).contains(&F::LockAfter));
        a.link = true;
        assert!(fields(6, &a, &ctx()).is_empty());
        assert_eq!(fields(1, &a, &ctx()), [F::Start, F::DeviceName]);
    }

    #[test]
    fn the_keys_walk_the_steps() {
        let mut w = Wizard::new(&ctx());
        // Welcome: Right changes the colours, and the screen shows it.
        press(&mut w, KeyCode::Right);
        assert_eq!(w.a.theme, ThemeName::Light);
        press(&mut w, KeyCode::PageDown);
        assert_eq!(w.step, 1);
        // This computer: 2 picks "link", and its name is typed.
        press(&mut w, KeyCode::Char('2'));
        assert!(w.a.link);
        press(&mut w, KeyCode::Down);
        typed(&mut w, "laptop");
        assert_eq!(w.a.device_name, "laptop");
        press(&mut w, KeyCode::Enter);
        assert_eq!(w.step, 2);
        // Relay: cleared and typed wrong, it does not pass.
        w.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        typed(&mut w, "relay.example");
        press(&mut w, KeyCode::PageDown);
        assert_eq!(w.step, 2);
        assert!(w.error.is_some());
        w.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        typed(&mut w, "wss://relay.example/ws");
        press(&mut w, KeyCode::PageDown);
        assert_eq!(w.step, 3);
        assert!(w.error.is_none());
        // Esc goes back, and the answers stay.
        press(&mut w, KeyCode::Esc);
        assert_eq!(w.step, 2);
        assert_eq!(w.a.relay, "wss://relay.example/ws");
        // To the review, and Enter there applies.
        for _ in 0..10 {
            if w.step == REVIEW {
                break;
            }
            press(&mut w, KeyCode::PageDown);
        }
        assert_eq!(w.step, REVIEW);
        assert!(matches!(press(&mut w, KeyCode::Enter), Action::Apply));
        assert!(matches!(
            w.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Action::Quit
        ));
    }

    #[test]
    fn applying_sets_the_directory_up() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let mut a = Answers::new(&ctx());
        a.guard = Guard::Passphrase;
        *a.secret = "correct horse".into();
        *a.secret_again = "correct horse".into();
        a.backup = true;
        a.backup_path = dir
            .path()
            .join("first.backup")
            .to_string_lossy()
            .into_owned();
        *a.backup_secret = "backup words".into();
        let mut auth = || -> anyhow::Result<Box<dyn silver_key::Authenticator>> {
            unreachable!("no security key was chosen")
        };
        let outcome = apply(&a, &mut store, &mut auth, &mut || {}).ok().unwrap();
        assert!(outcome.link.is_none());
        assert!(store.has_identity());
        assert!(store.has_passphrase());
        assert!(dir.path().join("first.backup").exists());
        let mut again = Store::open(dir.path()).unwrap();
        again.unlock("correct horse").unwrap();
        assert_eq!(
            again.load_config().unwrap().relay_url.as_deref(),
            Some("wss://relay.example/ws")
        );
    }

    #[test]
    fn a_security_key_that_is_not_had_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let mut a = Answers::new(&ctx());
        a.guard = Guard::SecurityKey;
        *a.secret = "recovery words".into();
        let mut auth = || -> anyhow::Result<Box<dyn silver_key::Authenticator>> {
            Err(silver_key::Error::Cancelled.into())
        };
        let failed = apply(&a, &mut store, &mut auth, &mut || {}).err().unwrap();
        assert_eq!(failed.step, 3);
        // No identity, so the next start asks again; no settings either.
        assert!(!store.has_identity(), "no identity left unprotected");
        assert!(!dir.path().join("config.json").exists());
    }

    #[test]
    fn applying_with_a_security_key_enrolls_it_and_a_spare() {
        use silver_key::soft::{SoftKey, authenticator};
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let mut a = Answers::new(&ctx());
        a.guard = Guard::SecurityKey;
        *a.secret = "recovery words".into();
        a.key_name = "YubiKey".into();
        a.spare = true;
        let keys = [
            Arc::new(Mutex::new(SoftKey::new([1; 32]).with_pin("4831"))),
            Arc::new(Mutex::new(SoftKey::new([2; 32]).with_pin("4831"))),
        ];
        // The first enrollment gets the first key; the swap between them
        // puts the spare in.
        let which = std::cell::Cell::new(0);
        let mut auth = || -> anyhow::Result<Box<dyn silver_key::Authenticator>> {
            Ok(Box::new(authenticator(keys[which.get()].clone(), "4831")))
        };
        let mut between = || which.set(1);
        let outcome = apply(&a, &mut store, &mut auth, &mut between);
        assert!(outcome.is_ok());
        assert_eq!(
            store.security_keys().unwrap(),
            ["YubiKey", "YubiKey (spare)"]
        );
        let mut again = Store::open(dir.path()).unwrap();
        again.unlock("recovery words").unwrap();
    }
}
