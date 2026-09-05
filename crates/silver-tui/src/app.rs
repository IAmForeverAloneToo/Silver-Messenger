//! Application state, key handling and command dispatch.

mod groups;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use ratatui::layout::Rect;
use silver_client::sequence::{self, SequenceCheck};
use silver_client::{
    Client, ClientError, ClientEvent, Contact, ContactRequest, Delivery, Direction, FileInfo,
    HeldMessage, HistoryEntry, InviteLink, Progress, ReceiptQueue, Store,
};
use silver_protocol::envelope::{ReceiptKind, capability};
use silver_protocol::{Content, KeyBundle, Message, UserId, now_ms};
use tokio::sync::mpsc;

use crate::clipboard::{Clipboard, Copied};
use crate::commands;
use crate::glyphs::{Glyphs, Marks};
use crate::notify::{Notifier, NotifyMode};
use crate::theme::{Theme, ThemeName};
use crate::{qr, ui};

const TOAST_TTL: Duration = Duration::from_secs(6);
/// A second Ctrl-C within this long quits.
const QUIT_CONFIRM: Duration = Duration::from_secs(3);
const SCROLL_STEP: usize = 5;
const MOUSE_SCROLL_STEP: usize = 3;
const HISTORY_LIMIT: usize = 200;
const SEARCH_LIMIT: usize = 30;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Connection {
    Connecting,
    Connected,
    Disconnected,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    /// A row of a QR code: drawn dark on light, unwrapped, without a clock.
    Code,
}

/// One row in a conversation.
pub struct ChatLine {
    pub id: String,
    pub direction: Direction,
    pub timestamp_ms: u64,
    pub text: String,
    /// The relay has accepted this outgoing message.
    pub delivered: bool,
    /// The relay refused this outgoing message for good.
    pub failed: bool,
    /// For sent messages: the furthest receipt the peer returned.
    pub receipt: Option<ReceiptKind>,
    /// For received files: where the file was saved.
    pub file: Option<PathBuf>,
    /// For received files not fetched yet: how to fetch it.
    pub pending: Option<FileInfo>,
    /// In a group: who wrote it (`None` for our own lines and for notes
    /// about the group).
    pub sender: Option<UserId>,
}

/// The saved location a file line names, if it does: `[file] name (size)
/// → /path` (or `->` in ASCII).
fn saved_file_path(text: &str) -> Option<PathBuf> {
    let rest = text.strip_prefix("[file] ")?;
    let path = rest
        .rsplit_once(" → ")
        .or_else(|| rest.rsplit_once(" -> "))
        .map(|(_, path)| path.trim())?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// One row in the system pane.
pub struct SystemLine {
    pub timestamp_ms: u64,
    pub level: Level,
    pub text: String,
}

/// What the message pane shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    System,
    Requests,
    Thread(UserId),
    Group(silver_protocol::group::GroupId),
}

/// One row of the message pane as laid out: its text, and which entry of
/// the pane's list (a message, a system line) it belongs to.
pub struct ViewRow {
    pub text: String,
    pub source: Option<usize>,
}

/// What the last frame drew, so mouse positions and selections can be
/// mapped back to text.
pub struct View {
    pub pane: Pane,
    /// The inside of the message pane.
    pub messages: Rect,
    /// Every row of the pane's content, visible or not.
    pub rows: Vec<ViewRow>,
    /// Index into `rows` of the first visible row.
    pub start: usize,
    pub sidebar: Rect,
    pub input: Rect,
    pub status: Rect,
}

impl Default for View {
    fn default() -> Self {
        Self {
            pane: Pane::System,
            messages: Rect::default(),
            rows: Vec::new(),
            start: 0,
            sidebar: Rect::default(),
            input: Rect::default(),
            status: Rect::default(),
        }
    }
}

/// Tab completion in progress: what was typed before the completed part,
/// the candidates, and which one is shown.
struct Completion {
    stem: String,
    candidates: Vec<String>,
    index: usize,
}

/// A selection in the message pane, in (row, column) coordinates of
/// `View::rows`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub anchor: (usize, usize),
    pub head: (usize, usize),
    /// Whole rows, whatever the columns say (keyboard and triple click).
    pub rows_only: bool,
}

impl Selection {
    /// Start and end (both inclusive), ordered.
    pub fn bounds(&self) -> ((usize, usize), (usize, usize)) {
        if self.anchor <= self.head {
            (self.anchor, self.head)
        } else {
            (self.head, self.anchor)
        }
    }
}

/// Clicks closer together than this on the same cell count as one.
const MULTI_CLICK: Duration = Duration::from_millis(450);
/// Strangers waiting in the Requests pane, at most.
const MAX_REQUESTS: usize = 50;
/// Messages kept per waiting stranger, at most; older ones go first.
const MAX_HELD_PER_SENDER: usize = 20;
/// Characters kept of a held message.
const MAX_HELD_CHARS: usize = 4000;
/// Characters an alias may have.
const MAX_ALIAS_CHARS: usize = 40;
/// Message ids remembered for de-duplication.
const KNOWN_IDS_CAP: usize = 20_000;
/// How far ahead of this clock a peer's claimed send time may be.
const FUTURE_SLACK_MS: u64 = 2 * 60 * 1000;

/// A peer's claimed send time, kept from placing a message in the future.
fn claimed_time(sent_at_ms: u64) -> u64 {
    sent_at_ms.min(now_ms().saturating_add(FUTURE_SLACK_MS))
}

/// The most recent message ids, for telling a re-delivery from a new
/// message without remembering every id ever seen.
pub struct RecentIds {
    set: HashSet<String>,
    order: std::collections::VecDeque<String>,
    cap: usize,
}

impl RecentIds {
    pub fn new(cap: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: std::collections::VecDeque::new(),
            cap: cap.max(1),
        }
    }

    pub fn insert(&mut self, id: String) {
        if !self.set.insert(id.clone()) {
            return;
        }
        self.order.push_back(id);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }
}

/// Results of background work spawned by the UI.
#[allow(clippy::large_enum_variant)] // a looked-up bundle carries ML-KEM keys
enum Internal {
    LookupDone {
        user_id: UserId,
        alias: Option<String>,
        result: Result<Option<KeyBundle>, ClientError>,
    },
    SendDone {
        peer: UserId,
        content: Content,
        result: Result<Box<Delivery>, String>,
    },
    /// A transfer moved on; shown as a toast.
    Progress { text: String },
    /// A file is on the relay (or could not be put there).
    Uploaded {
        peer: UserId,
        result: Result<FileInfo, String>,
    },
    /// A received file was fetched and saved (or not).
    Downloaded {
        peer: UserId,
        id: String,
        info: FileInfo,
        result: Result<PathBuf, String>,
    },
    /// The relay's sequencer answered about a group.
    GroupSequenced {
        group: silver_protocol::group::GroupId,
        purpose: groups::Purpose,
        answer: Result<silver_client::SequencerAnswer, String>,
    },
    /// A group message's envelopes (and blobs) were handed to the relay.
    GroupSent {
        group: silver_protocol::group::GroupId,
        id: Option<String>,
        text: Option<String>,
        result: Result<(), String>,
    },
    /// A parked group message was fetched from the blob store.
    GroupParked {
        from: UserId,
        body: Box<silver_protocol::group::GroupBody>,
        chunks: Result<Vec<Vec<u8>>, String>,
    },
    /// The relay answered a key package request.
    KeyPackageFor {
        group: silver_protocol::group::GroupId,
        user: UserId,
        result: Result<Option<(silver_protocol::wire::KeyPackageDeposit, bool)>, String>,
    },
    /// The relay answered a key package deposit.
    KeyPackages {
        result: Result<silver_client::KeyPackageStatus, String>,
    },
    /// The admin an invite link names was looked up.
    GroupJoinLookup {
        link: silver_client::GroupLink,
        result: Result<Option<KeyBundle>, String>,
    },
    GroupUploaded {
        group: silver_protocol::group::GroupId,
        result: Result<FileInfo, String>,
    },
    GroupDownloaded {
        group: silver_protocol::group::GroupId,
        id: String,
        info: FileInfo,
        result: Result<PathBuf, String>,
    },
}

pub struct App {
    store: Store,
    client: Client,
    pub relay_url: String,
    pub me: UserId,
    pub connection: Connection,
    pub contacts: Vec<Contact>,
    /// Messages from unknown senders awaiting /accept or /block.
    pub requests: Vec<ContactRequest>,
    blocked: Vec<UserId>,
    pub threads: HashMap<UserId, Vec<ChatLine>>,
    /// Ids of messages received but not yet shown, per contact.
    pub unread: HashMap<UserId, Vec<String>>,
    /// The groups engine (`docs/design/groups.md`).
    groups: silver_client::Groups,
    /// Groups in the chat list, in order; invitations are not listed.
    pub group_list: Vec<silver_protocol::group::GroupId>,
    pub group_threads: HashMap<silver_protocol::group::GroupId, Vec<ChatLine>>,
    pub group_unread: HashMap<silver_protocol::group::GroupId, Vec<String>>,
    /// The first unread message of the group that was just opened.
    pub group_new_marker: Option<(silver_protocol::group::GroupId, String)>,
    /// Envelope id -> (group, message id), for the sent mark of a message
    /// that goes out as one envelope per member.
    group_envelopes: HashMap<String, (silver_protocol::group::GroupId, String)>,
    /// Message id -> envelopes the relay has not accepted yet.
    group_outstanding: HashMap<String, usize>,
    /// When to put key packages on deposit again.
    key_packages_due: Option<Instant>,
    last_group_maintenance: Instant,
    known_ids: RecentIds,
    /// The note that the Requests pane is full has been made.
    requests_full_noted: bool,
    /// Receipts waiting to go out.
    receipts: ReceiptQueue,
    /// Whether to tell contacts when their messages were shown.
    pub read_receipts: bool,
    /// Whether to send cover traffic to contacts who do the same.
    pub cover: bool,
    /// Who is being covered and when the next cover message is due.
    cover_schedule: silver_client::CoverSchedule,
    /// The symbols the interface draws with.
    pub glyphs: Glyphs,
    pub theme: Theme,
    /// The terminal is too narrow for the chat list; set by the renderer.
    pub narrow: bool,
    /// The first unread message of the chat that was just opened, for the
    /// "new messages" rule above it.
    pub new_marker: Option<(UserId, String)>,
    clipboard: Clipboard,
    /// When Ctrl-C was pressed with nothing to copy; a second press quits.
    quit_armed: Option<Instant>,
    /// What the last frame drew.
    pub view: View,
    pub selection: Option<Selection>,
    /// The left button is down in the message pane.
    selecting: bool,
    /// The last press: when, where, and how many in a row.
    last_click: Option<(Instant, (usize, usize), u8)>,
    /// Columns given to the chat list; the divider drags it.
    pub sidebar_width: u16,
    /// Most `downloads/` may hold, from `downloads_quota_mib` in the config.
    downloads_quota: Option<u64>,
    /// The left button is down on the divider.
    resizing: bool,
    /// The left button is down on the scrollbar.
    dragging_scrollbar: bool,
    /// The help overlay is up.
    pub help_open: bool,
    /// Rows the help overlay is scrolled down; clamped by the renderer.
    pub help_scroll: usize,
    completion: Option<Completion>,
    notifier: Notifier,
    pub system: Vec<SystemLine>,
    /// 0 is the system pane; `i >= 1` selects `contacts[i - 1]`.
    pub selected: usize,
    pub input: String,
    /// Cursor position in `input`, in chars.
    pub cursor: usize,
    /// Lines sent or run before, oldest first, for Up/Down recall.
    history: Vec<String>,
    /// Which history entry the input currently shows, while recalling.
    history_pos: Option<usize>,
    /// What was being typed when recall started.
    history_draft: String,
    /// The terminal window has focus, as far as it tells us.
    pub focused: bool,
    /// Rows scrolled up from the bottom of the message pane.
    pub scroll: usize,
    /// Set by the renderer so scrolling can be clamped.
    pub max_scroll: usize,
    pub toast: Option<(String, Instant)>,
    internal_tx: mpsc::Sender<Internal>,
    internal_rx: Option<mpsc::Receiver<Internal>>,
    /// Epoch for numbering outgoing messages; see [`silver_protocol::Sequence`].
    send_epoch: u64,
    should_quit: bool,
    /// How the data directory is protected on disk.
    at_rest: AtRest,
    /// Lock after this long without a keystroke, when set and possible.
    lock_after: Option<Duration>,
    last_activity: Instant,
    /// `/lock` was asked for, or the idle time ran out.
    lock_requested: bool,
    /// `/rotate` handed over to a new identity this session. The data
    /// directory already holds the new key while this session still runs
    /// as the old one, so no further identity change is taken until a
    /// restart: `/revoke` would retire the new key, not the old.
    rotated: bool,
}

/// What stands between the data directory and whoever copies it, as the
/// front end tells the user at the start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtRest {
    Passphrase,
    Keystore,
    /// Plain files, and why.
    Plain(String),
}

/// Why [`App::run`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Quit,
    /// Drop everything that holds keys and ask for the passphrase again.
    Lock,
}

impl App {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Store,
        client: Client,
        relay_url: String,
        fresh_identity: bool,
        send_epoch: u64,
        glyphs: Glyphs,
        theme: Theme,
        at_rest: AtRest,
    ) -> anyhow::Result<Self> {
        let me = client.user_id();
        let contacts = store.load_contacts()?;
        let requests = store.load_requests()?;
        let blocked = store.load_blocked()?;
        let config = store.load_config()?;
        let read_receipts = config.read_receipts;
        let cover = config.cover;
        client.set_cover(cover);
        let lock_after = (config.lock_after_minutes > 0)
            .then(|| Duration::from_secs(config.lock_after_minutes.saturating_mul(60)));
        let notifier = Notifier::new(NotifyMode::parse(&config.notify).unwrap_or(NotifyMode::All));
        let pending: HashSet<String> = client.pending_ids().into_iter().collect();
        let mut threads = HashMap::new();
        let mut known_ids = RecentIds::new(KNOWN_IDS_CAP);
        for id in requests
            .iter()
            .flat_map(|r| r.messages.iter().map(|m| &m.id))
        {
            known_ids.insert(id.clone());
        }
        for contact in &contacts {
            let lines: Vec<ChatLine> = store
                .load_history(&contact.user_id)?
                .into_iter()
                .map(|h| {
                    known_ids.insert(h.id.clone());
                    let delivered = !pending.contains(&h.id);
                    let file = match h.direction {
                        Direction::Received => saved_file_path(&h.text),
                        Direction::Sent => None,
                    };
                    // A file still waits until its line says where it went.
                    let pending = h.file.filter(|_| file.is_none());
                    ChatLine {
                        id: h.id,
                        direction: h.direction,
                        timestamp_ms: h.timestamp_ms,
                        text: h.text,
                        delivered,
                        failed: false,
                        receipt: h.receipt,
                        file,
                        pending,
                        sender: None,
                    }
                })
                .collect();
            threads.insert(contact.user_id, lines);
        }
        let groups = silver_client::Groups::load(&store, client.identity_arc())?;
        let mut group_threads = HashMap::new();
        for (id, _) in groups.list() {
            let lines: Vec<ChatLine> = store
                .load_group_history(id)?
                .into_iter()
                .map(|h| {
                    known_ids.insert(h.id.clone());
                    let file = match h.direction {
                        Direction::Received => saved_file_path(&h.text),
                        Direction::Sent => None,
                    };
                    let pending = h.file.filter(|_| file.is_none());
                    ChatLine {
                        id: h.id,
                        direction: h.direction,
                        timestamp_ms: h.timestamp_ms,
                        text: h.text,
                        delivered: true,
                        failed: false,
                        receipt: None,
                        file,
                        pending,
                        sender: h.from,
                    }
                })
                .collect();
            group_threads.insert(*id, lines);
        }
        let (internal_tx, internal_rx) = mpsc::channel(64);
        let mut app = Self {
            store,
            client,
            relay_url,
            me,
            connection: Connection::Connecting,
            contacts,
            requests,
            blocked,
            threads,
            unread: HashMap::new(),
            groups,
            group_list: Vec::new(),
            group_threads,
            group_unread: HashMap::new(),
            group_new_marker: None,
            group_envelopes: HashMap::new(),
            group_outstanding: HashMap::new(),
            key_packages_due: None,
            last_group_maintenance: Instant::now(),
            known_ids,
            requests_full_noted: false,
            receipts: ReceiptQueue::default(),
            read_receipts,
            cover,
            cover_schedule: silver_client::CoverSchedule::default(),
            glyphs,
            theme,
            narrow: false,
            new_marker: None,
            clipboard: Clipboard::new(),
            quit_armed: None,
            view: View::default(),
            selection: None,
            selecting: false,
            last_click: None,
            sidebar_width: config.sidebar_width.clamp(12, 60),
            downloads_quota: config.downloads_quota(),
            resizing: false,
            dragging_scrollbar: false,
            help_open: false,
            help_scroll: 0,
            completion: None,
            notifier,
            system: Vec::new(),
            selected: 0,
            input: String::new(),
            cursor: 0,
            history: Vec::new(),
            history_pos: None,
            history_draft: String::new(),
            focused: true,
            scroll: 0,
            max_scroll: 0,
            toast: None,
            internal_tx,
            internal_rx: Some(internal_rx),
            send_epoch,
            should_quit: false,
            at_rest,
            lock_after,
            last_activity: Instant::now(),
            lock_requested: false,
            rotated: false,
        };
        app.refresh_group_list();
        app.system(Level::Info, "Welcome to Silver Messenger.");
        match &app.at_rest {
            AtRest::Passphrase => {}
            AtRest::Keystore => app.system(
                Level::Info,
                "Keys, contacts and history are encrypted with a key kept in this computer's key store: a copy of the data directory is useless elsewhere. A passphrase (--set-passphrase) protects them from anyone using this account too.",
            ),
            AtRest::Plain(why) => app.system(
                Level::Warn,
                format!(
                    "Keys, contacts and history are stored unencrypted: {why}. --set-passphrase protects them with a passphrase."
                ),
            ),
        }
        if fresh_identity {
            app.system(
                Level::Info,
                format!("Generated a new identity in {}", app.store.root().display()),
            );
        }
        app.system(Level::Info, format!("Your id: {me}"));
        app.system(
            Level::Info,
            "Share it with people who want to message you. F1 or /help lists every command and key.",
        );
        if fresh_identity || (app.contacts.is_empty() && app.requests.is_empty()) {
            for line in [
                "Getting started:",
                "  1. Share your id: /invite shows it as a link and a QR code, /copy id puts it on the clipboard.",
                "  2. Add someone with /add <their id or link>, or accept their request in the Requests pane when they write first.",
                "  3. Type to chat. /send <path> sends a file. Tab completes commands and paths; F1 shows everything.",
            ] {
                app.system(Level::Info, line);
            }
        }
        if !app.requests.is_empty() {
            let n = app.requests.len();
            app.system(
                Level::Info,
                format!("{n} contact request(s) waiting in the Requests pane."),
            );
        }
        Ok(app)
    }

    pub async fn run(
        mut self,
        mut terminal: DefaultTerminal,
        mut events: mpsc::Receiver<ClientEvent>,
    ) -> anyhow::Result<Exit> {
        let mut keys = spawn_input_thread();
        let mut internal_rx = self.internal_rx.take().expect("run is called once");
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        self.notifier.push_title();

        let exit = loop {
            terminal.draw(|frame| ui::draw(frame, &mut self))?;
            let unread: usize = self.unread.values().map(Vec::len).sum::<usize>()
                + self.group_unread.values().map(Vec::len).sum::<usize>()
                + self.held_message_count();
            self.notifier.set_unread(unread);
            tokio::select! {
                Some(ev) = keys.recv() => {
                    self.last_activity = Instant::now();
                    self.handle_terminal_event(ev)
                }
                Some(ev) = events.recv() => self.handle_client_event(ev),
                Some(ev) = internal_rx.recv() => self.handle_internal(ev),
                _ = tick.tick() => {
                    self.expire_toast();
                    self.flush_receipts();
                    self.flush_cover();
                    self.maintain_groups();
                    if let Some(after) = self.lock_after {
                        if self.can_lock() && self.last_activity.elapsed() >= after {
                            self.lock_requested = true;
                        }
                    }
                }
            }
            if self.lock_requested {
                break Exit::Lock;
            }
            if self.should_quit {
                break Exit::Quit;
            }
        };
        self.notifier.pop_title();
        self.client.shutdown().await;
        Ok(exit)
    }

    /// Locking only means something when a passphrase stands between the
    /// files and the next start.
    fn can_lock(&self) -> bool {
        self.at_rest == AtRest::Passphrase
    }

    /// `/lock`: drop the keys and ask for the passphrase again.
    fn cmd_lock(&mut self) {
        if self.can_lock() {
            self.lock_requested = true;
        } else {
            self.toast("Locking needs a passphrase: set one with --set-passphrase.");
        }
    }

    // --- derived state -----------------------------------------------------

    pub fn selected_contact(&self) -> Option<&Contact> {
        self.selected
            .checked_sub(1)
            .and_then(|i| self.contacts.get(i))
    }

    fn contact_index(&self, user_id: &UserId) -> Option<usize> {
        self.contacts.iter().position(|c| c.user_id == *user_id)
    }

    /// Index into `contacts` of the selected pane, if it is a contact.
    fn selected_contact_index(&self) -> Option<usize> {
        self.selected
            .checked_sub(1)
            .filter(|i| *i < self.contacts.len())
    }

    /// Panes: System, one per contact, one per group, then Requests while
    /// any request or invitation is pending.
    pub fn pane_count(&self) -> usize {
        self.contacts.len() + self.group_list.len() + 1 + usize::from(self.has_requests_pane())
    }

    /// Whether the Requests pane is shown: contact requests or group
    /// invitations wait.
    pub fn has_requests_pane(&self) -> bool {
        !self.requests.is_empty() || !self.invitations().is_empty()
    }

    pub fn requests_pane_selected(&self) -> bool {
        self.has_requests_pane() && self.selected == self.contacts.len() + self.group_list.len() + 1
    }

    /// Total messages waiting in contact requests, plus group invitations.
    pub fn held_message_count(&self) -> usize {
        self.requests
            .iter()
            .map(|r| r.messages.len())
            .sum::<usize>()
            + self.invitations().len()
    }

    fn contact_name(&self, user_id: &UserId) -> String {
        self.contact_index(user_id)
            .map(|i| self.contacts[i].display_name())
            .unwrap_or_else(|| format!("{}…", user_id.short()))
    }

    /// Outgoing messages the relay has not accepted yet.
    pub fn pending_count(&self) -> usize {
        self.client.pending_count()
    }

    /// How messages with this contact are protected, for the pane title.
    pub fn encryption_label(&self, contact: &Contact) -> Option<&'static str> {
        if let Some(info) = self.client.session_info(&contact.user_id) {
            Some(if info.post_quantum {
                "forward secret, post-quantum"
            } else {
                "forward secret"
            })
        } else if contact
            .bundle
            .as_ref()
            .is_some_and(|b| !b.supports_sessions())
        {
            if self.relay_supports_prekeys() {
                Some("their client has no forward secrecy yet")
            } else {
                Some("relay too old for forward secrecy")
            }
        } else {
            None
        }
    }

    fn relay_supports_prekeys(&self) -> bool {
        self.client
            .relay_supports(silver_protocol::wire::feature::PREKEYS)
    }

    fn mark_line(&mut self, id: &str, update: impl FnOnce(&mut ChatLine)) {
        for lines in self.threads.values_mut() {
            if let Some(line) = lines.iter_mut().rev().find(|l| l.id == id) {
                update(line);
                return;
            }
        }
    }

    fn contact_supports(&self, user_id: &UserId, cap: &str) -> bool {
        self.contact_index(user_id)
            .is_some_and(|i| self.contacts[i].supports(cap))
    }

    // --- notices -----------------------------------------------------------

    fn system(&mut self, level: Level, text: impl Into<String>) {
        self.system.push(SystemLine {
            timestamp_ms: now_ms(),
            level,
            text: text.into(),
        });
    }

    fn toast(&mut self, text: impl Into<String>) {
        self.toast = Some((text.into(), Instant::now()));
    }

    fn expire_toast(&mut self) {
        if self
            .toast
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() > TOAST_TTL)
        {
            self.toast = None;
        }
    }

    // --- terminal input ----------------------------------------------------

    fn handle_terminal_event(&mut self, ev: Event) {
        match ev {
            Event::Key(key) if key.kind != KeyEventKind::Release => self.handle_key(key),
            Event::Paste(text) => self.insert_str(&text.replace("\r\n", "\n").replace('\r', "\n")),
            Event::Mouse(mouse) => match mouse.kind {
                MouseEventKind::ScrollUp if self.help_open => {
                    self.help_scroll = self.help_scroll.saturating_sub(MOUSE_SCROLL_STEP)
                }
                MouseEventKind::ScrollDown if self.help_open => {
                    self.help_scroll += MOUSE_SCROLL_STEP
                }
                MouseEventKind::ScrollUp => self.scroll_by(MOUSE_SCROLL_STEP as isize),
                MouseEventKind::ScrollDown => self.scroll_by(-(MOUSE_SCROLL_STEP as isize)),
                MouseEventKind::Down(MouseButton::Right) => self.paste_from_clipboard(),
                MouseEventKind::Down(MouseButton::Left) => self.mouse_down(mouse.column, mouse.row),
                MouseEventKind::Drag(MouseButton::Left) => self.mouse_drag(mouse.column, mouse.row),
                MouseEventKind::Up(MouseButton::Left) => self.mouse_up(),
                _ => {}
            },
            Event::FocusGained => {
                self.focused = true;
                self.mark_selected_read();
            }
            Event::FocusLost => self.focused = false,
            _ => {}
        }
    }

    fn scroll_by(&mut self, rows: isize) {
        self.scroll = self.scroll.saturating_add_signed(rows).min(self.max_scroll);
    }

    // --- selection ---------------------------------------------------------

    /// The content row and column under a screen position inside the
    /// message pane, if any.
    fn cell_at(&self, x: u16, y: u16) -> Option<(usize, usize)> {
        let pane = self.view.messages;
        if !pane.contains(ratatui::layout::Position::new(x, y)) {
            return None;
        }
        let row = self.view.start + (y - pane.y) as usize;
        (row < self.view.rows.len()).then_some((row, (x - pane.x) as usize))
    }

    /// Whether (x, y) is the sidebar's right border, which drags to resize.
    fn on_divider(&self, x: u16, y: u16) -> bool {
        let sidebar = self.view.sidebar;
        sidebar.width > 0
            && x == sidebar.x + sidebar.width - 1
            && y >= sidebar.y
            && y < sidebar.y + sidebar.height
    }

    /// Whether (x, y) is on the message pane's scrollbar (its right border).
    fn on_scrollbar(&self, x: u16, y: u16) -> bool {
        let pane = self.view.messages;
        self.max_scroll > 0 && x == pane.x + pane.width && y >= pane.y && y < pane.y + pane.height
    }

    /// Scroll so the position on the scrollbar at row `y` is under the thumb.
    fn scroll_to_scrollbar(&mut self, y: u16) {
        let pane = self.view.messages;
        let span = pane.height.saturating_sub(1).max(1) as usize;
        let at = (y.saturating_sub(pane.y) as usize).min(span);
        let from_top = (at * self.max_scroll).div_ceil(span).min(self.max_scroll);
        self.scroll = self.max_scroll - from_top;
    }

    fn mouse_down(&mut self, x: u16, y: u16) {
        if self.help_open {
            self.help_open = false;
            self.help_scroll = 0;
            return;
        }
        if self
            .view
            .status
            .contains(ratatui::layout::Position::new(x, y))
        {
            // The status line always offers help.
            self.help_open = true;
            return;
        }
        if self.on_divider(x, y) {
            self.resizing = true;
            return;
        }
        if self.on_scrollbar(x, y) {
            self.dragging_scrollbar = true;
            self.scroll_to_scrollbar(y);
            return;
        }
        let Some(cell) = self.cell_at(x, y) else {
            // A click anywhere else drops the selection; in the chat list
            // it also opens the chat under the pointer.
            self.selection = None;
            self.selecting = false;
            let sidebar = self.view.sidebar;
            if sidebar.contains(ratatui::layout::Position::new(x, y))
                && y > sidebar.y
                && x > sidebar.x
            {
                let row = (y - sidebar.y - 1) as usize;
                if row < self.pane_count() {
                    self.select(row);
                }
            }
            return;
        };
        let clicks = match self.last_click {
            Some((at, last, n)) if last == cell && at.elapsed() < MULTI_CLICK => n % 3 + 1,
            _ => 1,
        };
        self.last_click = Some((Instant::now(), cell, clicks));
        match clicks {
            1 => {
                self.selection = Some(Selection {
                    anchor: cell,
                    head: cell,
                    rows_only: false,
                });
                self.selecting = true;
            }
            2 => match (self.file_at_row(cell.0), self.pending_at_row(cell.0)) {
                (Some(path), _) => {
                    self.selection = None;
                    self.open_file(&path);
                }
                (None, Some((peer, id, info))) => {
                    self.selection = None;
                    self.start_download(peer, id, info);
                }
                (None, None) => self.select_word(cell),
            },
            _ => self.select_source(cell.0),
        }
    }

    fn mouse_drag(&mut self, x: u16, y: u16) {
        if self.resizing {
            let sidebar = self.view.sidebar;
            self.sidebar_width = (x.saturating_sub(sidebar.x) + 1).clamp(12, 60);
            return;
        }
        if self.dragging_scrollbar {
            self.scroll_to_scrollbar(y);
            return;
        }
        if !self.selecting {
            return;
        }
        let pane = self.view.messages;
        // Dragging past the top or bottom scrolls the pane along.
        if y < pane.y {
            self.scroll_by(1);
        } else if y >= pane.y + pane.height {
            self.scroll_by(-1);
        }
        let y = y.clamp(pane.y, (pane.y + pane.height).saturating_sub(1).max(pane.y));
        let x = x.clamp(pane.x, (pane.x + pane.width).saturating_sub(1).max(pane.x));
        let Some(cell) = self.cell_at(x, y) else {
            return;
        };
        if let Some(selection) = &mut self.selection {
            selection.head = cell;
        }
    }

    fn mouse_up(&mut self) {
        if self.resizing {
            self.resizing = false;
            let mut config = self.store.load_config().unwrap_or_default();
            config.sidebar_width = self.sidebar_width;
            if let Err(e) = self.store.save_config(&config) {
                self.toast(format!("Could not save config: {e}"));
            }
            return;
        }
        self.dragging_scrollbar = false;
        if !self.selecting {
            return;
        }
        self.selecting = false;
        // A click without a drag is not a selection; it may be an open.
        if let Some(s) = self
            .selection
            .filter(|s| s.anchor == s.head && !s.rows_only)
        {
            self.selection = None;
            self.click_row(s.anchor.0);
        }
    }

    /// Double click: the word under the cursor.
    fn select_word(&mut self, (row, col): (usize, usize)) {
        let Some(text) = self.view.rows.get(row).map(|r| r.text.as_str()) else {
            return;
        };
        self.selection = ui::word_at(text, col).map(|(from, to)| Selection {
            anchor: (row, from),
            head: (row, to),
            rows_only: false,
        });
    }

    /// Triple click: every row of the message (or system line) the row
    /// belongs to; a row that belongs to none is selected alone.
    fn select_source(&mut self, row: usize) {
        if row >= self.view.rows.len() {
            return;
        }
        let (first, last) = self.source_rows(row);
        self.selection = Some(Selection {
            anchor: (first, 0),
            head: (last, usize::MAX),
            rows_only: true,
        });
    }

    /// Shift-Up / Shift-Down: extend a selection of whole messages from the
    /// newest one upwards, or shrink it again.
    fn select_rows_by_key(&mut self, up: bool) {
        let total = self.view.rows.len();
        if total == 0 {
            return;
        }
        let selection = match self.selection {
            Some(s) if s.rows_only => s,
            _ => {
                // The first press selects the newest message.
                let (first, last) = self.source_rows(total - 1);
                self.selection = Some(Selection {
                    anchor: (last, usize::MAX),
                    head: (first, 0),
                    rows_only: true,
                });
                self.scroll_row_into_view(first);
                return;
            }
        };
        let head_row = if up {
            let Some(above) = selection.head.0.checked_sub(1) else {
                return;
            };
            self.source_rows(above).0
        } else {
            let below = self.source_rows(selection.head.0).1 + 1;
            if below > selection.anchor.0 {
                return; // nothing left to shrink
            }
            below
        };
        self.selection = Some(Selection {
            head: (head_row, 0),
            ..selection
        });
        self.scroll_row_into_view(head_row);
    }

    /// First and last row of the message that `row` belongs to, or `row`
    /// alone when it belongs to none (a date rule).
    fn source_rows(&self, row: usize) -> (usize, usize) {
        let Some(source) = self.view.rows.get(row).and_then(|r| r.source) else {
            return (row, row);
        };
        let mut rows = self
            .view
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.source == Some(source))
            .map(|(i, _)| i);
        let first = rows.next().unwrap_or(row);
        let last = rows.next_back().unwrap_or(first);
        (first, last)
    }

    /// Scroll so that content row `row` is on screen.
    fn scroll_row_into_view(&mut self, row: usize) {
        let height = self.view.messages.height as usize;
        let total = self.view.rows.len();
        if height == 0 || total == 0 {
            return;
        }
        let end = total.saturating_sub(self.scroll);
        let start = end.saturating_sub(height);
        if row < start {
            self.scroll = total
                .saturating_sub(height)
                .saturating_sub(row)
                .min(self.max_scroll);
        } else if row >= end {
            self.scroll = total.saturating_sub(row + 1);
        }
    }

    /// The selected text, as a terminal would copy it: whole messages come
    /// out as "time name: text", partial rows as what is on screen.
    fn selection_text(&self) -> Option<String> {
        let selection = self.selection?;
        let ((r0, c0), (r1, c1)) = selection.bounds();
        let rows = &self.view.rows;
        if rows.is_empty() {
            return None;
        }
        let r1 = r1.min(rows.len() - 1);
        let mut out: Vec<String> = Vec::new();
        let mut skip_source: Option<usize> = None;
        for (i, row) in rows.iter().enumerate().take(r1 + 1).skip(r0) {
            if selection.rows_only {
                if row.source.is_some() && row.source == skip_source {
                    continue;
                }
                skip_source = None;
                // Date rules between messages are not text anyone wants.
                if row.source.is_none()
                    && matches!(self.view.pane, Pane::Thread(_) | Pane::Group(_))
                {
                    continue;
                }
                if let Some(source) = row.source {
                    let all_rows: Vec<usize> = rows
                        .iter()
                        .enumerate()
                        .filter(|(_, r)| r.source == Some(source))
                        .map(|(j, _)| j)
                        .collect();
                    let whole = all_rows.iter().all(|j| (r0..=r1).contains(j));
                    if whole && let Some(text) = self.source_text(source) {
                        out.push(text);
                        skip_source = Some(source);
                        continue;
                    }
                }
                out.push(row.text.trim_end().to_owned());
            } else {
                let from = if i == r0 { c0 } else { 0 };
                let to = if i == r1 { c1 } else { usize::MAX };
                out.push(ui::slice_columns(&row.text, from, to).trim_end().to_owned());
            }
        }
        let text = out.join("\n");
        (!text.trim().is_empty()).then_some(text)
    }

    /// The clean text of entry `source` of the shown pane.
    fn source_text(&self, source: usize) -> Option<String> {
        match self.view.pane {
            Pane::System => self.system.get(source).map(|l| {
                if l.level == Level::Code {
                    l.text.clone()
                } else {
                    format!("{} {}", ui::clock(l.timestamp_ms), l.text)
                }
            }),
            Pane::Requests => None,
            Pane::Thread(peer) => {
                let line = self.threads.get(&peer)?.get(source)?;
                let who = match line.direction {
                    Direction::Sent => "you".to_owned(),
                    Direction::Received => self.contact_name(&peer),
                };
                Some(format!(
                    "{} {who}: {}",
                    ui::clock(line.timestamp_ms),
                    line.text
                ))
            }
            Pane::Group(group) => {
                let line = self.group_threads.get(&group)?.get(source)?;
                let who = match (line.direction, line.sender) {
                    (Direction::Sent, _) => "you".to_owned(),
                    (_, Some(sender)) => self.member_name(&sender),
                    (_, None) => String::new(),
                };
                Some(if who.is_empty() {
                    format!("{} {}", ui::clock(line.timestamp_ms), line.text)
                } else {
                    format!("{} {who}: {}", ui::clock(line.timestamp_ms), line.text)
                })
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        if self.help_open {
            // The help scrolls with the usual keys; any other key closes it.
            match key.code {
                KeyCode::Up => self.help_scroll = self.help_scroll.saturating_sub(1),
                KeyCode::Down => self.help_scroll += 1,
                KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(SCROLL_STEP),
                KeyCode::PageDown => self.help_scroll += SCROLL_STEP,
                _ => {
                    self.help_open = false;
                    self.help_scroll = 0;
                }
            }
            return;
        }
        if key.code != KeyCode::Tab {
            self.completion = None;
        }
        match key.code {
            KeyCode::F(1) => self.help_open = true,
            KeyCode::Char('q') if ctrl => self.should_quit = true,
            KeyCode::Char('c') if ctrl => self.copy_or_quit(),
            KeyCode::Char('v') if ctrl => self.paste_from_clipboard(),
            KeyCode::Insert if shift => self.paste_from_clipboard(),
            KeyCode::Char('n') if ctrl => self.select_next(),
            KeyCode::Char('p') if ctrl => self.select_prev(),
            KeyCode::Char('u') if ctrl => self.clear_input(),
            KeyCode::Char('a') if ctrl => self.cursor = self.line_start(),
            KeyCode::Char('e') if ctrl => self.cursor = self.line_end(),
            KeyCode::Tab if self.input.starts_with('/') => self.complete(),
            KeyCode::Tab => self.select_next(),
            KeyCode::BackTab => self.select_prev(),
            KeyCode::Down if alt => self.select_next(),
            KeyCode::Up if alt => self.select_prev(),
            KeyCode::Up if shift => self.select_rows_by_key(true),
            KeyCode::Down if shift => self.select_rows_by_key(false),
            KeyCode::Up => self.input_up(),
            KeyCode::Down => self.input_down(),
            KeyCode::Home if ctrl => self.scroll = self.max_scroll,
            KeyCode::End if ctrl => self.scroll = 0,
            KeyCode::Home => self.cursor = self.line_start(),
            KeyCode::End => self.cursor = self.line_end(),
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.input.chars().count()),
            KeyCode::Enter if alt => self.insert_str("\n"),
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    let at = self.byte_index(self.cursor);
                    self.input.remove(at);
                    self.history_pos = None;
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.input.chars().count() {
                    let at = self.byte_index(self.cursor);
                    self.input.remove(at);
                    self.history_pos = None;
                }
            }
            KeyCode::PageUp => self.scroll = (self.scroll + SCROLL_STEP).min(self.max_scroll),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(SCROLL_STEP),
            KeyCode::Esc if self.selection.is_some() => self.selection = None,
            KeyCode::Esc => self.clear_input(),
            KeyCode::Enter => self.submit(),
            KeyCode::Char(c) if !ctrl && !alt => {
                let at = self.byte_index(self.cursor);
                self.input.insert(at, c);
                self.cursor += 1;
                self.history_pos = None;
            }
            _ => {}
        }
    }

    // --- clipboard ---------------------------------------------------------

    /// Ctrl-C: copy what is selected; with nothing selected, quit on the
    /// second press so a copy habit from other programs does not end the
    /// session by accident.
    fn copy_or_quit(&mut self) {
        if self.copy_selection() {
            return;
        }
        if self
            .quit_armed
            .is_some_and(|at| at.elapsed() < QUIT_CONFIRM)
        {
            self.should_quit = true;
            return;
        }
        self.quit_armed = Some(Instant::now());
        self.toast("Nothing selected to copy. Press Ctrl-C again to quit (Ctrl-Q quits at once).");
    }

    /// Copy the selection in the message pane, if there is one.
    fn copy_selection(&mut self) -> bool {
        let Some(text) = self.selection_text() else {
            return false;
        };
        let rows = text.lines().count();
        let what = if rows > 1 {
            format!("{rows} lines")
        } else {
            "the selection".to_owned()
        };
        self.copy_text(&text, &what);
        true
    }

    /// Put `text` on the clipboard and say so; `what` names it in the toast.
    fn copy_text(&mut self, text: &str, what: &str) {
        match self.clipboard.set(text) {
            Copied::System => self.toast(format!("Copied {what} to the clipboard.")),
            Copied::Terminal => self.toast(format!(
                "Handed {what} to the terminal's clipboard (no system clipboard here)."
            )),
        }
    }

    fn paste_from_clipboard(&mut self) {
        match self.clipboard.get() {
            Some(text) => self.insert_str(&text.replace("\r\n", "\n").replace('\r', "\n")),
            None if self.clipboard.can_read() => self.toast("The clipboard is empty."),
            None => self.toast(
                "No system clipboard here; paste with the terminal's own shortcut (Ctrl-Shift-V, Shift-Insert or the menu).",
            ),
        }
    }

    /// `/copy`: the last message in the selected chat; `/copy id`, `/copy
    /// link` for your id and invite link.
    fn cmd_copy(&mut self, args: &[&str]) {
        match args.first().map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("id") | Some("me") => {
                let me = self.me.to_string();
                self.copy_text(&me, "your id");
            }
            Some("link") | Some("invite") => {
                let link = self.invite_link().to_string();
                self.copy_text(&link, "your invite link");
            }
            Some(_) => self.toast("Usage: /copy (last message), /copy id, /copy link"),
            None => {
                let Some(peer) = self.selected_contact().map(|c| c.user_id) else {
                    self.toast("Select a chat first, or /copy id, /copy link.");
                    return;
                };
                let Some(text) = self
                    .threads
                    .get(&peer)
                    .and_then(|lines| lines.last())
                    .map(|line| line.text.clone())
                else {
                    self.toast("No messages in this chat yet.");
                    return;
                };
                self.copy_text(&text, "the last message");
            }
        }
    }

    fn byte_index(&self, char_index: usize) -> usize {
        self.input
            .char_indices()
            .nth(char_index)
            .map_or(self.input.len(), |(i, _)| i)
    }

    /// Line and column (in chars) of the cursor within a multi-line input.
    pub fn cursor_line_col(&self) -> (usize, usize) {
        let mut line = 0;
        let mut col = 0;
        for c in self.input.chars().take(self.cursor) {
            if c == '\n' {
                line += 1;
                col = 0;
            } else {
                col += 1;
            }
        }
        (line, col)
    }

    /// Char index where the cursor's line starts.
    fn line_start(&self) -> usize {
        self.input
            .chars()
            .take(self.cursor)
            .enumerate()
            .filter(|(_, c)| *c == '\n')
            .last()
            .map_or(0, |(i, _)| i + 1)
    }

    /// Char index where the cursor's line ends.
    fn line_end(&self) -> usize {
        self.input
            .chars()
            .enumerate()
            .skip(self.cursor)
            .find(|(_, c)| *c == '\n')
            .map_or(self.input.chars().count(), |(i, _)| i)
    }

    /// Put the cursor on `line` at `col` (clamped to the line's length).
    fn move_cursor_to(&mut self, line: usize, col: usize) {
        let mut index = 0;
        for (i, text) in self.input.split('\n').enumerate() {
            let len = text.chars().count();
            if i == line {
                self.cursor = index + col.min(len);
                return;
            }
            index += len + 1;
        }
    }

    /// Up: the previous line of a multi-line input, else the previous
    /// history entry.
    fn input_up(&mut self) {
        let (line, col) = self.cursor_line_col();
        if self.history_pos.is_none() && line > 0 {
            self.move_cursor_to(line - 1, col);
            return;
        }
        if self.history.is_empty() {
            return;
        }
        let pos = match self.history_pos {
            None => {
                self.history_draft = self.input.clone();
                self.history.len() - 1
            }
            Some(0) => return,
            Some(p) => p - 1,
        };
        self.history_pos = Some(pos);
        self.input = self.history[pos].clone();
        self.cursor = self.input.chars().count();
    }

    /// Down: the next line of a multi-line input, else the next history
    /// entry, and past the newest back to what was being typed.
    fn input_down(&mut self) {
        let (line, col) = self.cursor_line_col();
        if self.history_pos.is_none() && line < self.input.matches('\n').count() {
            self.move_cursor_to(line + 1, col);
            return;
        }
        let Some(pos) = self.history_pos else {
            return;
        };
        if pos + 1 < self.history.len() {
            self.history_pos = Some(pos + 1);
            self.input = self.history[pos + 1].clone();
        } else {
            self.history_pos = None;
            self.input = std::mem::take(&mut self.history_draft);
        }
        self.cursor = self.input.chars().count();
    }

    fn remember(&mut self, line: &str) {
        if self.history.last().is_none_or(|last| last != line) {
            self.history.push(line.to_owned());
            if self.history.len() > HISTORY_LIMIT {
                self.history.remove(0);
            }
        }
        self.history_pos = None;
        self.history_draft.clear();
    }

    fn insert_str(&mut self, text: &str) {
        let at = self.byte_index(self.cursor);
        self.input.insert_str(at, text);
        self.cursor += text.chars().count();
        // Editing a recalled line makes it the current line.
        self.history_pos = None;
    }

    fn clear_input(&mut self) {
        self.input.clear();
        self.cursor = 0;
    }

    fn select_next(&mut self) {
        let n = self.pane_count();
        self.select((self.selected + 1) % n);
    }

    fn select_prev(&mut self) {
        let n = self.pane_count();
        self.select((self.selected + n - 1) % n);
    }

    fn select(&mut self, index: usize) {
        self.selected = index.min(self.pane_count() - 1);
        self.scroll = 0;
        self.selection = None;
        // A rule above what arrived while this chat was not open.
        self.new_marker = self.selected_contact().map(|c| c.user_id).and_then(|id| {
            self.unread
                .get(&id)
                .and_then(|ids| ids.first().cloned())
                .map(|first| (id, first))
        });
        self.group_new_marker = self.selected_group().and_then(|id| {
            self.group_unread
                .get(&id)
                .and_then(|ids| ids.iter().find(|i| !i.is_empty()).cloned())
                .map(|first| (id, first))
        });
        self.mark_selected_read();
    }

    /// The selected chat is in front of the user: its unread messages are
    /// read now, and their sender may be told so.
    fn mark_selected_read(&mut self) {
        if !self.focused {
            return;
        }
        if let Some(id) = self.selected_contact().map(|c| c.user_id) {
            let shown = self.unread.remove(&id).unwrap_or_default();
            if self.read_receipts && self.contact_supports(&id, capability::RECEIPTS) {
                for message_id in shown {
                    self.receipts.read(id, message_id);
                }
            }
        }
        if let Some(group) = self.selected_group() {
            self.group_unread.remove(&group);
        }
    }

    fn submit(&mut self) {
        let line = std::mem::take(&mut self.input).trim().to_owned();
        self.cursor = 0;
        if line.is_empty() {
            return;
        }
        self.remember(&line);
        match line.strip_prefix('/') {
            Some(command) => self.run_command(command),
            None => self.send_message(line),
        }
    }

    // --- commands ----------------------------------------------------------

    fn run_command(&mut self, command: &str) {
        let mut parts = command.split_whitespace();
        let name = parts.next().unwrap_or_default();
        let rest: Vec<&str> = parts.collect();
        match name {
            "help" | "h" | "?" => self.print_help(),
            "me" | "id" => {
                let me = self.me;
                self.system(Level::Info, format!("Your id: {me}"));
                self.system(
                    Level::Info,
                    format!("Your invite link: {}", self.invite_link()),
                );
                self.select(0);
            }
            "invite" | "link" | "qr" if rest.first().is_some_and(|a| *a == "copy") => {
                self.cmd_copy(&["link"])
            }
            "invite" | "link" | "qr" => self.cmd_invite(),
            "copy" => self.cmd_copy(&rest),
            "add" => self.cmd_add(&rest),
            "alias" | "rename" => self.cmd_alias(&rest),
            "remove" | "rm" => self.cmd_remove(),
            "verify" => self.cmd_verify(&rest),
            "refresh" => self.cmd_refresh(),
            "session" => self.cmd_session(),
            "receipts" => self.cmd_receipts(&rest),
            "cover" => self.cmd_cover(&rest),
            "group" | "g" => self.cmd_group(&rest),
            "decline" => self.cmd_decline(&rest),
            "notify" => self.cmd_notify(&rest),
            "marks" | "ascii" => self.cmd_marks(&rest),
            "theme" | "colors" | "colours" => self.cmd_theme(&rest),
            "search" | "find" => self.cmd_search(&rest),
            "accept" => self.cmd_accept(&rest),
            "block" => self.cmd_block(&rest),
            "unblock" => self.cmd_unblock(&rest),
            "blocked" => self.cmd_blocked(),
            "send" | "file" | "attach" => self.cmd_send(&rest),
            "get" | "fetch" => self.cmd_get(&rest),
            "files" => self.cmd_files(&rest),
            "open" => self.cmd_open(),
            "relay" => self.cmd_relay(&rest),
            "revoke" => self.cmd_revoke(&rest),
            "rotate" => self.cmd_rotate(&rest),
            "log" | "keylog" => self.cmd_log(),
            "lock" => self.cmd_lock(),
            "quit" | "q" | "exit" => self.should_quit = true,
            other => match commands::closest(other) {
                Some(meant) => self.toast(format!(
                    "Unknown command /{other}. Did you mean /{meant}? F1 lists them all."
                )),
                None => self.toast(format!("Unknown command /{other}. F1 lists them all.")),
            },
        }
    }

    // --- help, completion and hints -----------------------------------------

    /// Tab in a command line: complete the command name, or a path
    /// argument; repeated presses cycle through the candidates.
    fn complete(&mut self) {
        if self.cursor != self.input.chars().count() {
            return; // only at the end of the line
        }
        if let Some(c) = &mut self.completion {
            c.index = (c.index + 1) % c.candidates.len();
            self.input = format!("{}{}", c.stem, c.candidates[c.index]);
            self.cursor = self.input.chars().count();
            return;
        }
        let Some(body) = self.input.strip_prefix('/') else {
            return;
        };
        let (stem, candidates) = match body.split_once(' ') {
            None => (
                "/".to_owned(),
                commands::matching(body)
                    .iter()
                    .map(|c| format!("{} ", c.name))
                    .collect::<Vec<_>>(),
            ),
            Some((name, rest)) => match commands::find(name) {
                Some(c) if c.path_arg => (
                    format!("/{name} "),
                    commands::complete_path(rest.trim_start()),
                ),
                _ => return,
            },
        };
        match candidates.len() {
            0 => self.toast("Nothing to complete."),
            1 => {
                self.input = format!("{stem}{}", candidates[0]);
                self.cursor = self.input.chars().count();
            }
            _ => {
                self.input = format!("{stem}{}", candidates[0]);
                self.cursor = self.input.chars().count();
                self.completion = Some(Completion {
                    stem,
                    candidates,
                    index: 0,
                });
            }
        }
    }

    /// What the status line says when there is no toast: the keys and
    /// commands that matter right now.
    pub fn status_hint(&self) -> String {
        if self.help_open {
            return "PgUp / PgDn or the wheel scroll the help · any other key closes it".to_owned();
        }
        if let Some(c) = &self.completion {
            let mut out = String::new();
            for (i, cand) in c.candidates.iter().enumerate() {
                // Command names get their slash back; paths are shown as typed.
                let shown = if c.stem == "/" {
                    format!("/{}", cand.trim_end())
                } else {
                    cand.trim_end().to_owned()
                };
                let piece = if i == c.index {
                    format!("[{shown}]")
                } else {
                    shown
                };
                if out.len() + piece.len() > 90 {
                    out.push_str(" …");
                    break;
                }
                if !out.is_empty() {
                    out.push_str("  ");
                }
                out.push_str(&piece);
            }
            return format!("Tab cycles: {out}");
        }
        if self.selection.is_some() {
            return "Ctrl-C copies the selection · Esc clears it".to_owned();
        }
        if let Some(body) = self.input.strip_prefix('/') {
            let name = body.split_whitespace().next().unwrap_or("");
            if let Some(c) = commands::find(name) {
                return if c.args.is_empty() {
                    format!("/{}: {}", c.name, c.help)
                } else {
                    format!("/{} {}: {}", c.name, c.args, c.help)
                };
            }
            let matches = commands::matching(name);
            return if matches.is_empty() {
                match commands::closest(name) {
                    Some(meant) => format!("No such command; did you mean /{meant}?"),
                    None => "No such command; F1 lists them all.".to_owned(),
                }
            } else {
                let names: Vec<String> = matches.iter().map(|c| format!("/{}", c.name)).collect();
                format!("{} · Tab completes", names.join("  "))
            };
        }
        if self.requests_pane_selected() {
            return "/accept <n> · /block <n> · /accept g<n> · /decline g<n> · F1 help".to_owned();
        }
        if let Some(group) = self.selected_group() {
            return match self.group_state_label(&group) {
                None => "Enter sends to everyone · /group members · /group add <contact> · F1 help"
                    .to_owned(),
                Some(state) => {
                    format!("This group is {state} · /group forget removes it · F1 help")
                }
            };
        }
        if self.selected_contact().is_none() {
            return if self.contacts.is_empty() {
                "/add <id or link> · /invite shows yours · F1 help".to_owned()
            } else {
                "Tab or a click opens a chat · F1 help".to_owned()
            };
        }
        if let Some(info) = self.selected_contact().and_then(|c| {
            self.threads
                .get(&c.user_id)?
                .iter()
                .rev()
                .find_map(|l| l.pending.as_ref())
        }) {
            let name: String = info.name.chars().take(24).collect();
            return format!("/get fetches {name} · /files auto skips the asking · F1 help");
        }
        "Enter sends · /send <path> a file · F1 help".to_owned()
    }

    fn print_help(&mut self) {
        self.help_open = true;
    }

    fn invite_link(&self) -> InviteLink {
        InviteLink::new(self.me, Some(self.relay_url.clone()))
    }

    /// Show the invite link and a QR code of it in the System pane.
    fn cmd_invite(&mut self) {
        let link = self.invite_link().to_string();
        self.system(
            Level::Info,
            "Your invite link. Anyone can paste it into /add, or scan the code with a phone:",
        );
        self.system(Level::Info, link.clone());
        match qr::render(&link) {
            Ok(rows) => {
                for row in rows {
                    self.system(Level::Code, row);
                }
            }
            Err(e) => self.system(Level::Warn, format!("Could not draw the QR code: {e}")),
        }
        self.system(
            Level::Info,
            "The code holds the same link; PgUp/PgDn scroll if it does not fit.",
        );
        self.select(0);
    }

    fn cmd_add(&mut self, args: &[&str]) {
        let Some(id_text) = args.first() else {
            self.toast("Usage: /add <user-id or invite link> [alias]");
            return;
        };
        let (user_id, their_relay) = if InviteLink::looks_like(id_text) {
            match id_text.parse::<InviteLink>() {
                Ok(link) => (link.user_id, link.relay),
                Err(e) => {
                    self.toast(format!("Bad invite link: {e}"));
                    return;
                }
            }
        } else {
            match id_text.parse::<UserId>() {
                Ok(id) => (id, None),
                Err(_) => {
                    self.toast("That is not a valid user id or invite link.");
                    return;
                }
            }
        };
        if user_id == self.me {
            self.toast("That is your own id.");
            return;
        }
        if let Some(relay) = their_relay.filter(|r| *r != self.relay_url) {
            self.system(
                Level::Warn,
                format!(
                    "This invite names the relay {relay}, but you are on {}. Relays do not talk to each other yet, so messages only reach them if you both use the same one (/relay {relay}).",
                    self.relay_url
                ),
            );
            self.toast("They use a different relay; see System.");
        }
        let alias = args.get(1).map(|s| s.to_string());
        if let Some(i) = self.contact_index(&user_id) {
            if alias.is_some() {
                self.contacts[i].alias = alias.clone();
                self.persist_contacts();
            }
            self.select(i + 1);
        }
        self.lookup_contact(user_id, alias);
    }

    /// Fetch a contact's key bundle in the background; the result arrives
    /// as [`Internal::LookupDone`].
    fn lookup_contact(&mut self, user_id: UserId, alias: Option<String>) {
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let result = client.lookup(user_id).await;
            let _ = tx
                .send(Internal::LookupDone {
                    user_id,
                    alias,
                    result,
                })
                .await;
        });
        self.toast(format!("Looking up {}…", user_id.short()));
    }

    fn cmd_refresh(&mut self) {
        let Some(contact) = self.selected_contact() else {
            self.toast("Select a contact first.");
            return;
        };
        let user_id = contact.user_id;
        self.lookup_contact(user_id, None);
    }

    fn cmd_search(&mut self, args: &[&str]) {
        let needle = args.join(" ");
        if needle.trim().is_empty() {
            self.toast("Usage: /search <text>");
            return;
        }
        let lower = needle.to_lowercase();
        let (scope, label) = match self.selected_contact() {
            Some(c) => (
                vec![c.user_id],
                format!("in the chat with {}", c.display_name()),
            ),
            None => (
                self.contacts.iter().map(|c| c.user_id).collect(),
                "in all chats".to_owned(),
            ),
        };
        let mut hits: Vec<(u64, String)> = Vec::new();
        for peer in scope {
            let name = self.contact_name(&peer);
            let Some(lines) = self.threads.get(&peer) else {
                continue;
            };
            for line in lines {
                if !line.text.to_lowercase().contains(&lower) {
                    continue;
                }
                let who = match line.direction {
                    Direction::Sent => format!("you → {name}"),
                    Direction::Received => name.clone(),
                };
                hits.push((
                    line.timestamp_ms,
                    format!("{} {who}: {}", ui::stamp(line.timestamp_ms), line.text),
                ));
            }
        }
        hits.sort_by_key(|(at, _)| *at);
        let total = hits.len();
        let skipped = total.saturating_sub(SEARCH_LIMIT);
        self.system(
            Level::Info,
            format!(
                "Search for \"{needle}\" {label}: {total} match(es){}",
                if skipped > 0 {
                    format!(", newest {SEARCH_LIMIT} shown")
                } else {
                    String::new()
                }
            ),
        );
        for (_, text) in hits.into_iter().skip(skipped) {
            self.system(Level::Info, text);
        }
        self.select(0);
    }

    fn cmd_notify(&mut self, args: &[&str]) {
        let mode = match args.first() {
            None => {
                self.toast(format!(
                    "Notifications: {}. Usage: /notify all|bell|off",
                    self.notifier.mode().as_str()
                ));
                return;
            }
            Some(arg) => match NotifyMode::parse(arg) {
                Some(mode) => mode,
                None => {
                    self.toast("Usage: /notify all|bell|off");
                    return;
                }
            },
        };
        self.notifier.set_mode(mode);
        let mut config = self.store.load_config().unwrap_or_default();
        config.notify = mode.as_str().to_owned();
        if let Err(e) = self.store.save_config(&config) {
            self.toast(format!("Could not save config: {e}"));
        }
        self.system(
            Level::Info,
            match mode {
                NotifyMode::All => "Notifications on: the terminal rings and, where it can, raises a desktop notification for messages you are not looking at. The window title shows the unread count.",
                NotifyMode::Bell => "Notifications: bell only.",
                NotifyMode::Off => "Notifications off. The window title still shows the unread count.",
            },
        );
    }

    fn cmd_theme(&mut self, args: &[&str]) {
        let name = match args.first() {
            None => {
                self.toast(format!(
                    "Theme: {}. Usage: /theme dark|light|mono",
                    self.theme.name.as_str()
                ));
                return;
            }
            Some(arg) => match ThemeName::parse(arg) {
                Some(name) => name,
                None => {
                    self.toast("Usage: /theme dark|light|mono");
                    return;
                }
            },
        };
        self.theme = Theme::named(name);
        let mut config = self.store.load_config().unwrap_or_default();
        config.theme = name.as_str().to_owned();
        if let Err(e) = self.store.save_config(&config) {
            self.toast(format!("Could not save config: {e}"));
        }
        self.toast(format!("Theme: {} (remembered).", name.as_str()));
    }

    fn cmd_marks(&mut self, args: &[&str]) {
        let marks = match args.first() {
            None => {
                self.toast(format!(
                    "Marks are drawn in {}. Usage: /marks ascii|unicode|auto",
                    if self.glyphs.ascii {
                        "ASCII"
                    } else {
                        "Unicode"
                    }
                ));
                return;
            }
            Some(arg) => match Marks::parse(arg) {
                Some(marks) => marks,
                None => {
                    self.toast("Usage: /marks ascii|unicode|auto");
                    return;
                }
            },
        };
        self.glyphs = Glyphs::for_marks(marks);
        let mut config = self.store.load_config().unwrap_or_default();
        config.marks = marks.as_str().to_owned();
        if let Err(e) = self.store.save_config(&config) {
            self.toast(format!("Could not save config: {e}"));
        }
        let g = self.glyphs;
        self.system(
            Level::Info,
            format!(
                "Marks: {} pending, {} accepted by the relay, {} delivered, {} in colour read, {} refused ({}; remembered).",
                g.pending,
                g.accepted,
                g.delivered,
                g.delivered,
                g.failed,
                marks.as_str()
            ),
        );
    }

    fn cmd_receipts(&mut self, args: &[&str]) {
        let on = match args.first().map(|s| s.to_ascii_lowercase()).as_deref() {
            None => {
                let state = if self.read_receipts { "on" } else { "off" };
                self.toast(format!(
                    "Read receipts are {state} (delivery receipts are always sent). Usage: /receipts on|off"
                ));
                return;
            }
            Some("on") => true,
            Some("off") => false,
            Some(_) => {
                self.toast("Usage: /receipts on|off");
                return;
            }
        };
        self.read_receipts = on;
        let mut config = self.store.load_config().unwrap_or_default();
        config.read_receipts = on;
        if let Err(e) = self.store.save_config(&config) {
            self.toast(format!("Could not save config: {e}"));
        }
        let line = if on {
            format!(
                "Read receipts on: contacts see {} in colour when you have looked at their messages.",
                self.glyphs.delivered
            )
        } else {
            "Read receipts off: contacts only learn that their messages arrived, not that you read them.".to_owned()
        };
        self.system(Level::Info, line);
    }

    /// `/cover on|off`: cover traffic to contacts who have it on too.
    fn cmd_cover(&mut self, args: &[&str]) {
        let on = match args.first().map(|s| s.to_ascii_lowercase()).as_deref() {
            None => {
                let state = if self.cover { "on" } else { "off" };
                let covering = self.cover_schedule.len();
                self.toast(format!(
                    "Cover traffic is {state}{}. Usage: /cover on|off",
                    if self.cover {
                        format!(", covering {covering} contact(s) right now")
                    } else {
                        String::new()
                    }
                ));
                return;
            }
            Some("on") => true,
            Some("off") => false,
            Some(_) => {
                self.toast("Usage: /cover on|off");
                return;
            }
        };
        self.cover = on;
        self.client.set_cover(on);
        if !on {
            self.cover_schedule.clear();
        }
        let mut config = self.store.load_config().unwrap_or_default();
        config.cover = on;
        if let Err(e) = self.store.save_config(&config) {
            self.toast(format!("Could not save config: {e}"));
        }
        let line = if on {
            "Cover traffic on: contacts who turn it on too get meaningless messages from you at random moments while you are both around, and you from them, so the relay cannot tell when you really talk. It shows that you are in contact, and long messages, files and bursts still stand out. It costs some bandwidth (about 20 KB an hour per contact)."
        } else {
            "Cover traffic off: the relay sees when you really send to and hear from each contact."
        };
        self.system(Level::Info, line);
    }

    fn cmd_session(&mut self) {
        let Some(index) = self.selected_contact_index() else {
            self.toast("Select a contact first.");
            return;
        };
        let contact = &self.contacts[index];
        let name = contact.display_name();
        let line = match self.client.session_info(&contact.user_id) {
            Some(info) => format!(
                "Messages with {name} are forward secret: each one is encrypted under a key used once and then discarded. The session was started by {} at {}{}. {}",
                if info.initiated_by_us { "you" } else { "them" },
                crate::ui::clock(info.established_at_ms),
                if info.awaiting_reply {
                    "; it completes when they answer"
                } else {
                    ""
                },
                if info.pq_ratchet {
                    "Its handshake and every ratchet step use ML-KEM-768, so it heals after a compromise even against a quantum computer; and its messages are deniable, since nothing in them proves to a third party who wrote them."
                } else if info.post_quantum {
                    "Its handshake used ML-KEM-768, so a recording of it stays closed even to a quantum computer; the ratchet after it is X25519 only. It becomes a fully post-quantum ratchet by itself when the next session starts, once both clients are on 0.8.0."
                } else {
                    "Its handshake was classical (X25519 only): their client or the relay predates the post-quantum handshake of 0.6.0. It becomes post-quantum by itself when the next session starts after they update."
                }
            ),
            None => match &contact.bundle {
                Some(b) if !b.supports_sessions() && !self.relay_supports_prekeys() => format!(
                    "Messages with {name} are encrypted to their long-term key only: the relay is older than 0.3.0 and does not keep prekeys. Forward secrecy starts by itself once it is updated."
                ),
                Some(b) if !b.supports_sessions() => format!(
                    "Messages with {name} are encrypted to their long-term key only: their client does not publish prekeys yet (it is older than 0.3.0). Forward secrecy starts by itself once it does."
                ),
                Some(_) => format!(
                    "No session with {name} yet; the next message you send starts a forward-secret one."
                ),
                None => format!("No key for {name} yet; /refresh fetches it."),
            },
        };
        self.system(Level::Info, line);
        self.select(0);
    }

    /// The relay served a different long-term key for a contact than the
    /// one pinned: adopt it, but say so loudly.
    fn note_key_change(&mut self, index: usize, new: KeyBundle) {
        let name = self.contacts[index].display_name();
        let was_verified = self.contacts[index].verified;
        let user_id = self.contacts[index].user_id;
        self.contacts[index].bundle = Some(new);
        self.contacts[index].verified = false;
        self.persist_contacts();
        self.client.forget_sessions(&user_id);
        self.system(
            Level::Warn,
            format!(
                "KEY CHANGE: {name}'s encryption key is different from the one you had. It is signed by their identity, so either they rotated it or their identity key is compromised. Confirm with them and run /verify before trusting it{}.",
                if was_verified { " (verified mark cleared)" } else { "" }
            ),
        );
        self.toast(format!("Key change for {name}! See System."));
    }

    fn cmd_verify(&mut self, args: &[&str]) {
        let Some(index) = self.selected_contact_index() else {
            self.toast("Select a contact first.");
            return;
        };
        let contact = &self.contacts[index];
        let name = contact.display_name();
        let peer = contact.user_id;
        match args.first().map(|s| s.to_ascii_lowercase()).as_deref() {
            None => {
                let number = silver_protocol::safety_number(&self.me, &peer);
                let groups: Vec<&str> = number.split(' ').collect();
                let status = if contact.verified {
                    format!("verified {}", self.glyphs.verified)
                } else {
                    "not verified yet".to_owned()
                };
                self.system(
                    Level::Info,
                    format!("Safety number with {name} ({status}). Read it to each other by voice or in person; it must match on both sides:"),
                );
                for row in groups.chunks(4) {
                    self.system(Level::Info, format!("    {}", row.join("  ")));
                }
                self.system(
                    Level::Info,
                    "If it matches, run /verify ok. If it does not, someone may be between you: do not trust this contact.",
                );
                self.select(0);
            }
            Some("ok") | Some("yes") => {
                self.contacts[index].verified = true;
                self.persist_contacts();
                let mark = self.glyphs.verified;
                self.system(Level::Info, format!("Marked {name} as verified {mark}"));
                self.toast(format!("{name} verified {mark}"));
            }
            Some("no") | Some("clear") => {
                self.contacts[index].verified = false;
                self.persist_contacts();
                self.toast(format!("{name} is no longer marked verified"));
            }
            Some(_) => self.toast("Usage: /verify, /verify ok, /verify no"),
        }
    }

    fn cmd_alias(&mut self, args: &[&str]) {
        if let Some(group) = self.selected_group() {
            let alias = args.join(" ");
            let alias = (!alias.trim().is_empty()).then_some(alias);
            match self.groups.set_alias(&group, alias) {
                Ok(()) => self.toast(format!("Now shown as {}.", self.group_name(&group))),
                Err(e) => self.toast(format!("Could not set the alias: {e}")),
            }
            return;
        }
        let Some(index) = self.selected_contact_index() else {
            self.toast("Select a contact first.");
            return;
        };
        if args.is_empty() {
            self.toast("Usage: /alias <name>");
            return;
        }
        // Only what can be seen, and not a paragraph of it.
        let alias = silver_client::files::printable(&args.join(" "), MAX_ALIAS_CHARS);
        if alias.is_empty() {
            self.toast("An alias needs at least one visible character.");
            return;
        }
        self.contacts[index].alias = Some(alias);
        self.persist_contacts();
    }

    fn cmd_remove(&mut self) {
        let Some(index) = self.selected_contact_index() else {
            self.toast("Select a contact first.");
            return;
        };
        let removed = self.contacts.remove(index);
        self.threads.remove(&removed.user_id);
        self.unread.remove(&removed.user_id);
        self.persist_contacts();
        self.select(0);
        self.system(
            Level::Info,
            format!("Removed {} ({})", removed.display_name(), removed.user_id),
        );
    }

    fn cmd_relay(&mut self, args: &[&str]) {
        let Some(url) = args.first() else {
            let current = self.relay_url.clone();
            self.toast(format!("Relay: {current}. Usage: /relay <ws-url>"));
            return;
        };
        let mut config = self.store.load_config().unwrap_or_default();
        if let Some(host) = config.downgrade(url) {
            self.system(
                Level::Warn,
                format!(
                    "{host} was reached over wss:// before, so it is not talked to over plain ws://. \
                     Use a wss:// URL, or remove the host from secure_hosts in config.json if the \
                     relay really stopped offering TLS."
                ),
            );
            self.toast("Refused: that relay speaks wss://; see System.");
            return;
        }
        config.relay_url = Some(url.to_string());
        match self.store.save_config(&config) {
            Ok(()) => self.system(
                Level::Info,
                format!("Relay set to {url}; restart to connect to it."),
            ),
            Err(e) => self.toast(format!("Could not save config: {e}")),
        }
    }

    /// Retire this identity for good. Publishes the pre-signed revocation to
    /// the relay and, best-effort, to every contact that understands lifecycle
    /// statements. Needs `/revoke confirm`, because it cannot be undone.
    fn cmd_revoke(&mut self, args: &[&str]) {
        if self.rotated {
            self.system(
                Level::Warn,
                "You handed over to a new identity this session, so nothing more is changed until you restart: a revocation now would retire the new key, not the old. The old key needs no revoking; the handover already retires it.",
            );
            self.toast("Restart first: a rotation is pending.");
            return;
        }
        let confirmed = matches!(
            args.first().map(|a| a.to_ascii_lowercase()).as_deref(),
            Some("confirm") | Some("yes")
        );
        if !confirmed {
            self.system(
                Level::Warn,
                "This retires your identity for good: contacts will be told it is dead and stop trusting it, and the relay will refuse to publish your key again. It cannot be undone; to keep talking you would start a new identity. Run /revoke confirm to go ahead.",
            );
            self.toast("Type /revoke confirm to retire this identity.");
            return;
        }
        let (identity, _) = match self.store.load_or_create_identity() {
            Ok(pair) => pair,
            Err(e) => {
                self.toast(format!("Could not load your identity: {e}"));
                return;
            }
        };
        let revocation = match self.store.load_or_create_revocation(&identity, now_ms()) {
            Ok(revocation) => revocation,
            Err(e) => {
                self.toast(format!("Could not read your revocation certificate: {e}"));
                return;
            }
        };
        // Tell contacts that can hear it now; the relay serves it to the rest.
        let peers: Vec<UserId> = self
            .contacts
            .iter()
            .filter(|c| !c.revoked && c.supports(capability::LIFECYCLE))
            .map(|c| c.user_id)
            .collect();
        for peer in peers {
            self.send_content_to(peer, Content::Revocation(revocation.clone()));
        }
        let client = self.client.clone();
        tokio::spawn(async move {
            let _ = client.revoke(revocation).await;
        });
        self.system(
            Level::Warn,
            "Your identity is revoked. The relay and your contacts have been told it is dead. Start a fresh installation to make a new identity; if you kept a backup, its contacts come with it.",
        );
        self.toast("Identity revoked. See System.");
    }

    /// Move to a fresh identity with a cross-signed succession, so contacts
    /// re-pin to the new key on their own. Needs `/rotate confirm`.
    fn cmd_rotate(&mut self, args: &[&str]) {
        if self.rotated {
            self.system(
                Level::Warn,
                "You already handed over to a new identity this session. Restart to run as it before rotating again; a second handover now would be signed by a key your contacts have not pinned yet.",
            );
            self.toast("Restart first: a rotation is pending.");
            return;
        }
        let confirmed = matches!(
            args.first().map(|a| a.to_ascii_lowercase()).as_deref(),
            Some("confirm") | Some("yes")
        );
        if !confirmed {
            self.system(
                Level::Warn,
                "This makes a new identity and hands over to it: the move is signed by both your old and new keys, so contacts re-pin to the new one without having to compare safety numbers again from scratch (though it is worth doing). Restart afterwards to run as the new identity. Run /rotate confirm to go ahead.",
            );
            self.toast("Type /rotate confirm to rotate your identity.");
            return;
        }
        let (old, _) = match self.store.load_or_create_identity() {
            Ok(pair) => pair,
            Err(e) => {
                self.toast(format!("Could not load your identity: {e}"));
                return;
            }
        };
        let new = silver_protocol::Identity::generate();
        let now = now_ms();
        let succession = old.succeed_to(&new, now);
        let new_id = new.user_id();
        // Announce to contacts that understand it, over the still-live old
        // sessions, then to the relay.
        let peers: Vec<UserId> = self
            .contacts
            .iter()
            .filter(|c| !c.revoked && c.supports(capability::LIFECYCLE))
            .map(|c| c.user_id)
            .collect();
        for peer in peers {
            self.send_content_to(peer, Content::Succession(succession.clone()));
        }
        let client = self.client.clone();
        let announced = succession.clone();
        tokio::spawn(async move {
            let _ = client.succeed(announced).await;
        });
        // Persist the new identity so the next start runs as it: its keys, a
        // fresh revocation certificate for it, and no carried-over sessions.
        if let Err(e) = self.store.save_identity(&new) {
            self.toast(format!("Could not save the new identity: {e}"));
            return;
        }
        if let Err(e) = self.store.load_or_create_revocation(&new, now) {
            self.system(
                Level::Warn,
                format!(
                    "New identity saved, but its revocation certificate could not be written: {e}"
                ),
            );
        }
        if let Err(e) = self.store.clear_sessions() {
            self.system(
                Level::Warn,
                format!("New identity saved, but old sessions could not be cleared: {e}"),
            );
        }
        self.rotated = true;
        self.system(
            Level::Info,
            format!(
                "Handed over to a new identity ({new_id}). Contacts have been told and will re-pin to it. Restart Silver to run as the new identity; until you do, this session still uses the old one, and no further identity change is taken."
            ),
        );
        self.toast("Rotation announced. Restart to use the new identity.");
    }

    fn persist_contacts(&mut self) {
        if let Err(e) = self.store.save_contacts(&self.contacts) {
            self.toast(format!("Could not save contacts: {e}"));
        }
    }

    // --- messaging ---------------------------------------------------------

    fn send_message(&mut self, text: String) {
        if self.requests_pane_selected() {
            self.toast("Accept a request first: /accept <n>.");
            return;
        }
        if let Some(group) = self.selected_group() {
            self.send_group_text(group, text);
            return;
        }
        let Some(index) = self.selected_contact_index() else {
            self.toast("Select a contact first, or /add <user-id>.");
            return;
        };
        if self.contacts[index].revoked {
            let name = self.contacts[index].display_name();
            self.system(
                Level::Warn,
                format!(
                    "{name} revoked their identity, so nothing can be sent to it. If they gave you a new identity, /add it and message that instead."
                ),
            );
            self.toast(format!("{name}'s identity is revoked; not sent."));
            return;
        }
        let peer = self.contacts[index].user_id;
        self.new_marker = None; // answered: nothing is "new" any more
        self.send_content_to(peer, Content::Text { body: text });
    }

    /// Number and send any content to a contact; the outcome arrives as
    /// [`Internal::SendDone`].
    fn send_content_to(&mut self, peer: UserId, content: Content) {
        let Some(index) = self.contact_index(&peer) else {
            return;
        };
        let contact = &mut self.contacts[index];
        let pinned = contact.bundle.clone();
        let sequence = contact.next_sequence(self.send_epoch);
        self.persist_contacts();
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let result = client
                .send_content(peer, pinned, content.clone(), sequence)
                .await
                .map_err(|e| e.to_string());
            let _ = tx
                .send(Internal::SendDone {
                    peer,
                    content,
                    result: result.map(Box::new),
                })
                .await;
        });
    }

    /// Send the receipts whose batching delay has passed.
    fn flush_receipts(&mut self) {
        if self.receipts.is_empty() {
            return;
        }
        for (peer, content) in self.receipts.take_due(Instant::now()) {
            self.send_content_to(peer, content);
        }
    }

    /// Send cover traffic to the contacts whose turn has come, while
    /// connected. Nothing is queued for later: cover that cannot go now
    /// is not worth sending later.
    fn flush_cover(&mut self) {
        if !self.cover || self.cover_schedule.is_empty() {
            return;
        }
        if !matches!(self.connection, Connection::Connected) {
            return;
        }
        for peer in self.cover_schedule.take_due(Instant::now()) {
            // Only while they still advertise it: a contact who turned
            // cover off stops receiving it with their next message, and a
            // revoked one is dead.
            if self.covers(&peer) {
                self.send_content_to(peer, silver_client::cover::message());
            } else {
                self.cover_schedule.forget(&peer);
            }
        }
    }

    /// A contact sent something: if both sides have cover on, keep
    /// covering them.
    fn note_heard(&mut self, peer: UserId) {
        if self.cover && self.covers(&peer) {
            self.cover_schedule.heard(peer, Instant::now());
        }
    }

    /// Whether `peer` is a live contact whose last message asked for cover.
    fn covers(&self, peer: &UserId) -> bool {
        self.contact_index(peer).is_some_and(|i| {
            let contact = &self.contacts[i];
            !contact.revoked && contact.supports(capability::COVER)
        })
    }

    fn handle_internal(&mut self, ev: Internal) {
        match ev {
            Internal::LookupDone {
                user_id,
                alias,
                result,
            } => match result {
                Ok(bundle) => match self.contact_index(&user_id) {
                    // An existing contact: compare with the pinned key.
                    Some(index) => {
                        let name = self.contacts[index].display_name();
                        match (self.contacts[index].bundle.clone(), bundle) {
                            (_, None) => self.system(
                                Level::Warn,
                                format!("The relay has no key for {name} right now."),
                            ),
                            (None, Some(new)) => {
                                self.contacts[index].bundle = Some(new);
                                self.persist_contacts();
                                self.system(Level::Info, format!("Got {name}'s key."));
                            }
                            (Some(old), Some(new)) if old.dh_public == new.dh_public => {
                                // Same identity; keep the fresher prekeys.
                                self.contacts[index].bundle = Some(new);
                                self.persist_contacts();
                                self.toast(format!("{name}'s key is unchanged."));
                            }
                            (Some(_), Some(new)) => self.note_key_change(index, new),
                        }
                    }
                    None => {
                        let found = bundle.is_some();
                        let mut contact = Contact::new(user_id);
                        contact.alias = alias;
                        contact.bundle = bundle;
                        let name = contact.display_name();
                        self.contacts.push(contact);
                        self.threads.entry(user_id).or_default();
                        self.persist_contacts();
                        self.select(self.contacts.len());
                        if found {
                            self.system(Level::Info, format!("Added {name} ({user_id})"));
                        } else {
                            self.system(
                                Level::Warn,
                                format!("Added {name}, but the relay has no key for them yet; they need to connect once before you can message them."),
                            );
                        }
                    }
                },
                Err(e) => self.toast(format!("Lookup failed: {e}")),
            },
            Internal::SendDone {
                peer,
                content,
                result,
            } => match result {
                Ok(delivery) => {
                    if let Some(i) = self.contact_index(&peer) {
                        if delivery.key_changed {
                            self.note_key_change(i, delivery.bundle);
                        } else {
                            self.contacts[i].bundle = Some(delivery.bundle);
                            self.persist_contacts();
                        }
                    }
                    let text = match &content {
                        Content::Text { body } => Some(body.clone()),
                        Content::File { .. } => FileInfo::from_content(&content)
                            .map(|i| format!("[file] {}", i.label())),
                        // Receipts, lifecycle statements and cover traffic
                        // are not shown in the conversation as messages of
                        // their own.
                        Content::Receipt { .. }
                        | Content::Revocation(_)
                        | Content::Succession(_)
                        | Content::Cover { .. }
                        | Content::Sync(_)
                        | Content::Provision(_) => None,
                    };
                    if let Some(text) = text {
                        // The relay may have answered before this event was
                        // handled; a line born delivered shows no pending mark.
                        let id = delivery.envelope.id;
                        let delivered = !self.client.pending_ids().contains(&id);
                        self.record(
                            peer,
                            ChatLine {
                                id,
                                direction: Direction::Sent,
                                timestamp_ms: now_ms(),
                                text,
                                delivered,
                                failed: false,
                                receipt: None,
                                file: None,
                                pending: None,
                                sender: None,
                            },
                        );
                        self.scroll = 0;
                    }
                }
                Err(e) => {
                    if matches!(content, Content::Receipt { .. } | Content::Cover { .. }) {
                        tracing::debug!("receipt or cover to {peer} not sent: {e}");
                    } else {
                        self.toast(format!("Not sent: {e}"));
                        self.system(
                            Level::Warn,
                            format!("Message to {} not sent: {e}", self.contact_name(&peer)),
                        );
                    }
                }
            },
            Internal::Progress { text } => self.toast(text),
            Internal::Uploaded { peer, result } => match result {
                Ok(info) => {
                    self.toast(format!("Sent {}", info.label()));
                    self.send_content_to(peer, info.into_content());
                }
                Err(e) => {
                    self.toast(format!("File not sent: {e}"));
                    self.system(
                        Level::Warn,
                        format!("File to {} not sent: {e}", self.contact_name(&peer)),
                    );
                }
            },
            Internal::GroupSequenced {
                group,
                purpose,
                answer,
            } => self.on_group_sequenced(group, purpose, answer),
            Internal::GroupSent {
                group,
                id,
                text,
                result,
            } => self.on_group_sent(group, id, text, result),
            Internal::GroupParked { from, body, chunks } => {
                self.on_group_parked(from, body, chunks)
            }
            Internal::KeyPackageFor {
                group,
                user,
                result,
            } => self.on_key_package_for(group, user, result),
            Internal::KeyPackages { result } => self.on_key_packages(result),
            Internal::GroupJoinLookup { link, result } => self.on_group_join_lookup(link, result),
            Internal::GroupUploaded { group, result } => self.on_group_uploaded(group, result),
            Internal::GroupDownloaded {
                group,
                id,
                info,
                result,
            } => self.on_group_downloaded(group, id, info, result),
            Internal::Downloaded {
                peer,
                id,
                info,
                result,
            } => {
                let label = info.label();
                let text = match &result {
                    Ok(path) => format!("[file] {label} {} {}", self.glyphs.arrow, path.display()),
                    Err(e) => format!(
                        "[file] {label} {} {e} · /get tries again",
                        self.glyphs.failed
                    ),
                };
                self.set_line_text(&peer, &id, text.clone());
                if let Err(e) = self.store.append_text(&peer, &id, &text) {
                    self.toast(format!("Could not save history: {e}"));
                }
                match result {
                    Ok(path) => {
                        if let Some(line) = self.line_mut(&peer, &id) {
                            line.file = Some(path.clone());
                            line.pending = None;
                        }
                        self.toast(format!(
                            "Saved {}. Double-click the line or /open to open it.",
                            path.display()
                        ));
                    }
                    Err(e) => {
                        // Still fetchable: the failure may have been the network.
                        if let Some(line) = self.line_mut(&peer, &id) {
                            line.pending = Some(info);
                        }
                        self.system(
                            Level::Warn,
                            format!(
                                "Could not fetch {label} from {}: {e}",
                                self.contact_name(&peer)
                            ),
                        )
                    }
                }
            }
        }
    }

    fn handle_client_event(&mut self, ev: ClientEvent) {
        match ev {
            ClientEvent::Connected { relay_url } => {
                self.connection = Connection::Connected;
                self.system(Level::Info, format!("Connected to {relay_url}"));
                self.deposit_key_packages();
                // Reached over TLS: from now on, never without.
                let mut config = self.store.load_config().unwrap_or_default();
                if config.note_secure(&relay_url)
                    && let Err(e) = self.store.save_config(&config)
                {
                    self.toast(format!("Could not save config: {e}"));
                }
            }
            ClientEvent::Disconnected { reason, retry_in } => {
                self.connection = Connection::Disconnected;
                self.system(
                    Level::Warn,
                    format!(
                        "Disconnected: {reason} (retrying in {}s)",
                        retry_in.as_secs()
                    ),
                );
            }
            ClientEvent::Sent { id } => {
                if !self.on_group_envelope_done(&id, true) {
                    self.mark_line(&id, |line| line.delivered = true);
                }
            }
            ClientEvent::Rejected { id, reason } => {
                if self.on_group_envelope_done(&id, false) {
                    return;
                }
                self.mark_line(&id, |line| line.failed = true);
                self.system(Level::Warn, format!("Relay refused a message: {reason}"));
                self.toast(format!("Not delivered: {reason}"));
            }
            ClientEvent::Message(message) => {
                let message = *message;
                tracing::debug!(id = %message.id, "front end received a message");
                if self.known_ids.contains(&message.id) {
                    return; // relay re-delivered something we already have
                }
                let from = message.from;
                if self.blocked.contains(&from) {
                    return;
                }
                let Some(index) = self.contact_index(&from) else {
                    // Strangers get no receipts, and their receipts mean nothing.
                    if !matches!(message.content, Content::Receipt { .. }) {
                        self.hold_request(message);
                    }
                    return;
                };
                if self.contacts[index].caps != message.caps {
                    self.contacts[index].caps = message.caps.clone();
                    self.persist_contacts();
                }
                self.note_heard(from);

                // Sequence numbers: drop replays, mention gaps and resets.
                let name = self.contact_name(&from);
                let check = sequence::check(self.contacts[index].received, message.sequence);
                match check {
                    SequenceCheck::Replay => {
                        self.system(
                            Level::Warn,
                            format!("Dropped a replayed message from {name}."),
                        );
                        return;
                    }
                    SequenceCheck::Gap { missing } => self.system(
                        Level::Warn,
                        format!("{missing} earlier message(s) from {name} have not arrived (yet)."),
                    ),
                    SequenceCheck::NewEpoch => self.system(
                        Level::Info,
                        format!("{name} is sending from a fresh installation."),
                    ),
                    SequenceCheck::Fresh | SequenceCheck::Legacy => {}
                }
                if check != SequenceCheck::Legacy {
                    self.contacts[index].received = Some(message.sequence);
                    self.persist_contacts();
                }

                let (text, file) = match message.content {
                    Content::Text { body } => (body, None),
                    Content::File { .. } => {
                        let info = FileInfo::from_content(&message.content).expect("file content");
                        (format!("[file] {}", info.label()), Some(info))
                    }
                    Content::Receipt { kind, ids } => {
                        self.known_ids.insert(message.id);
                        self.apply_receipt(from, kind, &ids);
                        return;
                    }
                    // Lifecycle statements are handled from PeerRevoked /
                    // PeerSucceeded events, which the client raises after
                    // verifying the signatures; they never reach here as a
                    // plain message.
                    Content::Revocation(_) | Content::Succession(_) => {
                        self.known_ids.insert(message.id);
                        return;
                    }
                    // Cover traffic says nothing and leaves no trace: no
                    // line, no receipt, no notification, no unread mark. It
                    // counted as hearing from them above, which is its job.
                    Content::Cover { .. } => {
                        self.known_ids.insert(message.id);
                        return;
                    }
                    // What one's own devices say to each other; nothing
                    // for a contact to show, and this client keeps no
                    // devices yet.
                    Content::Sync(_) | Content::Provision(_) => {
                        self.known_ids.insert(message.id);
                        return;
                    }
                };
                // A file is fetched now only for a contact on /files auto;
                // otherwise it waits for /get. What the sender claims about
                // it is checked before either.
                let (text, fetch_now, pending) = match file {
                    None => (text, None, None),
                    Some(info) => match info.check() {
                        Err(e) => (format!("{text} · refused: {e}"), None, None),
                        Ok(()) if self.contacts[index].auto_files => (text, Some(info), None),
                        Ok(()) => (format!("{text} · /get to fetch"), None, Some(info)),
                    },
                };
                let id = message.id.clone();
                self.record(
                    from,
                    ChatLine {
                        id: message.id,
                        direction: Direction::Received,
                        timestamp_ms: claimed_time(message.sent_at_ms),
                        text,
                        delivered: true,
                        failed: false,
                        receipt: None,
                        file: None,
                        pending,
                        sender: None,
                    },
                );
                // Shown means in the selected chat of a window that has focus;
                // a chat open on an unattended screen has not been read.
                let shown =
                    self.selected_contact().map(|c| c.user_id) == Some(from) && self.focused;
                if !shown {
                    self.notifier.announce(&format!("New message from {name}"));
                }
                let wants = self.contacts[index].supports(capability::RECEIPTS);
                if shown && wants && self.read_receipts {
                    self.receipts.read(from, id.clone());
                } else if wants {
                    self.receipts.delivered(from, id.clone());
                }
                if !shown {
                    self.unread.entry(from).or_default().push(id.clone());
                }
                if let Some(info) = fetch_now {
                    self.start_download(from, id, info);
                }
            }
            ClientEvent::SessionEstablished {
                peer,
                initiated_by_us,
            } => {
                let name = self.contact_name(&peer);
                let info = self.client.session_info(&peer);
                let note = match info {
                    Some(s) if s.pq_ratchet => {
                        " Its handshake and every ratchet step use ML-KEM-768, so it is post-quantum throughout, and its messages are deniable."
                    }
                    Some(s) if s.post_quantum => {
                        " The handshake also used ML-KEM-768, so it is post-quantum."
                    }
                    _ => "",
                };
                self.system(
                    Level::Info,
                    format!(
                        "Forward-secret session with {name} started by {}. From here each message is encrypted under a key that is used once and then discarded.{note}",
                        if initiated_by_us { "you" } else { "them" },
                    ),
                );
            }
            ClientEvent::Undecryptable { from, reason, .. } => {
                let name = self.contact_name(&from);
                self.system(
                    Level::Warn,
                    format!(
                        "A message from {name} could not be read: {reason}. It is lost; sending them a message starts a fresh session so the next ones get through."
                    ),
                );
                self.toast(format!("Unreadable message from {name}; see System."));
            }
            ClientEvent::PeerRevoked { revocation } => self.handle_peer_revoked(revocation),
            ClientEvent::PeerSucceeded { succession } => self.handle_peer_succeeded(succession),
            ClientEvent::Transparency(event) => self.handle_transparency(event),
            ClientEvent::Group { from, id, body } => self.on_group_body(from, id, body),
            ClientEvent::Error(text) => {
                self.system(Level::Warn, text.clone());
                self.toast(text);
            }
        }
    }

    // --- identity lifecycle ----------------------------------------------------

    /// A validly-signed revocation reached us (from a lookup or pushed inside
    /// a message; the client checked the signature first). If it names a
    /// contact we have pinned, retire that contact: mark it revoked, drop the
    /// sessions and warn. A revocation for someone we do not know is ignored.
    fn handle_peer_revoked(&mut self, revocation: silver_protocol::Revocation) {
        let Some(index) = self.contact_index(&revocation.identity) else {
            return; // not a contact of ours
        };
        if self.contacts[index].revoked {
            return; // already known dead
        }
        let name = self.contact_name(&revocation.identity);
        let peer = revocation.identity;
        self.contacts[index].revoked = true;
        self.contacts[index].verified = false;
        self.persist_contacts();
        self.client.forget_sessions(&peer);
        self.system(
            Level::Warn,
            format!(
                "{name} revoked their identity. It is dead: do not trust it and you can no longer message it. If they move to a new identity you will be told, or they can send you a new one to /add."
            ),
        );
        self.toast(format!("{name} revoked their identity. See System."));
    }

    /// A validly-signed, cross-signed succession reached us. If its old key is
    /// a contact we have pinned, re-pin that contact to the successor key:
    /// migrate the conversation, clear the pinned bundle and the verified mark,
    /// start numbering afresh, and look the new key up. A succession whose old
    /// key we have not pinned is ignored.
    fn handle_peer_succeeded(&mut self, succession: silver_protocol::Succession) {
        let Some(index) = self.contact_index(&succession.old) else {
            return; // the old key is not one of ours
        };
        // A revocation is final: a dead key cannot hand over, so a
        // succession never lifts a revoked mark. Otherwise whoever holds a
        // compromised key could name their own successor after the owner
        // revoked it.
        if self.contacts[index].revoked {
            let name = self.contact_name(&succession.old);
            self.system(
                Level::Warn,
                format!(
                    "Ignored a handover from {name}'s revoked identity: a revoked key cannot name a successor."
                ),
            );
            return;
        }
        // Nothing to do if we already moved to (or past) this successor.
        if self.contact_index(&succession.new).is_some() {
            return;
        }
        let name = self.contact_name(&succession.old);
        let (old, new) = (succession.old, succession.new);
        // Migrate the on-disk conversation, then the in-memory view.
        if let Err(e) = self.store.migrate_history(&old, &new) {
            self.system(
                Level::Warn,
                format!("Could not move the conversation with {name} to their new key: {e}"),
            );
        }
        if let Some(thread) = self.threads.remove(&old) {
            self.threads.insert(new, thread);
        }
        if let Some(unread) = self.unread.remove(&old) {
            self.unread.entry(new).or_default().extend(unread);
        }
        let contact = &mut self.contacts[index];
        contact.user_id = new;
        contact.bundle = None; // re-pin on lookup below
        contact.verified = false;
        contact.revoked = false;
        contact.sent_seq = 0;
        contact.received = None;
        self.persist_contacts();
        self.client.forget_sessions(&old);
        self.system(
            Level::Warn,
            format!(
                "{name} moved to a new identity ({new}). It is signed by both their old and new keys, so it is genuine, and I have re-pinned them. The safety number has changed: run /verify and compare it again before you trust it."
            ),
        );
        self.toast(format!("{name} rotated their identity. See System."));
        // Fetch and pin the successor's key so messages can flow again.
        self.lookup_contact(new, None);
    }

    // --- key transparency ------------------------------------------------------

    /// The client checked the relay's key log: say what it found. A first
    /// sync is a quiet note; everything else means the relay's story to us
    /// and to a contact differ, which is the one thing the log is for.
    fn handle_transparency(&mut self, event: silver_client::TransparencyEvent) {
        use silver_client::TransparencyEvent as T;
        match event {
            T::Synced { head } => {
                self.system(
                    Level::Info,
                    format!(
                        "The relay's key log checks out up to entry {} ({}). /log shows where a contact's keys stand in it.",
                        head.index,
                        short_hash(&head.hash)
                    ),
                );
            }
            T::Lookup { who, problem } => {
                let name = self.contact_name(&who);
                self.system(
                    Level::Warn,
                    format!(
                        "KEY LOG: {problem} (looking up {name}). The key was refused and nothing was sent with it. The relay is showing you something it is not showing everyone; do not trust keys from it until this is explained."
                    ),
                );
                self.toast(format!(
                    "Key refused for {name}: the relay's log disagrees. See System."
                ));
            }
            T::Fork { peer, at } => {
                let whose = match peer {
                    Some(peer) => format!("{} was shown", self.contact_name(&peer)),
                    None => "the relay itself now shows".to_owned(),
                };
                self.system(
                    Level::Warn,
                    format!(
                        "KEY LOG FORK at entry {at}: {whose} a different key log than you have. The relay keeps two versions of its log, so it is lying to one of you about somebody's keys. Compare safety numbers (/verify) with the contacts that matter before trusting any key from this relay."
                    ),
                );
                self.toast("The relay's key log forks! See System.");
            }
            T::Withheld { peer, index } => {
                let whose = match peer {
                    Some(peer) => format!("{} has verified", self.contact_name(&peer)),
                    None => "it itself claims".to_owned(),
                };
                self.system(
                    Level::Warn,
                    format!(
                        "KEY LOG: the relay will not hand over its key log up to entry {index}, which {whose}. It is hiding entries from you; do not trust keys from it until this is explained."
                    ),
                );
                self.toast("The relay is withholding its key log. See System.");
            }
            T::Rewound { from, to } => {
                self.system(
                    Level::Warn,
                    format!(
                        "KEY LOG: the relay's key log went backwards, from {from} entries to {to}. Either it was restored from an older backup or its log was replaced. It is being replayed from the start; compare safety numbers (/verify) with any contact whose key changes from here."
                    ),
                );
                self.toast("The relay's key log went backwards. See System.");
            }
        }
    }

    /// Where the relay's key log stands, and where the selected contact
    /// appears in it.
    fn cmd_log(&mut self) {
        let Some(log) = self.client.transparency().cloned() else {
            self.toast("This client keeps no key log.");
            return;
        };
        if !self
            .client
            .relay_supports(silver_protocol::wire::feature::TRANSPARENCY)
        {
            self.system(
                Level::Info,
                "This relay keeps no key transparency log (it is older than 0.8.0), so what it shows about keys cannot be checked against one; safety numbers (/verify) are the only check.",
            );
            self.select(0);
            return;
        }
        let selected = self
            .selected_contact()
            .map(|c| (c.user_id, c.display_name()));
        let (head, verified_at, latest) = {
            let log = log.lock().unwrap_or_else(|e| e.into_inner());
            let latest = selected.as_ref().map(|(id, _)| log.latest(id));
            (log.head(), log.verified_at_ms(), latest)
        };
        let checked = if verified_at == 0 {
            "not verified yet".to_owned()
        } else {
            format!(
                "verified {}s ago",
                now_ms().saturating_sub(verified_at) / 1000
            )
        };
        self.system(
            Level::Info,
            format!(
                "Relay key log: {} entries, head {}, {checked}. Every key you are shown is checked against it, and contacts compare heads inside their messages.",
                head.index,
                short_hash(&head.hash)
            ),
        );
        if let (Some((_, name)), Some(latest)) = (selected, latest) {
            match latest {
                Some(l) => {
                    let what = match l.kind {
                        Some(silver_protocol::EntryKind::Bundle) => "a key",
                        Some(silver_protocol::EntryKind::Revocation) => "a revocation",
                        Some(silver_protocol::EntryKind::Succession) => "a handover",
                        None => "an entry",
                    };
                    self.system(
                        Level::Info,
                        format!(
                            "{name} last appears at entry {} ({what}){}.",
                            l.last.index,
                            l.bundle
                                .map(|b| format!(", current key logged at entry {}", b.index))
                                .unwrap_or_default()
                        ),
                    );
                }
                None => self.system(
                    Level::Info,
                    format!("{name} does not appear in the log yet (they have not published a key on this relay since it started logging)."),
                ),
            }
        }
        self.select(0);
    }

    // --- contact requests ------------------------------------------------------

    /// A contact told us how far our messages got: update their marks and
    /// remember it in the history.
    fn apply_receipt(&mut self, from: UserId, kind: ReceiptKind, ids: &[String]) {
        let mut applied = Vec::new();
        if let Some(lines) = self.threads.get_mut(&from) {
            for line in lines.iter_mut() {
                if line.direction == Direction::Sent
                    && ids.contains(&line.id)
                    && line.receipt.is_none_or(|r| r < kind)
                {
                    line.receipt = Some(kind);
                    applied.push(line.id.clone());
                }
            }
        }
        if applied.is_empty() {
            return;
        }
        if let Err(e) = self.store.append_receipt(&from, kind, &applied, now_ms()) {
            self.toast(format!("Could not save receipt: {e}"));
        }
    }

    /// Fetch a file a contact sent, updating its line as it goes. The line
    /// stops waiting while the fetch runs, so a second `/get` does not
    /// start it twice; a failure puts it back.
    fn start_download(&mut self, peer: UserId, id: String, info: FileInfo) {
        let label = info.label();
        if let Some(line) = self.line_mut(&peer, &id) {
            line.pending = None;
        }
        self.set_line_text(&peer, &id, format!("[file] {label} · receiving…"));
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        let dir = self.store.downloads_dir();
        let quota = self.downloads_quota;
        let (ptx, prx) = mpsc::channel::<Progress>(16);
        tokio::spawn(async move {
            let result = with_progress(
                &tx,
                prx,
                &format!("Receiving {label}"),
                client.download_file(&info, &dir, quota, Some(ptx)),
            )
            .await
            .map_err(|e| e.to_string());
            let _ = tx
                .send(Internal::Downloaded {
                    peer,
                    id,
                    info,
                    result,
                })
                .await;
        });
    }

    fn line_mut(&mut self, peer: &UserId, id: &str) -> Option<&mut ChatLine> {
        self.threads
            .get_mut(peer)
            .and_then(|lines| lines.iter_mut().rev().find(|l| l.id == id))
    }

    fn set_line_text(&mut self, peer: &UserId, id: &str, text: String) {
        if let Some(line) = self.line_mut(peer, id) {
            line.text = text;
        }
    }

    /// Open a received file with whatever the system uses for its kind,
    /// unless that would run it.
    fn open_file(&mut self, path: &std::path::Path) {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(why) = silver_client::files::refuse_to_open(path) {
            self.toast(format!("Not opening {name}: {why}."));
            return;
        }
        match open::that_detached(path) {
            Ok(()) => self.toast(format!("Opening {}", path.display())),
            Err(e) => self.toast(format!("Could not open {}: {e}", path.display())),
        }
    }

    /// `/open`: the last received file in this chat that was saved.
    fn cmd_open(&mut self) {
        let Some(peer) = self.selected_contact().map(|c| c.user_id) else {
            self.toast("Select a chat first.");
            return;
        };
        let path = self
            .threads
            .get(&peer)
            .and_then(|lines| lines.iter().rev().find_map(|l| l.file.clone()));
        match path {
            Some(path) => self.open_file(&path),
            None => self.toast("No saved file in this chat yet."),
        }
    }

    /// The saved file behind a row of the message pane, if it shows one.
    fn file_at_row(&self, row: usize) -> Option<PathBuf> {
        let source = self.view.rows.get(row)?.source?;
        match self.view.pane {
            Pane::Thread(peer) => self.threads.get(&peer)?.get(source)?.file.clone(),
            Pane::Group(group) => self.group_threads.get(&group)?.get(source)?.file.clone(),
            _ => None,
        }
    }

    /// The file waiting to be fetched behind a row, if it shows one.
    fn pending_at_row(&self, row: usize) -> Option<(UserId, String, FileInfo)> {
        let Pane::Thread(peer) = self.view.pane else {
            return None;
        };
        let source = self.view.rows.get(row)?.source?;
        let line = self.threads.get(&peer)?.get(source)?;
        line.pending
            .clone()
            .map(|info| (peer, line.id.clone(), info))
    }

    /// A single click on a received file's line says how to open or fetch
    /// it; a double click does.
    fn click_row(&mut self, row: usize) {
        if let Some(path) = self.file_at_row(row) {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            self.toast(format!("Double-click to open {name}, or /open."));
        } else if let Some((_, _, info)) = self.pending_at_row(row) {
            self.toast(format!("Double-click to fetch {}, or /get.", info.label()));
        }
    }

    /// `/get [all]`: fetch the newest file waiting in this chat, or all of
    /// them.
    fn cmd_get(&mut self, args: &[&str]) {
        let all = args.first().is_some_and(|a| a.eq_ignore_ascii_case("all"));
        if let Some(group) = self.selected_group() {
            self.group_get(group, all);
            return;
        }
        let Some(peer) = self.selected_contact().map(|c| c.user_id) else {
            self.toast("Select a chat first.");
            return;
        };
        let waiting: Vec<(String, FileInfo)> = self
            .threads
            .get(&peer)
            .map(|lines| {
                lines
                    .iter()
                    .rev()
                    .filter_map(|l| l.pending.clone().map(|p| (l.id.clone(), p)))
                    .collect()
            })
            .unwrap_or_default();
        if waiting.is_empty() {
            self.toast("No file is waiting in this chat.");
            return;
        }
        let chosen = if all { waiting.len() } else { 1 };
        for (id, info) in waiting.into_iter().take(chosen) {
            self.start_download(peer, id, info);
        }
    }

    /// `/files auto|ask`: whether the selected contact's files are fetched
    /// as they arrive or wait for `/get`.
    fn cmd_files(&mut self, args: &[&str]) {
        let Some(index) = self.selected_contact_index() else {
            self.toast("Select a contact first.");
            return;
        };
        let name = self.contacts[index].display_name();
        match args.first().map(|s| s.to_ascii_lowercase()).as_deref() {
            None => {
                let state = if self.contacts[index].auto_files {
                    "fetched as they arrive"
                } else {
                    "wait for /get"
                };
                self.toast(format!(
                    "Files from {name} {state}. /files auto fetches them at once, /files ask waits."
                ));
            }
            Some("auto") | Some("on") => {
                self.contacts[index].auto_files = true;
                self.persist_contacts();
                self.toast(format!(
                    "Files from {name} are fetched as they arrive, into downloads/. /files ask undoes that."
                ));
            }
            Some("ask") | Some("off") => {
                self.contacts[index].auto_files = false;
                self.persist_contacts();
                self.toast(format!("Files from {name} wait for /get."));
            }
            Some(_) => self.toast("Usage: /files auto|ask"),
        }
    }

    /// Send a file to the selected contact: upload it, then a message that
    /// says where it is and how to read it.
    fn cmd_send(&mut self, args: &[&str]) {
        if let Some(group) = self.selected_group() {
            self.send_group_file(group, args);
            return;
        }
        let Some(index) = self.selected_contact_index() else {
            self.toast("Select a contact first.");
            return;
        };
        if args.is_empty() {
            self.toast("Usage: /send <path to file>");
            return;
        }
        let contact = &self.contacts[index];
        let (peer, name) = (contact.user_id, contact.display_name());
        if !contact.supports(capability::FILES) {
            self.system(
                Level::Warn,
                format!(
                    "{name}'s client has not shown that it can receive files. They need Silver Messenger 0.4.0 or later and to have written to you since updating."
                ),
            );
            self.toast(format!("{name} cannot receive files yet; see System."));
            return;
        }
        if !self
            .client
            .relay_supports(silver_protocol::wire::feature::BLOBS)
        {
            self.system(
                Level::Warn,
                "The relay does not store files; it needs Silver Messenger 0.4.0 or later.",
            );
            self.toast("The relay is too old for files; see System.");
            return;
        }
        // A recipient that cuts files to their promised size can be sent a
        // padded one, so the relay sees only a multiple of the chunk size.
        let pad = contact.supports(capability::PADDED_FILES);
        let path = commands::expand_home(&args.join(" "));
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        let (ptx, prx) = mpsc::channel::<Progress>(16);
        self.toast(format!("Sending {}…", path.display()));
        tokio::spawn(async move {
            let result = with_progress(
                &tx,
                prx,
                &format!("Sending {}", path.display()),
                client.upload_file(&path, pad, Some(ptx)),
            )
            .await
            .map_err(|e| e.to_string());
            let _ = tx.send(Internal::Uploaded { peer, result }).await;
        });
    }

    /// Keep a message from an unknown sender until the user decides.
    fn hold_request(&mut self, message: Message) {
        let from = message.from;
        let mut file = None;
        let text = match message.content {
            Content::Text { body } => body,
            Content::File { .. } => {
                let info = FileInfo::from_content(&message.content).expect("file content");
                match info.check() {
                    Ok(()) => {
                        let text = format!(
                            "[file] {} (not fetched; /get can once you accept them)",
                            info.label()
                        );
                        file = Some(info);
                        text
                    }
                    Err(e) => format!("[file] {} · refused: {e}", info.label()),
                }
            }
            Content::Receipt { .. }
            | Content::Revocation(_)
            | Content::Succession(_)
            | Content::Cover { .. }
            | Content::Sync(_)
            | Content::Provision(_) => return,
        };
        // Strangers get bounded room: so many senders, so much per sender.
        let mut text: String = text.chars().take(MAX_HELD_CHARS).collect();
        if text.chars().count() == MAX_HELD_CHARS {
            text.push('…');
        }
        let held = HeldMessage {
            id: message.id.clone(),
            timestamp_ms: claimed_time(message.sent_at_ms),
            text,
            sequence: message.sequence,
            file,
            caps: message.caps.clone(),
        };
        self.known_ids.insert(message.id);
        let is_new = match self.requests.iter().position(|r| r.from == from) {
            Some(i) => {
                let request = &mut self.requests[i];
                request.messages.push(held);
                // The newest ones are kept: they are what /accept shows.
                while request.messages.len() > MAX_HELD_PER_SENDER {
                    request.messages.remove(0);
                }
                false
            }
            None if self.requests.len() >= MAX_REQUESTS => {
                if !self.requests_full_noted {
                    self.requests_full_noted = true;
                    self.system(
                        Level::Warn,
                        format!(
                            "{MAX_REQUESTS} people are waiting in the Requests pane; messages from anyone else are dropped until some are accepted or blocked."
                        ),
                    );
                }
                return;
            }
            None => {
                self.requests.push(ContactRequest {
                    from,
                    first_seen_ms: now_ms(),
                    messages: vec![held],
                });
                true
            }
        };
        self.persist_requests();
        if is_new {
            let n = self.requests.len();
            self.system(
                Level::Info,
                format!(
                    "Contact request from {}… ({from}). Open the Requests pane, then /accept {n} or /block {n}.",
                    from.short()
                ),
            );
            self.toast(format!("Contact request from {}…", from.short()));
            self.notifier
                .announce(&format!("Contact request from {}…", from.short()));
        }
    }

    /// Find a request by 1-based position or by user id.
    fn resolve_request(&self, arg: &str) -> Option<usize> {
        if let Ok(n) = arg.parse::<usize>() {
            return (1..=self.requests.len()).contains(&n).then(|| n - 1);
        }
        let id: UserId = arg.parse().ok()?;
        self.requests.iter().position(|r| r.from == id)
    }

    fn cmd_accept(&mut self, args: &[&str]) {
        let Some(arg) = args.first() else {
            self.toast("Usage: /accept <n|user-id|g<n>> (see the Requests pane)");
            return;
        };
        if let Some(n) = arg
            .strip_prefix(['g', 'G'])
            .and_then(|rest| rest.parse::<usize>().ok())
        {
            self.accept_invitation(n);
            return;
        }
        let Some(index) = self.resolve_request(arg) else {
            self.toast("No such request. Numbers are shown in the Requests pane.");
            return;
        };
        let request = self.requests.remove(index);
        self.persist_requests();
        let from = request.from;
        let mut contact = Contact::new(from);
        if let Some(last) = request.messages.last() {
            if last.sequence.seq != 0 {
                contact.received = Some(last.sequence);
            }
            // Remember what their client can do, so a file or receipt can go
            // to them at once rather than waiting for their next message.
            contact.caps = last.caps.clone();
        }
        self.contacts.push(contact);
        self.persist_contacts();
        let count = request.messages.len();
        for held in request.messages {
            // A file they sent while a stranger can be fetched now.
            let (text, pending) = match held.file {
                Some(info) => (
                    format!("[file] {} · /get to fetch", info.label()),
                    Some(info),
                ),
                None => (held.text, None),
            };
            self.record(
                from,
                ChatLine {
                    id: held.id,
                    direction: Direction::Received,
                    timestamp_ms: held.timestamp_ms,
                    text,
                    delivered: true,
                    failed: false,
                    receipt: None,
                    file: None,
                    pending,
                    sender: None,
                },
            );
        }
        self.select(self.contacts.len());
        self.system(
            Level::Info,
            format!(
                "Accepted {}… ({from}); {count} message(s) moved into the chat. Use /alias to name them and /verify to confirm who they are.",
                from.short()
            ),
        );
    }

    fn cmd_block(&mut self, args: &[&str]) {
        let Some(arg) = args.first() else {
            self.toast("Usage: /block <n|user-id>");
            return;
        };
        let id = match self.resolve_request(arg) {
            Some(index) => {
                let request = self.requests.remove(index);
                self.persist_requests();
                request.from
            }
            None => match arg.parse::<UserId>() {
                Ok(id) => id,
                Err(_) => {
                    self.toast("Give a request number or a user id.");
                    return;
                }
            },
        };
        if let Some(index) = self.contact_index(&id) {
            self.contacts.remove(index);
            self.threads.remove(&id);
            self.unread.remove(&id);
            self.persist_contacts();
        }
        if !self.blocked.contains(&id) {
            self.blocked.push(id);
            self.persist_blocked();
        }
        self.client.forget_sessions(&id);
        self.select(0);
        self.system(
            Level::Info,
            format!("Blocked {id}. Their messages are dropped; /unblock {id} undoes this."),
        );
    }

    fn cmd_unblock(&mut self, args: &[&str]) {
        let id = match args.first().map(|a| a.parse::<UserId>()) {
            Some(Ok(id)) => id,
            _ => {
                self.toast("Usage: /unblock <user-id>");
                return;
            }
        };
        let before = self.blocked.len();
        self.blocked.retain(|b| *b != id);
        if self.blocked.len() == before {
            self.toast("That id is not blocked.");
            return;
        }
        self.persist_blocked();
        self.system(Level::Info, format!("Unblocked {id}."));
    }

    fn cmd_blocked(&mut self) {
        if self.blocked.is_empty() {
            self.system(Level::Info, "No blocked ids.");
        } else {
            for id in self.blocked.clone() {
                self.system(Level::Info, format!("Blocked: {id}"));
            }
        }
        self.select(0);
    }

    fn persist_requests(&mut self) {
        if let Err(e) = self.store.save_requests(&self.requests) {
            self.toast(format!("Could not save requests: {e}"));
        }
        if self.requests.is_empty() && self.selected >= self.pane_count() {
            self.select(0);
        }
    }

    fn persist_blocked(&mut self) {
        if let Err(e) = self.store.save_blocked(&self.blocked) {
            self.toast(format!("Could not save the blocked list: {e}"));
        }
    }

    /// Append a line to a thread and to the on-disk history.
    fn record(&mut self, peer: UserId, line: ChatLine) {
        let entry = HistoryEntry {
            id: line.id.clone(),
            direction: line.direction,
            timestamp_ms: line.timestamp_ms,
            text: line.text.clone(),
            receipt: None,
            file: line.pending.clone(),
            from: None,
        };
        if let Err(e) = self.store.append_history(&peer, &entry) {
            self.toast(format!("Could not save history: {e}"));
        }
        self.known_ids.insert(line.id.clone());
        self.threads.entry(peer).or_default().push(line);
    }
}

/// Drive a transfer while showing its progress as "`label`: N%" toasts. The
/// transfer's outcome is returned only once the reports made before it were
/// shown, so a stale percentage never lands on top of the final word.
async fn with_progress<T>(
    tx: &mpsc::Sender<Internal>,
    mut reports: mpsc::Receiver<Progress>,
    label: &str,
    work: impl Future<Output = T>,
) -> T {
    let mut work = std::pin::pin!(work);
    let mut open = true;
    loop {
        tokio::select! {
            result = &mut work => return result,
            report = reports.recv(), if open => match report {
                Some(p) => {
                    let percent = p.done * 100 / p.total.max(1);
                    let _ = tx
                        .send(Internal::Progress {
                            text: format!("{label}: {percent}%"),
                        })
                        .await;
                }
                None => open = false,
            },
        }
    }
}

/// The first bytes of a log hash, for telling heads apart by eye.
fn short_hash(hash: &[u8; 32]) -> String {
    hash[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Crossterm's reader blocks, so it gets a thread of its own.
fn spawn_input_thread() -> mpsc::Receiver<Event> {
    let (tx, rx) = mpsc::channel(64);
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if tx.blocking_send(ev).is_err() {
                break;
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_client::{Client, ConnectOptions, Contact, Store};
    use silver_protocol::Identity;
    use std::sync::Arc;

    /// An app over a fresh store, with a client that never reaches a relay.
    fn app() -> (App, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (identity, _) = store.load_or_create_identity().unwrap();
        let url = "ws://127.0.0.1:1/ws".to_owned();
        let (client, _events) =
            Client::spawn(url.clone(), Arc::new(identity), ConnectOptions::default()).unwrap();
        let app = App::new(
            store,
            client,
            url,
            false,
            1,
            crate::glyphs::UNICODE,
            crate::theme::Theme::dark(),
            AtRest::Passphrase,
        )
        .unwrap();
        (app, dir)
    }

    fn message_from(
        id: &str,
        from: &Identity,
        to: UserId,
        content: silver_protocol::Content,
    ) -> Message {
        Message {
            id: id.to_owned(),
            from: from.user_id(),
            to,
            sent_at_ms: 1,
            sequence: silver_protocol::Sequence::default(),
            content,
            forward_secret: true,
            signed: false,
            caps: vec![capability::COVER.to_owned()],
            head: None,
            device: None,
        }
    }

    #[tokio::test]
    async fn cover_is_off_by_default_and_the_setting_is_advertised_and_kept() {
        let (mut app, _dir) = app();
        assert!(!app.cover);
        assert!(!app.client.capabilities().contains(&capability::COVER));
        app.cmd_cover(&["on"]);
        assert!(app.cover);
        assert!(app.client.capabilities().contains(&capability::COVER));
        assert!(app.store.load_config().unwrap().cover);
        app.cmd_cover(&["off"]);
        assert!(!app.cover);
        assert!(!app.client.capabilities().contains(&capability::COVER));
        assert!(!app.store.load_config().unwrap().cover);
    }

    #[tokio::test]
    async fn a_cover_message_leaves_no_trace_and_keeps_its_sender_covered() {
        let (mut app, _dir) = app();
        let me = app.me;
        let peer = Identity::generate();
        let mut contact = Contact::new(peer.user_id());
        contact.bundle = Some(peer.key_bundle());
        app.contacts.push(contact);

        // With cover off, a cover message is discarded and nobody is covered.
        let message = message_from(
            "c1",
            &peer,
            me,
            silver_protocol::Content::Cover { pad: "x".into() },
        );
        let id = message.id.clone();
        app.handle_client_event(ClientEvent::Message(Box::new(message)));
        assert!(
            app.threads
                .get(&peer.user_id())
                .is_none_or(|t| t.is_empty())
        );
        assert!(app.unread.get(&peer.user_id()).is_none_or(|u| u.is_empty()));
        assert!(app.receipts.is_empty(), "no receipt for cover");
        assert!(app.known_ids.contains(&id));
        assert!(app.cover_schedule.is_empty());

        // With cover on, hearing from a contact who advertises it starts
        // covering them; a real message counts the same, and is shown.
        app.cmd_cover(&["on"]);
        let message = message_from(
            "c2",
            &peer,
            me,
            silver_protocol::Content::Cover { pad: "y".into() },
        );
        app.handle_client_event(ClientEvent::Message(Box::new(message)));
        assert_eq!(app.cover_schedule.len(), 1);
        assert!(
            app.threads
                .get(&peer.user_id())
                .is_none_or(|t| t.is_empty())
        );
        let message = message_from(
            "t1",
            &peer,
            me,
            silver_protocol::Content::Text {
                body: "hello".into(),
            },
        );
        app.handle_client_event(ClientEvent::Message(Box::new(message)));
        assert_eq!(app.threads[&peer.user_id()].len(), 1);
        assert_eq!(app.cover_schedule.len(), 1);

        // A contact who does not advertise cover is never covered.
        let other = Identity::generate();
        app.contacts.push(Contact::new(other.user_id()));
        let mut message = message_from(
            "t2",
            &other,
            me,
            silver_protocol::Content::Text { body: "hi".into() },
        );
        message.caps = Vec::new();
        app.handle_client_event(ClientEvent::Message(Box::new(message)));
        assert_eq!(app.cover_schedule.len(), 1);

        // Turning cover off stops it at once.
        app.cmd_cover(&["off"]);
        assert!(app.cover_schedule.is_empty());
    }

    #[tokio::test]
    async fn a_revoked_contact_never_hands_over() {
        let (mut app, _dir) = app();
        let old = Identity::generate();
        let new = Identity::generate();
        app.contacts.push(Contact::new(old.user_id()));

        // The order one lookup delivers them in: the revocation, then the
        // succession. The succession must not lift the revoked mark.
        app.handle_client_event(ClientEvent::PeerRevoked {
            revocation: old.revocation(1),
        });
        assert!(app.contacts[0].revoked);
        app.handle_client_event(ClientEvent::PeerSucceeded {
            succession: old.succeed_to(&new, 2),
        });
        assert_eq!(
            app.contacts[0].user_id,
            old.user_id(),
            "still the revoked key, not the would-be successor"
        );
        assert!(app.contacts[0].revoked);
        assert!(app.contact_index(&new.user_id()).is_none());
        // Once revoked, it stays so.
        app.handle_client_event(ClientEvent::PeerRevoked {
            revocation: old.revocation(3),
        });
        assert!(app.contacts[0].revoked);
    }

    #[tokio::test]
    async fn a_live_contact_is_re_pinned_by_a_succession() {
        let (mut app, _dir) = app();
        let old = Identity::generate();
        let new = Identity::generate();
        let mut contact = Contact::new(old.user_id());
        contact.verified = true;
        contact.sent_seq = 5;
        contact.bundle = Some(old.key_bundle());
        app.contacts.push(contact);
        app.threads
            .entry(old.user_id())
            .or_default()
            .push(ChatLine {
                id: "1".into(),
                direction: Direction::Sent,
                timestamp_ms: 1,
                text: "before".into(),
                delivered: true,
                failed: false,
                receipt: None,
                file: None,
                pending: None,
                sender: None,
            });

        app.handle_client_event(ClientEvent::PeerSucceeded {
            succession: old.succeed_to(&new, 1),
        });
        let contact = &app.contacts[0];
        assert_eq!(contact.user_id, new.user_id());
        assert!(!contact.verified, "the safety number changed");
        assert!(!contact.revoked);
        assert!(contact.bundle.is_none(), "re-pinned on the next lookup");
        assert_eq!(contact.sent_seq, 0);
        assert_eq!(
            app.threads.get(&new.user_id()).map(Vec::len),
            Some(1),
            "the conversation moved with the contact"
        );
        assert!(!app.threads.contains_key(&old.user_id()));

        // A later revocation of the old key names nobody still pinned.
        app.handle_client_event(ClientEvent::PeerRevoked {
            revocation: old.revocation(2),
        });
        assert!(!app.contacts[0].revoked);
        // Statements about strangers are ignored, not added.
        let stranger = Identity::generate();
        app.handle_client_event(ClientEvent::PeerRevoked {
            revocation: stranger.revocation(3),
        });
        app.handle_client_event(ClientEvent::PeerSucceeded {
            succession: stranger.succeed_to(&Identity::generate(), 4),
        });
        assert_eq!(app.contacts.len(), 1);
    }

    #[tokio::test]
    async fn no_identity_change_is_taken_after_a_rotation_until_restart() {
        let (mut app, _dir) = app();
        let before = app.system.len();
        app.rotated = true;
        app.cmd_revoke(&["confirm"]);
        app.cmd_rotate(&["confirm"]);
        // Both refused with an explanation, and the stored identity is the
        // one the rotation left, untouched.
        assert_eq!(app.system.len(), before + 2);
        assert!(app.store.revocation().unwrap().is_none());
    }

    // --- groups ------------------------------------------------------------------

    use super::groups::Purpose;
    use silver_client::SequencerAnswer;
    use silver_client::groups::{Groups, Outgoing};
    use silver_protocol::envelope::{Body, Envelope, open_bytes};
    use silver_protocol::group::GroupId;

    /// Another member's client: an engine over a fresh identity.
    fn engine() -> (Arc<Identity>, Groups) {
        let identity = Arc::new(Identity::generate());
        (identity.clone(), Groups::ephemeral(identity))
    }

    /// Open an envelope another engine sealed to the app's user, as the
    /// connection task would, and hand its group body to the app.
    fn deliver(app: &mut App, envelope: &Envelope) {
        let identity = app.client.identity_arc();
        let opened = open_bytes(&identity, envelope).unwrap();
        let Body::Group(body) = Body::decode(&opened.body).unwrap() else {
            panic!("not a group body");
        };
        app.handle_client_event(ClientEvent::Group {
            from: opened.from,
            id: opened.id,
            body: Box::new(body),
        });
    }

    /// `admin` adds the app's user to `group` with the app's `n`th key
    /// package on deposit: the Welcome to send.
    fn add_me(app: &mut App, admin: &mut Groups, group: &GroupId, n: usize) -> Outgoing {
        let (packages, _) = app.groups.deposit(now_ms()).unwrap();
        let verified = admin
            .verify_key_package(&app.me, &packages[n].data, now_ms())
            .unwrap();
        admin.stage_add(group, &[verified]).unwrap();
        admin.commit_staged(group, now_ms()).unwrap()
    }

    fn text(s: &str) -> Content {
        Content::Text { body: s.into() }
    }

    fn group_texts(app: &App, group: &GroupId) -> Vec<String> {
        app.group_threads
            .get(group)
            .map(|lines| lines.iter().map(|l| l.text.clone()).collect())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn a_group_stands_on_the_sequencers_word_and_falls_without_it() {
        let (mut app, _dir) = app();
        assert_eq!(app.pane_count(), 1);
        let created = app.groups.create("team", now_ms()).unwrap();
        let group = created.group;
        app.refresh_group_list();
        assert_eq!(app.group_list, vec![group]);
        assert_eq!(app.pane_count(), 2);
        assert_eq!(
            app.selected_group(),
            None,
            "not opened before the relay agrees"
        );

        // The relay takes it: the pane opens.
        app.on_group_sequenced(group, Purpose::Create, Ok(SequencerAnswer::Stands(0)));
        assert_eq!(app.selected_group(), Some(group));
        assert!(app.group_title(&group).contains("you are an admin"));
        assert!(
            app.system
                .iter()
                .any(|l| l.text.starts_with("Created team"))
        );

        // A rename the relay calls stale is discarded, and the name stays.
        app.groups.stage_rename(&group, "crew").unwrap();
        app.on_group_sequenced(
            group,
            Purpose::Rename("crew".into()),
            Ok(SequencerAnswer::Stale(3)),
        );
        assert!(!app.groups.has_staged(&group));
        assert_eq!(app.group_name(&group), "team");
        assert!(
            app.toast
                .as_ref()
                .is_some_and(|(t, _)| t.contains("did not go through"))
        );

        // One that stands is merged and noted in the group.
        app.groups.stage_rename(&group, "crew").unwrap();
        app.on_group_sequenced(
            group,
            Purpose::Rename("crew".into()),
            Ok(SequencerAnswer::Stands(1)),
        );
        assert_eq!(app.group_name(&group), "crew");
        assert_eq!(
            group_texts(&app, &group),
            vec!["· you renamed the group to crew"]
        );
        assert_eq!(app.store.load_group_history(&group).unwrap().len(), 1);

        // A second group the relay refuses is dropped again.
        let other = app.groups.create("other", now_ms()).unwrap();
        app.refresh_group_list();
        assert_eq!(app.group_list.len(), 2);
        app.on_group_sequenced(other.group, Purpose::Create, Ok(SequencerAnswer::Exists(4)));
        assert_eq!(app.group_list, vec![group]);
        assert!(app.groups.get(&other.group).is_none());
        assert_eq!(app.pane_count(), 2);
    }

    #[tokio::test]
    async fn an_invitation_waits_for_a_stranger_and_is_taken_from_a_contact() {
        let (mut app, _dir) = app();
        let (alice_id, mut alice) = engine();
        let alice_id = alice_id.user_id();
        let created = alice.create("the papers", now_ms()).unwrap();
        let group = created.group;
        let out = add_me(&mut app, &mut alice, &group, 0);
        assert_eq!(out.envelopes.len(), 1, "a Welcome to us alone");
        deliver(&mut app, &out.envelopes[0]);

        // A stranger's Welcome waits in Requests; nothing of the group shows.
        assert!(app.group_list.is_empty());
        assert_eq!(app.invitations().len(), 1);
        assert!(app.has_requests_pane());
        assert_eq!(app.held_message_count(), 1);
        assert_eq!(app.pane_count(), 2);
        assert!(
            app.system
                .iter()
                .any(|l| l.text.contains("invites you to the group the papers"))
        );
        let out = alice
            .send(&group, text("before you said yes"), None, now_ms())
            .unwrap();
        deliver(&mut app, &out.envelopes[0]);
        assert!(group_texts(&app, &group).is_empty());

        // /accept g1 opens it, and what comes next shows with its writer.
        app.cmd_accept(&["g1"]);
        assert_eq!(app.group_list, vec![group]);
        assert!(app.invitations().is_empty());
        assert!(!app.has_requests_pane());
        assert_eq!(app.selected_group(), Some(group));
        assert!(
            group_texts(&app, &group)
                .iter()
                .any(|t| t.ends_with(" added you"))
        );
        let out = alice.send(&group, text("hello"), None, now_ms()).unwrap();
        deliver(&mut app, &out.envelopes[0]);
        let last = app.group_threads[&group].last().unwrap();
        assert_eq!(last.text, "hello");
        assert_eq!(last.direction, Direction::Received);
        assert_eq!(last.sender, Some(alice_id));
        assert!(
            app.group_unread.get(&group).is_none_or(|u| u.is_empty()),
            "read at once in the open, focused pane"
        );
        let history = app.store.load_group_history(&group).unwrap();
        assert_eq!(history.last().unwrap().from, Some(alice_id));
        // The same envelope again is not shown twice.
        deliver(&mut app, &out.envelopes[0]);
        assert_eq!(
            group_texts(&app, &group)
                .iter()
                .filter(|t| *t == "hello")
                .count(),
            1
        );

        // Declined, an invitation goes without a trace.
        let second = alice.create("another", now_ms()).unwrap();
        let out = add_me(&mut app, &mut alice, &second.group, 1);
        deliver(&mut app, &out.envelopes[0]);
        assert_eq!(app.invitations().len(), 1);
        app.cmd_decline(&["g1"]);
        assert!(app.invitations().is_empty());
        assert!(app.groups.get(&second.group).is_none());
        assert_eq!(app.group_list, vec![group]);

        // A contact's Welcome is taken at once, with a badge on the pane.
        let (bob_id, mut bob) = engine();
        app.contacts.push(Contact::new(bob_id.user_id()));
        let third = bob.create("bob's", now_ms()).unwrap();
        let out = add_me(&mut app, &mut bob, &third.group, 2);
        deliver(&mut app, &out.envelopes[0]);
        assert!(app.invitations().is_empty());
        assert!(app.group_list.contains(&third.group));
        assert!(
            app.group_unread
                .get(&third.group)
                .is_some_and(|u| !u.is_empty())
        );

        // A blocked sender's Welcome is declined without a word.
        let (eve_id, mut eve) = engine();
        app.blocked.push(eve_id.user_id());
        let fourth = eve.create("eve's", now_ms()).unwrap();
        let out = add_me(&mut app, &mut eve, &fourth.group, 3);
        let before = app.system.len();
        deliver(&mut app, &out.envelopes[0]);
        assert!(app.invitations().is_empty());
        assert!(app.groups.get(&fourth.group).is_none());
        assert_eq!(app.system.len(), before);
    }

    #[tokio::test]
    async fn a_group_message_is_marked_sent_once_every_member_has_it() {
        let (mut app, _dir) = app();
        let created = app.groups.create("team", now_ms()).unwrap();
        let group = created.group;
        app.refresh_group_list();
        app.on_group_sequenced(group, Purpose::Create, Ok(SequencerAnswer::Stands(0)));

        // Two envelopes went out for one message; the relay took one so far.
        app.group_envelopes
            .insert("e1".into(), (group, "m1".into()));
        app.group_envelopes
            .insert("e2".into(), (group, "m1".into()));
        app.group_outstanding.insert("m1".into(), 2);
        app.on_group_sent(group, Some("m1".into()), Some("hello".into()), Ok(()));
        let line = app.group_line_mut(&group, "m1").unwrap();
        assert_eq!(line.direction, Direction::Sent);
        assert!(!line.delivered);
        assert!(app.on_group_envelope_done("e1", true));
        assert!(!app.group_line_mut(&group, "m1").unwrap().delivered);
        assert!(app.on_group_envelope_done("e2", true));
        assert!(app.group_line_mut(&group, "m1").unwrap().delivered);
        assert!(app.group_outstanding.is_empty());
        // An envelope of a one-to-one message is not ours to count.
        assert!(!app.on_group_envelope_done("elsewhere", true));

        // A message the relay refused is not shown as sent.
        app.on_group_sent(
            group,
            Some("m2".into()),
            Some("lost".into()),
            Err("gone".into()),
        );
        assert!(app.group_line_mut(&group, "m2").is_none());
        assert!(
            app.system
                .last()
                .is_some_and(|l| l.text.contains("not sent"))
        );
    }
}
