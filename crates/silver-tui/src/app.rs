//! Application state, key handling and command dispatch.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use silver_client::{Client, ClientError, ClientEvent, Contact, Direction, HistoryEntry, Store};
use silver_protocol::{Content, Envelope, KeyBundle, UserId, now_ms};
use tokio::sync::mpsc;

use crate::ui;

const TOAST_TTL: Duration = Duration::from_secs(6);
const SCROLL_STEP: usize = 5;

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
}

/// One row in a conversation.
pub struct ChatLine {
    pub id: String,
    pub direction: Direction,
    pub timestamp_ms: u64,
    pub text: String,
    /// The relay has accepted this outgoing message.
    pub delivered: bool,
}

/// One row in the system pane.
pub struct SystemLine {
    pub timestamp_ms: u64,
    pub level: Level,
    pub text: String,
}

/// Results of background work spawned by the UI.
enum Internal {
    LookupDone {
        user_id: UserId,
        alias: Option<String>,
        result: Result<Option<KeyBundle>, ClientError>,
    },
    SendDone {
        peer: UserId,
        text: String,
        /// A bundle we had to look up on the way; pin it.
        learned: Option<KeyBundle>,
        result: Result<Envelope, String>,
    },
}

pub struct App {
    store: Store,
    client: Client,
    pub relay_url: String,
    pub me: UserId,
    pub connection: Connection,
    pub contacts: Vec<Contact>,
    pub threads: HashMap<UserId, Vec<ChatLine>>,
    pub unread: HashMap<UserId, usize>,
    known_ids: HashSet<String>,
    pub system: Vec<SystemLine>,
    /// 0 is the system pane; `i >= 1` selects `contacts[i - 1]`.
    pub selected: usize,
    pub input: String,
    /// Cursor position in `input`, in chars.
    pub cursor: usize,
    /// Rows scrolled up from the bottom of the message pane.
    pub scroll: usize,
    /// Set by the renderer so scrolling can be clamped.
    pub max_scroll: usize,
    pub toast: Option<(String, Instant)>,
    internal_tx: mpsc::Sender<Internal>,
    internal_rx: Option<mpsc::Receiver<Internal>>,
    should_quit: bool,
}

impl App {
    pub fn new(
        store: Store,
        client: Client,
        relay_url: String,
        fresh_identity: bool,
    ) -> anyhow::Result<Self> {
        let me = client.user_id();
        let contacts = store.load_contacts()?;
        let mut threads = HashMap::new();
        let mut known_ids = HashSet::new();
        for contact in &contacts {
            let lines: Vec<ChatLine> = store
                .load_history(&contact.user_id)?
                .into_iter()
                .map(|h| {
                    known_ids.insert(h.id.clone());
                    ChatLine {
                        id: h.id,
                        direction: h.direction,
                        timestamp_ms: h.timestamp_ms,
                        text: h.text,
                        delivered: true,
                    }
                })
                .collect();
            threads.insert(contact.user_id, lines);
        }
        let (internal_tx, internal_rx) = mpsc::channel(64);
        let mut app = Self {
            store,
            client,
            relay_url,
            me,
            connection: Connection::Connecting,
            contacts,
            threads,
            unread: HashMap::new(),
            known_ids,
            system: Vec::new(),
            selected: 0,
            input: String::new(),
            cursor: 0,
            scroll: 0,
            max_scroll: 0,
            toast: None,
            internal_tx,
            internal_rx: Some(internal_rx),
            should_quit: false,
        };
        app.system(Level::Info, "Welcome to Silver Message.");
        if fresh_identity {
            app.system(
                Level::Info,
                format!("Generated a new identity in {}", app.store.root().display()),
            );
        }
        app.system(Level::Info, format!("Your id: {me}"));
        app.system(
            Level::Info,
            "Share it with people who want to message you. Type /help for commands.",
        );
        Ok(app)
    }

    pub async fn run(
        mut self,
        mut terminal: DefaultTerminal,
        mut events: mpsc::Receiver<ClientEvent>,
    ) -> anyhow::Result<()> {
        let mut keys = spawn_input_thread();
        let mut internal_rx = self.internal_rx.take().expect("run is called once");
        let mut tick = tokio::time::interval(Duration::from_millis(250));

        loop {
            terminal.draw(|frame| ui::draw(frame, &mut self))?;
            tokio::select! {
                Some(ev) = keys.recv() => self.handle_terminal_event(ev),
                Some(ev) = events.recv() => self.handle_client_event(ev),
                Some(ev) = internal_rx.recv() => self.handle_internal(ev),
                _ = tick.tick() => self.expire_toast(),
            }
            if self.should_quit {
                break;
            }
        }
        self.client.shutdown().await;
        Ok(())
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

    fn contact_name(&self, user_id: &UserId) -> String {
        self.contact_index(user_id)
            .map(|i| self.contacts[i].display_name())
            .unwrap_or_else(|| format!("{}…", user_id.short()))
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
            Event::Paste(text) => self.insert_str(&text),
            _ => {}
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('q') if ctrl => self.should_quit = true,
            KeyCode::Char('n') if ctrl => self.select_next(),
            KeyCode::Char('p') if ctrl => self.select_prev(),
            KeyCode::Char('u') if ctrl => self.clear_input(),
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.input.chars().count(),
            KeyCode::Tab | KeyCode::Down => self.select_next(),
            KeyCode::BackTab | KeyCode::Up => self.select_prev(),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.input.chars().count(),
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.input.chars().count()),
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    let at = self.byte_index(self.cursor);
                    self.input.remove(at);
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.input.chars().count() {
                    let at = self.byte_index(self.cursor);
                    self.input.remove(at);
                }
            }
            KeyCode::PageUp => self.scroll = (self.scroll + SCROLL_STEP).min(self.max_scroll),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(SCROLL_STEP),
            KeyCode::Esc => self.clear_input(),
            KeyCode::Enter => self.submit(),
            KeyCode::Char(c) if !ctrl && !alt => {
                let at = self.byte_index(self.cursor);
                self.input.insert(at, c);
                self.cursor += 1;
            }
            _ => {}
        }
    }

    fn byte_index(&self, char_index: usize) -> usize {
        self.input
            .char_indices()
            .nth(char_index)
            .map_or(self.input.len(), |(i, _)| i)
    }

    fn insert_str(&mut self, text: &str) {
        let at = self.byte_index(self.cursor);
        self.input.insert_str(at, text);
        self.cursor += text.chars().count();
    }

    fn clear_input(&mut self) {
        self.input.clear();
        self.cursor = 0;
    }

    fn select_next(&mut self) {
        let n = self.contacts.len() + 1;
        self.select((self.selected + 1) % n);
    }

    fn select_prev(&mut self) {
        let n = self.contacts.len() + 1;
        self.select((self.selected + n - 1) % n);
    }

    fn select(&mut self, index: usize) {
        self.selected = index.min(self.contacts.len());
        self.scroll = 0;
        if let Some(id) = self.selected_contact().map(|c| c.user_id) {
            self.unread.remove(&id);
        }
    }

    fn submit(&mut self) {
        let line = std::mem::take(&mut self.input).trim().to_owned();
        self.cursor = 0;
        if line.is_empty() {
            return;
        }
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
                self.select(0);
            }
            "add" => self.cmd_add(&rest),
            "alias" | "rename" => self.cmd_alias(&rest),
            "remove" | "rm" => self.cmd_remove(),
            "relay" => self.cmd_relay(&rest),
            "quit" | "q" | "exit" => self.should_quit = true,
            other => self.toast(format!("Unknown command /{other}. Try /help.")),
        }
    }

    fn print_help(&mut self) {
        for line in [
            "Commands:",
            "  /add <user-id> [alias]   add a contact by id (looks up their key on the relay)",
            "  /alias <name>            name the selected contact",
            "  /remove                  forget the selected contact (history stays on disk)",
            "  /me                      show your own id",
            "  /relay <ws-url>          change the relay (takes effect on next start)",
            "  /quit                    exit",
            "Keys: Tab/Shift-Tab or Up/Down switch chats · PgUp/PgDn scroll · Esc clears input · Ctrl-C quits",
        ] {
            self.system(Level::Info, line);
        }
        self.select(0);
    }

    fn cmd_add(&mut self, args: &[&str]) {
        let Some(id_text) = args.first() else {
            self.toast("Usage: /add <user-id> [alias]");
            return;
        };
        let user_id: UserId = match id_text.parse() {
            Ok(id) => id,
            Err(_) => {
                self.toast("That is not a valid user id.");
                return;
            }
        };
        if user_id == self.me {
            self.toast("That is your own id.");
            return;
        }
        let alias = args.get(1).map(|s| s.to_string());
        if let Some(i) = self.contact_index(&user_id) {
            if alias.is_some() {
                self.contacts[i].alias = alias;
                self.persist_contacts();
            }
            self.select(i + 1);
            return;
        }
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

    fn cmd_alias(&mut self, args: &[&str]) {
        let Some(index) = self.selected.checked_sub(1) else {
            self.toast("Select a contact first.");
            return;
        };
        if args.is_empty() {
            self.toast("Usage: /alias <name>");
            return;
        }
        self.contacts[index].alias = Some(args.join(" "));
        self.persist_contacts();
    }

    fn cmd_remove(&mut self) {
        let Some(index) = self.selected.checked_sub(1) else {
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
        config.relay_url = Some(url.to_string());
        match self.store.save_config(&config) {
            Ok(()) => self.system(
                Level::Info,
                format!("Relay set to {url}; restart to connect to it."),
            ),
            Err(e) => self.toast(format!("Could not save config: {e}")),
        }
    }

    fn persist_contacts(&mut self) {
        if let Err(e) = self.store.save_contacts(&self.contacts) {
            self.toast(format!("Could not save contacts: {e}"));
        }
    }

    // --- messaging ---------------------------------------------------------

    fn send_message(&mut self, text: String) {
        let Some(contact) = self.selected_contact() else {
            self.toast("Select a contact first, or /add <user-id>.");
            return;
        };
        let peer = contact.user_id;
        let pinned = contact.bundle.clone();
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let (bundle, learned) = match pinned {
                Some(b) => (b, None),
                None => match client.lookup(peer).await {
                    Ok(Some(b)) => (b.clone(), Some(b)),
                    Ok(None) => {
                        let _ = tx
                            .send(Internal::SendDone {
                                peer,
                                text,
                                learned: None,
                                result: Err("they have not published a key yet (they need to run Silver Message once)".into()),
                            })
                            .await;
                        return;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Internal::SendDone {
                                peer,
                                text,
                                learned: None,
                                result: Err(e.to_string()),
                            })
                            .await;
                        return;
                    }
                },
            };
            let result = client
                .send_text(&bundle, text.clone())
                .await
                .map_err(|e| e.to_string());
            let _ = tx
                .send(Internal::SendDone {
                    peer,
                    text,
                    learned,
                    result,
                })
                .await;
        });
    }

    fn handle_internal(&mut self, ev: Internal) {
        match ev {
            Internal::LookupDone {
                user_id,
                alias,
                result,
            } => match result {
                Ok(bundle) => {
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
                Err(e) => self.toast(format!("Lookup failed: {e}")),
            },
            Internal::SendDone {
                peer,
                text,
                learned,
                result,
            } => {
                if let Some(bundle) = learned {
                    if let Some(i) = self.contact_index(&peer) {
                        self.contacts[i].bundle = Some(bundle);
                        self.persist_contacts();
                    }
                }
                match result {
                    Ok(envelope) => {
                        self.record(
                            peer,
                            ChatLine {
                                id: envelope.id,
                                direction: Direction::Sent,
                                timestamp_ms: now_ms(),
                                text,
                                delivered: false,
                            },
                        );
                        self.scroll = 0;
                    }
                    Err(e) => {
                        self.toast(format!("Not sent: {e}"));
                        self.system(
                            Level::Warn,
                            format!("Message to {} not sent: {e}", self.contact_name(&peer)),
                        );
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
                for lines in self.threads.values_mut() {
                    if let Some(line) = lines.iter_mut().rev().find(|l| l.id == id) {
                        line.delivered = true;
                        break;
                    }
                }
            }
            ClientEvent::Message(message) => {
                if self.known_ids.contains(&message.id) {
                    return; // relay re-delivered something we already have
                }
                let from = message.from;
                if self.contact_index(&from).is_none() {
                    self.contacts.push(Contact::new(from));
                    self.persist_contacts();
                    self.system(
                        Level::Info,
                        format!(
                            "New contact {}… ({from}). Use /alias to name them.",
                            from.short()
                        ),
                    );
                }
                let Content::Text { body } = message.content;
                self.record(
                    from,
                    ChatLine {
                        id: message.id,
                        direction: Direction::Received,
                        timestamp_ms: message.sent_at_ms,
                        text: body,
                        delivered: true,
                    },
                );
                if self.selected_contact().map(|c| c.user_id) != Some(from) {
                    *self.unread.entry(from).or_default() += 1;
                }
            }
            ClientEvent::Error(text) => {
                self.system(Level::Warn, text.clone());
                self.toast(text);
            }
        }
    }

    /// Append a line to a thread and to the on-disk history.
    fn record(&mut self, peer: UserId, line: ChatLine) {
        let entry = HistoryEntry {
            id: line.id.clone(),
            direction: line.direction,
            timestamp_ms: line.timestamp_ms,
            text: line.text.clone(),
        };
        if let Err(e) = self.store.append_history(&peer, &entry) {
            self.toast(format!("Could not save history: {e}"));
        }
        self.known_ids.insert(line.id.clone());
        self.threads.entry(peer).or_default().push(line);
    }
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
