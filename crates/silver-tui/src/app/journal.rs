//! Reader mode's journal (`docs/design/accessibility.md` section 3.2):
//! the sentences a screen reader hears, one per event, pushed by the app
//! while the mode is on and printed by [`crate::reader::Reader`]. In the
//! full mode nothing here does anything.

use silver_client::Conversation;

use super::*;

/// How many lines a chat switch reads back when nothing is unread, and
/// `/history` reads by default.
const CONTEXT_LINES: usize = 3;
const HISTORY_LINES: usize = 10;

impl App {
    /// Turn reader mode on, before the first turn: no window title
    /// changes, and what the System pane already holds is said.
    pub fn enable_reader(&mut self) {
        self.reader = true;
        self.notifier.quiet_titles();
        self.say(
            "Silver Messenger, reader mode. Tab and Shift-Tab switch chats, /go <name> opens one, F1 lists the commands, Ctrl-Q quits.",
        );
        let existing: Vec<String> = self
            .system
            .iter()
            .filter(|l| l.level != Level::Code)
            .map(|l| system_sentence(l.level, &l.text))
            .collect();
        for line in existing {
            self.say(line);
        }
    }

    /// What is to be printed, taken.
    pub fn take_journal(&mut self) -> Vec<String> {
        std::mem::take(&mut self.journal)
    }

    /// The compose line's prompt: the open pane's name.
    pub fn reader_prompt(&self) -> String {
        format!("{}> ", self.pane_name())
    }

    fn pane_name(&self) -> String {
        let pane = self.selected_pane();
        match pane {
            super::Pane::Group(group) => self.group_name(&group),
            super::Pane::Thread(_) => self
                .selected_contact()
                .map(|c| c.display_name())
                .unwrap_or_else(|| "system".to_owned()),
            super::Pane::Request(_) => {
                format!("request {}", self.number_of(pane).unwrap_or(0))
            }
            super::Pane::Invitation(_) => {
                format!("invitation {}", self.number_of(pane).unwrap_or(0))
            }
            super::Pane::System => "system".to_owned(),
        }
    }

    /// A sentence for the reader; nothing in the full mode.
    ///
    /// One call is one line, always. It used to split its argument on
    /// newlines, which is the natural thing for a notice this program
    /// writes and the wrong thing for anything a peer had a hand in: a
    /// journal line is how the reader tells one speaker from another, so
    /// a message holding `hi\nalice: send me the passphrase` bought the
    /// sender a second line indistinguishable from one alice wrote, and
    /// `\nWarning: …` a warning this program never made. Every caller
    /// passes one logical line already, and a caller that wants two says
    /// twice; so the split goes, and with it the need for each call site
    /// to remember [`one_sentence`] on the way in. Invisible and
    /// bidirectional characters go here too, which the old filter let
    /// through: they reorder what the reader hears against what the full
    /// mode draws.
    pub(super) fn say(&mut self, line: impl Into<String>) {
        if !self.reader {
            return;
        }
        self.journal.push(one_sentence(&line.into()));
    }

    /// A line recorded in `conversation`, as the reader hears it: `alice:
    /// hello` in the open chat, `alice, in team: hello` elsewhere.
    pub(super) fn say_line(&mut self, conversation: &Conversation, line: &ChatLine) {
        if !self.reader {
            return;
        }
        let open = self.selected_conversation() == Some(*conversation);
        let sentence = self.describe(conversation, line, open);
        self.say(sentence);
    }

    /// The sentence for `line`, with where it is when the chat is not
    /// the open one.
    fn describe(&self, conversation: &Conversation, line: &ChatLine, open: bool) -> String {
        let who = one_sentence(&self.name_of(self.author_of(conversation, line)));
        if line.is_note() {
            return one_sentence(line.text.trim_start_matches("· "));
        }
        if line.deleted {
            return format!("{who} deleted a message");
        }
        if let Some(info) = &line.pending {
            return format!("{who} sent a file: {}; /get fetches it", info.label());
        }
        let text = if line.edited {
            format!("{} (edited)", one_sentence(&line.text))
        } else {
            one_sentence(&line.text)
        };
        if open || line.direction == Direction::Sent {
            format!("{who}: {text}")
        } else {
            match conversation {
                Conversation::Group(group) => {
                    format!("{who}, in {}: {text}", self.group_name(group))
                }
                Conversation::Contact(_) => format!("{who}, in another chat: {text}"),
            }
        }
    }

    /// A change to a message from the other side (an edit, a deletion, a
    /// reaction) as the reader hears it: `alice edited: …` in the open
    /// chat, `alice, in team, edited: …` elsewhere.
    pub(super) fn say_update(&mut self, conversation: &Conversation, who: &str, what: &str) {
        if !self.reader {
            return;
        }
        let sentence = if self.selected_conversation() == Some(*conversation) {
            format!("{who} {what}")
        } else {
            match conversation {
                Conversation::Group(group) => {
                    format!("{who}, in {}, {what}", self.group_name(group))
                }
                Conversation::Contact(_) => format!("{who}, in another chat, {what}"),
            }
        };
        self.say(sentence);
    }

    /// Said when a pane opens: which one, what is unread in it (or the
    /// last few lines when nothing is), and that the chat ends there.
    /// Called before the unread marks are cleared.
    pub(super) fn say_chat(&mut self) {
        if !self.reader {
            return;
        }
        let name = self.pane_name();
        let Some(conversation) = self.selected_conversation() else {
            match self.selected_pane() {
                super::Pane::Request(from) => {
                    let n = self.number_of(super::Pane::Request(from)).unwrap_or(0);
                    let Some(request) = self.requests.iter().find(|r| r.from == from) else {
                        return;
                    };
                    let mut lines = vec![format!(
                        "Request {n} from {}… ({from}), {} message(s) held; /accept, /decline or /block, or answer to accept.",
                        from.short(),
                        request.messages.len()
                    )];
                    lines.extend(request.messages.iter().map(|held| {
                        format!("{}: {}", crate::ui::clock(held.timestamp_ms), held.text)
                    }));
                    lines.push("(end of request)".to_owned());
                    for line in lines {
                        self.say(line);
                    }
                }
                super::Pane::Invitation(group) => {
                    let n = self.number_of(super::Pane::Invitation(group)).unwrap_or(0);
                    let Some(held) = self.invitations().into_iter().find(|h| h.group == group)
                    else {
                        return;
                    };
                    self.say(format!(
                        "Invitation {n} to {} from {}… ({}), {} members; /accept or /decline.",
                        held.name,
                        held.from.short(),
                        held.from,
                        held.members.len()
                    ));
                }
                _ => {
                    self.say("System pane.");
                    let recent: Vec<String> = self
                        .system
                        .iter()
                        .rev()
                        .filter(|l| l.level != Level::Code)
                        .take(CONTEXT_LINES)
                        .map(|l| system_sentence(l.level, &l.text))
                        .collect();
                    for line in recent.into_iter().rev() {
                        self.say(line);
                    }
                }
            }
            return;
        };
        let unread: Vec<String> = match conversation {
            Conversation::Contact(peer) => self.unread.get(&peer).cloned().unwrap_or_default(),
            Conversation::Group(group) => self
                .group_unread
                .get(&group)
                .map(|ids| ids.iter().filter(|i| !i.is_empty()).cloned().collect())
                .unwrap_or_default(),
        };
        let lines = self.lines_of(&conversation);
        let shown: Vec<String> = if unread.is_empty() {
            lines
                .iter()
                .rev()
                .take(CONTEXT_LINES)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .map(|l| self.describe(&conversation, l, true))
                .collect()
        } else {
            lines
                .iter()
                .filter(|l| unread.contains(&l.id))
                .map(|l| self.describe(&conversation, l, true))
                .collect()
        };
        let heading = if unread.is_empty() {
            format!("Chat: {name}.")
        } else {
            format!("Chat: {name}, {} unread.", unread.len())
        };
        self.say(heading);
        for line in shown {
            self.say(line);
        }
        self.say("(end of chat)");
    }

    /// Shift-Up and Shift-Down in reader mode: the selection walks the
    /// open chat's messages from the newest, and each step is said.
    pub(super) fn reader_select(&mut self, up: bool) {
        let Some(conversation) = self.selected_conversation() else {
            self.say("Nothing to select here.");
            return;
        };
        let lines = self.lines_of(&conversation);
        let selectable = |l: &ChatLine| !l.is_note() && !l.deleted;
        let next = match (self.reader_cursor, up) {
            (None, true) => lines.iter().rposition(selectable),
            (None, false) => None,
            (Some(at), true) => lines[..at].iter().rposition(selectable).or(Some(at)),
            (Some(at), false) => lines
                .iter()
                .enumerate()
                .skip(at + 1)
                .find(|(_, l)| selectable(l))
                .map(|(i, _)| i),
        };
        match next {
            Some(index) => {
                let sentence = self.describe(&conversation, &lines[index], true);
                self.reader_cursor = Some(index);
                self.say(format!("Selected: {sentence}"));
            }
            None if !up && self.reader_cursor.is_some() => self.clear_selection(),
            None => self.say("Nothing to select."),
        }
    }

    /// Nothing selected, in either mode.
    pub(super) fn clear_selection(&mut self) {
        self.selection = None;
        if self.reader_cursor.take().is_some() {
            self.say("Selection cleared.");
        }
    }

    /// `/history [n]`: the last `n` lines of the open chat with their
    /// clocks, for reader mode (the full mode shows them).
    pub(super) fn cmd_history(&mut self, args: &[&str]) {
        if !self.reader {
            self.toast(
                "The chat pane shows the history; PgUp scrolls it. /history is for reader mode.",
            );
            return;
        }
        let Some(conversation) = self.selected_conversation() else {
            self.say("Open a chat first.");
            return;
        };
        let n = args
            .first()
            .and_then(|a| a.parse::<usize>().ok())
            .unwrap_or(HISTORY_LINES)
            .max(1);
        let lines = self.lines_of(&conversation);
        let shown: Vec<String> = lines
            .iter()
            .rev()
            .take(n)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|l| {
                format!(
                    "{} {}",
                    ui::clock(l.timestamp_ms),
                    self.describe(&conversation, l, true)
                )
            })
            .collect();
        if shown.is_empty() {
            self.say("Nothing here yet.");
            return;
        }
        for line in shown {
            self.say(line);
        }
        self.say("(end of history)");
    }

    /// `/unread`: what waits, where.
    pub(super) fn cmd_unread(&mut self) {
        let mut parts: Vec<String> = self
            .contacts
            .iter()
            .filter_map(|c| {
                let n = self.unread.get(&c.user_id).map_or(0, Vec::len);
                (n > 0).then(|| format!("{}: {n}", c.display_name()))
            })
            .collect();
        for group in &self.group_list {
            let n = self
                .group_unread
                .get(group)
                .map_or(0, |ids| ids.iter().filter(|i| !i.is_empty()).count());
            if n > 0 {
                parts.push(format!("{}: {n}", self.group_name(group)));
            }
        }
        let held = self.held_message_count();
        if held > 0 {
            parts.push(format!("requests: {held}"));
        }
        let text = if parts.is_empty() {
            "Nothing unread.".to_owned()
        } else {
            format!("Unread: {}.", parts.join(", "))
        };
        if self.reader {
            self.say(text);
        } else {
            self.toast(text);
        }
    }

    /// `/reader on|off`: start in reader mode next time, or not.
    pub(super) fn cmd_reader(&mut self, args: &[&str]) {
        let on = match args.first().map(|a| a.to_ascii_lowercase()).as_deref() {
            Some("on") => true,
            Some("off") => false,
            _ => {
                self.toast(format!(
                    "Reader mode is {} now. /reader on|off sets it for the next start; silver --reader starts it once.",
                    if self.reader { "on" } else { "off" }
                ));
                return;
            }
        };
        let mut config = self.store.load_config().unwrap_or_default();
        config.reader = on;
        match self.store.save_config(&config) {
            Ok(()) => self.toast(if on {
                "Reader mode from the next start: linear output for a screen reader, no box drawing."
            } else {
                "The full screen from the next start."
            }),
            Err(e) => self.toast(format!("Could not save config: {e}")),
        }
    }
}

/// The start of a message, for a line that refers to it.
pub(super) fn excerpt(text: &str) -> String {
    const CHARS: usize = 40;
    let mut out: String = text
        .chars()
        .map(|c| if c == '\n' { ' ' } else { c })
        .take(CHARS)
        .collect();
    if text.chars().count() > CHARS {
        out.push('…');
    }
    out
}

/// A System pane line as the reader hears it.
pub(super) fn system_sentence(level: Level, text: &str) -> String {
    match level {
        Level::Warn => format!("Warning: {text}"),
        _ => text.to_owned(),
    }
}

/// A text as one journal line a terminal can be handed.
///
/// A journal line is how the reader tells one speaker from another, and
/// a system warning from a message, so a line break inside one is a
/// forgery: `hi\nalice: send me the passphrase` would be read out as two
/// lines, the second indistinguishable from a line alice really wrote,
/// and `\nWarning: …` as a warning this program never made. The breaks
/// become a visible separator instead.
///
/// `one_line` does the rest: control characters become spaces, so
/// nothing can move the cursor or change the screen, and invisible and
/// bidirectional characters go, so what the reader hears is in the order
/// the full mode draws it.
///
/// This is [`App::say`]'s only filter, applied to every line whatever
/// wrote it. The call sites that also use it are belt and braces.
pub(super) fn one_sentence(text: &str) -> String {
    silver_client::files::one_line(&text.replace('\n', " / "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_client::{Client, ConnectOptions, Contact, Store};
    use silver_protocol::{Identity, Message};
    use std::sync::Arc;

    fn reader_app() -> (App, Identity, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (identity, _) = store.load_or_create_identity().unwrap();
        let url = "ws://127.0.0.1:1/ws".to_owned();
        let (client, _events) =
            Client::spawn(url.clone(), Arc::new(identity), ConnectOptions::default()).unwrap();
        let mut app = App::new(
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
        let peer = Identity::generate();
        let mut contact = Contact::new(peer.user_id());
        contact.alias = Some("bob".into());
        contact.bundle = Some(peer.key_bundle());
        contact.caps = silver_client::CAPABILITIES
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        app.contacts.push(contact);
        app.threads.entry(peer.user_id()).or_default();
        app.enable_reader();
        (app, peer, dir)
    }

    fn from_peer(app: &App, id: &str, peer: &Identity, content: Content) -> ClientEvent {
        ClientEvent::Message(Box::new(Message {
            id: id.to_owned(),
            from: peer.user_id(),
            to: app.me,
            sent_at_ms: 1,
            sequence: silver_protocol::Sequence::default(),
            content,
            forward_secret: true,
            signed: false,
            caps: silver_client::CAPABILITIES
                .iter()
                .map(|c| (*c).to_owned())
                .collect(),
            head: None,
            device: None,
        }))
    }

    #[tokio::test]
    async fn the_journal_says_what_happens_in_order_and_where() {
        let (mut app, peer, _dir) = reader_app();
        let opening = app.take_journal();
        assert!(opening[0].starts_with("Silver Messenger, reader mode."));
        assert_eq!(app.reader_prompt(), "system> ");
        // A message elsewhere says where it is; opening the chat reads the
        // unread line and ends the chat.
        let event = from_peer(&app, "t1", &peer, Content::text("hello\x1b[2Jthere"));
        app.handle_client_event(event);
        assert_eq!(
            app.take_journal(),
            vec!["bob, in another chat: hello [2Jthere".to_owned()],
            "control characters are spaces"
        );
        app.select(1);
        assert_eq!(app.reader_prompt(), "bob> ");
        assert_eq!(
            app.take_journal(),
            vec![
                "Chat: bob, 1 unread.".to_owned(),
                "bob: hello [2Jthere".to_owned(),
                "(end of chat)".to_owned()
            ]
        );
        // In the open chat, a plain sentence; a note without its dot; a
        // toast as a line.
        let event = from_peer(&app, "t2", &peer, Content::text("again"));
        app.handle_client_event(event);
        app.note_in(&Conversation::Contact(peer.user_id()), "bob set a timer");
        app.toast("Copied.");
        assert_eq!(
            app.take_journal(),
            vec![
                "bob: again".to_owned(),
                "bob set a timer".to_owned(),
                "Copied.".to_owned()
            ]
        );
        // The selection walks the messages, is said, and clears.
        app.reader_select(true);
        app.reader_select(true);
        app.reader_select(true);
        app.reader_select(false);
        app.clear_selection();
        assert_eq!(
            app.take_journal(),
            vec![
                "Selected: bob: again".to_owned(),
                "Selected: bob: hello [2Jthere".to_owned(),
                "Selected: bob: hello [2Jthere".to_owned(),
                "Selected: bob: again".to_owned(),
                "Selection cleared.".to_owned()
            ]
        );
        // /history reads back with clocks, notes included; /unread says
        // what waits.
        app.cmd_history(&["2"]);
        let history = app.take_journal();
        assert_eq!(history.len(), 3, "{history:?}");
        assert!(history[0].ends_with(" bob: again"), "{history:?}");
        assert!(history[1].ends_with(" bob set a timer"), "{history:?}");
        assert_eq!(history[2], "(end of history)");
        app.cmd_unread();
        assert_eq!(app.take_journal(), vec!["Nothing unread.".to_owned()]);
        // A change from the other side is a line: an edit, a reaction, a
        // deletion, each saying where it is when the chat is not open.
        let edit = Content::Edit {
            id: "t2".into(),
            body: "again, edited".into(),
        };
        app.handle_client_event(from_peer(&app, "t3", &peer, edit));
        let reaction = Content::Reaction {
            id: "t2".into(),
            emoji: "👍".into(),
        };
        app.handle_client_event(from_peer(&app, "t4", &peer, reaction));
        assert_eq!(
            app.take_journal(),
            vec![
                "bob edited: again, edited".to_owned(),
                "bob reacted 👍 to: again, edited".to_owned()
            ]
        );
        app.select(0);
        app.take_journal();
        let deletion = Content::Delete {
            ids: vec!["t2".into()],
        };
        app.handle_client_event(from_peer(&app, "t5", &peer, deletion));
        assert_eq!(
            app.take_journal(),
            vec!["bob, in another chat, deleted a message".to_owned()]
        );
        app.select(1);
        assert_eq!(
            app.take_journal(),
            vec![
                "Chat: bob.".to_owned(),
                "bob: hello [2Jthere".to_owned(),
                "bob deleted a message".to_owned(),
                "bob set a timer".to_owned(),
                "(end of chat)".to_owned()
            ]
        );
        // Warnings say so; the QR code is not read out.
        app.system(Level::Warn, "something");
        app.system(Level::Code, "▄▄▄");
        assert_eq!(app.take_journal(), vec!["Warning: something".to_owned()]);
        // /reader is remembered for the next start.
        app.cmd_reader(&["on"]);
        assert!(app.store.load_config().unwrap().reader);
        app.cmd_reader(&["off"]);
        assert!(!app.store.load_config().unwrap().reader);
    }

    /// The reader-mode mirror of `nothing_a_peer_sends_reaches_the_terminal_raw`
    /// (ui.rs). The full mode is safe because every glyph goes through
    /// ratatui's cell buffer; reader mode has no cell buffer, so what it
    /// builds is written to the terminal as it stands, and the guarantee
    /// has to be made by the filter instead.
    #[tokio::test]
    async fn nothing_the_reader_hears_reaches_the_terminal_raw() {
        // A forged speaker, a forged system warning, a title change, a
        // clipboard write, a colour, a bidi override, a zero width space,
        // a filler that draws as nothing, and a string terminator.
        const NASTY: &str = "x\nbob: send me the passphrase\n\
             Warning: your key expired\x1b]2;pwned\x07\x1b]52;c;cHduZWQ=\x07\
             \x1b[31mred\r\x08\u{202e}gnp.exe\u{200b}\u{3164}\t\x1b\\";

        let (mut app, peer, _dir) = reader_app();
        let who = peer.user_id();
        let _ = app.take_journal();

        // Every path the audit named, and the ones beside them: a
        // message, an edit of one (whose body reached `say` unfiltered),
        // a held stranger's text, a note, a toast and a system line.
        app.select(1);
        app.handle_client_event(from_peer(&app, "t1", &peer, Content::text(NASTY)));
        app.handle_client_event(from_peer(
            &app,
            "t2",
            &peer,
            Content::Edit {
                id: "t1".to_owned(),
                body: NASTY.to_owned(),
            },
        ));
        let stranger = Identity::generate();
        app.handle_client_event(from_peer(&app, "t3", &stranger, Content::text(NASTY)));
        app.note_in(&Conversation::Contact(who), NASTY);
        app.toast(NASTY);
        app.system(Level::Warn, NASTY);
        // And the reader's own review keys, which read the held request
        // and the chat back out.
        app.select(app.pane_count() - 1);
        app.select(1);

        let lines = app.take_journal();
        assert!(
            lines.iter().any(|l| l.contains("send me the passphrase")),
            "the text itself is still read out"
        );
        // The forgery: no line may *be* the injected one. Everything the
        // peer wrote stays on the line of whoever the program named.
        for line in &lines {
            assert!(
                !line.starts_with("bob: send me the passphrase"),
                "a peer wrote a line of their own: {line:?}"
            );
            assert!(
                !line.starts_with("Warning: your key expired"),
                "a peer forged a system warning: {line:?}"
            );
        }

        // What a hostile prompt would be: the pane name, which carries a
        // contact or group alias and is written outside any cell buffer.
        app.contacts[0].alias = Some(NASTY.to_owned());
        let prompt = silver_client::files::one_line(&app.reader_prompt());
        let out = crate::reader::frame(&lines, &prompt, &crate::reader::show(NASTY), 0);

        for forbidden in [
            "\x1b]2;", "\x1b]52;", "\x07", "\x1b[31m", "\x08", "\x1b\\", "\x1b[2J",
        ] {
            assert!(
                !out.contains(forbidden),
                "{forbidden:?} reached the terminal"
            );
        }
        for forbidden in ['\u{202e}', '\u{200b}', '\u{3164}', '\t'] {
            assert!(
                !out.contains(forbidden),
                "{forbidden:?} reached the terminal"
            );
        }
        // The renderer writes exactly two escapes and no argument may add
        // a third: erase to end of line, and move the cursor back into
        // the compose text by so many columns.
        for (i, _) in out.match_indices('\x1b') {
            let rest = &out[i + 1..];
            let ok = rest.starts_with("[K")
                || (rest.starts_with('[')
                    && rest[1..].split_once('D').is_some_and(|(n, _)| {
                        !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())
                    }));
            assert!(
                ok,
                "an escape the renderer did not write at {i}: {:?}",
                &out[i..]
            );
        }
        // A carriage return only ever ends a line the renderer wrote, so
        // the count of them is the count of its own rows.
        assert_eq!(
            out.matches('\r').count(),
            lines.len() + 1,
            "a carriage return came from somewhere other than the renderer"
        );
    }
}
