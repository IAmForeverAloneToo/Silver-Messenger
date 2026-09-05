//! What the client holds in memory, bounded (`docs/design/robustness.md`
//! section 5): the newest lines of each conversation, the newest System
//! lines, and the updates waiting for a message; and `/search`, which
//! reads the files so the bounds hide nothing from it.

use silver_client::{Conversation, Direction};

use super::*;

/// Lines of a conversation kept in memory; the file keeps them all.
pub(super) const HISTORY_WINDOW: usize = 2_000;
/// System pane lines kept.
pub(super) const SYSTEM_WINDOW: usize = 500;
/// Updates waiting for a message not held yet, besides the day each
/// waits at most.
pub(super) const LATE_CAP: usize = 1_000;

impl App {
    /// Keep the newest [`HISTORY_WINDOW`] lines of `conversation`; the
    /// oldest go, and with them a selection, since every row moves, and a
    /// marker that sat above one of them.
    pub(super) fn trim_window(&mut self, conversation: &Conversation) {
        let Some(lines) = self.lines_of_mut(conversation) else {
            return;
        };
        if lines.len() <= HISTORY_WINDOW {
            return;
        }
        let extra = lines.len() - HISTORY_WINDOW;
        lines.drain(..extra);
        self.has_older.insert(*conversation);
        match conversation {
            Conversation::Contact(peer) => {
                if self
                    .new_marker
                    .as_ref()
                    .is_some_and(|(p, id)| p == peer && !self.holds(conversation, id))
                {
                    self.new_marker = None;
                }
            }
            Conversation::Group(group) => {
                if self
                    .group_new_marker
                    .as_ref()
                    .is_some_and(|(g, id)| g == group && !self.holds(conversation, id))
                {
                    self.group_new_marker = None;
                }
            }
        }
        if self.selected_conversation() == Some(*conversation) {
            self.clear_selection();
        }
    }

    fn holds(&self, conversation: &Conversation, id: &str) -> bool {
        self.lines_of(conversation).iter().any(|l| l.id == id)
    }

    /// Whether the file holds lines older than the window in memory.
    pub fn has_older_lines(&self, conversation: &Conversation) -> bool {
        self.has_older.contains(conversation)
    }

    /// The System pane's newest [`SYSTEM_WINDOW`] lines.
    pub(super) fn trim_system(&mut self) {
        if self.system.len() > SYSTEM_WINDOW {
            let extra = self.system.len() - SYSTEM_WINDOW;
            self.system.drain(..extra);
        }
    }

    /// Remember an update for a message not held yet; past [`LATE_CAP`]
    /// the oldest goes.
    pub(super) fn push_late(&mut self, update: everyday::LateUpdate) {
        if self.late.len() >= LATE_CAP {
            self.late.remove(0);
        }
        self.late.push(update);
    }

    /// `/search <text>`: through the files, so what the window dropped is
    /// found too; in the selected chat, or in every chat from System.
    pub(super) fn cmd_search(&mut self, args: &[&str]) {
        let needle = args.join(" ");
        if needle.trim().is_empty() {
            self.toast("Usage: /search <text>");
            return;
        }
        let lower = needle.to_lowercase();
        let (scope, label): (Vec<Conversation>, String) = if let Some(group) = self.selected_group()
        {
            (
                vec![Conversation::Group(group)],
                format!("in {}", self.group_name(&group)),
            )
        } else if let Some(contact) = self.selected_contact() {
            (
                vec![Conversation::Contact(contact.user_id)],
                format!("in the chat with {}", contact.display_name()),
            )
        } else {
            (
                self.contacts
                    .iter()
                    .map(|c| Conversation::Contact(c.user_id))
                    .chain(self.group_list.iter().map(|g| Conversation::Group(*g)))
                    .collect(),
                "in all chats".to_owned(),
            )
        };
        let mut hits: Vec<(u64, String)> = Vec::new();
        for conversation in scope {
            let entries = match self.store.load_conversation(&conversation) {
                Ok(entries) => entries,
                Err(e) => {
                    self.toast(format!("Could not read the history: {e}"));
                    return;
                }
            };
            for entry in entries {
                if entry.deleted || !entry.text.to_lowercase().contains(&lower) {
                    continue;
                }
                let who = match conversation {
                    Conversation::Contact(peer) => match entry.direction {
                        Direction::Sent => format!("you → {}", self.contact_name(&peer)),
                        Direction::Received => self.contact_name(&peer),
                    },
                    Conversation::Group(group) => {
                        let name = self.group_name(&group);
                        if entry.text.starts_with("· ") {
                            name
                        } else if entry.direction == Direction::Sent {
                            format!("you → {name}")
                        } else {
                            format!("{} in {name}", self.name_of(entry.from))
                        }
                    }
                };
                hits.push((
                    entry.timestamp_ms,
                    format!("{} {who}: {}", ui::stamp(entry.timestamp_ms), entry.text),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_client::{Client, ConnectOptions, Contact, HistoryEntry, Store};
    use silver_protocol::{GroupId, Identity};
    use std::sync::Arc;

    /// A store with bob as a contact and `lines` numbered lines from him,
    /// the second of them marked.
    fn store_with_bob(lines: usize) -> (Store, Identity, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.load_or_create_identity().unwrap();
        let peer = Identity::generate();
        let mut contact = Contact::new(peer.user_id());
        contact.alias = Some("bob".into());
        store.save_contacts(&[contact]).unwrap();
        for i in 0..lines {
            let text = if i == 1 {
                "a needle in the old part".to_owned()
            } else {
                format!("line {i}")
            };
            let entry = HistoryEntry::new(format!("m{i}"), Direction::Received, i as u64, text);
            store.append_history(&peer.user_id(), &entry).unwrap();
        }
        (store, peer, dir)
    }

    fn open(store: Store) -> App {
        let (identity, _) = store.load_or_create_identity().unwrap();
        let url = "ws://127.0.0.1:1/ws".to_owned();
        let (client, _events) =
            Client::spawn(url.clone(), Arc::new(identity), ConnectOptions::default()).unwrap();
        App::new(
            store,
            client,
            url,
            false,
            1,
            crate::glyphs::UNICODE,
            crate::theme::Theme::dark(),
            AtRest::Passphrase,
        )
        .unwrap()
    }

    fn received(i: usize) -> ChatLine {
        ChatLine::new(
            format!("r{i}"),
            Direction::Received,
            i as u64,
            format!("line {i}"),
        )
    }

    #[tokio::test]
    async fn loading_keeps_the_newest_window_and_every_id() {
        let (store, peer, _dir) = store_with_bob(HISTORY_WINDOW + 5);
        let app = open(store);
        let conversation = Conversation::Contact(peer.user_id());
        let lines = app.lines_of(&conversation);
        assert_eq!(lines.len(), HISTORY_WINDOW);
        assert_eq!(lines[0].id, "m5", "the oldest five are not in memory");
        assert!(app.has_older_lines(&conversation));
        assert!(
            app.known_ids.contains("m0"),
            "a message older than the window is still known, so it is not shown twice"
        );
    }

    #[tokio::test]
    async fn recording_past_the_window_drops_the_oldest_with_what_sat_on_it() {
        let (store, peer, _dir) = store_with_bob(0);
        let mut app = open(store);
        let conversation = Conversation::Contact(peer.user_id());
        for i in 0..HISTORY_WINDOW {
            app.record(peer.user_id(), received(i));
        }
        assert!(
            !app.has_older_lines(&conversation),
            "the window is not full yet"
        );
        app.enable_reader();
        app.select(1);
        app.reader_select(true);
        app.take_journal();
        app.new_marker = Some((peer.user_id(), "r0".to_owned()));
        app.record(peer.user_id(), received(HISTORY_WINDOW));
        let lines = app.lines_of(&conversation);
        assert_eq!(lines.len(), HISTORY_WINDOW);
        assert_eq!(lines[0].id, "r1", "the oldest went");
        assert!(app.has_older_lines(&conversation));
        assert!(
            app.reader_cursor.is_none(),
            "the selection went with the rows"
        );
        assert!(
            app.take_journal()
                .contains(&"Selection cleared.".to_owned())
        );
        assert!(
            app.new_marker.is_none(),
            "the marker above the dropped line went"
        );
    }

    #[tokio::test]
    async fn the_system_pane_and_the_waiting_updates_are_capped() {
        let (store, peer, _dir) = store_with_bob(0);
        let mut app = open(store);
        for i in 0..SYSTEM_WINDOW + 10 {
            app.system(Level::Info, format!("notice {i}"));
        }
        assert_eq!(app.system.len(), SYSTEM_WINDOW);
        assert_eq!(
            app.system.last().unwrap().text,
            format!("notice {}", SYSTEM_WINDOW + 9)
        );
        for i in 0..LATE_CAP + 1 {
            app.push_late(everyday::LateUpdate {
                conversation: Conversation::Contact(peer.user_id()),
                id: format!("late {i}"),
                from: Some(peer.user_id()),
                kind: everyday::Late::Deleted,
                at_ms: 0,
            });
        }
        assert_eq!(app.late.len(), LATE_CAP);
        assert_eq!(app.late[0].id, "late 1", "the oldest went");
    }

    #[tokio::test]
    async fn search_reads_the_file_past_the_window_and_the_groups() {
        let (store, peer, _dir) = store_with_bob(HISTORY_WINDOW + 5);
        let group = GroupId::generate();
        store
            .append_group_history(
                &group,
                &HistoryEntry {
                    from: Some(peer.user_id()),
                    ..HistoryEntry::new("g1", Direction::Received, 9, "a needle in the team")
                },
            )
            .unwrap();
        let mut app = open(store);
        app.group_list.push(group);
        app.cmd_search(&["needle"]);
        let found: Vec<&str> = app
            .system
            .iter()
            .filter(|l| l.text.contains("needle"))
            .map(|l| l.text.as_str())
            .collect();
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found[0].contains("2 match(es)"), "{found:?}");
        assert!(
            found[1].contains("bob: a needle in the old part"),
            "{found:?}"
        );
        assert!(
            found[2].contains("bob in ") && found[2].ends_with(": a needle in the team"),
            "{found:?}"
        );
    }
}
