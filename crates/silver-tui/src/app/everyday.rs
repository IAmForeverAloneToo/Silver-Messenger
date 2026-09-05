//! The everyday features in the terminal client (`docs/design/everyday.md`,
//! `docs/PROTOCOL.md` section 4.7): the commands that act on a message
//! (`/reply`, `/react`, `/edit`, `/delete`), a conversation's timer
//! (`/timer`), what an edit, a deletion, a reaction or a timer from the
//! other side does to the screen and the history, and the sweeper that
//! removes what has run out.

use silver_client::everyday::{self, TOMBSTONE_MS};
use silver_client::{Conversation, Deletion, GroupError, Reaction};
use silver_protocol::device::Sync;

use super::*;

/// An update for a message not held yet (a crossed group fan-out, a
/// message still in the mailbox), kept for a day to apply on arrival.
pub(super) struct LateUpdate {
    conversation: Conversation,
    id: String,
    from: Option<UserId>,
    kind: Late,
    at_ms: u64,
}

enum Late {
    Edit(String),
    Reaction(String),
    /// Its author deleted it for everyone before it came: it shows nothing.
    Deleted,
}

/// Which message a command acts on when none is selected.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    /// The last one of one's own.
    Own,
    /// The last one received.
    Received,
    /// The last one, whoever wrote it.
    Any,
}

/// The note a timer leaves in the conversation.
pub(super) fn timer_note(who: &str, seconds: u64) -> String {
    if seconds == 0 {
        format!("{who} turned disappearing messages off")
    } else {
        format!(
            "{who} set messages to disappear after {}",
            everyday::describe_timer(seconds)
        )
    }
}

impl App {
    // --- conversations -------------------------------------------------------

    /// The conversation whose pane is open, if one is.
    pub(super) fn selected_conversation(&self) -> Option<Conversation> {
        if let Some(group) = self.selected_group() {
            return Some(Conversation::Group(group));
        }
        self.selected_contact()
            .map(|c| Conversation::Contact(c.user_id))
    }

    pub(super) fn lines_of(&self, conversation: &Conversation) -> &[ChatLine] {
        match conversation {
            Conversation::Contact(peer) => self.threads.get(peer).map_or(&[], Vec::as_slice),
            Conversation::Group(group) => self.group_threads.get(group).map_or(&[], Vec::as_slice),
        }
    }

    fn lines_of_mut(&mut self, conversation: &Conversation) -> Option<&mut Vec<ChatLine>> {
        match conversation {
            Conversation::Contact(peer) => self.threads.get_mut(peer),
            Conversation::Group(group) => self.group_threads.get_mut(group),
        }
    }

    fn line_in_mut(&mut self, conversation: &Conversation, id: &str) -> Option<&mut ChatLine> {
        self.lines_of_mut(conversation)
            .and_then(|lines| lines.iter_mut().rev().find(|l| l.id == id))
    }

    /// The conversation's disappearing-message timer, in seconds; 0 for
    /// none.
    pub(super) fn timer_of(&self, conversation: &Conversation) -> u64 {
        match conversation {
            Conversation::Contact(peer) => self
                .contact_index(peer)
                .map_or(0, |i| self.contacts[i].expire_after_s),
            Conversation::Group(group) => self.groups.get(group).map_or(0, |r| r.expire_after_s),
        }
    }

    /// `line` with the conversation's timer on it, as a message sent or
    /// received now is recorded: a later change of the timer leaves it
    /// alone.
    pub(super) fn timed(&self, conversation: &Conversation, mut line: ChatLine) -> ChatLine {
        line.expire_after_s = self.timer_of(conversation);
        line
    }

    /// Who wrote `line`: `None` for oneself.
    pub(super) fn author_of(&self, conversation: &Conversation, line: &ChatLine) -> Option<UserId> {
        match conversation {
            Conversation::Contact(peer) => match line.direction {
                Direction::Received => Some(*peer),
                Direction::Sent => None,
            },
            Conversation::Group(_) => line.sender,
        }
    }

    /// "you", or the contact's or member's name.
    pub(super) fn name_of(&self, who: Option<UserId>) -> String {
        match who {
            None => "you".to_owned(),
            Some(user) => self.member_name(&user),
        }
    }

    /// A note about the conversation, in it, in the dim style.
    pub(super) fn note_in(&mut self, conversation: &Conversation, text: &str) {
        match conversation {
            Conversation::Group(group) => self.note_in_group(*group, text),
            Conversation::Contact(peer) => {
                let line = ChatLine {
                    delivered: true,
                    ..ChatLine::new(
                        uuid::Uuid::new_v4().to_string(),
                        Direction::Received,
                        now_ms(),
                        format!("· {text}"),
                    )
                };
                self.record(*peer, line);
            }
        }
    }

    // --- what a command acts on ------------------------------------------------

    /// The one message every row of the selection belongs to, when the
    /// selection covers exactly one (Shift-Up, a triple click, a drag
    /// within it).
    pub(super) fn selected_source(&self) -> Option<usize> {
        let selection = self.selection?;
        if !matches!(self.view.pane, Pane::Thread(_) | Pane::Group(_)) {
            return None;
        }
        let ((first, _), (last, _)) = selection.bounds();
        let last = last.min(self.view.rows.len().checked_sub(1)?);
        let mut source = None;
        for row in self.view.rows.get(first..=last)? {
            match (row.source, source) {
                (None, _) => {}
                (Some(s), None) => source = Some(s),
                (Some(s), Some(t)) if s == t => {}
                _ => return None,
            }
        }
        source
    }

    /// The message a command acts on: the selected one when exactly one
    /// is selected, otherwise the last one it makes sense for.
    fn target_line(&self, conversation: &Conversation, want: Want) -> Result<usize, String> {
        let lines = self.lines_of(conversation);
        if self.selection.is_some() {
            let Some(index) = self.selected_source() else {
                return Err("Select one message (Shift-Up selects the newest).".to_owned());
            };
            let line = lines
                .get(index)
                .ok_or("The selection is stale; select the message again.")?;
            if line.is_note() {
                return Err("That is a note about the chat, not a message.".to_owned());
            }
            if line.deleted {
                return Err("That message was deleted.".to_owned());
            }
            if want == Want::Own && self.author_of(conversation, line).is_some() {
                return Err(
                    "Select one of your own messages, or none to take your last one.".to_owned(),
                );
            }
            return Ok(index);
        }
        lines
            .iter()
            .rposition(|line| {
                !line.is_note()
                    && !line.deleted
                    && match want {
                        Want::Own => self.author_of(conversation, line).is_none(),
                        Want::Received => self.author_of(conversation, line).is_some(),
                        Want::Any => true,
                    }
            })
            .ok_or_else(|| {
                match want {
                    Want::Own => "You have not sent anything here yet.",
                    Want::Received => "Nothing has been received here yet.",
                    Want::Any => "Nothing here yet.",
                }
                .to_owned()
            })
    }

    // --- commands ------------------------------------------------------------

    /// `/timer [<how long>|off]`: show or set how long after sending (for
    /// you) or reading (for them) messages in this conversation go.
    pub(super) fn cmd_timer(&mut self, args: &[&str]) {
        let Some(conversation) = self.selected_conversation() else {
            self.toast("Open a chat first.");
            return;
        };
        let current = self.timer_of(&conversation);
        if args.is_empty() {
            let mut text = match current {
                0 => {
                    "Messages here do not disappear; /timer 1d, for example, makes them.".to_owned()
                }
                s => format!(
                    "Messages here disappear {} after you send them or they read them.",
                    everyday::describe_timer(s)
                ),
            };
            if let Conversation::Contact(peer) = conversation
                && current > 0
                && !self.contact_supports(&peer, capability::TIMERS)
            {
                text.push_str(" On this side only: their client is older and keeps everything.");
            }
            self.toast(text);
            return;
        }
        let seconds = match everyday::parse_timer(&args.join(" ")) {
            Ok(seconds) => seconds,
            Err(e) => {
                self.toast(e.to_string());
                return;
            }
        };
        match conversation {
            Conversation::Contact(peer) => {
                let name = self.contact_name(&peer);
                let one_sided = !self.contact_supports(&peer, capability::TIMERS);
                if !one_sided {
                    self.send_content_to(peer, Content::Timer { seconds });
                }
                if let Some(i) = self.contact_index(&peer) {
                    self.contacts[i].expire_after_s = seconds;
                    self.persist_contacts();
                }
                let mut note = timer_note("you", seconds);
                if one_sided && seconds > 0 {
                    note.push_str(&format!(
                        " on this side only; {name}'s client is older and keeps everything"
                    ));
                }
                self.note_in(&conversation, &note);
                self.toast(if seconds == 0 {
                    "Messages here stay.".to_owned()
                } else if one_sided {
                    format!("Set here only: {name}'s client is older and would not read the timer.")
                } else {
                    format!(
                        "Messages here disappear {} after being sent or read.",
                        everyday::describe_timer(seconds)
                    )
                });
            }
            Conversation::Group(group) => {
                let head = self.client.gossip_head();
                match self
                    .groups
                    .send(&group, Content::Timer { seconds }, head, now_ms())
                {
                    Ok(outgoing) => {
                        let id = outgoing.id.clone();
                        self.fan_out(group, outgoing, id, None, None);
                        self.note_in_group(group, &timer_note("you", seconds));
                        self.toast(if seconds == 0 {
                            "Messages here stay.".to_owned()
                        } else {
                            format!(
                                "Messages here disappear {} after being sent or read.",
                                everyday::describe_timer(seconds)
                            )
                        });
                    }
                    Err(GroupError::NotAdmin) => self.toast("Only an admin sets a group's timer."),
                    Err(e) => self.toast(format!("Not set: {e}")),
                }
            }
        }
    }

    /// `/delete`: the selected own message (or the last one) goes for
    /// everyone, within a day of sending; `/delete me` removes any message
    /// from this side's devices only.
    pub(super) fn cmd_delete(&mut self, args: &[&str]) {
        let Some(conversation) = self.selected_conversation() else {
            self.toast("Open a chat first.");
            return;
        };
        let for_me = match args {
            [] => false,
            ["me"] => true,
            _ => {
                self.toast("Usage: /delete (for everyone, your own within a day) or /delete me");
                return;
            }
        };
        let want = if for_me { Want::Any } else { Want::Own };
        let index = match self.target_line(&conversation, want) {
            Ok(index) => index,
            Err(e) => {
                self.toast(e);
                return;
            }
        };
        let line = &self.lines_of(&conversation)[index];
        let id = line.id.clone();
        let sent_at_ms = line.timestamp_ms;
        let saved = line.file.clone();
        if for_me {
            if let Err(e) = self
                .store
                .remove_messages(&conversation, std::slice::from_ref(&id))
            {
                self.toast(format!("Could not remove it: {e}"));
                return;
            }
            self.remove_lines(&conversation, std::slice::from_ref(&id));
            let (peer, group) = match conversation {
                Conversation::Contact(peer) => (Some(peer), None),
                Conversation::Group(group) => (None, Some(group)),
            };
            self.sync(Sync::Remove {
                peer,
                group,
                ids: vec![id],
            });
            self.toast(match saved {
                Some(path) => format!(
                    "Removed from your devices; the file you saved stays: {}",
                    path.display()
                ),
                None => "Removed from your devices; the other side keeps its copy.".to_owned(),
            });
            return;
        }
        if !everyday::may_revise(now_ms(), sent_at_ms) {
            self.toast(
                "Too late to delete it for everyone: a day has passed. /delete me removes it here.",
            );
            return;
        }
        match conversation {
            Conversation::Contact(peer) => {
                if !self.contact_supports(&peer, capability::EDITS) {
                    let name = self.contact_name(&peer);
                    self.toast(format!(
                        "Not deleted: {name}'s client is older and cannot remove it. /delete me removes it here."
                    ));
                    return;
                }
                self.send_content_to(
                    peer,
                    Content::Delete {
                        ids: vec![id.clone()],
                    },
                );
            }
            Conversation::Group(group) => {
                let head = self.client.gossip_head();
                let content = Content::Delete {
                    ids: vec![id.clone()],
                };
                match self.groups.send(&group, content, head, now_ms()) {
                    Ok(outgoing) => {
                        let message = outgoing.id.clone();
                        self.fan_out(group, outgoing, message, None, None);
                    }
                    Err(e) => {
                        self.toast(format!("Not deleted: {e}"));
                        return;
                    }
                }
            }
        }
        self.delete_line(&conversation, &id, None);
        self.selection = None;
        self.toast("Deleted for everyone; their clients remove it when it reaches them.");
    }

    /// `/edit <text>`: the selected own message (or the last one) says
    /// `text` from now on, within a day of sending.
    pub(super) fn cmd_edit(&mut self, args: &[&str]) {
        let Some(conversation) = self.selected_conversation() else {
            self.toast("Open a chat first.");
            return;
        };
        let text = args.join(" ");
        if text.trim().is_empty() {
            self.toast("Usage: /edit <the new text>");
            return;
        }
        let index = match self.target_line(&conversation, Want::Own) {
            Ok(index) => index,
            Err(e) => {
                self.toast(e);
                return;
            }
        };
        let line = &self.lines_of(&conversation)[index];
        if line.is_file() {
            self.toast("A file cannot be edited.");
            return;
        }
        if !everyday::may_revise(now_ms(), line.timestamp_ms) {
            self.toast("Too late to edit it: a day has passed.");
            return;
        }
        let id = line.id.clone();
        let content = Content::Edit {
            id: id.clone(),
            body: text.clone(),
        };
        if let Err(e) = content.check() {
            self.toast(format!("Not edited: {e}"));
            return;
        }
        let edit_id = match conversation {
            Conversation::Contact(peer) => {
                if !self.contact_supports(&peer, capability::EDITS) {
                    let name = self.contact_name(&peer);
                    self.toast(format!(
                        "Not edited: {name}'s client is older and would not show the new text."
                    ));
                    return;
                }
                self.send_content_to(peer, content);
                uuid::Uuid::new_v4().to_string()
            }
            Conversation::Group(group) => {
                let head = self.client.gossip_head();
                match self.groups.send(&group, content, head, now_ms()) {
                    Ok(outgoing) => {
                        let message = outgoing.id.clone();
                        self.fan_out(group, outgoing, message.clone(), None, None);
                        message.unwrap_or_default()
                    }
                    Err(e) => {
                        self.toast(format!("Not edited: {e}"));
                        return;
                    }
                }
            }
        };
        self.apply_edit(&conversation, &id, text, &edit_id, now_ms(), None);
        self.selection = None;
        self.toast("Edited.");
    }

    /// `/reply <text>`: a text that answers the selected message (or the
    /// last one received), quoted above it on every reader's screen.
    pub(super) fn cmd_reply(&mut self, args: &[&str]) {
        let Some(conversation) = self.selected_conversation() else {
            self.toast("Open a chat first.");
            return;
        };
        let text = args.join(" ");
        if text.trim().is_empty() {
            self.toast("Usage: /reply <text>");
            return;
        }
        let index = match self.target_line(&conversation, Want::Received) {
            Ok(index) => index,
            Err(e) => {
                self.toast(e);
                return;
            }
        };
        let id = self.lines_of(&conversation)[index].id.clone();
        let content = Content::Text {
            body: text.clone(),
            reply_to: Some(id),
        };
        match conversation {
            Conversation::Contact(peer) => {
                if self
                    .contact_index(&peer)
                    .is_some_and(|i| self.contacts[i].revoked)
                {
                    self.toast(format!(
                        "{}'s identity is revoked; not sent.",
                        self.contact_name(&peer)
                    ));
                    return;
                }
                self.new_marker = None;
                self.send_content_to(peer, content);
            }
            Conversation::Group(group) => self.send_group_content(group, content, text),
        }
        self.selection = None;
    }

    /// `/react <emoji|none>`: a reaction to the selected message (or the
    /// last one received), one per person; `none` takes yours back.
    pub(super) fn cmd_react(&mut self, args: &[&str]) {
        let Some(conversation) = self.selected_conversation() else {
            self.toast("Open a chat first.");
            return;
        };
        let emoji = args.join(" ").trim().to_owned();
        let emoji = match emoji.as_str() {
            "" => {
                self.toast("Usage: /react <emoji>, or /react none to take yours back");
                return;
            }
            "none" | "off" | "-" => String::new(),
            _ => emoji,
        };
        let index = match self.target_line(&conversation, Want::Received) {
            Ok(index) => index,
            Err(e) => {
                self.toast(e);
                return;
            }
        };
        let id = self.lines_of(&conversation)[index].id.clone();
        let content = Content::Reaction {
            id: id.clone(),
            emoji: emoji.clone(),
        };
        if let Err(e) = content.check() {
            self.toast(format!("Not sent: {e}"));
            return;
        }
        match conversation {
            Conversation::Contact(peer) => {
                if !self.contact_supports(&peer, capability::REACTIONS) {
                    let name = self.contact_name(&peer);
                    self.toast(format!(
                        "Not sent: {name}'s client is older and would not show a reaction."
                    ));
                    return;
                }
                // Through the receipt queue, with a receipt's wait, so its
                // moment says no more than a receipt's does.
                self.receipts.react(peer, id.clone(), emoji.clone());
            }
            Conversation::Group(group) => {
                let head = self.client.gossip_head();
                match self.groups.send(&group, content, head, now_ms()) {
                    Ok(outgoing) => {
                        let message = outgoing.id.clone();
                        self.fan_out(group, outgoing, message, None, None);
                    }
                    Err(e) => {
                        self.toast(format!("Not sent: {e}"));
                        return;
                    }
                }
            }
        }
        self.apply_reaction(&conversation, &id, None, emoji.clone());
        self.selection = None;
        self.toast(if emoji.is_empty() {
            "Reaction taken back.".to_owned()
        } else {
            format!("Reacted {emoji}.")
        });
    }

    // --- what arrives ---------------------------------------------------------

    /// An edit, a deletion, a reaction or a timer from `from` (`None`: one
    /// of this identity's own devices), `update_id` being the message it
    /// came as and `at_ms` when it was sent.
    pub(super) fn apply_everyday(
        &mut self,
        conversation: Conversation,
        from: Option<UserId>,
        update_id: &str,
        at_ms: u64,
        content: Content,
    ) {
        match content {
            Content::Timer { seconds } => self.apply_timer(&conversation, from, seconds),
            Content::Edit { id, body } => {
                self.apply_edit(&conversation, &id, body, update_id, at_ms, from)
            }
            Content::Delete { ids } => {
                for id in ids {
                    self.delete_line(&conversation, &id, from);
                }
            }
            Content::Reaction { id, emoji } => self.apply_reaction(&conversation, &id, from, emoji),
            _ => {}
        }
    }

    /// A contact's timer, or one of this identity's other devices' word
    /// on a contact's; a group's comes as [`GroupEvent::TimerSet`].
    fn apply_timer(&mut self, conversation: &Conversation, from: Option<UserId>, seconds: u64) {
        let Conversation::Contact(peer) = conversation else {
            return;
        };
        let Some(i) = self.contact_index(peer) else {
            return;
        };
        if self.contacts[i].expire_after_s == seconds {
            return;
        }
        self.contacts[i].expire_after_s = seconds;
        self.persist_contacts();
        let who = self.name_of(from);
        self.note_in(conversation, &timer_note(&who, seconds));
    }

    /// The message `id` says `body` from now on, if `from` wrote it (or
    /// once it arrives, if it has not).
    fn apply_edit(
        &mut self,
        conversation: &Conversation,
        id: &str,
        body: String,
        edit_id: &str,
        at_ms: u64,
        from: Option<UserId>,
    ) {
        let held = self
            .lines_of(conversation)
            .iter()
            .rev()
            .find(|l| l.id == id);
        match held {
            Some(line) => {
                if self.author_of(conversation, line) != from || line.deleted || line.is_file() {
                    return;
                }
                if let Err(e) =
                    self.store
                        .append_edit(conversation, id, &body, edit_id, at_ms, from)
                {
                    self.toast(format!("Could not save the edit: {e}"));
                }
                if let Some(line) = self.line_in_mut(conversation, id) {
                    line.text = body;
                    line.edited = true;
                }
            }
            None => {
                if self.late.iter().any(|l| {
                    l.conversation == *conversation && l.id == id && matches!(l.kind, Late::Deleted)
                }) {
                    return;
                }
                if let Err(e) =
                    self.store
                        .append_edit(conversation, id, &body, edit_id, at_ms, from)
                {
                    self.toast(format!("Could not save the edit: {e}"));
                }
                self.late.push(LateUpdate {
                    conversation: *conversation,
                    id: id.to_owned(),
                    from,
                    kind: Late::Edit(body),
                    at_ms: now_ms(),
                });
            }
        }
    }

    /// `from` deleted the message `id` for everyone: a placeholder, if
    /// `from` wrote it; a tombstone if it has not arrived.
    fn delete_line(&mut self, conversation: &Conversation, id: &str, from: Option<UserId>) {
        match self.store.mark_deleted(conversation, id, from) {
            Ok(Deletion::Applied) => {
                if let Some(line) = self.line_in_mut(conversation, id) {
                    line.text.clear();
                    line.file = None;
                    line.pending = None;
                    line.reply_to = None;
                    line.edited = false;
                    line.reactions.clear();
                    line.deleted = true;
                }
            }
            Ok(Deletion::Tombstoned) => self.late.push(LateUpdate {
                conversation: *conversation,
                id: id.to_owned(),
                from,
                kind: Late::Deleted,
                at_ms: now_ms(),
            }),
            Ok(Deletion::Refused) => {}
            Err(e) => self.toast(format!("Could not save the deletion: {e}")),
        }
    }

    /// `from`'s reaction to the message `id`, replacing their earlier one;
    /// an empty `emoji` takes it back.
    fn apply_reaction(
        &mut self,
        conversation: &Conversation,
        id: &str,
        from: Option<UserId>,
        emoji: String,
    ) {
        if self
            .lines_of(conversation)
            .iter()
            .any(|l| l.id == id && l.deleted)
        {
            return;
        }
        if let Err(e) = self.store.append_reaction(conversation, id, from, &emoji) {
            self.toast(format!("Could not save the reaction: {e}"));
        }
        match self.line_in_mut(conversation, id) {
            Some(line) => {
                line.reactions.retain(|r| r.from != from);
                if !emoji.is_empty() {
                    line.reactions.push(Reaction { from, emoji });
                }
            }
            None => self.late.push(LateUpdate {
                conversation: *conversation,
                id: id.to_owned(),
                from,
                kind: Late::Reaction(emoji),
                at_ms: now_ms(),
            }),
        }
    }

    /// Whether a message arriving now from `author` was deleted for
    /// everyone by them before it came: it shows nothing.
    pub(super) fn arrived_deleted(
        &self,
        conversation: &Conversation,
        id: &str,
        author: Option<UserId>,
    ) -> bool {
        self.late.iter().any(|l| {
            l.conversation == *conversation
                && l.id == id
                && l.from == author
                && matches!(l.kind, Late::Deleted)
        })
    }

    /// Apply to the line `id`, just recorded, what arrived for it before
    /// it did. The history has those lines already; this is the screen.
    pub(super) fn apply_late(&mut self, conversation: &Conversation, id: &str) {
        let (mine, rest): (Vec<LateUpdate>, Vec<LateUpdate>) = std::mem::take(&mut self.late)
            .into_iter()
            .partition(|l| l.conversation == *conversation && l.id == id);
        self.late = rest;
        for update in mine {
            let author = self
                .lines_of(conversation)
                .iter()
                .rev()
                .find(|l| l.id == id)
                .map(|l| self.author_of(conversation, l));
            let Some(line) = self.line_in_mut(conversation, id) else {
                return;
            };
            match update.kind {
                Late::Edit(body) => {
                    if author == Some(update.from) && !line.is_file() {
                        line.text = body;
                        line.edited = true;
                    }
                }
                Late::Reaction(emoji) => {
                    line.reactions.retain(|r| r.from != update.from);
                    if !emoji.is_empty() {
                        line.reactions.push(Reaction {
                            from: update.from,
                            emoji,
                        });
                    }
                }
                Late::Deleted => {}
            }
        }
    }

    /// Forget what waited a day for a message that never came.
    pub(super) fn prune_late(&mut self) {
        let now = now_ms();
        self.late
            .retain(|l| now.saturating_sub(l.at_ms) < TOMBSTONE_MS);
    }

    // --- timers ---------------------------------------------------------------

    /// The messages `ids` were shown at `at_ms`: for a received one with
    /// a timer, that is when its clock starts, and the history is told so
    /// a restart does not restart it.
    pub(super) fn note_read(&mut self, conversation: &Conversation, ids: &[String], at_ms: u64) {
        let mut noted = Vec::new();
        if let Some(lines) = self.lines_of_mut(conversation) {
            for line in lines.iter_mut().filter(|l| ids.contains(&l.id)) {
                if line.direction == Direction::Received
                    && line.expire_after_s > 0
                    && line.read_at_ms.is_none()
                {
                    line.read_at_ms = Some(at_ms);
                    noted.push(line.id.clone());
                }
            }
        }
        if noted.is_empty() {
            return;
        }
        if let Err(e) = self.store.append_read(conversation, &noted, at_ms) {
            self.toast(format!("Could not save when a message was read: {e}"));
        }
        self.expiry_dirty = true;
    }

    /// Take the messages `ids` off the screen (and out of the unread
    /// counts); the history was rewritten by the caller.
    pub(super) fn remove_lines(&mut self, conversation: &Conversation, ids: &[String]) {
        if let Some(lines) = self.lines_of_mut(conversation) {
            lines.retain(|l| !ids.contains(&l.id));
        }
        match conversation {
            Conversation::Contact(peer) => {
                if let Some(unread) = self.unread.get_mut(peer) {
                    unread.retain(|i| !ids.contains(i));
                }
            }
            Conversation::Group(group) => {
                if let Some(unread) = self.group_unread.get_mut(group) {
                    unread.retain(|i| !ids.contains(i));
                }
            }
        }
        if self.selected_conversation() == Some(*conversation) {
            self.selection = None;
        }
        self.expiry_dirty = true;
    }

    /// Remove what has run out, when something has: the earliest expiry
    /// among the lines on screen is kept, so nothing is read from disk
    /// until it is due.
    pub(super) fn sweep_if_due(&mut self) {
        let now = now_ms();
        if self.expiry_dirty {
            self.next_expiry = self
                .threads
                .values()
                .chain(self.group_threads.values())
                .flatten()
                .filter_map(ChatLine::expires_at_ms)
                .min();
            self.expiry_dirty = false;
        }
        if !self.next_expiry.is_some_and(|at| at <= now) {
            return;
        }
        self.expiry_dirty = true;
        match everyday::sweep_expired(&self.store, now) {
            Ok(swept) => {
                for swept in swept {
                    let ids: Vec<String> = swept.entries.iter().map(|e| e.id.clone()).collect();
                    let saved = swept
                        .entries
                        .iter()
                        .filter(|e| saved_file_path(&e.text).is_some())
                        .count();
                    self.remove_lines(&swept.conversation, &ids);
                    if saved > 0 {
                        self.note_in(
                            &swept.conversation,
                            &format!(
                                "{saved} file(s) you saved from messages that disappeared stay in downloads"
                            ),
                        );
                    }
                }
            }
            Err(e) => self.system(
                Level::Warn,
                format!("Could not remove messages whose time ran out: {e}"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_client::{Client, ConnectOptions, Contact, Store};
    use silver_protocol::{Identity, Message};
    use std::sync::Arc;

    /// An app over a fresh store, with a client that never reaches a relay,
    /// and one contact whose client reads everything this one sends.
    fn app_with_contact() -> (App, Identity, tempfile::TempDir) {
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

    fn edit(id: &str, body: &str) -> Content {
        Content::Edit {
            id: id.to_owned(),
            body: body.to_owned(),
        }
    }

    #[tokio::test]
    async fn a_contacts_edits_deletions_and_reactions_apply_by_the_rules() {
        let (mut app, peer, _dir) = app_with_contact();
        let bob = peer.user_id();
        // A text, then an edit of it and a reaction to it.
        let event = from_peer(&app, "t1", &peer, Content::text("helo"));
        app.handle_client_event(event);
        let event = from_peer(&app, "e1", &peer, edit("t1", "hello"));
        app.handle_client_event(event);
        assert_eq!(app.threads[&bob][0].text, "hello");
        assert!(app.threads[&bob][0].edited);
        let event = from_peer(
            &app,
            "r1",
            &peer,
            Content::Reaction {
                id: "t1".into(),
                emoji: "👍".into(),
            },
        );
        app.handle_client_event(event);
        assert_eq!(
            app.threads[&bob][0].reactions,
            vec![Reaction {
                from: Some(bob),
                emoji: "👍".into()
            }]
        );
        // Their edit or deletion of one of ours counts for nothing.
        let mine = ChatLine {
            delivered: true,
            ..ChatLine::new("s1", Direction::Sent, 1, "mine")
        };
        app.record(bob, mine);
        let event = from_peer(&app, "e2", &peer, edit("s1", "theirs?"));
        app.handle_client_event(event);
        let event = from_peer(
            &app,
            "d1",
            &peer,
            Content::Delete {
                ids: vec!["s1".into()],
            },
        );
        app.handle_client_event(event);
        assert_eq!(app.threads[&bob][1].text, "mine");
        assert!(!app.threads[&bob][1].edited && !app.threads[&bob][1].deleted);
        // Their deletion of their own: a placeholder, its reactions gone.
        let event = from_peer(
            &app,
            "d2",
            &peer,
            Content::Delete {
                ids: vec!["t1".into()],
            },
        );
        app.handle_client_event(event);
        let line = &app.threads[&bob][0];
        assert!(line.deleted && line.text.is_empty() && line.reactions.is_empty());
        // An edit and a deletion for messages that have not arrived yet
        // wait for them: the edited one shows edited, the deleted one not
        // at all.
        let event = from_peer(&app, "e3", &peer, edit("t9", "fixed"));
        app.handle_client_event(event);
        let event = from_peer(
            &app,
            "d3",
            &peer,
            Content::Delete {
                ids: vec!["t8".into()],
            },
        );
        app.handle_client_event(event);
        let event = from_peer(&app, "t9", &peer, Content::text("draft"));
        app.handle_client_event(event);
        let event = from_peer(&app, "t8", &peer, Content::text("never seen"));
        app.handle_client_event(event);
        let lines = &app.threads[&bob];
        assert_eq!(
            lines.len(),
            3,
            "{:?}",
            lines.iter().map(|l| &l.id).collect::<Vec<_>>()
        );
        assert_eq!(lines[2].id, "t9");
        assert_eq!(lines[2].text, "fixed");
        assert!(lines[2].edited);
        // The history says the same.
        let history = app.store.load_history(&bob).unwrap();
        assert_eq!(history.len(), 3);
        assert!(history[0].deleted);
        assert_eq!(history[1].text, "mine");
        assert_eq!(history[2].text, "fixed");
        assert_eq!(history[2].previous, vec!["draft"]);
        // A timer from them leaves a note and sticks to what comes after.
        let event = from_peer(&app, "k1", &peer, Content::Timer { seconds: 3600 });
        app.handle_client_event(event);
        assert_eq!(app.contacts[0].expire_after_s, 3600);
        assert!(
            app.threads[&bob]
                .last()
                .unwrap()
                .text
                .contains("bob set messages to disappear after 1 hour")
        );
        let event = from_peer(&app, "t10", &peer, Content::text("timed"));
        app.handle_client_event(event);
        assert_eq!(app.threads[&bob].last().unwrap().expire_after_s, 3600);
        assert_eq!(
            app.store
                .load_history(&bob)
                .unwrap()
                .last()
                .unwrap()
                .expire_after_s,
            3600
        );
    }

    #[tokio::test]
    async fn own_edits_reactions_and_deletions_apply_here_at_once() {
        let (mut app, peer, _dir) = app_with_contact();
        let bob = peer.user_id();
        app.select(1);
        let now = now_ms();
        let sent = ChatLine {
            delivered: true,
            ..ChatLine::new("s1", Direction::Sent, now, "first draft")
        };
        app.record(bob, sent);
        let event = from_peer(&app, "r1", &peer, Content::text("from bob"));
        app.handle_client_event(event);

        app.cmd_edit(&["second", "draft"]);
        assert_eq!(app.threads[&bob][0].text, "second draft");
        assert!(app.threads[&bob][0].edited);
        app.cmd_react(&["👍"]);
        assert_eq!(
            app.threads[&bob][1].reactions,
            vec![Reaction {
                from: None,
                emoji: "👍".into()
            }]
        );
        app.cmd_react(&["none"]);
        assert!(app.threads[&bob][1].reactions.is_empty());
        app.cmd_delete(&[]);
        assert!(app.threads[&bob][0].deleted);
        app.cmd_delete(&["me"]);
        let ids: Vec<&str> = app.threads[&bob].iter().map(|l| l.id.as_str()).collect();
        assert_eq!(ids, ["s1"], "the last message, theirs, went from here");
        let history = app.store.load_history(&bob).unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].deleted);
        // Too old to revise, and a client that would not read it.
        let old = ChatLine {
            delivered: true,
            ..ChatLine::new(
                "s2",
                Direction::Sent,
                now - 2 * everyday::REVISION_WINDOW_MS,
                "old",
            )
        };
        app.record(bob, old);
        app.cmd_edit(&["too", "late"]);
        assert!(app.toast.as_ref().unwrap().0.contains("a day has passed"));
        assert_eq!(app.threads[&bob][1].text, "old");
        app.contacts[0].caps.clear();
        let recent = ChatLine {
            delivered: true,
            ..ChatLine::new("s3", Direction::Sent, now, "recent")
        };
        app.record(bob, recent);
        app.cmd_edit(&["for", "an", "older", "client"]);
        assert!(app.toast.as_ref().unwrap().0.contains("older"));
        assert_eq!(app.threads[&bob][2].text, "recent");
        app.cmd_timer(&["1h"]);
        assert_eq!(app.contacts[0].expire_after_s, 3600);
        assert!(app.toast.as_ref().unwrap().0.contains("Set here only"));
    }

    #[tokio::test]
    async fn what_ran_out_goes_at_the_next_tick_and_from_the_history() {
        let (mut app, peer, _dir) = app_with_contact();
        let bob = peer.user_id();
        let conversation = Conversation::Contact(bob);
        app.contacts[0].expire_after_s = 1;
        let sent = app.timed(
            &conversation,
            ChatLine {
                delivered: true,
                ..ChatLine::new("s1", Direction::Sent, now_ms() - 5_000, "old")
            },
        );
        app.record(bob, sent);
        let received = app.timed(
            &conversation,
            ChatLine {
                delivered: true,
                ..ChatLine::new("r1", Direction::Received, now_ms() - 5_000, "unread")
            },
        );
        app.record(bob, received);
        app.sweep_if_due();
        let ids: Vec<&str> = app.threads[&bob].iter().map(|l| l.id.as_str()).collect();
        assert_eq!(ids, ["r1"], "sent goes from sending; unread waits");
        assert_eq!(app.store.load_history(&bob).unwrap().len(), 1);
        // Read two seconds ago: due now.
        app.note_read(&conversation, &["r1".into()], now_ms() - 2_000);
        app.sweep_if_due();
        assert!(app.threads[&bob].is_empty());
        assert!(app.store.load_history(&bob).unwrap().is_empty());
    }
}
