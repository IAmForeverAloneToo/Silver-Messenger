//! `silver --export-history`: every conversation to a file of its own,
//! as plain text or as JSON lines, for reading elsewhere or keeping
//! (`docs/design/everyday.md` section 6.5). What was deleted for oneself
//! or ran out is not there; the placeholder of a message its author
//! deleted for everyone is, as it is on screen.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use chrono::{Local, TimeZone};
use serde::Serialize;
use silver_protocol::UserId;

use crate::store::{Conversation, Direction, HistoryEntry, Store};
use crate::{everyday, files};

/// How the export is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// One line per message: time, who, text, `(edited)` after an edited
    /// text and the reactions in brackets; a reply's quote above it.
    Text,
    /// One JSON object per line: every field of the entry as the history
    /// keeps it (the earlier texts of an edited message, the reactions,
    /// the timer), and `who` wrote it.
    Json,
}

impl Format {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "text" | "txt" | "plain" => Some(Self::Text),
            "json" | "jsonl" => Some(Self::Json),
            _ => None,
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::Json => "jsonl",
        }
    }
}

/// One line of the JSON form.
#[derive(Serialize)]
struct Exported<'a> {
    who: &'a str,
    #[serde(flatten)]
    entry: &'a HistoryEntry,
}

/// Write every conversation that has one into `dir`, which must lie
/// outside the data directory: `<contact>.txt` (or `.jsonl`) named by
/// the contact's alias, else id, and `group-<name>.txt` for a group.
/// Nothing is overwritten: a taken name gets ` (2)` as a download does.
/// Messages whose timer ran out go first, so none of them is written.
/// Returns the files written.
pub fn export_history(
    store: &Store,
    dir: &Path,
    format: Format,
    now_ms: u64,
) -> anyhow::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let root = store.root().canonicalize()?;
    let target = dir.canonicalize()?;
    if target.starts_with(&root) {
        bail!(
            "the export must go outside the data directory ({})",
            root.display()
        );
    }
    everyday::sweep_expired(store, now_ms)?;
    let contacts = store.load_contacts()?;
    let group_names = store.load_groups()?.names();
    let name_of = |user: &UserId| -> String {
        contacts
            .iter()
            .find(|c| c.user_id == *user)
            .map(|c| c.display_name())
            .unwrap_or_else(|| user.to_string())
    };
    let mut written = Vec::new();
    for conversation in store.conversations()? {
        let entries = store.load_conversation(&conversation)?;
        if entries.is_empty() {
            continue;
        }
        let stem = match conversation {
            Conversation::Contact(peer) => name_of(&peer),
            Conversation::Group(group) => format!(
                "group-{}",
                group_names
                    .get(&group)
                    .cloned()
                    .unwrap_or_else(|| group.to_string())
            ),
        };
        let who_of = |entry: &HistoryEntry| -> String {
            match (conversation, entry.direction, entry.from) {
                (_, Direction::Sent, _) => "you".to_owned(),
                (Conversation::Contact(peer), Direction::Received, _) => name_of(&peer),
                (Conversation::Group(_), Direction::Received, Some(from)) => name_of(&from),
                // A note about the group.
                (Conversation::Group(_), Direction::Received, None) => String::new(),
            }
        };
        let mut out = String::new();
        for entry in &entries {
            let who = who_of(entry);
            match format {
                Format::Json => {
                    out.push_str(&serde_json::to_string(&Exported { who: &who, entry })?);
                    out.push('\n');
                }
                Format::Text => out.push_str(&text_lines(entry, &who, &entries, &who_of, &name_of)),
            }
        }
        let name = format!("{stem}.{}", format.extension());
        written.push(files::save(dir, &name, out.as_bytes(), None)?);
    }
    Ok(written)
}

/// The text form of one entry, with a newline; two lines for a reply.
fn text_lines(
    entry: &HistoryEntry,
    who: &str,
    entries: &[HistoryEntry],
    who_of: &dyn Fn(&HistoryEntry) -> String,
    name_of: &dyn Fn(&UserId) -> String,
) -> String {
    let stamp = stamp(entry.timestamp_ms);
    let mut out = String::new();
    if let Some(target) = &entry.reply_to {
        let quote = match entries.iter().find(|e| e.id == *target) {
            Some(t) if t.deleted => "a deleted message".to_owned(),
            Some(t) => format!(
                "{}: {}",
                who_of(t),
                t.text.lines().next().unwrap_or_default()
            ),
            None => "a message not here".to_owned(),
        };
        out.push_str(&format!("{stamp}  > {quote}\n"));
    }
    if entry.deleted {
        out.push_str(&format!("{stamp}  {who} deleted a message\n"));
        return out;
    }
    let mut text = entry.text.clone();
    if entry.edited {
        text.push_str(" (edited)");
    }
    if !entry.reactions.is_empty() {
        let reactions: Vec<String> = entry
            .reactions
            .iter()
            .map(|r| {
                let by = match r.from {
                    None => "you".to_owned(),
                    Some(user) => name_of(&user),
                };
                format!("{} {by}", r.emoji)
            })
            .collect();
        text.push_str(&format!(" [{}]", reactions.join(", ")));
    }
    if who.is_empty() {
        out.push_str(&format!("{stamp}  {text}\n"));
    } else {
        out.push_str(&format!("{stamp}  {who}: {text}\n"));
    }
    out
}

/// Local date and time to the minute.
fn stamp(timestamp_ms: u64) -> String {
    Local
        .timestamp_millis_opt(timestamp_ms as i64)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| timestamp_ms.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Contact, Reaction};
    use silver_protocol::{GroupId, Identity};

    #[test]
    fn every_conversation_goes_to_a_file_of_its_own_in_either_form() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("data")).unwrap();
        let bob = Identity::generate().user_id();
        let carol = Identity::generate().user_id();
        let mut contact = Contact::new(bob);
        contact.alias = Some("bob".into());
        store.save_contacts(&[contact]).unwrap();
        let conv = Conversation::Contact(bob);
        store
            .append_history(
                &bob,
                &HistoryEntry::new("1", Direction::Sent, 1_000, "hello"),
            )
            .unwrap();
        let mut reply = HistoryEntry::new("2", Direction::Received, 61_000, "hi\nsecond line");
        reply.reply_to = Some("1".into());
        store.append_history(&bob, &reply).unwrap();
        store
            .append_edit(&conv, "1", "hello there", "e1", 2_000, None)
            .unwrap();
        store.append_reaction(&conv, "2", None, "👍").unwrap();
        store
            .append_history(
                &bob,
                &HistoryEntry::new("3", Direction::Received, 62_000, "gone"),
            )
            .unwrap();
        store.mark_deleted(&conv, "3", Some(bob)).unwrap();
        let mut timed = HistoryEntry::new("4", Direction::Sent, 1_000, "ran out");
        timed.expire_after_s = 1;
        store.append_history(&bob, &timed).unwrap();
        let group = GroupId::generate();
        let mut line = HistoryEntry::new("g1", Direction::Received, 70_000, "team talk");
        line.from = Some(carol);
        store.append_group_history(&group, &line).unwrap();

        let out = dir.path().join("out");
        let written = export_history(&store, &out, Format::Text, 100_000).unwrap();
        assert_eq!(written.len(), 2, "{written:?}");
        let bob_file = std::fs::read_to_string(out.join("bob.txt")).unwrap();
        let lines: Vec<&str> = bob_file.lines().collect();
        assert!(
            lines[0].ends_with("  you: hello there (edited)"),
            "{bob_file}"
        );
        assert!(lines[1].ends_with("  > you: hello there"), "{bob_file}");
        assert!(lines[2].ends_with("  bob: hi"), "{bob_file}");
        assert_eq!(lines[3], "second line [👍 you]");
        assert!(lines[4].ends_with("  bob deleted a message"), "{bob_file}");
        assert!(
            !bob_file.contains("ran out"),
            "an expired line is not exported"
        );
        let group_file = std::fs::read_to_string(out.join(format!("group-{group}.txt"))).unwrap();
        assert!(group_file.contains(&format!("  {carol}: team talk")));

        let written = export_history(&store, &out, Format::Json, 100_000).unwrap();
        assert!(written.iter().any(|p| p.ends_with("bob.jsonl")));
        let json = std::fs::read_to_string(out.join("bob.jsonl")).unwrap();
        let rows: Vec<serde_json::Value> = json
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["who"], "you");
        assert_eq!(rows[0]["text"], "hello there");
        assert_eq!(rows[0]["previous"][0], "hello");
        assert_eq!(rows[0]["edited"], true);
        assert_eq!(rows[1]["reply_to"], "1");
        assert_eq!(rows[1]["reactions"][0]["emoji"], "👍");
        assert_eq!(rows[2]["deleted"], true);
        let _ = Reaction {
            from: None,
            emoji: String::new(),
        };

        // Written again, nothing is overwritten.
        let written = export_history(&store, &out, Format::Text, 100_000).unwrap();
        assert!(
            written.iter().any(|p| p.ends_with("bob (2).txt")),
            "{written:?}"
        );
        // And never inside the data directory.
        let err = export_history(
            &store,
            &dir.path().join("data/export"),
            Format::Text,
            100_000,
        )
        .unwrap_err();
        assert!(err.to_string().contains("outside the data directory"));
    }
}
