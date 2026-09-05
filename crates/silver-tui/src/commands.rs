//! The command table: the one place that says what each slash command is
//! called, what it takes and what it does. The help overlay, Tab
//! completion, the status line and the "did you mean" hint all read it.

use std::path::{Path, PathBuf};

pub struct CommandInfo {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    /// Placeholder for the arguments; empty when there are none.
    pub args: &'static str,
    pub help: &'static str,
    /// The argument is a file path, which Tab completes.
    pub path_arg: bool,
}

const fn cmd(
    name: &'static str,
    aliases: &'static [&'static str],
    args: &'static str,
    help: &'static str,
) -> CommandInfo {
    CommandInfo {
        name,
        aliases,
        args,
        help,
        path_arg: false,
    }
}

pub const COMMANDS: &[CommandInfo] = &[
    cmd(
        "add",
        &[],
        "<id or link> [alias]",
        "add a contact by id or invite link (looks up their key on the relay)",
    ),
    cmd(
        "invite",
        &["link", "qr"],
        "[copy]",
        "show your invite link and a QR code of it; /invite copy puts it on the clipboard",
    ),
    cmd(
        "copy",
        &[],
        "[id|link]",
        "copy the last message of this chat, your id, or your invite link",
    ),
    cmd(
        "group",
        &["g"],
        "<what> …",
        "groups: new <name>, add <contact>, remove <member>, leave, members, invite [copy], join <link>, link reset, admin add|remove <member>, rename <name>, info, rejoin, forget",
    ),
    cmd(
        "decline",
        &[],
        "<g1…>",
        "turn a group invitation down (the Requests pane lists them)",
    ),
    cmd(
        "alias",
        &["rename"],
        "<name>",
        "name the selected contact or group",
    ),
    cmd(
        "remove",
        &["rm"],
        "",
        "forget the selected contact (history stays on disk)",
    ),
    cmd(
        "verify",
        &[],
        "[ok|no]",
        "show the safety number to compare with the selected contact; ok marks them verified, no clears it",
    ),
    cmd(
        "refresh",
        &[],
        "",
        "fetch the selected contact's key again and report changes",
    ),
    cmd(
        "session",
        &[],
        "",
        "show how messages with the selected contact are protected",
    ),
    cmd(
        "receipts",
        &[],
        "on|off",
        "tell contacts when you have read their messages (default on)",
    ),
    cmd(
        "cover",
        &[],
        "on|off",
        "send meaningless messages at random moments to contacts who do the same, so the relay cannot tell when you really talk (default off; costs bandwidth)",
    ),
    cmd(
        "notify",
        &[],
        "all|bell|off",
        "bell and desktop notification for new messages, bell only, or nothing",
    ),
    cmd(
        "marks",
        &["ascii"],
        "ascii|unicode|auto",
        "draw the check marks in ASCII if your terminal shows boxes instead",
    ),
    cmd(
        "theme",
        &["colors", "colours"],
        "dark|light|mono",
        "colours for a dark or a light background, or none at all",
    ),
    cmd(
        "accept",
        &[],
        "<n|user-id>",
        "accept a contact request from the Requests pane",
    ),
    cmd(
        "block",
        &[],
        "<n|user-id>",
        "ignore a requester or contact from now on",
    ),
    cmd("unblock", &[], "<user-id>", "undo a block"),
    cmd("blocked", &[], "", "list blocked ids"),
    CommandInfo {
        name: "send",
        aliases: &["file", "attach"],
        args: "<path>",
        help: "send a file (up to 16 MiB) to the selected contact; received files land in <data-dir>/downloads",
        path_arg: true,
    },
    cmd(
        "reply",
        &[],
        "<text>",
        "answer the selected message (or the last one received), quoting it",
    ),
    cmd(
        "react",
        &[],
        "<emoji|none>",
        "react to the selected message (or the last one received); none takes yours back",
    ),
    cmd(
        "edit",
        &[],
        "<text>",
        "replace the text of the selected message of yours (or your last one) within a day of sending",
    ),
    cmd(
        "delete",
        &["del"],
        "[me]",
        "delete the selected message of yours (or your last one) for everyone within a day of sending; /delete me removes any message from your devices only",
    ),
    cmd(
        "timer",
        &[],
        "[30s|5m|1h|8h|1d|1w|off]",
        "make messages in this chat disappear that long after you send them or they read them (in a group: admins only); no argument shows the setting",
    ),
    cmd(
        "get",
        &["fetch"],
        "[all]",
        "fetch the newest file waiting in this chat (or double-click its line); all fetches every one",
    ),
    cmd(
        "files",
        &[],
        "auto|ask",
        "fetch this contact's files as they arrive, or wait for /get (the default)",
    ),
    cmd(
        "open",
        &[],
        "",
        "open the last file received in this chat (or double-click its line)",
    ),
    cmd(
        "search",
        &["find"],
        "<text>",
        "find messages in the selected chat (or all chats from System)",
    ),
    cmd("me", &["id"], "", "show your own id and invite link"),
    cmd(
        "devices",
        &["device"],
        "[link <link> [days] | remove <n> | name <n> <name> | join | leave]",
        "your identity's devices: list them; link one that printed a link with silver --link (with that many days of history, default 30), unlink or rename one, add them to your groups, or unlink this one",
    ),
    cmd(
        "relay",
        &[],
        "<ws-url>",
        "change the relay (takes effect on next start)",
    ),
    cmd(
        "revoke",
        &[],
        "confirm",
        "retire your identity for good; contacts are told it is dead (needs /revoke confirm)",
    ),
    cmd(
        "rotate",
        &[],
        "confirm",
        "move to a new identity; contacts re-pin automatically, then restart (needs /rotate confirm)",
    ),
    cmd(
        "log",
        &["keylog"],
        "",
        "where the relay's key transparency log stands, and where the selected contact appears in it",
    ),
    cmd("help", &["h", "?"], "", "show this help"),
    cmd(
        "lock",
        &[],
        "",
        "forget the keys until the passphrase is typed again (needs one; lock_after_minutes in config.json does it by itself)",
    ),
    cmd("quit", &["q", "exit"], "", "exit"),
];

pub const KEY_HELP: &[&str] = &[
    "Tab / Shift-Tab, Alt-Up / Alt-Down, or a click in the list   switch chats",
    "Enter sends · Alt-Enter new line · Up / Down recall earlier lines · Tab completes /commands and paths",
    "PgUp / PgDn or the mouse wheel scroll · Ctrl-Home / Ctrl-End jump · drag the scrollbar or the divider",
    "Drag to select text, double click a word, triple click a message, Shift-Up / Shift-Down for messages",
    "With one message selected, /reply, /react, /edit and /delete act on it",
    "Ctrl-C copies the selection (twice with nothing selected: quit) · Ctrl-V, Shift-Insert or right click paste",
    "Esc clears the selection, then the input · F1 opens and closes this help · Ctrl-Q quits",
];

/// The command called `name` (or aliased so).
pub fn find(name: &str) -> Option<&'static CommandInfo> {
    COMMANDS
        .iter()
        .find(|c| c.name == name || c.aliases.contains(&name))
}

/// Commands whose name starts with `prefix`, alphabetically.
pub fn matching(prefix: &str) -> Vec<&'static CommandInfo> {
    let mut out: Vec<&CommandInfo> = COMMANDS
        .iter()
        .filter(|c| c.name.starts_with(prefix))
        .collect();
    out.sort_by_key(|c| c.name);
    out
}

/// The command someone most likely meant by `typo`, when one is close.
pub fn closest(typo: &str) -> Option<&'static str> {
    let typo = typo.to_ascii_lowercase();
    if typo.is_empty() {
        return None;
    }
    if let Some(c) = COMMANDS.iter().find(|c| c.name.starts_with(&typo)) {
        return Some(c.name);
    }
    COMMANDS
        .iter()
        .map(|c| {
            let best = std::iter::once(c.name)
                .chain(c.aliases.iter().copied())
                .map(|n| edit_distance(n, &typo))
                .min()
                .unwrap_or(usize::MAX);
            (best, c.name)
        })
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, name)| name)
}

/// Levenshtein distance.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// `~/x` as the user's home directory plus `x`.
pub fn expand_home(path: &str) -> PathBuf {
    let path = path.trim();
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

/// Completions for a partly typed path: the entries of its directory that
/// start with the typed name, directories with a trailing separator. The
/// candidates keep the spelling the user started with (`~/`, relative).
pub fn complete_path(partial: &str) -> Vec<String> {
    let partial = if partial.is_empty() { "~/" } else { partial };
    let (dir_text, prefix) = match partial.rfind(['/', '\\']) {
        Some(i) => (&partial[..=i], &partial[i + 1..]),
        None => ("", partial),
    };
    let dir: PathBuf = if dir_text.is_empty() {
        PathBuf::from(".")
    } else {
        expand_home(dir_text)
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    // Directories end in the separator the user has been typing (`/` on
    // Windows too, if that is what they wrote), the platform's otherwise.
    let separator = match dir_text.chars().next_back() {
        Some(sep @ ('/' | '\\')) => sep.to_string(),
        _ => std::path::MAIN_SEPARATOR_STR.to_owned(),
    };
    let mut out: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with(prefix) || (prefix.is_empty() && name.starts_with('.')) {
                return None;
            }
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false)
                || (e.path().is_dir() && Path::new(&e.path()).exists());
            Some(format!(
                "{dir_text}{name}{}",
                if is_dir { separator.as_str() } else { "" }
            ))
        })
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_finds_names_and_aliases() {
        assert_eq!(find("send").map(|c| c.name), Some("send"));
        assert_eq!(find("attach").map(|c| c.name), Some("send"));
        assert_eq!(find("qr").map(|c| c.name), Some("invite"));
        assert!(find("nope").is_none());
        let names: Vec<&str> = matching("se").iter().map(|c| c.name).collect();
        assert_eq!(names, ["search", "send", "session"]);
    }

    #[test]
    fn typos_get_a_suggestion() {
        assert_eq!(closest("sned"), Some("send"));
        assert_eq!(closest("acept"), Some("accept"));
        assert_eq!(closest("inv"), Some("invite"));
        assert_eq!(closest("xyzzy"), None);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn the_table_is_well_formed() {
        let mut names: Vec<&str> = COMMANDS.iter().map(|c| c.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), COMMANDS.len(), "duplicate command names");
        for c in COMMANDS {
            assert!(!c.help.is_empty() && !c.help.ends_with('.'), "/{}", c.name);
        }
        assert!(KEY_HELP.iter().any(|k| k.contains("F1")));
    }

    #[test]
    fn paths_complete_from_their_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("photo.jpg"), b"x").unwrap();
        std::fs::write(dir.path().join("phone.txt"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("pictures")).unwrap();
        std::fs::write(dir.path().join(".hidden"), b"x").unwrap();
        let base = format!("{}/", dir.path().display());
        let got = complete_path(&format!("{base}ph"));
        assert_eq!(
            got,
            [format!("{base}phone.txt"), format!("{base}photo.jpg")]
        );
        let got = complete_path(&format!("{base}pi"));
        assert_eq!(got, [format!("{base}pictures/")]);
        // Nothing typed after the directory lists it without dot files.
        assert_eq!(complete_path(&base).len(), 3);
        assert!(complete_path(&format!("{base}zz")).is_empty());
        assert!(complete_path("/definitely/not/here/x").is_empty());
    }
}
