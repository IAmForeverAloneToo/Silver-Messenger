//! On-disk state for a client: identity keys, contacts, config and history.
//!
//! Layout under the data directory:
//!
//! ```text
//! vault.json           present when a passphrase protects the directory
//! identity.json        private keys (0600 on Unix)
//! prekeys.json         private prekeys peers start sessions against (0600)
//! sessions.json        forward-secret session state per peer (0600)
//! config.json          relay URL etc.
//! contacts.json        known peers and their pinned key bundles
//! outbox.json          outgoing envelopes the relay has not accepted yet
//! requests.json        messages from people who are not contacts yet
//! blocked.json         ids whose messages are dropped
//! devices.json         the account's linked devices and revocations
//! state                which version of each file is the current one
//! state.prev           the version of that before the last write
//! history/<user>.jsonl one line per message, per peer
//! ```
//!
//! On a linked device `identity.json` also carries, under `linked`, the
//! account it belongs to and the certificate the account signed for it.
//!
//! With a passphrase set, every file is encrypted with the vault's data key
//! (see [`crate::vault`]); history files are encrypted line by line. Files
//! written before the passphrase was set are recognised as plaintext and
//! re-encrypted when the passphrase is set.
//!
//! Each of those files is also written at a generation, recorded in
//! `state`, so that an older copy of one put back by somebody with write
//! access is refused rather than read: see [`crate::rollback`].

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use silver_protocol::envelope::ReceiptKind;
use silver_protocol::wire::url_host;
use silver_protocol::{Identity, IdentitySecrets, KeyBundle, Revocation, Sequence, UserId};

use crate::devices::{DevicesFile, Linked};
use crate::files::FileInfo;
use crate::rollback::{Generations, STATE_FILE, STATE_PREVIOUS_FILE, State};
use crate::sequence::Seen;
use crate::sessions::{PrekeyFile, SessionsFile};
use crate::vault::{FileCipher, Kdf, LINE_PREFIX, VaultError, VaultFile};

const VAULT_FILE: &str = "vault.json";
/// Key store entries this directory may not need, written down before the
/// step that could orphan them. See [`Store::add_pending`].
const PENDING_FILE: &str = "vault.pending";
/// Where `SILVER_LOG` writes, when it is set. Not under the data key: it
/// is opened before the directory is unlocked.
pub const LOG_FILE: &str = "silver.log";
/// The previous log, kept when `silver.log` is rolled over.
pub const ROLLED_LOG_FILE: &str = "silver.log.1";
const IDENTITY_FILE: &str = "identity.json";
const REVOCATION_FILE: &str = "revocation.json";
const PREKEYS_FILE: &str = "prekeys.json";
const SESSIONS_FILE: &str = "sessions.json";
const CONFIG_FILE: &str = "config.json";
const CONTACTS_FILE: &str = "contacts.json";
const OUTBOX_FILE: &str = "outbox.json";
const TRANSPARENCY_FILE: &str = crate::transparency::LOG_NAME;
const REQUESTS_FILE: &str = "requests.json";
const BLOCKED_FILE: &str = "blocked.json";
const DECLINED_FILE: &str = "declined.json";
const DEVICES_FILE: &str = "devices.json";
const HISTORY_DIR: &str = "history";

/// Every whole file the store keeps for the identity, and whether it is
/// written 0600 as key material.
///
/// The one list the re-encryption ([`Store::recrypt_all`]) and the wipe
/// work from, so a file added to the store cannot be remembered by one
/// and forgotten by the other. A file the re-encryption misses stays in
/// the clear on a directory the client calls protected, and becomes
/// unreadable when the protection is taken off; `groups.json`,
/// `groups.mls` and `revocation.json` were missed until 0.10.1, which
/// left the MLS epoch secrets of every group in plaintext.
const IDENTITY_FILES: &[&str] = &[
    IDENTITY_FILE,
    REVOCATION_FILE,
    PREKEYS_FILE,
    SESSIONS_FILE,
    CONTACTS_FILE,
    OUTBOX_FILE,
    TRANSPARENCY_FILE,
    REQUESTS_FILE,
    BLOCKED_FILE,
    DECLINED_FILE,
    DEVICES_FILE,
    crate::groups::GROUPS_FILE,
    crate::groups::MLS_FILE,
];

/// The files the re-encryption walks: everything belonging to the
/// identity, and the settings, which the wipe keeps but the data key
/// covers.
fn recrypted_files() -> impl Iterator<Item = &'static str> {
    IDENTITY_FILES
        .iter()
        .copied()
        .chain(std::iter::once(CONFIG_FILE))
}

/// Client-side configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub relay_url: Option<String>,
    /// PEM file with extra trusted root certificates, for `wss://` relays
    /// behind a private CA.
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    /// Proxy URL, `http://` (CONNECT) or `socks5://`. When unset,
    /// `HTTPS_PROXY` (else `ALL_PROXY`) from the environment is used.
    #[serde(default)]
    pub proxy: Option<String>,
    /// Pins for the relay's TLS public key (`sha256:<hex>`); with any set,
    /// a `wss://` connection whose chain carries none of them is refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_pins: Vec<String>,
    /// Hosts this client has reached over `wss://`. A relay once reached
    /// securely is never talked to over plain `ws://`, so that a changed
    /// URL cannot quietly strip the transport encryption.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secure_hosts: Vec<String>,
    /// What each relay host has told this client it can do, remembered as
    /// the union of everything it has ever offered.
    ///
    /// The features come from the relay on every connection and are the
    /// relay's own word. A relay that stops offering `transparency` turns
    /// off the checking of the keys it serves; one that stops offering
    /// `anonymous_send` learns which identity submitted every message.
    /// Both are downgrades a relay can make for one client at a time,
    /// silently, and neither is visible unless somebody remembers what was
    /// offered before. This is that memory (`docs/PROTOCOL.md` 7.3).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub relay_features: BTreeMap<String, Vec<String>>,
    /// Random value identifying this installation's message numbering; see
    /// [`silver_protocol::Sequence`].
    #[serde(default)]
    pub send_epoch: Option<u64>,
    /// Invite token for relays that only register invited identities.
    #[serde(default)]
    pub invite_token: Option<String>,
    /// Ask the releases page, once a day at start, whether something newer
    /// exists, and say so in the System pane.
    ///
    /// Off unless turned on. A check on a timer tells the release host
    /// this computer's address, that it runs Silver Messenger, and when it
    /// is used -- a usage pattern, which is what the rest of the client
    /// works to withhold. On, it goes through the same proxy the relay
    /// connection uses, and nothing is ever downloaded by it: it prints,
    /// and `silver update` installs.
    #[serde(default)]
    pub update_check: bool,
    /// The day the last such check was made, `YYYY-MM-DD`, so a client
    /// started ten times in a day asks once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_checked_on: Option<String>,
    /// Tell contacts when their messages have been shown. Delivery receipts
    /// are always sent.
    #[serde(default = "default_true")]
    pub read_receipts: bool,
    /// Send cover traffic to contacts who have it on too, so the relay
    /// cannot tell when the two of you are really talking. Off by default:
    /// it costs bandwidth on both sides. See [`crate::cover`].
    #[serde(default)]
    pub cover: bool,
    /// How to draw attention to new messages: `all`, `bell` or `off`.
    #[serde(default = "default_notify")]
    pub notify: String,
    /// Symbols in the interface: `auto`, `unicode` or `ascii` (for
    /// terminals whose fonts lack the check marks, such as the classic
    /// Windows console).
    #[serde(default = "default_marks")]
    pub marks: String,
    /// Colours: `dark`, `light` or `mono`.
    #[serde(default = "default_theme")]
    pub theme: String,
    /// Width of the chat list, in columns.
    #[serde(default = "default_sidebar_width")]
    pub sidebar_width: u16,
    /// Most the `downloads/` folder may hold, in MiB; 0 means no limit.
    #[serde(default = "default_downloads_quota_mib")]
    pub downloads_quota_mib: u64,
    /// Keep the data key in the operating system's key store when no
    /// passphrase is set, so the files are encrypted at rest.
    #[serde(default = "default_true")]
    pub os_keystore: bool,
    /// Lock the client (drop the keys, ask for the passphrase again) after
    /// this many minutes without a keystroke; 0 never. Needs a passphrase.
    #[serde(default)]
    pub lock_after_minutes: u64,
    /// Write received files under the data key, so `downloads/` holds
    /// ciphertext like the rest of the directory; `/open` decrypts a
    /// private temporary copy. Only where the directory is protected.
    #[serde(default)]
    pub encrypted_downloads: bool,
    /// Start in reader mode: one line per event for a screen reader, no
    /// box drawing, no alternate screen.
    #[serde(default)]
    pub reader: bool,
}

fn default_downloads_quota_mib() -> u64 {
    1024
}

impl Config {
    /// The downloads quota in bytes, if there is one.
    pub fn downloads_quota(&self) -> Option<u64> {
        (self.downloads_quota_mib > 0).then(|| self.downloads_quota_mib.saturating_mul(1024 * 1024))
    }

    /// Remember that `url` was reached over `wss://`. `true` when that is
    /// news (and the config should be saved).
    pub fn note_secure(&mut self, url: &str) -> bool {
        if !url.trim_start().to_ascii_lowercase().starts_with("wss://") {
            return false;
        }
        let Some(host) = url_host(url) else {
            return false;
        };
        if self.secure_hosts.contains(&host) {
            return false;
        }
        self.secure_hosts.push(host);
        true
    }

    /// Record what the relay at `url` offers, and say which of the things
    /// it offered before are missing now.
    ///
    /// The record is the union of everything the host has ever offered,
    /// so a feature added later is remembered too and a relay cannot
    /// quietly take back what it once gave. A returned list is a
    /// downgrade for the user to hear about.
    pub fn note_features(&mut self, url: &str, offered: &[String]) -> Vec<String> {
        let Some(host) = url_host(url) else {
            return Vec::new();
        };
        let known = self.relay_features.entry(host).or_default();
        let withdrawn: Vec<String> = known
            .iter()
            .filter(|f| !offered.contains(f))
            .cloned()
            .collect();
        for feature in offered {
            if !known.contains(feature) {
                known.push(feature.clone());
            }
        }
        known.sort();
        withdrawn
    }

    /// The host of `url` when `url` is plain `ws://` to a host this client
    /// has reached over `wss://` before: such a URL must not be used.
    pub fn downgrade(&self, url: &str) -> Option<String> {
        if !url.trim_start().to_ascii_lowercase().starts_with("ws://") {
            return None;
        }
        let host = url_host(url)?;
        self.secure_hosts.contains(&host).then_some(host)
    }
}

fn default_true() -> bool {
    true
}

fn default_notify() -> String {
    "all".to_owned()
}

fn default_marks() -> String {
    "auto".to_owned()
}

fn default_theme() -> String {
    "dark".to_owned()
}

fn default_sidebar_width() -> u16 {
    26
}

impl Default for Config {
    fn default() -> Self {
        Self {
            relay_url: None,
            ca_cert: None,
            proxy: None,
            relay_pins: Vec::new(),
            secure_hosts: Vec::new(),
            relay_features: BTreeMap::new(),
            send_epoch: None,
            invite_token: None,
            update_check: false,
            update_checked_on: None,
            read_receipts: true,
            cover: false,
            notify: default_notify(),
            marks: default_marks(),
            theme: default_theme(),
            sidebar_width: default_sidebar_width(),
            downloads_quota_mib: default_downloads_quota_mib(),
            os_keystore: true,
            lock_after_minutes: 0,
            encrypted_downloads: false,
            reader: false,
        }
    }
}

/// A known peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub user_id: UserId,
    #[serde(default)]
    pub alias: Option<String>,
    /// Pinned on first lookup (trust on first use).
    #[serde(default)]
    pub bundle: Option<KeyBundle>,
    /// Sequence number of the last message we sent them.
    #[serde(default)]
    pub sent_seq: u64,
    /// What has been accepted from them: the highest sequence, which
    /// messages below it have arrived, and where their previous numbering
    /// ended ([`crate::sequence`]).
    #[serde(default)]
    pub received: Option<Seen>,
    /// The user compared safety numbers with this contact out of band.
    #[serde(default)]
    pub verified: bool,
    /// The linked device whose `sync contact` supplied the pinned bundle,
    /// when it was not this one; see [`Contact::drop_trust_from`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_by: Option<UserId>,
    /// The linked device whose `sync contact` set `verified`, when it was
    /// not this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_by: Option<UserId>,
    /// Capabilities their last message advertised; see
    /// [`silver_protocol::envelope::capability`].
    #[serde(default)]
    pub caps: Vec<String>,
    /// Fetch the files they send as they arrive, instead of waiting for
    /// the user to ask for each one.
    #[serde(default)]
    pub auto_files: bool,
    /// The contact published a revocation for this identity: it is dead and
    /// must not be messaged. Set when a valid revocation for their pinned key
    /// arrives; cleared only by removing and re-adding them.
    #[serde(default)]
    pub revoked: bool,
    /// The last sequence accepted from each of their linked devices, which
    /// number their own streams (`docs/PROTOCOL.md` section 14); the
    /// primary's is `received`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub device_received: HashMap<UserId, Seen>,
    /// The conversation's disappearing-message timer, in seconds; 0 for
    /// none (`docs/design/everyday.md`). Set by either side, applied to
    /// messages sent and received from then on.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub expire_after_s: u64,
    /// The strongest post-quantum protection a session with them has ever
    /// had, so that losing it can be noticed (0.15.0).
    ///
    /// A session that is weaker than this one was is either their client
    /// going backwards or somebody serving a bundle with the ML-KEM keys
    /// taken out, and those look identical from here. `None` until the
    /// first session, and for contacts carried over from before 0.15.0 --
    /// which is why the first session after an upgrade sets it rather than
    /// warning about it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub best_pq: Option<crate::sessions::PqLevel>,
}

impl Contact {
    pub fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            alias: None,
            bundle: None,
            sent_seq: 0,
            received: None,
            verified: false,
            pinned_by: None,
            verified_by: None,
            caps: Vec::new(),
            auto_files: false,
            revoked: false,
            device_received: HashMap::new(),
            expire_after_s: 0,
            best_pq: None,
        }
    }

    /// What has been accepted from `device` (`None`: their primary).
    pub fn received_from(&self, device: Option<&UserId>) -> Option<Seen> {
        match device {
            None => self.received,
            Some(device) => self.device_received.get(device).copied(),
        }
    }

    /// Note the sequence just accepted from `device` (`None`: their primary).
    pub fn note_received(&mut self, device: Option<&UserId>, sequence: Sequence) {
        match device {
            None => crate::sequence::note(&mut self.received, sequence),
            Some(device) => {
                let mut seen = self.device_received.get(device).copied();
                crate::sequence::note(&mut seen, sequence);
                if let Some(seen) = seen {
                    self.device_received.insert(*device, seen);
                }
            }
        }
    }

    /// Pin `bundle`, this device's own doing: whatever a sibling had
    /// pinned here, this device has now seen the key itself.
    pub fn pin(&mut self, bundle: Option<KeyBundle>) {
        self.bundle = bundle;
        self.pinned_by = None;
    }

    /// Set the verified mark, this device's own doing.
    pub fn set_verified(&mut self, verified: bool) {
        self.verified = verified;
        self.verified_by = None;
    }

    /// Undo what one of the account's own devices said about this
    /// contact's keys, because that device has been unlinked.
    ///
    /// A linked device can pin a bundle and mark a contact verified here
    /// through `sync contact` (`docs/PROTOCOL.md` section 14.4). Both are
    /// trust the user placed in the device as much as in the contact, so
    /// when the device is unlinked — the answer to a stolen or
    /// compromised one — they go with it: the pin is dropped, so the next
    /// lookup pins afresh and any change is reported, and the verified
    /// mark is cleared, so the safety numbers are compared again. What
    /// this device pinned or verified itself is untouched.
    pub fn drop_trust_from(&mut self, device: &UserId) -> bool {
        let mut changed = false;
        if self.pinned_by.as_ref() == Some(device) {
            self.bundle = None;
            self.pinned_by = None;
            changed = true;
        }
        if self.verified_by.as_ref() == Some(device) {
            self.verified = false;
            self.verified_by = None;
            changed = true;
        }
        changed
    }

    /// Whether their client advertised `capability`.
    pub fn supports(&self, capability: &str) -> bool {
        self.caps.iter().any(|c| c == capability)
    }

    /// Allocate the sequence for the next message to this contact.
    pub fn next_sequence(&mut self, epoch: u64) -> Sequence {
        self.sent_seq += 1;
        Sequence {
            epoch,
            seq: self.sent_seq,
        }
    }

    /// Alias if set, otherwise a short form of the id. The alias is reduced
    /// to what can be seen even if the file on disk says otherwise: it
    /// ends up in window titles and notifications, not only in the cell
    /// buffer.
    pub fn display_name(&self) -> String {
        self.alias
            .as_deref()
            .map(|alias| crate::files::printable(alias, crate::files::MAX_ALIAS_CHARS))
            .filter(|alias| !alias.is_empty())
            .unwrap_or_else(|| format!("{}…", self.user_id.short()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Sent,
    Received,
}

/// A reaction to a message, as kept with it: whose (`None` for one's
/// own) and what.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reaction {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<UserId>,
    pub emoji: String,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One message in a conversation log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub direction: Direction,
    pub timestamp_ms: u64,
    pub text: String,
    /// For sent messages: the furthest receipt the peer returned. Never
    /// written to disk with the entry; applied from later receipt lines.
    #[serde(skip)]
    pub receipt: Option<ReceiptKind>,
    /// For a received file: how to fetch it, kept until it has been.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileInfo>,
    /// Where a received file was written, once it has been. Written by
    /// the download itself and never taken from the line's text, which is
    /// the sender's: a text saying `[file] … → /path` is a claim, not a
    /// record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved: Option<PathBuf>,
    /// In a group's history: who wrote it (absent for our own lines and
    /// for notes about the group).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<UserId>,
    /// This line is a note this client wrote about the conversation
    /// rather than a message somebody sent.
    ///
    /// Set by the note writers and by nothing else. Before 0.11.0 a note
    /// was told from a message by its text starting with `· `, which a
    /// received message could imitate — and a message treated as a note
    /// is dimmed, loses its author when read aloud, and is skipped by
    /// `/reply`, `/react`, `/edit` and `/delete`. `None` means a line
    /// written before the flag existed, where the old guess is all there
    /// is; every line written from 0.11.0 on says which it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<bool>,
    /// The message this one answers (`docs/PROTOCOL.md` section 4.7), if
    /// it is a reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// The conversation's disappearing-message timer when this was sent
    /// or received, in seconds; 0 for none. The clock runs from
    /// `timestamp_ms` for a sent message and from `read_at_ms` for a
    /// received one ([`crate::everyday::expires_at`]).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub expire_after_s: u64,
    /// When a received message was shown; applied from later `read`
    /// lines, and written with the entry only where the entry carries its
    /// state whole (a device snapshot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at_ms: Option<u64>,
    /// The text was replaced by an edit; `previous` holds the earlier
    /// texts, oldest first.
    #[serde(default, skip_serializing_if = "is_false")]
    pub edited: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous: Vec<String>,
    /// The author deleted the message for everyone: what stays is a
    /// placeholder with no text and no file, which later edits and
    /// reactions leave alone.
    #[serde(default, skip_serializing_if = "is_false")]
    pub deleted: bool,
    /// The reactions to it, one per person; applied from later lines.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reactions: Vec<Reaction>,
}

impl HistoryEntry {
    /// A plain entry: no receipt, no file, no sender, nothing of section
    /// 4.7 about it.
    pub fn new(
        id: impl Into<String>,
        direction: Direction,
        timestamp_ms: u64,
        text: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            direction,
            timestamp_ms,
            text: text.into(),
            receipt: None,
            file: None,
            saved: None,
            from: None,
            note: Some(false),
            reply_to: None,
            expire_after_s: 0,
            read_at_ms: None,
            edited: false,
            previous: Vec::new(),
            deleted: false,
            reactions: Vec::new(),
        }
    }

    /// When this message goes, if it has a timer and its clock runs.
    pub fn expires_at_ms(&self) -> Option<u64> {
        crate::everyday::expires_at(
            self.direction,
            self.timestamp_ms,
            self.read_at_ms,
            self.expire_after_s,
        )
    }
}

/// A later line in a history file that updates earlier entries.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReceiptLine {
    receipt: ReceiptKind,
    ids: Vec<String>,
    at_ms: u64,
}

/// A later line that replaces the text of an earlier entry, for example
/// once a file it announced has been fetched and saved. `saved` carries
/// where it went, so that the path is read back as data rather than
/// parsed out of the text.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TextLine {
    update: String,
    text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    saved: Option<PathBuf>,
}

/// Messages shown to the user, and when: a received message's timer runs
/// from the first such line that names it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReadLine {
    read: Vec<String>,
    at_ms: u64,
}

/// An edit: the message `edit` says `text` from now on, by `from`
/// (absent: one's own), which must be the message's author for the edit
/// to apply; the edit's own id and time are kept for the record.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EditLine {
    edit: String,
    text: String,
    edit_id: String,
    at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<UserId>,
}

/// A reaction to the message `react` from `from` (absent: one's own);
/// an empty `emoji` withdraws it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReactLine {
    react: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<UserId>,
    emoji: String,
}

/// The message `gone` was removed for good: an entry for it and any line
/// naming it, before or after this one, count for nothing. With `from`,
/// the message was deleted for everyone by `from` before it arrived, and
/// only an entry `from` wrote is dropped: nobody tombstones another's
/// message.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct GoneLine {
    gone: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<UserId>,
}

/// What a deletion for everyone did to the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deletion {
    /// The entry is a placeholder now.
    Applied,
    /// The message is not held; a tombstone drops it should it arrive.
    Tombstoned,
    /// The entry is held and was not written by the one deleting; nothing
    /// changed.
    Refused,
}

/// Who wrote `entry` in `conversation`: the sender a group entry names;
/// in a conversation with a contact, the contact for what was received
/// and nobody (one's own) for what was sent.
fn author_of(entry: &HistoryEntry, conversation: &Conversation) -> Option<UserId> {
    entry.from.or(match (conversation, entry.direction) {
        (Conversation::Contact(peer), Direction::Received) => Some(*peer),
        _ => None,
    })
}

/// What one line of a history file can be. Each kind has a key of its
/// own (`id` and `direction`, `receipt`, `update`, `read`, `edit`,
/// `react`, `gone`), which is how the untagged enum tells them apart.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum HistoryLine {
    Entry(Box<HistoryEntry>),
    Receipt(ReceiptLine),
    Text(TextLine),
    Read(ReadLine),
    Edit(EditLine),
    React(ReactLine),
    Gone(GoneLine),
}

impl HistoryLine {
    /// The message ids this line is about, for a rewrite that drops what
    /// names a removed message.
    fn names(&self, id: &str) -> bool {
        match self {
            Self::Entry(e) => e.id == id,
            Self::Receipt(r) => r.ids.iter().any(|i| i == id),
            Self::Text(t) => t.update == id,
            Self::Read(r) => r.read.iter().any(|i| i == id),
            Self::Edit(e) => e.edit == id,
            Self::React(r) => r.react == id,
            Self::Gone(g) => g.gone == id,
        }
    }
}

/// A conversation's log: with a contact, or in a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Conversation {
    Contact(UserId),
    Group(silver_protocol::GroupId),
}

impl Conversation {
    fn file_name(&self) -> String {
        match self {
            Self::Contact(peer) => history_name(peer),
            Self::Group(group) => group_history_name(group),
        }
    }
}

/// A message from someone who is not a contact yet, held until the user
/// accepts or blocks them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeldMessage {
    pub id: String,
    pub timestamp_ms: u64,
    pub text: String,
    #[serde(default)]
    pub sequence: Sequence,
    /// A file they sent: never fetched while they are a stranger, but
    /// fetchable once they are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileInfo>,
    /// What the sender's client said it understands, so that once the
    /// sender is accepted the new contact knows their capabilities without
    /// waiting for another message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
}

/// Messages from one unknown sender, waiting for a decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactRequest {
    pub from: UserId,
    pub first_seen_ms: u64,
    pub messages: Vec<HeldMessage>,
}

/// A stranger the user said *not now* to (`docs/design/requests.md`):
/// their next request waits like any other, but rings nothing. Cleared
/// when they are accepted or blocked.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Declined {
    pub user: UserId,
    pub at_ms: u64,
}

/// Declined strangers remembered, at most; the oldest go first.
pub const MAX_DECLINED: usize = 200;

/// What stands between the files on disk and whoever copies them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// Plain files.
    None,
    /// Encrypted under a key kept in this computer's key store.
    Keystore,
    /// Encrypted under a key a passphrase unlocks.
    Passphrase,
}

/// Handle to the data directory.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
    cipher: Option<Arc<FileCipher>>,
    /// Which generation each file should be at, so that an older copy of
    /// one is refused rather than read (see [`crate::rollback`]).
    ///
    /// Shared between clones, because two handles to one directory are
    /// two views of the same generations and must not drift apart.
    /// Meaningful only while unlocked: an unprotected directory has
    /// nothing to bind a generation into, and says so at start.
    generations: Arc<Mutex<Generations>>,
}

impl Store {
    /// The platform's standard data directory for this app.
    pub fn default_dir() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "silver-messenger")
            .map(|d| d.data_dir().to_path_buf())
    }

    /// Move a data directory created under the app's former name, if one
    /// exists and the current one does not. Best effort; never fails.
    pub fn migrate_legacy_dir() {
        let Some(new) = Self::default_dir() else {
            return;
        };
        let Some(old) = directories::ProjectDirs::from("", "", "silver-message")
            .map(|d| d.data_dir().to_path_buf())
        else {
            return;
        };
        if !old.exists() || new.exists() {
            return;
        }
        if let Some(parent) = new.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::rename(&old, &new) {
            Ok(()) => {
                tracing::info!("moved data from {} to {}", old.display(), new.display());
                if let Some(parent) = old.parent() {
                    let _ = fs::remove_dir(parent); // only succeeds if now empty
                }
            }
            Err(e) => tracing::warn!("could not move {} to {}: {e}", old.display(), new.display()),
        }
    }

    /// Open the data directory. If it is protected by a passphrase the store
    /// starts locked; call [`Store::unlock`] before reading anything.
    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        create_private_dir(&root, Some(HISTORY_DIR))?;
        create_private_dir(&root.join(HISTORY_DIR), None)?;
        let store = Self {
            root,
            cipher: None,
            generations: Arc::new(Mutex::new(Generations::default())),
        };
        // Before anything else looks at the directory, and before any
        // unlock: a change that a crash cut short may have left a key in
        // the key store that nothing here needs. Reads no key and asks the
        // store nothing when there is no note, which is every normal start.
        store.settle_pending();
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // --- protection at rest -------------------------------------------------

    /// How the directory is protected on disk.
    pub fn protection(&self) -> Protection {
        match self.read_vault() {
            Ok(Some(vault)) if vault.kdf.is_keystore() => Protection::Keystore,
            Ok(Some(_)) => Protection::Passphrase,
            Ok(None) => Protection::None,
            // An unreadable vault is treated as a passphrase one: the
            // unlock then fails with the real reason.
            Err(_) => Protection::Passphrase,
        }
    }

    /// Whether a passphrase protects this directory.
    pub fn has_passphrase(&self) -> bool {
        self.protection() == Protection::Passphrase
    }

    /// Protected and not yet unlocked.
    pub fn is_locked(&self) -> bool {
        self.protection() != Protection::None && self.cipher.is_none()
    }

    /// The data key, for components that keep their own files (the outbox).
    pub fn cipher(&self) -> Option<Arc<FileCipher>> {
        self.cipher.clone()
    }

    // --- keys the store may still be holding --------------------------------

    /// The names in `vault.pending`, or none when it is absent or
    /// unreadable.
    ///
    /// Plaintext and read before any unlock, since the whole point is to
    /// reach it on a start that cannot open anything else.
    fn read_pending(&self) -> Vec<String> {
        let path = self.root.join(PENDING_FILE);
        fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<Vec<String>>(&text).ok())
            .unwrap_or_default()
    }

    /// Write down that the key store may end up holding a key under `name`
    /// that this directory does not need, before the step that makes it so.
    ///
    /// This is the durable half of [`Store::drop_unused_kek`]. That runs on
    /// the error paths of a change and cannot run at all if the process
    /// dies: the key store is written before the vault that would make the
    /// key needed, so a crash in the window between leaves a key nobody
    /// reads and nobody remembers to remove. The note is written and synced
    /// first, so the next [`Store::open`] finishes what the crash
    /// interrupted.
    ///
    /// A failure here fails the change. The alternative is making a key
    /// with no record that it exists, which is the situation this exists to
    /// prevent.
    fn add_pending(&self, name: &str) -> anyhow::Result<()> {
        let mut names = self.read_pending();
        if !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
        write_atomic(
            &self.root.join(PENDING_FILE),
            serde_json::to_string(&names)?.as_bytes(),
        )
        .context("noting the key store entry that may need removing")
    }

    /// Take `name` off the list: its fate is settled, either way.
    fn clear_pending(&self, name: &str) {
        let names: Vec<String> = self
            .read_pending()
            .into_iter()
            .filter(|n| n != name)
            .collect();
        let path = self.root.join(PENDING_FILE);
        let _ = if names.is_empty() {
            fs::remove_file(&path).or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })
        } else {
            serde_json::to_string(&names)
                .map_err(std::io::Error::other)
                .and_then(|text| {
                    write_atomic(&path, text.as_bytes()).map_err(std::io::Error::other)
                })
        };
    }

    /// Settle every name a interrupted change left behind. Called from
    /// [`Store::open`], before anything else reads the directory.
    ///
    /// Costs nothing on a normal start: with no `vault.pending` there is
    /// no name to settle and the key store is never asked anything.
    fn settle_pending(&self) {
        for name in self.read_pending() {
            self.drop_unused_kek(&name);
        }
    }

    /// Whether the vault on disk names `name`, so the directory needs the
    /// key kept under it.
    ///
    /// `Err` when that cannot be established. The caller keeps the key
    /// then, and keeps the note so a later start can decide: a key left
    /// behind is a bounded exposure this comes back to, while a key
    /// deleted because a read happened to fail takes every file in the
    /// directory with it.
    fn vault_needs_key(&self, name: &str) -> anyhow::Result<bool> {
        Ok(self
            .read_vault()?
            .is_some_and(|vault| vault.kdf.is_keystore() && vault.kdf.keystore_name() == name))
    }

    fn read_vault(&self) -> anyhow::Result<Option<VaultFile>> {
        let path = self.root.join(VAULT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text)
            .context("parsing vault.json")
            .map(Some)
    }

    fn write_vault(&self, vault: &VaultFile) -> anyhow::Result<()> {
        write_atomic(
            &self.root.join(VAULT_FILE),
            serde_json::to_string_pretty(vault)?.as_bytes(),
        )
    }

    pub fn unlock(&mut self, passphrase: &str) -> Result<(), VaultError> {
        let vault = self
            .read_vault()
            .map_err(VaultError::Other)?
            .ok_or_else(|| VaultError::Other(anyhow::anyhow!("no passphrase is set")))?;
        self.cipher = Some(Arc::new(FileCipher::unlock(&vault, passphrase)?));
        self.seal_stragglers().map_err(VaultError::Other)?;
        self.finish_rotation(&vault).map_err(VaultError::Other)?;
        self.load_generations().map_err(VaultError::Other)?;
        Ok(())
    }

    // --- rollback binding ----------------------------------------------------

    /// Read `state` and check it against the anchor in `vault.json`,
    /// adopting generations if this directory has none yet.
    ///
    /// Called once the cipher is in place, and after the two repairs that
    /// run first: sealing files a protection left plain, and finishing a
    /// half-done key rotation. Both rewrite files, and they do it in the
    /// unbound shape, so they must happen before anything is stamped.
    fn load_generations(&self) -> anyhow::Result<()> {
        let Some(cipher) = self.cipher.clone() else {
            return Ok(());
        };
        let Some(vault) = self.read_vault()? else {
            return Ok(());
        };
        let Some(anchor) = vault.state_generation else {
            return self.adopt_generations(&cipher);
        };
        // A record that cannot be read is not a reason to fail the
        // unlock: the person still has to be able to run the reset that
        // gets out of it, and that needs the key. Every read and write
        // refuses with the reason until then.
        *self.generations.lock().unwrap_or_else(|e| e.into_inner()) =
            match self.read_generations(&cipher, anchor) {
                Ok(state) => Generations::Bound(state),
                Err(e) => {
                    tracing::error!("{e}");
                    Generations::Unreadable(e.to_string())
                }
            };
        Ok(())
    }

    /// The `state` file, or the version before it if the last write was
    /// interrupted.
    fn read_generations(&self, cipher: &FileCipher, anchor: u64) -> anyhow::Result<State> {
        let mut trouble = Vec::new();
        for name in [STATE_FILE, STATE_PREVIOUS_FILE] {
            let path = self.root.join(name);
            if !path.exists() {
                trouble.push(format!("{name} is missing"));
                continue;
            }
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let state = match cipher.decrypt(STATE_FILE, &bytes) {
                Ok(plain) => serde_json::from_slice::<State>(&plain)
                    .with_context(|| format!("parsing {name}")),
                Err(e) => Err(e),
            };
            match state {
                // The anchor is raised after `state` is written, so a
                // state one generation ahead of the anchor is the write
                // that was interrupted between the two, and is the newer
                // truth. Behind the anchor is an older copy put back.
                Ok(state) if state.generation == anchor || state.generation == anchor + 1 => {
                    return Ok(state);
                }
                Ok(state) => trouble.push(format!(
                    "{name} is from generation {} where the vault says {anchor}",
                    state.generation
                )),
                Err(e) => trouble.push(format!("{name}: {e}")),
            }
        }
        bail!(
            "the record of what this directory last wrote cannot be read ({}), so an older copy \
             of a file could not be told from the current one. Nothing has been opened. \
             `silver --reset-rollback-protection` starts the record again from what is on disk, \
             which gives up being able to prove anything about what happened to this directory \
             before now.",
            trouble.join("; ")
        )
    }

    /// Give a directory written before generations existed its first one.
    ///
    /// Every file is rewritten at generation 1 and recorded, and the
    /// anchor follows. A crash part-way leaves some files rewritten and
    /// some not, and no anchor, so the next unlock runs this again --
    /// which is why it reads each file both ways round.
    fn adopt_generations(&self, cipher: &FileCipher) -> anyhow::Result<()> {
        const FIRST: u64 = 1;
        let mut state = State {
            generation: FIRST,
            ..State::default()
        };
        for name in recrypted_files() {
            let path = self.root.join(name);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            if !FileCipher::is_encrypted(&bytes) {
                // Still plain; `seal_stragglers` has already had its turn,
                // so leave it and let the next write bind it.
                continue;
            }
            // Either shape: name-only for a file this has not reached
            // yet, generation-bearing for one a run that did not finish
            // already converted.
            let opened = cipher.open_file(name, &bytes)?;
            let at = opened.generation.unwrap_or(FIRST);
            if opened.generation.is_none() {
                write_atomic(&path, &cipher.encrypt_at(name, at, &opened.plain))?;
            }
            state.wrote(name, at);
            state.generation = state.generation.max(at);
        }
        self.persist_generations(&state, cipher)?;
        *self.generations.lock().unwrap_or_else(|e| e.into_inner()) = Generations::Bound(state);
        tracing::info!(
            "this data directory now records what it last wrote, so an older copy of one of its \
             files is refused rather than read"
        );
        Ok(())
    }

    /// Start the record again from what is on disk, forfeiting what it
    /// could have proved about the past.
    ///
    /// For the case in `docs/design/format-changes.md` section 5.5: both
    /// `state` and `state.prev` unreadable, which without this would leave
    /// a directory that opens for nobody. It is deliberately a thing a
    /// person asks for by name.
    pub fn reset_rollback_protection(&self) -> anyhow::Result<()> {
        let Some(cipher) = self.cipher.clone() else {
            bail!("the data directory is not unlocked");
        };
        for name in [STATE_FILE, STATE_PREVIOUS_FILE] {
            let path = self.root.join(name);
            if path.exists() {
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            }
        }
        let mut vault = self.read_vault()?.context("reading the vault")?;
        vault.state_generation = None;
        self.write_vault(&vault)?;
        *self.generations.lock().unwrap_or_else(|e| e.into_inner()) = Generations::Unbound;
        tracing::warn!(
            "the record of what this directory last wrote was started again; whether any of its \
             files was replaced with an older copy before now can no longer be told"
        );
        self.adopt_generations(&cipher)
    }

    /// Unlock a directory whose wrapping key lives in this computer's key
    /// store.
    pub fn unlock_with_keystore(&mut self) -> anyhow::Result<()> {
        let vault = self
            .read_vault()?
            .context("the data directory is not protected")?;
        if !vault.kdf.is_keystore() {
            bail!("the data directory is protected by a passphrase, not the key store");
        }
        let kek = crate::keystore::load(&vault.kdf.keystore_name())?.context(
            "this computer's key store has no key for this data directory: it was copied from \
             another computer or account, or the key was removed; restore from a backup or \
             start over with a fresh data directory",
        )?;
        let cipher = FileCipher::unlock_with_kek(&vault, &kek).map_err(|e| {
            anyhow::anyhow!("the key in the key store does not open this vault: {e}")
        })?;
        self.cipher = Some(Arc::new(cipher));
        self.seal_stragglers()?;
        self.finish_rotation(&vault)?;
        self.load_generations()?;
        Ok(())
    }

    /// Finish a key rotation a crash cut short.
    ///
    /// The vault names two keys while files are being moved from one to
    /// the other ([`Store::rotate_key`]). Everything is readable meanwhile,
    /// so this is not urgent, but the whole point of the rotation is that
    /// the old key stops opening what is written from now on: the files
    /// still under it are rewritten and it is dropped from the vault. The
    /// wrapping itself does not change, so no passphrase is needed here.
    fn finish_rotation(&mut self, vault: &VaultFile) -> anyhow::Result<()> {
        if vault.previous_key.is_none() {
            return Ok(());
        }
        let Some(rotating) = self.cipher.clone() else {
            return Ok(());
        };
        tracing::info!("finishing a key rotation an earlier run left half done");
        self.recrypt_all(Some(&rotating), Some(&rotating))?;
        self.write_vault(&VaultFile {
            previous_key: None,
            ..vault.clone()
        })?;
        self.cipher = Some(Arc::new(rotating.settled()));
        Ok(())
    }

    /// Encrypt anything a cut-short protection left in the clear.
    ///
    /// Protecting a directory writes the vault first and then rewrites the
    /// files, so a crash in between leaves a directory that opens with
    /// some files still plain (a reader takes a plain file as itself).
    /// This finishes the job on the next unlock. It reads a few bytes of
    /// each file to decide, and does nothing at all in the ordinary case.
    fn seal_stragglers(&self) -> anyhow::Result<()> {
        let Some(cipher) = self.cipher.clone() else {
            return Ok(());
        };
        if !self.any_plain()? {
            return Ok(());
        }
        tracing::info!("sealing files an interrupted protection left in the clear");
        self.recrypt_all(Some(&cipher), Some(&cipher))
    }

    /// Whether any file the data key covers is lying in the clear.
    fn any_plain(&self) -> anyhow::Result<bool> {
        for name in recrypted_files() {
            let path = self.root.join(name);
            if !path.exists() {
                continue;
            }
            if !FileCipher::is_encrypted(&head_of(&path)?) {
                return Ok(true);
            }
        }
        let history = self.root.join(HISTORY_DIR);
        if history.exists() {
            for entry in fs::read_dir(&history)? {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                    continue;
                }
                let head = head_of(&path)?;
                if !head.is_empty() && !head.starts_with(LINE_PREFIX.as_bytes()) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Encrypt everything under a key kept in the operating system's key
    /// store. For a directory that is not protected yet.
    pub fn protect_with_keystore(&mut self) -> anyhow::Result<()> {
        if self.protection() != Protection::None {
            bail!("the data directory is already protected");
        }
        let kdf = Kdf::keystore();
        let name = kdf.keystore_name();
        self.add_pending(&name)?;
        let kek = crate::keystore::create(&name)?;
        let sealed = self.seal_under_kek(&kek, kdf);
        // Either way the key's fate is decided: the vault names it, or it
        // goes. The note only outlives a crash.
        self.drop_unused_kek(&name);
        sealed
    }

    fn seal_under_kek(&mut self, kek: &[u8; 32], kdf: Kdf) -> anyhow::Result<()> {
        let (_, cipher) = FileCipher::create_with_kek(kek);
        // A directory that was unprotected has no generations yet; the
        // rewrite below gives it its first.
        let vault = cipher.wrap_under_kek(kek, kdf, None);
        let cipher = Arc::new(cipher);
        // The vault first. It holds the only copy of the data key, and a
        // reader takes a plain file as itself, so a crash between the two
        // steps leaves a directory that still opens and that the next
        // unlock finishes sealing. Written last, as it was before 0.10.1,
        // the same crash left files encrypted under a key that had never
        // been written down: every message, contact and key lost.
        self.write_vault(&vault)?;
        self.cipher = Some(cipher.clone());
        self.recrypt_all(None, Some(&cipher)).context(
            "the data directory is now protected, but not every file could be encrypted; \
             the rest are sealed the next time it is unlocked",
        )?;
        // Now that there is an AEAD to bind them into, the directory gets
        // its generations; until this it had nowhere to keep them.
        self.load_generations()
    }

    /// Drop a key-encryption key made for a change that then failed.
    ///
    /// The key store is written before the vault that would make the key
    /// needed, so a failure in between used to leave a key nobody reads --
    /// and an entry nobody reads is still an extractable key sitting beside
    /// a directory somebody may have copied. Kept only when the vault on
    /// disk names it, which is when the directory does need it.
    ///
    /// Every outcome is final for the note in `vault.pending` except the
    /// two that are not settled: a vault that cannot be read, and a key
    /// store that will not take the key out. Both keep the note, so the
    /// next [`Store::open`] tries again rather than forgetting the key
    /// exists.
    fn drop_unused_kek(&self, name: &str) {
        match self.vault_needs_key(name) {
            Ok(true) => self.clear_pending(name),
            Ok(false) => match crate::keystore::delete(name) {
                Ok(()) => self.clear_pending(name),
                Err(e) => {
                    tracing::warn!("could not take an unused key out of the key store: {e:#}")
                }
            },
            // Fail safe. Deleting on a read that merely failed would take
            // every file in the directory with it.
            Err(e) => {
                tracing::warn!("cannot tell whether a key store entry is still in use: {e:#}")
            }
        }
    }

    /// Protect the directory with `passphrase`, encrypting everything in it.
    /// A directory the key store protects keeps its files as they are:
    /// only the wrapping changes, and the key store forgets its key.
    pub fn set_passphrase(&mut self, passphrase: &str) -> anyhow::Result<()> {
        self.set_passphrase_with(passphrase, Kdf::default_params())
    }

    #[doc(hidden)]
    pub fn set_passphrase_with(&mut self, passphrase: &str, kdf: Kdf) -> anyhow::Result<()> {
        match self.protection() {
            Protection::Passphrase => {
                bail!("a passphrase is already set; remove it first to change it")
            }
            Protection::Keystore => {
                self.ensure_unlocked()?;
                let old = self.read_vault()?.context("reading the vault")?;
                let cipher = self
                    .cipher
                    .clone()
                    .context("the data directory is locked")?;
                // Written down before the rotation, not after it: until it
                // happens the vault still names this key and settling the
                // note keeps it, and once it happens the note is the only
                // record that the superseded key is still in the store.
                let old_name = old.kdf.keystore_name();
                self.add_pending(&old_name)?;
                let anchor = self.anchor();
                self.rotate_key(&cipher, |c| {
                    c.wrap_under_passphrase(passphrase, kdf.clone(), anchor)
                })?;
                // The files are under a new key now, so the old one opens
                // nothing current -- but it still opens a copy of the
                // directory taken before the change, which is exactly what
                // a changed passphrase is meant to close.
                crate::keystore::delete(&old_name).context(
                    "the passphrase is set and the files are under a new key, but the old key \
                     could not be taken out of the key store; remove it by hand",
                )?;
                self.clear_pending(&old_name);
                Ok(())
            }
            Protection::None => {
                let (vault, cipher) = FileCipher::create(passphrase, kdf)?;
                let cipher = Arc::new(cipher);
                // The vault first; see `protect_with_keystore`.
                self.write_vault(&vault)?;
                self.cipher = Some(cipher.clone());
                self.recrypt_all(None, Some(&cipher)).context(
                    "the passphrase is set, but not every file could be encrypted; the rest \
                     are sealed the next time the directory is unlocked",
                )?;
                self.load_generations()
            }
        }
    }

    /// Forget the passphrase. With a key store at hand the files stay
    /// encrypted under a key kept there; otherwise they are stored
    /// unencrypted again. Says which happened.
    pub fn remove_passphrase(&mut self) -> anyhow::Result<Protection> {
        if self.protection() != Protection::Passphrase {
            bail!("no passphrase is set");
        }
        self.ensure_unlocked()?;
        let cipher = self
            .cipher
            .clone()
            .context("the data directory is locked")?;
        if crate::keystore::available() {
            let kdf = Kdf::keystore();
            let name = kdf.keystore_name();
            self.add_pending(&name)?;
            let kek = crate::keystore::create(&name)?;
            let anchor = self.anchor();
            let rotated =
                self.rotate_key(&cipher, |c| Ok(c.wrap_under_kek(&kek, kdf.clone(), anchor)));
            self.drop_unused_kek(&name);
            rotated?;
            return Ok(Protection::Keystore);
        }
        self.remove_protection()
    }

    /// Move the directory onto a fresh data key, `wrap` saying how the new
    /// key is to be kept.
    ///
    /// Changing the protection used to re-wrap the same data key, so an old
    /// copy of `vault.json` and the passphrase in force when it was taken
    /// went on opening everything written afterwards — including everything
    /// written after the user changed the passphrase because the old one had
    /// got out. The files are rewritten under a new key instead.
    ///
    /// The order is chosen so that a crash at any point leaves a directory
    /// that still opens: the vault written first names *both* keys, so a
    /// file rewritten and a file not yet rewritten are both readable, and
    /// only when the last one is done is the old key dropped from it.
    fn rotate_key(
        &mut self,
        old: &Arc<FileCipher>,
        wrap: impl Fn(&FileCipher) -> anyhow::Result<VaultFile>,
    ) -> anyhow::Result<()> {
        let rotating = Arc::new(old.rotating());
        self.write_vault(&wrap(&rotating)?)?;
        self.cipher = Some(rotating.clone());
        self.recrypt_all(Some(old), Some(&rotating)).context(
            "the protection changed, but not every file could be written under the new key; \
             the old key is kept in vault.json until they are",
        )?;
        let settled = Arc::new(rotating.settled());
        self.write_vault(&wrap(&settled)?)?;
        self.cipher = Some(settled);
        Ok(())
    }

    /// Store everything unencrypted again, whatever protected it.
    pub fn remove_protection(&mut self) -> anyhow::Result<Protection> {
        self.ensure_unlocked()?;
        let Some(vault) = self.read_vault()? else {
            return Ok(Protection::None);
        };
        let Some(cipher) = self.cipher.take() else {
            bail!("the data directory is locked");
        };
        self.recrypt_all(Some(&cipher), None)?;
        // Before the vault goes, since the vault is the only other record
        // that the key exists: a crash between the two used to leave a key
        // opening a copy of the directory taken while it was encrypted.
        let keystore_name = vault.kdf.is_keystore().then(|| vault.kdf.keystore_name());
        if let Some(name) = &keystore_name {
            self.add_pending(name)?;
        }
        fs::remove_file(self.root.join(VAULT_FILE)).context("removing vault.json")?;
        if let Some(name) = &keystore_name {
            // As in `set_passphrase_with`: the files are plain now, but the
            // key still opens a copy taken while they were not.
            crate::keystore::delete(name).context(
                "the files are stored unencrypted now, but the old key could not be taken out \
                 of the key store; remove it by hand",
            )?;
            self.clear_pending(name);
        }
        Ok(Protection::None)
    }

    fn ensure_unlocked(&self) -> anyhow::Result<()> {
        if self.is_locked() {
            bail!("the data directory is protected; unlock it first");
        }
        Ok(())
    }

    /// Rewrite every file from one cipher to another (`None` = plaintext).
    ///
    /// A file already in the state it should be in is rewritten all the
    /// same, so this is also how a directory is tidied after a protection
    /// that a crash cut short: `from` reads a plain file as itself, so
    /// running it with the same cipher on both sides seals whatever was
    /// left in the clear.
    fn recrypt_all(
        &self,
        from: Option<&FileCipher>,
        to: Option<&FileCipher>,
    ) -> anyhow::Result<()> {
        for name in recrypted_files() {
            let path = self.root.join(name);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path)?;
            // Keeps whichever generation the file already carries: a
            // rotation changes the key, not what was written.
            let (generation, plain) = match from {
                Some(c) if FileCipher::is_encrypted(&bytes) => {
                    let opened = c.open_file(name, &bytes)?;
                    (opened.generation, opened.plain.to_vec())
                }
                _ => (None, decode_file(from, name, &bytes)?),
            };
            let out = match (to, generation) {
                (Some(c), Some(at)) => c.encrypt_at(name, at, &plain),
                (to, _) => encode_file(to, name, &plain),
            };
            write_atomic(&path, &out)?;
        }
        // The record of those generations moves with them, or the new key
        // would open every file and not the one that says which version of
        // each is the right one. Bound to its name alone, so it needs no
        // generation of its own here.
        let state_path = self.root.join(STATE_FILE);
        if state_path.exists() {
            let bytes = fs::read(&state_path)?;
            let plain = decode_file(from, STATE_FILE, &bytes)?;
            match to {
                Some(c) => write_atomic(&state_path, &c.encrypt(STATE_FILE, &plain))?,
                // Going back to plaintext: there is nothing to bind a
                // generation into any more, so the record goes with the
                // encryption rather than being left readable.
                None => {
                    for name in [STATE_FILE, STATE_PREVIOUS_FILE] {
                        let path = self.root.join(name);
                        if path.exists() {
                            fs::remove_file(&path)?;
                        }
                    }
                    *self.generations.lock().unwrap_or_else(|e| e.into_inner()) =
                        Generations::Unbound;
                }
            }
        }
        // Files received while `encrypted_downloads` was on are bound to
        // their own name, not to a path under the data directory, and sit
        // beside plain ones, which stay as they are. On the way out they
        // are decrypted, since the key is about to be gone; on a rotation
        // they move onto the new key with everything else, or they would
        // be the one thing left behind when the old key is dropped.
        let downloads = self.downloads_dir();
        if (from.is_some() || to.is_some()) && downloads.exists() {
            for entry in fs::read_dir(&downloads)? {
                let path = entry?.path();
                if !path.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let bytes = fs::read(&path)?;
                if !FileCipher::is_encrypted(&bytes) {
                    continue;
                }
                let plain = decode_file(from, name, &bytes)?;
                write_atomic(&path, &encode_file(to, name, &plain))?;
            }
        }
        for entry in fs::read_dir(self.root.join(HISTORY_DIR))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let name = relative_name(&self.root, &path);
            let text = fs::read_to_string(&path)?;
            let mut out = String::new();
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let plain = decode_line(from, &name, line)?;
                out.push_str(&encode_line(to, &name, &plain));
                out.push('\n');
            }
            write_atomic(&path, out.as_bytes())?;
        }
        Ok(())
    }

    // --- files ---------------------------------------------------------------

    fn read_file(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.ensure_unlocked()?;
        let path = self.root.join(name);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let Some(cipher) = self.cipher.as_deref() else {
            return Ok(Some(decode_file(None, name, &bytes)?));
        };
        if !FileCipher::is_encrypted(&bytes) {
            // Left plain by a protection a crash cut short; `seal_stragglers`
            // takes care of it, and until then it reads as itself.
            return Ok(Some(bytes));
        }
        let generations = self.generations();
        if let Some(why) = generations.refusal() {
            bail!("{why}");
        }
        let opened = cipher.open_file(name, &bytes)?;
        // The generation the file carries is its own -- it is bound into
        // the tag, so it opened only because it is what was written -- and
        // the question here is whether it is the one that *should* have
        // been written.
        if let Some(state) = generations.state() {
            let acceptable = state.acceptable(name);
            if !opened.generation.is_some_and(|at| acceptable.contains(&at)) {
                bail!(
                    "{name} is not the version this directory last wrote ({}, where it should be \
                     {acceptable:?}): it has been replaced with another copy of itself, which is \
                     what the generation in the vault is there to catch. Nothing has been read \
                     from it.",
                    match opened.generation {
                        Some(at) => format!("generation {at}"),
                        None => "no generation at all".to_owned(),
                    }
                );
            }
        }
        Ok(Some(opened.plain.to_vec()))
    }

    /// Write one of the store's files whole. Every one of them is
    /// owner-only: `config.json` holds the proxy's credentials and the
    /// invite token, `contacts.json` and the history are the contact
    /// graph, and neither is anyone else's on a shared machine.
    ///
    /// With the directory protected, the write also raises the file's
    /// generation and records it, so that this version of the file is the
    /// only one that will be read back. The file is written **before** the
    /// record is: a crash between them leaves a file one generation ahead,
    /// which [`State::acceptable`] allows, where the other order would
    /// leave one behind — indistinguishable from an older copy put back.
    fn write_file(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.ensure_unlocked()?;
        let Some(cipher) = self.cipher.clone() else {
            return write_atomic(&self.root.join(name), bytes);
        };
        let mut generations = self.generations.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(why) = generations.refusal() {
            bail!("{why}");
        }
        let Generations::Bound(state) = &mut *generations else {
            let out = cipher.encrypt(name, bytes);
            return write_atomic(&self.root.join(name), &out);
        };
        let at = state.generation + 1;
        let out = cipher.encrypt_at(name, at, bytes);
        write_atomic(&self.root.join(name), &out)?;
        state.wrote(name, at);
        state.generation = at;
        let state = state.clone();
        drop(generations);
        self.persist_generations(&state, &cipher)
    }

    /// The generation `vault.json` should be pointing at, for a rewrite
    /// of the vault that is not itself a write of the directory.
    fn anchor(&self) -> Option<u64> {
        self.generations().state().map(|state| state.generation)
    }

    /// The generations as they stand, for a read.
    fn generations(&self) -> Generations {
        self.generations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Write `state` and then raise the anchor in `vault.json` to match.
    ///
    /// The previous `state` is kept beside it first, so an interrupted
    /// write has something to fall back to; see
    /// `docs/design/format-changes.md` section 5.5.
    fn persist_generations(&self, state: &State, cipher: &FileCipher) -> anyhow::Result<()> {
        let path = self.root.join(STATE_FILE);
        if path.exists() {
            let previous = self.root.join(STATE_PREVIOUS_FILE);
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            write_atomic(&previous, &bytes)?;
        }
        let bytes = serde_json::to_vec(state).context("encoding the file generations")?;
        // Bound to its own name only: what stops an older `state` being
        // read as this one is the generation inside it, checked against
        // the number in `vault.json`, which is the anchor everything else
        // hangs from.
        write_atomic(&path, &cipher.encrypt(STATE_FILE, &bytes))?;
        let mut vault = self
            .read_vault()?
            .context("the vault is gone; the directory cannot record what it wrote")?;
        vault.state_generation = Some(state.generation);
        self.write_vault(&vault)
    }

    pub(crate) fn read_json_or_default<T: Default + for<'de> Deserialize<'de>>(
        &self,
        name: &str,
    ) -> anyhow::Result<T> {
        match self.read_file(name)? {
            None => Ok(T::default()),
            Some(bytes) => {
                serde_json::from_slice(&bytes).with_context(|| format!("parsing {name}"))
            }
        }
    }

    /// A private (0600) JSON file, written whole.
    pub(crate) fn write_json_private<T: Serialize>(
        &self,
        name: &str,
        value: &T,
    ) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(value).with_context(|| format!("encoding {name}"))?;
        self.write_file(name, &bytes)
    }

    /// A private file's bytes, if it exists.
    pub(crate) fn read_private_file(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.read_file(name)
    }

    pub(crate) fn write_private_file(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.write_file(name, bytes)
    }

    // --- identity, config, contacts ------------------------------------------

    /// Load the identity from disk, generating and saving a new one if this
    /// is the first run. The boolean is `true` when a new identity was made.
    pub fn load_or_create_identity(&self) -> anyhow::Result<(Identity, bool)> {
        if let Some(bytes) = self.read_file(IDENTITY_FILE)? {
            let secrets: IdentitySecrets =
                serde_json::from_slice(&bytes).context("parsing identity.json")?;
            return Ok((Identity::from_secrets(&secrets), false));
        }
        let identity = Identity::generate();
        let text = serde_json::to_string_pretty(&identity.to_secrets())?;
        self.write_file(IDENTITY_FILE, text.as_bytes())?;
        Ok((identity, true))
    }

    pub fn has_identity(&self) -> bool {
        self.root.join(IDENTITY_FILE).exists()
    }

    /// Whether nothing but keys and settings is here: no contacts,
    /// requests, blocked ids, groups or history, and no link. Such a
    /// directory can still become a linked device of another identity.
    pub fn is_unused(&self) -> anyhow::Result<bool> {
        if self.load_linked()?.is_some()
            || !self.load_contacts()?.is_empty()
            || !self.load_requests()?.is_empty()
            || !self.load_blocked()?.is_empty()
            || self.has_groups()?
        {
            return Ok(false);
        }
        let history = self.root.join(HISTORY_DIR);
        if history.exists() {
            for entry in fs::read_dir(&history)? {
                if entry?.path().extension().and_then(|e| e.to_str()) == Some("jsonl") {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// What `identity.json` says under `linked`: on a linked device, the
    /// account and this key's certificate; nothing on a primary.
    pub fn load_linked(&self) -> anyhow::Result<Option<Linked>> {
        #[derive(Deserialize)]
        struct IdentityFile {
            #[serde(default)]
            linked: Option<Linked>,
        }
        match self.read_file(IDENTITY_FILE)? {
            None => Ok(None),
            Some(bytes) => {
                let file: IdentityFile =
                    serde_json::from_slice(&bytes).context("parsing identity.json")?;
                Ok(file.linked)
            }
        }
    }

    /// Write `linked` into `identity.json` next to the keys (`None` takes
    /// it out), leaving everything else in the file as it was.
    pub fn save_linked(&self, linked: Option<&Linked>) -> anyhow::Result<()> {
        let bytes = self
            .read_file(IDENTITY_FILE)?
            .context("there is no identity to link")?;
        let mut file: serde_json::Value =
            serde_json::from_slice(&bytes).context("parsing identity.json")?;
        let object = file
            .as_object_mut()
            .context("identity.json is not an object")?;
        match linked {
            Some(linked) => {
                object.insert("linked".into(), serde_json::to_value(linked)?);
            }
            None => {
                object.remove("linked");
            }
        }
        let text = serde_json::to_string_pretty(&file)?;
        self.write_file(IDENTITY_FILE, text.as_bytes())
    }

    /// The account's devices as this device last knew them.
    pub fn load_devices(&self) -> anyhow::Result<DevicesFile> {
        self.read_json_or_default(DEVICES_FILE)
    }

    pub fn save_devices(&self, devices: &DevicesFile) -> anyhow::Result<()> {
        self.write_file(
            DEVICES_FILE,
            serde_json::to_string_pretty(devices)?.as_bytes(),
        )
    }

    /// Overwrite the identity, e.g. when restoring a backup.
    pub fn save_identity(&self, identity: &Identity) -> anyhow::Result<()> {
        let text = serde_json::to_string_pretty(&identity.to_secrets())?;
        self.write_file(IDENTITY_FILE, text.as_bytes())
    }

    /// Load the pre-signed revocation certificate, minting and saving one for
    /// `identity` on first call. It is signed once, while the key is still
    /// present, and kept aside so the identity can be declared dead even after
    /// the private key is lost. `created_at_ms` stamps a freshly minted one.
    pub fn load_or_create_revocation(
        &self,
        identity: &Identity,
        created_at_ms: u64,
    ) -> anyhow::Result<Revocation> {
        if let Some(existing) = self.revocation()? {
            if existing.identity == identity.user_id() {
                return Ok(existing);
            }
            // The stored certificate is for a different key (a restored or
            // rotated identity): mint a fresh one below.
        }
        let revocation = identity.revocation(created_at_ms);
        self.save_revocation(&revocation)?;
        Ok(revocation)
    }

    /// The stored revocation certificate, if one has been minted.
    pub fn revocation(&self) -> anyhow::Result<Option<Revocation>> {
        match self.read_file(REVOCATION_FILE)? {
            None => Ok(None),
            Some(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("parsing revocation.json")?,
            )),
        }
    }

    /// Store a revocation certificate, e.g. when restoring a backup.
    pub fn save_revocation(&self, revocation: &Revocation) -> anyhow::Result<()> {
        let text = serde_json::to_string_pretty(revocation)?;
        self.write_file(REVOCATION_FILE, text.as_bytes())
    }

    // --- prekeys and sessions ------------------------------------------------

    pub(crate) fn load_prekeys(&self) -> anyhow::Result<PrekeyFile> {
        self.read_json_or_default(PREKEYS_FILE)
    }

    pub(crate) fn save_prekeys(&self, prekeys: &PrekeyFile) -> anyhow::Result<()> {
        self.write_file(PREKEYS_FILE, &serde_json::to_vec(prekeys)?)
    }

    pub(crate) fn load_sessions(&self) -> anyhow::Result<SessionsFile> {
        self.read_json_or_default(SESSIONS_FILE)
    }

    pub(crate) fn save_sessions(&self, sessions: &SessionsFile) -> anyhow::Result<()> {
        self.write_file(SESSIONS_FILE, &serde_json::to_vec(sessions)?)
    }

    /// Delete prekeys and sessions, e.g. when the identity is replaced.
    pub fn clear_sessions(&self) -> anyhow::Result<()> {
        for name in [PREKEYS_FILE, SESSIONS_FILE] {
            let path = self.root.join(name);
            if path.exists() {
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            }
        }
        Ok(())
    }

    /// Erase the keys, the contacts, the history and everything else that
    /// belongs to the identity, keeping the settings and the files saved
    /// in `downloads/`: what a device does once it is unlinked.
    pub fn wipe(&self) -> anyhow::Result<()> {
        // Read before the vault goes: it names the key store entry, and
        // that key has to go too. A wipe that left it behind left an
        // extractable key beside a directory somebody may have copied
        // first, so the copy went on opening long after the erase.
        let keystore_entry = self
            .read_vault()
            .ok()
            .flatten()
            .filter(|vault| vault.kdf.is_keystore())
            .map(|vault| vault.kdf.keystore_name());
        // Noted before the vault naming it goes, so a wipe that dies partway
        // through still has the key taken out on the next start rather than
        // leaving it beside whatever copy was made first.
        if let Some(name) = &keystore_entry {
            let _ = self.add_pending(name);
        }
        // `silver.log` goes with the rest. It is written only when
        // SILVER_LOG asks for it, it is outside the data key, and at
        // `debug` it names envelope ids, contact ids and the relay: a
        // device that has just erased its keys should not be left holding
        // a record of who it talked to.
        // `silver.log.1` with it: the log is rolled over rather than left
        // to grow, so the older half is the same record of who this
        // device talked to and would otherwise survive the erase.
        for name in IDENTITY_FILES
            .iter()
            .copied()
            // The record of what this directory last wrote goes with the
            // directory: it names every file and, once history is in it,
            // every conversation.
            .chain([
                VAULT_FILE,
                LOG_FILE,
                ROLLED_LOG_FILE,
                STATE_FILE,
                STATE_PREVIOUS_FILE,
            ])
        {
            let path = self.root.join(name);
            if path.exists() {
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            }
        }
        let history = self.root.join(HISTORY_DIR);
        if history.exists() {
            for entry in fs::read_dir(&history)? {
                let path = entry?.path();
                if path.is_file() {
                    fs::remove_file(&path)
                        .with_context(|| format!("removing {}", path.display()))?;
                }
            }
        }
        // Last, so that a failure earlier leaves a directory whose key is
        // still where its vault says. A key store that cannot be reached
        // is not worth failing the wipe over: the files are already gone.
        if let Some(name) = keystore_entry {
            if crate::keystore::delete(&name).is_ok() {
                self.clear_pending(&name);
            }
        }
        Ok(())
    }

    pub fn load_config(&self) -> anyhow::Result<Config> {
        self.read_json_or_default(CONFIG_FILE)
    }

    pub fn save_config(&self, config: &Config) -> anyhow::Result<()> {
        self.write_file(
            CONFIG_FILE,
            serde_json::to_string_pretty(config)?.as_bytes(),
        )
    }

    /// The epoch this installation numbers outgoing messages with, created
    /// and saved on first use.
    pub fn ensure_send_epoch(&self, config: &mut Config) -> anyhow::Result<u64> {
        if let Some(epoch) = config.send_epoch {
            return Ok(epoch);
        }
        let epoch = loop {
            let candidate: u64 = rand::random();
            if candidate != 0 {
                break candidate;
            }
        };
        config.send_epoch = Some(epoch);
        self.save_config(config)?;
        Ok(epoch)
    }

    pub fn load_contacts(&self) -> anyhow::Result<Vec<Contact>> {
        self.read_json_or_default(CONTACTS_FILE)
    }

    pub fn save_contacts(&self, contacts: &[Contact]) -> anyhow::Result<()> {
        self.write_file(
            CONTACTS_FILE,
            serde_json::to_string_pretty(contacts)?.as_bytes(),
        )
    }

    // --- contact requests and blocking ------------------------------------------

    pub fn load_requests(&self) -> anyhow::Result<Vec<ContactRequest>> {
        self.read_json_or_default(REQUESTS_FILE)
    }

    pub fn save_requests(&self, requests: &[ContactRequest]) -> anyhow::Result<()> {
        self.write_file(
            REQUESTS_FILE,
            serde_json::to_string_pretty(requests)?.as_bytes(),
        )
    }

    pub fn load_declined(&self) -> anyhow::Result<Vec<Declined>> {
        self.read_json_or_default(DECLINED_FILE)
    }

    pub fn save_declined(&self, declined: &[Declined]) -> anyhow::Result<()> {
        self.write_file(
            DECLINED_FILE,
            serde_json::to_string_pretty(declined)?.as_bytes(),
        )
    }

    pub fn load_blocked(&self) -> anyhow::Result<Vec<UserId>> {
        self.read_json_or_default(BLOCKED_FILE)
    }

    pub fn save_blocked(&self, blocked: &[UserId]) -> anyhow::Result<()> {
        self.write_file(
            BLOCKED_FILE,
            serde_json::to_string_pretty(blocked)?.as_bytes(),
        )
    }

    // --- history ---------------------------------------------------------------

    pub fn append_history(&self, peer: &UserId, entry: &HistoryEntry) -> anyhow::Result<()> {
        self.append_history_line(&history_name(peer), &serde_json::to_string(entry)?)
    }

    /// A group's conversation log, kept like a contact's under
    /// `history/group-<id>.jsonl`.
    pub fn append_group_history(
        &self,
        group: &silver_protocol::GroupId,
        entry: &HistoryEntry,
    ) -> anyhow::Result<()> {
        self.append_history_line(&group_history_name(group), &serde_json::to_string(entry)?)
    }

    /// [`Store::append_text`] for a group's log.
    pub fn append_group_text(
        &self,
        group: &silver_protocol::GroupId,
        id: &str,
        text: &str,
        saved: Option<&Path>,
    ) -> anyhow::Result<()> {
        let line = TextLine {
            update: id.to_owned(),
            text: text.to_owned(),
            saved: saved.map(Path::to_path_buf),
        };
        self.append_history_line(&group_history_name(group), &serde_json::to_string(&line)?)
    }

    /// [`Store::load_history`] for a group's log.
    pub fn load_group_history(
        &self,
        group: &silver_protocol::GroupId,
    ) -> anyhow::Result<Vec<HistoryEntry>> {
        self.load_history_named(&Conversation::Group(*group))
    }

    /// Record that the peer returned a receipt for messages we sent.
    pub fn append_receipt(
        &self,
        peer: &UserId,
        receipt: ReceiptKind,
        ids: &[String],
        at_ms: u64,
    ) -> anyhow::Result<()> {
        let line = ReceiptLine {
            receipt,
            ids: ids.to_vec(),
            at_ms,
        };
        self.append_history_line(&history_name(peer), &serde_json::to_string(&line)?)
    }

    /// Replace the text of the entry `id` from now on; the original line
    /// stays in the file.
    pub fn append_text(
        &self,
        peer: &UserId,
        id: &str,
        text: &str,
        saved: Option<&Path>,
    ) -> anyhow::Result<()> {
        let line = TextLine {
            update: id.to_owned(),
            text: text.to_owned(),
            saved: saved.map(Path::to_path_buf),
        };
        self.append_history_line(&history_name(peer), &serde_json::to_string(&line)?)
    }

    fn append_history_line(&self, name: &str, json: &str) -> anyhow::Result<()> {
        self.ensure_unlocked()?;
        let path = self.root.join(name);
        let mut file = append_private(&path)?;
        let mut line = encode_line(self.cipher.as_deref(), name, json);
        line.push('\n');
        // A line cut short by a crash has no newline; start a fresh one
        // rather than glue this line onto it and lose both.
        if !ends_with_newline(&mut file)? {
            line.insert(0, '\n');
        }
        file.write_all(line.as_bytes())?;
        Ok(())
    }

    /// Move the conversation log from `old` to `new`, for example when a
    /// contact rotates to a successor identity. Each line is decoded under the
    /// old file's name and re-encoded under the new one, because the file name
    /// is bound into the at-rest encryption. Any log already at `new` is kept
    /// and the migrated lines appended after it.
    pub fn migrate_history(&self, old: &UserId, new: &UserId) -> anyhow::Result<()> {
        self.ensure_unlocked()?;
        if old == new {
            return Ok(());
        }
        let old_name = history_name(old);
        let old_path = self.root.join(&old_name);
        if !old_path.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&old_path)
            .with_context(|| format!("reading {}", old_path.display()))?;
        let new_name = history_name(new);
        let new_path = self.root.join(&new_name);
        let mut out = append_private(&new_path)?;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let plain = decode_line(self.cipher.as_deref(), &old_name, line)?;
            let mut encoded = encode_line(self.cipher.as_deref(), &new_name, &plain);
            encoded.push('\n');
            out.write_all(encoded.as_bytes())?;
        }
        out.flush()?;
        fs::remove_file(&old_path).with_context(|| format!("removing {}", old_path.display()))?;
        Ok(())
    }

    /// The conversation with `peer`, receipts applied to the entries they
    /// refer to.
    pub fn load_history(&self, peer: &UserId) -> anyhow::Result<Vec<HistoryEntry>> {
        self.load_history_named(&Conversation::Contact(*peer))
    }

    /// A conversation's log, whichever kind it is.
    pub fn load_conversation(
        &self,
        conversation: &Conversation,
    ) -> anyhow::Result<Vec<HistoryEntry>> {
        self.load_history_named(conversation)
    }

    /// Every line of a history file, decoded; unreadable lines are kept as
    /// they are (`Err`), so a rewrite loses nothing it does not understand.
    fn read_history_lines(&self, name: &str) -> anyhow::Result<Vec<Result<HistoryLine, String>>> {
        self.ensure_unlocked()?;
        let path = self.root.join(name);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let mut lines = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parsed = decode_line(self.cipher.as_deref(), name, line)
                .and_then(|plain| serde_json::from_str::<HistoryLine>(&plain).map_err(Into::into));
            match parsed {
                Ok(parsed) => lines.push(Ok(parsed)),
                Err(e) => {
                    tracing::warn!("keeping an unreadable history line in {name} as it is: {e:#}");
                    lines.push(Err(line.to_owned()));
                }
            }
        }
        Ok(lines)
    }

    /// The entries of a history file with every update applied. The entry
    /// lines are taken first and the update lines after, in their order,
    /// so an update that stands before its entry in the file (a group's
    /// crossed fan-out) applies all the same; a `gone` line removes its
    /// entry wherever the entry stands. An edit applies only to a message
    /// its sender wrote, whichever came first.
    fn load_history_named(&self, conversation: &Conversation) -> anyhow::Result<Vec<HistoryEntry>> {
        let lines = self.read_history_lines(&conversation.file_name())?;
        let mut entries: Vec<HistoryEntry> = Vec::new();
        let mut updates = Vec::new();
        for line in lines.into_iter().flatten() {
            match line {
                HistoryLine::Entry(entry) => entries.push(*entry),
                update => updates.push(update),
            }
        }
        for update in updates {
            match update {
                HistoryLine::Entry(_) => unreachable!("entries were taken first"),
                HistoryLine::Receipt(receipt) => {
                    for entry in entries.iter_mut().filter(|e| receipt.ids.contains(&e.id)) {
                        if entry.receipt.is_none_or(|r| r < receipt.receipt) {
                            entry.receipt = Some(receipt.receipt);
                        }
                    }
                }
                HistoryLine::Text(update) => {
                    if let Some(entry) = revisable(&mut entries, &update.update) {
                        entry.text = update.text;
                        if update.saved.is_some() {
                            entry.saved = update.saved;
                        }
                    }
                }
                HistoryLine::Read(read) => {
                    for entry in entries.iter_mut().filter(|e| read.read.contains(&e.id)) {
                        // The first showing starts the clock; a later one
                        // (a sibling's, say) does not restart it.
                        if entry.read_at_ms.is_none() {
                            entry.read_at_ms = Some(read.at_ms);
                        }
                    }
                }
                HistoryLine::Edit(edit) => {
                    if let Some(entry) = revisable(&mut entries, &edit.edit)
                        && author_of(entry, conversation) == edit.from
                    {
                        let old = std::mem::replace(&mut entry.text, edit.text);
                        entry.previous.push(old);
                        entry.edited = true;
                    }
                }
                HistoryLine::React(react) => {
                    if let Some(entry) = revisable(&mut entries, &react.react) {
                        entry.reactions.retain(|r| r.from != react.from);
                        if !react.emoji.is_empty() {
                            entry.reactions.push(Reaction {
                                from: react.from,
                                emoji: react.emoji,
                            });
                        }
                    }
                }
                HistoryLine::Gone(gone) => entries.retain(|e| {
                    e.id != gone.gone
                        || gone
                            .from
                            .is_some_and(|by| author_of(e, conversation) != Some(by))
                }),
            }
        }
        Ok(entries)
    }

    /// Write `lines` as the whole of a history file, under the same name
    /// binding, atomically (beside, then over).
    fn write_history_lines(
        &self,
        name: &str,
        lines: &[Result<HistoryLine, String>],
    ) -> anyhow::Result<()> {
        self.ensure_unlocked()?;
        let mut out = String::new();
        for line in lines {
            match line {
                Ok(parsed) => {
                    let json = serde_json::to_string(parsed)?;
                    out.push_str(&encode_line(self.cipher.as_deref(), name, &json));
                }
                Err(raw) => out.push_str(raw),
            }
            out.push('\n');
        }
        write_atomic(&self.root.join(name), out.as_bytes())
    }

    // --- section 4.7: read marks, edits, reactions, deletions ------------------

    /// Note that the messages `ids` were shown at `at_ms`, from when a
    /// received message's timer runs.
    pub fn append_read(
        &self,
        conversation: &Conversation,
        ids: &[String],
        at_ms: u64,
    ) -> anyhow::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let line = ReadLine {
            read: ids.to_vec(),
            at_ms,
        };
        self.append_history_line(&conversation.file_name(), &serde_json::to_string(&line)?)
    }

    /// The message `id` says `text` from now on, by the edit `edit_id`
    /// that `from` (`None`: oneself) made at `at_ms`; the earlier text
    /// stays in the file. The edit applies, now or when the message
    /// arrives, only if `from` wrote the message.
    pub fn append_edit(
        &self,
        conversation: &Conversation,
        id: &str,
        text: &str,
        edit_id: &str,
        at_ms: u64,
        from: Option<UserId>,
    ) -> anyhow::Result<()> {
        let line = EditLine {
            edit: id.to_owned(),
            text: text.to_owned(),
            edit_id: edit_id.to_owned(),
            at_ms,
            from,
        };
        self.append_history_line(&conversation.file_name(), &serde_json::to_string(&line)?)
    }

    /// `from`'s reaction to the message `id` (`None`: one's own); an empty
    /// `emoji` withdraws it.
    pub fn append_reaction(
        &self,
        conversation: &Conversation,
        id: &str,
        from: Option<UserId>,
        emoji: &str,
    ) -> anyhow::Result<()> {
        let line = ReactLine {
            react: id.to_owned(),
            from,
            emoji: emoji.to_owned(),
        };
        self.append_history_line(&conversation.file_name(), &serde_json::to_string(&line)?)
    }

    /// Remove the messages `ids` from the file for good ("delete for me",
    /// or a timer that ran out): the file is rewritten without their
    /// entries and without the lines about them, and a `gone` line per id
    /// is left so that a line naming one of them later counts for
    /// nothing. Returns the entries as they stood, so the caller can say
    /// what went. A conversation without a file is left without one: a
    /// tombstone is not worth a history file for a conversation there
    /// never was.
    pub fn remove_messages(
        &self,
        conversation: &Conversation,
        ids: &[String],
    ) -> anyhow::Result<Vec<HistoryEntry>> {
        let name = conversation.file_name();
        if !self.root.join(&name).exists() {
            return Ok(Vec::new());
        }
        let before = self.load_history_named(conversation)?;
        let removed: Vec<HistoryEntry> =
            before.into_iter().filter(|e| ids.contains(&e.id)).collect();
        let mut lines: Vec<Result<HistoryLine, String>> = self
            .read_history_lines(&name)?
            .into_iter()
            .filter_map(|line| match line {
                Ok(HistoryLine::Receipt(mut r)) => {
                    r.ids.retain(|i| !ids.contains(i));
                    (!r.ids.is_empty()).then_some(Ok(HistoryLine::Receipt(r)))
                }
                Ok(HistoryLine::Read(mut r)) => {
                    r.read.retain(|i| !ids.contains(i));
                    (!r.read.is_empty()).then_some(Ok(HistoryLine::Read(r)))
                }
                Ok(parsed) => (!ids.iter().any(|id| parsed.names(id))).then_some(Ok(parsed)),
                Err(raw) => Some(Err(raw)),
            })
            .collect();
        for id in ids {
            lines.push(Ok(HistoryLine::Gone(GoneLine {
                gone: id.clone(),
                from: None,
            })));
        }
        self.write_history_lines(&name, &lines)?;
        Ok(removed)
    }

    /// `from` (`None`: oneself) deleted the message `id` for everyone: its
    /// entry, if `from` wrote it, becomes a placeholder without text,
    /// file, earlier texts or reactions, and the lines that edited it or
    /// reacted to it go. When the message is not held (not arrived, or
    /// removed), a `gone` line naming `from` is left so that a late
    /// arrival of `from`'s counts for nothing. An entry someone else
    /// wrote is left alone.
    pub fn mark_deleted(
        &self,
        conversation: &Conversation,
        id: &str,
        from: Option<UserId>,
    ) -> anyhow::Result<Deletion> {
        Ok(self.mark_all_deleted(conversation, &[id.to_owned()], from)?[0])
    }

    /// [`Store::mark_deleted`] for a whole `delete` body at once.
    ///
    /// One body carries up to 64 ids and each used to read, filter and
    /// rewrite the whole file, so a member could make a victim rewrite
    /// its history sixty-four times per message. It is one pass now.
    ///
    /// An id the history does not hold leaves nothing behind on disk. A
    /// tombstone used to be appended for it, so that a message arriving
    /// later would still be removed — and an id nobody has ever seen is
    /// free to invent, which made a permanent line per invented id. The
    /// front end holds such deletions in its own bounded list instead,
    /// for the ten minutes in which the message might still turn up; a
    /// deletion that arrives before its message *and* is followed by a
    /// restart no longer catches it, which is the narrow case the DoS
    /// cost more than it was worth.
    pub fn mark_all_deleted(
        &self,
        conversation: &Conversation,
        ids: &[String],
        from: Option<UserId>,
    ) -> anyhow::Result<Vec<Deletion>> {
        let name = conversation.file_name();
        let lines = self.read_history_lines(&name)?;
        let authors: HashMap<&str, Option<UserId>> = lines
            .iter()
            .filter_map(|line| match line {
                Ok(HistoryLine::Entry(entry)) if ids.contains(&entry.id) => {
                    Some((entry.id.as_str(), author_of(entry, conversation)))
                }
                _ => None,
            })
            .collect();
        let outcome: Vec<Deletion> = ids
            .iter()
            .map(|id| match authors.get(id.as_str()) {
                Some(author) if *author != from => Deletion::Refused,
                Some(_) => Deletion::Applied,
                None => Deletion::Tombstoned,
            })
            .collect();
        let going: Vec<&str> = ids
            .iter()
            .zip(&outcome)
            .filter(|(_, out)| **out == Deletion::Applied)
            .map(|(id, _)| id.as_str())
            .collect();
        if going.is_empty() {
            return Ok(outcome);
        }
        let lines: Vec<Result<HistoryLine, String>> = lines
            .into_iter()
            .filter_map(|line| match line {
                Ok(HistoryLine::Entry(mut entry)) if going.contains(&entry.id.as_str()) => {
                    entry.text.clear();
                    entry.file = None;
                    entry.saved = None;
                    entry.reply_to = None;
                    entry.edited = false;
                    entry.previous.clear();
                    entry.reactions.clear();
                    entry.deleted = true;
                    Some(Ok(HistoryLine::Entry(entry)))
                }
                Ok(HistoryLine::Edit(e)) if going.contains(&e.edit.as_str()) => None,
                Ok(HistoryLine::React(r)) if going.contains(&r.react.as_str()) => None,
                Ok(HistoryLine::Text(t)) if going.contains(&t.update.as_str()) => None,
                other => Some(other),
            })
            .collect();
        self.write_history_lines(&name, &lines)?;
        Ok(outcome)
    }

    /// Every conversation that has a log, from the history directory's
    /// file names.
    pub fn conversations(&self) -> anyhow::Result<Vec<Conversation>> {
        let dir = self.root.join(HISTORY_DIR);
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let name = entry?.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".jsonl")) else {
                continue;
            };
            if let Some(group) = stem.strip_prefix("group-") {
                if let Ok(group) = group.parse() {
                    out.push(Conversation::Group(group));
                }
            } else if let Ok(peer) = stem.parse() {
                out.push(Conversation::Contact(peer));
            }
        }
        out.sort_by_key(|c| c.file_name());
        Ok(out)
    }

    /// Where the client keeps not-yet-accepted outgoing envelopes.
    pub fn outbox_path(&self) -> PathBuf {
        self.root.join(OUTBOX_FILE)
    }

    /// Where the relay's transparency log, as replayed, is kept.
    pub fn transparency_path(&self) -> PathBuf {
        self.root.join(TRANSPARENCY_FILE)
    }

    /// Where received files are saved.
    pub fn downloads_dir(&self) -> PathBuf {
        self.root.join("downloads")
    }
}

/// The entry an edit or a reaction applies to: the latest with that id
/// (a duplicate is the same message twice, and the last one shows), and
/// none at all once the entry is deleted for everyone.
fn revisable<'a>(entries: &'a mut [HistoryEntry], id: &str) -> Option<&'a mut HistoryEntry> {
    entries
        .iter_mut()
        .rev()
        .find(|e| e.id == id)
        .filter(|e| !e.deleted)
}

fn history_name(peer: &UserId) -> String {
    format!("{HISTORY_DIR}/{peer}.jsonl")
}

fn group_history_name(group: &silver_protocol::GroupId) -> String {
    format!("{HISTORY_DIR}/group-{group}.jsonl")
}

fn relative_name(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Plaintext of a whole file, accepting unencrypted legacy content.
fn decode_file(cipher: Option<&FileCipher>, name: &str, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    if FileCipher::is_encrypted(bytes) {
        match cipher {
            Some(c) => Ok(c.decrypt(name, bytes)?.to_vec()),
            None => bail!("{name} is encrypted but the data directory is not unlocked"),
        }
    } else {
        Ok(bytes.to_vec())
    }
}

fn encode_file(cipher: Option<&FileCipher>, name: &str, plain: &[u8]) -> Vec<u8> {
    match cipher {
        Some(c) => c.encrypt(name, plain),
        None => plain.to_vec(),
    }
}

fn decode_line(cipher: Option<&FileCipher>, name: &str, line: &str) -> anyhow::Result<String> {
    if line.starts_with(LINE_PREFIX) {
        match cipher {
            Some(c) => c.decrypt_line(name, line),
            None => bail!("{name} is encrypted but the data directory is not unlocked"),
        }
    } else {
        Ok(line.to_owned())
    }
}

fn encode_line(cipher: Option<&FileCipher>, name: &str, plain: &str) -> String {
    match cipher {
        Some(c) => c.encrypt_line(name, plain),
        None => plain.to_owned(),
    }
}

/// The first few bytes of a file, for telling an encrypted one from a
/// plain one without reading it all.
fn head_of(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut file = File::open(path)?;
    let mut head = [0u8; 8];
    let read = file.read(&mut head)?;
    Ok(head[..read].to_vec())
}

/// Whether `file` is empty or ends with a newline. Reads the last byte;
/// an append goes to the end whatever the position after.
fn ends_with_newline(file: &mut File) -> std::io::Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    if file.metadata()?.len() == 0 {
        return Ok(true);
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    Ok(last[0] == b'\n')
}

/// Open a file for writing, owner-only on Unix. Every file this program
/// writes goes through here: what is in the data directory is nobody
/// else's business even when it is encrypted, and on a machine with no
/// key store and no passphrase it is not encrypted at all.
pub(crate) fn create_private(path: &Path) -> anyhow::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("creating {}", path.display()))
}

/// Open a file to append to, readable, owner-only on Unix, created if it
/// is not there.
fn append_private(path: &Path) -> anyhow::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("opening {}", path.display()))
}

/// Make a directory, owner-only on Unix, and tighten it if it is already
/// there under wider modes — which it will be for anyone upgrading from
/// before 0.11.0, when the directory was made at the umask's mercy.
///
/// Only a directory this program owns is tightened: `guard` names a file
/// or directory that only Silver Messenger puts there. Without that a
/// `--data-dir ~` would take the user's home directory to 0700 with it.
pub(crate) fn create_private_dir(path: &Path, guard: Option<&str>) -> anyhow::Result<()> {
    let existed = path.exists();
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ours = !existed || guard.is_none_or(|g| path.join(g).exists());
        if ours && let Ok(meta) = fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & !0o077));
            }
        }
    }
    let _ = (existed, guard);
    Ok(())
}

/// Write via a temp file + rename so a crash never leaves a half-written
/// file, the temp file synced first so the name never points at an empty
/// one after a power loss, and created owner-only.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    // The temp file's name carries this process's id. Two clients on one
    // data directory is not a supported way to run — they interleave
    // history appends whatever the names are — but with a shared `.tmp`
    // they also write over each other's half-written file and rename the
    // result into place, which turns "the two disagree" into "the file is
    // neither one's".
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = create_private(&tmp)?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", tmp.display()))?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    // The contents were synced, the name that reaches them was not: a
    // rename is a change to the directory, and until that is synced a crash
    // can leave the old name (or no name) with the new bytes safely on
    // disk. It matters most for `vault.pending`, whose whole purpose is to
    // be readable after a crash, and for `vault.json`, which is what says
    // whether the key store's key is still needed.
    sync_parent(path);
    Ok(())
}

/// Flush the directory entry a `rename` just made. Best effort: a file
/// system that will not sync a directory handle (some do not) is not a
/// reason to fail a write that has otherwise succeeded.
fn sync_parent(path: &Path) {
    if let Some(dir) = path.parent()
        && let Ok(handle) = fs::File::open(dir)
    {
        let _ = handle.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Store::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn an_append_after_a_line_cut_short_starts_a_fresh_line() {
        let (store, dir) = temp_store();
        let peer = Identity::generate().user_id();
        store.append_history(&peer, &entry(0)).unwrap();
        // A crash in the middle of a write leaves the file without its
        // final newline.
        let path = dir.path().join(history_name(&peer));
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"id\":\"1\",\"dir").unwrap();
        drop(file);
        store.append_history(&peer, &entry(2)).unwrap();
        let ids: Vec<String> = store
            .load_history(&peer)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(
            ids,
            ["0", "2"],
            "the cut line is skipped, the next one is whole"
        );
    }

    /// The data directory and everything in it are the owner's alone. It
    /// holds the proxy's credentials, the invite token, the contact list
    /// and the history, and on a machine with no key store and no
    /// passphrase it holds them in the clear.
    #[cfg(unix)]
    #[test]
    fn nothing_in_the_data_directory_is_anyone_elses() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        // As an upgrade finds it: made by an older version at the umask.
        fs::create_dir_all(root.join(HISTORY_DIR)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

        let store = Store::open(&root).unwrap();
        let peer = Identity::generate().user_id();
        store.load_or_create_identity().unwrap();
        store.save_config(&Config::default()).unwrap();
        store.append_history(&peer, &entry(0)).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700, "the directory itself");
        for name in [IDENTITY_FILE, CONFIG_FILE, HISTORY_DIR] {
            let path = root.join(name);
            assert_eq!(mode(&path) & 0o077, 0, "{name} is readable by others");
        }
        assert_eq!(mode(&root.join(history_name(&peer))) & 0o077, 0);

        // A directory that is not ours is left as it is: --data-dir could
        // name anything, and tightening someone's home directory with it
        // would be the program's doing, not theirs.
        let theirs = dir.path().join("theirs");
        fs::create_dir_all(&theirs).unwrap();
        fs::set_permissions(&theirs, fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir(&theirs, Some("identity.json")).unwrap();
        assert_eq!(mode(&theirs), 0o755);
    }

    /// A crash in the middle of a key rotation leaves both keys in the
    /// vault, so nothing is lost; the next unlock finishes the move and
    /// drops the old key.
    #[test]
    fn a_rotation_cut_short_is_finished_on_the_next_unlock() {
        let (mut store, dir) = temp_store();
        let peer = Identity::generate().user_id();
        store.load_or_create_identity().unwrap();
        store.append_history(&peer, &entry(0)).unwrap();
        store.set_passphrase_with("first", Kdf::fast()).unwrap();

        // The state a crash between the two writes leaves: the vault names
        // both keys and the files are still under the old one.
        let old = store.cipher().unwrap();
        let rotating = Arc::new(old.rotating());
        let vault = rotating
            .wrap_under_passphrase("first", Kdf::fast(), None)
            .unwrap();
        store.write_vault(&vault).unwrap();
        assert!(store.read_vault().unwrap().unwrap().previous_key.is_some());
        let stale = fs::read(dir.path().join(IDENTITY_FILE)).unwrap();

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock("first").unwrap();
        assert_eq!(again.load_history(&peer).unwrap().len(), 1);
        // Finished: one key in the vault, and the files under it.
        assert!(again.read_vault().unwrap().unwrap().previous_key.is_none());
        let fresh = fs::read(dir.path().join(IDENTITY_FILE)).unwrap();
        assert_ne!(fresh, stale);
        assert!(old.decrypt(IDENTITY_FILE, &fresh).is_err());
        let mut third = Store::open(dir.path()).unwrap();
        third.unlock("first").unwrap();
        assert_eq!(third.load_history(&peer).unwrap().len(), 1);
    }

    // --- rollback binding ---------------------------------------------------

    /// A directory protected by the key store, with generations adopted
    /// and a couple of writes behind it.
    fn bound_store() -> (Store, tempfile::TempDir) {
        crate::keystore::use_mock_store();
        let (mut store, dir) = temp_store();
        store.load_or_create_identity().unwrap();
        store.protect_with_keystore().unwrap();
        (store, dir)
    }

    /// The finding SM-C-24 is about: somebody with write access to a live
    /// directory puts back an older `sessions.json`, so the next send
    /// reuses ratchet state that has already been used.
    #[test]
    fn an_older_copy_of_a_file_put_back_is_refused_rather_than_read() {
        let (store, dir) = bound_store();
        let path = dir.path().join(CONTACTS_FILE);

        let peer = Identity::generate();
        store
            .save_contacts(&[Contact::new(peer.user_id())])
            .unwrap();
        let older = fs::read(&path).unwrap();
        // Something changes -- a key-change warning, a `verified` mark --
        // and the file moves on.
        store.save_contacts(&[]).unwrap();
        assert!(store.load_contacts().unwrap().is_empty());

        // The old copy goes back. It has the right name and the right
        // key, and until generations it read as the current file.
        fs::write(&path, &older).unwrap();
        let err = store.load_contacts().unwrap_err().to_string();
        assert!(
            err.contains("not the version this directory last wrote"),
            "an older copy was accepted: {err}"
        );
    }

    /// The other direction: the anchor put back while the files move on.
    /// Every file is then further ahead than one interrupted write, which
    /// is the same tampering seen from the other side.
    #[test]
    fn an_older_record_of_what_was_written_is_refused_too() {
        let (store, dir) = bound_store();
        let vault_path = dir.path().join(VAULT_FILE);
        let state_path = dir.path().join(STATE_FILE);
        let old_vault = fs::read(&vault_path).unwrap();
        let old_state = fs::read(&state_path).unwrap();

        // Several writes on, so the anchor is well past where it was.
        for _ in 0..4 {
            store.save_contacts(&[]).unwrap();
        }
        fs::write(&vault_path, &old_vault).unwrap();
        fs::write(&state_path, &old_state).unwrap();
        // `state.prev` is one behind the state that was just replaced, so
        // it is not a way back in either.
        let _ = fs::remove_file(dir.path().join(STATE_PREVIOUS_FILE));

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        let err = again.load_contacts().unwrap_err().to_string();
        assert!(
            err.contains("not the version this directory last wrote"),
            "a file well ahead of a rolled-back anchor was accepted: {err}"
        );
    }

    /// A crash between writing a file and raising the anchor leaves the
    /// file one generation ahead. That is the ordinary interrupted write
    /// and must still open, or an ill-timed power cut would lose the
    /// directory.
    #[test]
    fn a_write_interrupted_before_the_anchor_rose_still_opens() {
        let (store, dir) = bound_store();
        // Written once first, so the record knows the file and the case
        // under test is a *recorded* file one generation ahead rather
        // than one the record has never heard of.
        store.save_contacts(&[]).unwrap();
        let vault_path = dir.path().join(VAULT_FILE);
        let state_path = dir.path().join(STATE_FILE);
        let before_vault = fs::read(&vault_path).unwrap();
        let before_state = fs::read(&state_path).unwrap();

        let peer = Identity::generate();
        store
            .save_contacts(&[Contact::new(peer.user_id())])
            .unwrap();
        // Wind the record back to just before that write: the file landed,
        // nothing that records it did.
        fs::write(&vault_path, &before_vault).unwrap();
        fs::write(&state_path, &before_state).unwrap();

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        assert_eq!(
            again.load_contacts().unwrap().len(),
            1,
            "the file the interrupted write left behind should still open"
        );
    }

    /// A directory written by a version before any of this still opens,
    /// and comes out the other side bound.
    #[test]
    fn a_directory_without_generations_adopts_them_on_the_next_unlock() {
        let (store, dir) = bound_store();
        let peer = Identity::generate();
        store
            .save_contacts(&[Contact::new(peer.user_id())])
            .unwrap();

        // Put the directory back into the shape an older version wrote:
        // files bound to their names alone, and no anchor.
        let cipher = store.cipher.clone().unwrap();
        for name in recrypted_files() {
            let path = dir.path().join(name);
            if !path.exists() {
                continue;
            }
            let opened = cipher.open_file(name, &fs::read(&path).unwrap()).unwrap();
            fs::write(&path, cipher.encrypt(name, &opened.plain)).unwrap();
        }
        let mut vault = store.read_vault().unwrap().unwrap();
        vault.state_generation = None;
        store.write_vault(&vault).unwrap();
        fs::remove_file(dir.path().join(STATE_FILE)).unwrap();
        let _ = fs::remove_file(dir.path().join(STATE_PREVIOUS_FILE));

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        assert_eq!(
            again.load_contacts().unwrap().len(),
            1,
            "an older directory should still be readable"
        );
        assert!(
            again
                .read_vault()
                .unwrap()
                .unwrap()
                .state_generation
                .is_some(),
            "it should be bound afterwards"
        );
        // And bound means bound: the same rollback is refused now.
        let path = dir.path().join(CONTACTS_FILE);
        let older = fs::read(&path).unwrap();
        again.save_contacts(&[]).unwrap();
        fs::write(&path, &older).unwrap();
        assert!(
            again.load_contacts().is_err(),
            "adoption should leave the directory actually protected"
        );
    }

    /// Changing what protects the directory rewrites every file under a
    /// new key. The generations have to come with them, or the new key
    /// would open files with nothing left to say which version of each is
    /// the current one.
    #[test]
    fn changing_the_protection_carries_the_generations_over() {
        let (mut store, dir) = bound_store();
        let peer = Identity::generate();
        store
            .save_contacts(&[Contact::new(peer.user_id())])
            .unwrap();

        store.set_passphrase_with("hunter2", Kdf::fast()).unwrap();
        assert_eq!(store.protection(), Protection::Passphrase);
        assert_eq!(store.load_contacts().unwrap().len(), 1);

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock("hunter2").unwrap();
        assert_eq!(again.load_contacts().unwrap().len(), 1);
        let path = dir.path().join(CONTACTS_FILE);
        let older = fs::read(&path).unwrap();
        again.save_contacts(&[]).unwrap();
        fs::write(&path, &older).unwrap();
        assert!(
            again.load_contacts().is_err(),
            "the protection changed and took the rollback binding with it"
        );
    }

    /// Losing both copies of the record refuses everything rather than
    /// carrying on unprotected -- and there is a way out that says what
    /// it gives up.
    #[test]
    fn a_lost_record_refuses_the_directory_until_it_is_reset() {
        let (store, dir) = bound_store();
        let peer = Identity::generate();
        store
            .save_contacts(&[Contact::new(peer.user_id())])
            .unwrap();
        fs::write(dir.path().join(STATE_FILE), b"not a state file").unwrap();
        let _ = fs::remove_file(dir.path().join(STATE_PREVIOUS_FILE));

        // The unlock itself goes through -- the reset needs the key, and
        // refusing to unlock would leave no way to run it -- but nothing
        // is read or written until the question is answered.
        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        let err = again.load_contacts().unwrap_err().to_string();
        assert!(
            err.contains("reset-rollback-protection"),
            "the way out should be named: {err}"
        );
        assert!(
            again.save_contacts(&[]).is_err(),
            "writing must refuse too, or the record would be rebuilt around a rollback"
        );

        again.reset_rollback_protection().unwrap();
        assert_eq!(
            again.load_contacts().unwrap().len(),
            1,
            "the directory should open again after the reset"
        );
        // And be protected again from here on.
        let path = dir.path().join(CONTACTS_FILE);
        let older = fs::read(&path).unwrap();
        again.save_contacts(&[]).unwrap();
        fs::write(&path, &older).unwrap();
        assert!(
            again.load_contacts().is_err(),
            "the reset should leave the directory bound again"
        );
    }

    #[test]
    fn the_key_store_protects_files_without_a_passphrase() {
        crate::keystore::use_mock_store();
        let (mut store, dir) = temp_store();
        let (identity, _) = store.load_or_create_identity().unwrap();
        let peer = Identity::generate();
        store.append_history(&peer.user_id(), &entry(0)).unwrap();
        assert_eq!(store.protection(), Protection::None);
        let identity_path = dir.path().join("identity.json");

        store.protect_with_keystore().unwrap();
        assert_eq!(store.protection(), Protection::Keystore);
        assert!(!store.is_locked() && !store.has_passphrase());
        assert!(FileCipher::is_encrypted(&fs::read(&identity_path).unwrap()));
        store.append_history(&peer.user_id(), &entry(1)).unwrap();

        // A fresh handle unlocks from the key store without being asked.
        let mut again = Store::open(dir.path()).unwrap();
        assert!(again.is_locked());
        assert!(again.unlock("anything").is_err());
        again.unlock_with_keystore().unwrap();
        assert_eq!(
            again.load_or_create_identity().unwrap().0.user_id(),
            identity.user_id()
        );
        assert_eq!(again.load_history(&peer.user_id()).unwrap().len(), 2);

        // A passphrase takes over. The files are rewritten under a fresh
        // data key, so the vault as it stood — kept here as somebody with
        // an old copy would keep it — no longer opens them; the key store
        // forgets its key too.
        let raw_before = fs::read(&identity_path).unwrap();
        let old_vault = again.read_vault().unwrap().unwrap();
        let name = old_vault.kdf.keystore_name();
        let old_kek = crate::keystore::load(&name).unwrap().unwrap();
        again
            .set_passphrase_with("correct horse", Kdf::fast())
            .unwrap();
        assert_eq!(again.protection(), Protection::Passphrase);
        let raw_after = fs::read(&identity_path).unwrap();
        assert_ne!(raw_after, raw_before);
        let old_key = FileCipher::unlock_with_kek(&old_vault, &old_kek).unwrap();
        assert!(old_key.decrypt("identity.json", &raw_after).is_err());
        assert!(crate::keystore::load(&name).unwrap().is_none());
        let mut third = Store::open(dir.path()).unwrap();
        assert!(third.unlock_with_keystore().is_err());
        third.unlock("correct horse").unwrap();
        assert_eq!(third.load_history(&peer.user_id()).unwrap().len(), 2);

        // Dropping the passphrase goes back to the key store, and rotates
        // the data key again: the passphrase that was in force opens
        // nothing written from now on.
        let vault_with_passphrase = third.read_vault().unwrap().unwrap();
        assert_eq!(third.remove_passphrase().unwrap(), Protection::Keystore);
        let raw_last = fs::read(&identity_path).unwrap();
        assert_ne!(raw_last, raw_after);
        let passphrase_key = FileCipher::unlock(&vault_with_passphrase, "correct horse").unwrap();
        assert!(passphrase_key.decrypt("identity.json", &raw_last).is_err());
        let mut fourth = Store::open(dir.path()).unwrap();
        fourth.unlock_with_keystore().unwrap();
        assert_eq!(fourth.load_history(&peer.user_id()).unwrap().len(), 2);

        // And plain files on request.
        assert_eq!(fourth.remove_protection().unwrap(), Protection::None);
        assert!(
            fs::read_to_string(&identity_path)
                .unwrap()
                .contains("signing_seed")
        );
        assert_eq!(
            Store::open(dir.path()).unwrap().protection(),
            Protection::None
        );
    }

    /// A wipe erases the files; the key that wrapped them has to go with
    /// them. Left behind, it went on opening a copy of the directory taken
    /// before the wipe -- which is the one thing a wipe promises it will
    /// not do.
    #[test]
    fn a_wipe_takes_the_key_store_key_with_it() {
        crate::keystore::use_mock_store();
        let (mut store, dir) = temp_store();
        store.load_or_create_identity().unwrap();
        store.protect_with_keystore().unwrap();
        let name = store.read_vault().unwrap().unwrap().kdf.keystore_name();
        assert!(crate::keystore::load(&name).unwrap().is_some());

        // Both halves of the log, which at `debug` name envelope ids,
        // contact ids and the relay. The rolled one is the same record
        // and used not to be removed.
        fs::write(dir.path().join(LOG_FILE), b"who this device talked to").unwrap();
        fs::write(dir.path().join(ROLLED_LOG_FILE), b"and who before that").unwrap();

        store.wipe().unwrap();
        assert!(!dir.path().join(VAULT_FILE).exists());
        assert!(!dir.path().join(LOG_FILE).exists());
        assert!(
            !dir.path().join(ROLLED_LOG_FILE).exists(),
            "the rolled log survived the erase"
        );
        assert!(
            crate::keystore::load(&name).unwrap().is_none(),
            "the wrapping key outlived the directory it wrapped"
        );
    }

    /// The key store is written before the vault that makes the key
    /// needed, so a failure in between must not leave a key nobody reads.
    /// A key the vault does name is left alone.
    #[test]
    fn a_key_made_for_a_change_that_failed_is_not_left_behind() {
        crate::keystore::use_mock_store();
        let (mut store, dir) = temp_store();
        store.load_or_create_identity().unwrap();

        // No vault at all: a key made for a directory that never got one.
        let stray = "data-key-0000000000000000000000000000000f";
        crate::keystore::create(stray).unwrap();
        store.drop_unused_kek(stray);
        assert!(crate::keystore::load(stray).unwrap().is_none());

        // The key the vault names stays, whatever else failed.
        store.protect_with_keystore().unwrap();
        let name = store.read_vault().unwrap().unwrap().kdf.keystore_name();
        store.drop_unused_kek(&name);
        assert!(crate::keystore::load(&name).unwrap().is_some());

        // A key for some other vault does not survive being looked at.
        crate::keystore::create(stray).unwrap();
        store.drop_unused_kek(stray);
        assert!(crate::keystore::load(stray).unwrap().is_none());
        assert!(crate::keystore::load(&name).unwrap().is_some());
        drop(dir);
    }

    /// The in-process error paths only run if the process survives. A
    /// crash between writing the key and writing the vault that needs it
    /// left a key nobody read and nobody remembered, next to a directory
    /// somebody may have copied. `vault.pending` is written first, so the
    /// next open finishes what the crash interrupted.
    #[test]
    fn a_key_a_crash_orphaned_is_taken_out_on_the_next_start() {
        crate::keystore::use_mock_store();
        let dir = tempfile::tempdir().unwrap();

        // Exactly what dying inside `protect_with_keystore` leaves: the
        // note, and the key, and no vault naming it.
        let kdf = Kdf::keystore();
        let name = kdf.keystore_name();
        let store = Store::open(dir.path()).unwrap();
        store.add_pending(&name).unwrap();
        crate::keystore::create(&name).unwrap();
        drop(store);
        assert!(dir.path().join(PENDING_FILE).exists());

        // The next start takes it out, and stops carrying the note.
        let store = Store::open(dir.path()).unwrap();
        assert!(
            crate::keystore::load(&name).unwrap().is_none(),
            "a key no vault names survived a restart"
        );
        assert!(!dir.path().join(PENDING_FILE).exists());
        drop(store);

        // The same note for a key the vault does name leaves it alone: a
        // crash in the other half of the window, after the vault landed.
        let mut store = Store::open(dir.path()).unwrap();
        store.load_or_create_identity().unwrap();
        store.protect_with_keystore().unwrap();
        let live = store.read_vault().unwrap().unwrap().kdf.keystore_name();
        store.add_pending(&live).unwrap();
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        assert!(
            crate::keystore::load(&live).unwrap().is_some(),
            "the key the directory runs on was taken out"
        );
        assert!(!dir.path().join(PENDING_FILE).exists());
        drop(store);
        drop(dir);
    }

    /// A vault that cannot be read is not permission to delete: the key it
    /// might name is the only way into every file in the directory, so an
    /// unreadable vault keeps both the key and the note for a later start.
    #[test]
    fn an_unreadable_vault_never_costs_the_key_that_opens_it() {
        crate::keystore::use_mock_store();
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        store.load_or_create_identity().unwrap();
        store.protect_with_keystore().unwrap();
        let name = store.read_vault().unwrap().unwrap().kdf.keystore_name();
        store.add_pending(&name).unwrap();
        drop(store);

        // Not absent -- unreadable. Absent means "no protection", which is
        // a fact; this is the absence of a fact.
        fs::write(dir.path().join(VAULT_FILE), b"{ this is not json").unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert!(
            crate::keystore::load(&name).unwrap().is_some(),
            "a key was deleted because the vault would not parse"
        );
        assert!(
            dir.path().join(PENDING_FILE).exists(),
            "the note was dropped while the question was still open"
        );
        drop(store);
        drop(dir);
    }

    /// Removing the protection deletes the vault and then the key. A crash
    /// between the two left a key that opens a copy of the directory taken
    /// while it was still encrypted.
    #[test]
    fn unprotecting_leaves_no_key_behind_even_if_it_stops_halfway() {
        crate::keystore::use_mock_store();
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        store.load_or_create_identity().unwrap();
        store.protect_with_keystore().unwrap();
        let name = store.read_vault().unwrap().unwrap().kdf.keystore_name();

        // Stop after the vault is gone but before the key is.
        store.add_pending(&name).unwrap();
        fs::remove_file(dir.path().join(VAULT_FILE)).unwrap();
        drop(store);
        assert!(crate::keystore::load(&name).unwrap().is_some());

        let store = Store::open(dir.path()).unwrap();
        assert!(
            crate::keystore::load(&name).unwrap().is_none(),
            "the key outlived the vault that named it"
        );
        drop(store);
        drop(dir);
    }

    fn entry(i: u64) -> HistoryEntry {
        HistoryEntry::new(
            i.to_string(),
            if i % 2 == 0 {
                Direction::Sent
            } else {
                Direction::Received
            },
            i,
            format!("msg {i}"),
        )
    }

    #[test]
    fn edits_reactions_and_reads_apply_in_order_and_before_their_entry() {
        let (store, _dir) = temp_store();
        let peer = Identity::generate().user_id();
        let conv = Conversation::Contact(peer);
        let bob = Identity::generate().user_id();
        // An edit and a reaction for a message that has not arrived yet,
        // and an edit of it from someone who did not write it.
        store
            .append_edit(&conv, "1", "forged", "f0", 4, Some(bob))
            .unwrap();
        store
            .append_edit(&conv, "1", "early edit", "e0", 5, Some(peer))
            .unwrap();
        store.append_reaction(&conv, "1", Some(bob), "👍").unwrap();
        for i in 0..3 {
            store.append_history(&peer, &entry(i)).unwrap();
        }
        store
            .append_edit(&conv, "0", "msg 0, again", "e1", 6, None)
            .unwrap();
        store
            .append_edit(&conv, "0", "msg 0, once more", "e2", 7, None)
            .unwrap();
        // The contact cannot edit what was sent to them.
        store
            .append_edit(&conv, "2", "forged too", "f1", 8, Some(peer))
            .unwrap();
        store.append_reaction(&conv, "0", None, "❤️").unwrap();
        store.append_reaction(&conv, "0", Some(bob), "👍").unwrap();
        store.append_reaction(&conv, "0", Some(bob), "😂").unwrap();
        store.append_reaction(&conv, "0", None, "").unwrap();
        store.append_read(&conv, &["1".into()], 100).unwrap();
        store.append_read(&conv, &["1".into()], 200).unwrap();
        store.append_read(&conv, &[], 300).unwrap();
        let history = store.load_history(&peer).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].text, "msg 0, once more");
        assert!(history[0].edited);
        assert_eq!(history[0].previous, vec!["msg 0", "msg 0, again"]);
        assert_eq!(
            history[0].reactions,
            vec![Reaction {
                from: Some(bob),
                emoji: "😂".into()
            }],
            "one per person, the last winning, an empty one withdrawing"
        );
        assert_eq!(history[1].text, "early edit", "applied before its entry");
        assert_eq!(history[1].previous, vec!["msg 1"], "the forgery did not");
        assert_eq!(history[1].reactions.len(), 1);
        assert_eq!(history[2].text, "msg 2", "not the contact's to edit");
        assert!(!history[2].edited);
        assert_eq!(history[1].read_at_ms, Some(100), "the first showing counts");
        assert_eq!(history[2].read_at_ms, None);
        assert_eq!(store.load_conversation(&conv).unwrap().len(), 3);
    }

    #[test]
    fn removed_messages_are_rewritten_out_and_stay_gone() {
        let (store, _dir) = temp_store();
        let peer = Identity::generate().user_id();
        let conv = Conversation::Contact(peer);
        for i in 0..4 {
            store.append_history(&peer, &entry(i)).unwrap();
        }
        store
            .append_receipt(&peer, ReceiptKind::Read, &["0".into(), "2".into()], 10)
            .unwrap();
        store
            .append_edit(&conv, "2", "edited", "e", 11, None)
            .unwrap();
        store.append_reaction(&conv, "2", None, "👍").unwrap();
        let removed = store
            .remove_messages(&conv, &["2".into(), "9".into()])
            .unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].text, "edited");
        let history = store.load_history(&peer).unwrap();
        assert_eq!(
            history.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            ["0", "1", "3"]
        );
        assert_eq!(history[0].receipt, Some(ReceiptKind::Read));
        // Nothing about it is left on disk, and a late line naming it, or
        // its entry again, counts for nothing.
        let raw = fs::read_to_string(store.root.join(history_name(&peer))).unwrap();
        assert!(!raw.contains("edited") && !raw.contains("msg 2"), "{raw}");
        store
            .append_edit(&conv, "2", "back?", "e2", 12, None)
            .unwrap();
        store.append_history(&peer, &entry(2)).unwrap();
        assert_eq!(store.load_history(&peer).unwrap().len(), 3);
        // Removing from a conversation that has no file does nothing.
        let nobody = Conversation::Contact(Identity::generate().user_id());
        assert!(
            store
                .remove_messages(&nobody, &["x".into()])
                .unwrap()
                .is_empty()
        );
        assert!(!store.root.join(nobody.file_name()).exists());
    }

    #[test]
    fn a_deletion_for_everyone_leaves_a_placeholder_or_a_tombstone() {
        let (store, _dir) = temp_store();
        let peer = Identity::generate().user_id();
        let conv = Conversation::Contact(peer);
        for i in 0..2 {
            store.append_history(&peer, &entry(i)).unwrap();
        }
        store
            .append_edit(&conv, "1", "edited", "e", 5, Some(peer))
            .unwrap();
        store.append_reaction(&conv, "1", None, "👍").unwrap();
        // Only the author deletes: the contact cannot delete what was
        // sent to them, and what they wrote goes at their word.
        assert_eq!(
            store.mark_deleted(&conv, "0", Some(peer)).unwrap(),
            Deletion::Refused
        );
        assert_eq!(store.load_history(&peer).unwrap()[0].text, "msg 0");
        assert_eq!(
            store.mark_deleted(&conv, "1", Some(peer)).unwrap(),
            Deletion::Applied
        );
        let history = store.load_history(&peer).unwrap();
        assert_eq!(history.len(), 2);
        let gone = &history[1];
        assert!(gone.deleted);
        assert!(gone.text.is_empty() && gone.previous.is_empty() && gone.reactions.is_empty());
        assert!(!gone.edited);
        let raw = fs::read_to_string(store.root.join(history_name(&peer))).unwrap();
        assert!(!raw.contains("edited") && !raw.contains("msg 1"), "{raw}");
        // Later edits and reactions leave the placeholder alone.
        store
            .append_edit(&conv, "1", "again", "e2", 6, Some(peer))
            .unwrap();
        store.append_reaction(&conv, "1", None, "❤️").unwrap();
        let history = store.load_history(&peer).unwrap();
        assert!(history[1].text.is_empty() && history[1].reactions.is_empty());
        // A deletion for a message not held is said to be tombstoned but
        // leaves nothing on disk: the front end holds it for the few
        // minutes in which the message might still turn up, and an id
        // nobody has seen is free to invent, so a line per invented id is
        // a file anyone in the conversation could grow without end
        // (SM-C-19).
        let before = fs::read_to_string(store.root.join(history_name(&peer))).unwrap();
        assert_eq!(
            store.mark_deleted(&conv, "7", Some(peer)).unwrap(),
            Deletion::Tombstoned
        );
        assert_eq!(
            fs::read_to_string(store.root.join(history_name(&peer))).unwrap(),
            before,
            "an id the history does not hold leaves nothing behind"
        );
        store.append_history(&peer, &entry(7)).unwrap();
        assert_eq!(store.load_history(&peer).unwrap().len(), 3);

        // A whole body's worth of ids goes through the file once, and
        // each is answered for itself: the author's message becomes a
        // placeholder, somebody else's is refused, an unheld one is not
        // written down.
        let bob = Identity::generate().user_id();
        store.append_history(&peer, &entry(9)).unwrap();
        let ids = ["7".to_owned(), "9".to_owned(), "11".to_owned()];
        assert_eq!(
            store.mark_all_deleted(&conv, &ids, Some(bob)).unwrap(),
            vec![Deletion::Refused, Deletion::Refused, Deletion::Tombstoned]
        );
        assert_eq!(
            store.mark_all_deleted(&conv, &ids, Some(peer)).unwrap(),
            vec![Deletion::Applied, Deletion::Applied, Deletion::Tombstoned]
        );
        let history = store.load_history(&peer).unwrap();
        assert_eq!(history.len(), 4);
        assert!(history.iter().filter(|e| e.deleted).count() == 3);
    }

    #[test]
    fn conversations_are_listed_from_the_history_directory() {
        let (store, _dir) = temp_store();
        assert!(store.conversations().unwrap().is_empty());
        let peer = Identity::generate().user_id();
        let group = silver_protocol::GroupId::generate();
        store.append_history(&peer, &entry(0)).unwrap();
        store.append_group_history(&group, &entry(1)).unwrap();
        fs::write(store.root.join(HISTORY_DIR).join("notes.txt"), "x").unwrap();
        let mut listed = store.conversations().unwrap();
        listed.sort_by_key(|c| matches!(c, Conversation::Group(_)));
        assert_eq!(
            listed,
            vec![Conversation::Contact(peer), Conversation::Group(group)]
        );
        // A file's at-rest encryption survives a rewrite.
        crate::keystore::use_mock_store();
        let mut store = store;
        store.protect_with_keystore().unwrap();
        let conv = Conversation::Group(group);
        store
            .append_edit(&conv, "1", "edited", "e", 2, None)
            .unwrap();
        store.remove_messages(&conv, &["nothing".into()]).unwrap();
        let raw = fs::read_to_string(store.root.join(conv.file_name())).unwrap();
        assert!(raw.lines().all(|l| l.starts_with(LINE_PREFIX)), "{raw}");
        assert_eq!(store.load_group_history(&group).unwrap()[0].text, "edited");
    }

    #[test]
    fn receipts_are_applied_to_history_entries() {
        let (store, _dir) = temp_store();
        let peer = Identity::generate().user_id();
        for i in 0..4 {
            store.append_history(&peer, &entry(i)).unwrap();
        }
        store
            .append_receipt(&peer, ReceiptKind::Delivered, &["0".into(), "2".into()], 10)
            .unwrap();
        store
            .append_receipt(&peer, ReceiptKind::Read, &["2".into()], 11)
            .unwrap();
        // A later, lesser receipt does not downgrade.
        store
            .append_receipt(&peer, ReceiptKind::Delivered, &["2".into()], 12)
            .unwrap();
        let history = store.load_history(&peer).unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history[0].receipt, Some(ReceiptKind::Delivered));
        assert_eq!(history[1].receipt, None);
        assert_eq!(history[2].receipt, Some(ReceiptKind::Read));
        assert_eq!(history[3].receipt, None);
    }

    #[test]
    fn text_updates_replace_an_entry_and_survive_reloading() {
        let (store, _dir) = temp_store();
        let peer = Identity::generate().user_id();
        for i in 0..3 {
            store.append_history(&peer, &entry(i)).unwrap();
        }
        let saved = Path::new("/home/me/a.txt");
        store
            .append_text(&peer, "1", "[file] a.txt → /home/me/a.txt", Some(saved))
            .unwrap();
        store.append_text(&peer, "9", "nobody", None).unwrap(); // unknown id: ignored
        let history = store.load_history(&peer).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].text, "msg 0");
        assert_eq!(history[1].text, "[file] a.txt → /home/me/a.txt");
        assert_eq!(
            history[1].saved.as_deref(),
            Some(saved),
            "where the file went is kept as data, not read back out of the text"
        );
        assert_eq!(history[2].text, "msg 2");
        // Receipts still land on the updated entry.
        store
            .append_receipt(&peer, ReceiptKind::Read, &["1".into()], 5)
            .unwrap();
        let history = store.load_history(&peer).unwrap();
        assert_eq!(history[1].receipt, Some(ReceiptKind::Read));
        assert_eq!(history[1].text, "[file] a.txt → /home/me/a.txt");
        assert_eq!(history[1].saved.as_deref(), Some(saved));
    }

    #[test]
    fn a_linked_device_and_the_device_list_are_kept_next_to_the_keys() {
        let (store, dir) = temp_store();
        let (laptop, _) = store.load_or_create_identity().unwrap();
        assert!(store.load_linked().unwrap().is_none());
        assert_eq!(store.load_devices().unwrap(), DevicesFile::default());

        // Linking writes under `linked`, leaving the keys as they were.
        let alice = Identity::generate();
        let linked = Linked {
            account: alice.user_id(),
            certificate: alice
                .certify_device(&laptop.user_id(), "laptop", 1)
                .unwrap(),
        };
        store.save_linked(Some(&linked)).unwrap();
        assert_eq!(store.load_linked().unwrap(), Some(linked.clone()));
        let (again, created) = store.load_or_create_identity().unwrap();
        assert!(!created);
        assert_eq!(again.user_id(), laptop.user_id());
        let text = fs::read_to_string(dir.path().join("identity.json")).unwrap();
        assert!(text.contains("\"linked\"") && text.contains("signing_seed"));
        store.save_linked(None).unwrap();
        assert!(store.load_linked().unwrap().is_none());
        assert_eq!(
            store.load_or_create_identity().unwrap().0.user_id(),
            laptop.user_id()
        );

        // The list round-trips through its own file.
        let phone = Identity::generate();
        let list = DevicesFile {
            devices: vec![linked.certificate.clone()],
            revoked: vec![alice.revoke_device(&phone.user_id(), 2)],
        };
        store.save_devices(&list).unwrap();
        assert_eq!(store.load_devices().unwrap(), list);
        // And the per-device sequences of a contact.
        let mut contact = Contact::new(alice.user_id());
        assert_eq!(contact.received_from(Some(&laptop.user_id())), None);
        contact.note_received(None, Sequence { epoch: 1, seq: 3 });
        contact.note_received(Some(&laptop.user_id()), Sequence { epoch: 2, seq: 1 });
        store.save_contacts(std::slice::from_ref(&contact)).unwrap();
        let loaded = store.load_contacts().unwrap().remove(0);
        assert_eq!(
            loaded.received_from(None).map(|s| s.last),
            Some(Sequence { epoch: 1, seq: 3 })
        );
        assert_eq!(
            loaded
                .received_from(Some(&laptop.user_id()))
                .map(|s| s.last),
            Some(Sequence { epoch: 2, seq: 1 })
        );
        assert_eq!(loaded.received_from(Some(&phone.user_id())), None);
    }

    #[test]
    fn identity_is_created_once_and_reloaded() {
        let (store, _dir) = temp_store();
        let (first, created) = store.load_or_create_identity().unwrap();
        assert!(created);
        let (second, created) = store.load_or_create_identity().unwrap();
        assert!(!created);
        assert_eq!(first.user_id(), second.user_id());
    }

    #[test]
    fn a_revocation_certificate_is_minted_once_and_matches_the_identity() {
        let (store, _dir) = temp_store();
        let (identity, _) = store.load_or_create_identity().unwrap();
        assert!(store.revocation().unwrap().is_none());

        let first = store.load_or_create_revocation(&identity, 1000).unwrap();
        assert_eq!(first.identity, identity.user_id());
        assert!(first.verify().is_ok());
        // Minting again returns the same certificate, not a fresh signature.
        let again = store.load_or_create_revocation(&identity, 2000).unwrap();
        assert_eq!(again, first);
        assert_eq!(store.revocation().unwrap(), Some(first.clone()));

        // A certificate stored for a different key is replaced.
        let other = Identity::generate();
        let fresh = store.load_or_create_revocation(&other, 3000).unwrap();
        assert_eq!(fresh.identity, other.user_id());
        assert_ne!(fresh, first);
    }

    #[test]
    fn history_migrates_to_a_successor_identity() {
        let (store, _dir) = temp_store();
        let old = Identity::generate().user_id();
        let new = Identity::generate().user_id();
        for i in 0..3 {
            store.append_history(&old, &entry(i)).unwrap();
        }
        store
            .append_receipt(&old, ReceiptKind::Read, &["0".into()], 5)
            .unwrap();

        store.migrate_history(&old, &new).unwrap();
        // The old log is gone and the new one carries the conversation with
        // its receipts still applied.
        assert!(store.load_history(&old).unwrap().is_empty());
        let moved = store.load_history(&new).unwrap();
        assert_eq!(moved.len(), 3);
        assert_eq!(moved[0].receipt, Some(ReceiptKind::Read));
        // Migrating a peer with no log is a no-op, not an error.
        let empty = Identity::generate().user_id();
        store.migrate_history(&empty, &new).unwrap();
        assert_eq!(store.load_history(&new).unwrap().len(), 3);
    }

    /// The audit's SM-C-02 and SM-C-08: every file the data key covers
    /// moves with the protection, and the vault is written before them,
    /// so a directory is never left holding files under a key that was
    /// never written down.
    #[test]
    fn protecting_and_unprotecting_moves_every_file() {
        crate::keystore::use_mock_store();
        let (mut store, _dir) = temp_store();
        let peer = Identity::generate().user_id();
        // One of everything the data key covers.
        let (identity, _) = store.load_or_create_identity().unwrap();
        store.load_or_create_revocation(&identity, 1).unwrap();
        store.save_config(&Config::default()).unwrap();
        store.save_contacts(&[Contact::new(peer)]).unwrap();
        store.save_requests(&[]).unwrap();
        store.save_blocked(&[peer]).unwrap();
        store
            .save_devices(&crate::devices::DevicesFile::default())
            .unwrap();
        store.append_history(&peer, &entry(0)).unwrap();
        store
            .write_json_private(crate::groups::GROUPS_FILE, &serde_json::json!({"a": 1}))
            .unwrap();
        store
            .write_private_file(crate::groups::MLS_FILE, b"mls state")
            .unwrap();

        let named: Vec<&str> = recrypted_files().collect();
        let root = store.root.clone();
        let is_encrypted = |name: &str| {
            let path = root.join(name);
            path.exists() && FileCipher::is_encrypted(&fs::read(&path).unwrap())
        };

        store.protect_with_keystore().unwrap();
        for name in &named {
            if !root.join(name).exists() {
                continue;
            }
            assert!(is_encrypted(name), "{name} was left in the clear");
        }
        let history = fs::read_to_string(root.join(history_name(&peer))).unwrap();
        assert!(history.lines().all(|l| l.starts_with(LINE_PREFIX)));
        assert_eq!(
            store.read_private_file(crate::groups::MLS_FILE).unwrap(),
            Some(b"mls state".to_vec())
        );

        // And back: everything readable again, nothing left encrypted
        // under a key that is gone.
        assert_eq!(store.remove_protection().unwrap(), Protection::None);
        for name in &named {
            assert!(!is_encrypted(name), "{name} is still encrypted");
        }
        assert_eq!(
            store.read_private_file(crate::groups::MLS_FILE).unwrap(),
            Some(b"mls state".to_vec())
        );
        assert_eq!(store.load_history(&peer).unwrap().len(), 1);
        assert_eq!(store.load_contacts().unwrap().len(), 1);
        assert!(store.revocation().unwrap().is_some());
    }

    /// The audit's SM-C-08: the vault holds the only copy of the data
    /// key, so it is written before the files are encrypted under it. A
    /// protection that fails part-way leaves a directory that still
    /// opens, and the next unlock seals what is left.
    #[test]
    fn a_protection_that_fails_part_way_leaves_the_directory_readable() {
        crate::keystore::use_mock_store();
        let (mut store, _dir) = temp_store();
        let (identity, _) = store.load_or_create_identity().unwrap();
        let peer = Identity::generate().user_id();
        store.save_contacts(&[Contact::new(peer)]).unwrap();
        // A file that claims to be encrypted already: the re-encryption
        // cannot read it without a key, so it fails half way through.
        let broken = store.root.join(BLOCKED_FILE);
        let mut bytes = crate::vault::FILE_MAGIC.to_vec();
        bytes.extend_from_slice(b"not really");
        write_atomic(&broken, &bytes).unwrap();

        assert!(store.protect_with_keystore().is_err());

        // The key is on disk, so what was rewritten before the failure is
        // still readable: the whole point of writing the vault first.
        // Written last, the same failure left every rewritten file under
        // a key that had never been recorded.
        fs::remove_file(&broken).unwrap();
        let mut reopened = Store::open(store.root.clone()).unwrap();
        assert_eq!(reopened.protection(), Protection::Keystore);
        reopened.unlock_with_keystore().unwrap();
        assert_eq!(
            reopened.load_or_create_identity().unwrap().0.user_id(),
            identity.user_id()
        );
        assert_eq!(reopened.load_contacts().unwrap().len(), 1);
        // And the unlock sealed anything the failure had left plain.
        reopened.save_blocked(&[peer]).unwrap();
        reopened.unlock_with_keystore().unwrap();
        assert!(!reopened.any_plain().unwrap());
    }

    #[test]
    fn history_migration_survives_at_rest_encryption() {
        crate::keystore::use_mock_store();
        let (mut store, _dir) = temp_store();
        let _ = store.load_or_create_identity().unwrap();
        store.protect_with_keystore().unwrap();
        let old = Identity::generate().user_id();
        let new = Identity::generate().user_id();
        for i in 0..2 {
            store.append_history(&old, &entry(i)).unwrap();
        }
        // Re-encoding under the new file name must still decrypt back.
        store.migrate_history(&old, &new).unwrap();
        assert_eq!(store.load_history(&new).unwrap().len(), 2);
        assert!(store.load_history(&old).unwrap().is_empty());
    }

    #[test]
    fn contacts_config_and_history_round_trip() {
        let (store, _dir) = temp_store();
        assert!(store.load_contacts().unwrap().is_empty());
        assert_eq!(store.load_config().unwrap().relay_url, None);

        let peer = Identity::generate();
        let mut contact = Contact::new(peer.user_id());
        contact.alias = Some("peer".into());
        contact.bundle = Some(peer.key_bundle());
        store.save_contacts(std::slice::from_ref(&contact)).unwrap();
        let loaded = store.load_contacts().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].alias.as_deref(), Some("peer"));
        assert_eq!(loaded[0].bundle, Some(peer.key_bundle()));

        store
            .save_config(&Config {
                relay_url: Some("ws://example:7777/ws".into()),
                ..Config::default()
            })
            .unwrap();
        assert_eq!(
            store.load_config().unwrap().relay_url.as_deref(),
            Some("ws://example:7777/ws")
        );

        for i in 0..2 {
            store.append_history(&peer.user_id(), &entry(i)).unwrap();
        }
        let history = store.load_history(&peer.user_id()).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].direction, Direction::Received);
        assert_eq!(history[1].text, "msg 1");
    }

    #[test]
    fn a_relay_reached_over_wss_is_never_talked_to_over_ws() {
        let mut config = Config::default();
        assert!(!config.note_secure("ws://relay.example:7777/ws"));
        assert!(config.downgrade("ws://relay.example:7777/ws").is_none());

        assert!(config.note_secure("wss://Relay.Example/ws"));
        assert!(
            !config.note_secure("wss://relay.example:443/ws"),
            "known already"
        );
        assert_eq!(config.secure_hosts, vec!["relay.example".to_owned()]);
        assert_eq!(
            config.downgrade("ws://RELAY.example.:7777/ws").as_deref(),
            Some("relay.example")
        );
        assert!(config.downgrade("wss://relay.example/ws").is_none());
        assert!(config.downgrade("ws://other.example/ws").is_none());

        // It survives a round trip through the file.
        let (store, _dir) = temp_store();
        store.save_config(&config).unwrap();
        let loaded = store.load_config().unwrap();
        assert_eq!(loaded.secure_hosts, config.secure_hosts);
        assert!(loaded.downgrade("ws://relay.example/ws").is_some());
    }

    /// A relay's features are its own word and it can say something
    /// different to each client on each connection. What a host offered
    /// before is remembered, so taking it back shows.
    #[test]
    fn a_relay_cannot_quietly_take_back_what_it_offered() {
        let mut config = Config::default();
        let all: Vec<String> = ["prekeys", "transparency", "anonymous_send"]
            .iter()
            .map(|f| (*f).to_owned())
            .collect();
        assert!(
            config
                .note_features("wss://relay.example/ws", &all)
                .is_empty()
        );
        // The same again says nothing, and the host is matched as the
        // downgrade rule matches it.
        assert!(
            config
                .note_features("wss://Relay.Example:443/ws", &all)
                .is_empty()
        );
        // A feature added later joins the record rather than replacing it.
        let more: Vec<String> = ["prekeys", "transparency", "anonymous_send", "groups"]
            .iter()
            .map(|f| (*f).to_owned())
            .collect();
        assert!(
            config
                .note_features("wss://relay.example/ws", &more)
                .is_empty()
        );

        // Two taken away at once, both reported.
        let fewer = vec!["prekeys".to_owned(), "groups".to_owned()];
        let mut gone = config.note_features("wss://relay.example/ws", &fewer);
        gone.sort();
        assert_eq!(gone, vec!["anonymous_send", "transparency"]);
        // The record is unchanged by the withdrawal, so it is reported
        // again on the next connection and not forgotten quietly.
        let again = config.note_features("wss://relay.example/ws", &fewer);
        assert_eq!(again.len(), 2);
        // Another relay's word is its own.
        assert!(
            config
                .note_features("wss://other.example/ws", &fewer)
                .is_empty()
        );

        let (store, _dir) = temp_store();
        store.save_config(&config).unwrap();
        let mut loaded = store.load_config().unwrap();
        assert_eq!(
            loaded.note_features("wss://relay.example/ws", &fewer).len(),
            2
        );
    }

    #[test]
    fn passphrase_encrypts_everything_and_can_be_removed() {
        let (mut store, dir) = temp_store();
        let (identity, _) = store.load_or_create_identity().unwrap();
        let peer = Identity::generate();
        store
            .save_contacts(&[Contact::new(peer.user_id())])
            .unwrap();
        store.append_history(&peer.user_id(), &entry(0)).unwrap();

        // Everything written so far is plaintext.
        let identity_path = dir.path().join("identity.json");
        assert!(
            fs::read_to_string(&identity_path)
                .unwrap()
                .contains("signing_seed")
        );

        store
            .set_passphrase_with("correct horse", Kdf::fast())
            .unwrap();
        assert!(store.has_passphrase() && !store.is_locked());
        store.append_history(&peer.user_id(), &entry(1)).unwrap();

        // Nothing readable remains on disk.
        let raw_identity = fs::read(&identity_path).unwrap();
        assert!(FileCipher::is_encrypted(&raw_identity));
        assert!(!String::from_utf8_lossy(&raw_identity).contains("signing_seed"));
        let raw_history = fs::read_to_string(
            dir.path()
                .join("history")
                .join(format!("{}.jsonl", peer.user_id())),
        )
        .unwrap();
        assert!(raw_history.lines().all(|l| l.starts_with(LINE_PREFIX)));
        assert!(!raw_history.contains("msg 0"));

        // A fresh handle starts locked and refuses to read until unlocked.
        let mut again = Store::open(dir.path()).unwrap();
        assert!(again.is_locked());
        assert!(again.load_contacts().is_err());
        assert!(matches!(
            again.unlock("wrong"),
            Err(VaultError::WrongPassphrase)
        ));
        again.unlock("correct horse").unwrap();
        assert_eq!(
            again.load_or_create_identity().unwrap().0.user_id(),
            identity.user_id()
        );
        assert_eq!(again.load_contacts().unwrap().len(), 1);
        let history = again.load_history(&peer.user_id()).unwrap();
        assert_eq!(
            history.iter().map(|h| h.text.as_str()).collect::<Vec<_>>(),
            ["msg 0", "msg 1"]
        );

        // Removing the passphrase restores plaintext (the mock key store is
        // empty and counts as absent here, so nothing moves into it).
        crate::keystore::use_mock_store();
        let after = again.remove_passphrase().unwrap();
        assert!(!again.has_passphrase());
        if after == Protection::Keystore {
            again.remove_protection().unwrap();
        }
        assert!(
            fs::read_to_string(&identity_path)
                .unwrap()
                .contains("signing_seed")
        );
        let plain = Store::open(dir.path()).unwrap();
        assert_eq!(plain.load_history(&peer.user_id()).unwrap().len(), 2);
        assert_eq!(
            plain.load_or_create_identity().unwrap().0.user_id(),
            identity.user_id()
        );
    }

    /// A device of one's own can pin a contact's keys and mark them
    /// verified over `sync contact`. Unlinking it — the answer to a stolen
    /// or compromised device — takes that word back, and leaves what this
    /// device did itself alone.
    #[test]
    fn unlinking_a_device_takes_back_what_it_said_about_a_contacts_keys() {
        let phone = Identity::generate().user_id();
        let laptop = Identity::generate().user_id();
        let peer = Identity::generate();

        let mut contact = Contact::new(peer.user_id());
        contact.bundle = Some(peer.key_bundle());
        contact.pinned_by = Some(phone);
        contact.verified = true;
        contact.verified_by = Some(phone);

        // Another device's unlinking says nothing about this contact.
        assert!(!contact.drop_trust_from(&laptop));
        assert!(contact.bundle.is_some() && contact.verified);

        assert!(contact.drop_trust_from(&phone));
        assert!(
            contact.bundle.is_none(),
            "the pin goes, so the next lookup pins afresh"
        );
        assert!(!contact.verified && contact.verified_by.is_none());
        assert!(!contact.drop_trust_from(&phone), "nothing left to undo");

        // What this device pinned and verified itself is not the phone's
        // to lose.
        let mut mine = Contact::new(peer.user_id());
        mine.pin(Some(peer.key_bundle()));
        mine.set_verified(true);
        assert!(!mine.drop_trust_from(&phone));
        assert!(mine.bundle.is_some() && mine.verified);

        // And a `contacts.json` written before any of this reads as
        // nobody else's word, with its JSON unchanged.
        let json = serde_json::to_string(&mine).unwrap();
        assert!(!json.contains("pinned_by") && !json.contains("verified_by"));
        let read: Contact = serde_json::from_str(&json).unwrap();
        assert_eq!(read.pinned_by, None);
        assert_eq!(read.verified_by, None);
    }
}
