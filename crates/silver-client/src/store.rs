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
//! history/<name>.jsonl one line per message, per conversation
//! ```
//!
//! The history file's `<name>` is a MAC of the conversation's id under a
//! key of its own, so a listing of the directory is not the contact and
//! group list; `state` says which file is whose. Without protection at
//! rest there is no key to compute one with, and the name is the id.
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
use crate::rollback::{COVERS_LOG_AND_OUTBOX, Generations, STATE_FILE, STATE_PREVIOUS_FILE, State};
use crate::sequence::Seen;
use crate::sessions::{PrekeyFile, SessionsFile};
use crate::vault::{
    FileCipher, Kdf, LINE_PREFIX, SECURITY_KEY_RP, SlotKey, SlotKind, VaultError, VaultFile,
    fresh_slot_salt,
};
use silver_key::Authenticator;
use zeroize::Zeroizing;

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
/// Where an update waits, and the version it replaced is kept
/// ([`crate::update::install::staging_dir`]).
const UPDATE_DIR: &str = "update";
/// In front of the directory and the name in the tag of a note in
/// `vault.pending`, so that the key-store key it is made with is used for
/// nothing else.
const PENDING_DOMAIN: &[u8] = b"silver-messenger/v1/vault-pending\0";

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

/// Whether `name` is one the data directory uses for a file of its own.
///
/// A received file is never saved under one ([`crate::files::sanitize_name`]
/// puts a `_` in front), and a file in `downloads/` under one is not
/// decrypted as a received file: before 0.25.0 a received file was sealed
/// exactly as a store file is, so a copy of `state` or `identity.json`
/// dropped there would have opened. Compared without regard to case,
/// which is how Windows and macOS compare names.
pub(crate) fn is_store_file_name(name: &str) -> bool {
    recrypted_files()
        .chain([
            VAULT_FILE,
            PENDING_FILE,
            STATE_FILE,
            STATE_PREVIOUS_FILE,
            LOG_FILE,
            ROLLED_LOG_FILE,
            HISTORY_DIR,
            UPDATE_DIR,
        ])
        .any(|own| own.eq_ignore_ascii_case(name))
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
    /// Chats whose messages do not notify, by `c:<user id>` or
    /// `g:<group id>`, each until a time in milliseconds or for good
    /// (`/mute`). A mention still notifies.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub muted: BTreeMap<String, Option<u64>>,
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
            muted: BTreeMap::new(),
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
    /// had, so that losing it can be noticed (0.16.0).
    ///
    /// A session that is weaker than this one was is either their client
    /// going backwards or somebody serving a bundle with the ML-KEM keys
    /// taken out, and those look identical from here. `None` until the
    /// first session, and for contacts carried over from before 0.16.0 --
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
    /// The name a version before SM-C-25 filed this conversation under,
    /// and the one a directory with no protection at rest still uses:
    /// there is no key to compute anything else with.
    fn plain_file_name(&self) -> String {
        match self {
            Self::Contact(peer) => history_name(peer),
            Self::Group(group) => group_history_name(group),
        }
    }

    /// How the record of what was written names this conversation, and
    /// what [`Conversation::parse_id`] reads back.
    fn id(&self) -> String {
        match self {
            Self::Contact(peer) => peer.to_string(),
            Self::Group(group) => format!("group-{group}"),
        }
    }

    /// The conversation an id from the record names.
    fn parse_id(id: &str) -> Option<Self> {
        match id.strip_prefix("group-") {
            Some(group) => group.parse().ok().map(Self::Group),
            None => id.parse().ok().map(Self::Contact),
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
    /// Encrypted under a key a security key unlocks, touch and PIN, or a
    /// recovery passphrase.
    SecurityKey,
}

/// What to do about a security key that did not answer while the
/// directory is moved to a fresh data key ([`Store::remove_security_key`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Missing {
    /// Ask it again (another key plugged in, say).
    Retry,
    /// Drop its slot: it opens nothing from now on.
    Drop,
    /// Change nothing.
    Cancel,
}

/// The recovery passphrase slot's name.
const RECOVERY_LABEL: &str = "recovery";

/// The secret of whichever enrolled key is plugged in: the index of its
/// slot, and the 32 bytes.
fn ask_security_key(
    vault: &VaultFile,
    auth: &mut dyn Authenticator,
) -> anyhow::Result<(usize, Zeroizing<[u8; 32]>)> {
    let slots: Vec<(usize, &[u8], &[u8; 32])> = vault
        .security_key_slots()
        .filter_map(|(index, slot)| match &slot.kind {
            SlotKind::Fido2 {
                credential_id,
                salt,
                rp_id,
            } => Some(check_rp(rp_id).map(|()| (index, credential_id.as_slice(), salt))),
            SlotKind::Passphrase { .. } => None,
        })
        .collect::<anyhow::Result<_>>()?;
    if slots.is_empty() {
        bail!("no security key is enrolled");
    }
    let candidates: Vec<(&[u8], &[u8])> = slots.iter().map(|s| (s.1, &s.2[..])).collect();
    let (which, output) = auth
        .secret(SECURITY_KEY_RP, &candidates)
        .map_err(security_key_error)?;
    let index = slots.get(which).context("the key answered for no slot")?.0;
    Ok((index, output))
}

/// Refuse a slot made under any relying party but this program's.
///
/// `vault.json` is read before anything can be decrypted, so a slot's
/// relying party is whatever somebody who can write the file says it is.
/// Every slot this client enrols is under [`SECURITY_KEY_RP`], and the
/// key is only ever asked under that: a slot naming another would have
/// the plugged-in key answer for some other site's credential.
fn check_rp(rp_id: &str) -> anyhow::Result<()> {
    if rp_id != SECURITY_KEY_RP {
        bail!(
            "a security key slot in vault.json is for {:?}, not this program's {SECURITY_KEY_RP:?}; \
             vault.json has been edited, and no key is asked anything for it",
            crate::files::one_line(rp_id)
        );
    }
    Ok(())
}

/// A security key's error as the rest of the client carries errors; the
/// original stays reachable with `downcast_ref`.
fn security_key_error(e: silver_key::Error) -> anyhow::Error {
    match e {
        silver_key::Error::NoCredentials => anyhow::Error::new(e)
            .context("the security key plugged in is not one enrolled for this data directory"),
        e => anyhow::Error::new(e),
    }
}

/// Why the generations are being adopted, which decides what is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Adoption {
    /// The authenticated record says a protection, or the adoption of a
    /// directory from before the record, has not finished. Plaintext and
    /// name-only files are what that leaves; a file further on than
    /// generation 1 is not, and is refused.
    Unfinished,
    /// The person asked for the record to start again from what is on
    /// disk (`--reset-rollback-protection`). Everything is taken as it is.
    Reset,
}

/// One entry in `vault.pending`: a key store entry that may need taking
/// out, and a tag only the holder of that key could have made
/// ([`Store::pending_mac`]).
#[derive(Serialize, Deserialize)]
struct PendingNote {
    name: String,
    #[serde(with = "silver_protocol::encoding::b64")]
    tag: Vec<u8>,
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
        // Tightened when something only this program puts there is
        // already in it: `history/` from an earlier start, or `update/`
        // from a `silver update` run before the first start, which used
        // to leave the directory at the umask's mercy for good.
        let guard = [HISTORY_DIR, UPDATE_DIR, VAULT_FILE]
            .into_iter()
            .find(|name| root.join(name).exists())
            .unwrap_or(HISTORY_DIR);
        create_private_dir(&root, Some(guard))?;
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
            Ok(Some(vault)) if vault.has_security_keys() => Protection::SecurityKey,
            Ok(Some(vault)) if vault.is_keystore() => Protection::Keystore,
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

    /// The data key, for what is kept outside the store's own files:
    /// received files written encrypted (`/files encrypt`).
    pub fn cipher(&self) -> Option<Arc<FileCipher>> {
        self.cipher.clone()
    }

    // --- keys the store may still be holding --------------------------------

    /// The notes in `vault.pending`, or none when it is absent or
    /// unreadable.
    ///
    /// Plaintext and read before any unlock, since the whole point is to
    /// reach it on a start that cannot open anything else. So it is
    /// somebody else's to write too, and a note is acted on only once it
    /// has been checked against the key it names ([`Store::settle_pending`]).
    /// A bare name, the shape written before 0.25.0, is kept for that
    /// check to drop.
    fn read_pending(&self) -> Vec<PendingNote> {
        let path = self.root.join(PENDING_FILE);
        let Some(entries) = fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<Vec<serde_json::Value>>(&text).ok())
        else {
            return Vec::new();
        };
        entries
            .into_iter()
            .filter_map(|entry| match entry {
                serde_json::Value::String(name) => Some(PendingNote {
                    name,
                    tag: Vec::new(),
                }),
                other => serde_json::from_value(other).ok(),
            })
            .collect()
    }

    fn write_pending(&self, notes: &[PendingNote]) -> anyhow::Result<()> {
        let path = self.root.join(PENDING_FILE);
        if notes.is_empty() {
            return match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
            };
        }
        write_atomic(&path, serde_json::to_string(notes)?.as_bytes())
    }

    /// The MAC a note for `name` in this directory is tagged with, under
    /// `kek`, the key the key store keeps under that name.
    ///
    /// Only somebody holding the key can make it, and the key is in this
    /// installation's key store, so a note that checks out was written by
    /// this installation. The directory is in it so that a note copied
    /// from another data directory of the same account, naming that
    /// directory's key, does not check out here.
    fn pending_mac(&self, name: &str, kek: &[u8; 32]) -> hmac::Hmac<sha2::Sha256> {
        use hmac::{KeyInit, Mac};
        let root = fs::canonicalize(&self.root).unwrap_or_else(|_| self.root.clone());
        let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(kek)
            .expect("HMAC takes a key of any length");
        mac.update(PENDING_DOMAIN);
        mac.update(root.to_string_lossy().as_bytes());
        mac.update(b"\0");
        mac.update(name.as_bytes());
        mac
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
    /// interrupted. `kek` is the key itself, which the note is tagged
    /// under.
    ///
    /// A failure here fails the change. The alternative is making a key
    /// with no record that it exists, which is the situation this exists to
    /// prevent.
    fn add_pending(&self, name: &str, kek: &[u8; 32]) -> anyhow::Result<()> {
        let mut notes = self.read_pending();
        notes.retain(|note| note.name != name);
        notes.push(PendingNote {
            name: name.to_owned(),
            tag: {
                use hmac::Mac;
                self.pending_mac(name, kek).finalize().into_bytes().to_vec()
            },
        });
        self.write_pending(&notes)
            .context("noting the key store entry that may need removing")
    }

    /// [`Store::add_pending`] for the key the directory runs on now, which
    /// the key store already holds and which is about to be superseded.
    fn note_existing(&self, name: &str) -> anyhow::Result<()> {
        let kek = crate::keystore::load(name)?.with_context(|| {
            format!("the key store no longer holds {name}, the key this directory runs on")
        })?;
        self.add_pending(name, &kek)
    }

    /// Take `name` off the list: its fate is settled, either way.
    fn clear_pending(&self, name: &str) {
        let notes: Vec<PendingNote> = self
            .read_pending()
            .into_iter()
            .filter(|note| note.name != name)
            .collect();
        let _ = self.write_pending(&notes);
    }

    /// Settle every note an interrupted change left behind. Called from
    /// [`Store::open`], before anything else reads the directory.
    ///
    /// Costs nothing on a normal start: with no `vault.pending` there is
    /// no note to settle and the key store is never asked anything.
    ///
    /// The file is plaintext and read before any unlock, so a note in it
    /// is only a claim. Until 0.25.0 the claim was enough: somebody who
    /// could write the directory could name any entry in the key store --
    /// another data directory's key, or this one's after moving
    /// `vault.json` aside -- and the next start deleted it, taking every
    /// file that key opened with it. A note is acted on now only when its
    /// tag checks out under the key it names, which only this
    /// installation holds. One that does not is dropped and nothing is
    /// deleted: a key left behind is a bounded exposure, and a key
    /// deleted on somebody else's word is a directory lost.
    fn settle_pending(&self) {
        for note in self.read_pending() {
            let kek = match crate::keystore::load(&note.name) {
                Ok(Some(kek)) => kek,
                // Nothing under that name: nothing to take out.
                Ok(None) => {
                    self.clear_pending(&note.name);
                    continue;
                }
                // Asked again at the next start.
                Err(e) => {
                    tracing::warn!("cannot reach the key store to settle a note: {e:#}");
                    continue;
                }
            };
            let genuine = {
                use hmac::Mac;
                self.pending_mac(&note.name, &kek)
                    .verify_slice(&note.tag)
                    .is_ok()
            };
            if !genuine {
                tracing::warn!(
                    "vault.pending names a key store entry this installation did not note for \
                     this directory; it is left as it is"
                );
                self.clear_pending(&note.name);
                continue;
            }
            self.drop_unused_kek(&note.name);
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
            .is_some_and(|vault| vault.keystore_name().as_deref() == Some(name)))
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
        self.finish_rotation(&vault).map_err(VaultError::Other)?;
        self.load_generations().map_err(VaultError::Other)?;
        Ok(())
    }

    // --- rollback binding ----------------------------------------------------

    /// Read `state` and check it against the anchor in `vault.json`;
    /// finish a protection or an adoption the record itself says is
    /// unfinished; adopt generations in a directory from before the record
    /// existed; and refuse one whose vault says it keeps a record that is
    /// not there to be found.
    ///
    /// Called once the cipher is in place, and after a half-done key
    /// rotation has been finished, which rewrites files keeping whatever
    /// generation each carries.
    ///
    /// Nothing that goes wrong with the record fails the unlock: the
    /// person still has to be able to run the reset that gets out of it,
    /// and that needs the key. Every read and write refuses with the
    /// reason until then (`docs/design/format-changes.md` section 5.5).
    fn load_generations(&mut self) -> anyhow::Result<()> {
        let Some(cipher) = self.cipher.clone() else {
            return Ok(());
        };
        let Some(vault) = self.read_vault()? else {
            return Ok(());
        };
        let outcome = match vault.state_generation {
            Some(anchor) => match self.read_generations(&cipher, anchor) {
                Ok(state) if state.unfinished => {
                    self.adopt_generations(&cipher, Adoption::Unfinished)
                }
                Ok(state) => {
                    *self.generations.lock().unwrap_or_else(|e| e.into_inner()) =
                        Generations::Bound(state);
                    Ok(())
                }
                Err(e) => Err(e),
            },
            // The wrap says this directory keeps a record, and the number
            // that points at it is gone. The anchor is plaintext, and
            // deleting it is how a directory used to be made to adopt
            // whatever was put in it.
            None if vault.is_bound() => Err(anyhow::anyhow!(
                "vault.json says this directory keeps a record of what it last wrote, but the \
                 number that points at that record has been taken out of it, so an older or \
                 substituted copy of a file could not be told from the current one. Nothing has \
                 been opened. `silver --reset-rollback-protection` starts the record again from \
                 what is on disk, which gives up being able to prove anything about what \
                 happened to this directory before now."
            )),
            None => self.adopt_legacy(&cipher),
        };
        if let Err(e) = outcome {
            tracing::error!("{e:#}");
            *self.generations.lock().unwrap_or_else(|e| e.into_inner()) =
                Generations::Unreadable(format!("{e:#}"));
            return Ok(());
        }
        self.bind_uncovered(&cipher)?;
        if self.rebind_vault()? {
            self.cipher = Some(Arc::new(cipher.without_rebind()));
        }
        Ok(())
    }

    /// Rewrite a version 1 vault as version 3, once the record it anchors
    /// is in place, so that from now on the anchor cannot be taken out
    /// without the directory refusing to open. Says whether it did.
    ///
    /// Left alone while the record cannot be read: the reset that gets out
    /// of that ends here too.
    fn rebind_vault(&self) -> anyhow::Result<bool> {
        let Some(cipher) = self.cipher.as_deref() else {
            return Ok(false);
        };
        if !cipher.needs_rebind() || self.generations().state().is_none() {
            return Ok(false);
        }
        let vault = self.read_vault()?.context("reading the vault")?;
        if let Some(rebound) = cipher.rebound(&vault) {
            self.write_vault(&rebound)?;
            tracing::info!(
                "vault.json now says this directory keeps a record of what it wrote, so the \
                 record cannot be detached from it"
            );
        }
        Ok(true)
    }

    /// A version 1 vault with no anchor: a directory from before the record
    /// existed, which is adopted -- or a bound one that a version 1 vault
    /// has been put back over or had its anchor taken out, which is not.
    ///
    /// Told apart by what the directory holds. One from before the record
    /// has no `state`, and every file in it is sealed under its name
    /// alone; a record, a file at a generation, a conversation log filed
    /// under a name only a bound directory uses, or anything in the clear
    /// says otherwise. Plaintext is refused because nothing authenticated
    /// says a protection was cut short here: since 0.25.0 a protection
    /// writes that into its record first, and a cut-short one from an
    /// older client is the rare case the reset is for.
    fn adopt_legacy(&self, cipher: &FileCipher) -> anyhow::Result<()> {
        if let Some(trace) = self.binding_trace(cipher)? {
            bail!(
                "vault.json has no record of what this directory last wrote, but {trace}: either \
                 the record was taken away from a directory that kept one, or a protection by a \
                 client older than 0.25.0 was cut short. Nothing has been opened. If it was the \
                 latter, `silver --reset-rollback-protection` takes the files as they are and \
                 starts the record from them."
            );
        }
        // The record goes first, saying the adoption is unfinished, so a
        // crash part-way leaves a directory the next unlock finishes on
        // the record's word rather than on what the files look like.
        let unfinished = State {
            unfinished: true,
            ..State::default()
        };
        self.persist_generations(&unfinished, cipher)?;
        self.adopt_generations(cipher, Adoption::Unfinished)
    }

    /// Something in the directory that only a bound one holds, or that
    /// nothing but a cut-short protection leaves; `None` for a directory
    /// that is exactly what a client from before the record wrote.
    fn binding_trace(&self, cipher: &FileCipher) -> anyhow::Result<Option<String>> {
        for name in [STATE_FILE, STATE_PREVIOUS_FILE] {
            if self.root.join(name).exists() {
                return Ok(Some(format!("{name} is there")));
            }
        }
        for name in recrypted_files() {
            let path = self.root.join(name);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            if !FileCipher::is_encrypted(&bytes) {
                return Ok(Some(format!("{name} is in the clear")));
            }
            if cipher.open_file(name, &bytes)?.generation.is_some() {
                return Ok(Some(format!("{name} was written at a generation")));
            }
        }
        let dir = self.root.join(HISTORY_DIR);
        if dir.exists() {
            for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
                let path = entry?.path();
                let Some(stem) = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.strip_suffix(".jsonl"))
                else {
                    continue;
                };
                if Conversation::parse_id(stem).is_none() {
                    return Ok(Some(
                        "a conversation log is filed under a name only a directory that keeps a \
                         record uses"
                            .to_owned(),
                    ));
                }
                let text = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                if lines_with_offsets(&text).any(|(_, line)| !line.starts_with(LINE_PREFIX)) {
                    return Ok(Some(
                        "a conversation log has a line in the clear".to_owned(),
                    ));
                }
            }
        }
        Ok(None)
    }

    /// Bring in the files the record did not cover when it was made.
    ///
    /// The relay's key log as replayed and the outbox were written bound
    /// to their names alone until roadmap item 66: unrecorded in a
    /// directory started on 0.16.0 or later, and recorded at generation 1
    /// by the adoption but since rewritten name-only in one that came up
    /// from 0.14.0. Each that exists is read through whichever shape it
    /// is in, written back at the next generation and recorded, and the
    /// record says so through `covers`, so this happens once per
    /// directory — and again after a client that does not know `covers`
    /// has written the record without it, since that is also a client
    /// that wrote the two files name-only
    /// (`docs/design/format-changes.md` section 5.7). A crash between
    /// the files and the record leaves `covers` where it was, and the
    /// next unlock does this again.
    fn bind_uncovered(&self, cipher: &FileCipher) -> anyhow::Result<()> {
        let mut generations = self.generations.lock().unwrap_or_else(|e| e.into_inner());
        let Generations::Bound(state) = &mut *generations else {
            return Ok(());
        };
        if state.covers >= COVERS_LOG_AND_OUTBOX {
            return Ok(());
        }
        for name in [TRANSPARENCY_FILE, OUTBOX_FILE] {
            let path = self.root.join(name);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            if !FileCipher::is_encrypted(&bytes) {
                // Nothing this client wrote: a bound directory holds no
                // plaintext. Left for the read to refuse, with the reason.
                continue;
            }
            let opened = cipher.open_file(name, &bytes).with_context(|| {
                format!(
                    "{name} could not be read while it was being brought into the record of what \
                     this directory writes; if it is damaged, move it aside"
                )
            })?;
            let at = state.generation + 1;
            write_atomic(&path, &cipher.encrypt_at(name, at, &opened.plain))?;
            state.wrote(name, at);
            state.generation = at;
        }
        state.covers = COVERS_LOG_AND_OUTBOX;
        self.persist_generations(state, cipher)?;
        tracing::info!(
            "the relay's key log and the outbox are in the record of what this directory writes"
        );
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

    /// Give a directory its first record of generations: one a protection
    /// has just been put on, one from before the record existed, or one the
    /// person has asked to start again.
    ///
    /// Every file is rewritten at generation 1 unless it already carries
    /// one, and recorded, and the anchor follows. What is accepted depends
    /// on why this is running ([`Adoption`]): a plaintext file is sealed in
    /// both cases, because each is one the authenticated record or the
    /// person has vouched for; a file already at a generation past 1 is
    /// accepted only at a reset. A crash part-way leaves the record saying
    /// it is unfinished, or (at a reset) no record that opens, and the next
    /// unlock or reset runs this again -- which is why each file is read
    /// whichever shape it is in.
    fn adopt_generations(&self, cipher: &FileCipher, mode: Adoption) -> anyhow::Result<()> {
        const FIRST: u64 = 1;
        let mut state = State {
            generation: FIRST,
            // Everything the re-encryption walks is stamped here, the
            // relay's key log and the outbox included, so there is
            // nothing left for `bind_uncovered` to bring in.
            covers: COVERS_LOG_AND_OUTBOX,
            ..State::default()
        };
        for name in recrypted_files() {
            let path = self.root.join(name);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let plain = if FileCipher::is_encrypted(&bytes) {
                // Either shape: name-only for a file this has not reached
                // yet, generation-bearing for one a run that did not
                // finish already converted.
                let opened = cipher.open_file(name, &bytes)?;
                match opened.generation {
                    // Further on than anything an unfinished protection or
                    // adoption writes: this is a directory that has been
                    // in use since, with an older record put back that
                    // says it is still being set up.
                    Some(at) if mode == Adoption::Unfinished && at > FIRST => bail!(
                        "{name} was written at generation {at}, further on than a protection or \
                         adoption that has not finished could have left it, so the record saying \
                         it is unfinished is an older copy put back. Nothing has been opened."
                    ),
                    Some(at) => {
                        state.wrote(name, at);
                        state.generation = state.generation.max(at);
                        continue;
                    }
                    None => opened.plain,
                }
            } else {
                // Left in the clear by the protection the record says is
                // unfinished, or taken as it stands at a reset.
                Zeroizing::new(bytes)
            };
            write_atomic(&path, &cipher.encrypt_at(name, FIRST, &plain))?;
            state.wrote(name, FIRST);
        }
        self.adopt_history(cipher, &mut state)?;
        self.persist_generations(&state, cipher)?;
        *self.generations.lock().unwrap_or_else(|e| e.into_inner()) = Generations::Bound(state);
        tracing::info!(
            "this data directory now records what it last wrote, so an older copy of one of its \
             files is refused rather than read"
        );
        Ok(())
    }

    /// Move history files off names that say whose they are, and record
    /// what each holds.
    ///
    /// A file already under its new name is one a run that did not finish
    /// had already moved, and is left alone but still recorded; a file
    /// under its old name is read there, written under the new one, and
    /// only then removed. So a crash leaves at worst both, and the next
    /// unlock finishes the job — which is why the old one goes last.
    fn adopt_history(&self, cipher: &FileCipher, state: &mut State) -> anyhow::Result<()> {
        let dir = self.root.join(HISTORY_DIR);
        if !dir.exists() {
            return Ok(());
        }
        let mut moved = 0usize;
        for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            let Some(stem) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".jsonl"))
            else {
                continue;
            };
            let old_name = format!("{HISTORY_DIR}/{stem}.jsonl");
            let Some(conversation) = Conversation::parse_id(stem) else {
                // Already under a name that says nothing, from a run that
                // did not finish. Its lines are bound to that name, so it
                // stays where it is; all it needs is to be in the index,
                // and the id for that is not in the file name any more.
                let known = state
                    .conversations()
                    .find(|(n, _)| *n == old_name)
                    .map(|(_, id)| id.to_owned());
                if let Some(id) = known {
                    let bytes = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    state.wrote_history(&old_name, &id, bytes);
                }
                continue;
            };
            // From the record being built, not from `self`: the store's
            // own view is still the one from before this adoption, and
            // asking it would give back the name we are moving away from.
            let new_name = format!(
                "{HISTORY_DIR}/{}.jsonl",
                cipher.history_name(&conversation.id())
            );
            if new_name == old_name {
                continue;
            }
            let text =
                fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            // Every line is bound to the file's name, so a rename means
            // re-encrypting each one. The ciphertext of a line is as long
            // as it was, so the offsets do not move.
            let mut out = String::new();
            for (at, line) in lines_with_offsets(&text) {
                // A line in the clear is one the protection being finished
                // here had not reached; nothing else gets this far with
                // one (see `binding_trace`).
                let plain = if line.starts_with(LINE_PREFIX) {
                    decode_line(Some(cipher), &old_name, at, line)?
                } else {
                    line.to_owned()
                };
                out.push_str(&encode_line(
                    Some(cipher),
                    &new_name,
                    out.len() as u64,
                    &plain,
                ));
                out.push('\n');
            }
            write_atomic(&self.root.join(&new_name), out.as_bytes())?;
            state.wrote_history(&new_name, &conversation.id(), out.len() as u64);
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            state.removed_history(&old_name);
            moved += 1;
        }
        if moved > 0 {
            tracing::info!(
                "{moved} conversation logs are no longer filed under the name of who they are \
                 with, so a listing of this directory is no longer the contact list"
            );
        }
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
        // The anchor in `vault.json` stays where it is until the new
        // record replaces it: taking it out first, as this did until
        // 0.25.0, left a crash here looking like a directory from before
        // the record existed. Now a crash leaves a record that does not
        // open, and the reset is run again.
        for name in [STATE_FILE, STATE_PREVIOUS_FILE] {
            let path = self.root.join(name);
            if path.exists() {
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            }
        }
        *self.generations.lock().unwrap_or_else(|e| e.into_inner()) = Generations::Unbound;
        tracing::warn!(
            "the record of what this directory last wrote was started again; whether any of its \
             files was replaced with an older copy before now can no longer be told"
        );
        self.adopt_generations(&cipher, Adoption::Reset)?;
        self.rebind_vault()?;
        Ok(())
    }

    /// Unlock a directory whose wrapping key lives in this computer's key
    /// store.
    pub fn unlock_with_keystore(&mut self) -> anyhow::Result<()> {
        let vault = self
            .read_vault()?
            .context("the data directory is not protected")?;
        let Some(name) = vault.keystore_name() else {
            bail!("the data directory is not protected by the key store");
        };
        let kek = crate::keystore::load(&name)?.context(
            "this computer's key store has no key for this data directory: it was copied from \
             another computer or account, or the key was removed; restore from a backup or \
             start over with a fresh data directory",
        )?;
        let cipher = FileCipher::unlock_with_kek(&vault, &kek).map_err(|e| {
            anyhow::anyhow!("the key in the key store does not open this vault: {e}")
        })?;
        self.cipher = Some(Arc::new(cipher));
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

    /// Encrypt everything under a key kept in the operating system's key
    /// store. For a directory that is not protected yet.
    pub fn protect_with_keystore(&mut self) -> anyhow::Result<()> {
        if self.protection() != Protection::None {
            bail!("the data directory is already protected");
        }
        let kdf = Kdf::keystore();
        let name = kdf.keystore_name();
        let kek = crate::keystore::fresh_key();
        self.add_pending(&name, &kek)?;
        crate::keystore::put(&name, &kek)?;
        let sealed = self.seal_under_kek(&kek, kdf);
        // Either way the key's fate is decided: the vault names it, or it
        // goes. The note only outlives a crash.
        self.drop_unused_kek(&name);
        sealed
    }

    fn seal_under_kek(&mut self, kek: &[u8; 32], kdf: Kdf) -> anyhow::Result<()> {
        let (_, cipher) = FileCipher::create_with_kek(kek);
        self.protect_fresh(
            Arc::new(cipher),
            |cipher, anchor| Ok(cipher.wrap_under_kek(kek, kdf, anchor)),
            "the data directory is now protected, but not every file could be encrypted; \
             the rest are sealed the next time it is unlocked",
        )
    }

    /// Protect a directory that had no protection, under `cipher`, with
    /// the vault `vault` makes for a given anchor.
    ///
    /// Three writes, in an order chosen so that a crash between any two
    /// leaves a directory that opens. First the record, saying the
    /// protection is unfinished: under the new key, and naming no file,
    /// so a crash before the vault leaves an unprotected directory with a
    /// record nothing reads, which the next protection replaces. Then the
    /// vault, pointing at that record. It holds the only copy of the data
    /// key; written last, as it was before 0.10.1, a crash left files
    /// encrypted under a key that had never been written down -- every
    /// message, contact and key lost. Then the files. A crash among them
    /// leaves some plain and some sealed, which the next unlock finishes
    /// because the record says it is to: plaintext in a protected
    /// directory is accepted on that word and on nothing else. Until
    /// 0.25.0 a cut-short protection was recognised by the anchor being
    /// absent, which anybody who can write `vault.json` can arrange.
    fn protect_fresh(
        &mut self,
        cipher: Arc<FileCipher>,
        vault: impl FnOnce(&FileCipher, Option<u64>) -> anyhow::Result<VaultFile>,
        cut_short: &'static str,
    ) -> anyhow::Result<()> {
        for name in [STATE_FILE, STATE_PREVIOUS_FILE] {
            let path = self.root.join(name);
            if path.exists() {
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            }
        }
        let unfinished = State {
            unfinished: true,
            ..State::default()
        };
        let record = serde_json::to_vec(&unfinished).context("encoding the file generations")?;
        write_atomic(
            &self.root.join(STATE_FILE),
            &cipher.encrypt(STATE_FILE, &record),
        )?;
        self.write_vault(&vault(&cipher, Some(unfinished.generation))?)?;
        self.cipher = Some(cipher.clone());
        self.recrypt_all(None, Some(&cipher)).context(cut_short)?;
        self.load_generations()?;
        if let Some(why) = self.generations().refusal() {
            bail!("{why}");
        }
        Ok(())
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
            Protection::SecurityKey => bail!(
                "a security key protects the data directory; its recovery passphrase is changed \
                 instead"
            ),
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
                let old_name = old
                    .keystore_name()
                    .context("the vault names no key store key")?;
                self.note_existing(&old_name)?;
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
                let (mut vault, cipher) = FileCipher::create(passphrase, kdf)?;
                self.protect_fresh(
                    Arc::new(cipher),
                    move |_, anchor| {
                        vault.state_generation = anchor;
                        Ok(vault)
                    },
                    "the passphrase is set, but not every file could be encrypted; the rest \
                     are sealed the next time the directory is unlocked",
                )
            }
        }
    }

    /// Forget the passphrase. With a key store at hand the files stay
    /// encrypted under a key kept there; otherwise they are stored
    /// unencrypted again. Says which happened.
    pub fn remove_passphrase(&mut self) -> anyhow::Result<Protection> {
        if self.protection() == Protection::SecurityKey {
            bail!(
                "a security key protects the data directory, and its recovery passphrase stays \
                 while it does; remove the security keys first"
            );
        }
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
            let kek = crate::keystore::fresh_key();
            self.add_pending(&name, &kek)?;
            crate::keystore::put(&name, &kek)?;
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
        let keystore_name = vault.keystore_name();
        if let Some(name) = &keystore_name {
            self.note_existing(name)?;
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

    // --- security keys (docs/design/security-key.md) ----------------------

    /// The names of the security keys that open this directory.
    pub fn security_keys(&self) -> anyhow::Result<Vec<String>> {
        Ok(self
            .read_vault()?
            .map(|vault| {
                vault
                    .security_key_slots()
                    .map(|(_, slot)| slot.label.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Unlock with whichever enrolled security key is plugged in: its PIN,
    /// then its touch. The recovery passphrase goes through
    /// [`Store::unlock`].
    pub fn unlock_with_security_key(&mut self, auth: &mut dyn Authenticator) -> anyhow::Result<()> {
        let vault = self
            .read_vault()?
            .filter(VaultFile::has_security_keys)
            .context("no security key protects the data directory")?;
        let (index, output) = ask_security_key(&vault, auth)?;
        let cipher = FileCipher::unlock_with_security_key(&vault, index, &output)?;
        self.cipher = Some(Arc::new(cipher));
        self.finish_rotation(&vault)?;
        self.load_generations()?;
        Ok(())
    }

    /// Enroll a security key, named `label`, to open the directory.
    ///
    /// The first key needs `recovery`, the recovery passphrase, which
    /// opens the directory when no key can; it replaces whatever protected
    /// the directory before, and the files move to a fresh data key, so
    /// that the old passphrase or key store key opens nothing written from
    /// now on. A second key is only a slot more, and needs the directory
    /// unlocked and nothing else.
    pub fn add_security_key(
        &mut self,
        auth: &mut dyn Authenticator,
        label: &str,
        recovery: Option<&str>,
    ) -> anyhow::Result<()> {
        self.add_security_key_with(auth, label, recovery, Kdf::default_params())
    }

    #[doc(hidden)]
    pub fn add_security_key_with(
        &mut self,
        auth: &mut dyn Authenticator,
        label: &str,
        recovery: Option<&str>,
        kdf: Kdf,
    ) -> anyhow::Result<()> {
        self.ensure_unlocked()?;
        let label = label.trim();
        if label.is_empty() {
            bail!("a security key needs a name");
        }
        let protection = self.protection();
        let vault = self.read_vault()?;
        if let Some(vault) = &vault
            && vault.slots.iter().any(|slot| slot.label == label)
        {
            bail!("a security key named {label:?} is already enrolled");
        }
        let recovery = match protection {
            Protection::SecurityKey => None,
            _ => {
                let recovery = recovery
                    .filter(|r| !r.is_empty())
                    .context("the first security key needs a recovery passphrase")?;
                Some(SlotKey::passphrase(recovery, kdf, RECOVERY_LABEL)?)
            }
        };
        // The key first: until it has answered nothing has changed.
        let salt = fresh_slot_salt();
        let enrolled = auth
            .enroll(SECURITY_KEY_RP, &salt)
            .map_err(security_key_error)?;
        let key = SlotKey::security_key(
            enrolled.credential_id,
            salt,
            SECURITY_KEY_RP,
            label,
            &enrolled.secret,
        );
        match (protection, recovery) {
            (Protection::SecurityKey, _) => {
                let mut vault = vault.context("reading the vault")?;
                let cipher = self
                    .cipher
                    .clone()
                    .context("the data directory is locked")?;
                cipher.add_slot(&mut vault, &key);
                self.write_vault(&vault)
            }
            (Protection::None, Some(recovery)) => self.protect_fresh(
                Arc::new(FileCipher::fresh()),
                |cipher, anchor| Ok(cipher.wrap_slots(&[key, recovery], anchor)),
                "the security key is enrolled, but not every file could be encrypted; the rest \
                 are sealed the next time the directory is unlocked",
            ),
            (_, Some(recovery)) => {
                let cipher = self
                    .cipher
                    .clone()
                    .context("the data directory is locked")?;
                // As in `set_passphrase_with`: noted before the rotation,
                // taken out after it.
                let old_name = vault.as_ref().and_then(VaultFile::keystore_name);
                if let Some(name) = &old_name {
                    self.note_existing(name)?;
                }
                let anchor = self.anchor();
                let slots = [key, recovery];
                self.rotate_key(&cipher, |c| Ok(c.wrap_slots(&slots, anchor)))?;
                if let Some(name) = old_name {
                    crate::keystore::delete(&name).context(
                        "the security key is enrolled and the files are under a new key, but \
                         the old key could not be taken out of the key store; remove it by hand",
                    )?;
                    self.clear_pending(&name);
                }
                Ok(())
            }
            (_, None) => unreachable!("asked for above"),
        }
    }

    /// Take the security key named `label` off: the directory moves to a
    /// fresh data key, so that an old copy of `vault.json` and the removed
    /// key together open nothing written afterwards.
    ///
    /// Wrapping the new key needs every slot that stays: the recovery
    /// passphrase, and each other key once, plugged in, PIN and touch. A
    /// key that cannot be had is put to `missing`, which says to try it
    /// again, to drop it, or to give up. With no key left, the recovery
    /// passphrase becomes the directory's ordinary passphrase.
    pub fn remove_security_key(
        &mut self,
        label: &str,
        auth: &mut dyn Authenticator,
        recovery: &str,
        missing: &mut dyn FnMut(&str, &anyhow::Error) -> Missing,
    ) -> anyhow::Result<Protection> {
        self.rekey_security_keys(
            Some(label),
            auth,
            recovery,
            recovery,
            missing,
            Kdf::default_params(),
        )
    }

    /// The recovery passphrase changed from `old` to `new`, the directory
    /// moved to a fresh data key under every key as for a removal, so that
    /// the old passphrase opens nothing written from now on.
    pub fn change_recovery_passphrase(
        &mut self,
        auth: &mut dyn Authenticator,
        old: &str,
        new: &str,
        missing: &mut dyn FnMut(&str, &anyhow::Error) -> Missing,
    ) -> anyhow::Result<Protection> {
        self.rekey_security_keys(None, auth, old, new, missing, Kdf::default_params())
    }

    #[doc(hidden)]
    pub fn rekey_security_keys(
        &mut self,
        without: Option<&str>,
        auth: &mut dyn Authenticator,
        recovery: &str,
        new_recovery: &str,
        missing: &mut dyn FnMut(&str, &anyhow::Error) -> Missing,
        kdf: Kdf,
    ) -> anyhow::Result<Protection> {
        self.ensure_unlocked()?;
        if new_recovery.is_empty() {
            bail!("the recovery passphrase must not be empty");
        }
        let vault = self
            .read_vault()?
            .filter(VaultFile::has_security_keys)
            .context("no security key protects the data directory")?;
        if let Some(label) = without
            && !vault
                .security_key_slots()
                .any(|(_, slot)| slot.label == label)
        {
            bail!("no security key named {label:?} is enrolled");
        }
        if !FileCipher::is_recovery_passphrase(&vault, recovery)? {
            return Err(VaultError::WrongPassphrase.into());
        }
        let cipher = self
            .cipher
            .clone()
            .context("the data directory is locked")?;
        let mut slots = Vec::new();
        for (_, slot) in vault.security_key_slots() {
            if Some(slot.label.as_str()) == without {
                continue;
            }
            let SlotKind::Fido2 {
                credential_id,
                rp_id,
                ..
            } = &slot.kind
            else {
                unreachable!("a security key slot");
            };
            check_rp(rp_id)?;
            // A fresh salt: an output seen before opens nothing new.
            let salt = fresh_slot_salt();
            loop {
                match auth.secret(SECURITY_KEY_RP, &[(credential_id, &salt)]) {
                    Ok((_, output)) => {
                        slots.push(SlotKey::security_key(
                            credential_id.clone(),
                            salt,
                            SECURITY_KEY_RP,
                            &slot.label,
                            &output,
                        ));
                        break;
                    }
                    Err(e) => {
                        let e = security_key_error(e);
                        match missing(&slot.label, &e) {
                            Missing::Retry => continue,
                            Missing::Drop => break,
                            Missing::Cancel => return Err(e),
                        }
                    }
                }
            }
        }
        let recovery_label = vault
            .passphrase_slot()
            .map_or(RECOVERY_LABEL.to_owned(), |(_, slot)| slot.label.clone());
        let anchor = self.anchor();
        if slots.is_empty() {
            self.rotate_key(&cipher, |c| {
                c.wrap_under_passphrase(new_recovery, kdf.clone(), anchor)
            })?;
            return Ok(Protection::Passphrase);
        }
        slots.push(SlotKey::passphrase(new_recovery, kdf, &recovery_label)?);
        self.rotate_key(&cipher, |c| Ok(c.wrap_slots(&slots, anchor)))?;
        Ok(Protection::SecurityKey)
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
    /// same, so this is also how a rotation a crash cut short is finished,
    /// with the same cipher on both sides. From a cipher, a file in the
    /// clear is refused: in a protected directory it is not one this
    /// client wrote, and sealing it would make it so. Until 0.25.0 it was
    /// sealed, which is how a plaintext `config.json` or `blocked.json`
    /// dropped into the directory became one the client vouched for.
    fn recrypt_all(
        &self,
        from: Option<&FileCipher>,
        to: Option<&FileCipher>,
    ) -> anyhow::Result<()> {
        // Taken before anything is rewritten, because it is the only
        // thing that still says which conversation a file that is named
        // after nothing holds.
        let index: HashMap<String, String> = self
            .generations()
            .state()
            .map(|state| {
                state
                    .conversations()
                    .map(|(n, id)| (n.to_owned(), id.to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        for name in recrypted_files() {
            let path = self.root.join(name);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path)?;
            // Keeps whichever generation the file already carries: a
            // rotation changes the key, not what was written.
            let (generation, plain) = match from {
                Some(_) if !FileCipher::is_encrypted(&bytes) => bail!(
                    "{name} is in the clear in a directory protected at rest, so it is not \
                     something this client wrote; nothing has been changed"
                ),
                Some(c) => {
                    let opened = c.open_file(name, &bytes)?;
                    (opened.generation, opened.plain)
                }
                None => (None, Zeroizing::new(decode_file(None, name, &bytes)?)),
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
        // generation of its own here. Its previous version moves too: it
        // is what an interrupted write falls back to, and under the old
        // key it would open for nobody once that key is dropped. A fresh
        // protection (`from` is `None`) wrote its record under the new key
        // just before, and there is nothing to move.
        if let Some(from) = from {
            for name in [STATE_FILE, STATE_PREVIOUS_FILE] {
                let path = self.root.join(name);
                if !path.exists() {
                    continue;
                }
                match to {
                    Some(c) => {
                        let bytes = fs::read(&path)?;
                        match from.decrypt(STATE_FILE, &bytes) {
                            Ok(plain) => write_atomic(&path, &c.encrypt(STATE_FILE, &plain))?,
                            Err(e) if name == STATE_FILE => return Err(e),
                            // Only ever a fallback, and one that would
                            // never open again: dropped rather than let it
                            // stop the move.
                            Err(_) => fs::remove_file(&path)?,
                        }
                    }
                    // Going back to plaintext: there is nothing to bind a
                    // generation into any more, so the record goes with
                    // the encryption rather than being left readable.
                    None => fs::remove_file(&path)?,
                }
            }
            if to.is_none() {
                *self.generations.lock().unwrap_or_else(|e| e.into_inner()) = Generations::Unbound;
            }
        }
        // Files received while `encrypted_downloads` was on are bound to
        // their own name, not to a path under the data directory, and sit
        // beside plain ones, which stay as they are. On the way out they
        // are decrypted, since the key is about to be gone; on a rotation
        // they move onto the new key with everything else, or they would
        // be the one thing left behind when the old key is dropped. One
        // received before downloads had a shape of their own is moved into
        // it on the way.
        //
        // What a received file begins with is the sender's to choose, so
        // one that looks encrypted and does not open is a plain file that
        // happens to, and is left alone. It used to stop the whole pass,
        // and with it every change of protection, for good.
        let downloads = self.downloads_dir();
        if let Some(from) = from
            && downloads.exists()
        {
            for entry in fs::read_dir(&downloads)? {
                let path = entry?.path();
                if !path.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let bytes = fs::read(&path)?;
                if !FileCipher::is_encrypted_download(&bytes) {
                    continue;
                }
                let plain = match from.decrypt_download(name, &bytes) {
                    Ok(plain) => plain,
                    Err(e) => {
                        tracing::warn!(
                            "a received file begins like one written under the data key and does \
                             not open as one; it is left as it is: {e:#}"
                        );
                        continue;
                    }
                };
                match to {
                    Some(c) => write_atomic(&path, &c.encrypt_download(name, &plain))?,
                    None => write_atomic(&path, &plain)?,
                }
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
            // Going back to plaintext takes the record of what each file
            // is called with it, so the file has to go back to the name
            // that says whose it is while the record can still say.
            let to_name = match to {
                None => index
                    .get(name.as_str())
                    .and_then(|id| Conversation::parse_id(id))
                    .map(|c| c.plain_file_name())
                    .unwrap_or_else(|| name.clone()),
                Some(_) => name.clone(),
            };
            // Read at the offset each line is at now, written at the
            // offset it lands on: blank lines are dropped, so the two are
            // not the same and the line has to be re-bound.
            for (at, line) in lines_with_offsets(&text) {
                let plain = decode_line(from, &name, at, line)?;
                out.push_str(&encode_line(to, &to_name, out.len() as u64, &plain));
                out.push('\n');
            }
            if to_name == name {
                write_atomic(&path, out.as_bytes())?;
            } else {
                write_atomic(&self.root.join(&to_name), out.as_bytes())?;
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            }
        }
        Ok(())
    }

    // --- files ---------------------------------------------------------------

    /// One of the store's files whole, decrypted, in memory that is
    /// wiped when it goes: `identity.json` and the session state pass
    /// through here.
    ///
    /// `None` for a file that was never written. In a bound directory a
    /// file the record names and that is not there was not "never
    /// written" but deleted by somebody else, since this client records
    /// every removal it makes, and it is refused: read as absent, a
    /// deleted `blocked.json` unblocked everybody, a deleted
    /// `transparency.json` started the relay's key log over, and a
    /// deleted `identity.json` had a new identity made in its place.
    fn read_file(&self, name: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.ensure_unlocked()?;
        let path = self.root.join(name);
        let generations = self.generations();
        if self.cipher.is_some()
            && let Some(why) = generations.refusal()
        {
            bail!("{why}");
        }
        if !path.exists() {
            if self.cipher.is_some() && generations.state().is_some_and(|s| s.records(name)) {
                bail!(
                    "{name} is missing, but this directory wrote it and never removed it: it has \
                     been deleted, and is not read as though it had never existed. Nothing has \
                     been read in its place. If it is gone for good, `silver \
                     --reset-rollback-protection` starts the record again from what is on disk."
                );
            }
            return Ok(None);
        }
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let Some(cipher) = self.cipher.as_deref() else {
            return Ok(Some(Zeroizing::new(decode_file(None, name, &bytes)?)));
        };
        if !FileCipher::is_encrypted(&bytes) {
            // A protection a crash cut short is finished at the unlock,
            // on the record's word, before anything is read; there is no
            // plaintext left by this client after that.
            bail!(
                "{name} is in the clear in a directory protected at rest, so it is not something \
                 this client wrote. Nothing has been read from it."
            );
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
                     from it. If a client older than this one has been run on this directory \
                     since, that is the cause, and `silver --reset-rollback-protection` starts \
                     the record again from what is on disk.",
                    match opened.generation {
                        Some(at) => format!("generation {at}"),
                        None => "no generation at all".to_owned(),
                    }
                );
            }
        }
        Ok(Some(opened.plain))
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
        // Held through the record's write. Several writers share one
        // record (the front end, and the sessions, the key log and the
        // outbox in the connection), and two records landing out of
        // order would leave a file two generations ahead, which the next
        // unlock reads as tampering.
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
        self.persist_generations(state, &cipher)
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

    /// A private file's bytes, if it exists. Moved out of the wiped
    /// buffer rather than copied, so there is never a second copy.
    pub(crate) fn read_private_file(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .read_file(name)?
            .map(|mut bytes| std::mem::take(&mut *bytes)))
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
        let text = Zeroizing::new(serde_json::to_string_pretty(&identity.to_secrets())?);
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
        let text = Zeroizing::new(serde_json::to_string_pretty(&file)?);
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
        let text = Zeroizing::new(serde_json::to_string_pretty(&identity.to_secrets())?);
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
        if let Some(existing) = self.revocation()?
            && existing.identity == identity.user_id()
        {
            return Ok(existing);
        }
        // None stored, or one for a different key (a restored or rotated
        // identity): mint a fresh one.
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
    ///
    /// In a bound directory they are written empty instead, through the
    /// same write as everything else. Removing a file the record names
    /// would be read as somebody deleting it, and the old contents go all
    /// the same: the empty file is renamed over them.
    pub fn clear_sessions(&self) -> anyhow::Result<()> {
        if self.cipher.is_some() && self.generations().state().is_some() {
            self.save_prekeys(&PrekeyFile::default())?;
            return self.save_sessions(&SessionsFile::default());
        }
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
            .and_then(|vault| vault.keystore_name());
        // Noted before the vault naming it goes, so a wipe that dies partway
        // through still has the key taken out on the next start rather than
        // leaving it beside whatever copy was made first.
        if let Some(name) = &keystore_entry {
            let _ = self.note_existing(name);
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
        // What a write a crash interrupted leaves beside its file
        // (`<name>.<pid>.tmp`): a whole copy of whichever file it was,
        // `identity.json` included.
        for dir in [self.root.clone(), history] {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let path = entry?.path();
                if path.is_file() && is_write_leftover(&path) {
                    fs::remove_file(&path)
                        .with_context(|| format!("removing {}", path.display()))?;
                }
            }
        }
        // The update waiting to be put in place and the version an update
        // replaced: neither is the identity's, but a device that has just
        // been erased should not be left holding a program somebody else
        // could have put there for it to run.
        let update = self.root.join(UPDATE_DIR);
        if update.exists() {
            fs::remove_dir_all(&update)
                .with_context(|| format!("removing {}", update.display()))?;
        }
        *self.generations.lock().unwrap_or_else(|e| e.into_inner()) = Generations::Unbound;
        // Last, so that a failure earlier leaves a directory whose key is
        // still where its vault says. A key store that cannot be reached
        // is not worth failing the wipe over: the files are already gone,
        // and the note naming the key is then the one thing kept, so the
        // next start tries again rather than forget the key exists.
        let kept = match keystore_entry {
            Some(name) => crate::keystore::delete(&name).is_err().then_some(name),
            None => None,
        };
        let notes: Vec<PendingNote> = self
            .read_pending()
            .into_iter()
            .filter(|note| Some(&note.name) == kept.as_ref())
            .collect();
        self.write_pending(&notes)?;
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
        self.append_history_line(
            &Conversation::Contact(*peer),
            &serde_json::to_string(entry)?,
        )
    }

    /// A group's conversation log, kept like a contact's under
    /// `history/group-<id>.jsonl`.
    pub fn append_group_history(
        &self,
        group: &silver_protocol::GroupId,
        entry: &HistoryEntry,
    ) -> anyhow::Result<()> {
        self.append_history_line(&Conversation::Group(*group), &serde_json::to_string(entry)?)
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
        self.append_history_line(&Conversation::Group(*group), &serde_json::to_string(&line)?)
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
        self.append_history_line(
            &Conversation::Contact(*peer),
            &serde_json::to_string(&line)?,
        )
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
        self.append_history_line(
            &Conversation::Contact(*peer),
            &serde_json::to_string(&line)?,
        )
    }

    fn append_history_line(&self, conversation: &Conversation, json: &str) -> anyhow::Result<()> {
        self.ensure_unlocked()?;
        let name = self.history_file(conversation);
        if let Some(why) = self.generations().refusal() {
            bail!("{why}");
        }
        let path = self.root.join(&name);
        let mut file = append_private(&path)?;
        let mut at = file.metadata()?.len();
        // A line cut short by a crash has no newline; start a fresh one
        // rather than glue this line onto it and lose both.
        let broken = !ends_with_newline(&mut file)?;
        if broken {
            at += 1;
        }
        let mut line = encode_line(self.cipher.as_deref(), &name, at, json);
        line.push('\n');
        if broken {
            line.insert(0, '\n');
        }
        file.write_all(line.as_bytes())?;
        file.flush()?;
        self.note_history_write(&name, conversation)
    }

    /// Record a history file's length after a write, so that a later
    /// truncation is refused rather than read as a shorter conversation.
    ///
    /// Counted from the file rather than from what was just appended,
    /// which makes this idempotent: an append interrupted before it got
    /// here leaves a longer file than the record says, and the next one
    /// through settles it. Longer is safe -- a line at an offset the
    /// record has not reached is one somebody encrypted there, which
    /// takes the key.
    fn note_history_write(&self, name: &str, conversation: &Conversation) -> anyhow::Result<()> {
        let Some(cipher) = self.cipher.clone() else {
            return Ok(());
        };
        let mut generations = self.generations.lock().unwrap_or_else(|e| e.into_inner());
        let Generations::Bound(state) = &mut *generations else {
            return Ok(());
        };
        let bytes = fs::metadata(self.root.join(name))
            .map(|m| m.len())
            .unwrap_or(0);
        state.wrote_history(name, &conversation.id(), bytes);
        state.generation += 1;
        // Held through the record's write, as in `write_file`.
        self.persist_generations(state, &cipher)
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
        let old_name = self.history_file(&Conversation::Contact(*old));
        let old_path = self.root.join(&old_name);
        if !old_path.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&old_path)
            .with_context(|| format!("reading {}", old_path.display()))?;
        let new_name = self.history_file(&Conversation::Contact(*new));
        let new_path = self.root.join(&new_name);
        let mut out = append_private(&new_path)?;
        // Appended after whatever the new name already holds, so each
        // line is bound to where it lands there rather than where it sat
        // in the file it came from.
        let mut at = out.metadata()?.len();
        for (from_at, line) in lines_with_offsets(&text) {
            let plain = decode_line(self.cipher.as_deref(), &old_name, from_at, line)?;
            let mut encoded = encode_line(self.cipher.as_deref(), &new_name, at, &plain);
            encoded.push('\n');
            at += encoded.len() as u64;
            out.write_all(encoded.as_bytes())?;
        }
        out.flush()?;
        drop(out);
        // Forgotten before it goes: a file the record holds and the disk
        // does not is read as deleted by somebody else, so a crash between
        // the two must leave the file without its record, not the record
        // without its file.
        self.forget_history_file(&old_name)?;
        fs::remove_file(&old_path).with_context(|| format!("removing {}", old_path.display()))?;
        self.note_history_write(&new_name, &Conversation::Contact(*new))
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
        let generations = self.generations();
        if self.cipher.is_some()
            && let Some(why) = generations.refusal()
        {
            bail!("{why}");
        }
        if !path.exists() {
            // As for a whole file in `read_file`: a conversation the
            // record holds and the disk does not was deleted by somebody
            // else, not never started.
            if self.cipher.is_some() && generations.state().is_some_and(|s| s.records(name)) {
                bail!(
                    "a conversation log this directory wrote and never removed is missing: it \
                     has been deleted, and is not read as an empty conversation."
                );
            }
            return Ok(Vec::new());
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        // A conversation shorter than the record says has had its end cut
        // off, which is the one thing binding each line to its offset
        // cannot show: what is left is all genuine, there is just less of
        // it. Longer is an append this directory made and did not finish
        // recording.
        if let Some(recorded) = generations.state().and_then(|s| s.history_bytes(name))
            && (text.len() as u64) < recorded
        {
            bail!(
                "{name} is shorter than this directory last wrote it ({} bytes where it wrote \
                 {recorded}): the end of the conversation has been cut off. Nothing has been \
                 read from it.",
                text.len()
            );
        }
        let mut lines = Vec::new();
        for (at, line) in lines_with_offsets(&text) {
            let parsed = decode_line(self.cipher.as_deref(), name, at, line)
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
        let lines = self.read_history_lines(&self.history_file(conversation))?;
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
            // Each line is bound to where it lands in the file it is
            // being written into, not where it came from: a rewrite that
            // drops a message moves everything after it.
            let at = out.len() as u64;
            match line {
                Ok(parsed) => {
                    let json = serde_json::to_string(parsed)?;
                    out.push_str(&encode_line(self.cipher.as_deref(), name, at, &json));
                }
                Err(raw) => out.push_str(raw),
            }
            out.push('\n');
        }
        write_atomic(&self.root.join(name), out.as_bytes())?;
        let Some(conversation) = self
            .generations()
            .state()
            .and_then(|s| s.conversations().find(|(n, _)| *n == name))
            .and_then(|(_, id)| Conversation::parse_id(id))
            .or_else(|| self.conversation_of_file(name))
        else {
            return Ok(());
        };
        self.note_history_write(name, &conversation)
    }

    /// Where a conversation's log lives.
    ///
    /// With the directory protected this is a MAC of the conversation's
    /// id under the data key, so a directory listing is no longer the
    /// contact and group list (SM-C-25). Without protection there is no
    /// key to compute one with, and an attacker who can read the
    /// directory can read the messages anyway, so the plain name stands.
    fn history_file(&self, conversation: &Conversation) -> String {
        match self.cipher.as_deref() {
            Some(cipher) => format!(
                "{HISTORY_DIR}/{}.jsonl",
                cipher.history_name(&conversation.id())
            ),
            None => conversation.plain_file_name(),
        }
    }

    /// Forget a history file that has been removed, so that its record
    /// does not outlive it and turn its absence into a truncation.
    fn forget_history_file(&self, name: &str) -> anyhow::Result<()> {
        let Some(cipher) = self.cipher.clone() else {
            return Ok(());
        };
        let mut generations = self.generations.lock().unwrap_or_else(|e| e.into_inner());
        let Generations::Bound(state) = &mut *generations else {
            return Ok(());
        };
        state.removed_history(name);
        state.generation += 1;
        // Held through the record's write, as in `write_file`.
        self.persist_generations(state, &cipher)
    }

    /// Which conversation a history file's name belongs to, worked out
    /// from the name itself.
    fn conversation_of_file(&self, name: &str) -> Option<Conversation> {
        let stem = name
            .strip_prefix(&format!("{HISTORY_DIR}/"))?
            .strip_suffix(".jsonl")?;
        Conversation::parse_id(stem)
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
        self.append_history_line(conversation, &serde_json::to_string(&line)?)
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
        self.append_history_line(conversation, &serde_json::to_string(&line)?)
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
        self.append_history_line(conversation, &serde_json::to_string(&line)?)
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
        let name = self.history_file(conversation);
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
        let name = self.history_file(conversation);
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

    /// Every conversation that has a log.
    ///
    /// From the index in `state` where there is one, since a history file
    /// is named after nothing once the directory is protected (SM-C-25)
    /// and its name no longer says whose it is. The index is what makes
    /// this list complete, which matters more than it looks: a
    /// conversation the expiry sweep cannot see is one whose
    /// disappearing messages never disappear, and history outlives a
    /// contact who was removed, so rebuilding the list from the contacts
    /// and groups files would be a different set.
    ///
    /// A directory with no protection is still read from its file names,
    /// which are still the ids.
    pub fn conversations(&self) -> anyhow::Result<Vec<Conversation>> {
        if let Some(state) = self.generations().state() {
            let mut out: Vec<Conversation> = state
                .conversations()
                .filter_map(|(_, id)| Conversation::parse_id(id))
                .collect();
            out.sort_by_key(|c| c.id());
            return Ok(out);
        }
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
            if let Some(conversation) = Conversation::parse_id(stem) {
                out.push(conversation);
            }
        }
        out.sort_by_key(|c| c.id());
        Ok(out)
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

/// One line of a line-oriented file, which sits at byte offset `at`.
///
/// The offset is bound in along with the name, so a line cannot be moved,
/// dropped or repeated without the lines around it failing to open: every
/// line after a change of length is at an offset it was not written at.
/// A line's own offset is what an append knows without reading the file,
/// which is why it is the offset and not the line's ordinal.
///
/// With a cipher, a line in the clear is refused. It is not one this
/// client wrote: a protection a crash cut short is finished at the unlock
/// on the record's word (`Store::adopt_history`), before anything reads a
/// conversation. Until 0.25.0 such a line was read as itself, so somebody
/// who could write the directory could add messages to an encrypted
/// conversation, with the record intact, by writing them in plain JSON.
fn decode_line(
    cipher: Option<&FileCipher>,
    name: &str,
    at: u64,
    line: &str,
) -> anyhow::Result<String> {
    match (cipher, line.starts_with(LINE_PREFIX)) {
        (Some(c), true) => c.decrypt_line_at(name, Some(at), line).or_else(|e| {
            // Written before offsets were bound in. A directory that
            // still holds such lines is one this version has not
            // rewritten yet.
            c.decrypt_line(name, line).map_err(|_| e)
        }),
        (Some(_), false) => bail!(
            "a line of {name} is in the clear in a directory protected at rest, so it is not one \
             this client wrote"
        ),
        (None, true) => bail!("{name} is encrypted but the data directory is not unlocked"),
        (None, false) => Ok(line.to_owned()),
    }
}

fn encode_line(cipher: Option<&FileCipher>, name: &str, at: u64, plain: &str) -> String {
    match cipher {
        Some(c) => c.encrypt_line_at(name, Some(at), plain),
        None => plain.to_owned(),
    }
}

/// Each non-blank line of `text` with the byte offset it sits at.
///
/// Blank lines are skipped but still counted towards the offsets, since
/// they take up room in the file: a reader that ignored them would be
/// looking at different offsets from the writer.
fn lines_with_offsets(text: &str) -> impl Iterator<Item = (u64, &str)> {
    let mut at = 0u64;
    text.split('\n').filter_map(move |line| {
        let here = at;
        at += line.len() as u64 + 1;
        (!line.trim().is_empty()).then_some((here, line))
    })
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
///
/// Always a new file. Whatever is at `path` is removed first and the file
/// is created exclusively, so the mode asked for is the mode it gets.
/// Opening an existing file to truncate it, as this did until 0.25.0,
/// kept that file's owner and mode -- a backup written over a file
/// somebody else had made readable was readable to them -- and followed
/// a symbolic link put where a temporary file was about to go.
pub(crate) fn create_private(path: &Path) -> anyhow::Result<File> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("replacing {}", path.display())),
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("creating {}", path.display()))
}

/// Whether `path` is what [`write_atomic`] writes before its rename:
/// `<name>.<digits>.tmp`.
fn is_write_leftover(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(rest) = name.strip_suffix(".tmp") else {
        return false;
    };
    rest.rsplit_once('.')
        .is_some_and(|(_, pid)| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
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
        let path = dir
            .path()
            .join(store.history_file(&Conversation::Contact(peer)));
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
        assert_eq!(
            mode(&root.join(store.history_file(&Conversation::Contact(peer)))) & 0o077,
            0
        );

        // A directory that is not ours is left as it is: --data-dir could
        // name anything, and tightening someone's home directory with it
        // would be the program's doing, not theirs.
        let theirs = dir.path().join("theirs");
        fs::create_dir_all(&theirs).unwrap();
        fs::set_permissions(&theirs, fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir(&theirs, Some("identity.json")).unwrap();
        assert_eq!(mode(&theirs), 0o755);

        // One `silver update` made before the first start, holding only
        // the update it downloaded, is ours all the same.
        let early = dir.path().join("early");
        fs::create_dir_all(early.join(UPDATE_DIR)).unwrap();
        fs::set_permissions(&early, fs::Permissions::from_mode(0o755)).unwrap();
        Store::open(&early).unwrap();
        assert_eq!(mode(&early), 0o700, "a directory an update made first");
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
            .wrap_under_passphrase("first", Kdf::fast(), store.anchor())
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

    /// SM-C-25: the directory listing was the contact and group list.
    /// Everything that was in a file name has to still be findable, so
    /// this checks the list is complete and the names say nothing —
    /// including for a conversation with somebody who is not a contact,
    /// which is the case rebuilding the list from `contacts.json` would
    /// miss.
    #[test]
    fn history_names_say_nothing_and_every_conversation_is_still_found() {
        let (store, dir) = bound_store();
        let peer = Identity::generate().user_id();
        let stranger = Identity::generate().user_id();
        let group = silver_protocol::GroupId::generate();
        store.append_history(&peer, &entry(0)).unwrap();
        store.append_history(&stranger, &entry(1)).unwrap();
        store.append_group_history(&group, &entry(2)).unwrap();
        // Only one of them is a contact, and the other two must be found
        // all the same.
        store.save_contacts(&[Contact::new(peer)]).unwrap();

        let mut found = store.conversations().unwrap();
        found.sort_by_key(|c| c.id());
        let mut want = vec![
            Conversation::Contact(peer),
            Conversation::Contact(stranger),
            Conversation::Group(group),
        ];
        want.sort_by_key(|c| c.id());
        assert_eq!(found, want, "every conversation with a log must be listed");

        for entry in fs::read_dir(dir.path().join(HISTORY_DIR)).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            for id in [peer.to_string(), stranger.to_string(), group.to_string()] {
                assert!(!name.contains(&id), "{name} names {id}");
            }
        }
    }

    /// A directory whose history is still filed under the contact's id is
    /// moved off those names on the next unlock, and the conversations
    /// stay readable and findable across the move.
    #[test]
    fn history_filed_under_a_contact_id_is_moved_on_the_next_unlock() {
        crate::keystore::use_mock_store();
        let (mut store, dir) = temp_store();
        store.load_or_create_identity().unwrap();
        let peer = Identity::generate().user_id();
        // Written while the directory is unprotected, so it lands under
        // the name an older version used.
        store.append_history(&peer, &entry(0)).unwrap();
        let plain = dir.path().join(history_name(&peer));
        assert!(plain.exists());

        store.protect_with_keystore().unwrap();
        assert!(
            !plain.exists(),
            "the file should have moved off the name that says whose it is"
        );
        assert_eq!(store.load_history(&peer).unwrap().len(), 1);
        assert_eq!(
            store.conversations().unwrap(),
            vec![Conversation::Contact(peer)]
        );

        // And it survives a fresh handle, which reads the index rather
        // than the file names.
        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        assert_eq!(again.load_history(&peer).unwrap().len(), 1);
        assert_eq!(
            again.conversations().unwrap(),
            vec![Conversation::Contact(peer)]
        );
    }

    /// The history half of SM-C-24: cutting the end off a conversation
    /// is the one thing binding each line to its offset cannot show, so
    /// the length is recorded and a shorter file is refused.
    #[test]
    fn a_history_file_with_its_end_cut_off_is_refused() {
        let (store, dir) = bound_store();
        let peer = Identity::generate().user_id();
        for i in 0..4 {
            store.append_history(&peer, &entry(i)).unwrap();
        }
        assert_eq!(store.load_history(&peer).unwrap().len(), 4);

        // Somebody with write access takes the last two messages off.
        let path = dir
            .path()
            .join(store.history_file(&Conversation::Contact(peer)));
        let text = fs::read_to_string(&path).unwrap();
        let keep: String = text.lines().take(2).map(|l| format!("{l}\n")).collect();
        fs::write(&path, keep).unwrap();

        let err = store.load_history(&peer).unwrap_err().to_string();
        assert!(
            err.contains("cut off"),
            "a truncated conversation was read as a shorter one: {err}"
        );
    }

    /// Taking a line out shortens the file, which the length catches.
    /// *Reordering* leaves the length exactly as it was, and is caught
    /// instead by each line being bound to the offset it was written at.
    #[test]
    fn two_history_lines_swapped_round_do_not_open() {
        let (store, dir) = bound_store();
        let peer = Identity::generate().user_id();
        for i in 0..4 {
            store.append_history(&peer, &entry(i)).unwrap();
        }
        let path = dir
            .path()
            .join(store.history_file(&Conversation::Contact(peer)));
        let text = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        // A swap keeps the file the same length whatever the lines are,
        // and keeps everything after them where it was.
        lines.swap(1, 2);
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        let ids: Vec<String> = store
            .load_history(&peer)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert!(
            !ids.contains(&entry(1).id) && !ids.contains(&entry(2).id),
            "the swapped lines should not have opened: {ids:?}"
        );
        assert_eq!(
            ids,
            vec![entry(0).id, entry(3).id],
            "the lines still at the offsets they were written at should open"
        );
    }

    /// An append interrupted before the length was recorded leaves a
    /// longer file than the record says, which is not tampering: a line
    /// at an offset the record has not reached is one somebody encrypted
    /// there, and that takes the key.
    #[test]
    fn a_history_append_interrupted_before_it_was_recorded_still_reads() {
        let (store, dir) = bound_store();
        let peer = Identity::generate().user_id();
        store.append_history(&peer, &entry(0)).unwrap();
        let vault_path = dir.path().join(VAULT_FILE);
        let state_path = dir.path().join(STATE_FILE);
        let before_vault = fs::read(&vault_path).unwrap();
        let before_state = fs::read(&state_path).unwrap();

        store.append_history(&peer, &entry(1)).unwrap();
        // Wind the record back: the line landed, nothing recorded it.
        fs::write(&vault_path, &before_vault).unwrap();
        fs::write(&state_path, &before_state).unwrap();

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        assert_eq!(
            again.load_history(&peer).unwrap().len(),
            2,
            "an interrupted append should still be read"
        );
    }

    /// Put a bound, key-store-protected directory back into the shape a
    /// client from before the record wrote: every file bound to its name
    /// alone, no `state`, and a version 1 vault with no anchor.
    fn make_unbound(store: &Store, dir: &Path) {
        let cipher = store.cipher.clone().unwrap();
        for name in recrypted_files() {
            let path = dir.join(name);
            if !path.exists() {
                continue;
            }
            let opened = cipher.open_file(name, &fs::read(&path).unwrap()).unwrap();
            fs::write(&path, cipher.encrypt(name, &opened.plain)).unwrap();
        }
        fs::remove_file(dir.join(STATE_FILE)).unwrap();
        let _ = fs::remove_file(dir.join(STATE_PREVIOUS_FILE));
        fs::write(dir.join(VAULT_FILE), unbound_vault(store)).unwrap();
    }

    /// The version 1 vault, with no anchor, that a client from before
    /// 0.25.0 wrote for the directory `store` is.
    fn unbound_vault(store: &Store) -> String {
        let vault = store.read_vault().unwrap().unwrap();
        let name = vault.keystore_name().unwrap();
        let kek = crate::keystore::load(&name).unwrap().unwrap();
        let unbound = store
            .cipher
            .clone()
            .unwrap()
            .wrap_unbound(&kek, vault.kdf.clone().unwrap());
        serde_json::to_string(&unbound).unwrap()
    }

    /// A directory written by a version before any of this still opens,
    /// comes out the other side bound, and has its vault rewritten so
    /// that it says so.
    #[test]
    fn a_directory_from_before_the_record_adopts_it_on_the_next_unlock() {
        let (store, dir) = bound_store();
        let peer = Identity::generate();
        store
            .save_contacts(&[Contact::new(peer.user_id())])
            .unwrap();
        make_unbound(&store, dir.path());
        assert_eq!(store.read_vault().unwrap().unwrap().version, 1);

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        assert_eq!(
            again.load_contacts().unwrap().len(),
            1,
            "an older directory should still be readable"
        );
        let vault = again.read_vault().unwrap().unwrap();
        assert!(
            vault.state_generation.is_some(),
            "it should be bound afterwards"
        );
        assert_eq!(
            vault.version,
            crate::vault::BOUND_VAULT_VERSION,
            "the vault should say so, where the anchor cannot be taken from it"
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
        // A second unlock finds nothing left to do.
        let mut third = Store::open(dir.path()).unwrap();
        third.unlock_with_keystore().unwrap();
        assert!(third.generations().state().is_some());
    }

    /// H7: the anchor is plaintext, and taking it out of `vault.json` used
    /// to make the next unlock adopt every file as it stood -- an older
    /// copy put back, or one overwritten with plaintext JSON, which was
    /// sealed first. The vault's own wrap says the directory keeps a
    /// record, so a missing anchor is refused, and relabelling the vault
    /// as one from before the record makes it not open at all.
    #[test]
    fn taking_the_anchor_out_is_refused_rather_than_adopted() {
        let (store, dir) = bound_store();
        let peer = Identity::generate();
        store
            .save_contacts(&[Contact::new(peer.user_id())])
            .unwrap();
        let contacts = dir.path().join(CONTACTS_FILE);
        let older = fs::read(&contacts).unwrap();
        store.save_contacts(&[]).unwrap();

        fs::write(&contacts, &older).unwrap();
        let config = dir.path().join(CONFIG_FILE);
        fs::write(&config, br#"{"relay":"wss://somebody-else.example"}"#).unwrap();
        fs::write(dir.path().join(BLOCKED_FILE), b"[]").unwrap();
        let mut vault = store.read_vault().unwrap().unwrap();
        vault.state_generation = None;
        store.write_vault(&vault).unwrap();

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        for err in [
            again.load_contacts().unwrap_err(),
            again.load_config().unwrap_err(),
            again.load_blocked().unwrap_err(),
        ] {
            assert!(
                err.to_string().contains("taken out"),
                "a directory with its anchor taken out was opened: {err}"
            );
        }
        assert!(again.save_contacts(&[]).is_err());
        assert!(
            !FileCipher::is_encrypted(&fs::read(&config).unwrap()),
            "the plaintext dropped in was sealed as though this client had written it"
        );

        // The anchor alone, nothing else changed: still refused.
        vault.version = 1;
        store.write_vault(&vault).unwrap();
        let mut relabelled = Store::open(dir.path()).unwrap();
        assert!(
            relabelled.unlock_with_keystore().is_err(),
            "a version 3 vault called version 1 must not open"
        );
    }

    /// The other way to make a bound directory look like one from before
    /// the record: put back a version 1 vault from before it was rewritten
    /// (the data key has not changed since). The record and the files say
    /// otherwise, and nothing is adopted.
    #[test]
    fn an_older_vault_put_back_over_a_bound_directory_is_not_adopted() {
        let (store, dir) = bound_store();
        store.save_contacts(&[]).unwrap();
        fs::write(dir.path().join(VAULT_FILE), unbound_vault(&store)).unwrap();

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        let err = again.load_contacts().unwrap_err().to_string();
        assert!(err.contains("state is there"), "{err}");

        // Without `state` either: the files are at generations.
        fs::remove_file(dir.path().join(STATE_FILE)).unwrap();
        let _ = fs::remove_file(dir.path().join(STATE_PREVIOUS_FILE));
        let mut third = Store::open(dir.path()).unwrap();
        third.unlock_with_keystore().unwrap();
        let err = third.load_contacts().unwrap_err().to_string();
        assert!(err.contains("written at a generation"), "{err}");
        assert!(
            third
                .read_vault()
                .unwrap()
                .unwrap()
                .state_generation
                .is_none(),
            "nothing was adopted"
        );
    }

    /// A record that says a protection is unfinished lets plaintext in, so
    /// it must not be one that can be put back later: it is at generation
    /// 0, and a directory that has been written since holds files further
    /// on than an unfinished protection leaves.
    #[test]
    fn an_unfinished_record_put_back_later_is_refused() {
        let (store, dir) = bound_store();
        for _ in 0..3 {
            store.save_contacts(&[]).unwrap();
        }
        let cipher = store.cipher.clone().unwrap();
        let unfinished = State {
            unfinished: true,
            ..State::default()
        };
        fs::write(
            dir.path().join(STATE_FILE),
            cipher.encrypt(STATE_FILE, &serde_json::to_vec(&unfinished).unwrap()),
        )
        .unwrap();
        let _ = fs::remove_file(dir.path().join(STATE_PREVIOUS_FILE));
        let mut vault = store.read_vault().unwrap().unwrap();
        vault.state_generation = Some(0);
        store.write_vault(&vault).unwrap();
        fs::write(dir.path().join(BLOCKED_FILE), b"[]").unwrap();

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        let err = again.load_contacts().unwrap_err().to_string();
        assert!(err.contains("older copy put back"), "{err}");
        assert!(
            !FileCipher::is_encrypted(&fs::read(dir.path().join(BLOCKED_FILE)).unwrap()),
            "the plaintext was sealed on the word of a record put back"
        );
    }

    /// M3: a line in the clear in an encrypted conversation, with the
    /// record intact, is not a message. It was read as one.
    #[test]
    fn a_plaintext_line_in_an_encrypted_conversation_is_not_read() {
        let (store, dir) = bound_store();
        let peer = Identity::generate().user_id();
        store.append_history(&peer, &entry(0)).unwrap();
        let path = dir
            .path()
            .join(store.history_file(&Conversation::Contact(peer)));
        let forged = serde_json::to_string(&entry(1)).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(format!("{forged}\n").as_bytes()).unwrap();
        drop(file);

        let ids: Vec<String> = store
            .load_history(&peer)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(
            ids,
            vec![entry(0).id],
            "a plaintext line was read as a message"
        );
        // At the head of a file, where the old check looked, too.
        let other = Identity::generate().user_id();
        store.append_history(&other, &entry(2)).unwrap();
        let path = dir
            .path()
            .join(store.history_file(&Conversation::Contact(other)));
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, format!("{forged}\n{text}")).unwrap();
        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        assert!(
            again
                .load_history(&other)
                .map(|h| h.iter().all(|e| e.id != entry(1).id))
                .unwrap_or(true),
            "a plaintext line at the head of a file was read as a message"
        );
        assert!(
            fs::read_to_string(&path).unwrap().starts_with(&forged),
            "the unlock sealed a line nobody had vouched for"
        );
    }

    /// A file the record names that is not on disk was deleted by
    /// somebody else, and is refused rather than read as never written:
    /// `blocked.json` gone unblocked everybody, `transparency.json` gone
    /// started the relay's key log over, `identity.json` gone minted a new
    /// identity. A file that was never written still reads as absent, and
    /// what the client removes itself it records.
    #[test]
    fn a_recorded_file_deleted_is_refused_and_a_new_one_is_not() {
        let (store, dir) = bound_store();
        assert!(store.load_blocked().unwrap().is_empty(), "never written");
        let peer = Identity::generate().user_id();
        store.save_blocked(&[peer]).unwrap();
        store.append_history(&peer, &entry(0)).unwrap();
        crate::transparency::LogStore::load(&store)
            .unwrap()
            .confirm(7);
        store.save_sessions(&SessionsFile::default()).unwrap();
        store.clear_sessions().unwrap();
        assert!(store.load_sessions().is_ok(), "the client's own removal");

        let history = dir
            .path()
            .join(store.history_file(&Conversation::Contact(peer)));
        for name in [BLOCKED_FILE, TRANSPARENCY_FILE, IDENTITY_FILE] {
            fs::remove_file(dir.path().join(name)).unwrap();
        }
        fs::remove_file(&history).unwrap();
        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        assert!(
            again
                .load_blocked()
                .unwrap_err()
                .to_string()
                .contains("deleted")
        );
        assert!(crate::transparency::LogStore::load(&again).is_err());
        assert!(again.load_or_create_identity().is_err());
        assert!(
            !dir.path().join(IDENTITY_FILE).exists(),
            "a new identity was made in place of a deleted one"
        );
        assert!(again.load_history(&peer).is_err());
    }

    /// Two files are written by code of their own, bound to their names
    /// alone: the relay's key log as replayed and the outbox. The adoption
    /// stamps a generation onto them with the rest, and their readers have
    /// to take that shape, or a directory from before generations stops
    /// opening after its first unlock (0.18.0 on a directory 0.14.0
    /// wrote).
    #[test]
    fn the_replayed_log_and_the_outbox_survive_adoption() {
        let (store, dir) = bound_store();
        let log_path = dir.path().join(TRANSPARENCY_FILE);
        let outbox_path = dir.path().join(OUTBOX_FILE);
        crate::transparency::LogStore::load(&store)
            .unwrap()
            .confirm(7);
        // What the outbox writes when nothing is queued.
        store.write_private_file(OUTBOX_FILE, b"[]").unwrap();

        // Back to the shape an older version wrote, as above.
        make_unbound(&store, dir.path());

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        for path in [&log_path, &outbox_path] {
            assert!(
                fs::read(path)
                    .unwrap()
                    .starts_with(crate::vault::GENERATION_MAGIC),
                "adoption should have stamped {}",
                path.display()
            );
        }
        // Stamped by the adoption with everything else, so nothing is
        // left for the unlock to bring in.
        assert_eq!(
            again.generations().state().unwrap().covers,
            COVERS_LOG_AND_OUTBOX
        );
        let log = crate::transparency::LogStore::load(&again).unwrap();
        assert_eq!(log.verified_at_ms(), 7);
        let outbox = crate::outbox::Outbox::load(Some(again.clone())).unwrap();
        assert!(outbox.ids().is_empty());
    }

    /// Directories in use hold the two files bound to their names alone:
    /// one started on 0.16.0 or later, where the record never heard of
    /// them; one that came up from 0.14.0, where the adoption recorded
    /// them at generation 1 and the writers 0.16.0 to 0.18.1 had then
    /// rewrote them name-only; and, after a crash between the rewrite and
    /// the record, one where they are bound and recorded but `covers` is
    /// still unset. Each comes in at the next unlock, once, and an older
    /// copy is refused from then on.
    #[test]
    fn the_two_files_written_name_only_are_brought_in_at_unlock() {
        let log_plain = serde_json::to_vec(&crate::transparency::LogState {
            verified_at_ms: 7,
            ..Default::default()
        })
        .unwrap();
        for (recorded_at_one, bound_at_one) in [(false, false), (true, false), (true, true)] {
            let (store, dir) = bound_store();
            let cipher = store.cipher.clone().unwrap();
            // The record as those versions left it.
            let mut state = store.generations().state().unwrap().clone();
            state.covers = 0;
            for name in [TRANSPARENCY_FILE, OUTBOX_FILE] {
                state.files.remove(name);
                if recorded_at_one {
                    state.wrote(name, 1);
                }
            }
            store.persist_generations(&state, &cipher).unwrap();
            for (name, plain) in [
                (TRANSPARENCY_FILE, log_plain.as_slice()),
                (OUTBOX_FILE, b"[]".as_slice()),
            ] {
                let bytes = if bound_at_one {
                    cipher.encrypt_at(name, 1, plain)
                } else {
                    cipher.encrypt(name, plain)
                };
                fs::write(dir.path().join(name), bytes).unwrap();
            }

            let mut again = Store::open(dir.path()).unwrap();
            again.unlock_with_keystore().unwrap();
            let state = again.generations().state().unwrap().clone();
            assert_eq!(state.covers, COVERS_LOG_AND_OUTBOX);
            for name in [TRANSPARENCY_FILE, OUTBOX_FILE] {
                let bytes = fs::read(dir.path().join(name)).unwrap();
                assert!(
                    bytes.starts_with(crate::vault::GENERATION_MAGIC),
                    "{name} should be bound (recorded at one: {recorded_at_one}, bound at one: \
                     {bound_at_one})"
                );
                assert!(state.files.contains_key(name), "{name} should be recorded");
            }
            assert_eq!(
                crate::transparency::LogStore::load(&again)
                    .unwrap()
                    .verified_at_ms(),
                7
            );
            assert!(
                crate::outbox::Outbox::load(Some(again.clone()))
                    .unwrap()
                    .ids()
                    .is_empty()
            );

            // Once: a second unlock rewrites nothing.
            let record = fs::read(dir.path().join(STATE_FILE)).unwrap();
            let log = fs::read(dir.path().join(TRANSPARENCY_FILE)).unwrap();
            let mut third = Store::open(dir.path()).unwrap();
            third.unlock_with_keystore().unwrap();
            assert_eq!(fs::read(dir.path().join(STATE_FILE)).unwrap(), record);
            assert_eq!(fs::read(dir.path().join(TRANSPARENCY_FILE)).unwrap(), log);

            // And bound means bound: the name-only copy put back is refused.
            fs::write(
                dir.path().join(TRANSPARENCY_FILE),
                cipher.encrypt(TRANSPARENCY_FILE, &log_plain),
            )
            .unwrap();
            let err = format!(
                "{:#}",
                crate::transparency::LogStore::load(&third).unwrap_err()
            );
            assert!(
                err.contains("not the version this directory last wrote"),
                "a name-only copy was read after the file was bound: {err}"
            );
        }
    }

    /// Several writers share one record: two threads writing different
    /// files through clones of one store leave a directory that opens,
    /// with every file at a generation the record accepts. Before the
    /// lock was held through the record's write, two records landing out
    /// of order could leave a file two generations ahead.
    #[test]
    fn writers_on_two_threads_leave_a_directory_that_opens() {
        let (store, dir) = bound_store();
        let peer = Identity::generate().user_id();
        let other = store.clone();
        let writer = std::thread::spawn(move || {
            for _ in 0..40 {
                other.save_blocked(&[peer]).unwrap();
            }
        });
        for _ in 0..40 {
            store.save_contacts(&[]).unwrap();
        }
        writer.join().unwrap();

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        assert!(again.load_contacts().unwrap().is_empty());
        assert_eq!(again.load_blocked().unwrap(), vec![peer]);
    }

    /// A client from before generations existed, run on a directory a
    /// newer one has opened, takes every generation-bearing file for a
    /// plain one and seals it again under its name alone before failing
    /// at `identity.json` (0.14.0 after 0.18.0). The directory must open
    /// as it is afterwards, and the generations must still count.
    #[test]
    fn a_directory_an_older_client_sealed_again_opens_and_still_refuses_an_older_copy() {
        let (store, dir) = bound_store();
        let identity = store.load_or_create_identity().unwrap().0;
        let peer = Identity::generate();
        store
            .save_contacts(&[Contact::new(peer.user_id())])
            .unwrap();
        let contacts_path = dir.path().join(CONTACTS_FILE);
        let older = fs::read(&contacts_path).unwrap();
        store.save_contacts(&[]).unwrap();

        // What 0.14.0's unlock does: its `is_encrypted` knows the
        // name-only shape alone, so every file looks plain and is
        // "sealed", ciphertext and all.
        let cipher = store.cipher.clone().unwrap();
        for name in recrypted_files() {
            let path = dir.path().join(name);
            if path.exists() {
                let raw = fs::read(&path).unwrap();
                fs::write(&path, cipher.encrypt(name, &raw)).unwrap();
            }
        }

        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_keystore().unwrap();
        assert_eq!(
            again.load_or_create_identity().unwrap().0.user_id(),
            identity.user_id()
        );
        assert!(
            again.load_contacts().unwrap().is_empty(),
            "the latest contacts should be read through the second seal"
        );
        // A write puts the file back in its own shape.
        again.save_contacts(&[]).unwrap();
        assert!(
            fs::read(&contacts_path)
                .unwrap()
                .starts_with(crate::vault::GENERATION_MAGIC)
        );

        // An older copy inside such a wrapping is an older copy still.
        fs::write(&contacts_path, cipher.encrypt(CONTACTS_FILE, &older)).unwrap();
        let err = again.load_contacts().unwrap_err().to_string();
        assert!(
            err.contains("not the version this directory last wrote"),
            "an older copy under a second seal was accepted: {err}"
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
        let name = old_vault.keystore_name().unwrap();
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
        let name = store
            .read_vault()
            .unwrap()
            .unwrap()
            .keystore_name()
            .unwrap();
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
        let name = store
            .read_vault()
            .unwrap()
            .unwrap()
            .keystore_name()
            .unwrap();
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
        let kek = crate::keystore::fresh_key();
        store.add_pending(&name, &kek).unwrap();
        crate::keystore::put(&name, &kek).unwrap();
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
        let live = store
            .read_vault()
            .unwrap()
            .unwrap()
            .keystore_name()
            .unwrap();
        store.note_existing(&live).unwrap();
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
        let name = store
            .read_vault()
            .unwrap()
            .unwrap()
            .keystore_name()
            .unwrap();
        store.note_existing(&name).unwrap();
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
        let name = store
            .read_vault()
            .unwrap()
            .unwrap()
            .keystore_name()
            .unwrap();

        // Stop after the vault is gone but before the key is.
        store.note_existing(&name).unwrap();
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

    /// `vault.pending` is plaintext and read before any unlock, so a note
    /// in it is only a claim. A bare name, as written before 0.25.0, and a
    /// note genuine in another data directory both name a key that is not
    /// this installation's to delete on their word, and neither is
    /// deleted; the same note in the directory that wrote it is acted on.
    #[test]
    fn a_note_nobody_here_wrote_never_costs_a_key() {
        crate::keystore::use_mock_store();
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let name = Kdf::keystore().keystore_name();
        let kek = crate::keystore::create(&name).unwrap();

        fs::write(
            dir.path().join(PENDING_FILE),
            serde_json::to_string(&[&name]).unwrap(),
        )
        .unwrap();
        drop(Store::open(dir.path()).unwrap());
        assert!(
            crate::keystore::load(&name).unwrap().is_some(),
            "a bare name in vault.pending took a key out of the key store"
        );
        assert!(!dir.path().join(PENDING_FILE).exists());

        let elsewhere = Store::open(other.path()).unwrap();
        elsewhere.add_pending(&name, &kek).unwrap();
        fs::copy(
            other.path().join(PENDING_FILE),
            dir.path().join(PENDING_FILE),
        )
        .unwrap();
        drop(Store::open(dir.path()).unwrap());
        assert!(
            crate::keystore::load(&name).unwrap().is_some(),
            "a note copied from another directory took its key out"
        );

        drop(elsewhere);
        drop(Store::open(other.path()).unwrap());
        assert!(
            crate::keystore::load(&name).unwrap().is_none(),
            "the directory that wrote the note settles it"
        );
    }

    /// What a received file begins with is the sender's to choose. One
    /// that begins like ciphertext used to stop every change of
    /// protection; it is left alone now, and the files that are encrypted
    /// move with the key, the ones received in the old shape into the
    /// new one.
    #[test]
    fn a_received_file_that_looks_encrypted_does_not_stop_a_change_of_protection() {
        crate::keystore::use_mock_store();
        let (mut store, dir) = temp_store();
        store.load_or_create_identity().unwrap();
        let downloads = store.downloads_dir();
        fs::create_dir_all(&downloads).unwrap();
        let mut lookalike = crate::vault::FILE_MAGIC.to_vec();
        lookalike.extend_from_slice(b" is how this file starts");
        fs::write(downloads.join("odd.bin"), &lookalike).unwrap();

        store.protect_with_keystore().unwrap();
        let cipher = store.cipher().unwrap();
        fs::write(
            downloads.join("new.txt"),
            cipher.encrypt_download("new.txt", b"received now"),
        )
        .unwrap();
        fs::write(
            downloads.join("old.txt"),
            cipher.encrypt("old.txt", b"received before"),
        )
        .unwrap();

        store.set_passphrase_with("hunter2", Kdf::fast()).unwrap();
        let cipher = store.cipher().unwrap();
        assert_eq!(fs::read(downloads.join("odd.bin")).unwrap(), lookalike);
        for (name, plain) in [("new.txt", "received now"), ("old.txt", "received before")] {
            let bytes = fs::read(downloads.join(name)).unwrap();
            assert!(bytes.starts_with(crate::vault::DOWNLOAD_MAGIC), "{name}");
            assert_eq!(
                cipher.decrypt_download(name, &bytes).unwrap().as_slice(),
                plain.as_bytes()
            );
        }
        assert_eq!(store.remove_protection().unwrap(), Protection::None);
        assert_eq!(
            fs::read(downloads.join("new.txt")).unwrap(),
            b"received now"
        );
        assert_eq!(fs::read(downloads.join("odd.bin")).unwrap(), lookalike);
        drop(dir);
    }

    /// A wipe leaves nothing of the identity behind, including what a
    /// write a crash interrupted left beside its file, the notes about key
    /// store entries, and the update waiting in the directory.
    #[test]
    fn a_wipe_leaves_no_half_written_copy_note_or_update_behind() {
        crate::keystore::use_mock_store();
        let (mut store, dir) = temp_store();
        store.load_or_create_identity().unwrap();
        store.protect_with_keystore().unwrap();
        let leftover = dir.path().join("identity.4242.tmp");
        fs::write(&leftover, b"a whole copy of the keys").unwrap();
        let history_leftover = dir.path().join(HISTORY_DIR).join("abc.4242.tmp");
        fs::write(&history_leftover, b"a conversation").unwrap();
        let other = Kdf::keystore().keystore_name();
        let kek = crate::keystore::create(&other).unwrap();
        store.add_pending(&other, &kek).unwrap();
        fs::create_dir_all(dir.path().join(UPDATE_DIR)).unwrap();
        fs::write(dir.path().join(UPDATE_DIR).join("previous"), b"a program").unwrap();
        let keep = dir.path().join("notes.tmp");
        fs::write(&keep, b"not ours").unwrap();

        store.wipe().unwrap();
        assert!(!leftover.exists() && !history_leftover.exists());
        assert!(!dir.path().join(PENDING_FILE).exists());
        assert!(!dir.path().join(UPDATE_DIR).exists());
        assert!(
            keep.exists(),
            "only what the store's own writes leave is taken"
        );
    }

    /// A file is created afresh, at the mode asked for, whatever was at
    /// its path: an existing file kept its own mode when it was opened to
    /// be truncated, and a link put where a temporary file was going was
    /// followed.
    #[cfg(unix)]
    #[test]
    fn a_private_file_is_new_whatever_was_in_its_place() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.json");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let mut file = create_private(&path).unwrap();
        file.write_all(b"new").unwrap();
        drop(file);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let elsewhere = dir.path().join("elsewhere");
        fs::write(&elsewhere, b"untouched").unwrap();
        let link = dir.path().join("identity.4242.tmp");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        write_atomic(&dir.path().join("identity.json"), b"keys").unwrap();
        assert_eq!(fs::read(&elsewhere).unwrap(), b"untouched");
    }

    /// `vault.json` is read before anything is decrypted, so a slot's
    /// relying party is whatever somebody who can write it says. A slot
    /// under any but this program's is refused, and the key is asked
    /// nothing for it.
    #[test]
    fn a_security_key_slot_for_another_relying_party_is_refused() {
        let (mut store, dir) = bound_store();
        let key = std::sync::Arc::new(std::sync::Mutex::new(
            silver_key::soft::SoftKey::new([5; 32]).with_pin("4831"),
        ));
        let mut auth = silver_key::soft::authenticator(key.clone(), "4831");
        store
            .add_security_key_with(&mut auth, "YubiKey", Some("recovery"), Kdf::fast())
            .unwrap();
        let mut vault = store.read_vault().unwrap().unwrap();
        for slot in &mut vault.slots {
            if let SlotKind::Fido2 { rp_id, .. } = &mut slot.kind {
                *rp_id = "bank.example".into();
            }
        }
        store.write_vault(&vault).unwrap();
        let mut again = Store::open(dir.path()).unwrap();
        let err = again.unlock_with_security_key(&mut auth).unwrap_err();
        assert!(format!("{err:#}").contains("bank.example"), "{err:#}");
        assert!(again.is_locked());
    }

    fn entry(i: u64) -> HistoryEntry {
        HistoryEntry::new(
            i.to_string(),
            if i.is_multiple_of(2) {
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
        let raw = fs::read_to_string(
            store
                .root
                .join(store.history_file(&Conversation::Contact(peer))),
        )
        .unwrap();
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
        assert!(!store.root.join(store.history_file(&nobody)).exists());
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
        let raw = fs::read_to_string(
            store
                .root
                .join(store.history_file(&Conversation::Contact(peer))),
        )
        .unwrap();
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
        let before = fs::read_to_string(
            store
                .root
                .join(store.history_file(&Conversation::Contact(peer))),
        )
        .unwrap();
        assert_eq!(
            store.mark_deleted(&conv, "7", Some(peer)).unwrap(),
            Deletion::Tombstoned
        );
        assert_eq!(
            fs::read_to_string(
                store
                    .root
                    .join(store.history_file(&Conversation::Contact(peer)))
            )
            .unwrap(),
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
        let raw = fs::read_to_string(store.root.join(store.history_file(&conv))).unwrap();
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
        let history =
            fs::read_to_string(root.join(store.history_file(&Conversation::Contact(peer))))
                .unwrap();
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
        for name in recrypted_files() {
            let path = reopened.root.join(name);
            if path.exists() {
                assert!(
                    fs::read(&path)
                        .unwrap()
                        .starts_with(crate::vault::GENERATION_MAGIC),
                    "{name} was left as the failure left it"
                );
            }
        }
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
        // And the file is no longer named after who it is with, which is
        // SM-C-25: a listing of the directory was the contact list, with
        // every file in it encrypted.
        let plain_name = dir
            .path()
            .join("history")
            .join(format!("{}.jsonl", peer.user_id()));
        assert!(
            !plain_name.exists(),
            "the history is still filed under the contact's id"
        );
        let conversation = Conversation::Contact(peer.user_id());
        let raw_history =
            fs::read_to_string(dir.path().join(store.history_file(&conversation))).unwrap();
        assert!(raw_history.lines().all(|l| l.starts_with(LINE_PREFIX)));
        assert!(!raw_history.contains("msg 0"));
        for entry in fs::read_dir(dir.path().join("history")).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.contains(&peer.user_id().to_string()),
                "{name} names the contact"
            );
        }

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

    /// A directory the key store protected moves to a security key: a
    /// fresh data key, and the key store's key taken out, since it would
    /// still open a copy taken before the change.
    #[test]
    fn a_key_store_directory_enrolling_a_security_key_leaves_nothing_in_the_key_store() {
        let (mut store, dir) = bound_store();
        let name = store
            .read_vault()
            .unwrap()
            .unwrap()
            .keystore_name()
            .unwrap();
        assert!(crate::keystore::load(&name).unwrap().is_some());
        let key = std::sync::Arc::new(std::sync::Mutex::new(
            silver_key::soft::SoftKey::new([3; 32]).with_pin("4831"),
        ));
        let mut auth = silver_key::soft::authenticator(key.clone(), "4831");
        store
            .add_security_key_with(&mut auth, "YubiKey", Some("recovery"), Kdf::fast())
            .unwrap();
        assert_eq!(store.protection(), Protection::SecurityKey);
        assert!(crate::keystore::load(&name).unwrap().is_none());
        assert!(store.read_pending().is_empty());
        // The key store has nothing to say about it from now on.
        assert!(store.unlock_with_keystore().is_err());
        let mut again = Store::open(dir.path()).unwrap();
        again.unlock_with_security_key(&mut auth).unwrap();
        assert!(again.load_or_create_identity().is_ok());
        // Neither the passphrase nor the key store can be put in its place
        // while a key protects it.
        assert!(again.set_passphrase_with("x", Kdf::fast()).is_err());
        assert!(again.remove_passphrase().is_err());
        assert!(again.protect_with_keystore().is_err());
    }
}
