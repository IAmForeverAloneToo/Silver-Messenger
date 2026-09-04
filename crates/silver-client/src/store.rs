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
//! history/<user>.jsonl one line per message, per peer
//! ```
//!
//! With a passphrase set, every file is encrypted with the vault's data key
//! (see [`crate::vault`]); history files are encrypted line by line. Files
//! written before the passphrase was set are recognised as plaintext and
//! re-encrypted when the passphrase is set.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use silver_protocol::envelope::ReceiptKind;
use silver_protocol::{Identity, IdentitySecrets, KeyBundle, Sequence, UserId};

use crate::sessions::{PrekeyFile, SessionsFile};
use crate::vault::{FileCipher, Kdf, LINE_PREFIX, VaultError, VaultFile};

const VAULT_FILE: &str = "vault.json";
const IDENTITY_FILE: &str = "identity.json";
const PREKEYS_FILE: &str = "prekeys.json";
const SESSIONS_FILE: &str = "sessions.json";
const CONFIG_FILE: &str = "config.json";
const CONTACTS_FILE: &str = "contacts.json";
const OUTBOX_FILE: &str = "outbox.json";
const REQUESTS_FILE: &str = "requests.json";
const BLOCKED_FILE: &str = "blocked.json";
const HISTORY_DIR: &str = "history";

/// Client-side configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub relay_url: Option<String>,
    /// PEM file with extra trusted root certificates, for `wss://` relays
    /// behind a private CA.
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    /// HTTP CONNECT proxy URL. When unset, `HTTPS_PROXY` from the
    /// environment is used.
    #[serde(default)]
    pub proxy: Option<String>,
    /// Random value identifying this installation's message numbering; see
    /// [`silver_protocol::Sequence`].
    #[serde(default)]
    pub send_epoch: Option<u64>,
    /// Invite token for relays that only register invited identities.
    #[serde(default)]
    pub invite_token: Option<String>,
    /// Tell contacts when their messages have been shown. Delivery receipts
    /// are always sent.
    #[serde(default = "default_true")]
    pub read_receipts: bool,
    /// How to draw attention to new messages: `all`, `bell` or `off`.
    #[serde(default = "default_notify")]
    pub notify: String,
}

fn default_true() -> bool {
    true
}

fn default_notify() -> String {
    "all".to_owned()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            relay_url: None,
            ca_cert: None,
            proxy: None,
            send_epoch: None,
            invite_token: None,
            read_receipts: true,
            notify: default_notify(),
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
    /// Sequence of the last message accepted from them.
    #[serde(default)]
    pub received: Option<Sequence>,
    /// The user compared safety numbers with this contact out of band.
    #[serde(default)]
    pub verified: bool,
    /// Capabilities their last message advertised; see
    /// [`silver_protocol::envelope::capability`].
    #[serde(default)]
    pub caps: Vec<String>,
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
            caps: Vec::new(),
        }
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

    /// Alias if set, otherwise a short form of the id.
    pub fn display_name(&self) -> String {
        self.alias
            .clone()
            .unwrap_or_else(|| format!("{}…", self.user_id.short()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Sent,
    Received,
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
}

/// A later line in a history file that updates earlier entries.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReceiptLine {
    receipt: ReceiptKind,
    ids: Vec<String>,
    at_ms: u64,
}

/// A later line that replaces the text of an earlier entry, for example
/// once a file it announced has been fetched and saved.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TextLine {
    update: String,
    text: String,
}

/// What one line of a history file can be.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum HistoryLine {
    Entry(HistoryEntry),
    Receipt(ReceiptLine),
    Text(TextLine),
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
}

/// Messages from one unknown sender, waiting for a decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactRequest {
    pub from: UserId,
    pub first_seen_ms: u64,
    pub messages: Vec<HeldMessage>,
}

/// Handle to the data directory.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
    cipher: Option<Arc<FileCipher>>,
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
        fs::create_dir_all(root.join(HISTORY_DIR))
            .with_context(|| format!("creating data dir {}", root.display()))?;
        Ok(Self { root, cipher: None })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // --- passphrase -----------------------------------------------------------

    /// Whether a passphrase protects this directory.
    pub fn has_passphrase(&self) -> bool {
        self.root.join(VAULT_FILE).exists()
    }

    /// Protected and not yet unlocked.
    pub fn is_locked(&self) -> bool {
        self.has_passphrase() && self.cipher.is_none()
    }

    /// The data key, for components that keep their own files (the outbox).
    pub fn cipher(&self) -> Option<Arc<FileCipher>> {
        self.cipher.clone()
    }

    pub fn unlock(&mut self, passphrase: &str) -> Result<(), VaultError> {
        let path = self.root.join(VAULT_FILE);
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))
            .map_err(VaultError::Other)?;
        let vault: VaultFile = serde_json::from_str(&text)
            .context("parsing vault.json")
            .map_err(VaultError::Other)?;
        self.cipher = Some(Arc::new(FileCipher::unlock(&vault, passphrase)?));
        Ok(())
    }

    /// Protect the directory with `passphrase`, encrypting everything in it.
    pub fn set_passphrase(&mut self, passphrase: &str) -> anyhow::Result<()> {
        self.set_passphrase_with(passphrase, Kdf::default_params())
    }

    #[doc(hidden)]
    pub fn set_passphrase_with(&mut self, passphrase: &str, kdf: Kdf) -> anyhow::Result<()> {
        if self.has_passphrase() {
            bail!("a passphrase is already set; remove it first to change it");
        }
        let (vault, cipher) = FileCipher::create(passphrase, kdf)?;
        let cipher = Arc::new(cipher);
        self.recrypt_all(None, Some(&cipher))?;
        write_private(
            &self.root.join(VAULT_FILE),
            serde_json::to_string_pretty(&vault)?.as_bytes(),
        )?;
        self.cipher = Some(cipher);
        Ok(())
    }

    /// Store everything unencrypted again and forget the passphrase.
    pub fn remove_passphrase(&mut self) -> anyhow::Result<()> {
        self.ensure_unlocked()?;
        let Some(cipher) = self.cipher.take() else {
            bail!("no passphrase is set");
        };
        self.recrypt_all(Some(&cipher), None)?;
        fs::remove_file(self.root.join(VAULT_FILE)).context("removing vault.json")?;
        Ok(())
    }

    fn ensure_unlocked(&self) -> anyhow::Result<()> {
        if self.is_locked() {
            bail!("the data directory is protected by a passphrase; unlock it first");
        }
        Ok(())
    }

    /// Rewrite every file from one cipher to another (`None` = plaintext).
    fn recrypt_all(
        &self,
        from: Option<&FileCipher>,
        to: Option<&FileCipher>,
    ) -> anyhow::Result<()> {
        for name in [
            IDENTITY_FILE,
            PREKEYS_FILE,
            SESSIONS_FILE,
            CONFIG_FILE,
            CONTACTS_FILE,
            OUTBOX_FILE,
            REQUESTS_FILE,
            BLOCKED_FILE,
        ] {
            let path = self.root.join(name);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path)?;
            let plain = decode_file(from, name, &bytes)?;
            let out = encode_file(to, name, &plain);
            if matches!(name, IDENTITY_FILE | PREKEYS_FILE | SESSIONS_FILE) {
                write_private(&path, &out)?;
            } else {
                write_atomic(&path, &out)?;
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
        Ok(Some(decode_file(self.cipher.as_deref(), name, &bytes)?))
    }

    fn write_file(&self, name: &str, bytes: &[u8], private: bool) -> anyhow::Result<()> {
        self.ensure_unlocked()?;
        let out = encode_file(self.cipher.as_deref(), name, bytes);
        let path = self.root.join(name);
        if private {
            write_private(&path, &out)
        } else {
            write_atomic(&path, &out)
        }
    }

    fn read_json_or_default<T: Default + for<'de> Deserialize<'de>>(
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
        self.write_file(IDENTITY_FILE, text.as_bytes(), true)?;
        Ok((identity, true))
    }

    pub fn has_identity(&self) -> bool {
        self.root.join(IDENTITY_FILE).exists()
    }

    /// Overwrite the identity, e.g. when restoring a backup.
    pub fn save_identity(&self, identity: &Identity) -> anyhow::Result<()> {
        let text = serde_json::to_string_pretty(&identity.to_secrets())?;
        self.write_file(IDENTITY_FILE, text.as_bytes(), true)
    }

    // --- prekeys and sessions ------------------------------------------------

    pub(crate) fn load_prekeys(&self) -> anyhow::Result<PrekeyFile> {
        self.read_json_or_default(PREKEYS_FILE)
    }

    pub(crate) fn save_prekeys(&self, prekeys: &PrekeyFile) -> anyhow::Result<()> {
        self.write_file(PREKEYS_FILE, &serde_json::to_vec(prekeys)?, true)
    }

    pub(crate) fn load_sessions(&self) -> anyhow::Result<SessionsFile> {
        self.read_json_or_default(SESSIONS_FILE)
    }

    pub(crate) fn save_sessions(&self, sessions: &SessionsFile) -> anyhow::Result<()> {
        self.write_file(SESSIONS_FILE, &serde_json::to_vec(sessions)?, true)
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

    pub fn load_config(&self) -> anyhow::Result<Config> {
        self.read_json_or_default(CONFIG_FILE)
    }

    pub fn save_config(&self, config: &Config) -> anyhow::Result<()> {
        self.write_file(
            CONFIG_FILE,
            serde_json::to_string_pretty(config)?.as_bytes(),
            false,
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
            false,
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
            false,
        )
    }

    pub fn load_blocked(&self) -> anyhow::Result<Vec<UserId>> {
        self.read_json_or_default(BLOCKED_FILE)
    }

    pub fn save_blocked(&self, blocked: &[UserId]) -> anyhow::Result<()> {
        self.write_file(
            BLOCKED_FILE,
            serde_json::to_string_pretty(blocked)?.as_bytes(),
            false,
        )
    }

    // --- history ---------------------------------------------------------------

    pub fn append_history(&self, peer: &UserId, entry: &HistoryEntry) -> anyhow::Result<()> {
        self.append_history_line(peer, &serde_json::to_string(entry)?)
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
        self.append_history_line(peer, &serde_json::to_string(&line)?)
    }

    /// Replace the text of the entry `id` from now on; the original line
    /// stays in the file.
    pub fn append_text(&self, peer: &UserId, id: &str, text: &str) -> anyhow::Result<()> {
        let line = TextLine {
            update: id.to_owned(),
            text: text.to_owned(),
        };
        self.append_history_line(peer, &serde_json::to_string(&line)?)
    }

    fn append_history_line(&self, peer: &UserId, json: &str) -> anyhow::Result<()> {
        self.ensure_unlocked()?;
        let name = history_name(peer);
        let path = self.root.join(&name);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let mut line = encode_line(self.cipher.as_deref(), &name, json);
        line.push('\n');
        file.write_all(line.as_bytes())?;
        Ok(())
    }

    /// The conversation with `peer`, receipts applied to the entries they
    /// refer to.
    pub fn load_history(&self, peer: &UserId) -> anyhow::Result<Vec<HistoryEntry>> {
        self.ensure_unlocked()?;
        let name = history_name(peer);
        let path = self.root.join(&name);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let mut entries: Vec<HistoryEntry> = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parsed = decode_line(self.cipher.as_deref(), &name, line)
                .and_then(|plain| serde_json::from_str::<HistoryLine>(&plain).map_err(Into::into));
            match parsed {
                Ok(HistoryLine::Entry(entry)) => entries.push(entry),
                Ok(HistoryLine::Receipt(receipt)) => {
                    for entry in entries.iter_mut().filter(|e| receipt.ids.contains(&e.id)) {
                        if entry.receipt.is_none_or(|r| r < receipt.receipt) {
                            entry.receipt = Some(receipt.receipt);
                        }
                    }
                }
                Ok(HistoryLine::Text(update)) => {
                    if let Some(entry) = entries.iter_mut().rev().find(|e| e.id == update.update) {
                        entry.text = update.text;
                    }
                }
                Err(e) => {
                    tracing::warn!("skipping unreadable history line in {name}: {e:#}")
                }
            }
        }
        Ok(entries)
    }

    /// Where the client keeps not-yet-accepted outgoing envelopes.
    pub fn outbox_path(&self) -> PathBuf {
        self.root.join(OUTBOX_FILE)
    }

    /// Where received files are saved.
    pub fn downloads_dir(&self) -> PathBuf {
        self.root.join("downloads")
    }
}

fn history_name(peer: &UserId) -> String {
    format!("{HISTORY_DIR}/{peer}.jsonl")
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

/// Write via a temp file + rename so a crash never leaves a half-written file.
fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

/// Like [`write_atomic`] but the file is created owner-readable only on Unix.
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Store::open(dir.path()).unwrap(), dir)
    }

    fn entry(i: u64) -> HistoryEntry {
        HistoryEntry {
            id: i.to_string(),
            direction: if i % 2 == 0 {
                Direction::Sent
            } else {
                Direction::Received
            },
            timestamp_ms: i,
            text: format!("msg {i}"),
            receipt: None,
        }
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
        store
            .append_text(&peer, "1", "[file] a.txt → /home/me/a.txt")
            .unwrap();
        store.append_text(&peer, "9", "nobody").unwrap(); // unknown id: ignored
        let history = store.load_history(&peer).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].text, "msg 0");
        assert_eq!(history[1].text, "[file] a.txt → /home/me/a.txt");
        assert_eq!(history[2].text, "msg 2");
        // Receipts still land on the updated entry.
        store
            .append_receipt(&peer, ReceiptKind::Read, &["1".into()], 5)
            .unwrap();
        let history = store.load_history(&peer).unwrap();
        assert_eq!(history[1].receipt, Some(ReceiptKind::Read));
        assert_eq!(history[1].text, "[file] a.txt → /home/me/a.txt");
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

        // Removing the passphrase restores plaintext.
        again.remove_passphrase().unwrap();
        assert!(!again.has_passphrase());
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
}
