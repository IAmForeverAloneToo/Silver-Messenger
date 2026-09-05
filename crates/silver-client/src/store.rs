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
use silver_protocol::wire::url_host;
use silver_protocol::{Identity, IdentitySecrets, KeyBundle, Revocation, Sequence, UserId};

use crate::files::FileInfo;
use crate::sessions::{PrekeyFile, SessionsFile};
use crate::vault::{FileCipher, Kdf, LINE_PREFIX, VaultError, VaultFile};

const VAULT_FILE: &str = "vault.json";
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
            send_epoch: None,
            invite_token: None,
            read_receipts: true,
            cover: false,
            notify: default_notify(),
            marks: default_marks(),
            theme: default_theme(),
            sidebar_width: default_sidebar_width(),
            downloads_quota_mib: default_downloads_quota_mib(),
            os_keystore: true,
            lock_after_minutes: 0,
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
    /// Fetch the files they send as they arrive, instead of waiting for
    /// the user to ask for each one.
    #[serde(default)]
    pub auto_files: bool,
    /// The contact published a revocation for this identity: it is dead and
    /// must not be messaged. Set when a valid revocation for their pinned key
    /// arrives; cleared only by removing and re-adding them.
    #[serde(default)]
    pub revoked: bool,
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
            auto_files: false,
            revoked: false,
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

    /// Alias if set, otherwise a short form of the id. The alias is reduced
    /// to what can be seen even if the file on disk says otherwise: it
    /// ends up in window titles and notifications, not only in the cell
    /// buffer.
    pub fn display_name(&self) -> String {
        self.alias
            .as_deref()
            .map(|alias| crate::files::printable(alias, 40))
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
    /// In a group's history: who wrote it (absent for our own lines and
    /// for notes about the group).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<UserId>,
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
        write_private(
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
        Ok(())
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
        Ok(())
    }

    /// Encrypt everything under a key kept in the operating system's key
    /// store. For a directory that is not protected yet.
    pub fn protect_with_keystore(&mut self) -> anyhow::Result<()> {
        if self.protection() != Protection::None {
            bail!("the data directory is already protected");
        }
        let kdf = Kdf::keystore();
        let kek = crate::keystore::create(&kdf.keystore_name())?;
        let (_, cipher) = FileCipher::create_with_kek(&kek);
        let vault = cipher.wrap_under_kek(&kek, kdf);
        let cipher = Arc::new(cipher);
        if let Err(e) = self.recrypt_all(None, Some(&cipher)) {
            let _ = crate::keystore::delete(&vault.kdf.keystore_name());
            return Err(e);
        }
        self.write_vault(&vault)?;
        self.cipher = Some(cipher);
        Ok(())
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
                self.write_vault(&cipher.wrap_under_passphrase(passphrase, kdf)?)?;
                crate::keystore::delete(&old.kdf.keystore_name())?;
                Ok(())
            }
            Protection::None => {
                let (vault, cipher) = FileCipher::create(passphrase, kdf)?;
                let cipher = Arc::new(cipher);
                self.recrypt_all(None, Some(&cipher))?;
                self.write_vault(&vault)?;
                self.cipher = Some(cipher);
                Ok(())
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
            let kek = crate::keystore::create(&kdf.keystore_name())?;
            self.write_vault(&cipher.wrap_under_kek(&kek, kdf))?;
            return Ok(Protection::Keystore);
        }
        self.remove_protection()
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
        fs::remove_file(self.root.join(VAULT_FILE)).context("removing vault.json")?;
        if vault.kdf.is_keystore() {
            let _ = crate::keystore::delete(&vault.kdf.keystore_name());
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
            TRANSPARENCY_FILE,
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
        self.write_file(name, &bytes, true)
    }

    /// A private file's bytes, if it exists.
    pub(crate) fn read_private_file(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.read_file(name)
    }

    pub(crate) fn write_private_file(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.write_file(name, bytes, true)
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
        self.write_file(REVOCATION_FILE, text.as_bytes(), true)
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
    ) -> anyhow::Result<()> {
        let line = TextLine {
            update: id.to_owned(),
            text: text.to_owned(),
        };
        self.append_history_line(&group_history_name(group), &serde_json::to_string(&line)?)
    }

    /// [`Store::load_history`] for a group's log.
    pub fn load_group_history(
        &self,
        group: &silver_protocol::GroupId,
    ) -> anyhow::Result<Vec<HistoryEntry>> {
        self.load_history_named(&group_history_name(group))
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
    pub fn append_text(&self, peer: &UserId, id: &str, text: &str) -> anyhow::Result<()> {
        let line = TextLine {
            update: id.to_owned(),
            text: text.to_owned(),
        };
        self.append_history_line(&history_name(peer), &serde_json::to_string(&line)?)
    }

    fn append_history_line(&self, name: &str, json: &str) -> anyhow::Result<()> {
        self.ensure_unlocked()?;
        let path = self.root.join(name);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let mut line = encode_line(self.cipher.as_deref(), name, json);
        line.push('\n');
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
        let mut out = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&new_path)
            .with_context(|| format!("opening {}", new_path.display()))?;
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
        self.load_history_named(&history_name(peer))
    }

    fn load_history_named(&self, name: &str) -> anyhow::Result<Vec<HistoryEntry>> {
        self.ensure_unlocked()?;
        let path = self.root.join(name);
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
            let parsed = decode_line(self.cipher.as_deref(), name, line)
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

    /// Where the relay's transparency log, as replayed, is kept.
    pub fn transparency_path(&self) -> PathBuf {
        self.root.join(TRANSPARENCY_FILE)
    }

    /// Where received files are saved.
    pub fn downloads_dir(&self) -> PathBuf {
        self.root.join("downloads")
    }
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

        // A passphrase takes over without rewriting the files; the key
        // store forgets its key, so a copy is useless without the passphrase.
        let raw_before = fs::read(&identity_path).unwrap();
        let name = again.read_vault().unwrap().unwrap().kdf.keystore_name();
        again
            .set_passphrase_with("correct horse", Kdf::fast())
            .unwrap();
        assert_eq!(again.protection(), Protection::Passphrase);
        assert_eq!(fs::read(&identity_path).unwrap(), raw_before);
        assert!(crate::keystore::load(&name).unwrap().is_none());
        let mut third = Store::open(dir.path()).unwrap();
        assert!(third.unlock_with_keystore().is_err());
        third.unlock("correct horse").unwrap();
        assert_eq!(third.load_history(&peer.user_id()).unwrap().len(), 2);

        // Dropping the passphrase goes back to the key store, files untouched.
        assert_eq!(third.remove_passphrase().unwrap(), Protection::Keystore);
        assert_eq!(fs::read(&identity_path).unwrap(), raw_before);
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
            file: None,
            from: None,
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
}
