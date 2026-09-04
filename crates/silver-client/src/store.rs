//! On-disk state for a client: identity keys, contacts, config and history.
//!
//! Layout under the data directory:
//!
//! ```text
//! identity.json        private keys (0600 on Unix)
//! config.json          relay URL etc.
//! contacts.json        known peers and their pinned key bundles
//! history/<user>.jsonl one line per message, per peer
//! ```
//!
//! History is currently stored in plaintext on the local disk; encrypting it
//! at rest behind a passphrase is on the roadmap.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use silver_protocol::{Identity, IdentitySecrets, KeyBundle, UserId};

/// Client-side configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub relay_url: Option<String>,
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
}

impl Contact {
    pub fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            alias: None,
            bundle: None,
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
}

/// Handle to the data directory.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// The platform's standard data directory for this app.
    pub fn default_dir() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "silver-message").map(|d| d.data_dir().to_path_buf())
    }

    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("history"))
            .with_context(|| format!("creating data dir {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Load the identity from disk, generating and saving a new one if this
    /// is the first run. The boolean is `true` when a new identity was made.
    pub fn load_or_create_identity(&self) -> anyhow::Result<(Identity, bool)> {
        let path = self.root.join("identity.json");
        if path.exists() {
            let text =
                fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            let secrets: IdentitySecrets =
                serde_json::from_str(&text).context("parsing identity.json")?;
            return Ok((Identity::from_secrets(&secrets), false));
        }
        let identity = Identity::generate();
        let text = serde_json::to_string_pretty(&identity.to_secrets())?;
        write_private(&path, text.as_bytes())?;
        Ok((identity, true))
    }

    pub fn load_config(&self) -> anyhow::Result<Config> {
        read_json_or_default(&self.root.join("config.json"))
    }

    pub fn save_config(&self, config: &Config) -> anyhow::Result<()> {
        write_atomic(
            &self.root.join("config.json"),
            serde_json::to_string_pretty(config)?.as_bytes(),
        )
    }

    pub fn load_contacts(&self) -> anyhow::Result<Vec<Contact>> {
        read_json_or_default(&self.root.join("contacts.json"))
    }

    pub fn save_contacts(&self, contacts: &[Contact]) -> anyhow::Result<()> {
        write_atomic(
            &self.root.join("contacts.json"),
            serde_json::to_string_pretty(contacts)?.as_bytes(),
        )
    }

    pub fn append_history(&self, peer: &UserId, entry: &HistoryEntry) -> anyhow::Result<()> {
        let path = self.history_path(peer);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let mut line = serde_json::to_string(entry)?;
        line.push('\n');
        file.write_all(line.as_bytes())?;
        Ok(())
    }

    pub fn load_history(&self, peer: &UserId) -> anyhow::Result<Vec<HistoryEntry>> {
        let path = self.history_path(peer);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let mut entries = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<HistoryEntry>(&line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    tracing::warn!("skipping corrupt history line in {}: {e}", path.display())
                }
            }
        }
        Ok(entries)
    }

    fn history_path(&self, peer: &UserId) -> PathBuf {
        self.root.join("history").join(format!("{peer}.jsonl"))
    }
}

fn read_json_or_default<T: Default + for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
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
            })
            .unwrap();
        assert_eq!(
            store.load_config().unwrap().relay_url.as_deref(),
            Some("ws://example:7777/ws")
        );

        for (i, dir) in [Direction::Sent, Direction::Received].iter().enumerate() {
            store
                .append_history(
                    &peer.user_id(),
                    &HistoryEntry {
                        id: i.to_string(),
                        direction: *dir,
                        timestamp_ms: i as u64,
                        text: format!("msg {i}"),
                    },
                )
                .unwrap();
        }
        let history = store.load_history(&peer.user_id()).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].direction, Direction::Received);
        assert_eq!(history[1].text, "msg 1");
    }
}
