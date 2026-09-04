//! Envelopes handed to us that the relay has not yet accepted.
//!
//! Sending never fails for lack of a connection: the envelope goes into the
//! outbox, is written to disk when a path is configured, and is (re)sent on
//! every connection until the relay answers `Sent` or `Rejected`. The relay
//! ignores duplicates by envelope id, so resending is safe.

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use silver_protocol::Envelope;
use tracing::warn;

#[derive(Debug, Default)]
pub(crate) struct Outbox {
    entries: VecDeque<Envelope>,
    path: Option<PathBuf>,
}

impl Outbox {
    /// Load the outbox from `path` (missing file = empty). Without a path the
    /// outbox lives in memory only.
    pub(crate) fn load(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let entries = match &path {
            Some(p) if p.exists() => read(p)?,
            _ => VecDeque::new(),
        };
        Ok(Self { entries, path })
    }

    pub(crate) fn push(&mut self, envelope: Envelope) {
        if !self.entries.iter().any(|e| e.id == envelope.id) {
            self.entries.push_back(envelope);
            self.persist();
        }
    }

    /// Forget the envelope with this id. Returns whether it was queued.
    pub(crate) fn remove(&mut self, id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        let removed = self.entries.len() != before;
        if removed {
            self.persist();
        }
        removed
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Envelope> {
        self.entries.iter()
    }

    pub(crate) fn ids(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.id.clone()).collect()
    }

    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Err(e) = write(path, &self.entries) {
            warn!("could not save outbox to {}: {e:#}", path.display());
        }
    }
}

fn read(path: &Path) -> anyhow::Result<VecDeque<Envelope>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn write(path: &Path, entries: &VecDeque<Envelope>) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec(entries)?)
        .with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::{Content, Identity, seal};

    fn envelope(text: &str) -> Envelope {
        let (a, b) = (Identity::generate(), Identity::generate());
        seal(&a, &b.key_bundle(), Content::Text { body: text.into() }, 0).unwrap()
    }

    #[test]
    fn outbox_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.json");
        let (first, second) = (envelope("one"), envelope("two"));
        {
            let mut outbox = Outbox::load(Some(path.clone())).unwrap();
            outbox.push(first.clone());
            outbox.push(second.clone());
            outbox.push(first.clone()); // duplicate, ignored
            assert_eq!(outbox.ids(), vec![first.id.clone(), second.id.clone()]);
        }
        let mut outbox = Outbox::load(Some(path.clone())).unwrap();
        assert_eq!(
            outbox.iter().cloned().collect::<Vec<_>>(),
            vec![first.clone(), second.clone()]
        );
        assert!(outbox.remove(&first.id));
        assert!(!outbox.remove(&first.id));
        let outbox = Outbox::load(Some(path)).unwrap();
        assert_eq!(outbox.ids(), vec![second.id]);
    }
}
