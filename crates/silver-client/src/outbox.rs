//! Envelopes handed to us that the relay has not yet accepted.
//!
//! Sending never fails for lack of a connection: the envelope goes into the
//! outbox, is written to the data directory when the connection has one,
//! and is (re)sent on every connection until the relay answers `Sent` or
//! `Rejected`. The relay ignores duplicates by envelope id, so resending is
//! safe.

use std::collections::VecDeque;

use anyhow::Context;
use silver_protocol::Envelope;
use tracing::warn;

use crate::store::Store;

const OUTBOX_NAME: &str = "outbox.json";

#[derive(Debug, Default)]
pub(crate) struct Outbox {
    entries: VecDeque<Envelope>,
    /// The directory the outbox is kept in, through whose bound writes
    /// the file is encrypted and bound to a generation like every other
    /// file there (`docs/design/format-changes.md` section 5.7). `None`
    /// keeps the outbox in memory only.
    store: Option<Store>,
}

impl Outbox {
    /// Load the outbox from the store's directory (a missing file is an
    /// empty outbox). Without a store the outbox lives in memory only.
    pub(crate) fn load(store: Option<Store>) -> anyhow::Result<Self> {
        let entries = match &store {
            Some(store) => match store
                .read_private_file(OUTBOX_NAME)
                .context("reading the outbox")?
            {
                Some(bytes) => serde_json::from_slice(&bytes).context("parsing outbox.json")?,
                None => VecDeque::new(),
            },
            None => VecDeque::new(),
        };
        Ok(Self { entries, store })
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
        let Some(store) = &self.store else {
            return;
        };
        // Synced by the store's write: the outbox holds sealed envelopes
        // waiting to go, and a power loss must not leave the name pointing
        // at an empty file.
        let written = serde_json::to_vec(&self.entries)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| store.write_private_file(OUTBOX_NAME, &bytes));
        if let Err(e) = written {
            warn!("could not save the outbox: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::{Content, Identity, seal};

    fn envelope(text: &str) -> Envelope {
        let (a, b) = (Identity::generate(), Identity::generate());
        seal(&a, &b.key_bundle(), Content::text(text), 0).unwrap()
    }

    #[test]
    fn outbox_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (first, second) = (envelope("one"), envelope("two"));
        {
            let mut outbox = Outbox::load(Some(store.clone())).unwrap();
            outbox.push(first.clone());
            outbox.push(second.clone());
            outbox.push(first.clone()); // duplicate, ignored
            assert_eq!(outbox.ids(), vec![first.id.clone(), second.id.clone()]);
        }
        let mut outbox = Outbox::load(Some(store.clone())).unwrap();
        assert_eq!(
            outbox.iter().cloned().collect::<Vec<_>>(),
            vec![first.clone(), second.clone()]
        );
        assert!(outbox.remove(&first.id));
        assert!(!outbox.remove(&first.id));
        let outbox = Outbox::load(Some(store)).unwrap();
        assert_eq!(outbox.ids(), vec![second.id]);
    }

    /// Through a protected store the file is under the data key and bound
    /// to a generation like every other, a store that is not unlocked
    /// reads none of it, and an older copy put back is refused rather
    /// than re-queued.
    #[test]
    fn a_protected_store_binds_the_outbox_and_refuses_an_older_copy() {
        crate::keystore::use_mock_store();
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        store.load_or_create_identity().unwrap();
        store.protect_with_keystore().unwrap();
        let env = envelope("secret");
        Outbox::load(Some(store.clone())).unwrap().push(env.clone());
        let path = dir.path().join(OUTBOX_NAME);
        let older = std::fs::read(&path).unwrap();
        assert!(older.starts_with(crate::vault::GENERATION_MAGIC));
        assert!(
            Outbox::load(Some(Store::open(dir.path()).unwrap())).is_err(),
            "a store that is not unlocked should read nothing"
        );
        let mut outbox = Outbox::load(Some(store.clone())).unwrap();
        assert_eq!(outbox.ids(), vec![env.id.clone()]);

        // The envelope went; its older self put back would send it again.
        assert!(outbox.remove(&env.id));
        std::fs::write(&path, &older).unwrap();
        let err = format!("{:#}", Outbox::load(Some(store)).unwrap_err());
        assert!(
            err.contains("not the version this directory last wrote"),
            "an older copy of the outbox was read: {err}"
        );
    }
}
