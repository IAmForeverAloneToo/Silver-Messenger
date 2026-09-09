//! What stops an older copy of a file being read as the current one.
//!
//! The at-rest encryption binds every file to its own name, which stops
//! one file being read as another but not an older copy of a file being
//! read as itself — an older copy has the right name. So somebody with
//! write access to a live directory could put back an older
//! `sessions.json` (reusing ratchet state, so the next send repeats a
//! message key), an older `contacts.json` (undoing a key-change warning
//! or a `verified` mark), or an older history file (dropping what was
//! said since). That is SM-C-24, and
//! [docs/design/format-changes.md](../../../docs/design/format-changes.md)
//! section 5 settles the shape of the answer; this is that shape.
//!
//! Every file is written at a **generation**, which is bound into its
//! associated data along with its name, so a file at another generation
//! does not decrypt at all rather than decrypting and being rejected
//! after the fact. What each file's generation should be is kept here, in
//! [`State`], which is itself an encrypted file — and the generation of
//! *that* file is the one number in plaintext `vault.json`. One anchor,
//! and nothing outside the encryption that names anything.
//!
//! ## What this cannot do
//!
//! An attacker who rolls the **whole directory** back to a consistent
//! earlier state cannot be caught from inside it: every file agrees with
//! every other, because they did once. What is caught is the partial
//! rollback — one file put back while the rest moves on — and the
//! reverse, the anchor put back while the files move on, which leaves
//! every file ahead of it. Deleting the directory is not a rollback and
//! no counter prevents it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The file the generations live in.
pub(crate) const STATE_FILE: &str = "state";
/// The version before it, kept so an interrupted write has something to
/// fall back to.
pub(crate) const STATE_PREVIOUS_FILE: &str = "state.prev";

/// Every file's generation.
///
/// History files are not in here yet: they are appended to a line at a
/// time rather than written whole, so they need a line index in each
/// line's associated data and a line count here, which is its own change.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct State {
    /// The generation this state itself was written at, matching
    /// `vault.json`'s `state_generation`.
    pub generation: u64,
    /// Whole files, by name.
    #[serde(default)]
    pub files: BTreeMap<String, u64>,
}

/// Where a directory stands with respect to rollback binding.
#[derive(Clone, Debug, Default)]
pub(crate) enum Generations {
    /// Not bound: a directory written before this existed, one being
    /// adopted right now, or one with no protection at rest, where there
    /// is no AEAD to bind a generation into and nothing to be gained by
    /// pretending otherwise. Files are bound to their names alone.
    #[default]
    Unbound,
    /// Bound, and this is what each file should be at.
    Bound(State),
    /// Bound, but the record of what was written cannot be read, so an
    /// older copy of a file cannot be told from the current one. Nothing
    /// is read or written until somebody says what to do about it; the
    /// string says what went wrong and how to get out of it.
    Unreadable(String),
}

impl Generations {
    /// The state, when there is one to consult.
    pub fn state(&self) -> Option<&State> {
        match self {
            Self::Bound(state) => Some(state),
            _ => None,
        }
    }

    /// Why this directory is refusing to be read, if it is.
    pub fn refusal(&self) -> Option<&str> {
        match self {
            Self::Unreadable(why) => Some(why),
            _ => None,
        }
    }
}

impl State {
    /// The generations a whole file may legitimately be at.
    ///
    /// Two: the one recorded, and the one an interrupted write would have
    /// left. Files are written *before* the anchor is raised, so a crash
    /// between them leaves a file one generation ahead of what this state
    /// records — which is safe to accept, because producing a file at a
    /// generation the anchor has not reached takes the key. Raising the
    /// anchor first would make the crash case a file one generation
    /// *behind*, which is exactly the old copy an attacker puts back.
    pub fn acceptable(&self, name: &str) -> Vec<u64> {
        match self.files.get(name).copied() {
            // A file this state has never heard of is one written by the
            // operation that also failed to record it, so the only
            // generation it can have is the one in flight.
            None => vec![self.generation + 1],
            Some(recorded) if recorded == self.generation + 1 => vec![recorded],
            Some(recorded) => vec![recorded, self.generation + 1],
        }
    }

    /// Record that `name` was written at `at`.
    pub fn wrote(&mut self, name: &str, at: u64) {
        self.files.insert(name.to_owned(), at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The crash case is a file one generation ahead, and the attack is a
    /// file behind. Both directions matter, so both are pinned.
    #[test]
    fn a_file_may_be_where_it_was_or_one_ahead_and_never_behind() {
        let mut state = State {
            generation: 7,
            ..State::default()
        };
        state.wrote("contacts.json", 7);

        let ok = state.acceptable("contacts.json");
        assert!(ok.contains(&7), "the recorded generation must be accepted");
        assert!(
            ok.contains(&8),
            "a write interrupted before the anchor rose must be accepted"
        );
        assert!(
            !ok.contains(&6),
            "an older copy of the file must not be accepted"
        );
        assert!(
            !ok.contains(&9),
            "a file further ahead than one write must not be accepted"
        );
    }

    /// A file written by the interrupted operation itself has no record,
    /// and the only generation it can be at is the one in flight.
    #[test]
    fn a_file_this_state_never_recorded_may_only_be_the_one_in_flight() {
        let state = State {
            generation: 3,
            ..State::default()
        };
        assert_eq!(state.acceptable("sessions.json"), vec![4]);
    }

    /// Once a file's record has caught up with the in-flight generation
    /// there is only one answer, not the same one twice.
    #[test]
    fn a_recorded_generation_one_ahead_is_not_offered_twice() {
        let mut state = State {
            generation: 2,
            ..State::default()
        };
        state.wrote("config.json", 3);
        assert_eq!(state.acceptable("config.json"), vec![3]);
    }
}
