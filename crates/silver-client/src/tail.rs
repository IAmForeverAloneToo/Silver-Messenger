//! Tailing the relay's transparency log within one connection.
//!
//! A [`Tail`] is a state machine the connection task drives: it is told
//! what the relay says (its head on login, a lookup's answer, a page of
//! log entries) and what contacts say (the head inside their messages),
//! and answers with frames to send and events to raise. It replays entries
//! into the shared [`LogStore`](crate::transparency::LogStore), checks
//! lookups against it, and holds a lookup's answer back until the log has
//! been replayed up to the head the relay answered with, so the check is
//! against the log as it stood then.
//!
//! One thing at a time: while a page is awaited, further answers and
//! contacts' heads queue up and are dealt with when the log is caught up.

use silver_protocol::transparency::{LogEntry, LogHead, LogPosition, ReplayError};
use silver_protocol::wire::ClientFrame;
use silver_protocol::{KeyBundle, Revocation, Succession, UserId, now_ms};
use tokio::sync::oneshot;

use crate::connection::{ClientError, ClientEvent, TransparencyEvent};
use crate::transparency::{HeadCheck, SharedLog};

pub(crate) type LookupReply = oneshot::Sender<Result<Option<KeyBundle>, ClientError>>;

/// What a step decided: frames for the relay, events for the front end.
#[derive(Default)]
pub(crate) struct Step {
    pub send: Vec<ClientFrame>,
    pub events: Vec<ClientEvent>,
}

/// A lookup's answer, with the callers waiting for it.
pub(crate) struct Answer {
    pub user_id: UserId,
    pub bundle: Option<KeyBundle>,
    pub revocation: Option<Revocation>,
    pub succession: Option<Succession>,
    pub head: Option<LogHead>,
    pub logged: Option<LogPosition>,
    pub replies: Vec<LookupReply>,
}

enum Mode {
    /// Bringing our head up to `target`, asked for by `origin` (a contact
    /// whose head is ahead of ours) or by the relay itself.
    Advance {
        target: LogHead,
        origin: Option<UserId>,
    },
    /// Recomputing the chain from `cursor` up to `check.index`, to compare
    /// with `check`, an old head a contact sent that we hold no hash for.
    Verify {
        cursor: LogHead,
        check: LogHead,
        peer: UserId,
    },
}

enum Deferred {
    /// Boxed: an answer carries a whole bundle, a head two words.
    Answer(Box<Answer>),
    PeerHead {
        peer: UserId,
        head: LogHead,
    },
}

pub(crate) struct Tail {
    /// `None`: transparency is off for this connection (no store, or a
    /// relay without a log); everything passes through unchecked.
    log: Option<SharedLog>,
    mode: Option<Mode>,
    deferred: Vec<Deferred>,
    last_synced: Option<LogHead>,
}

impl Tail {
    pub fn new(log: Option<SharedLog>) -> Self {
        Self {
            log,
            mode: None,
            deferred: Vec::new(),
            last_synced: None,
        }
    }

    fn ours(&self) -> LogHead {
        self.log
            .as_ref()
            .map(|log| lock(log).head())
            .unwrap_or_default()
    }

    /// The relay told us where its log stands: on login, or with an
    /// answer. Catches up, and notices a relay whose log went backwards or
    /// contradicts what we replayed.
    pub fn on_relay_head(&mut self, head: LogHead) -> Step {
        let mut step = Step::default();
        let Some(log) = self.log.clone() else {
            return step;
        };
        let ours = lock(&log).head();
        if head.index < ours.index {
            step.events.push(transparency(TransparencyEvent::Rewound {
                from: ours.index,
                to: head.index,
            }));
            lock(&log).reset();
            self.mode = None;
            self.last_synced = None;
            self.start_advance(head, None, &mut step);
        } else if head.index == ours.index && head.hash != ours.hash {
            step.events.push(transparency(TransparencyEvent::Fork {
                peer: None,
                at: head.index,
            }));
            lock(&log).reset();
            self.mode = None;
            self.last_synced = None;
            self.start_advance(head, None, &mut step);
        } else if head.index > ours.index && self.mode.is_none() {
            self.start_advance(head, None, &mut step);
        }
        step
    }

    fn start_advance(&mut self, target: LogHead, origin: Option<UserId>, step: &mut Step) {
        let ours = self.ours();
        self.mode = Some(Mode::Advance { target, origin });
        step.send.push(ClientFrame::LogSince { index: ours.index });
    }

    /// A lookup was answered. Checked against the log once the log is
    /// replayed up to the head the answer came with; unchecked when
    /// transparency is off.
    pub fn on_answer(&mut self, answer: Answer) -> Step {
        let Some(log) = self.log.clone() else {
            let mut step = Step::default();
            settle(answer, &mut step);
            return step;
        };
        let Some(head) = answer.head else {
            let mut step = Step::default();
            refuse(
                answer,
                "the relay keeps a transparency log but answered without its head",
                &mut step,
            );
            return step;
        };
        let mut step = self.on_relay_head(head);
        if self.mode.is_some() || head.index > lock(&log).head().index {
            self.deferred.push(Deferred::Answer(Box::new(answer)));
            if self.mode.is_none() {
                self.start_advance(head, None, &mut step);
            }
            return step;
        }
        resolve(&log, answer, &mut step);
        step
    }

    /// A page of entries arrived.
    pub fn on_entries(&mut self, entries: Vec<LogEntry>, head: LogHead) -> Step {
        let mut step = Step::default();
        let Some(log) = self.log.clone() else {
            return step;
        };
        match self.mode.take() {
            None => {} // unasked for; nothing to do with it
            Some(Mode::Advance { target, origin }) => {
                let applied = lock(&log).apply(&entries, now_ms());
                let ours = match applied {
                    Err(ReplayError::Broken { at, .. }) | Err(ReplayError::Fork { at }) => {
                        step.events
                            .push(transparency(TransparencyEvent::Fork { peer: origin, at }));
                        self.fail_deferred("the relay's log does not chain", &mut step);
                        return step;
                    }
                    Ok(ours) => ours,
                };
                if ours.index < head.index {
                    if entries.is_empty() {
                        // It says there is more but hands out nothing.
                        step.events.push(transparency(TransparencyEvent::Withheld {
                            peer: origin,
                            index: head.index,
                        }));
                        self.fail_deferred("the relay withholds its log", &mut step);
                        return step;
                    }
                    self.mode = Some(Mode::Advance { target, origin });
                    step.send.push(ClientFrame::LogSince { index: ours.index });
                    return step;
                }
                // Caught up with the relay. Its own head must be ours...
                if ours.index == head.index && ours.hash != head.hash {
                    step.events.push(transparency(TransparencyEvent::Fork {
                        peer: None,
                        at: head.index,
                    }));
                    self.fail_deferred("the relay's log does not chain", &mut step);
                    return step;
                }
                // ...and the head that asked for this must lie on the chain.
                if target.index > ours.index {
                    step.events.push(transparency(TransparencyEvent::Withheld {
                        peer: origin,
                        index: target.index,
                    }));
                } else if lock(&log).hash_at(target.index) != Some(target.hash) {
                    step.events.push(transparency(TransparencyEvent::Fork {
                        peer: origin,
                        at: target.index,
                    }));
                }
                if self.last_synced != Some(ours) {
                    self.last_synced = Some(ours);
                    step.events
                        .push(transparency(TransparencyEvent::Synced { head: ours }));
                }
                self.resolve_deferred(&log, &mut step);
            }
            Some(Mode::Verify {
                mut cursor,
                check,
                peer,
            }) => {
                let mut outcome = None;
                for entry in &entries {
                    if !entry.follows(&cursor) {
                        outcome = Some(false);
                        break;
                    }
                    cursor = entry.head();
                    if cursor.index == check.index {
                        outcome = Some(cursor.hash == check.hash);
                        break;
                    }
                }
                match outcome {
                    Some(true) => {}
                    Some(false) => step.events.push(transparency(TransparencyEvent::Fork {
                        peer: Some(peer),
                        at: check.index,
                    })),
                    None if entries.is_empty() => {
                        step.events.push(transparency(TransparencyEvent::Withheld {
                            peer: Some(peer),
                            index: check.index,
                        }));
                    }
                    None => {
                        self.mode = Some(Mode::Verify {
                            cursor,
                            check,
                            peer,
                        });
                        step.send.push(ClientFrame::LogSince {
                            index: cursor.index,
                        });
                        return step;
                    }
                }
                self.resolve_deferred(&log, &mut step);
            }
        }
        step
    }

    /// A contact's message carried their head.
    pub fn on_peer_head(&mut self, peer: UserId, head: LogHead) -> Step {
        let mut step = Step::default();
        let Some(log) = self.log.clone() else {
            return step;
        };
        if self.mode.is_some() {
            self.deferred.push(Deferred::PeerHead { peer, head });
            return step;
        }
        self.check_head(&log, peer, head, &mut step);
        step
    }

    /// Compare a contact's head with our chain, fetching what that needs.
    /// Returns whether a fetch was started (so the caller stops resolving).
    fn check_head(
        &mut self,
        log: &SharedLog,
        peer: UserId,
        head: LogHead,
        step: &mut Step,
    ) -> bool {
        // Bound first: a guard in a match scrutinee lives through the arms,
        // and `start_advance` takes the lock again.
        let check = lock(log).check_peer_head(&head);
        match check {
            HeadCheck::Consistent => false,
            HeadCheck::Fork { at } => {
                step.events.push(transparency(TransparencyEvent::Fork {
                    peer: Some(peer),
                    at,
                }));
                false
            }
            HeadCheck::Ahead => {
                self.start_advance(head, Some(peer), step);
                true
            }
            HeadCheck::NeedEntries { from } => {
                self.mode = Some(Mode::Verify {
                    cursor: from,
                    check: head,
                    peer,
                });
                step.send.push(ClientFrame::LogSince { index: from.index });
                true
            }
        }
    }

    /// Deal with what waited for the log to catch up, until something
    /// needs another fetch.
    fn resolve_deferred(&mut self, log: &SharedLog, step: &mut Step) {
        while self.mode.is_none() && !self.deferred.is_empty() {
            match self.deferred.remove(0) {
                Deferred::Answer(answer) => {
                    let ours = lock(log).head();
                    match answer.head {
                        Some(head) if head.index > ours.index => {
                            // The relay moved on while we caught up.
                            self.deferred.insert(0, Deferred::Answer(answer));
                            self.start_advance(head, None, step);
                        }
                        _ => resolve(log, *answer, step),
                    }
                }
                Deferred::PeerHead { peer, head } => {
                    self.check_head(log, peer, head, step);
                }
            }
        }
    }

    fn fail_deferred(&mut self, reason: &str, step: &mut Step) {
        for deferred in self.deferred.drain(..) {
            if let Deferred::Answer(answer) = deferred {
                refuse(*answer, reason, step);
            }
        }
    }
}

fn lock(log: &SharedLog) -> std::sync::MutexGuard<'_, crate::transparency::LogStore> {
    log.lock().unwrap_or_else(|e| e.into_inner())
}

fn transparency(event: TransparencyEvent) -> ClientEvent {
    ClientEvent::Transparency(event)
}

/// Check the answer against the log and settle or refuse it.
fn resolve(log: &SharedLog, answer: Answer, step: &mut Step) {
    let check = lock(log).check_lookup(
        &answer.user_id,
        answer.bundle.as_ref(),
        answer.revocation.as_ref(),
        answer.succession.as_ref(),
        answer.logged,
    );
    match check {
        Ok(()) => settle(answer, step),
        Err(problem) => {
            let problem = problem.to_string();
            refuse(answer, &problem, step);
        }
    }
}

/// Hand the answer to the callers, and raise the lifecycle statements it
/// carried (validly signed ones only; the front end matches them against
/// the contact it has pinned).
fn settle(answer: Answer, step: &mut Step) {
    for reply in answer.replies {
        let _ = reply.send(Ok(answer.bundle.clone()));
    }
    if let Some(revocation) = answer.revocation
        && revocation.verify().is_ok()
    {
        step.events.push(ClientEvent::PeerRevoked { revocation });
    }
    if let Some(succession) = answer.succession
        && succession.verify().is_ok()
    {
        step.events.push(ClientEvent::PeerSucceeded { succession });
    }
}

fn refuse(answer: Answer, reason: &str, step: &mut Step) {
    for reply in answer.replies {
        let _ = reply.send(Err(ClientError::Transparency(reason.to_owned())));
    }
    step.events.push(transparency(TransparencyEvent::Lookup {
        who: answer.user_id,
        problem: reason.to_owned(),
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparency::LogStore;
    use silver_protocol::Identity;
    use silver_protocol::prekey::{PrekeySecret, Prekeys};
    use silver_protocol::transparency::{EntryKind, Hash, subject};

    /// A relay's log, to answer `LogSince` from.
    struct Relay {
        entries: Vec<LogEntry>,
    }

    impl Relay {
        fn new() -> Self {
            Self {
                entries: Vec::new(),
            }
        }

        fn head(&self) -> LogHead {
            self.entries.last().map(LogEntry::head).unwrap_or_default()
        }

        fn log(&mut self, user: &UserId, kind: EntryKind, leaf: Hash) {
            let entry = LogEntry::after(&self.head(), subject(user), kind, leaf, 1);
            self.entries.push(entry);
        }

        fn log_bundle(&mut self, bundle: &KeyBundle) {
            self.log(
                &bundle.user_id,
                EntryKind::Bundle,
                bundle.transparency_leaf(),
            );
        }

        fn latest(&self, user: &UserId) -> Option<LogPosition> {
            let s = subject(user);
            self.entries
                .iter()
                .rev()
                .find(|e| e.subject == s)
                .map(|e| LogPosition {
                    index: e.index,
                    leaf: e.leaf,
                })
        }

        /// Answer the frames a step asked for: every `LogSince` gets a page.
        fn answer(&self, step: &Step, page: usize) -> Vec<(Vec<LogEntry>, LogHead)> {
            step.send
                .iter()
                .map(|frame| match frame {
                    ClientFrame::LogSince { index } => (
                        self.entries
                            .iter()
                            .filter(|e| e.index > *index)
                            .take(page)
                            .cloned()
                            .collect(),
                        self.head(),
                    ),
                    other => panic!("unexpected frame {other:?}"),
                })
                .collect()
        }
    }

    fn bundle_of(id: &Identity, prekey_id: u32) -> KeyBundle {
        id.key_bundle_with(Prekeys::classical(
            PrekeySecret::generate(prekey_id, 0).signed_by(id),
            Vec::new(),
        ))
    }

    fn events(step: &Step) -> Vec<&TransparencyEvent> {
        step.events
            .iter()
            .filter_map(|e| match e {
                ClientEvent::Transparency(t) => Some(t),
                _ => None,
            })
            .collect()
    }

    /// Drive the tail through every fetch a step asked for, until it asks
    /// for none; collect the events.
    fn drive(tail: &mut Tail, relay: &Relay, mut step: Step, page: usize) -> Vec<ClientEvent> {
        let mut all = Vec::new();
        loop {
            all.append(&mut step.events);
            let pages = relay.answer(&step, page);
            if pages.is_empty() {
                return all;
            }
            let mut next = Step::default();
            for (entries, head) in pages {
                let mut s = tail.on_entries(entries, head);
                next.send.append(&mut s.send);
                next.events.append(&mut s.events);
            }
            step = next;
        }
    }

    fn answer_for(
        relay: &Relay,
        bundle: &KeyBundle,
    ) -> (
        Answer,
        oneshot::Receiver<Result<Option<KeyBundle>, ClientError>>,
    ) {
        let (tx, rx) = oneshot::channel();
        (
            Answer {
                user_id: bundle.user_id,
                bundle: Some(bundle.clone()),
                revocation: None,
                succession: None,
                head: Some(relay.head()),
                logged: relay.latest(&bundle.user_id),
                replies: vec![tx],
            },
            rx,
        )
    }

    #[test]
    fn a_login_catches_up_in_pages_and_reports_one_sync() {
        let mut relay = Relay::new();
        let alice = Identity::generate();
        for i in 1..=5 {
            relay.log_bundle(&bundle_of(&alice, i));
        }
        let log = LogStore::ephemeral().shared();
        let mut tail = Tail::new(Some(log.clone()));
        let step = tail.on_relay_head(relay.head());
        assert!(matches!(
            step.send.as_slice(),
            [ClientFrame::LogSince { index: 0 }]
        ));
        let got = drive(&mut tail, &relay, step, 2);
        assert_eq!(lock(&log).head(), relay.head());
        let synced: Vec<_> = got
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    ClientEvent::Transparency(TransparencyEvent::Synced { .. })
                )
            })
            .collect();
        assert_eq!(synced.len(), 1);
        // Nothing new: nothing to do.
        let step = tail.on_relay_head(relay.head());
        assert!(step.send.is_empty() && step.events.is_empty());
    }

    #[test]
    fn a_lookup_waits_for_the_log_and_is_checked_against_it() {
        let mut relay = Relay::new();
        let alice = Identity::generate();
        let bob = Identity::generate();
        let old = bundle_of(&alice, 1);
        relay.log_bundle(&old);
        let current = bundle_of(&alice, 2);
        relay.log_bundle(&current);
        let log = LogStore::ephemeral().shared();
        let mut tail = Tail::new(Some(log.clone()));

        // The right bundle, before we have the log: held, then handed over.
        let (answer, rx) = answer_for(&relay, &current);
        let step = tail.on_answer(answer);
        assert!(!step.send.is_empty(), "it fetches first");
        let got = drive(&mut tail, &relay, step, 10);
        assert_eq!(rx.blocking_recv().unwrap().unwrap(), Some(current.clone()));
        assert!(!got.iter().any(|e| matches!(
            e,
            ClientEvent::Transparency(TransparencyEvent::Lookup { .. })
        )));

        // An old bundle, with the log in hand: refused at once.
        let (answer, rx) = answer_for(&relay, &old);
        let step = tail.on_answer(answer);
        assert!(step.send.is_empty());
        let err = rx.blocking_recv().unwrap().unwrap_err();
        assert!(matches!(err, ClientError::Transparency(_)), "{err}");
        assert!(matches!(
            events(&step).as_slice(),
            [TransparencyEvent::Lookup { who, .. }] if *who == alice.user_id()
        ));

        // A bundle for someone never logged: refused.
        let (answer, rx) = answer_for(&relay, &bob.key_bundle());
        let step = tail.on_answer(answer);
        assert!(rx.blocking_recv().unwrap().is_err());
        assert_eq!(events(&step).len(), 1);

        // Off: everything passes.
        let mut off = Tail::new(None);
        let (answer, rx) = answer_for(&relay, &old);
        let step = off.on_answer(answer);
        assert!(step.send.is_empty() && step.events.is_empty());
        assert_eq!(rx.blocking_recv().unwrap().unwrap(), Some(old));
    }

    #[test]
    fn a_settled_answer_raises_its_lifecycle_statements() {
        let mut relay = Relay::new();
        let alice = Identity::generate();
        let bundle = bundle_of(&alice, 1);
        relay.log_bundle(&bundle);
        let revocation = alice.revocation(3);
        relay.log(
            &alice.user_id(),
            EntryKind::Revocation,
            revocation.transparency_leaf(),
        );
        let log = LogStore::ephemeral().shared();
        let mut tail = Tail::new(Some(log));
        let (tx, rx) = oneshot::channel();
        let step = tail.on_answer(Answer {
            user_id: alice.user_id(),
            bundle: Some(bundle),
            revocation: Some(revocation.clone()),
            succession: None,
            head: Some(relay.head()),
            logged: relay.latest(&alice.user_id()),
            replies: vec![tx],
        });
        let got = drive(&mut tail, &relay, step, 10);
        assert!(rx.blocking_recv().unwrap().is_ok());
        assert!(
            got.iter().any(
                |e| matches!(e, ClientEvent::PeerRevoked { revocation: r } if *r == revocation)
            )
        );
    }

    #[test]
    fn a_contacts_head_is_checked_fetching_old_entries_when_needed() {
        let mut relay = Relay::new();
        let alice = Identity::generate();
        for i in 1..=4 {
            relay.log_bundle(&bundle_of(&alice, i));
        }
        let log = LogStore::ephemeral().shared();
        let mut tail = Tail::new(Some(log.clone()));
        let step = tail.on_relay_head(relay.head());
        drive(&mut tail, &relay, step, 10);
        let bob = Identity::generate().user_id();

        // On our chain: quiet.
        let step = tail.on_peer_head(bob, relay.entries[1].head());
        assert!(step.send.is_empty() && step.events.is_empty());
        // Same index, other hash: a fork, named after the contact.
        let mut forked = relay.entries[1].head();
        forked.hash[0] ^= 1;
        let step = tail.on_peer_head(bob, forked);
        assert!(matches!(
            events(&step).as_slice(),
            [TransparencyEvent::Fork { peer: Some(p), at: 2 }] if *p == bob
        ));
        // Ahead of us: we catch up, and it must be on the chain we get.
        relay.log_bundle(&bundle_of(&alice, 5));
        let step = tail.on_peer_head(bob, relay.head());
        assert!(!step.send.is_empty());
        let got = drive(&mut tail, &relay, step, 10);
        assert_eq!(lock(&log).head(), relay.head());
        assert!(
            !got.iter()
                .any(|e| matches!(e, ClientEvent::Transparency(TransparencyEvent::Fork { .. })))
        );
        // Ahead of us with a hash the relay's chain does not reach: a fork.
        relay.log_bundle(&bundle_of(&alice, 6));
        let mut wrong = relay.head();
        wrong.hash[0] ^= 1;
        let step = tail.on_peer_head(bob, wrong);
        let got = drive(&mut tail, &relay, step, 10);
        assert!(got.iter().any(|e| matches!(e, ClientEvent::Transparency(TransparencyEvent::Fork { peer: Some(p), at }) if *p == bob && *at == relay.head().index)));
    }

    #[test]
    fn a_relay_that_withholds_or_rewinds_is_reported() {
        let mut relay = Relay::new();
        let alice = Identity::generate();
        for i in 1..=3 {
            relay.log_bundle(&bundle_of(&alice, i));
        }
        let log = LogStore::ephemeral().shared();
        let mut tail = Tail::new(Some(log.clone()));
        let step = tail.on_relay_head(relay.head());
        drive(&mut tail, &relay, step, 10);

        // A contact verified further than the relay will serve: withheld.
        let bob = Identity::generate().user_id();
        let beyond = LogHead {
            index: 9,
            hash: [9; 32],
        };
        let step = tail.on_peer_head(bob, beyond);
        let empty = relay.answer(&step, 10);
        let step = tail.on_entries(empty[0].0.clone(), relay.head());
        assert!(matches!(
            events(&step).as_slice(),
            [TransparencyEvent::Withheld { peer: Some(p), index: 9 }] if *p == bob
        ));

        // The relay comes back shorter: rewound, and we start over from it.
        let shorter = relay.entries[0].head();
        let step = tail.on_relay_head(shorter);
        assert!(matches!(
            events(&step).as_slice(),
            [TransparencyEvent::Rewound { from: 3, to: 1 }]
        ));
        assert_eq!(lock(&log).head(), LogHead::EMPTY);
        assert!(matches!(
            step.send.as_slice(),
            [ClientFrame::LogSince { index: 0 }]
        ));
    }
}
