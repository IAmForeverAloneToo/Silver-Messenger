//! Forward-secret sessions and prekeys, as kept by one client.
//!
//! [`silver_protocol::Session`] is the cryptography; this module decides
//! which session to use with a peer, keeps the private prekeys that let
//! peers start sessions with us, and persists both (`sessions.json` and
//! `prekeys.json` in the data directory, encrypted like everything else when
//! a passphrase is set).
//!
//! ## Which session
//!
//! A peer can end up with more than one session: both sides may start one
//! at the same moment, or one side may lose its state and start over. Every
//! session is kept for receiving, so messages sent on any of them still
//! decrypt. For sending, one session per peer is *active*:
//!
//! * A session we start becomes active at once.
//! * A session the peer starts becomes active when its first message
//!   arrives, unless we started one ourselves in the last few minutes, have
//!   not heard back on it yet, and our id sorts before theirs. In that case
//!   the two starts crossed and both sides settle on the one started by the
//!   lower id.
//!
//! ## Prekeys
//!
//! One signed prekey is current at a time and is replaced weekly; older
//! ones are kept for three weeks so handshakes that named them still work.
//! Twenty one-time prekeys are kept on deposit at the relay, topped up when
//! the relay reports fewer than ten. The private half of a one-time prekey
//! is deleted when a session uses it, or a month after the relay handed it
//! out without a session following.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use silver_protocol::prekey::Prekeys;
use silver_protocol::{
    Identity, InitHeader, KeyBundle, PrekeySecret, ProtocolError, RatchetBody, Session, UserId,
};
use zeroize::Zeroizing;

use crate::store::Store;

/// One-time prekeys kept on deposit.
pub const ONE_TIME_TARGET: usize = 20;
/// Deposit level at which more are generated.
pub const ONE_TIME_MIN: u32 = 10;
pub const SIGNED_PREKEY_ROTATION: Duration = Duration::from_secs(7 * 24 * 3600);
pub const SIGNED_PREKEY_RETENTION: Duration = Duration::from_secs(21 * 24 * 3600);
pub const ONE_TIME_RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);
/// Two sessions started within this window of each other count as crossed.
pub const CROSSING_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Sessions kept per peer for receiving; the least recently used go first.
pub const MAX_SESSIONS_PER_PEER: usize = 5;

/// A session store shared between the connection task and the front end.
pub type SharedSessions = Arc<Mutex<SessionStore>>;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("they have not published prekeys, so no forward-secret session can be started")]
    NoPrekeys,
    #[error("the message belongs to a session this client does not have")]
    UnknownSession,
    #[error("the message was started against prekey {0}, which this client no longer has")]
    UnknownPrekey(u32),
    #[error("session id does not match the handshake")]
    SessionMismatch,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("could not save session state: {0}")]
    Storage(#[from] anyhow::Error),
}

#[derive(Serialize, Deserialize)]
struct OneTimeSecret {
    key: PrekeySecret,
    /// When the relay reported handing this key out, if it has.
    #[serde(default)]
    handed_out_at_ms: Option<u64>,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct PrekeyFile {
    /// Newest first.
    #[serde(default)]
    signed: Vec<PrekeySecret>,
    #[serde(default)]
    one_time: Vec<OneTimeSecret>,
}

#[derive(Serialize, Deserialize)]
struct PeerSession {
    session: Session,
    initiator: UserId,
    established_at_ms: u64,
    last_used_ms: u64,
    /// For sessions we started: sent with every message until the peer
    /// answers on this session.
    #[serde(default)]
    pending_init: Option<InitHeader>,
    #[serde(default)]
    active: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct PeerSessions {
    sessions: Vec<PeerSession>,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct SessionsFile {
    #[serde(default)]
    peers: HashMap<UserId, PeerSessions>,
}

/// What the front end may want to know about a conversation's session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub established_at_ms: u64,
    pub initiated_by_us: bool,
    /// We started it and have not heard back on it yet.
    pub awaiting_reply: bool,
}

pub struct SessionStore {
    store: Option<Store>,
    me: UserId,
    prekeys: PrekeyFile,
    peers: HashMap<UserId, PeerSessions>,
}

impl SessionStore {
    /// Load from the data directory (missing files mean a fresh start).
    pub fn load(store: &Store, me: UserId) -> anyhow::Result<Self> {
        Ok(Self {
            prekeys: store.load_prekeys()?,
            peers: store.load_sessions()?.peers,
            store: Some(store.clone()),
            me,
        })
    }

    /// A store that lives in memory only.
    pub fn ephemeral(me: UserId) -> Self {
        Self {
            store: None,
            me,
            prekeys: PrekeyFile::default(),
            peers: HashMap::new(),
        }
    }

    pub fn shared(self) -> SharedSessions {
        Arc::new(Mutex::new(self))
    }

    // --- prekeys ----------------------------------------------------------------

    /// The prekeys to publish: rotates the signed prekey when it is due and
    /// tops the one-time keys up, then returns the public halves.
    pub fn prekeys_for_publish(
        &mut self,
        identity: &Identity,
        now_ms: u64,
    ) -> anyhow::Result<Prekeys> {
        let rotation = SIGNED_PREKEY_ROTATION.as_millis() as u64;
        let due = self
            .prekeys
            .signed
            .first()
            .is_none_or(|s| now_ms.saturating_sub(s.created_at_ms) >= rotation);
        if due {
            let id = self.fresh_id();
            self.prekeys
                .signed
                .insert(0, PrekeySecret::generate(id, now_ms));
        }
        let retention = SIGNED_PREKEY_RETENTION.as_millis() as u64;
        self.prekeys.signed.truncate(
            1.max(
                self.prekeys
                    .signed
                    .iter()
                    .take_while(|s| now_ms.saturating_sub(s.created_at_ms) < retention)
                    .count(),
            ),
        );
        self.top_up_one_time(now_ms);
        self.persist_prekeys()?;
        Ok(self.public_prekeys(identity))
    }

    /// Note what the relay reported after a publish. Returns whether the
    /// deposit ran low enough that fresh keys were made and a new publish
    /// is needed.
    pub fn apply_prekey_status(
        &mut self,
        one_time_remaining: u32,
        consumed: &[u32],
        now_ms: u64,
    ) -> anyhow::Result<bool> {
        let mut changed = false;
        for secret in &mut self.prekeys.one_time {
            if consumed.contains(&secret.key.id) && secret.handed_out_at_ms.is_none() {
                secret.handed_out_at_ms = Some(now_ms);
                changed = true;
            }
        }
        let republish = one_time_remaining < ONE_TIME_MIN;
        if republish {
            self.top_up_one_time(now_ms);
            changed = true;
        }
        if changed {
            self.persist_prekeys()?;
        }
        Ok(republish)
    }

    fn top_up_one_time(&mut self, now_ms: u64) {
        let retention = ONE_TIME_RETENTION.as_millis() as u64;
        self.prekeys.one_time.retain(|o| {
            o.handed_out_at_ms
                .is_none_or(|at| now_ms.saturating_sub(at) < retention)
        });
        let deposited = self
            .prekeys
            .one_time
            .iter()
            .filter(|o| o.handed_out_at_ms.is_none())
            .count();
        for _ in deposited..ONE_TIME_TARGET {
            let id = self.fresh_id();
            self.prekeys.one_time.push(OneTimeSecret {
                key: PrekeySecret::generate(id, now_ms),
                handed_out_at_ms: None,
            });
        }
    }

    /// A random id no current prekey uses. Random rather than sequential so
    /// a reinstall does not reuse ids the relay may still remember.
    fn fresh_id(&self) -> u32 {
        loop {
            let id: u32 = rand::random();
            let taken = id == 0
                || self.prekeys.signed.iter().any(|s| s.id == id)
                || self.prekeys.one_time.iter().any(|o| o.key.id == id);
            if !taken {
                return id;
            }
        }
    }

    fn public_prekeys(&self, identity: &Identity) -> Prekeys {
        Prekeys {
            signed: self.prekeys.signed[0].signed_by(identity),
            one_time: self
                .prekeys
                .one_time
                .iter()
                .filter(|o| o.handed_out_at_ms.is_none())
                .map(|o| o.key.one_time())
                .collect(),
        }
    }

    /// One-time prekeys still on deposit as far as this client knows.
    pub fn one_time_prekeys_deposited(&self) -> usize {
        self.prekeys
            .one_time
            .iter()
            .filter(|o| o.handed_out_at_ms.is_none())
            .count()
    }

    // --- sessions ---------------------------------------------------------------

    /// Whether messages to `peer` can be sent on an existing session.
    pub fn has_session(&self, peer: &UserId) -> bool {
        self.active(peer).is_some()
    }

    pub fn session_info(&self, peer: &UserId) -> Option<SessionInfo> {
        self.active(peer).map(|s| SessionInfo {
            established_at_ms: s.established_at_ms,
            initiated_by_us: s.initiator == self.me,
            awaiting_reply: s.pending_init.is_some(),
        })
    }

    fn active(&self, peer: &UserId) -> Option<&PeerSession> {
        self.peers
            .get(peer)?
            .sessions
            .iter()
            .find(|s| s.active && s.session.can_send())
    }

    /// Encrypt `plaintext` for the owner of `peer`, starting a session from
    /// the bundle's prekeys if there is none yet.
    pub fn encrypt(
        &mut self,
        identity: &Identity,
        peer: &KeyBundle,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<RatchetBody, SessionError> {
        let entry = self.peers.entry(peer.user_id).or_default();
        if let Some(current) = entry
            .sessions
            .iter_mut()
            .find(|s| s.active && s.session.can_send())
        {
            let message = current.session.encrypt(plaintext)?;
            current.last_used_ms = now_ms;
            let body = RatchetBody {
                v: 2,
                session: *current.session.id(),
                init: current.pending_init.clone(),
                message,
            };
            self.persist_sessions()?;
            return Ok(body);
        }

        if !peer.supports_sessions() {
            return Err(SessionError::NoPrekeys);
        }
        let (mut session, init) = Session::initiate(identity, peer)?;
        let message = session.encrypt(plaintext)?;
        let body = RatchetBody {
            v: 2,
            session: *session.id(),
            init: Some(init.clone()),
            message,
        };
        for other in &mut entry.sessions {
            other.active = false;
        }
        entry.sessions.push(PeerSession {
            session,
            initiator: self.me,
            established_at_ms: now_ms,
            last_used_ms: now_ms,
            pending_init: Some(init),
            active: true,
        });
        Self::prune(entry);
        self.persist_sessions()?;
        Ok(body)
    }

    /// Decrypt a ratchet body from `from`, deriving a new session from our
    /// prekeys when the body carries a handshake we have not seen. The
    /// boolean says whether a session was established by this call.
    pub fn decrypt(
        &mut self,
        identity: &Identity,
        from: UserId,
        body: &RatchetBody,
        now_ms: u64,
    ) -> Result<(Zeroizing<Vec<u8>>, bool), SessionError> {
        if let Some(existing) = self.peers.get_mut(&from).and_then(|p| {
            p.sessions
                .iter_mut()
                .find(|s| *s.session.id() == body.session)
        }) {
            let plaintext = existing.session.decrypt(&body.message)?;
            existing.last_used_ms = now_ms;
            existing.pending_init = None;
            self.persist_sessions()?;
            return Ok((plaintext, false));
        }

        let init = body.init.as_ref().ok_or(SessionError::UnknownSession)?;
        let signed = self
            .prekeys
            .signed
            .iter()
            .find(|s| s.id == init.signed_prekey_id)
            .cloned()
            .ok_or(SessionError::UnknownPrekey(init.signed_prekey_id))?;
        let one_time_index = match init.one_time_prekey_id {
            Some(id) => Some(
                self.prekeys
                    .one_time
                    .iter()
                    .position(|o| o.key.id == id)
                    .ok_or(SessionError::UnknownPrekey(id))?,
            ),
            None => None,
        };
        let one_time = one_time_index.map(|i| self.prekeys.one_time[i].key.clone());
        let mut session = Session::respond(identity, &from, &signed, one_time.as_ref(), init)?;
        if *session.id() != body.session {
            return Err(SessionError::SessionMismatch);
        }
        let plaintext = session.decrypt(&body.message)?;

        // The handshake worked: the one-time key has served its purpose.
        if let Some(i) = one_time_index {
            self.prekeys.one_time.remove(i);
            self.persist_prekeys()?;
        }
        let me = self.me;
        let entry = self.peers.entry(from).or_default();
        let window = CROSSING_WINDOW.as_millis() as u64;
        let ours_wins = entry.sessions.iter().any(|s| {
            s.active
                && s.initiator == me
                && s.pending_init.is_some()
                && now_ms.saturating_sub(s.established_at_ms) < window
                && me < from
        });
        if !ours_wins {
            for other in &mut entry.sessions {
                other.active = false;
            }
        }
        entry.sessions.push(PeerSession {
            session,
            initiator: from,
            established_at_ms: now_ms,
            last_used_ms: now_ms,
            pending_init: None,
            active: !ours_wins,
        });
        Self::prune(entry);
        self.persist_sessions()?;
        Ok((plaintext, true))
    }

    /// Drop every session with `peer`, for example because their identity
    /// key changed.
    pub fn forget(&mut self, peer: &UserId) -> anyhow::Result<()> {
        if self.peers.remove(peer).is_some() {
            self.persist_sessions()?;
        }
        Ok(())
    }

    fn prune(entry: &mut PeerSessions) {
        while entry.sessions.len() > MAX_SESSIONS_PER_PEER {
            let Some(victim) = entry
                .sessions
                .iter()
                .enumerate()
                .filter(|(_, s)| !s.active)
                .min_by_key(|(_, s)| s.last_used_ms)
                .map(|(i, _)| i)
            else {
                break;
            };
            entry.sessions.remove(victim);
        }
    }

    fn persist_prekeys(&self) -> anyhow::Result<()> {
        match &self.store {
            Some(store) => store.save_prekeys(&self.prekeys),
            None => Ok(()),
        }
    }

    fn persist_sessions(&self) -> anyhow::Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let mut file = SessionsFile::default();
        for (peer, sessions) in &self.peers {
            file.peers.insert(
                *peer,
                PeerSessions {
                    sessions: sessions
                        .sessions
                        .iter()
                        .map(|s| PeerSession {
                            session: s.session.clone(),
                            initiator: s.initiator,
                            established_at_ms: s.established_at_ms,
                            last_used_ms: s.last_used_ms,
                            pending_init: s.pending_init.clone(),
                            active: s.active,
                        })
                        .collect(),
                },
            );
        }
        store.save_sessions(&file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::{Body, Content, Sequence};

    fn plain(text: &str) -> Vec<u8> {
        Body::plain(Content::Text { body: text.into() }, 0, Sequence::default())
            .encode()
            .unwrap()
    }

    fn text_of(bytes: &[u8]) -> String {
        match Body::decode(bytes).unwrap() {
            Body::Plain {
                content: Content::Text { body },
                ..
            } => body,
            _ => panic!("expected a plain body"),
        }
    }

    struct Party {
        identity: Identity,
        sessions: SessionStore,
    }

    impl Party {
        fn new() -> Self {
            let identity = Identity::generate();
            let sessions = SessionStore::ephemeral(identity.user_id());
            Self { identity, sessions }
        }

        fn bundle(&mut self, now: u64) -> KeyBundle {
            let prekeys = self
                .sessions
                .prekeys_for_publish(&self.identity, now)
                .unwrap();
            // What a relay hands out: one one-time key.
            let mut one = prekeys.clone();
            one.one_time.truncate(1);
            self.identity.key_bundle_with(one)
        }

        fn send(&mut self, to: &KeyBundle, text: &str, now: u64) -> RatchetBody {
            self.sessions
                .encrypt(&self.identity, to, &plain(text), now)
                .unwrap()
        }

        fn recv(&mut self, from: &Party, body: &RatchetBody, now: u64) -> (String, bool) {
            let (bytes, established) = self
                .sessions
                .decrypt(&self.identity, from.identity.user_id(), body, now)
                .unwrap();
            (text_of(&bytes), established)
        }
    }

    #[test]
    fn prekeys_rotate_and_top_up() {
        let mut p = Party::new();
        let first = p.sessions.prekeys_for_publish(&p.identity, 0).unwrap();
        assert_eq!(first.one_time.len(), ONE_TIME_TARGET);
        assert!(first.verify(&p.identity.user_id()).is_ok());
        let again = p.sessions.prekeys_for_publish(&p.identity, 1000).unwrap();
        assert_eq!(again.signed.id, first.signed.id);

        // Handed-out keys leave the published list but stay usable.
        let consumed: Vec<u32> = first.one_time[..3].iter().map(|k| k.id).collect();
        assert!(!p.sessions.apply_prekey_status(17, &consumed, 2000).unwrap());
        assert_eq!(p.sessions.one_time_prekeys_deposited(), 17);
        assert!(p.sessions.apply_prekey_status(5, &[], 3000).unwrap());
        assert_eq!(p.sessions.one_time_prekeys_deposited(), ONE_TIME_TARGET);
        assert_eq!(p.sessions.prekeys.one_time.len(), ONE_TIME_TARGET + 3);

        // A week later the signed prekey rotates; the old one is kept.
        let week = SIGNED_PREKEY_ROTATION.as_millis() as u64;
        let rotated = p.sessions.prekeys_for_publish(&p.identity, week).unwrap();
        assert_ne!(rotated.signed.id, first.signed.id);
        assert_eq!(p.sessions.prekeys.signed.len(), 2);
        // And a month on, the old one and the stale handed-out keys are gone.
        let month = ONE_TIME_RETENTION.as_millis() as u64 + 4000;
        p.sessions.prekeys_for_publish(&p.identity, month).unwrap();
        assert_eq!(p.sessions.prekeys.signed.len(), 1);
        assert_eq!(p.sessions.prekeys.one_time.len(), ONE_TIME_TARGET);
    }

    #[test]
    fn a_session_starts_from_prekeys_and_the_one_time_key_is_consumed() {
        let mut alice = Party::new();
        let mut bob = Party::new();
        let bob_bundle = bob.bundle(0);
        let before = bob.sessions.prekeys.one_time.len();

        let m1 = alice.send(&bob_bundle, "hello", 1);
        assert!(m1.init.is_some());
        assert!(
            alice
                .sessions
                .session_info(&bob.identity.user_id())
                .unwrap()
                .awaiting_reply
        );
        assert_eq!(bob.recv(&alice, &m1, 2), ("hello".into(), true));
        assert_eq!(bob.sessions.prekeys.one_time.len(), before - 1);
        assert!(bob.sessions.has_session(&alice.identity.user_id()));

        // Alice keeps sending the handshake until Bob answers.
        let m2 = alice.send(&bob_bundle, "still there?", 3);
        assert!(m2.init.is_some());
        assert_eq!(bob.recv(&alice, &m2, 4), ("still there?".into(), false));
        let r1 = bob.send(&alice.bundle(5), "here", 5);
        assert!(r1.init.is_none());
        assert_eq!(alice.recv(&bob, &r1, 6), ("here".into(), false));
        let m3 = alice.send(&bob_bundle, "good", 7);
        assert!(m3.init.is_none());
        assert_eq!(bob.recv(&alice, &m3, 8), ("good".into(), false));

        // A replayed handshake message finds the session and fails cleanly.
        assert!(matches!(
            bob.sessions
                .decrypt(&bob.identity, alice.identity.user_id(), &m1, 9),
            Err(SessionError::Protocol(ProtocolError::DecryptFailed))
        ));
    }

    #[test]
    fn crossed_starts_settle_on_the_lower_id() {
        let (mut a, mut b) = (Party::new(), Party::new());
        if a.identity.user_id() > b.identity.user_id() {
            std::mem::swap(&mut a, &mut b);
        }
        let (a_bundle, b_bundle) = (a.bundle(0), b.bundle(0));
        let from_a = a.send(&b_bundle, "from a", 1);
        let from_b = b.send(&a_bundle, "from b", 1);
        let a_session = a
            .sessions
            .active(&b.identity.user_id())
            .unwrap()
            .session
            .id()
            .to_owned();

        assert_eq!(a.recv(&b, &from_b, 2), ("from b".into(), true));
        assert_eq!(b.recv(&a, &from_a, 2), ("from a".into(), true));
        // A (lower id) kept its own; B adopted A's.
        assert_eq!(
            a.sessions
                .active(&b.identity.user_id())
                .unwrap()
                .session
                .id(),
            &a_session
        );
        assert_eq!(
            b.sessions
                .active(&a.identity.user_id())
                .unwrap()
                .session
                .id(),
            &a_session
        );
        // Both directions work on it from here.
        let m = a.send(&b_bundle, "settled", 3);
        assert_eq!(b.recv(&a, &m, 4), ("settled".into(), false));
        let r = b.send(&a_bundle, "agreed", 5);
        assert_eq!(a.recv(&b, &r, 6), ("agreed".into(), false));
        assert_eq!(a.sessions.peers[&b.identity.user_id()].sessions.len(), 2);
    }

    #[test]
    fn a_peer_that_lost_its_state_starts_over_and_is_followed() {
        let (mut alice, mut bob) = (Party::new(), Party::new());
        let bob_bundle = bob.bundle(0);
        let m = alice.send(&bob_bundle, "one", 1);
        bob.recv(&alice, &m, 2);
        let r = bob.send(&alice.bundle(3), "two", 3);
        alice.recv(&bob, &r, 4);

        // Bob reinstalls: no sessions, fresh prekeys.
        let mut bob2 = Party {
            identity: Identity::from_secrets(&bob.identity.to_secrets()),
            sessions: SessionStore::ephemeral(bob.identity.user_id()),
        };
        let m2 = alice.send(&bob_bundle, "three", 5);
        assert!(matches!(
            bob2.sessions
                .decrypt(&bob2.identity, alice.identity.user_id(), &m2, 6),
            Err(SessionError::UnknownSession)
        ));
        // Bob starts a new session; Alice moves to it even though hers was
        // working, because hers is not a fresh crossed start.
        let alice_bundle = alice.bundle(7);
        let fresh = bob2.send(&alice_bundle, "again", 7);
        assert_eq!(alice.recv(&bob2, &fresh, 8), ("again".into(), true));
        let m3 = alice.send(&bob2.bundle(9), "welcome back", 9);
        assert_eq!(bob2.recv(&alice, &m3, 10), ("welcome back".into(), false));
    }

    #[test]
    fn unknown_prekeys_and_missing_prekeys_are_reported() {
        let (mut alice, mut bob) = (Party::new(), Party::new());
        let bob_bundle = bob.bundle(0);
        let m = alice.send(&bob_bundle, "x", 1);
        let mut stranger = Party::new();
        assert!(matches!(
            stranger
                .sessions
                .decrypt(&stranger.identity, alice.identity.user_id(), &m, 2),
            Err(SessionError::UnknownPrekey(_))
        ));
        // Without prekeys in the bundle, no session can start.
        assert!(matches!(
            stranger.sessions.encrypt(
                &stranger.identity,
                &bob.identity.key_bundle(),
                &plain("x"),
                3
            ),
            Err(SessionError::NoPrekeys)
        ));
        // But an existing session keeps working whatever the bundle says.
        assert!(
            alice
                .sessions
                .encrypt(&alice.identity, &bob.identity.key_bundle(), &plain("x"), 3)
                .is_ok()
        );
        alice.sessions.forget(&bob.identity.user_id()).unwrap();
        assert!(!alice.sessions.has_session(&bob.identity.user_id()));
    }

    #[test]
    fn state_persists_through_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (identity, _) = store.load_or_create_identity().unwrap();
        let mut bob = Party::new();
        let bob_bundle = bob.bundle(0);
        let first = {
            let mut sessions = SessionStore::load(&store, identity.user_id()).unwrap();
            sessions.prekeys_for_publish(&identity, 0).unwrap();
            sessions
                .encrypt(&identity, &bob_bundle, &plain("persisted"), 1)
                .unwrap()
        };
        let mut reloaded = SessionStore::load(&store, identity.user_id()).unwrap();
        assert!(reloaded.has_session(&bob.identity.user_id()));
        assert_eq!(reloaded.one_time_prekeys_deposited(), ONE_TIME_TARGET);
        let second = reloaded
            .encrypt(&identity, &bob_bundle, &plain("after reload"), 2)
            .unwrap();
        assert_eq!(second.message.header.n, 1);
        let alice = Party {
            identity,
            sessions: reloaded,
        };
        assert_eq!(bob.recv(&alice, &first, 3).0, "persisted");
        assert_eq!(bob.recv(&alice, &second, 4).0, "after reload");
        assert!(dir.path().join("sessions.json").exists());
        assert!(dir.path().join("prekeys.json").exists());
    }
}
