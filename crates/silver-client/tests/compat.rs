//! Data written by an earlier release still opens and carries on.
//!
//! `tests/fixtures/0.21.0/` was written by 0.21.0 through the code below
//! (`write_fixtures`, run once with `--ignored`): two data directories under
//! a passphrase, alice's and bob's, with a post-quantum session between them
//! in mid-conversation, a message from alice bob has not read yet, and a
//! backup of alice's with her history. Every later version must open the
//! directories, read what they hold, decrypt the waiting message, and go on
//! talking in both directions on the same session; and it must restore the
//! backup. The protocol's own wire formats are pinned byte for byte by
//! `docs/vectors`; this pins what the client keeps on disk, which a change
//! of cryptography crates must leave readable.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use silver_client::backup::{export_backup_with, import_backup, read_backup};
use silver_client::sessions::SessionStore;
use silver_client::store::{Contact, Direction, HistoryEntry, Store};
use silver_client::vault::Kdf;
use silver_protocol::bundle::capability::PQ_RATCHET;
use silver_protocol::envelope::RatchetBody;
use silver_protocol::{Identity, KeyBundle, UserId};

const ALICE_PASS: &str = "alice's passphrase";
const BOB_PASS: &str = "bob's passphrase";
const BACKUP_PASS: &str = "the backup's passphrase";
/// When the fixtures were written; the sessions' clocks run from here.
const WRITTEN_AT: u64 = 1_793_000_000_000;

/// What the test needs alongside the directories.
#[derive(Serialize, Deserialize)]
struct Fixture {
    version: String,
    alice: UserId,
    bob: UserId,
    /// Bundles as each published them, for sending on an existing session.
    alice_bundle: KeyBundle,
    bob_bundle: KeyBundle,
    /// From alice to bob, on the session, not yet decrypted by bob.
    waiting: RatchetBody,
    waiting_text: String,
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/0.21.0")
}

/// The published bundle as a relay serves it: one one-time key of each kind,
/// and the post-quantum ratchet advertised.
fn bundle(identity: &Identity, sessions: &mut SessionStore, now: u64) -> KeyBundle {
    let mut prekeys = sessions.prekeys_for_publish(identity, now).unwrap();
    prekeys.one_time.truncate(1);
    prekeys.pq_one_time.truncate(1);
    identity
        .key_bundle_with(prekeys)
        .with_caps(identity, vec![PQ_RATCHET.to_owned()])
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn open(dir: &Path, passphrase: &str) -> (Store, Identity) {
    let mut store = Store::open(dir).unwrap();
    assert!(
        store.is_locked(),
        "{} is under its passphrase",
        dir.display()
    );
    store.unlock(passphrase).unwrap();
    let (identity, created) = store.load_or_create_identity().unwrap();
    assert!(!created, "the identity was read, not made anew");
    (store, identity)
}

/// Writes `tests/fixtures/<this version>/`. Run by hand, once per fixture set:
/// `cargo test -p silver-client --test compat -- --ignored write_fixtures`.
#[test]
#[ignore = "writes the fixtures; run by hand"]
fn write_fixtures() {
    let out = fixture_dir();
    assert!(
        !out.exists(),
        "{} exists; fixtures are written once",
        out.display()
    );
    fs::create_dir_all(&out).unwrap();
    let now = WRITTEN_AT;

    let mut alice_store = Store::open(out.join("alice")).unwrap();
    let (alice, _) = alice_store.load_or_create_identity().unwrap();
    alice_store
        .set_passphrase_with(ALICE_PASS, Kdf::fast())
        .unwrap();
    let mut bob_store = Store::open(out.join("bob")).unwrap();
    let (bob, _) = bob_store.load_or_create_identity().unwrap();
    bob_store
        .set_passphrase_with(BOB_PASS, Kdf::fast())
        .unwrap();

    let mut alice_contact = Contact::new(bob.user_id());
    alice_contact.alias = Some("bob".into());
    alice_store.save_contacts(&[alice_contact]).unwrap();
    let mut bob_contact = Contact::new(alice.user_id());
    bob_contact.alias = Some("alice".into());
    bob_store.save_contacts(&[bob_contact]).unwrap();

    let mut alice_sessions = SessionStore::load(&alice_store, alice.user_id()).unwrap();
    let mut bob_sessions = SessionStore::load(&bob_store, bob.user_id()).unwrap();
    let alice_bundle = bundle(&alice, &mut alice_sessions, now);
    let bob_bundle = bundle(&bob, &mut bob_sessions, now);

    // A conversation under way: a handshake, a reply, then one more from
    // alice that bob has not read.
    let first = alice_sessions
        .encrypt(&alice, &bob_bundle, b"first, from alice", now + 1)
        .unwrap();
    let (text, _) = bob_sessions
        .decrypt(&bob, alice.user_id(), &first, now + 2)
        .unwrap();
    assert_eq!(&text[..], b"first, from alice");
    let reply = bob_sessions
        .encrypt(&bob, &alice_bundle, b"a reply, from bob", now + 3)
        .unwrap();
    let (text, _) = alice_sessions
        .decrypt(&alice, bob.user_id(), &reply, now + 4)
        .unwrap();
    assert_eq!(&text[..], b"a reply, from bob");
    let waiting_text = "waiting for bob";
    let waiting = alice_sessions
        .encrypt(&alice, &bob_bundle, waiting_text.as_bytes(), now + 5)
        .unwrap();

    alice_store
        .append_history(
            &bob.user_id(),
            &HistoryEntry::new("m1", Direction::Sent, now + 1, "first, from alice"),
        )
        .unwrap();
    alice_store
        .append_history(
            &bob.user_id(),
            &HistoryEntry::new("m2", Direction::Received, now + 4, "a reply, from bob"),
        )
        .unwrap();
    drop(alice_sessions);
    drop(bob_sessions);

    export_backup_with(
        &alice_store,
        &out.join("alice.backup"),
        BACKUP_PASS,
        Kdf::fast(),
        true,
    )
    .unwrap();

    let fixture = Fixture {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        alice: alice.user_id(),
        bob: bob.user_id(),
        alice_bundle,
        bob_bundle,
        waiting,
        waiting_text: waiting_text.to_owned(),
    };
    fs::write(
        out.join("fixture.json"),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .unwrap();
}

#[test]
fn data_from_0_21_0_opens_and_the_conversation_goes_on() {
    let fixture: Fixture =
        serde_json::from_str(&fs::read_to_string(fixture_dir().join("fixture.json")).unwrap())
            .unwrap();
    assert_eq!(fixture.version, "0.21.0");
    // Opening writes (the rollback record, the sessions); the fixtures stay
    // as they were written.
    let work = tempfile::tempdir().unwrap();
    copy_dir(&fixture_dir(), work.path());
    let now = WRITTEN_AT + 60_000;

    let (alice_store, alice) = open(&work.path().join("alice"), ALICE_PASS);
    let (bob_store, bob) = open(&work.path().join("bob"), BOB_PASS);
    assert_eq!(alice.user_id(), fixture.alice);
    assert_eq!(bob.user_id(), fixture.bob);
    // The keys behind the ids, not only the ids: a bundle signed now
    // verifies as the one signed then did.
    assert!(fixture.alice_bundle.verify().is_ok());
    assert_eq!(alice.key_bundle().dh_public, fixture.alice_bundle.dh_public);
    assert_eq!(bob.key_bundle().dh_public, fixture.bob_bundle.dh_public);

    let contacts = alice_store.load_contacts().unwrap();
    assert_eq!(contacts[0].user_id, fixture.bob);
    assert_eq!(contacts[0].alias.as_deref(), Some("bob"));
    let history = alice_store.load_history(&fixture.bob).unwrap();
    let texts: Vec<&str> = history.iter().map(|e| e.text.as_str()).collect();
    assert_eq!(texts, ["first, from alice", "a reply, from bob"]);

    // The waiting message decrypts on the session kept on disk, and the
    // conversation carries on both ways.
    let mut alice_sessions = SessionStore::load(&alice_store, alice.user_id()).unwrap();
    let mut bob_sessions = SessionStore::load(&bob_store, bob.user_id()).unwrap();
    assert!(bob_sessions.has_session(&fixture.alice));
    let (text, _) = bob_sessions
        .decrypt(&bob, fixture.alice, &fixture.waiting, now)
        .unwrap();
    assert_eq!(&text[..], fixture.waiting_text.as_bytes());
    let answer = bob_sessions
        .encrypt(
            &bob,
            &fixture.alice_bundle,
            b"read it, after the upgrade",
            now + 1,
        )
        .unwrap();
    assert!(
        answer.init.is_none(),
        "on the old session, no new handshake"
    );
    let (text, _) = alice_sessions
        .decrypt(&alice, fixture.bob, &answer, now + 2)
        .unwrap();
    assert_eq!(&text[..], b"read it, after the upgrade");
    let onward = alice_sessions
        .encrypt(&alice, &fixture.bob_bundle, b"and onward", now + 3)
        .unwrap();
    let (text, _) = bob_sessions
        .decrypt(&bob, fixture.alice, &onward, now + 4)
        .unwrap();
    assert_eq!(&text[..], b"and onward");

    // The backup restores, history and all.
    let payload = read_backup(&work.path().join("alice.backup"), BACKUP_PASS).unwrap();
    let fresh = tempfile::tempdir().unwrap();
    let target = Store::open(fresh.path()).unwrap();
    assert_eq!(import_backup(&target, payload, false).unwrap(), 2);
    let (restored, _) = target.load_or_create_identity().unwrap();
    assert_eq!(restored.user_id(), fixture.alice);
    assert_eq!(target.load_history(&fixture.bob).unwrap().len(), 2);
}
