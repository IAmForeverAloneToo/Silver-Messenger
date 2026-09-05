//! The store under a kill (`docs/design/robustness.md` section 4): a
//! writer child saves the config, the contacts and history lines as fast
//! as it can, is killed at a random moment, and the store must open with
//! every file loading, the config and the contacts at a value the child
//! wrote, and the history a prefix of the child's lines with at most the
//! line being written lost. The next child carries on in the same store,
//! so a line cut short by a kill is followed by whole ones. Ten rounds
//! plain, ten under a passphrase.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};

use silver_client::vault::Kdf;
use silver_client::{Config, Contact, Conversation, Direction, HistoryEntry, Store};
use silver_protocol::{Identity, UserId};

/// Set in the child: the data directory to write.
const WRITER_DIR: &str = "SILVER_KILL_TEST_DIR";
/// Set in the child: the contact whose history is written.
const WRITER_PEER: &str = "SILVER_KILL_TEST_PEER";
/// Set in the child when the store is under the passphrase.
const WRITER_LOCKED: &str = "SILVER_KILL_TEST_LOCKED";
const PASSPHRASE: &str = "kill test";
const ROUNDS: u64 = 10;

/// The child: round `n` saves the config with `n` in `lock_after_minutes`,
/// the contacts as a list of `n % 50 + 1` entries whose aliases count up,
/// history line `n`, and every third round a read and every fifth a
/// reaction for it; then it prints `n`. It never returns.
fn write_until_killed(dir: &str, peer: UserId, locked: bool) -> ! {
    let mut store = Store::open(dir).expect("open");
    if locked {
        store.unlock(PASSPHRASE).expect("unlock");
    }
    let conversation = Conversation::Contact(peer);
    // Carry on from what the last child left, so a line cut short by its
    // kill is written again after it.
    let start = store.load_history(&peer).expect("history").len() as u64;
    let mut out = std::io::stdout().lock();
    let mut n = start;
    loop {
        let config = Config {
            lock_after_minutes: n,
            ..Config::default()
        };
        store.save_config(&config).expect("config");
        let contacts: Vec<Contact> = (0..=(n % 50))
            .map(|i| {
                let mut c = Contact::new(peer);
                c.alias = Some(i.to_string());
                c
            })
            .collect();
        store.save_contacts(&contacts).expect("contacts");
        let entry = HistoryEntry::new(n.to_string(), Direction::Received, n, format!("line {n}"));
        store.append_history(&peer, &entry).expect("history");
        if n % 3 == 0 {
            store
                .append_read(&conversation, &[n.to_string()], n)
                .expect("read");
        }
        if n % 5 == 0 {
            store
                .append_reaction(&conversation, &n.to_string(), None, "+1")
                .expect("reaction");
        }
        writeln!(out, "{n}").expect("report");
        out.flush().expect("flush");
        n += 1;
    }
}

/// A child that is killed when dropped, whatever happened.
struct Writer(Child);

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// One round: run the writer, kill it a random 5 to 60 ms after its first
/// round, and check the store it left. The last round the child reported
/// complete.
fn kill_once(dir: &std::path::Path, peer: UserId, locked: bool, rng: &mut Rng) -> u64 {
    let exe = std::env::current_exe().expect("this test binary");
    let mut command = Command::new(exe);
    command
        .arg("--nocapture")
        .arg("the_store_survives_a_kill")
        .env(WRITER_DIR, dir)
        .env(WRITER_PEER, peer.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if locked {
        command.env(WRITER_LOCKED, "1");
    }
    let mut child = Writer(command.spawn().expect("spawn the writer"));
    let mut reader = BufReader::new(child.0.stdout.take().expect("piped"));
    // Let the child finish a round (the unlock alone can take longer than
    // the wait below), then kill it at a random moment after that.
    let mut first = String::new();
    loop {
        first.clear();
        let read = reader.read_line(&mut first).expect("read the child");
        assert!(read > 0, "the writer died before finishing a round");
        if first.trim().parse::<u64>().is_ok() {
            break;
        }
    }
    std::thread::sleep(Duration::from_millis(5 + rng.next() % 56));
    child.0.kill().expect("kill");
    child.0.wait().expect("wait");
    // What the child reported before it died: its first round and its
    // last complete one. Rounds before its first belong to earlier
    // children, one of which may have been cut between a round's entry
    // and that round's updates; those were checked when they were made.
    let first_round: u64 = first.trim().parse().expect("a round");
    let reported = reader
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| line.trim().parse::<u64>().ok())
        .last()
        .unwrap_or(first_round);

    let mut store = Store::open(dir).expect("the store opens");
    if locked {
        store.unlock(PASSPHRASE).expect("the store unlocks");
    }
    let config = store.load_config().expect("the config loads");
    let contacts = store.load_contacts().expect("the contacts load");
    store.load_requests().expect("the requests load");
    store.load_blocked().expect("the blocked list load");
    let history = store.load_history(&peer).expect("the history loads");

    let done = reported;
    // The config and the contacts are a round the child reached: the last
    // reported one, or the one it was in when killed.
    let counter = config.lock_after_minutes;
    assert!(
        counter == done || counter == done + 1,
        "config counter {counter} after round {done}"
    );
    let expected_len = (counter % 50 + 1) as usize;
    assert!(
        contacts.len() == expected_len || contacts.len() == ((done % 50) + 1) as usize,
        "{} contacts after round {done}, config at {counter}",
        contacts.len()
    );
    for (i, contact) in contacts.iter().enumerate() {
        assert_eq!(contact.alias.as_deref(), Some(i.to_string().as_str()));
    }
    // The history is a prefix of the lines, in order, ending at the last
    // reported round or the one after.
    let ids: Vec<u64> = history
        .iter()
        .map(|e| e.id.parse::<u64>().expect("a numbered line"))
        .collect();
    let expected: Vec<u64> = (0..ids.len() as u64).collect();
    assert_eq!(ids, expected, "the history is a prefix in order");
    assert!(
        ids.len() as u64 == done + 1 || ids.len() as u64 == done + 2,
        "{} lines after round {done}",
        ids.len()
    );
    for entry in history.iter().filter(|e| {
        let n = e.id.parse::<u64>().unwrap();
        (first_round..=done).contains(&n)
    }) {
        let n: u64 = entry.id.parse().unwrap();
        assert_eq!(entry.text, format!("line {n}"));
        if n % 3 == 0 {
            assert_eq!(
                entry.read_at_ms,
                Some(n),
                "the read of a finished round is there"
            );
        }
        if n % 5 == 0 {
            assert_eq!(
                entry.reactions.len(),
                1,
                "the reaction of a finished round is there"
            );
        }
    }
    done
}

#[test]
fn the_store_survives_a_kill() {
    if let Ok(dir) = std::env::var(WRITER_DIR) {
        let peer: UserId = std::env::var(WRITER_PEER)
            .expect("the peer")
            .parse()
            .expect("a user id");
        write_until_killed(&dir, peer, std::env::var(WRITER_LOCKED).is_ok());
    }
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
        | 1;
    let mut rng = Rng(seed);
    let peer = Identity::generate().user_id();

    for locked in [false, true] {
        let dir = tempfile::tempdir().expect("a directory");
        if locked {
            let mut store = Store::open(dir.path()).expect("open");
            store
                .set_passphrase_with(PASSPHRASE, Kdf::fast())
                .expect("a passphrase");
        }
        let mut furthest = 0;
        for _ in 0..ROUNDS {
            furthest = furthest.max(kill_once(dir.path(), peer, locked, &mut rng));
        }
        assert!(
            furthest > 0,
            "the writer never finished a round; the kill came too early every time"
        );
        // A temp file beside a store file, as a kill between the write
        // and the rename leaves, does not stop the file loading.
        std::fs::write(dir.path().join("contacts.tmp"), b"not json at all")
            .expect("a stray temp file");
        let mut store = Store::open(dir.path()).expect("open");
        if locked {
            store.unlock(PASSPHRASE).expect("unlock");
        }
        store
            .load_contacts()
            .expect("the contacts load beside a stray temp file");
    }
}
