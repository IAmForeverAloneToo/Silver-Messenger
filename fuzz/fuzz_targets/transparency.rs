//! The relay's key transparency log, as replayed by a client.
//!
//! A page of entries comes from the relay, which is the party the log
//! exists to check, so the replay must believe nothing it is told. Two
//! properties are asserted rather than merely exercised: a page that is
//! accepted really does chain onto the head it was applied to, and a page
//! that is refused leaves the state exactly as it was -- which is what
//! makes the kept evidence of a fork worth anything.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_client::LogStore;
use silver_client::protocol::transparency::LogEntry;
use silver_client::transparency::LogState;

fuzz_target!(|data: &[u8]| {
    // The state as read back from this client's own directory: encrypted
    // there, but parsed after decryption, so a corrupted or edited file
    // reaches this parser.
    let _ = serde_json::from_slice::<LogState>(data);

    let Ok(entries) = serde_json::from_slice::<Vec<LogEntry>>(data) else {
        return;
    };

    let mut log = LogStore::ephemeral();
    let before = log.head();
    match log.apply(&entries, 1_700_000_000_000) {
        Ok(head) => {
            // Accepting a page means every entry in it followed the one
            // before, ending where the returned head says.
            let mut at = before;
            for entry in &entries {
                assert!(
                    entry.follows(&at),
                    "an accepted page had an entry that does not follow {}",
                    at.index
                );
                at = entry.head();
            }
            assert_eq!(at, head, "the returned head is not where the page ends");
            assert_eq!(log.head(), head, "the stored head is not the returned one");
        }
        Err(_) => {
            // Refusing a page must leave nothing behind: the head a
            // client shows, and takes to an operator as evidence, has to
            // be the one it actually verified.
            assert_eq!(log.head(), before, "a refused page moved the head anyway");
        }
    }

    // Whatever the head is now, the checkpoints kept for it must bracket
    // it: `checkpoint_below` and `checkpoint_above` are what a client
    // uses to ask the relay for the part of the chain it can check, and
    // an index outside the log is the case a hostile page would try to
    // produce.
    let head = log.head();
    let below = log.checkpoint_below(head.index);
    let above = log.checkpoint_above(head.index);
    assert!(
        below.index <= head.index,
        "a checkpoint below the head is above it"
    );
    assert!(
        above.index >= head.index || above.index == 0,
        "a checkpoint above the head is below it"
    );
    let _ = log.hash_at(head.index);
    let _ = log.can_check(head.index);
    let _ = log.check_peer_head(&head);
    let _ = log.breaks().len();
});
