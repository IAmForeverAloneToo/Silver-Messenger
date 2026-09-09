//! What a device reads when it is being linked to an account.
//!
//! Two shapes. The link itself is a line a person carries between two
//! computers and compares by eye, so what it parses to must be what it
//! prints -- a link that displayed one device id and parsed to another
//! would defeat the comparison the whole ceremony rests on. The snapshot
//! is the contacts, groups and history the primary sends afterwards:
//! bytes from another computer, parsed by a device that has nothing of
//! its own yet.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_client::linking::{DeviceLink, Snapshot};

fuzz_target!(|data: &[u8]| {
    // The snapshot arrives sealed and is parsed once opened, so the
    // parser sees whatever the other device sent.
    if let Ok(snapshot) = Snapshot::from_bytes(data) {
        let _ = snapshot.is_empty();
        let _ = snapshot.message_count();
        // What it says it holds must survive being written out again.
        if let Ok(bytes) = snapshot.to_bytes() {
            assert!(
                Snapshot::from_bytes(&bytes).is_ok(),
                "a snapshot this version wrote is not one it reads"
            );
        }
    }

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // `looks_like` decides whether a pasted line is treated as a device
    // link at all, so anything that parses must first look like one --
    // otherwise a link could be parsed by a path that never checked it.
    if let Ok(link) = text.parse::<DeviceLink>() {
        assert!(
            DeviceLink::looks_like(text),
            "a line parsed as a device link that looks_like refuses"
        );

        // The comparison the ceremony rests on: what is printed for the
        // person to check names the device that was parsed.
        let printed = link.to_string();
        let again: DeviceLink = printed
            .parse()
            .expect("a link this version printed must be one it reads");
        assert_eq!(
            again.device, link.device,
            "a link printed a different device from the one it parsed"
        );
        assert_eq!(
            again.secret, link.secret,
            "a link printed a different secret from the one it parsed"
        );
        assert_eq!(
            again.relay, link.relay,
            "a link printed a different relay from the one it parsed"
        );
        assert_eq!(again.key(), link.key(), "the sealing key did not survive");
    }

    // And on the way in, before anything has decided what the line is.
    let _ = DeviceLink::looks_like(text);
});
