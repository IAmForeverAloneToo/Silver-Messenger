//! Invite links as `/add` parses them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_client::InviteLink;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(link) = text.parse::<InviteLink>() {
        let again = link.to_string();
        assert!(again.parse::<InviteLink>().is_ok());
    }
});
