//! Identifiers as every frame field that carries one parses them.
//!
//! `UserId` and `GroupId` are base58 where a person reads them, and base58
//! decoding is quadratic in the input's length, so what matters here is not only that a decoder
//! accepts nothing it should refuse but that a long input is measured
//! before it is decoded (SM-P-02). The target is run with a larger
//! `-max_len` than the others for that reason: a 4 KiB identifier costs
//! nothing to send and used to cost the relay a great deal to parse.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_protocol::UserId;
use silver_protocol::group::GroupId;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(id) = text.parse::<UserId>() {
        // What an id prints as parses back to the same id: the encoding is
        // the one canonical form of the key (SM-P-10).
        let again = id.to_string();
        assert_eq!(again.parse::<UserId>().ok(), Some(id));
        assert_eq!(UserId::from_bytes(*id.as_bytes()).ok(), Some(id));
    }
    if let Ok(id) = text.parse::<GroupId>() {
        let again = id.to_string();
        assert!(again.parse::<GroupId>().ok() == Some(id));
    }
    // The same strings where they actually arrive: inside a frame field,
    // through serde, which is the path the relay takes before it has
    // authenticated anything. A group id is base58 in a link and base64 in
    // JSON, so this covers the second decoder as well.
    let quoted = serde_json::to_string(text).expect("a string encodes");
    let _ = serde_json::from_str::<UserId>(&quoted);
    let _ = serde_json::from_str::<GroupId>(&quoted);
});
