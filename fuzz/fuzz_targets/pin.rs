//! Certificate pins, as typed, pasted, or read back from `config.json`.
//!
//! A pin is the one thing that takes every certificate authority out of
//! the question for the relay, so what matters is that it parses to the
//! key somebody meant and to nothing else. Both spellings round-trip
//! here: a pin that parses must print and parse back to itself, and two
//! different texts must never land on the same key unless they say the
//! same thing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_client::Pin;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(pin) = Pin::parse(text) {
        // What it prints must be what it reads. This is what a person
        // compares against a pin the operator published, so a pin that
        // printed differently from what it parsed would have them
        // comparing two things neither of which is the key in use.
        let hex = pin.to_hex();
        let base64 = pin.to_base64();
        assert_eq!(
            Pin::parse(&hex).ok(),
            Some(pin),
            "a pin did not survive being printed as hex"
        );
        assert_eq!(
            Pin::parse(&base64).ok(),
            Some(pin),
            "a pin did not survive being printed as base64"
        );
        assert_eq!(hex, pin.to_string(), "Display and to_hex disagree");
        // The two spellings name one key.
        assert_eq!(
            Pin::parse(&hex).ok(),
            Pin::parse(&base64).ok(),
            "the hex and base64 spellings of one pin parsed differently"
        );
    }

    // Whitespace is trimmed, so a pasted line with a newline on the end
    // must reach the same answer as the line without it.
    assert_eq!(
        Pin::parse(text).ok(),
        Pin::parse(text.trim()).ok(),
        "trimming changed what a pin parsed to"
    );
});
