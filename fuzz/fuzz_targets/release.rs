//! What the updater parses out of an answer from the release host.
//!
//! These run before any signature has been checked -- the signature is
//! over `SHA256SUMS`, and finding `SHA256SUMS` means parsing the release
//! description first -- so everything here is attacker-controlled input
//! on the path to replacing the running binary. Every other parser that
//! faces the network has had a target since 0.10.0; these did not,
//! because they face a host the client chose rather than a peer, which
//! is not the same as facing nothing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_client::update::{parse_release_for_fuzzing, sums_line_for_fuzzing};

fuzz_target!(|data: &[u8]| {
    // The release description: JSON from the API host, whose asset names
    // and URLs are printed to a terminal and used to build requests.
    if let Ok(release) = parse_release_for_fuzzing(data) {
        // Whatever came back must be usable without panicking, which is
        // what every caller does with it.
        let _ = release.version();
        let _ = release.asset("SHA256SUMS");
        for asset in &release.assets {
            let _ = asset.name.len();
            let _ = asset.url.len();
        }
    }

    // The checksum list, matched against an asset name. The name is
    // taken from the same answer, so a hostile host controls both sides
    // of the comparison.
    let _ = sums_line_for_fuzzing(data, "silver-v1.2.3-x86_64-unknown-linux-musl");
    if let Ok(text) = std::str::from_utf8(data) {
        // And against a name from the data itself, so the two can be
        // made to agree in whatever way the format allows.
        if let Some(first) = text.lines().next() {
            let _ = sums_line_for_fuzzing(data, first);
        }
    }
});
