//! The updater's own HTTP, which is hand-rolled and reads bytes chosen by
//! whoever answers.
//!
//! Two things happen before a signature is anywhere in sight. The header
//! block is read for a status and a `Location:`, and the status line is
//! printed to a terminal; then the redirect target is split into host,
//! port and path, and checked against where the request started. That
//! check is the whole of what stops an answer from the release host
//! walking the updater onto another one, so it is fuzzed on both sides:
//! a `Location:` the parser produces, and a URL the fuzzer chooses.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_client::update::{parse_head_for_fuzzing, redirect_target_for_fuzzing};

/// Where the updater's requests start out. A redirect that leaves this
/// host, other than for another host of the same release service, must be
/// refused.
const ORIGIN: &str = "api.github.com";

/// What allowing a redirect is *meant* to mean, as against how the
/// updater spells it: the target is the host the request is already on,
/// or a name inside one of the release service's domains.
///
/// Deliberately stricter than the code it checks. The code asks whether
/// the host ends with `.github.com`, and a string ending in a release
/// host is not the same thing as a name inside it -- which is how
/// `evil.com@api.github.com` used to pass. Matching whole labels, and
/// insisting the host is one, is the property; anything the updater
/// allows that this refuses is a finding.
fn is_release_name(host: &str) -> bool {
    const DOMAINS: [&str; 2] = ["github.com", "githubusercontent.com"];
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let plausible = labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    });
    plausible
        && DOMAINS
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

fuzz_target!(|data: &[u8]| {
    let (status, status_line, location) = parse_head_for_fuzzing(data);

    // The status line reaches a terminal that is not the interface, so it
    // must survive being made into one line the same way every other
    // borrowed string does.
    let _ = silver_client::files::one_line(&status_line);

    // A redirect is followed only for a 3xx, which is where the parsed
    // location goes next.
    if (300..400).contains(&status)
        && let Some(location) = location
    {
        // Absolute: taken as it stands. Relative: pasted onto the origin,
        // which is the shape the updater builds.
        let url = if location.starts_with("https://") {
            location
        } else if location.starts_with('/') {
            format!("https://{ORIGIN}{location}")
        } else {
            // Anything else is refused before it gets here.
            return;
        };
        if let Some((host, _port, _path, allowed)) = redirect_target_for_fuzzing(&url, ORIGIN) {
            // The property: anything allowed through is a host inside the
            // release service, or the one the request is already on.
            assert!(
                !allowed || host.eq_ignore_ascii_case(ORIGIN) || is_release_name(&host),
                "a redirect to {host:?} was allowed from {ORIGIN}"
            );
        }
    }

    // And the same splitter on whatever the fuzzer makes of the bytes
    // directly, since a URL also arrives from `config.json`.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = redirect_target_for_fuzzing(text, ORIGIN);
        let _ = redirect_target_for_fuzzing(text, text);
    }
});
