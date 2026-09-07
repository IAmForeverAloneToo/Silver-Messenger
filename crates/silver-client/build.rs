//! The release signing key, compiled in.
//!
//! `silver update` checks a downloaded binary against the project's
//! minisign key before it replaces the running one, so the key has to
//! come from the source rather than the network. It is read here, at
//! build time, from `minisign.pub` at the repository root.
//!
//! A checkout without that file builds fine and produces a client that
//! says so and refuses to update: a fork with no key of its own should
//! not silently accept whatever the release host serves.

use std::path::Path;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let key = root.join("minisign.pub");
    println!("cargo:rerun-if-changed={}", key.display());
    let contents = std::fs::read_to_string(&key).unwrap_or_default();
    // One line, the second of the file: the comment above it is a
    // comment. Empty when there is no key.
    let line = contents
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .unwrap_or_default();
    println!("cargo:rustc-env=SILVER_MINISIGN_PUB={line}");
}
