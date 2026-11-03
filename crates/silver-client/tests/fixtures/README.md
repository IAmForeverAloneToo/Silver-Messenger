# Compatibility fixtures

Data directories and a backup written by a released version of the
client, kept so that every later version is checked against them
(`tests/compat.rs`): they must still open, decrypt and carry the
conversation on.

Every key in here belongs to an identity made up for the test and used
nowhere else, and every passphrase is in `tests/compat.rs` in plain
sight. Nothing here protects anything.

A new set is written once per format worth pinning, by the version
whose output it is, with
`cargo test -p silver-client --test compat -- --ignored write_fixtures`
after pointing `fixture_dir` at the new version's directory; existing
sets are never rewritten.

`security-key/` is a data directory under a version 2 `vault.json`
(docs/design/security-key.md): one security key, the software
authenticator of `silver-key` with the seed and PIN in
`tests/security_key.rs`, and a recovery passphrase, written with
`cargo test -p silver-client --test security_key -- --ignored write_fixture`.
