# Contributing

Silver Messenger is a terminal messenger with a relay of its own. The
documents are as much the product as the code; read the one your
change touches first:

* [README.md](README.md): what it does and how to use it.
* [docs/PROTOCOL.md](docs/PROTOCOL.md): the wire.
* [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what it protects
  against and what it does not.
* [docs/OPERATING.md](docs/OPERATING.md): running a relay;
  [docs/UPGRADING.md](docs/UPGRADING.md): what changes between versions
  for one.
* [docs/RELEASES.md](docs/RELEASES.md): how a release is made, checked
  and signed.
* [docs/TERMINALS.md](docs/TERMINALS.md): what the client asks of a
  terminal.
* `docs/design/`: a note per larger item, written before its code.

## Building

A Rust toolchain from https://rustup.rs; `rust-toolchain.toml` pins the
exact version, which rustup installs on the first build, and which every
CI job and the release use as well, so a release can be rebuilt byte for
byte later. Bumping it is its own commit, together with the Rust image
`deploy/Dockerfile` names. Then, from the repository root:

```sh
cargo build --workspace            # the client (silver) and the relay (silver-relay)
cargo run --release --bin silver-relay -- --ephemeral --listen 127.0.0.1:7777
cargo run --release --bin silver -- --relay ws://127.0.0.1:7777/ws --data-dir /tmp/alice
```

Two clients with two data directories against one relay is a whole
network; nothing else is needed to try a change.

## Checking a change

Every push to `main` runs these in CI; run them before you propose a
change, and they should all pass:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check                                     # advisories, licences, duplicate crates
pip install pyte && TERMS="xterm-256color linux" tests/tui/run.sh   # the client in a pseudo-terminal
cd fuzz && RUSTUP_TOOLCHAIN=nightly cargo fuzz build  # the fuzz targets still build
```

What CI runs on every push, beyond those:

* The test suite on Linux, macOS and Windows, and the terminal tests
  under two terminal types plus a client driven inside tmux.
* `tests/tui/soak.py --minutes 3`: a relay and two clients exchanging
  messages for three minutes with their memory watched. The workflow
  can be dispatched for up to six hours; `--minutes 1440` is the
  day-long run.
* A minute of fuzzing per parser against a corpus that carries over
  between runs, and half an hour a parser once a week.
* The relay's ACME client against Pebble, Let's Encrypt's test server
  (`crates/silver-relay/tests/acme.rs`, with `SILVER_PEBBLE` pointing
  at the binary).
* The formal models with Verifpal (`formal/check.sh`).
* The packaging with the tools of each platform (the `packaging` and
  `homebrew` jobs).
* A reproducibility check that builds the Linux binaries twice from
  scratch and compares them, and the OpenSSF Scorecard weekly. Every
  GitHub Action is pinned to a commit hash, every container image by
  digest, and the compiler to an exact version.
* `tests/docs/check_links.py`: every cross-reference in the documents
  resolves.

Where the tests are:

* Unit tests beside the code in every crate, the known-answer vectors
  of `docs/vectors/` and the property tests among them.
* `crates/silver-client/tests/`: end-to-end tests through an in-process
  relay. `e2e.rs` starts a relay on a random port, connects two clients
  and checks both directions, offline queueing, reconnection after the
  relay goes away, forward-secret sessions (handshakes that wait in the
  mailbox, restarts, a peer that lost its session state, a peer without
  prekeys, whom nothing is sent to), anonymous submission, capabilities
  and receipts, and file transfer (chunking, progress, a missing blob,
  a tampered hash, a relay without file storage). `groups.rs`,
  `devices.rs` (a device linked by its link, a message reaching every
  device under one id, a revoked device cut off), `rekey.rs`,
  `update.rs` and the rest each cover their subject. `kill.rs` runs a
  writer child that saves the store as fast as it can, kills it at
  random moments, and checks that the store opens with nothing but the
  line being written lost.
* `tests/tui/`: the terminal client at a pseudo-terminal. Each test
  starts a relay and one or two clients, types, clicks, drags and reads
  the screen back through a terminal emulator (`pip install pyte`
  first; `tests/tui/run.sh` runs them all, `TERMS="xterm-256color
  linux"` for both terminal types, and `test_tmux.py` drives a client
  inside tmux). Which terminals are known to work, and how, is in
  `docs/TERMINALS.md`.

A test that fails only sometimes is a bug in the test or in the code,
not a thing to retry; the pseudo-terminal tests wait for what the
screen must show rather than sleeping.

## Proposing a change

1. **Say what you mean to do first** when the change decides something:
   a new command, a change to the wire, to what the relay stores, or to
   what the threat model promises. Open an issue, or for a larger item
   write a design note in `docs/design/` the way the existing ones are
   written (the decisions in a table, the goals and non-goals, what
   changes where, the tests, the order of the work), and have it agreed
   before the code. A fix for a plain bug needs no preamble.
2. **One change per pull request**, against `main`, with the checks
   above passing. A change to the wire bumps a protocol version and says
   in `PROTOCOL.md` how older clients and relays fare; a change to what
   is stored says in `UPGRADING.md` what a rollback leaves; a change to
   what is promised says so in `THREAT_MODEL.md`; every change people
   would notice goes in `CHANGELOG.md` under "Unreleased", and in the
   README where the README describes it.
3. **Tests come with the change**: a unit test for a rule, an end-to-end
   test in `crates/silver-client/tests/` for behaviour between clients
   and the relay, a pseudo-terminal test for what the screen shows.
4. **Commit messages** say what changed and why, in prose, as the
   history does; the first line is the change, the body the reasons and
   what was tested.

The maintainer reviews every change; CI must be green on the final
commit. A security problem goes through `SECURITY.md`, not the issue
tracker.

## What the code holds to

* `#![forbid(unsafe_code)]` in every crate but the terminal binary,
  which is `#![deny(unsafe_code)]` with one documented exception; the
  few places that need `unsafe` are in dependencies that are fuzzed and
  audited.
* Everything that comes in from the network, a file or a link is
  bounded before it is used (`crates/silver-client/tests/garbage.rs` and
  the fuzz targets feed the parsers bytes nobody meant), and nothing a
  peer sends reaches the terminal raw.
* Errors carry context (`anyhow::Context`) that names the file, the
  peer or the step, so a person can act on the message.
* Comments and documents are prose, in sentences, in British spelling;
  they say why, since the code says what.
* The client is a terminal program on purpose (no GUI or mobile client
  before 1.0), one relay is one network (no federation), and groups run
  on MLS; a change that assumes otherwise needs the roadmap changed
  first.

## What the documents hold to

The documents are as much the product as the code, and each is held to
a shape:

* **Each is one kind of thing**, and its first paragraph says which. A
  *front door* (the README) is for deciding and starting: short
  sections, a table where there is a choice, a command block where
  there is a step. A *reference* (`PROTOCOL.md`, the command table,
  `TERMINALS.md`) is for looking one thing up: tables and code blocks,
  one item per row, prose only to state a rule. A *guide*
  (`OPERATING.md`, `UPGRADING.md`, the FAQ, this file) is for doing one
  task in order: numbered steps, one task per section. A *promise*
  (`THREAT_MODEL.md`, `SECURITY.md`, the assessment) is for checking:
  claims as lists, short, each with what backs it, and the version it
  was checked against. An *argument* (a design note) says why: the
  decisions, the reasons, the alternatives not taken, dated, with
  corrections made after the code landed kept in a section of their
  own. A *record* (`CHANGELOG.md`, `ROADMAP.md`, the audit reports) is
  appended to and never rewritten for style.
* **One home per fact.** The README describes, the operator's guide
  operates, the protocol specifies, the threat model promises, the
  design notes argue, the changelog records. A fact wanted in two
  places is stated in one and linked from the other.
* **History goes to the changelog.** A document describes the program
  as it is; a version appears only where a reader must act on it, as in
  a compatibility rule or an upgrade note.
* **A table cell is a line**: a value, a phrase, at most two short
  sentences. Anything longer is a list, or prose under a run-in
  heading. A paragraph makes one point and fits in a dozen lines.
* **Section numbers do not move.** `PROTOCOL.md` sections and roadmap
  items are cited by the code, the tests and the audit reports.
* **A cross-reference names its target**: a relative link, a file by
  its path, "protocol section 13.5", "roadmap item 52".
  `tests/docs/check_links.py` resolves every one, and CI runs it.
* British spelling; the em dash, never `--`; commands, flags and file
  names in code spans; *the client* and *the relay*.

## Licence

AGPL-3.0-only. By contributing you agree that your contribution is
published under the same licence.
